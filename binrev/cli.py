"""binrev CLI — inspect a binary, configure the agent, run a session.

``binrev inspect ./fw.bin --isa arm`` is the m1 entry point: it loads a binary
into a BinState and prints the function table (or one function's
decompilation).  ``binrev ./fw.bin`` runs the agent loop (needs an LLM key).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from . import __version__
from .agent import BinrevAgent, OpenAICompatibleClient
from .binst import load_binary, render_inspect
from .config import CONFIG_PATH, Config
from .ghidra_bridge import GhidraBridge
from .models import ISAKind

console = Console()


class _DefaultGroup(click.Group):
    """Route the first token to a hidden ``run`` command when it isn't a
    known subcommand, so ``binrev ./fw.bin`` works alongside
    ``binrev inspect ./fw.bin``."""

    def parse_args(self, ctx: click.Context, args: list[str]):
        if args and not args[0].startswith("-") and args[0] not in self.commands:
            args = ["run"] + args
        return super().parse_args(ctx, args)


def _parse_isa(value: str) -> ISAKind:
    try:
        return ISAKind(value)
    except ValueError:
        raise click.BadParameter(f"unknown isa {value!r}; choose arm / thumb / aarch64")


def _parse_func_addr(value: Optional[str]) -> Optional[int]:
    """Parse ``--func`` like ``0x1000``; a clean usage error, not a traceback."""
    if value is None:
        return None
    try:
        return int(value, 0)
    except ValueError:
        raise click.BadParameter(f"{value!r} is not a function address (try hex like 0x1000)")


def _load_state(binary: Path, isa: ISAKind, config: Config):
    """Load a BinState, preferring Ghidra when configured + available."""
    bridge = GhidraBridge(ghidra_path=Path(config.ghidra_path) if config.ghidra_path else None)
    if bridge.is_available():
        console.print("[dim]using ghidra headless backend[/dim]")
        return bridge.dump(binary, isa)
    console.print("[dim]using capstone backend (no ghidra configured)[/dim]")
    return load_binary(binary, isa)


def _make_agent(state, config: Config) -> BinrevAgent:
    if not config.is_llm_ready():
        console.print(
            "[yellow]no LLM key configured — run `binrev config set --api-key ...`[/yellow]"
        )
        sys.exit(1)
    return BinrevAgent(state=state, client=OpenAICompatibleClient(config.llm), model=config.llm.model)


@click.group(cls=_DefaultGroup, invoke_without_command=True)
@click.version_option(version=__version__, prog_name="binrev")
@click.pass_context
def cli(ctx: click.Context) -> None:
    """binrev — binary-action-space reverse-engineering agent."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@cli.command(hidden=True)
@click.argument("binary", type=click.Path(exists=True, path_type=Path))
@click.option("--isa", "isa", default="arm", help="instruction set: arm / thumb / aarch64")
@click.option("--question", "-q", default=None, help="ask the agent one question and exit")
def run(binary: Path, isa: str, question: Optional[str]) -> None:
    """Load a binary into an agent session (``binrev ./fw.bin``)."""
    config = Config.load()
    state = _load_state(binary, _parse_isa(isa), config)
    console.print(Panel.fit(state.summary(), title=str(binary)))
    agent = _make_agent(state, config)
    if question is None:
        console.print("[bold]binrev agent session[/bold]  (empty line / Ctrl-D to quit)\n")
        try:
            while True:
                q = click.prompt("ask", default="", show_default=False, prompt_suffix="> ")
                if not q.strip():
                    break
                console.print(agent.ask(q))
        except (EOFError, click.exceptions.Abort):
            pass
        return
    console.print(agent.ask(question))


@cli.command()
@click.argument("binary", type=click.Path(exists=True, path_type=Path))
@click.option("--isa", "isa", default="arm", help="arm / thumb / aarch64")
@click.option("--func", "func", default=None, help="function address to show, e.g. 0x1000")
def inspect(binary: Path, isa: str, func: Optional[str]) -> None:
    """Inspect a binary's BinState: function table or one function's decompilation."""
    func_addr = _parse_func_addr(func)
    state = _load_state(binary, _parse_isa(isa), Config.load())
    out = render_inspect(state, func_addr=func_addr)
    if func_addr is not None and state.decompile(func_addr):
        console.print(Syntax(out, "text", theme="ansi_dark"))
    else:
        console.print(out)


@cli.group()
def config() -> None:
    """Manage binrev configuration (ghidra path, LLM key, model target)."""


@config.command("set")
@click.option("--ghidra", "ghidra", default=None, help="path to a Ghidra install dir")
@click.option("--api-key", "api_key", default=None, help="LLM API key (Qwen / DeepSeek)")
@click.option("--base-url", "base_url", default=None, help="OpenAI-compatible base URL")
@click.option("--model", "model", default=None, help="model name, e.g. qwen-plus / deepseek-chat")
@click.option(
    "--target",
    "target",
    type=click.Choice(["qwen", "deepseek"]),
    default=None,
    help="preset a model target",
)
def config_set(
    ghidra: Optional[str],
    api_key: Optional[str],
    base_url: Optional[str],
    model: Optional[str],
    target: Optional[str],
) -> None:
    """Set configuration values (persists to ~/.binrev/config.json)."""
    cfg = Config.load()
    if target:
        cfg.apply_target(target)
    if ghidra is not None:
        cfg.ghidra_path = ghidra
    if api_key is not None:
        cfg.llm.api_key = api_key
    if base_url is not None:
        cfg.llm.base_url = base_url
    if model is not None:
        cfg.llm.model = model
    cfg.save()
    console.print(f"[green]saved[/green] -> {CONFIG_PATH}")
    _show_config(cfg)


@config.command("show")
def config_show() -> None:
    """Show the current configuration."""
    _show_config(Config.load())


def _show_config(cfg: Config) -> None:
    key = (cfg.llm.api_key[:6] + "…") if cfg.llm.api_key else "(unset)"
    console.print(f"  ghidra   : {cfg.ghidra_path or '(unset)'}")
    console.print(f"  target   : {cfg.llm.target}")
    console.print(f"  base_url : {cfg.llm.base_url}")
    console.print(f"  model    : {cfg.llm.model}")
    console.print(f"  api_key  : {key}")


if __name__ == "__main__":
    cli()
