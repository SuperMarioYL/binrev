"""Ghidra headless bridge.

Runs ``analyzeHeadless`` with an embedded Jython dump script that exports
the function list, decompilation, cross-references and strings to JSON, then
hands that JSON back to :mod:`binrev.binst` to hydrate a :class:`BinState`.

This is the *rich* backend (real decompiled C, struct-aware xrefs).  When
Ghidra is not installed binrev falls back to the capstone backend in
``binst.build_from_bytes`` so ``inspect`` still works out of the box.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .binst import BinState, build_from_ghidra_json
from .models import ISAKind, default_isa

# The Jython dump script run inside Ghidra's headless analyzer.  It walks the
# function listing, decompiles each (FlatAPI + DecompInterface), collects
# call/data xrefs and strings, and writes one JSON file.
_DUMP_SCRIPT = """\
import json, os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

mon = ConsoleTaskMonitor()
listing = currentProgram.getListing()
fm = currentProgram.getFunctionManager()
ref_mgr = currentProgram.getReferenceManager()
space = currentProgram.getAddressFactory().getDefaultAddressSpace()

dec = DecompInterface()
dec.openProgram(currentProgram)

funcs = []
xrefs = []
strings = []

for fn in fm.getFunctions(True):
    addr = int(fn.getEntryPoint().toString(), 16)
    dec_out = dec.decompileFunction(fn, 30, mon)
    c_code = dec_out.getDecompiledFunction().getC() if dec_out and dec_out.getDecompiledFunction() else ""
    funcs.append({
        "addr": addr,
        "name": fn.getName(),
        "size": fn.getBody().getNumAddresses(),
        "decompilation": c_code,
        "instructions": [],
    })
    # call/data xrefs TO this function entry
    for ref in ref_mgr.getReferencesTo(fn.getEntryPoint()):
        xrefs.append({
            "from_addr": int(ref.getFromAddress().toString(), 16),
            "to_addr": addr,
            "kind": "call" if ref.getReferenceType().isCall() else "data",
        })

# strings
for data in listing.getDefinedData(True):
    if data.getDataType().getName().startswith("string") or data.getValue() is not None:
        try:
            v = str(data.getValue())
            if len(v) >= 4:
                strings.append({"addr": int(data.getAddress().toString(), 16), "value": v})
        except Exception:
            pass

isa_kind = "arm"
lang = currentProgram.getLanguage().getLanguageID().toString()
if "ARM" in lang or "AARCH64" in lang:
    isa_kind = "aarch64" if "64" in lang else "arm"

out = {
    "isa": {"kind": isa_kind, "registers": [], "calling_convention": ""},
    "base_addr": int(currentProgram.getImageBase().toString(), 16),
    "entry": int(currentProgram.getImageBase().toString(), 16),
    "functions": {str(f["addr"]): f for f in funcs},
    "xrefs": xrefs,
    "strings": strings,
    "notes": {},
    "source": "ghidra",
}
with open(os.environ["BINREV_DUMP_OUT"], "w") as fh:
    json.dump(out, fh)
dec.dispose()
"""


@dataclass
class GhidraBridge:
    """Run Ghidra ``analyzeHeadless`` to dump a binary to JSON.

    ``ghidra_path`` points at the Ghidra install dir (the one containing
    ``support/analyzeHeadless``).  Configure via ``binrev config set --ghidra``.
    """

    ghidra_path: Optional[Path] = None
    project_dir: Path = Path(tempfile.gettempdir()) / "binrev-ghidra-projects"

    def analyze_headless_path(self) -> Optional[Path]:
        if self.ghidra_path is None:
            return None
        cand = self.ghidra_path / "support" / "analyzeHeadless"
        return cand if cand.exists() else None

    def is_available(self) -> bool:
        """True if a Ghidra install is configured and reachable."""
        exe = self.analyze_headless_path()
        return exe is not None and os.access(exe, os.X_OK)

    def dump(self, binary: Path, isa_kind: ISAKind = ISAKind.ARM) -> BinState:
        """Dump ``binary`` to a :class:`BinState` via Ghidra headless.

        Raises :class:`RuntimeError` if Ghidra is not installed.
        """
        exe = self.analyze_headless_path()
        if exe is None:
            raise RuntimeError(
                "Ghidra is not configured — run `binrev config set --ghidra <path>` "
                "or rely on the capstone backend (no decompiled C)."
            )
        self.project_dir.mkdir(parents=True, exist_ok=True)
        project = "binrev_proj"
        with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as fh:
            fh.write(_DUMP_SCRIPT.encode())
            script_path = Path(fh.name)
        out_json = Path(tempfile.mktemp(suffix=".json"))
        try:
            env = dict(os.environ, BINREV_DUMP_OUT=str(out_json))
            cmd = [
                str(exe),
                str(self.project_dir),
                project,
                "-import", str(binary),
                "-overwrite",
                "-scriptPath", str(script_path.parent),
                "-postScript", script_path.name,
                "-deleteProject",
            ]
            subprocess.run(cmd, check=True, env=env, capture_output=True, text=True)
            if not out_json.exists():
                raise RuntimeError("Ghidra dump produced no JSON (script failed)")
            state = build_from_ghidra_json(out_json)
            # Ensure ISA metadata is populated for the configured family.
            if not state.isa.registers:
                state.isa = default_isa(isa_kind)
            return state
        finally:
            script_path.unlink(missing_ok=True)
            out_json.unlink(missing_ok=True)
