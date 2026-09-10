"""Create SHA256SUMS for precisely this build's wheel and source distribution."""
import hashlib
from pathlib import Path

directory = Path(__file__).resolve().parents[1] / "dist"
paths = [directory / "cerberus_cyber_eval-0.1.0rc1-py3-none-any.whl",
         directory / "cerberus_cyber_eval-0.1.0rc1.tar.gz"]
lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in paths]
(directory / "SHA256SUMS").write_text("\n".join(lines) + "\n")
print("\n".join(lines))
