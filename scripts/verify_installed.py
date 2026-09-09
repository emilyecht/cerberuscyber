"""Run using the clean installed environment's Python with -I.

Does not import the repository, install dependencies, or contact external targets.
"""
import argparse
from importlib import metadata, resources
import json
from pathlib import Path
import subprocess
import sys
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("--repo-root", type=Path, required=True)
args = parser.parse_args()

import cerberus
import sdk.shared_types.action_envelope

for module in (cerberus, sdk.shared_types.action_envelope):
    if Path(module.__file__).resolve().is_relative_to(args.repo_root.resolve()):
        raise RuntimeError("source checkout leaked into installed-artifact verification")
with tempfile.TemporaryDirectory(prefix="cerberus-installed-") as directory:
    command = Path(sys.executable).with_name("cerberus-cyber.exe" if sys.platform == "win32" else "cerberus-cyber")
    proc = subprocess.run([str(command), "demo", "--json"], cwd=directory, text=True, capture_output=True, check=True)
    output = json.loads(proc.stdout)
    assert output["mode"] == "simulation-only" and output["cases_passed"] == 4
    assert output["receipt"]["side_effects"] is False
    assert output["token_version"] == "1.3.0"
for schema in ("action-envelope", "decision-token", "policy-bundle"):
    json.loads(resources.files("cerberus").joinpath(f"data/schemas/{schema}.schema.json").read_text())
from jsonschema import Draft202012Validator, FormatChecker
schema = json.loads(resources.files("cerberus").joinpath("data/schemas/action-envelope.schema.json").read_text())
Draft202012Validator(schema, format_checker=FormatChecker()).validate(output["request"])
assert metadata.version("cerberus-cyber-eval") == "0.1.0rc1"
print(json.dumps({"installed_artifact": "passed", "version": metadata.version("cerberus-cyber-eval"),
                  "cases_passed": output["cases_passed"], "source_checkout_imported": False,
                  "python": sys.version.split()[0]}, sort_keys=True))
