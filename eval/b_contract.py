"""One place to import Person B's shared files: check_interface.py and prompt.py.

They live at the repo root on B's branch (issue #6). Until B's branch is merged into main
(and main into person-c-eval), they are not in this branch, so we also look in the folder
named by the environment variable GULLHACK_B_DIR. That lets you test against B's real files
without copying them into eval/ or committing them on this branch.

Example (run from the repo root):
  mkdir -p ../b-contract
  git show origin/person-b-checks:check_interface.py > ../b-contract/check_interface.py
  git show origin/person-b-checks:prompt.py > ../b-contract/prompt.py
  export GULLHACK_B_DIR=../b-contract
"""
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

for _folder in (REPO_ROOT, os.environ.get("GULLHACK_B_DIR")):
    if _folder and str(Path(_folder).resolve()) not in sys.path:
        sys.path.append(str(Path(_folder).resolve()))  # appended, so eval/ modules always win a name clash

try:
    from check_interface import BaseCheck, CheckResult, SecurityContext  # noqa: E402,F401
    from prompt import PROTECTED_POLICIES, build_system_prompt, get_static_secret_values  # noqa: E402,F401
except ImportError as err:
    # ModuleNotFoundError (a kind of ImportError) lets pytest.importorskip skip tests cleanly.
    raise ModuleNotFoundError(
        "Person B's check_interface.py / prompt.py not found. Merge B's branch, or set GULLHACK_B_DIR "
        "(see the top of eval/b_contract.py)."
    ) from err
