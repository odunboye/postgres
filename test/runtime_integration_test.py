"""Fail the existing PG smoke suite on either process errors or printed FAILs."""
from pathlib import Path
import os
import subprocess
root = Path(__file__).resolve().parents[1]
app = root / 'test/build/exec/postgres-test_app'
env = dict(os.environ, IDRIS2_INC_SRC=str(app), LD_LIBRARY_PATH=str(app), DYLD_LIBRARY_PATH=str(app))
result = subprocess.run([str(app / 'postgres-test.so')], env=env,
                        text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
print(result.stdout, end='')
assert result.returncode == 0, result.returncode
assert 'FAIL' not in result.stdout, 'PG integration suite reported failures'
