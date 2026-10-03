"""Bounded real-Postgres ownership tests, invoking Chez without a shell child."""
from pathlib import Path
import os
import subprocess
import sys
root = Path(__file__).resolve().parents[1]
app = root / 'async/build/exec/postgres-pool-test_app'
env = dict(os.environ, IDRIS2_INC_SRC=str(app), LD_LIBRARY_PATH=str(app), DYLD_LIBRARY_PATH=str(app))
process = subprocess.Popen([str(app / 'postgres-pool-test.so')], env=env)
try:
    code = process.wait(timeout=12 if '--sample' in sys.argv else 45)
    if code:
        raise subprocess.CalledProcessError(code, process.args)
except subprocess.TimeoutExpired:
    try:
      if '--sample' in sys.argv:
        subprocess.run(['/usr/bin/sample', str(process.pid), '1', '-file', '/tmp/flux-pool-stall.sample'], timeout=5, check=False)
    finally:
      process.kill()
      process.wait()
    raise
