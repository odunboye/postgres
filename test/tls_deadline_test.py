"""Exercise TLS deadlines in an isolated, disposable local Postgres container."""
from pathlib import Path
import os
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
name = 'flux-pg-tls-' + uuid.uuid4().hex[:12]
created = False
with tempfile.TemporaryDirectory(prefix='flux-pg-tls-', dir='/tmp') as temporary:
    certs = Path(temporary)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(certs / 'server.key'), '-out', str(certs / 'server.crt'),
                    '-days', '1', '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'], check=True, timeout=20,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    command = '''set -eu
mkdir -p /tmp/tls
cp /input/server.key /input/server.crt /tmp/tls/
chown postgres:postgres /tmp/tls/server.key /tmp/tls/server.crt
chmod 600 /tmp/tls/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/tls/server.crt -c ssl_key_file=/tmp/tls/server.key -c ssl_ecdh_curve=prime256v1
'''
    try:
        subprocess.run(['docker', 'run', '--pull', 'never', '--rm', '-d', '--name', name,
                        '--cpus', '2', '--memory', '512m', '-p', '127.0.0.1::5432',
                        '-e', 'POSTGRES_USER=testuser', '-e', 'POSTGRES_PASSWORD=testpass',
                        '-e', 'POSTGRES_DB=testdb', '-v', str(certs) + ':/input:ro',
                        '--entrypoint', 'sh', 'postgres:16', '-c', command],
                       check=True, timeout=30, stdout=subprocess.DEVNULL)
        created = True
        for _ in range(60):
            ready = subprocess.run(['docker', 'exec', name, 'pg_isready', '-h', '127.0.0.1', '-U', 'testuser', '-d', 'testdb'],
                                   timeout=5, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('disposable TLS database failed to start')
        address = subprocess.check_output(['docker', 'port', name, '5432/tcp'], text=True, timeout=5).strip()
        port = address.rsplit(':', 1)[1]
        app = ROOT / 'test/build/exec/postgres-tls-deadline-test_app'
        env = dict(os.environ, PG_TEST_PORT=port, PG_TEST_CA_FILE=str(certs / 'server.crt'), IDRIS2_INC_SRC=str(app),
                   LD_LIBRARY_PATH=str(app), DYLD_LIBRARY_PATH=str(app))
        subprocess.run([str(app / 'postgres-tls-deadline-test.so')], env=env, check=True, timeout=90)
    finally:
        if created:
            subprocess.run(['docker', 'rm', '-f', '-v', name], timeout=15, check=True,
                           stdout=subprocess.DEVNULL)
