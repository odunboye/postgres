"""Authenticated TLS: disposable PKI, adversarial peers and real PostgreSQL.
No credentials are sent to negative peers. All sockets/processes have deadlines.
"""
from pathlib import Path
import concurrent.futures
import os
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / 'test/build/exec/idris2-pg-tls-identity-test_app'


def run(args, **kwargs):
    return subprocess.run(args, check=True, timeout=30, text=True, capture_output=True, **kwargs)


def openssl(directory, *args):
    return run(['openssl', *args], cwd=directory)


def pki(d):
    openssl(d, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-keyout', 'root.key', '-out', 'root.pem', '-days', '2', '-subj', '/CN=idris2-pg Test Root',
            '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
    openssl(d, 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', 'other.key', '-out', 'other.pem', '-days', '2', '-subj', '/CN=Other Root',
            '-addext', 'basicConstraints=critical,CA:TRUE')
    (d/'openssl.cnf').write_text(f'''openssl_conf=init
[init]
ssl_conf=ssl
[ssl]
system_default=defaults
[defaults]
VerifyCAFile={d/'root.pem'}
''')
    openssl(d, 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-keyout', 'intermediate.key', '-out', 'intermediate.csr', '-subj', '/CN=idris2-pg Test Intermediate')
    (d/'ca.ext').write_text('basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n')
    openssl(d, 'x509', '-req', '-in', 'intermediate.csr', '-CA', 'root.pem', '-CAkey', 'root.key',
            '-CAcreateserial', '-days', '2', '-extfile', 'ca.ext', '-out', 'intermediate.pem')
    (d/'index').write_text('')
    (d/'serial').write_text('1000\n')
    (d/'ca.cnf').write_text('''[ca]
default_ca=test
[test]
database=index
serial=serial
new_certs_dir=.
certificate=intermediate.pem
private_key=intermediate.key
default_md=sha256
default_days=1
policy=policy
unique_subject=no
[policy]
commonName=supplied
''')
    variants = {
        'valid': ('DNS:localhost,IP:127.0.0.1', 'serverAuth'),
        'mismatch': ('DNS:wrong.example,IP:127.0.0.2', 'serverAuth'),
        'expired': ('DNS:localhost,IP:127.0.0.1', 'serverAuth'),
        'future': ('DNS:localhost,IP:127.0.0.1', 'serverAuth'),
        'usage': ('DNS:localhost,IP:127.0.0.1', 'clientAuth'),
        'cn-only': ('', 'serverAuth'),
        'dns-ip': ('DNS:127.0.0.1', 'serverAuth'),
        'partial': ('DNS:local*', 'serverAuth'),
    }
    for name, (san, usage) in variants.items():
        openssl(d, 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-keyout', name+'.key', '-out', name+'.csr', '-subj', '/CN=localhost')
        ext = f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\n'
        if san: ext += f'subjectAltName={san}\n'
        (d/'leaf.ext').write_text('[leaf]\n'+ext)
        dates = []
        if name == 'expired': dates = ['-startdate', '20200101000000Z', '-enddate', '20210101000000Z']
        if name == 'future': dates = ['-startdate', '20990101000000Z', '-enddate', '20990102000000Z']
        openssl(d, 'ca', '-batch', '-config', 'ca.cnf', '-notext', '-in', name+'.csr', '-out', name+'.pem',
                '-extfile', 'leaf.ext', '-extensions', 'leaf', *dates)
        (d/(name+'.chain')).write_text((d/(name+'.pem')).read_text()+(d/'intermediate.pem').read_text())


def probe(port, host, mode, ca, extra=None):
    env = dict(os.environ, PG_TLS_HOST=host, PG_TLS_PORT=str(port), PG_TLS_MODE=mode,
               IDRIS2_INC_SRC=str(APP), LD_LIBRARY_PATH=str(APP), DYLD_LIBRARY_PATH=str(APP))
    env.pop('PG_TLS_CA', None)
    # Do not inherit an accidental development trust override.
    env.pop('SSL_CERT_FILE', None)
    env.pop('SSL_CERT_DIR', None)
    env.pop('OPENSSL_CONF', None)
    if ca is not None: env['PG_TLS_CA'] = str(ca)
    if extra: env.update(extra)
    command = ([sys.executable, str(ROOT/'test/tls_native_probe.py')]
               if '--native-only' in sys.argv else [str(APP/'idris2-pg-tls-identity-test.so')])
    result = run(command, env=env)
    assert 'PASS' in result.stdout, result.stdout
    return result.stdout


def peer_case(d, name, host='localhost', ca='root.pem', mode='reject', protocol=None, chain=True, reason=None, extra=None):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = protocol or ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(str(d/(name+('.chain' if chain else '.pem'))), str(d/(name+'.key')))
    seen_sni = []
    context.set_servername_callback(lambda sock, server_name, ctx: seen_sni.append(server_name))
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(5)
        def serve():
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(3)
                request = b''
                while len(request) < 8:
                    chunk = conn.recv(8-len(request))
                    if not chunk: break
                    request += chunk
                assert request == bytes.fromhex('0000000804d2162f'), request
                conn.sendall(b'S')
                try:
                    with context.wrap_socket(conn, server_side=True) as secure:
                        data = secure.recv(4096)
                        assert not data, 'probe sent application bytes before/without identity acceptance'
                except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
                    pass  # expected certificate rejection/abrupt close without close_notify
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(serve)
            output = probe(listener.getsockname()[1], host, mode, d/ca if ca else None, extra)
            future.result(timeout=5)
        if reason: assert reason.lower() in output.lower(), output
        if mode == 'ok': assert seen_sni == ([None] if host == '127.0.0.1' else [host]), seen_sni
        print(f'PASS TLS peer {name}: {host}, {mode}, chain={chain}, ca={ca}')


def raw_case(response, mode):
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(5)
        def serve():
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(3)
                data = b''
                while len(data) < 8:
                    chunk = conn.recv(8-len(data))
                    assert chunk, 'client closed before SSLRequest'
                    data += chunk
                conn.sendall(response)
                if response == b'S':
                    # Consume ClientHello then withhold the handshake indefinitely
                    # relative to the client's 500ms budget; EOF proves joined close.
                    while conn.recv(65536): pass
                else:
                    assert conn.recv(4096) == b'', 'plaintext fallback after SSL refusal'
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(serve)
            before = time.monotonic()
            probe(listener.getsockname()[1], 'localhost', mode, None)
            elapsed = time.monotonic()-before
            future.result(timeout=5)
        assert elapsed < 3, elapsed
        if mode == 'timeout': assert elapsed >= .45, elapsed
        print(f'PASS TLS negotiation {response!r}: {mode}, joined close in {elapsed:.2f}s')


def database(d):
    name = 'flux-verified-tls-' + uuid.uuid4().hex[:12]
    created = False
    command = '''set -eu
mkdir -p /tmp/tls
cp /input/valid.key /tmp/tls/server.key
cp /input/valid.chain /tmp/tls/server.crt
chown -R postgres:postgres /tmp/tls
chmod 600 /tmp/tls/server.key
exec docker-entrypoint.sh postgres -c ssl=on -c ssl_min_protocol_version=TLSv1.3 -c ssl_cert_file=/tmp/tls/server.crt -c ssl_key_file=/tmp/tls/server.key
'''
    try:
        run(['docker', 'run', '--pull', 'never', '--rm', '-d', '--name', name,
             '-p', '127.0.0.1::5432', '-e', 'POSTGRES_USER=testuser', '-e', 'POSTGRES_PASSWORD=testpass',
             '-e', 'POSTGRES_DB=testdb', '-v', str(d)+':/input:ro', '--entrypoint', 'sh', 'postgres:16', '-c', command])
        created = True
        for _ in range(80):
            try:
                run(['docker','exec',name,'pg_isready','-h','127.0.0.1','-U','testuser','-d','testdb']); break
            except subprocess.CalledProcessError: time.sleep(.2)
        else: raise RuntimeError('TLS PostgreSQL startup timed out')
        port = run(['docker','port',name,'5432/tcp']).stdout.strip().rsplit(':',1)[1]
        for host in ['localhost', '127.0.0.1']:
            print(probe(port, host, 'database', d/'root.pem'), end='')
        app_env = dict(PGHOST='localhost', PGPORT=port, PGUSER='testuser',
                       PGPASSWORD='testpass', PGDATABASE='testdb',
                       PGSSLMODE='verify-full', PGSSLROOTCERT=str(d/'root.pem'))
        print(probe(port, 'localhost', 'appconfig', None, app_env), end='')
        for mode in ['require', 'prefer', 'allow', 'verify-ca', 'disable', 'invalid']:
            try:
                probe(port, 'localhost', 'appconfig', None, dict(app_env, PGSSLMODE=mode))
            except subprocess.CalledProcessError as error:
                assert 'PGSSLMODE' in error.stdout or 'conflicts' in error.stdout, error.stdout
            else: raise AssertionError(f'unsafe/conflicting application TLS mode accepted: {mode}')
        print('PASS application rejects weaker/unknown TLS modes and CA/plaintext conflict')
        # OpenSSL's default trust path honors deployment-provided SSL_CERT_FILE.
        print(probe(port, 'localhost', 'database', None,
                    {'SSL_CERT_FILE': str(d/'root.pem'), 'SSL_CERT_DIR': str(d/'empty-trust')}), end='')
    finally:
        if created: run(['docker','rm','-f','-v',name])


def main():
    with tempfile.TemporaryDirectory(prefix='flux-verified-tls-', dir='/tmp') as temp:
        d = Path(temp); pki(d); (d/'empty-trust').mkdir()
        for host in ['localhost', '127.0.0.1']: peer_case(d, 'valid', host, mode='ok')
        peer_case(d, 'valid', ca=None, reason='certificate')
        peer_case(d, 'valid', chain=False, reason='certificate')
        peer_case(d, 'valid', ca='missing.pem', reason='CA file')
        peer_case(d, 'valid', ca='other.pem', reason='certificate', extra={
            'OPENSSL_CONF': str(d/'openssl.cnf'), 'SSL_CERT_FILE': str(d/'root.pem'),
            'SSL_CERT_DIR': str(d/'empty-trust')})
        for host in ['localhost', '127.0.0.1']: peer_case(d, 'mismatch', host, reason='mismatch')
        peer_case(d, 'expired', reason='expired')
        peer_case(d, 'future', reason='not yet valid')
        peer_case(d, 'usage', reason='purpose')
        peer_case(d, 'cn-only', reason='mismatch')
        peer_case(d, 'dns-ip', '127.0.0.1', reason='mismatch')
        peer_case(d, 'partial', reason='mismatch')
        peer_case(d, 'valid', protocol=ssl.TLSVersion.TLSv1_2)
        raw_case(b'N', 'reject'); raw_case(b'X', 'reject'); raw_case(b'S', 'timeout')
        if '--native-only' not in sys.argv: database(d)
    print('PASS native TLS bridge certificate matrix (no Idris/database run)' if '--native-only' in sys.argv
          else 'PASS authenticated PostgreSQL TLS identity integration')


if __name__ == '__main__': main()
