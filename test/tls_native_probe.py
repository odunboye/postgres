"""Native bridge probe for Linux without an Idris compiler; not an Idris test."""
import ctypes
import os
from pathlib import Path
import socket
import sys

root = Path(__file__).resolve().parents[1]
suffix = 'dylib' if sys.platform == 'darwin' else 'so'
lib = ctypes.CDLL(str(root / f'lib/libidris2_pg_transport.{suffix}'))
lib.pg_deadline_push.argtypes = [ctypes.c_int]
lib.pg_deadline_push.restype = ctypes.c_int64
lib.pg_deadline_restore.argtypes = [ctypes.c_int64]
lib.pg_socket_connect.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
lib.pg_socket_send.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
lib.pg_socket_receive.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
lib.pg_tls_new.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p]
lib.pg_tls_new.restype = ctypes.c_void_p
lib.pg_tls_handshake.argtypes = [ctypes.c_void_p]
lib.pg_tls_error.argtypes = [ctypes.c_void_p]
lib.pg_tls_error.restype = ctypes.c_char_p
lib.pg_tls_free.argtypes = [ctypes.c_void_p]

host = os.environ['PG_TLS_HOST'].encode()
port = int(os.environ['PG_TLS_PORT'])
mode = os.environ['PG_TLS_MODE']
previous = lib.pg_deadline_push(500)
pointer = None
accepted = False
try:
    with socket.socket() as sock:
        assert lib.pg_socket_connect(sock.fileno(), host, port) == 0
        request = ctypes.create_string_buffer(bytes.fromhex('0000000804d2162f'))
        assert lib.pg_socket_send(sock.fileno(), request, 8) == 8
        response = ctypes.create_string_buffer(1)
        assert lib.pg_socket_receive(sock.fileno(), response, 1) == 1
        if response.raw == b'S':
            pointer = lib.pg_tls_new(sock.fileno(), host, os.environ.get('PG_TLS_CA', '').encode())
            assert pointer
            accepted = lib.pg_tls_handshake(pointer) == 0
            if not accepted: print(lib.pg_tls_error(pointer).decode())
        expired = bool(lib.pg_deadline_expired())
        assert ((mode == 'ok' and accepted and not expired) or
                (mode == 'reject' and not accepted and not expired) or
                (mode == 'timeout' and not accepted and expired)), (mode, accepted, expired)
        print('PASS native TLS bridge', mode)
finally:
    if pointer: lib.pg_tls_free(pointer)
    lib.pg_deadline_restore(previous)
