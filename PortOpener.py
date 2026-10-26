"""Open a TCP listener on a chosen port - used to test the FOCUS scanner.

    python PortOpener.py 5555       # port as an argument (demo friendly)
    python PortOpener.py            # or enter it interactively
"""
import contextlib
import socket
import sys

if len(sys.argv) > 1:
    argument = sys.argv[1]
    try:
        port = int(argument)
    except ValueError:
        raise SystemExit(f'port must be an integer, got {argument!r}')
else:
    try:
        port = int(input('Enter port to be opened: '))
    except ValueError:
        raise SystemExit('port must be an integer')

if not 1 <= port <= 65535:
    raise SystemExit('port must be between 1 and 65535')

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(('localhost', port))
except OSError as error:
    sock.close()
    raise SystemExit(f'cannot open port {port}: {error}')

sock.listen()
print(f"Listening on port {port} (ctrl-c to stop)")

try:
    while True:
        conn, addr = sock.accept()
        print(f"Accepted connection from {addr}")
        with contextlib.suppress(OSError):
            conn.close()
except KeyboardInterrupt:
    pass
finally:
    sock.close()
