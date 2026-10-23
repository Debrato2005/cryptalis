"""Bounded localhost SMTP capture for public application fixtures."""

from contextlib import contextmanager
from email.utils import parseaddr
from queue import Queue
import socket
import socketserver
from threading import Lock, Thread


@contextmanager
def capture_smtp():
    """Yield (host, port, messages) without external delivery or message logs."""
    messages, errors = Queue(maxsize=32), Queue(maxsize=1)
    lock = Lock()

    class Handler(socketserver.StreamRequestHandler):
        def line(self, *, between_commands=False):
            try:
                line = self.rfile.readline(8193)
            except TimeoutError:
                if between_commands:
                    return None
                raise
            if not line and between_commands:
                return None
            if len(line) > 8192 or not line.endswith(b'\r\n'):
                raise ValueError('SMTP line limit or terminator failed.')
            return line

        def reply(self, message):
            self.wfile.write(message + b'\r\n')
            self.wfile.flush()

        def handle(self):
            self.connection.settimeout(3)
            self.reply(b'220 localhost fixture SMTP')
            sender, recipients = False, []
            for _ in range(256):
                line = self.line(between_commands=not sender and not recipients)
                if line is None:
                    return
                command, _, argument = line[:-2].partition(b' ')
                command = command.upper()
                if command in (b'EHLO', b'HELO'):
                    sender, recipients = False, []
                    self.reply(b'250-localhost\r\n250 8BITMIME')
                elif command in (b'MAIL', b'RCPT'):
                    prefix = b'FROM:' if command == b'MAIL' else b'TO:'
                    if not argument.upper().startswith(prefix) or (command == b'RCPT' and not sender):
                        raise ValueError('SMTP envelope order or syntax failed.')
                    address = parseaddr(argument[len(prefix):].decode('ascii'))[1]
                    if not address or (command == b'RCPT' and len(recipients) >= 32):
                        raise ValueError('SMTP recipient or envelope limit failed.')
                    if command == b'MAIL':
                        sender, recipients = True, []
                    else:
                        recipients.append(address)
                    self.reply(b'250 accepted')
                elif command == b'DATA':
                    if not sender or not recipients:
                        raise ValueError('SMTP DATA requires a complete envelope.')
                    self.reply(b'354 end with dot')
                    data = bytearray()
                    while True:
                        part = self.line()
                        if part == b'.\r\n':
                            break
                        data.extend(part[1:] if part.startswith(b'..') else part)
                        if len(data) > 1024 * 1024:
                            raise ValueError('SMTP message exceeds the fixture limit.')
                    messages.put_nowait({'data': bytes(data), 'recipients': tuple(recipients)})
                    sender, recipients = False, []
                    self.reply(b'250 captured')
                elif command == b'RSET':
                    sender, recipients = False, []
                    self.reply(b'250 reset')
                elif command == b'NOOP':
                    self.reply(b'250 ok')
                elif command == b'QUIT':
                    self.reply(b'221 bye')
                    return
                else:
                    self.reply(b'500 unsupported fixture command')
                    raise ValueError('Unexpected SMTP fixture command.')
            raise ValueError('SMTP command limit exceeded.')

    class Server(socketserver.ThreadingTCPServer):
        active, stopping = set(), False

        def verify_request(self, request, client_address):
            with lock:
                if len(self.active) >= 8:
                    if errors.empty():
                        errors.put_nowait('SMTP fixture connection limit exceeded.')
                    return False
                self.active.add(request)
                return True

        def shutdown_request(self, request):
            try:
                super().shutdown_request(request)
            finally:
                with lock:
                    self.active.discard(request)

        def handle_error(self, request, client_address):
            with lock:
                if not self.stopping and errors.empty():
                    errors.put_nowait('SMTP capture failed. Check the local fixture protocol and limits.')

    server = Server(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
    thread.start()
    try:
        yield (*server.server_address, messages)
    finally:
        with lock:
            server.stopping = True
        server.shutdown()
        with lock:
            active = tuple(server.active)
        for connection in active:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError('SMTP fixture thread did not stop.')
        if not errors.empty():
            raise RuntimeError(errors.get_nowait())
