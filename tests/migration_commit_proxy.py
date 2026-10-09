"""Real PostgreSQL fault injection: discard one already-committed reply."""
from contextlib import contextmanager
import socket
import threading
import psycopg


def receive(sock, count):
    value=b''
    while len(value)<count:
        part=sock.recv(count-len(value))
        if not part: raise EOFError
        value+=part
    return value


@contextmanager
def lost_commit_reply(url, commit_number=None, drop_after_sql=None, pause_after_sql=None, pause_events=None):
    info=psycopg.conninfo.conninfo_to_dict(url)
    listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1)
    dropped=threading.Event(); errors=[]; counter=[0]
    def serve():
        client=None; server=None
        try:
            client,_=listener.accept()
            server=socket.create_connection((info['host'],int(info['port'])),timeout=10)
            # Client SSL is disabled for this test-only local transport.
            length=receive(client,4); packet=receive(client,int.from_bytes(length,'big')-4)
            server.sendall(length+packet)
            # Startup messages until ReadyForQuery.
            while True:
                typ=receive(server,1); length=receive(server,4); payload=receive(server,int.from_bytes(length,'big')-4)
                client.sendall(typ+length+payload)
                if typ in (b'R',):
                    authentication=int.from_bytes(payload[:4],'big')
                    if authentication not in (0,):
                        # Pass SCRAM/password messages both directions. SCRAM
                        # uses R challenges; final R(0) needs no client reply.
                        if authentication in (3,5,10,11):
                            t=receive(client,1); l=receive(client,4); p=receive(client,int.from_bytes(l,'big')-4)
                            server.sendall(t+l+p)
                if typ==b'Z': break
            matched=False; paused=False
            while True:
                typ=receive(client,1); length=receive(client,4); payload=receive(client,int.from_bytes(length,'big')-4)
                server.sendall(typ+length+payload)
                if drop_after_sql and typ in (b'Q',b'P') and drop_after_sql.encode() in payload: matched=True
                if pause_after_sql and typ in (b'Q',b'P') and pause_after_sql.encode() in payload: paused=True
                if typ==b'X': break
                is_commit=typ==b'Q' and payload.rstrip(b'\0').strip().upper()==b'COMMIT'
                if is_commit: counter[0]+=1
                discard=(is_commit and counter[0]==commit_number) or matched
                # Extended queries are pipelined to Sync, then receive replies.
                if typ!=b'Q' and typ!=b'S': continue
                buffered=[]
                while True:
                    t=receive(server,1); l=receive(server,4); p=receive(server,int.from_bytes(l,'big')-4)
                    if paused: buffered.append(t+l+p)
                    elif not discard: client.sendall(t+l+p)
                    if t==b'Z': break
                if paused:
                    ready,resume=pause_events; ready.set()
                    if not resume.wait(10): raise TimeoutError('test observation did not resume')
                    client.sendall(b''.join(buffered)); paused=False
                if discard:
                    # Backend is now idle: original COMMIT is terminal. Close
                    # before the client receives CommandComplete/ReadyForQuery.
                    dropped.set(); break
        except EOFError: pass
        except Exception as exc: errors.append(type(exc).__name__)
        finally:
            if client: client.close()
            if server: server.close()
    thread=threading.Thread(target=serve,daemon=True); thread.start()
    proxied=psycopg.conninfo.make_conninfo(url,host='127.0.0.1',port=listener.getsockname()[1],sslmode='disable',gssencmode='disable')
    try: yield proxied,dropped
    finally:
        listener.close(); thread.join(timeout=15)
        assert not thread.is_alive(),'test proxy did not finish'
        assert not errors,errors
