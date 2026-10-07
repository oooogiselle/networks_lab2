import os
import re
import resource
import socket
import sys
import threading
import time
from urllib.parse import unquote_to_bytes

'''
    Hardened HTTP/1.1 GET server using raw sockets (one thread per connection)

    Author: Giselle Wu, Dartmouth CS60, Fall 2026
            Starter template by Tim Pierson (receive_tcp_multithreaded.py),
            assisted by Microsoft Copilot
            Assisted by Claude (Anthropic): wrote the HTTP parsing and the hardening (framing checks,
            size limits, timeouts, path safety, connection eviction)

    run: python3 server.py <port>

    Serves files from the directory the server is started in.
    test with the client (replace IP address and port):
    python3 client.py 127.0.0.1 8080 helloworld.html
'''

#define host ip and port
HOST = '0.0.0.0' #'127.0.0.1' #localhost

RECV_SIZE = 4096
SEND_CHUNK = 64 * 1024

#concurrency limits. every connection costs a thread and a file descriptor, so cap how many
#we serve at once. the cap must stay under the OS limit on open files (only 256 by default
#on macOS), or accept() itself starts failing and nobody gets served
def connection_limit(wanted):
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = 4096 if hard == resource.RLIM_INFINITY else min(hard, 4096)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            soft = target
    except (ValueError, OSError):
        return wanted
    return max(10, min(wanted, soft - 50)) #leave room for files we open and the listen socket

MAX_CONNECTIONS = connection_limit(500)
BUSY_THRESHOLD = MAX_CONNECTIONS // 2 #above this many open connections, give clients less time

#timeouts (seconds). the request timeout is a deadline for the WHOLE request, not per recv(),
#so a slowloris client trickling one byte every second still gets cut off
REQUEST_TIMEOUT = 5.0  #time to send one complete request (headers + body)
BUSY_TIMEOUT = 2.0     #same, but used while the server is under load
IDLE_TIMEOUT = 5.0     #time a keep-alive connection may sit idle between requests
SEND_TIMEOUT = 10.0    #time to send a response to a client that won't read it

#size limits. every byte we read from the socket is bounded by one of these
MAX_REQUEST_LINE = 8192 #-> 414
MAX_URI = 2048          #-> 414
MAX_HEADER_BYTES = 16384 #-> 431
MAX_HEADERS = 100       #-> 431
MAX_BODY = 1024 * 1024  #-> 413
MAX_CHUNK_LINE = 1024   #a chunk-size line ("1a;ext\r\n") longer than this is bogus

REASONS = {200: "OK", 400: "Bad Request", 403: "Forbidden", 404: "Not Found",
           408: "Request Timeout", 413: "Content Too Large", 414: "URI Too Long",
           431: "Request Header Fields Too Large", 501: "Not Implemented",
           503: "Service Unavailable", 505: "HTTP Version Not Supported"}

#content types for the files we expect to serve; anything else is sent as raw bytes
CONTENT_TYPES = {".html": "text/html", ".txt": "text/plain"}

#the directory we serve, resolved once at startup. no file outside it is ever opened
ROOT = os.path.realpath(os.getcwd())
SERVER_SOURCE = os.path.realpath(__file__)
SOURCE_EXTS = {".py", ".pyc"}

#tokens are the characters allowed in methods and header names (RFC 9110 section 5.6.2)
TOKEN = re.compile(rb"[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
VERSION = re.compile(rb"HTTP/(\d)\.(\d)")
HEX = re.compile(rb"[0-9A-Fa-f]{1,8}")
DIGITS = re.compile(rb"[0-9]+")
CONTROL_CHARS = re.compile(rb"[\x00-\x08\x0a-\x1f\x7f]") #everything but tab

active_lock = threading.Lock()
active_connections = 0
#sockets currently waiting to receive a request -> when they started waiting. when we're
#full, the one that has waited longest is almost certainly a slow attacker, so we evict it
waiting = {}


#raised anywhere in parsing to send an error status and close the connection
class HTTPError(Exception):
    def __init__(self, code, reason=""):
        super().__init__(reason)
        self.code = code

#raised when the client closes the connection mid-request
class ClientClosed(Exception):
    pass


#a socket plus its per-connection buffer. tcp is a byte stream, so a recv() can return
#part of a request or several requests; bytes we haven't parsed yet wait in buf
class Connection:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    #read more bytes into buf, but never past the deadline
    def fill(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout()
        self.sock.settimeout(remaining)
        data = self.sock.recv(RECV_SIZE)
        if not data: #empty bytes means the client sent FIN, not "no data yet"
            raise ClientClosed()
        self.buf += data

    #return one CRLF-terminated line (without the CRLF). a line longer than limit raises
    #too_long_code; a bare CR or bare LF raises 400, since lines MUST end in CRLF
    def read_line(self, deadline, limit, too_long_code):
        while True:
            end = self.buf.find(b"\r\n")
            if end != -1:
                line = self.buf[:end]
                if end > limit:
                    raise HTTPError(too_long_code, "line too long")
                if b"\r" in line or b"\n" in line:
                    raise HTTPError(400, "bare CR or LF")
                self.buf = self.buf[end + 2:]
                return line
            #no CRLF yet. an LF here can't be part of a CRLF, and a CR that isn't the
            #last byte isn't followed by LF, so either one is a bare line ending
            if b"\n" in self.buf or b"\r" in self.buf[:-1]:
                raise HTTPError(400, "bare CR or LF")
            if len(self.buf) > limit:
                raise HTTPError(too_long_code, "line too long")
            self.fill(deadline)

    #remove exactly n bytes from the stream and return them
    def read_exact(self, n, deadline):
        while len(self.buf) < n:
            self.fill(deadline)
        data, self.buf = self.buf[:n], self.buf[n:]
        return data


#read and validate one complete request, including its body, so the next request starts
#exactly where this one ends. returns (method, target, version, headers) or None if the
#connection should just close quietly (client hung up or sat idle)
def read_request(conn, busy):
    #wait for the first byte of the next request. an idle keep-alive connection that sends
    #nothing is closed silently; there's no half-finished request to answer with a 408
    if not conn.buf:
        try:
            conn.fill(time.monotonic() + IDLE_TIMEOUT)
        except (socket.timeout, ClientClosed):
            return None

    deadline = time.monotonic() + (BUSY_TIMEOUT if busy else REQUEST_TIMEOUT)
    try:
        return parse_request(conn, deadline)
    except socket.timeout:
        raise HTTPError(408, "client too slow")
    except ClientClosed:
        return None


def parse_request(conn, deadline):
    #request line: METHOD SP target SP VERSION. a long target shows up here as a long line.
    #skip a couple of stray empty lines first, which RFC 9112 section 2.2 allows
    for _ in range(3):
        line = conn.read_line(deadline, MAX_REQUEST_LINE, 414)
        if line:
            break
    else:
        raise HTTPError(400, "no request line")

    parts = line.split(b" ")
    if len(parts) != 3: #also catches double spaces, which leave an empty part
        raise HTTPError(400, f"bad request line: {line[:100]!r}")
    method, target, version = parts
    if not TOKEN.fullmatch(method):
        raise HTTPError(400, "bad method")
    v = VERSION.fullmatch(version)
    if not v:
        raise HTTPError(400, "bad version")
    if (v.group(1), v.group(2)) not in ((b"1", b"1"), (b"1", b"0")):
        raise HTTPError(505, "unsupported version")
    if method != b"GET":
        raise HTTPError(501, "unsupported method")
    if len(target) > MAX_URI:
        raise HTTPError(414, "target too long")
    if not target.startswith(b"/"):
        raise HTTPError(400, "target must start with /")

    #header fields: "Name: value". names are case-insensitive, so store them lowercased.
    #each name maps to a list so duplicates (e.g. two Content-Length) aren't silently lost
    headers = {}
    header_bytes = 0
    count = 0
    while True:
        line = conn.read_line(deadline, MAX_HEADER_BYTES - header_bytes, 431)
        if not line:
            break #blank line: end of headers
        header_bytes += len(line) + 2
        count += 1
        if count > MAX_HEADERS:
            raise HTTPError(431, "too many headers")
        if line[:1] in (b" ", b"\t"):
            raise HTTPError(400, "obsolete line folding") #RFC 9112 section 5.2
        name, sep, value = line.partition(b":")
        if not sep or not TOKEN.fullmatch(name): #no space allowed before the colon
            raise HTTPError(400, f"bad header line: {line[:100]!r}")
        value = value.strip(b" \t")
        if CONTROL_CHARS.search(value): #e.g. a NUL or a CR smuggled into a value
            raise HTTPError(400, "control character in header value")
        headers.setdefault(name.lower().decode(), []).append(value)

    #http/1.1 requires exactly one Host header
    hosts = headers.get("host", [])
    if len(hosts) > 1 or (version == b"HTTP/1.1" and len(hosts) != 1):
        raise HTTPError(400, "missing or duplicate Host")

    read_body(conn, headers, deadline)
    return method, target, version, headers


#consume the body exactly as its framing headers say, so no body bytes are left behind
#to be parsed as the next request. we never use a GET body; we just read past it
def read_body(conn, headers, deadline):
    lengths = headers.get("content-length")
    encodings = headers.get("transfer-encoding")

    #two framing headers disagree about where the body ends: request smuggling
    if lengths and encodings:
        raise HTTPError(400, "both Content-Length and Transfer-Encoding")

    if encodings:
        if len(encodings) > 1:
            raise HTTPError(400, "duplicate Transfer-Encoding")
        if encodings[0].lower() != b"chunked":
            raise HTTPError(501, "unsupported Transfer-Encoding")
        read_chunked(conn, deadline)
        return

    if lengths:
        #a second Content-Length, even an equal one, is ambiguous; don't guess
        if len(lengths) > 1:
            raise HTTPError(400, "duplicate Content-Length")
        #digits only: no sign, no spaces, no "5, 5", no hex
        if not DIGITS.fullmatch(lengths[0]):
            raise HTTPError(400, "invalid Content-Length")
        #compare the digit count first so a 10,000-digit number is never converted
        if len(lengths[0]) > 12 or int(lengths[0]) > MAX_BODY:
            raise HTTPError(413, "body too large")
        conn.read_exact(int(lengths[0]), deadline)


#chunked body: hex size CRLF, that many bytes, CRLF ... ending with a 0 chunk, then
#optional trailer fields and a blank line
def read_chunked(conn, deadline):
    total = 0
    while True:
        line = conn.read_line(deadline, MAX_CHUNK_LINE, 400)
        size = line.split(b";", 1)[0] #ignore chunk extensions
        if not HEX.fullmatch(size): #rejects "0x5", " 5", "-1", "" and huge sizes
            raise HTTPError(400, f"bad chunk size: {line[:50]!r}")
        size = int(size, 16)
        total += size
        if total > MAX_BODY:
            raise HTTPError(413, "chunked body too large")
        if size == 0:
            break
        conn.read_exact(size, deadline)
        if conn.read_exact(2, deadline) != b"\r\n":
            raise HTTPError(400, "chunk data not followed by CRLF")

    #trailer section, bounded like the headers
    trailer_bytes = 0
    while True:
        line = conn.read_line(deadline, MAX_HEADER_BYTES - trailer_bytes, 431)
        if not line:
            return
        trailer_bytes += len(line) + 2
        name, sep, _ = line.partition(b":")
        if not sep or not TOKEN.fullmatch(name):
            raise HTTPError(400, "bad trailer line")


#turn the request target into a safe absolute path inside ROOT, or raise 400/403
def resolve_path(target):
    path = target.split(b"?", 1)[0].split(b"#", 1)[0] #drop query string and fragment

    #percent-decode. do it repeatedly so double-encoding (%252e -> %2e -> .) can't hide
    #a "..", and refuse anything still encoded after a few rounds
    for _ in range(3):
        if b"%" not in path:
            break
        if re.search(rb"%(?![0-9A-Fa-f]{2})", path):
            raise HTTPError(400, "bad percent-encoding")
        path = unquote_to_bytes(path)
    if b"%" in path:
        raise HTTPError(403, "too many layers of percent-encoding")

    if b"\x00" in path or b"\\" in path: #null-byte truncation, windows-style separators
        raise HTTPError(403, "null byte or backslash in path")
    if CONTROL_CHARS.search(path):
        raise HTTPError(400, "control character in path")
    try:
        text = path.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPError(400, "path is not valid utf-8")

    segments = [s for s in text.split("/") if s]
    if any(s.startswith(".") for s in segments): #"..", ".git", ".env", ...
        raise HTTPError(403, "dot segment or dotfile")
    rel = "/".join(segments) or "index.html"
    if os.path.splitext(rel)[1].lower() in SOURCE_EXTS or "__pycache__" in segments:
        raise HTTPError(403, "source file")

    #resolve symlinks too, then make sure the result is still inside ROOT
    full = os.path.realpath(os.path.join(ROOT, rel))
    if os.path.commonpath([ROOT, full]) != ROOT or full == SERVER_SOURCE:
        raise HTTPError(403, "outside served directory")
    return full


#send a status line, headers and a blank line. never echoes anything from the request,
#so a CRLF in a request can't inject headers into our response (response splitting)
def send_head(sock, code, length, content_type, keep_alive):
    head = (f"HTTP/1.1 {code} {REASONS[code]}\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {length}\r\n"
            f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n"
            f"\r\n")
    sock.settimeout(SEND_TIMEOUT)
    sock.sendall(head.encode())

def send_error(sock, code):
    body = f"{code} {REASONS[code]}\n".encode()
    send_head(sock, code, len(body), "text/plain", keep_alive=False)
    sock.sendall(body)

#stream the file in chunks so a big file never has to sit in memory all at once
def serve_file(sock, full, keep_alive):
    try:
        f = open(full, "rb")
    except (FileNotFoundError, IsADirectoryError, NotADirectoryError):
        raise HTTPError(404, "no such file")
    except PermissionError:
        raise HTTPError(403, "permission denied")
    with f:
        if not os.path.isfile(full):
            raise HTTPError(404, "not a regular file")
        size = os.fstat(f.fileno()).st_size
        ext = os.path.splitext(full)[1]
        send_head(sock, 200, size, CONTENT_TYPES.get(ext, "application/octet-stream"), keep_alive)
        while True:
            chunk = f.read(SEND_CHUNK)
            if not chunk:
                break
            sock.sendall(chunk) #sendall keeps calling send() until every byte is out

#half-close and drain briefly before closing. closing a socket that still has unread
#bytes makes the kernel send a RST, which can destroy our error response before the
#client reads it (e.g. a 413 sent while the client is still uploading)
def close_gracefully(sock):
    try:
        sock.shutdown(socket.SHUT_WR)
        sock.settimeout(0.5)
        drained = 0
        while drained < 64 * 1024:
            data = sock.recv(RECV_SIZE)
            if not data:
                break
            drained += len(data)
    except OSError:
        pass
    finally:
        sock.close()

#everything that used to be the body of the while loop now lives in here.
#one thread runs this function per connected client, so the loop below is
#free to go straight back to accept() and pick up the next client
def handle_client(client_socket, addr):
    global active_connections
    conn = Connection(client_socket)
    try:
        while True:
            with active_lock:
                busy = active_connections > BUSY_THRESHOLD
                waiting[client_socket] = time.monotonic()
            try:
                request = read_request(conn, busy)
            except HTTPError as e:
                #framing is broken or untrusted, so we can't know where the next request
                #starts. answer and close instead of trying to keep reading
                print(f"{addr}: -> {e.code} ({e})")
                send_error(client_socket, e.code)
                break
            finally:
                with active_lock:
                    waiting.pop(client_socket, None)
            if request is None:
                break
            method, target, version, headers = request

            #http/1.1 keeps the connection open unless the client asks to close it;
            #http/1.0 closes unless the client asks to keep it alive
            options = [o.strip().lower() for v in headers.get("connection", []) for o in v.split(b",")]
            if version == b"HTTP/1.0":
                keep_alive = b"keep-alive" in options
            else:
                keep_alive = b"close" not in options

            #the request (and its body) has been fully consumed, so a 403/404 here can
            #safely keep the connection open for the next request
            try:
                serve_file(client_socket, resolve_path(target), keep_alive)
                print(f"{addr}: {method.decode()} {target[:100].decode('latin-1')} -> 200")
            except HTTPError as e:
                print(f"{addr}: {method.decode()} {target[:100].decode('latin-1')} -> {e.code} ({e})")
                body = f"{e.code} {REASONS[e.code]}\n".encode()
                send_head(client_socket, e.code, len(body), "text/plain", keep_alive)
                client_socket.sendall(body)
            if not keep_alive:
                break
    except OSError as e: #connection reset, send timeout, ...: drop this client only
        print(f"Connection lost: {addr} ({e.__class__.__name__})")
    except Exception as e: #a bug in one connection must never take down the server
        print(f"Internal error on {addr}: {e!r}")
    finally:
        close_gracefully(client_socket)
        with active_lock:
            active_connections -= 1


def main():
    global active_connections
    if len(sys.argv) != 2:
        print("Usage: python3 server.py <port>")
        sys.exit(1)
    port = int(sys.argv[1])

    #small thread stacks so hundreds of connections don't eat memory
    threading.stack_size(512 * 1024)

    #create TCP socket listening on ip address and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #lets us restart right away instead of waiting out TIME_WAIT
    server_socket.bind((HOST, port))

    #listen for connections
    server_socket.listen(1024) #big accept queue so a connection flood doesn't crowd out real clients
    print(f"Server listening on {HOST}:{port}, serving {ROOT} (max {MAX_CONNECTIONS} connections)...")
    try:
        while True:
            try:
                client_socket, addr = server_socket.accept() #accept returns a new socket to the client and the clients ip/port
            except OSError as e: #e.g. out of file descriptors; back off instead of crashing
                print(f"accept failed: {e}")
                time.sleep(0.1)
                continue

            with active_lock:
                full = active_connections >= MAX_CONNECTIONS
                victim = None
                if full and waiting:
                    #make room by dropping whoever has waited longest for a request.
                    #a real client finishes in milliseconds; a slowloris client never does
                    victim = min(waiting, key=waiting.get)
                    del waiting[victim]
                    full = False
                if not full:
                    active_connections += 1
            if victim is not None:
                try:
                    victim.shutdown(socket.SHUT_RDWR) #wakes its thread's recv(), which then exits
                except OSError:
                    pass
            if full:
                #every slot is busy sending a response; refuse instead of queueing
                try:
                    send_error(client_socket, 503)
                    #read whatever request bytes already arrived (without blocking the
                    #accept loop) so close() doesn't send a RST that wipes out the 503
                    client_socket.shutdown(socket.SHUT_WR)
                    client_socket.setblocking(False)
                    client_socket.recv(MAX_REQUEST_LINE)
                except OSError:
                    pass
                client_socket.close()
                continue

            #daemon=True so ctrl-c kills the server even with clients still connected
            t = threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True)
            try:
                t.start()
            except RuntimeError: #can't start a new thread
                with active_lock:
                    active_connections -= 1
                client_socket.close()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
