import sys

from common import port_arg, run

'''
    Red team: path traversal and status-code discipline (403, 404, 400, 501, 505)

    Author: Giselle Wu, Dartmouth CS60, Fall 2026
            Assisted by Claude (Anthropic): wrote the attack scripts

    run: python3 redteam/paths.py <server_port>   (server must already be running)

    For the dotfile test, create one where the server runs: echo SECRET > .env
'''

def get(target, extra=b""):
    return b"GET " + target + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n" + extra + b"\r\n"

TESTS = [
    #directory traversal in every encoding we could think of
    ("../../etc/passwd", get(b"/../../etc/passwd"), ["403"]),
    ("%2e%2e/%2e%2e/etc/passwd", get(b"/%2e%2e/%2e%2e/etc/passwd"), ["403"]),
    ("..%2f..%2fetc%2fpasswd", get(b"/..%2f..%2fetc%2fpasswd"), ["403"]),
    ("double-encoded %252e%252e", get(b"/%252e%252e/%252e%252e/etc/passwd"), ["403"]),
    ("triple-encoded %25252e", get(b"/%25252e%25252e/etc/passwd"), ["403"]),
    ("null byte helloworld.html%00.txt", get(b"/helloworld.html%00.txt"), ["403"]),
    ("backslash ..%5c..%5cetc", get(b"/..%5c..%5cetc"), ["403"]),
    ("dotfile /.env", get(b"/.env"), ["403"]),
    ("dotfile /.git/config", get(b"/.git/config"), ["403"]),
    ("own source /server.py", get(b"/server.py"), ["403"]),
    ("own source, encoded /server%2epy", get(b"/server%2epy"), ["403"]),
    ("bytecode /__pycache__/", get(b"/__pycache__/"), ["403"]),
    ("//etc/passwd stays inside the root", get(b"//etc/passwd"), ["404"]),

    #malformed targets
    ("bad percent-encoding %zz", get(b"/%zz"), ["400"]),
    ("absolute-form target", get(b"http://evil/etc/passwd"), ["400"]),
    ("CRLF injection via %0d%0a", get(b"/x%0d%0aSet-Cookie:%20a=b"), ["400"]),
    ("missing file", get(b"/nope.html"), ["404"]),

    #methods and versions
    ("POST with a body", b"POST /helloworld.html HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello", ["501"]),
    ("DELETE, body is a pipelined GET", b"DELETE /x HTTP/1.1\r\nHost: x\r\nContent-Length: 30\r\n\r\n"
        + b"GET /helloworld.html HTTP/1.1\r\n", ["501"]),
    ("HEAD", get(b"/helloworld.html").replace(b"GET", b"HEAD", 1), ["501"]),
    ("HTTP/2.0", b"GET / HTTP/2.0\r\nHost: x\r\n\r\n", ["505"]),
    ("HTTP/1.2", b"GET / HTTP/1.2\r\nHost: x\r\n\r\n", ["505"]),
    ("HTTP/9.9", b"GET / HTTP/9.9\r\nHost: x\r\n\r\n", ["505"]),
    ("HTTPS/1.1 (not a version)", b"GET / HTTPS/1.1\r\nHost: x\r\n\r\n", ["400"]),
]

if __name__ == "__main__":
    sys.exit(1 if run(port_arg(), TESTS) else 0)
