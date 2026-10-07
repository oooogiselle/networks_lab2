import sys

from common import G, port_arg, run

'''
    Red team: oversized and incomplete input (413, 414, 431, 408)

    Author: Giselle Wu, Dartmouth CS60, Fall 2026
            Assisted by Claude (Anthropic): wrote the attack scripts

    run: python3 redteam/limits.py <server_port>   (server must already be running)

    Each attack asks "does this server bound what it reads, or does it buffer forever
    and wait forever?" The 408 tests take about 5 seconds each by design.
'''

TESTS = [
    #413: declared or actual body too big
    ("Content-Length: 20 digits", G + b"Content-Length: 99999999999999999999\r\n\r\n", ["413"]),
    ("Content-Length: 10 MB", G + b"Content-Length: 10000000\r\n\r\n", ["413"]),
    ("chunked body over the limit", G + b"Transfer-Encoding: chunked\r\n\r\n"
        + b"fffff\r\n" + b"a" * 0xfffff + b"\r\n" + b"fffff\r\n" + b"a" * 10, ["413"]),

    #414: request target too long
    ("5 KB URI", b"GET /" + b"a" * 5000 + b" HTTP/1.1\r\nHost: x\r\n\r\n", ["414"]),
    ("100 KB request line", b"GET /" + b"a" * 100000 + b" HTTP/1.1\r\nHost: x\r\n\r\n", ["414"]),

    #431: header section too big
    ("one 100 KB header", G + b"X: " + b"a" * 100000 + b"\r\n\r\n", ["431"]),
    ("1000 headers", G + b"".join(b"X%d: a\r\n" % i for i in range(1000)) + b"\r\n", ["431"]),

    #408: the client lies about what it will send, then goes quiet
    ("body shorter than Content-Length", G + b"Content-Length: 100\r\n\r\nshort", ["408"]),
    ("headers never finished", b"GET / HTTP/1.1\r\nHost: x\r\nX-a: b", ["408"]),
    ("chunked body never finished", G + b"Transfer-Encoding: chunked\r\n\r\n5\r\nhel", ["408"]),
]

if __name__ == "__main__":
    sys.exit(1 if run(port_arg(), TESTS) else 0)
