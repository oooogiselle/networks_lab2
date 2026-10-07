import sys

from common import G, NEXT, port_arg, run

'''
    Red team: framing and parsing attacks (request smuggling, desync, bad line endings)

    Author: Giselle Wu, Dartmouth CS60, Fall 2026
            Assisted by Claude (Anthropic): wrote the attack scripts

    run: python3 redteam/framing.py <server_port>   (server must already be running)

    Most attacks pipeline a normal GET (NEXT) after the bad request. A safe server
    answers once with 400 and closes; a desynced server answers the planted bytes too.
'''

TESTS = [
    ("normal request", G + b"Connection: close\r\n\r\n", ["200"]),

    #request smuggling: two framing headers that disagree about where the body ends
    ("CL + TE smuggling", G + b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" + NEXT, ["400"]),
    ("TE + CL smuggling", G + b"Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n" + NEXT, ["400"]),
    ("conflicting Content-Length", G + b"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello!" + NEXT, ["400"]),
    ("Content-Length list '5, 5'", G + b"Content-Length: 5, 5\r\n\r\nhello" + NEXT, ["400"]),
    ("negative Content-Length", G + b"Content-Length: -1\r\n\r\n" + NEXT, ["400"]),
    ("Content-Length '+5'", G + b"Content-Length: +5\r\n\r\nhello" + NEXT, ["400"]),

    #body accounting on a keep-alive connection: the body must be consumed exactly
    ("GET with body, then pipelined GET", G + b"Content-Length: 11\r\n\r\nhello world" + NEXT, ["200", "200"]),
    #surplus after the declared body is a new request. "GARBAGE" is a valid method token,
    #so the right answer is 501 for it, and nothing served from it
    ("body longer than Content-Length", G + b"Content-Length: 5\r\n\r\nhelloGARBAGE /x HTTP/1.1\r\n\r\n", ["200", "501"]),
    ("GET smuggled after CL: 0", G + b"Content-Length: 0\r\n\r\nGET /nope HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", ["200", "404"]),

    #chunked encoding
    ("valid chunked body, then pipelined GET", G + b"Transfer-Encoding: chunked\r\n\r\nb\r\nhello world\r\n0\r\n\r\n" + NEXT, ["200", "200"]),
    ("chunk data missing its CRLF", G + b"Transfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n" + NEXT, ["400"]),
    ("chunk size '0x5'", G + b"Transfer-Encoding: chunked\r\n\r\n0x5\r\nhello\r\n0\r\n\r\n", ["400"]),
    ("chunk size ' 5' (leading space)", G + b"Transfer-Encoding: chunked\r\n\r\n 5\r\nhello\r\n0\r\n\r\n", ["400"]),
    ("chunk size larger than 32 bits", G + b"Transfer-Encoding: chunked\r\n\r\nffffffffff\r\n", ["400"]),
    ("Transfer-Encoding: gzip", G + b"Transfer-Encoding: gzip\r\n\r\n", ["501"]),
    ("Transfer-Encoding: xchunked", G + b"Transfer-Encoding: xchunked\r\n\r\n", ["501"]),
    ("'Transfer-Encoding :' (space before colon)", G + b"Transfer-Encoding : chunked\r\n\r\n", ["400"]),
    ("two Transfer-Encoding headers", G + b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n", ["400"]),

    #line endings and header syntax
    ("bare LF line endings", b"GET /helloworld.html HTTP/1.1\nHost: x\n\n", ["400"]),
    ("bare LF inside headers", G + b"X: a\nY: b\r\n\r\n", ["400"]),
    ("bare CR inside headers", G + b"X: a\rY: b\r\n\r\n", ["400"]),
    ("NUL byte in header value", G + b"X: a\x00b\r\n\r\n", ["400"]),
    ("obsolete line folding", G + b"X: a\r\n b\r\n\r\n", ["400"]),
    ("header line without a colon", G + b"NoColonHere\r\n\r\n", ["400"]),
    ("missing Host (HTTP/1.1)", b"GET /helloworld.html HTTP/1.1\r\n\r\n", ["400"]),
    ("two Host headers", G + b"Host: y\r\n\r\n", ["400"]),
    ("HTTP/1.0 without Host (allowed)", b"GET /helloworld.html HTTP/1.0\r\n\r\n", ["200"]),
    ("garbage request line", b"GARBAGE\r\n\r\n", ["400"]),
    ("double space in request line", b"GET  /helloworld.html HTTP/1.1\r\nHost: x\r\n\r\n", ["400"]),
]

if __name__ == "__main__":
    sys.exit(1 if run(port_arg(), TESTS) else 0)
