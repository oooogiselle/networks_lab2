import re
import socket
import sys
import time

'''
    Shared helpers for the red-team attack scripts

    Author: Giselle Wu, Dartmouth CS60, Fall 2026
            Assisted by Claude (Anthropic): wrote the attack scripts

    not run directly; imported by framing.py, limits.py, paths.py and floods.py
'''

HOST = "127.0.0.1"

#a normal request header block (no blank line yet) that most attacks build on
G = b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\n"
#a well-formed request to pipeline after an attack. if the attack desyncs the server,
#this is where it shows: the server answers something other than what we expect
NEXT = b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"

STATUS = re.compile(rb"HTTP/1\.1 (\d{3})")

#send data over a raw socket (all at once, or step bytes at a time with a delay between
#pieces) and return the list of status codes in everything the server sent back.
#a pipelined attack that gets two answers shows up as two codes
def talk(port, data, step=None, delay=0, wait=3.0):
    s = socket.create_connection((HOST, port))
    try:
        if step:
            for i in range(0, len(data), step):
                s.sendall(data[i:i + step])
                time.sleep(delay)
        else:
            s.sendall(data)
    except OSError: #the server may close on us mid-send (e.g. after a 413); that's fine
        pass
    s.settimeout(wait)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            out += d
    except OSError: #timeout or reset: return whatever arrived
        pass
    s.close()
    return [c.decode() for c in STATUS.findall(out)]

#run a list of (name, request bytes, expected status codes) and print PASS/FAIL for each.
#an attack "lands" if the codes differ: a hang (no code), a crash, a desync (extra or
#wrong second code) or the wrong status. returns how many landed
def run(port, tests):
    landed = 0
    for name, data, expected in tests:
        start = time.time()
        got = talk(port, data, wait=10 if "408" in expected else 3)
        ok = got == expected
        landed += not ok
        took = f" ({time.time() - start:.1f}s)" if "408" in expected else ""
        print(f"{'PASS' if ok else 'FAIL'}  {name:<40} got {got}{took}"
              + ("" if ok else f"   expected {expected}"))
    print(f"{len(tests) - landed}/{len(tests)} attacks handled correctly")
    return landed

def port_arg():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <server_port>")
        sys.exit(1)
    return int(sys.argv[1])
