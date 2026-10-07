# Red team: attack scripts and results

Author: Giselle Wu, Dartmouth CS60, Fall 2026
Assisted by Claude (Anthropic): wrote the attack scripts and this note

These scripts extend the course's `http_attack_harness.py` with my own attacks. Each one
talks to the server over raw sockets and prints PASS/FAIL per attack. An attack
**lands** (FAIL) if the server crashes, hangs, stops serving other clients, desyncs on a
pipelined request, or returns the wrong or an unsafe status.

```bash
# in the directory the server serves (with helloworld.html, english_words.txt):
echo SECRET > .env              # a dotfile for paths.py to try to steal
python3 server.py 8080
# in another terminal:
bash redteam/run_all.sh 8080    # or run one file: python3 redteam/framing.py 8080
```

| Script | Attacks | What it checks |
|---|---|---|
| `framing.py` | 30 | request smuggling, keep-alive desync, chunked encoding, line endings, header syntax |
| `limits.py` | 10 | oversized input (413/414/431) and incomplete input (408) |
| `paths.py` | 24 | directory traversal in every encoding, dotfiles, the server's own source, 501/505 |
| `floods.py` | 4 | connection exhaustion while a legit client keeps requesting |
| `common.py` | – | shared raw-socket helper |

## Attacks that landed

These are the interesting ones. Each found a real bug that I then fixed.

| # | Attack | What happened | Fix |
|---|---|---|---|
| 1 | `floods.py slowloris 600`: 600 connections each send one header byte every 0.5 s and reconnect as soon as they're dropped | **Legit client starved: 47/88 requests got 200, 41 got a connection reset.** With 600 attackers and a 500-connection cap, attackers took every slot as soon as it freed up. See `postmortem.md`. | When full, evict the connection that has waited longest for its request (`waiting` dict in `server.py`). After: 88/88. |
| 2 | Same attack: the bytes a rejected client actually received | The 503 status line and headers arrived, then `ConnectionResetError`, and the body was lost. Closing a socket with unread request bytes makes the kernel send a RST. | Half-close and do a non-blocking drain before closing in the 503 path. After: a complete 503. |
| 3 | `floods.py slowloris 1500` | Up to 1,000 connections the legit client gets 88/88. At 1,500 on macOS the legit client stalls (~19 s, then a reset) because macOS caps the accept queue at 128 (`kern.ipc.somaxconn`). | Listen backlog raised to 1024. **Resolved on the Linux VM** (`somaxconn` 4096): 1,500 attackers → 88/88, worst 0.03 s. The macOS stall is an OS accept-queue cap, not a server flaw. |

## Every attack and how the server responds

### Framing and parsing (`framing.py`)
Most of these pipeline a normal GET after the bad request. A desynced server would answer
the planted bytes too, so getting exactly one code back is part of the check.

| Attack | Why a naive server fails | Server response |
|---|---|---|
| `Content-Length` + `Transfer-Encoding: chunked` (both orders) | Picks one framing; the body bytes the other framing would count become a smuggled request | **400**, close |
| Two different `Content-Length`s; `Content-Length: 5, 5` | Trusts the first or last value, so the boundary is wrong | **400**, close (any duplicate is rejected) |
| `Content-Length: -1` / `+5` | `int()` accepts both | **400** (digits only) |
| GET with an 11-byte body, then a pipelined GET | Ignores the GET body, then parses `hello world` as the next request | **200, 200** (body consumed exactly) |
| Body longer than `Content-Length` (`helloGARBAGE /x ...`) | – | **200**, then the surplus parses as its own request: **501**, nothing served |
| `Content-Length: 0` followed by a smuggled `GET /nope` | – | **200, 404** (correctly treated as a second request) |
| Valid chunked body, then a pipelined GET | Doesn't parse chunked, so the chunks become garbage requests | **200, 200** |
| Chunk data not followed by CRLF | Trusts the size and keeps going | **400** |
| Chunk size `0x5`, ` 5`, `ffffffffff` | `int(x, 16)` accepts `0x5` and spaces; the huge size buffers forever | **400** |
| `Transfer-Encoding: gzip` / `xchunked` | Ignores it or substring-matches "chunked" | **501** |
| `Transfer-Encoding : chunked` (space before the colon) | Strips the name, so it's treated as TE (a classic smuggling trick) | **400** |
| Two `Transfer-Encoding` headers | – | **400** |
| Bare LF / bare CR line endings | Splits on `\n`, so it disagrees with strict servers about where lines end | **400** |
| NUL in a header value; obsolete line folding; header without a colon | – | **400** |
| Missing / duplicate `Host` on HTTP/1.1 | – | **400** (HTTP/1.0 without Host: 200) |
| Garbage request line; double space in the request line | `split()` collapses spaces | **400** |

### Size limits and timeouts (`limits.py`)
| Attack | Server response |
|---|---|
| `Content-Length` with 20 digits; 10 MB `Content-Length`; chunked body over 1 MB | **413** (the size is checked before reading; a 20-digit number is never converted) |
| 5 KB URI; 100 KB request line | **414** (limits: 2 KB URI, 8 KB request line) |
| One 100 KB header; 1000 headers | **431** (limits: 16 KB of headers, 100 headers) |
| Body shorter than `Content-Length`; headers never finished; chunked body never finished | **408** after 5.0 s (a deadline for the whole request, not per `recv()`) |

### Paths, methods and versions (`paths.py`)
| Attack | Server response |
|---|---|
| `../../etc/passwd`, `%2e%2e/`, `..%2f`, `%252e%252e` (double), `%25252e` (triple) | **403** (decoded up to 3 times, then `..` rejected and `realpath` checked against the root) |
| `helloworld.html%00.txt` (null byte), `..%5c` (backslash) | **403** |
| `/.env`, `/.git/config`, `/server.py`, `/server%2epy`, `/__pycache__/` | **403** |
| `//etc/passwd` | **404**: it resolves to `<root>/etc/passwd`, never `/etc/passwd` |
| `%zz` (bad encoding), `http://evil/...` (absolute-form), `%0d%0a` in the path | **400** (CRLF in a path can't reach response headers anyway; responses never echo request data) |
| POST, DELETE (with a pipelined GET as its body), HEAD | **501**, close (the body is never left on the socket) |
| `HTTP/2.0`, `HTTP/1.2`, `HTTP/9.9` / `HTTPS/1.1` | **505** / **400** |

### Connection floods (`floods.py`, legit client every 0.2 s for 20 s)
Numbers below are from the Linux VM (`seedvm2026`, Ubuntu 22.04); macOS matches.
| Attack | Legit client | Server afterwards |
|---|---|---|
| Slowloris, 600 connections | 89/89 OK, worst 0.03 s | threads and file descriptors back to baseline |
| Idle keep-alive, 600 connections | 89/89 OK, worst 0.01 s | back to baseline |
| Slow body, 300 connections | 89/89 OK, worst 0.01 s | back to baseline |
| Slow reader (never reads the big file), 50 connections | 89/89 OK | back to baseline; the send timeout drops them |
| Slowloris, 1,500 connections | 88/88 OK, worst 0.03 s | back to baseline |

The 1,500 run needs `ulimit -n 8192` in the shell running `floods.py`: the harness opens
1,500 client sockets in one process and Ubuntu's default 1024 fd limit makes the *attacker*
(not the server) crash with a `pthread_exit` / libgcc core dump. The server self-raises its
own fd limit and caps concurrency at 500, so it is unaffected. The full run (`run_all.sh` +
the 1,500 slowloris) was verified on the VM; `framing.py` 30/30, `limits.py` and `paths.py`
all pass there as on macOS.
