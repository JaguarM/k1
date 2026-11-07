#!/usr/bin/env python3
"""Load tests for the HTTPS OS. QEMU must already be serving on 127.0.0.1:$PORT (default 8443).

  load.py hold [N]      the score test: open connections (32 handshakes in flight, starts 4 ms
                        apart since slirp's listen backlog is only 1) and keep
                        all of them open; at 64, 128, 256, ... and at the end, fetch the page
                        over every open connection. Stops at the first checkpoint where any
                        connection fails, at N, or when the client runs out of ports.
                        Prints "connections: C" = most connections that all worked at once.
  load.py burst K[,K..] K clients connect at the same moment, each fetches the page, all stay
                        open, then each fetches it again over the same connection
  load.py seq N         N fresh connections, one after another (handshake rate)
  load.py ka N          N requests on one keep-alive connection
"""
import asyncio, collections, errno, os, ssl, sys, time

HOST = "127.0.0.1"
PORT = int(os.environ.get("PORT", "8443"))
TIMEOUT = float(os.environ.get("TIMEOUT", "60"))  # per handshake / per request
INFLIGHT = int(os.environ.get("INFLIGHT", "32"))
GAP = float(os.environ.get("GAP", "0.004"))  # between connection starts: slirp's listen backlog is 1
EXPECT = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "www", "index.html"), "rb").read()
REQ = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"

CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def ename(e):
    return f"{type(e).__name__}({e.reason})" if isinstance(e, ssl.SSLError) else type(e).__name__


def log(*a):
    print(*a, file=sys.stderr, flush=True)


async def connect():
    return await asyncio.wait_for(asyncio.open_connection(HOST, PORT, ssl=CTX), TIMEOUT)


async def get(conn):
    """One request, one response (the server frames it with Content-Length and bare LFs)."""
    r, w = conn

    async def go():
        w.write(REQ)
        head = await r.readuntil(b"\n\n")
        n = int(head.split(b"Content-Length:")[1].split(b"\n")[0])
        if await r.readexactly(n) != EXPECT:
            raise ValueError("bad body")

    await asyncio.wait_for(go(), TIMEOUT)


def close(conns):
    for c in conns:
        try:
            c[1].transport.abort()
        except Exception:
            pass


async def fetch_all(conns, inflight):
    """Fetch the page over every connection, `inflight` at a time; returns (ok, error counts)."""
    sem = asyncio.Semaphore(inflight)
    errs = collections.Counter()

    async def one(c):
        async with sem:
            try:
                await get(c)
                return True
            except Exception as e:
                errs[ename(e)] += 1
                return False

    res = await asyncio.gather(*(one(c) for c in conns))
    return sum(res), errs


async def hold(limit):
    conns, errs = [], collections.Counter()
    sem = asyncio.Semaphore(INFLIGHT)
    out_of_ports = False
    best = 0
    t0 = time.time()

    async def opener():
        nonlocal out_of_ports
        try:
            conns.append(await connect())
        except OSError as e:
            if e.errno == errno.EADDRNOTAVAIL:
                out_of_ports = True
            errs[ename(e)] += 1
        except Exception as e:
            errs[ename(e)] += 1
        finally:
            sem.release()

    checked = 0

    async def checkpoint():
        nonlocal best, checked
        n = checked = len(conns)
        ok, ferrs = await fetch_all(conns, INFLIGHT)
        log(f"  {n:6d} open after {time.time() - t0:6.1f}s: {ok} served"
            + (f", errors {dict(ferrs)}" if ferrs else "")
            + (f"; handshake errors so far {dict(errs)}" if errs else ""))
        best = max(best, ok)
        return ok == n

    tasks, mark, started, healthy = set(), 64, 0, True
    while started < limit and not out_of_ports and sum(errs.values()) < 10:
        await sem.acquire()
        if out_of_ports:
            break
        started += 1
        t = asyncio.create_task(opener())
        tasks.add(t)
        t.add_done_callback(tasks.discard)
        await asyncio.sleep(GAP)
        if len(conns) >= mark:
            await asyncio.gather(*tasks)
            healthy = await checkpoint()
            if not healthy:
                break
            mark *= 2
    await asyncio.gather(*tasks)
    if healthy and checked != len(conns):
        await checkpoint()
    close(conns)
    why = ("a checkpoint failed" if not healthy else "client out of ports" if out_of_ports
           else "handshakes failing" if sum(errs.values()) >= 10 else f"limit {limit}")
    print(f"connections: {best}  ({len(conns)} opened in {time.time() - t0:.0f}s, stopped: {why}"
          + (f", handshake errors {dict(errs)}" if errs else "") + ")")
    return best


async def burst(k):
    t0 = time.time()
    res = await asyncio.gather(*(connect() for _ in range(k)), return_exceptions=True)
    conns = [c for c in res if not isinstance(c, BaseException)]
    herrs = collections.Counter(ename(c) for c in res if isinstance(c, BaseException))
    t_hs = time.time() - t0
    ok1, e1 = await fetch_all(conns, k)
    ok2, e2 = await fetch_all(conns, k)
    close(conns)
    errs = herrs + e1 + e2
    print(f"burst {k:5d}: {len(conns)} handshakes in {t_hs:.1f}s, served {ok1} then {ok2} again,"
          f" {time.time() - t0:.1f}s" + (f", errors {dict(errs)}" if errs else ""))


async def seq(n):
    t0, fails = time.time(), 0
    for _ in range(n):
        try:
            c = await connect()
            await get(c)
            close([c])
        except Exception:
            fails += 1
    dt = time.time() - t0
    print(f"sequential: {n} fresh connections in {dt:.1f}s = {n / dt:.1f}/s, {fails} failed")


async def ka(n):
    c = await connect()
    t0 = time.time()
    for _ in range(n):
        await get(c)
    dt = time.time() - t0
    close([c])
    print(f"keep-alive: {n} requests on one connection in {dt:.2f}s = {n / dt:.0f}/s")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    mode, arg = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else None)
    if mode == "hold":
        asyncio.run(hold(int(arg) if arg else 10**6))
    elif mode == "burst":
        for k in map(int, (arg or "64").split(",")):
            asyncio.run(burst(k))
    elif mode == "seq":
        asyncio.run(seq(int(arg or 100)))
    elif mode == "ka":
        asyncio.run(ka(int(arg or 1000)))
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
