#!/usr/bin/env python3
"""Hold TLS connections open against k1 on a tap interface, from several source IPs.

  tapload.py IPS PORTS_PER_IP [BASE_PORT]

Every source IP (10.0.2.32 ...) uses the SAME source ports, so if the guest keyed slots on the
port alone, connections from different IPs would overwrite each other. Fetches the page over
every open connection at 64, 128, ... open and at the end.
Env: INFLIGHT (handshakes at once), TIMEOUT (s), VERIFY (fetches at once), GAP (s between starts),
IPOFF (first source IP is 10.0.2.(32+IPOFF)). For several processes (one per fd limit): BARRIER=dir,
WID=i, NW=n make them all hold their connections open until every worker's final fetch is done.
"""
import asyncio, collections, errno, gc, os, resource, socket, ssl, struct, sys, time

HOST, PORT = "10.0.2.15", 443
TIMEOUT = float(os.environ.get("TIMEOUT", "30"))
INFLIGHT = int(os.environ.get("INFLIGHT", "4"))
VERIFY = int(os.environ.get("VERIFY", "64"))
GAP = float(os.environ.get("GAP", "0"))
IPOFF = int(os.environ.get("IPOFF", "0"))
BARRIER = os.environ.get("BARRIER")
WID = os.environ.get("WID", "0")
NW = int(os.environ.get("NW", "1"))
EXPECT = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "www", "index.html"), "rb").read()
REQ = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"

CTX = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE
asyncio.sslproto.SSLProtocol.max_size = 16 * 1024


def ename(e):
    if isinstance(e, ssl.SSLError):
        return f"{type(e).__name__}({e.reason})"
    return f"{type(e).__name__}({errno.errorcode.get(e.errno, e.errno)})" if isinstance(e, OSError) else type(e).__name__


async def connect(ip, port):
    return await asyncio.wait_for(
        asyncio.open_connection(HOST, PORT, ssl=CTX, ssl_handshake_timeout=TIMEOUT,
                                local_addr=(ip, port)), TIMEOUT)


async def get(conn):
    r, w = conn

    async def go():
        w.write(REQ)
        head = await r.readuntil(b"\n\n")
        n = int(head.split(b"Content-Length:")[1].split(b"\n")[0])
        if await r.readexactly(n) != EXPECT:
            raise ValueError("bad body")

    await asyncio.wait_for(go(), TIMEOUT)


async def fetch_all(conns):
    sem = asyncio.Semaphore(VERIFY)
    errs = collections.Counter()

    async def one(c):
        async with sem:
            try:
                await get(c)
                return 1
            except Exception as e:
                errs[ename(e)] += 1
                return 0

    return sum(await asyncio.gather(*(one(c) for c in conns))), errs


async def barrier(name):
    """Tell the other workers we reached `name` and wait until they all have."""
    if not BARRIER:
        return
    open(os.path.join(BARRIER, f"{name}.{WID}"), "w").close()
    while sum(f.startswith(name + ".") for f in os.listdir(BARRIER)) < NW:
        await asyncio.sleep(0.5)


def close(conns):
    for c in conns:
        try:
            c[1].get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                                     struct.pack("ii", 1, 0))
            c[1].transport.abort()
        except Exception:
            pass


async def main(ips, per_ip, base):
    addrs = [f"10.0.2.{32 + IPOFF + i}" for i in range(ips)]
    conns, errs = [], collections.Counter()
    sem = asyncio.Semaphore(INFLIGHT)
    t0 = time.time()
    mark, tasks = 64, set()

    async def opener(ip, port):
        try:
            conns.append(await connect(ip, port))
        except Exception as e:
            errs[ename(e)] += 1
            if isinstance(e, OSError) and e.errno == errno.EADDRINUSE:
                print(f"  EADDRINUSE on {ip}:{port}", flush=True)
        finally:
            sem.release()

    async def checkpoint():
        n = len(conns)
        ok, ferrs = await fetch_all(conns)
        print(f"  {n:6d} open, {time.time() - t0:7.1f}s: {ok} served"
              + (f", fetch errors {dict(ferrs)}" if ferrs else "")
              + (f"; handshake errors so far {dict(errs)}" if errs else ""), flush=True)
        return ok

    for port in range(base, base + per_ip):
        for ip in addrs:
            await sem.acquire()
            t = asyncio.create_task(opener(ip, port))
            tasks.add(t)
            t.add_done_callback(tasks.discard)
            if GAP:
                await asyncio.sleep(GAP)
            if len(conns) >= mark:
                await asyncio.gather(*tasks)
                await checkpoint()
                mark *= 2
    await asyncio.gather(*tasks)
    dt = time.time() - t0
    await barrier("opened")
    print(f"  worker {WID}: everyone is open, {time.time() - t0:.0f}s; final fetch", flush=True)
    ok = await checkpoint()
    await barrier("verified")
    rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(f"attempted {ips * per_ip}, opened {len(conns)}, served at end {ok}, "
          f"handshake errors {dict(errs)}, {dt:.0f}s, {len(conns) / dt:.1f} conn/s, "
          f"client RSS {rss / 1024:.0f} MiB ({rss * 1024 / max(len(conns), 1) / 1024:.0f} KiB/conn)")
    close(conns)


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) < 2:
        sys.exit(__doc__)
    gc.disable()  # scanning tens of thousands of live connections is pure cost here
    asyncio.run(main(int(a[0]), int(a[1]), int(a[2]) if len(a) > 2 else 20000))
