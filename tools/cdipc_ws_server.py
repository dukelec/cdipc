#!/usr/bin/env python3

"""cdipc websocket server
web browser can communicate with any cdipc node through this server

url link, args after "?" are optional:
  /NAME?role=ROLE&id=ID&bin=BOOL&hdr=BOOL&timeout=SEC

e.g.: /test?role=sub&id=0&bin=true

arg list, hdr is not supported at now:
  role:       pub or sub, default sub
  id:         id for pub or sub, default 0
  bin:        default false for string, binary if true
  hdr:        default false, add header before data if true
              for situation like override default timeout value for pub
              and timeout report or other error report
  timeout:    timeout value for pub, unit sec, default 10

on error (e.g. timeout, message too big) the connection is closed with a reason

only pages from localhost and non-browser clients are accepted by default,
allow more by: --origin http://192.168.1.10:8080 (repeatable), or --origin '*',
pages opened from local files need: --origin null

needs python websockets >= 14.2
"""

import asyncio
import re
import sys
import urllib.parse as urlparse
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
import websockets
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed
from websockets.protocol import State
from cdipc import *

LOCAL_ORIGIN = re.compile(r'https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?')


def abstime_after(sec):
    t = timespec()
    clock_gettime(CLOCK_MONOTONIC, t)
    us2tv(tv2us(t) + int(sec * 1000000), t)
    return t


async def ws_serve(ws):
    url = ws.request.path
    print('connect from path: ' + url)
    parsed = urlparse.urlparse(url)
    name = parsed.path.lstrip('/')
    qs = urlparse.parse_qs(parsed.query)
    role = CDIPC_PUB if qs.get('role') == ['pub'] else CDIPC_SUB
    _id = int(qs['id'][0]) if 'id' in qs else 0
    bin = qs.get('bin') == ['true']
    timeout = float(qs['timeout'][0]) if 'timeout' in qs else 10

    # blocking cdipc calls run in a per-connection thread (swig -threads releases the GIL)
    loop = asyncio.get_running_loop()
    ex = ThreadPoolExecutor(1)
    def call(fn, *args):
        return loop.run_in_executor(ex, fn, *args)

    ch = cdipc_ch_t()
    if await call(cdipc_open, ch, name, role, _id):
        ex.shutdown(wait=False)
        await ws.close(1011, 'cdipc_open failed')
        return
    kind = 'topic' if ch.hdr.type == CDIPC_TOPIC else 'service'
    print(f'type: {kind}, role: {"pub" if role == CDIPC_PUB else "sub"}')

    try:
        if role == CDIPC_SUB and kind == 'topic':
            while ws.state is State.OPEN:
                # short poll: a closed connection could still take one message in it
                nd = await call(cdipc_sub_get, ch, abstime_after(0.1))
                if not nd:
                    continue
                data = buf_read(nd.dat, nd.len)
                cdipc_sub_free(ch, nd)
                print(f'topic {name}, sub {_id}: read data:', data[:10])
                await ws.send(data if bin else data.decode(errors='replace'))

        elif role == CDIPC_PUB:
            while True:
                print(f'{kind} {name}, pub {_id}: wait data')
                data = await ws.recv()
                if isinstance(data, str):
                    data = data.encode()
                if len(data) > ch.hdr.max_len:
                    await ws.close(1009, f'over max_len {ch.hdr.max_len}')
                    break
                t = abstime_after(timeout)
                nd = await call(cdipc_pub_alloc, ch, t)
                if not nd:
                    await ws.close(1011, 'cdipc_pub_alloc failed')
                    break
                buf_write(nd.dat, data)
                nd.len = len(data)
                r = await call(cdipc_pub_put, ch, nd, t)
                if kind == 'service' and not r:
                    r = await call(cdipc_pub_wait, ch, nd, t)
                    if not r:
                        rdata = buf_read(buf_offset(nd.dat, ch.hdr.max_len), nd.len_r)
                if kind == 'service' or r:
                    cdipc_pub_free(ch, nd) # free before reply cancels the request
                if r:
                    await ws.close(1011, f'cdipc error: {r}')
                    break
                if kind == 'service':
                    print(f'service {name}, pub {_id}: return data:', rdata[:10])
                    await ws.send(rdata if bin else rdata.decode(errors='replace'))
        # sub of service is not supported

    except ConnectionClosed:
        pass
    finally:
        ex.submit(cdipc_close, ch) # runs after any call still in flight
        ex.shutdown(wait=False)
        print('disconnect from path: ' + url)


async def main(args):
    origins = None if '*' in args.origin else [None, LOCAL_ORIGIN, *args.origin]
    async with serve(ws_serve, args.ip, int(args.port), origins=origins) as server:
        print('ws server listen on {}:{}'.format(args.ip, args.port))
        await server.serve_forever()


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('--ip', dest='ip', default='localhost')
    parser.add_argument('--port', dest='port', default='52480') # 0xcd00
    parser.add_argument('--origin', dest='origin', action='append', default=[],
                        help='allowed page origin, repeatable, "*" for any')
    args = parser.parse_args()
    # older ones don't match LOCAL_ORIGIN: no regex support in origins
    if tuple(int(x) for x in websockets.__version__.split('.')[:2]) < (14, 2):
        sys.exit('websockets >= 14.2 required')
    asyncio.run(main(args))
