#!/usr/bin/env python3

"""cdipc websocket server
web browser can communicate with any cdipc node through this server

url link, args after "?" are optional:
  /NAME?role=ROLE&id=ID&bin=BOOL&hdr=BOOL&timout=SEC

e.g.: /test?role=sub&id=0&bin=true&timout=1.0

arg list, only support top three at now:
  role:       pub or sub, default sub
  id:         id for pub or sub, default 0
  bin:        default false for string, binary if true
  hdr:        default false, add header before data if true
              for situation like override default timeout value for pub
              and timeout report or other error report
  timeout:    timeout value, unit sec, used for sub
"""

import asyncio
import datetime
import websockets
import time
import subprocess
import os.path
from argparse import ArgumentParser
import urllib.parse as urlparse
from cdipc import *


async def ws_serve(ws, url):
    print('connect from path: ' + url)
    parsed = urlparse.urlparse(url)
    name = parsed.path.lstrip('/')
    qs = urlparse.parse_qs(parsed.query)
    role = CDIPC_PUB if 'role' in qs and qs['role'][0] == 'pub' else CDIPC_SUB
    _id = int(qs['id'][0]) if 'id' in qs else 0
    bin = True if 'bin' in qs and qs['bin'][0] == 'true' else False
    now = timespec()
    abstime = timespec()
    
    ch = cdipc_ch_t()
    cdipc_open(ch, name, role, _id)
    
    try:
        if ch.hdr.type == CDIPC_TOPIC:
            print("type: topic")
            if ch.role == CDIPC_SUB:
                print("role: sub")
                while True:
                    print(f'topic {name}, sub {_id}: wait data')
                    while True:
                        clock_gettime(CLOCK_MONOTONIC, now)
                        us2tv(tv2us(now) + 100000, abstime);
                        nd = cdipc_sub_get(ch, abstime)
                        if nd:
                            break
                        await ws.ping()
                        await asyncio.sleep(0)
                    data = buf_read(nd.dat, nd.len)
                    cdipc_sub_free(ch, nd)
                    print(f'topic {name}, sub {_id}: read data:', data[:10])
                    await ws.send(data if bin else data.decode());
            else:
                print("role: pub")
                while True:
                    print(f'topic {name}, pub {_id}: wait data')
                    data = await ws.recv()
                    nd = cdipc_pub_alloc(ch, None)
                    if not nd:
                        print(f'topic {name}, pub {_id}: break')
                        break
                    data = data.encode()
                    buf_write(nd.dat, data)
                    nd.len = len(data)
                    cdipc_pub_put(ch, nd, None)
        else:
            print("type: service")
            if ch.role == CDIPC_PUB:
                print("role: pub")
                while True:
                    print(f'service {name}, pub {_id}: wait data')
                    data = await ws.recv()
                    nd = cdipc_pub_alloc(ch, None)
                    if not nd:
                        print(f'service {name}, pub {_id}: break')
                        break
                    data = data.encode()
                    buf_write(nd.dat, data)
                    nd.len = len(data)
                    cdipc_pub_put(ch, nd, None)
                    cdipc_pub_wait(ch, nd, None)
                    rdata = buf_read(buf_offset(nd.dat, ch.hdr.max_len), nd.len_r)
                    cdipc_pub_free(ch, nd)
                    print(f'service {name}, sub {_id}: return data:', rdata[:10])
                    await ws.send(rdata if bin else rdata.decode());
            else:
                print("role: sub")
    
    except websockets.exceptions.ConnectionClosed:
        print('disconnect from path: ' + url)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('--ip', dest='ip', default='localhost')
    parser.add_argument('--port', dest='port', default='52480') # 0xcd00
    args = parser.parse_args()
    
    print("ws server listen on {}:{}".format(args.ip, args.port))
    start_server = websockets.serve(ws_serve, args.ip, int(args.port))

    asyncio.get_event_loop().run_until_complete(start_server)
    print('until end')
    asyncio.get_event_loop().run_forever()

