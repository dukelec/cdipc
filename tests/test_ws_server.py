#!/usr/bin/env python3
# Software License Agreement (MIT License)
#
# Copyright (c) 2026, DUKELEC, Inc.
# All rights reserved.
#
# Author: Duke Fong <d@d-l.io>

"""End-to-end test of tools/cdipc_ws_server.py, run by: make test-ws
needs LD_LIBRARY_PATH and PYTHONPATH pointing to the build tree
"""

import asyncio, os, socket, subprocess, sys, tempfile, time
from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed, InvalidStatus

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, 'tools/cli_tool/cdipc')
TOPIC, SVC = 'cdipc_test_ws_t', 'cdipc_test_ws_s'
fails = 0


def check(ok, msg):
    global fails
    fails += not ok
    print(('  ok   ' if ok else '  FAIL ') + msg)


def cli(*args):
    return subprocess.run([CLI, *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


async def closed_reason(ws):
    try:
        await asyncio.wait_for(ws.recv(), 5)
    except ConnectionClosed as e:
        return (e.rcvd.code, e.rcvd.reason) if e.rcvd else (None, '')
    return None, 'not closed'


async def run(url):
    # idle subs must not block the event loop for others
    idle = [await connect(f'{url}/{TOPIC}?role=sub&id={1 + i % 3}') for i in range(12)]
    async with connect(f'{url}/{TOPIC}?role=sub&id=0') as sub, connect(f'{url}/{TOPIC}?role=pub') as pub:
        await asyncio.sleep(0.3)
        t0 = time.monotonic()
        await pub.send('hello')
        got = await asyncio.wait_for(sub.recv(), 5)
        dt = (time.monotonic() - t0) * 1000
        check(got == 'hello' and dt < 200, f'topic pub -> sub: {got!r} in {dt:.0f} ms with 12 idle subs')
        await pub.send(b'\x00\xff')
        got = await asyncio.wait_for(sub.recv(), 5)
        check(got == '\x00\ufffd', f'binary frame to text sub: {got!a}')
    for ws in idle:
        await ws.close()

    async with connect(f'{url}/{TOPIC}?role=sub&id=0&bin=true') as sub, connect(f'{url}/{TOPIC}?role=pub') as pub:
        await asyncio.sleep(0.3)
        await pub.send(b'\x01\x02')
        got = await asyncio.wait_for(sub.recv(), 5)
        check(got == b'\x01\x02', f'bin=true sub gets bytes: {got!r}')

    async with connect(f'{url}/{TOPIC}?role=pub') as pub:
        await pub.send('x' * 1000)
        code, reason = await closed_reason(pub)
        check(code == 1009, f'oversize message closes with {code} {reason!r}')

    async with connect(f'{url}/{TOPIC}?role=sub&id=99') as ws:
        code, reason = await closed_reason(ws)
        check(code == 1011, f'bad id closes with {code} {reason!r}')

    try:
        async with connect(f'{url}/{TOPIC}?role=sub', origin='http://evil.example'):
            check(False, 'foreign origin accepted')
    except InvalidStatus as e:
        check(e.response.status_code == 403, f'foreign origin rejected: HTTP {e.response.status_code}')
    async with connect(f'{url}/{TOPIC}?role=sub', origin='http://localhost:8000'):
        check(True, 'localhost origin accepted')

    async with connect(f'{url}/{SVC}?role=pub&timeout=3') as pub:
        await pub.send('ping')
        got = await asyncio.wait_for(pub.recv(), 5)
        check(got == 'pong', f'service reply: {got!r}')
    async with connect(f'{url}/{SVC}?role=pub&timeout=0.3') as pub:
        await pub.send('ping') # the replier answered once and exited
        code, reason = await closed_reason(pub)
        check(code == 1011, f'no reply closes with {code} {reason!r}')


def main():
    with socket.socket() as s:
        s.bind(('localhost', 0))
        port = s.getsockname()[1]
    for name in (TOPIC, SVC):
        cli('unlink', '--name', name)
    cli('create', '--name', TOPIC, '--max-sub', '4')
    for i in range(4):
        cli('pend-cfg', '--name', TOPIC, '--id', str(i))
    cli('create', '--name', SVC, '--type', 'service')
    cli('pend-cfg', '--name', SVC)

    log = tempfile.TemporaryFile(mode='w+')
    server = subprocess.Popen([sys.executable, '-u', os.path.join(ROOT, 'tools/cdipc_ws_server.py'),
                               '--port', str(port)], stdout=log, stderr=subprocess.STDOUT)
    replier = subprocess.Popen([CLI, 'get', '--name', SVC, '--timeout', '30', '--ret-dat', 'pong'],
                               stdout=subprocess.DEVNULL)
    ok = False
    try:
        for _ in range(50):
            try:
                socket.create_connection(('localhost', port)).close()
                break
            except OSError:
                time.sleep(0.1)
        asyncio.run(run(f'ws://localhost:{port}'))
        ok = not fails
    finally:
        for p in (server, replier):
            p.terminate()
            p.wait()
        for name in (TOPIC, SVC):
            cli('unlink', '--name', name)
        if not ok:
            log.seek(0)
            print('--- server log:\n' + log.read())
    print('PASS' if ok else 'FAIL')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
