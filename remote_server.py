import asyncio
import struct
import aiosqlite3
import socket
import hashlib
import signal
import logging
import argparse
import sys
import traceback
SOCKS_VER = 5

def logExc(exc):
    if args.logExc:
        log.error(f'{traceback.format_exc()}')

async def handle_local(reader, remote_writer,writer):
    while True:
        req_data = await reader.read(4096)
        if not req_data:
            return
        client_addr=writer.get_extra_info('peername')
        logger.debug('client {} want: {}'.format(client_addr,req_data[0:8]))
        remote_writer.write(req_data)
        await remote_writer.drain()

async def handle_remote(writer, remote_reader,remote_writer):
    while True:
        resp_data = await remote_reader.read(4096)
        if not resp_data:                                                                                                            
            return
        server_addr=remote_writer.get_extra_info('peername')
        logger.debug('server {} resp: {}'.format(server_addr,resp_data[0:8]))
        writer.write(resp_data)
        await writer.drain()

async def handle(reader, writer):
    req = await reader.readline()
    req = bytes.decode(req)
    addr = req[:-2].split()
    logger.info(f'remote server receive request {req[:-2]}')
    host, port = addr[0], int(addr[1])
    username, password = addr[2], addr[3]
    cursor = await db.execute("select password from user where username='%s'" % username)
    row = await cursor.fetchone()
    assert password==row[0]
    remote_reader, remote_writer = await asyncio.open_connection(host, port)
    bind_host, bind_port, *_ = remote_writer.get_extra_info('sockname')
    logger.debug(f'connect to {host} {port}, with {bind_host} {bind_port}')
    writer.write(f'{bind_host} {bind_port}\r\n'.encode())
    await writer.drain()
    try:
        await asyncio.gather(handle_local(reader, remote_writer,writer), handle_remote(writer, remote_reader,remote_writer))
    except Exception as exc:
        logExc(exc)
        writer.close()
        remote_writer.close()

async def main():
    global db
    db=await aiosqlite3.connect("user.db")
    cursor=await db.execute("select * from user")
    row = await cursor.fetchone()
    print(row)
    server = await asyncio.start_server(
        handle, host=args.listen_host, port=args.listen_port)
    addr = server.sockets[0].getsockname()
    logger.info(f'Serving on {addr}')
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    # interrupt from keyboard, perform the default function for the signal
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    # logging
    logger = logging.getLogger(__name__)
    logger.setLevel(level=logging.DEBUG)
    handler = logging.FileHandler('remote_server.log')
    formatter = logging.Formatter('%(asctime)s %(levelname).1s %(lineno)-3d %(funcName)-20s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    chlr = logging.StreamHandler()
    logger.addHandler(chlr)
    # parser
    _parser = argparse.ArgumentParser(description='server')
    _parser.add_argument('--exc', dest='logExc', default=False, action='store_true', help='show exception traceback')
    _parser.add_argument('--listen_ip', dest='listen_host', metavar='listen_host', help='proxy listen host default listen all interfaces')
    _parser.add_argument('--listen_port', dest='listen_port', metavar='listen_port', required=True, help='proxy listen port')
    args = _parser.parse_args()

    if sys.platform == 'win32':
        asyncio.set_event_loop(asyncio.ProactorEventLoop())

    asyncio.run(main())