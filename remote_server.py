from enum import Enum
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
import time
SOCKS_VER = 5

READ_MODE = Enum(
    'readmode', ('EXACT', 'LINE', 'MAX', 'UNTIL')
)

class token_bucket:
    def __init__(self, rate):
        self._consume = asyncio.Lock()
        self.tokens = 0
        self.last = 0
        self.rate = rate
    async def consume(self, amount):
        await self._consume.acquire()
        try:
            now = time.time()
            if self.last == 0:
                self.last == now
            elapsed = now - self.last
            if int(elapsed * self.rate):
                self.tokens += int(elapsed * self.rate)
                self.last = now
            self.tokens = (self.rate if self.tokens > self.rate*100 else self.tokens)
            if self.tokens > amount:
                self.tokens -= amount
            else:
                amount = 0
            return amount
        finally:
            self._consume.release()

class program_err(Exception):
    print(Exception)


def logExc(exc):
    if args.logExc:
        logger.error(f'{traceback.format_exc()}')


async def handle_local(client_reader, remote_writer, client_writer):
    while True:
        try:
            req_data = await aio_read(client_reader, READ_MODE.MAX, read_len=4096)
            if not req_data:
                return
            client_addr = client_writer.get_extra_info('peername')
            logger.debug('client {} want: {}'.format(client_addr, req_data[0:8]))
            await aio_write(remote_writer,req_data)
        except Exception as exc:
            logger.debug(exc)
            return


async def handle_remote(client_writer, remote_reader, remote_writer,rate,my_token_bucket):
    while True:
        try:
            amount = await my_token_bucket.consume(1024)
            if amount==1024:
                resp_data = await aio_read(remote_reader, READ_MODE.MAX, read_len=1024)
                if not resp_data:
                    return
                server_addr = remote_writer.get_extra_info('peername')
                logger.debug('server {} resp: {}'.format(server_addr, resp_data[0:8]))
                await aio_write(client_writer, resp_data)
            else:
                time.sleep(0.5)
        except Exception as exc:
            logger.debug(exc)
            return


async def aio_read(reader, read_mode, *, log_hint=None, exact_data=None, read_len=None, until_str=b'\r\n'):
    data = None
    try:
        if read_mode == READ_MODE.EXACT:
            if exact_data:
                read_len = len(exact_data)
            data = await reader.readexactly(read_len)
            if exact_data and data != exact_data:
                raise program_err(
                    f'ERR={data}, it should be {exact_data}, {log_hint}')
        elif read_mode == READ_MODE.LINE:
            data = await reader.readline()
        elif read_mode == READ_MODE.MAX:
            data = await reader.read(read_len)
        elif read_mode == READ_MODE.UNTIL:
            data = await reader.readuntil(until_str)
        else:
            logger.error(f'invalid mode={read_mode}')
            exit(1)
    except asyncio.IncompleteReadError as exc:
        raise program_err(f'EXC={exc} {log_hint}')
    except ConnectionResetError as exc:
        raise program_err(f'EXC={exc} {log_hint}')
    except ConnectionAbortedError as exc:
        raise program_err(f'EXC={exc} {log_hint}')
    if not data:
        raise program_err(f'find EOF when read {log_hint}')
    return data

async def aio_write(writer, data=None, *, log_hint=None):
    try:
        writer.write(data)
        await writer.drain()
    except ConnectionAbortedError as exc:
        raise program_errk(f'EXC={exc} {log_hint}')
    except Exception as exc:
        logger.debug(exc)

async def handle(client_reader, client_writer):
    req = await aio_read(client_reader,READ_MODE.LINE,log_hint='recv req')
    req = bytes.decode(req)
    addr = req[:-2].split()
    logger.info(f'remote server receive request {req[:-2]}')
    host, port = addr[0], int(addr[1])
    username, password = addr[2], addr[3]
    cursor = await db.execute("select password,rate from user where username='%s'" % username)
    row = await cursor.fetchone()
    print(row)
    assert password == row[0]
    rate = row[1]
    print(rate)
    my_token_bucket = None
    try:
        my_token_bucket = dict[username]
        print(f'{username} connect again')
    except KeyError:
        my_token_bucket = token_bucket(rate)
        dict[username]=my_token_bucket
    remote_reader, remote_writer = await asyncio.open_connection(host, port)
    bind_host, bind_port, *_ = remote_writer.get_extra_info('sockname')
    logger.debug(f'connect to {host} {port}, with {bind_host} {bind_port}')
    await aio_write(client_writer,f'{bind_host} {bind_port}\r\n'.encode())
    try:
        await asyncio.gather(handle_local(client_reader, remote_writer,client_writer), handle_remote(client_writer, remote_reader,remote_writer,rate,my_token_bucket))
    except Exception as exc:
        logExc(exc)
        client_writer.close()
        remote_writer.close()

async def main():
    global db
    db = await aiosqlite3.connect("user.db")
    await db.execute("delete from user")
    await db.execute("insert into user values('aaaa','bbbb',5000)")
    cursor = await db.execute("select * from user")
    row=await cursor.fetchone()
    while row:
        print(row)
        row=await cursor.fetchone()
    global dict
    dict={'':None}
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
    #输出log到标准控制流
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

    # python remote_server.py --listen_port 8889 --listen_ip 127.0.0.1