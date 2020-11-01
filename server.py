import asyncio
import struct
import socket
import hashlib
import signal
import logging
import argparse
import sys
import traceback
import ipaddress
SOCKS_VER = 5

from enum import Enum
ReadMode = Enum('ReadMod', ('EXACT', 'LINE', 'MAX', 'UNTIL'))

class program_err(Exception):
    pass

def logExc(exc):
    if args.logExc:
        log.error(f'{traceback.format_exc()}')
    
async def aioClose(writer):
    try:
        if writer:
            writer.close()
            await writer.wait_closed()
    except Exception as exc:
        logExc(exc)

async def aioWrite(writer, data, *, err_hint=None):
    try:
        writer.write(data)
        await w.drain()
    except Exception as exc:
        logExc(exc)
        raise program_err(f'Exc={err_hint}')

async def handle_local(reader, remote_writer):
    while True:
        req_data = await reader.read(4096)
        req_data = decrypt(req_data)
        if not req_data:
            return
        # client_addr=writer.get_extra_info('peername')
        # print('client {} want: {}'.format(client_addr,req_data[0:8]))
        remote_writer.write(req_data)
        await remote_writer.drain()

async def handle_remote(writer, remote_reader):
    while True:
        resp_data = await remote_reader.read(4096)
        if not resp_data:                                                                                                            
            return
        # server_addr=remote_writer.get_extra_info('peername')
        # print('server {} resp: {}'.format(server_addr,resp_data[0:8]))
        resp_data = encrypt(resp_data)
        writer.write(resp_data)
        await writer.drain()
    
def encrypt(data):
    # return data.translate(encrypt_table)
    return data

def decrypt(data):
    # return data.translate(decrypt_table)
    return data

async def aioRead(reader, mode, *, err_hint=None, exact_data=None, len=-1, utilSep=b'\reader\n'):
    data = None
    try:
        if mode == ReadMode.EXACT:
            data = await reader.readexactly(len)
            if exact_data and data != exact_data:
                raise program_err(f'Error {err_hint}={data} correct={exact_data}')
        elif mode == ReadMode.MAX:
            data = await reader.read(len)
        else:
            raise program_err(f'Error mode={mode}')
    except Exception as exc:
        logExc(exc)
        raise exc
    else:
        if not data:
            raise program_err(f'EOF met! can not read {err_hint}')
        return data

async def handle(reader, writer):
    remote_reader, remote_writer = None, None
    try:
        await aioRead(reader, ReadMode.EXACT, exact_data=b'\x05', err_hint='version')
        nmethods=await aioRead(reader,ReadMode.EXACT,len=1)
        await aioRead(reader, ReadMode.EXACT, exact_data=nmethods[0])
        await aioWrite(writer, b'\x05\x00', err_hint='method: no auth')
        
        await aioRead(reader, ReadMode.EXACT, exact_data=b'\x05', err_hint='req:version')
        await aioRead(reader, ReadMode.EXACT, exact_data=b'\x01', err_hint='req:cmd')
        await aioRead(reader, ReadMode.EXACT, exact_data=b'\x00', err_hint='req:rsv')
        atyp = await aioRead(reader, ReadMode.EXACT, len=1, err_hint='req:atyp')

        if atyp == 1:  # IPv4
            ipv4 = await aioRead(reader, ReadMode.EXACT, len=4, err_hint='ipv4')
            remote_addr = socket.inet_ntoa(msg)
            remote_port = struct.unpack('!H', message[temp_pos:temp_pos + port_len])
        elif atyp == 3: # domain
            domain_len = await aioRead(reader, ReadMode.EXACT, len=1, err_hint='domain len')
            remote_addr = await aioRead(reader, ReadMode.EXACT, len=domain_len, err_hint='domain');
            remote_port = struct.unpack('!H', message[temp_pos:temp_pos + port_len])
        elif atyp == 4:  # IPv6
            ipv6 = await aioRead(reader, ReadMode.EXACT, len=16, err_hint='ipv6');
            remote_addr = socket.inet_ntop(socket.AF_INET6, ipv6)
            remote_port = struct.unpack('!H', message[temp_pos:temp_pos + port_len])
        else:
            raise program_err(f'Error atyp={atyp}')
        remote_port = await aioRead(reader, ReadMode.EXACT, len=2, err_hint='port');
        remote_port = int.from_bytes(remote_port, 'big')
        logger.info(f'Receive req from dst={remote_addr},port={remote_port}')
        remote_reader, remote_writer = await asyncio.open_connection(remote_addr, remote_port)
        bind_ip, bind_port, *_ = remote_writer.get_extra_info('sockname')
        logger.info(f'bind to ip={bind_ip}, port={bind_port}')
    except Exception as exc:
        logExc(exc)
    try:
        if cmd == 1:
            try:
                bind_ip = ipaddress.ip_address(bind_ip)
                if bind_ip.version == 4:
                    bind_ip=struct.pack('!L',int(bind_ip))
            except Exception:
                return
            resp = struct.pack(f'!ssss{len(bind_ip)}sH', SOCKS_VER, 0, 0, 1, bind_ip, int(bind_port))
            logger.info('respon to client: {}'.format(resp))
        else:
            resp = "\x05\x07\x00\x01"
            logger.info('command not supported')
    except:
        resp = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
    resp = encrypt(resp)
    writer.write(resp)
    await writer.drain()
    if resp[1] == 0 and cmd == 1:
        try:
            await asyncio.gather(handle_local(reader, remote_writer), handle_remote(writer, remote_reader))
        except (ConnectionResetError):
            writer.close()
            remote_writer.close()
    
async def main():
    server = await asyncio.start_server(
        handle, host=args.listenHost, port=args.listenPort)
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
    handler = logging.FileHandler('server.log')
    formatter = logging.Formatter('%(asctime)s - %(funcName)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # parser
    _parser = argparse.ArgumentParser(description='socks5 server')
    _parser.add_argument('--exc', dest='logExc', default=False, action='store_true', help='show exception traceback')
    _parser.add_argument('--host', dest='listenHost', metavar='listen_host', help='proxy listen host default listen all interfaces')
    _parser.add_argument('--port', dest='listenPort', metavar='listen_port', required=True, help='proxy listen port')
    args = _parser.parse_args()

    if sys.platform == 'win32':
        asyncio.set_event_loop(asyncio.ProactorEventLoop())

    asyncio.run(main())