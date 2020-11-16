from enum import Enum
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

READ_MODE = Enum(
    'readmode', ('EXACT', 'LINE', 'MAX', 'UNTIL')
)


class program_err(Exception):
    print(Exception)


def logExc(exc):
    if args.logExc:
        logger.error(f'{traceback.format_exc()}')


async def handle_local(client_reader, remote_writer, client_writer):
    while True:
        try:
            req_data = await client_reader.read(4096)
            if not req_data:
                return
            client_addr = client_writer.get_extra_info('peername')
            logger.debug('client {} want: {}'.format(client_addr, req_data[0:8]))
            remote_writer.write(req_data)
            await remote_writer.drain()
        except Exception as exc:
            logger.debug(exc)


async def handle_remote(client_writer, remote_reader, remote_writer):
    while True:
        try:
            resp_data = await remote_reader.read(4096)
            logger.debug(resp_data[0:8])
            if not resp_data:
                return
            server_addr = remote_writer.get_extra_info('peername')
            logger.debug('server {} resp: {}'.format(server_addr, resp_data[0:8]))
            client_writer.write(resp_data)
            await client_writer.drain()
        except Exception as exc:
            logger.debug(exc)


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
    client_host, client_port, *_ = client_writer.get_extra_info('peername')
    logger.info(f'Request from local: {client_host} {client_port}')
    first_byte = await aio_read(client_reader, READ_MODE.EXACT, read_len=1, log_hint=f'first byte from {client_host}:{client_port}')
    # SOCK5 部分
    remote_host = None
    remote_port=None
    try:
        if first_byte == b'\x05':
            proxy_protocal = 'SOCKS5'
            nmethods = await aio_read(client_reader, READ_MODE.EXACT, read_len=1, log_hint=f'nmethods')
            await aio_read(client_reader, READ_MODE.EXACT, read_len=nmethods[0], log_hint='methods')
            resp_data = struct.pack("!BB", SOCKS_VER, 0)
            await aio_write(client_writer, b'\x05\x00', log_hint='reply no auth')
            await aio_read(client_reader, READ_MODE.EXACT, exact_data=b'\x05\x01\x00', read_len=1, log_hint='version command reservation')
            atyp = await aio_read(client_reader, READ_MODE.EXACT, read_len=1, log_hint=f'atyp')
            if atyp == b'\x01':  # IPv4
                temp_addr = await aio_read(client_reader, READ_MODE.EXACT, read_len=4, log_hint='ipv4')
                remote_host = str(ipaddress.ip_address(dstHost))
            elif atyp == b'\x03':  # domain
                domain_len = await aio_read(client_reader, READ_MODE.EXACT, read_len=1, log_hint='domain len')
                remote_host = await aio_read(client_reader, READ_MODE.EXACT, read_len=domain_len[0], log_hint='domain')
                remote_host = remote_host.decode('utf8')
            elif atyp == b'\x04':  # IPv6
                temp_addr = await aio_read(client_reader, READ_MODE.EXACT, read_len=16, log_hint='ipv6')
                remote_host = str(ipaddress.ip_address(dstHost))
            else:
                raise program_err(f'invalid atyp')
            remote_port = await aio_read(client_reader, READ_MODE.EXACT, read_len=2, log_hint='port')
            remote_port = int.from_bytes(remote_port, 'big')            
            log_hint = f'{client_host}:{client_port}'
            logger.info(f'{log_hint} connect to {remote_host}:{remote_port}')

            remote_reader, remote_writer = await asyncio.open_connection(args.remote_server_ip, args.remote_server_port)
            logger.info('Connected to remote server')
            await aio_write(remote_writer, f'{remote_host}:{remote_port}:{args.username}:{password}\r\n'.encode(),
                log_hint=f'{log_hint} connect to remote server, {remote_host}:{remote_port}')
            reply_bindaddr = await aio_read(remote_reader, READ_MODE.LINE, log_hint='remote server reply the bind addr')
            reply_bindaddr = bytes.decode(reply_bindaddr)
            addr = reply_bindaddr[:-2].split(":")
            bind_host, bind_port=addr[0],int(addr[1])
            logger.info(f'{log_hint} bind at {bind_host}:{bind_port}')
            if proxy_protocal == 'SOCKS5':
                bind_domain=bind_host
                bind_host = ipaddress.ip_address(bind_host)
                atyp = b'\x03'
                host_data=None
                try:
                    if bind_host.version == 4:
                        atyp = b'\01'
                        host_data = struct.pack('!L', int(bind_host))
                    else:
                        atyp = b'\x04'
                        host_data = struct.pack('!16s', ipaddress.v6_int_to_packed(int(bind_host)))
                except Exception as exc:
                    host_data = struct.pack(f'!B{len(bind_domain)}s', len(bind_domain), bind_domain.encode())
                reply_data = struct.pack(f'!ssss{len(host_data)}sH', b'\x05', b'\x00', b'\x00', atyp, host_data, bind_port)
                logger.debug(reply_data)
                await aio_write(client_writer, reply_data, log_hint='reply the bind addr')  
                try:
                    await asyncio.gather(handle_local(client_reader, remote_writer, client_writer), handle_remote(client_writer, remote_reader, remote_writer))
                except Exception as exc:
                    logExc(exc)
                    logger.info(exc)
                    client_writer.close()
                    remote_writer.close()
                    
        else:
            req = await client_reader.readline()
            req = bytes.decode(req)
            addr = req.split(" ")
            addr = addr[1].split(":")
            host, port = addr[0], addr[1]
            remote_reader, remote_writer = await asyncio.open_connection(args.remote_server_ip, args.remote_server_port)
            logger.debug('Connected to remote server')
            remote_writer.write(
                f'{host}:{port}:{args.username}:{password}\r\n'.encode())
            await remote_writer.drain()
            logger.info(f'connect to {host} {port}')
            client_writer.write(
                'HTTP/1.1 200 Connection Established\r\n\r\n'.encode())
            await client_writer.drain()
            data = await client_reader.read(4096)
            try:
                await asyncio.gather(handle_local(client_reader, remote_writer, client_writer), handle_remote(client_writer, remote_reader, remote_writer))
            except Exception as exc:
                logExc(exc)
                client_writer.close()
                remote_writer.close()
    except Exception as exc:
            logExc(exc)
            logger.debug(exc)
            resp = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'.encode()
            logger.debug('respon to client: {}'.format(resp))
            client_writer.write(resp)
            await client_writer.drain()

async def main():
    server = await asyncio.start_server(
        handle, host=args.listen_ip, port=args.listen_port)
    addr = server.sockets[0].getsockname()
    logger.info(f'Serving on {addr[1]}')
    async with server:
        await server.serve_forever()


if __name__ == '__main__':

    # interrupt from keyboard, perform the default function for the signal
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    # logging
    logger = logging.getLogger(__name__)
    logger.setLevel(level=logging.DEBUG)
    handler = logging.FileHandler('local_server.log')
    formatter = logging.Formatter(
        '%(asctime)s %(levelname).1s %(lineno)-3d %(funcName)-20s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    chlr = logging.StreamHandler()
    logger.addHandler(chlr)

    # parser
    _parser = argparse.ArgumentParser(description='server')
    _parser.add_argument('--exc', dest='logExc', default=False,
                         action='store_true', help='show exception traceback')
    _parser.add_argument('--listen_ip', dest='listen_ip', metavar='listen_host',
                         help='proxy listen host default listen all interfaces')
    _parser.add_argument('--listen_port', dest='listen_port',
                         metavar='listen_port', required=True, help='proxy listen port')
    _parser.add_argument('--remote_ip', dest='remote_server_ip',
                         metavar='remote_server_ip', required=True, help='remote server ip')
    _parser.add_argument('--remote_port', dest='remote_server_port',
                         metavar='remote_server_port', required=True, help='remote server port')
    _parser.add_argument('--user', dest='username',
                         metavar='username', required=True, help='username')
    args = _parser.parse_args()
    logger.debug(f'{args}')

    password = input("please input your password:\n")

    if sys.platform == 'win32':
        asyncio.set_event_loop(asyncio.ProactorEventLoop())

    asyncio.run(main())
