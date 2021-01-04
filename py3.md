# Python程序设计#3作业

截止时间：2020年11月09日23:59:59

## 作业题目

实现localProxy和remoteProxy分离式代理。

支持SOCKS5代理和HTTPS代理（基于#2作业的成果）。

localProxy收到的每个TCP连接单独建立代理TCP连接。

## 作业内容

程序源代码嵌入下方的code block中。

local_server.py：

```python
import asyncio
import struct
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
        logger.debug(resp_data[0:8])
        if not resp_data:                                                                                                            
            return
        server_addr=remote_writer.get_extra_info('peername')
        logger.debug('server {} resp: {}'.format(server_addr,resp_data[0:8]))
        writer.write(resp_data)
        await writer.drain()

async def handle(reader, writer):
    first_byte = await reader.read(1)
    # SOCK5 部分
    if first_byte == b'\x05':
        data = await reader.read(2)
        logger.debug(f"receive {data}")
        addr = writer.get_extra_info('peername')
        logger.info(f"Request from local: {addr[1]!r}")
        nmethods, method_1 = struct.unpack("!BB", data)
        assert nmethods > 0
        assert method_1 == 0
        resp_data = struct.pack("!BB", SOCKS_VER, 0)
        writer.write(resp_data)
        await writer.drain()
        data = await reader.read(4096)
        header_len = 4
        ipv4_len = 4
        ipv6_len = 16
        port_len = 2
        temp_pos = 0
        header = data[temp_pos:temp_pos + header_len]
        temp_pos = temp_pos + header_len
        ver,cmd, _, atyp = struct.unpack("!BBBB", header)
        assert ver == SOCKS_VER
        if atyp == 1: # IPv4
            remote_addr = socket.inet_ntoa(data[temp_pos:temp_pos + ipv4_len])
            temp_pos = temp_pos + ipv4_len
            remote_port = struct.unpack('!H', data[temp_pos:temp_pos + port_len])
        elif atyp == 3: # domain
            domain_len = data[temp_pos]
            temp_pos = temp_pos + 1
            remote_addr = data[temp_pos:temp_pos + domain_len]
            temp_pos = temp_pos + domain_len
            remote_port = struct.unpack('!H', data[temp_pos:temp_pos + port_len])
        elif atyp == 4:  # IPv6
            remote_addr = socket.inet_ntop(socket.AF_INET6, data[temp_pos:temp_pos + ipv6_len])
            temp_pos = temp_pos + ipv6_len
            remote_port = struct.unpack('!H', data[temp_pos:temp_pos + port_len])
        else:
            return
        try:
            if cmd == 1:
                remote_reader, remote_writer = await asyncio.open_connection(args.remote_server_ip, args.remote_server_port)
                logger.info('Connected to remote server')
                remote_writer.write(f'{bytes.decode(remote_addr)}:{remote_port[0]}\r\n'.encode())
                await remote_writer.drain()
                bind_ip = struct.unpack("!I", socket.inet_aton(args.remote_server_ip))[0]
                resp = struct.pack('!BBBBIH', SOCKS_VER, 0, 0, 1, bind_ip,int(args.remote_server_port))
            else:
                resp = "\x05\x07\x00\x01"
                logger.error('command not supported')
        except Exception as exc:
            logExc(exc)
            resp = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'.encode()
        logger.debug('respon to client: {}'.format(resp))
        writer.write(resp)
        await writer.drain()
        if resp[1] == 0 and cmd == 1:
            try:
                await asyncio.gather(handle_local(reader, remote_writer,writer), handle_remote(writer, remote_reader,remote_writer))
            except Exception as exc:
                logExc(exc)
                writer.close()
                remote_writer.close()
    else:
        req = await reader.readline()
        req = bytes.decode(req)
        addr = req.split(" ")
        addr = addr[1].split(":")
        host, port = addr[0], addr[1]
        remote_reader, remote_writer = await asyncio.open_connection(args.remote_server_ip, args.remote_server_port)
        logger.debug('Connected to remote server')
        remote_writer.write(f'{host}:{port}\r\n'.encode())
        await remote_writer.drain()
        logger.info(f'connect to {host} {port}')
        writer.write('HTTP/1.1 200 Connection Established\r\n\r\n'.encode())
        await writer.drain()
        data = await reader.read(4096)
        try:
            await asyncio.gather(handle_local(reader, remote_writer,writer), handle_remote(writer, remote_reader,remote_writer))
        except Exception as exc:
            logExc(exc)
            writer.close()
            remote_writer.close()

async def main():
    server = await asyncio.start_server(
        handle, host=args.listen_ip, port=args.listen_port)
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
    handler = logging.FileHandler('local_server.log')
    formatter = logging.Formatter('%(asctime)s %(levelname).1s %(lineno)-3d %(funcName)-20s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # parser
    _parser = argparse.ArgumentParser(description='server')
    _parser.add_argument('--exc', dest='logExc', default=False, action='store_true', help='show exception traceback')
    _parser.add_argument('--listen_ip', dest='listen_ip', metavar='listen_host', help='proxy listen host default listen all interfaces')
    _parser.add_argument('--listen_port', dest='listen_port', metavar='listen_port', required=True, help='proxy listen port')
    _parser.add_argument('--remote_ip', dest='remote_server_ip', metavar='remote_server_ip', required=True,help='remote server ip')
    _parser.add_argument('--remote_port', dest='remote_server_port', metavar='remote_server_port', required=True, help='remote server port')
    args = _parser.parse_args()

    if sys.platform == 'win32':
        asyncio.set_event_loop(asyncio.ProactorEventLoop())

    asyncio.run(main())
```

remote_server.py：

```python
import asyncio
import struct
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
    addr = req[:-2].split(":")
    logger.info(f'remote server receive request {req[:-2]}')
    host, port = addr[0], int(addr[1])
    remote_reader, remote_writer = await asyncio.open_connection(host, port)
    logger.debug(f'connect to {host} {port}')
    try:
        await asyncio.gather(handle_local(reader, remote_writer,writer), handle_remote(writer, remote_reader,remote_writer))
    except Exception as exc:
        logExc(exc)
        writer.close()
        remote_writer.close()

async def main():
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

    # parser
    _parser = argparse.ArgumentParser(description='server')
    _parser.add_argument('--exc', dest='logExc', default=False, action='store_true', help='show exception traceback')
    _parser.add_argument('--listen_ip', dest='listen_host', metavar='listen_host', help='proxy listen host default listen all interfaces')
    _parser.add_argument('--listen_port', dest='listen_port', metavar='listen_port', required=True, help='proxy listen port')
    args = _parser.parse_args()

    if sys.platform == 'win32':
        asyncio.set_event_loop(asyncio.ProactorEventLoop())

    asyncio.run(main())
```

## 代码说明（可选）

源代码中不要出现大段的说明注释，如果需要可以可以在本节中加上说明。

local server和本地浏览器之间实现了HTTP协议和SOCKS5协议，核心代码在local_server.py的handle函数内。两个协议共用一个端口。

而local server和remote server之间使用了自定义的最为简洁的协议——local server向remote server发送格式如'[host]:[port]'的报文，告知remote server需要连接的地址。local server的发送部分在local_server.py的79-82行(SOCKS5)和107-110行（HTTP）。remote server对于接受到的消息和连接位于remote_server.py的37-43行。完成连接后，local server和remote server进行相同的转发操作即可。

同时这次作业完善了上次没有完成的日志功能和报告例外功能，现在能较为有效地输出日志信息、调试信息和程序的错误（exception报告），方便了程序的debug。

但目前代码整体上还是不够精炼，后期准备学习老师提供的范例优化stream的读写。