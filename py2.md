# Python程序设计#2作业

截止时间：2020年11月02日23:59:59

## 作业题目

实现localProxy双协议（SOCKS5和HTTP tunnel）本地代理。

支持（SOCKS5代理）基于#1作业的成果。

支持HTTP tunnel（ 即HTTP CONNECT method）可用于HTTPS代理。

关于HTTP tunnel可以参见：https://www.zhihu.com/question/21955083

## 作业内容

程序源代码嵌入下方的code block中。

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

async def handle_local(reader, remote_writer):
    while True:
        req_data = await reader.read(4096)
        # print(req_data)
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
        # print(resp_data[0:8])
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

async def handle(reader, writer):
    if args.protocal == 'socks5':
        data = await reader.read(3)
        print(f"receive {data}")
        message = decrypt(data)
        addr = writer.get_extra_info('peername')
        print(f"Request from local: {addr[1]!r}")

        version, nmethods, method_1 = struct.unpack("!BBB", message)
        assert version == SOCKS_VER
        assert nmethods > 0
        assert method_1 == 0

        resp_data = struct.pack("!BB", SOCKS_VER, 0)
        resp_message = encrypt(resp_data)
        writer.write(resp_message)
        await writer.drain()

        data = await reader.read(4096)
        print(f"then receive {data}")
        message = decrypt(data)
        header_len = 4
        ipv4_len = 4
        ipv6_len = 16
        port_len = 2
        temp_pos = 0

        header = message[temp_pos:temp_pos + header_len]
        temp_pos = temp_pos + header_len
        ver, cmd, _, atyp = struct.unpack("!BBBB", header)
        assert ver == SOCKS_VER
        if atyp == 1: # IPv4
            remote_addr = socket.inet_ntoa(message[temp_pos:temp_pos + ipv4_len])
            temp_pos = temp_pos + ipv4_len
            remote_port = struct.unpack('!H', message[temp_pos:temp_pos + port_len])
        elif atyp == 3: # domain
            domain_len = message[temp_pos]
            temp_pos = temp_pos + 1
            remote_addr = message[temp_pos:temp_pos + domain_len]
            temp_pos = temp_pos + domain_len
            remote_port = struct.unpack('!H', message[temp_pos:temp_pos + port_len])
        elif atyp == 4:  # IPv6
            remote_addr = socket.inet_ntop(socket.AF_INET6, message[temp_pos:temp_pos + ipv6_len])
            temp_pos = temp_pos + ipv6_len
            remote_port = struct.unpack('!H', message[temp_pos:temp_pos + port_len])
        else:
            return
        try:
            if cmd == 1:
                remote_reader, remote_writer = await asyncio.open_connection(remote_addr, remote_port[0])
                print('Connected to {} {}'.format(remote_addr, remote_port[0]))
                bind_addr = remote_writer.get_extra_info('sockname')
                print('Bind addr: {}'.format(bind_addr))
                try:
                    bind_ip = struct.unpack("!I", socket.inet_aton(bind_addr[0]))[0]
                except socket.error:
                    return
                bind_port = bind_addr[1]
                resp = struct.pack('!BBBBIH', SOCKS_VER, 0, 0, 1, bind_ip, bind_port)
                print('respon to client: {}'.format(resp))
            else:
                resp = "\x05\x07\x00\x01"
                print('command not supported')
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
    elif args.protocal == 'http':
        req = await reader.readline()
        req = bytes.decode(req)
        addr = req.split(" ")
        addr = addr[1].split(":")
        host, port = addr[0], addr[1]
        print(f'receive from {host} {port}')
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
        print(f'connect to {host} {port}')
        writer.write('HTTP/1.1 200 Connection Established\r\n\r\n'.encode())
        await writer.drain()
        data = await reader.read(4096)
        print(data)
        try:
            await asyncio.gather(handle_local(reader, remote_writer), handle_remote(writer, remote_reader))
        except Exception:
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
    _parser.add_argument('--protocal',dest='protocal',metavar='protocal',required=True,help='protocal: socks5 or http')
    args = _parser.parse_args()

    if sys.platform == 'win32':
        asyncio.set_event_loop(asyncio.ProactorEventLoop())

    asyncio.run(main())
```

## 代码说明（可选）

源代码中不要出现大段的说明注释，如果需要可以可以在本节中加上说明。

本次作业在原作业基础上主要增加的是118-135行的代码，同时增加一个命令行参数让用户选择运行协议即可。

HTTP CONNECT中，客户端会在发起请求后发送一些关于代理的信息，以其中一次请求为例，在发起请求后客户端发送了：

```
Host: pic3.zhimg.com:443\r\nProxy-Connection: keep-alive\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36\r\n\r\
```

这部分要求代理服务器对信息进行处理后转发，但在此版本代码中还没有进行处理。

同时此版本的代码意在学习老师提供的作业一的代码，添加命令行参数、日志、统一的读数据函数等，但本周期中考试压力较大，目前仅完成了命令行参数和日志的添加（日志未测试完成），其他部分的修改由于重写后仍存在bug故回退到了较早的版本。计划在接下来两周完成代码的改善和HTTP协议的改善。