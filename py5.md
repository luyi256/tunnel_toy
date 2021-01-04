# Python程序设计#5作业

截止时间：2020年11月23日23:59:59

## 作业题目

在作业#4的基础上实现remoteProxy对每个用户进行单独流控

SQLite3数据库的每个用户的账号信息中增加带宽信息（用户名、密码、带宽）

带宽的单位为BPS（Bytes / Second，字节每秒），该带宽为某个用户的所有连接的转发数据总和带宽。

此次作业需要在【代码说明】中陈述流控的技术方案和实现机制。

## 作业内容

程序源代码嵌入下方的code block中。

```python
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
    assert password == row[0]
    rate = row[1]
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
```

## 代码说明

源代码中不要出现大段的说明注释，所有文字描述在本节中以行号引用说明。

![image-20201121171148663](E:\python\fig\image-20201121171148663.png)



如图所示，本次作业要求实现的是限制remote proxy向local proxy发送数据的速度，即限制从接收缓冲区中取出数据的速度。

原设计是每当接收到app server的数据，马上转发给local proxy；使用令牌桶算法，现设计为每当接收到app server的数据，就获取当前最大能获取的令牌数量，进而读取相应大小的数据内容，转发给local proxy。

令牌桶可以使用python asyncio库的Synchronization Primitives中的Lock轻松实现，本设计中实现了令牌桶类`token_bucket`，该类有四个成员：

- `rate`（流量速率）
- `last`（上次获取令牌的时间）
- `tokens`（桶内的令牌数量）
- `_consume`（同步互斥锁）

具体实现在18-42行，核心为`consume`函数。`consume`函数获取当前的`token_bucket`类的对象的锁，接着判断当前的桶内的令牌数量，具体实现为(当前时间-上次获取的时间)*rate+原token量，改变桶内的令牌数量后，同时改变`last`为当前的时间。若桶内的令牌数量超过需要的令牌数量，将返回需要的令牌数量表示当前可以取令牌，否则返回0。

主程序调用令牌桶的方式如下：

1. 当一个新的连接到来，先到字典dist内查找当前用户的`token_bucket`对象，若找到，即直接使用该对象来完成后续的流量控制操作，转2；否则先给该用户建立一个`token_bucket`对象再转2。这个实现是考虑到用户可能有多个连接请求，但总的连接流量应该保持低于限制的流量。实现在134-140行。
2. 将`token_bucket`对象作为参数传递给`handle_remote`函数，该函数内先调用`token_bucket`对象的`consume`函数来确定当前是否能获取1024个令牌，若可以，则读取1024大小的数据并转发，否则先睡眠0.5秒。该设定是为了防止`handle_remote`内的`while`忙等待，睡眠时间最好能够保证睡醒后可以获取到足够数量的令牌，这些写死为0.5秒是为了简化程序流程，减少运行时的计算负担，可以测出更为真实的速度。
3. 循环2，直至连接终止。



测试结果如下：

当限制速度为3000BPS时，可以测得程序较为稳定地维持在2600-3000之间：

![image-20201123195246306](E:\python\fig\image-20201123195246306.png)

当限制速度为5000BPS时，可以测得程序较为稳定地维持在4700-5000之间：

![image-20201123195617009](E:\python\fig\image-20201123195617009.png)

实际上令牌桶算法允许小时间的突发，实际测试时，当限制速度为5000BPS时，可以观测到如下结果：

![image-20201123195840374](E:\python\fig\image-20201123195840374.png)

但这种突然不会维持较长时间，而且平均流量不会超出限制的流量。