# Python程序设计#6作业

截止时间：2020年11月30日23:59:59

## 作业题目

在作业#5的基础上实现localProxy的图形管理界面localGui

localGui单独一个源文件

可通过图形界面（可以使用QDialog）关闭和开启localProxy

界面上提供remoteProxy的主机地址和端口、认证的用户名和密码（掩码显示）

建议使用QProcess类管理localProxy进程

可以实时查看localProxy的运行状态（是否运行、实时吞吐率）

localGui与localProxy之间采用WebSocket连接（localGui为client）

## localProxy代码

localProxy代码嵌入下方的code block中。

```python
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
import websockets
import time

READ_MODE = Enum(
    'readmode', ('EXACT', 'LINE', 'MAX', 'UNTIL')
)

class program_err(Exception):
    print(Exception)

def logExc(exc):
    if args.logExc:
        logger.error(f'{traceback.format_exc()}')

async def handle_local(client_reader, remote_writer, client_writer):
    global gSendBandwidth
    global send_last
    global send_remain
    while True:
        try:
            req_data = await aio_read(client_reader, READ_MODE.MAX, read_len=4096)
            now = time.time()
            try:
                gSendBandwidth = (len(req_data)+send_remain) / (now - send_last)
                print(f'send:{gSendBandwidth} ')
                send_last = time.time()
                send_remain=0
            except:# 时间间隔太短，浮点数除于0
                send_remain=len(req_data)
            if not req_data:
                return
            client_addr = client_writer.get_extra_info('peername')
            # logger.debug('client {} want: {}'.format(client_addr, req_data[0:8]))
            await aio_write(remote_writer,req_data)
        except Exception as exc:
            logger.debug(exc)
            return

async def handle_remote(client_writer, remote_reader, remote_writer):
    global gRecvBandwidth
    global recv_last
    global recv_remain
    while True:
        try:
            resp_data = await aio_read(remote_reader, READ_MODE.MAX, read_len=4096)
            now = time.time()
            try:
                gRecvBandwidth = (len(resp_data) + recv_remain) / (now - recv_last)
                recv_last = time.time()
                recv_remain=0
            except:
                recv_remain=len(resp_data)
                pass
            if not resp_data:
                return
            server_addr = remote_writer.get_extra_info('peername')
            # logger.debug('server {} resp: {}'.format(server_addr, resp_data[0:8]))
            await aio_write(client_writer,resp_data)
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
        raise program_err(f'EXC={exc} {log_hint}')
    except Exception as exc:
        logger.debug(exc)

async def handle(client_reader, client_writer):
    client_host, client_port, *_ = client_writer.get_extra_info('peername')
    logger.info(f'Request from local: {client_host} {client_port}')
    first_byte = await aio_read(client_reader, READ_MODE.EXACT, read_len=1, log_hint=f'first byte from {client_host} {client_port}')
    log_hint=f'{client_host} {client_port}'
    remote_host = None
    remote_port = None
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
                remote_host = str(ipaddress.ip_address(temp_addr))
            elif atyp == b'\x03':  # domain
                domain_len = await aio_read(client_reader, READ_MODE.EXACT, read_len=1, log_hint='domain len')
                remote_host = await aio_read(client_reader, READ_MODE.EXACT, read_len=domain_len[0], log_hint='domain')
                remote_host = remote_host.decode('utf8')
            elif atyp == b'\x04':  # IPv6
                temp_addr = await aio_read(client_reader, READ_MODE.EXACT, read_len=16, log_hint='ipv6')
                remote_host = str(ipaddress.ip_address(temp_addr))
            else:
                raise program_err(f'invalid atyp')
            remote_port = await aio_read(client_reader, READ_MODE.EXACT, read_len=2, log_hint='port')
            remote_port = int.from_bytes(remote_port, 'big')            
        else:
            req = await aio_read(client_reader, READ_MODE.LINE, log_hint='http request')
            req = bytes.decode(first_byte+req)
            method, uri, protocal, *_ = req.split()
            if method.lower() == 'connect':
                proxy_protocal = 'HTTPS'
                log_hint=f'{log_hint} {proxy_protocal}'
                remote_host, remote_port, *_ = uri.split(':')
                await aio_read(client_reader, READ_MODE.UNTIL, until_str=b'\r\n\r\n', log_hint='message left')
            else:
                raise program_err(f'cannot server the request {req.split()}')
        
        logger.info(f'{log_hint} connect to {remote_host} {remote_port}')

        remote_reader, remote_writer = await asyncio.open_connection(args.remote_server_ip, args.remote_server_port)
        await aio_write(remote_writer, f'{remote_host} {remote_port} {args.username} {args.password}\r\n'.encode(),
            log_hint=f'{log_hint} connect to remote server, {remote_host} {remote_port}')
        reply_bindaddr = await aio_read(remote_reader, READ_MODE.LINE, log_hint='remote server reply the bind addr')
        reply_bindaddr = bytes.decode(reply_bindaddr)
        addr = reply_bindaddr[:-2].split()
        bind_host, bind_port=addr[0],addr[1]
        logger.info(f'{log_hint} bind at {bind_host} {bind_port}')

        if proxy_protocal == 'SOCKS5':
            bind_domain=bind_host
            bind_host = ipaddress.ip_address(bind_host)
            atyp = b'\x03'
            host_data = None
            try:
                if bind_host.version == 4:
                    atyp = b'\x01'
                    host_data = struct.pack('!L', int(bind_host))
                    reply_data = struct.pack(f'!ssss', b'\x05', b'\x00', b'\x00', atyp)+host_data+struct.pack('!H',int(bind_port))
                else:
                    atyp = b'\x04'
                    host_data = struct.pack('!16s', ipaddress.v6_int_to_packed(int(bind_host)))
                    reply_data = struct.pack(f'!ssss', b'\x05', b'\x00', b'\x00', atyp)+host_data+struct.pack('!H',int(bind_port))
            except Exception as exc:
                logExc(exc)
                host_data = struct.pack(f'!B{len(bind_domain)}s', len(bind_domain), bind_domain.encode())
                reply_data = struct.pack(f'!ssss{len(host_data)}sH', b'\x05', b'\x00', b'\x00', atyp, host_data, int(bind_port))

            await aio_write(client_writer, reply_data, log_hint='reply the bind addr')
        else:
            await aio_write(client_writer, f'{protocal} 200 OK\r\n\r\n'.encode(), log_hint='response to HTTPS')
            
        try:
            await asyncio.gather(handle_local(client_reader, remote_writer, client_writer), handle_remote(client_writer, remote_reader, remote_writer))
        except Exception as exc:
                logExc(exc)
                client_writer.close()
                remote_writer.close()
    except program_err as exc:
        logger.info(f'{log_hint} {exc}')
        await client_writer.close()
        await remote_writer.close()
    except OSError:
        logger.info(f'{log_hint} connect fail')
        await client_writer.close()
    except Exception as exc:
        logger.error(f'{traceback.format_exc()}')
        exit(1)


async def local_console(ws, path):
    try:
        while True:
            await asyncio.sleep(1)
            msg = await ws.send(f'{round(gSendBandwidth,2)} {round(gRecvBandwidth,2)}')
    except websockets.exceptions.ConnectionClosedError as exc:
        logger.error(f'web1 {exc}')
    except websockets.exceptions.ConnectionClosedOK as exc:
        logger.error(f'web2 {exc}')
    except Exception:
        logger.error(f'web3 {traceback.format_exc()}')
        exit(1)

async def main():
    global gSendBandwidth
    global gRecvBandwidth
    gRecvBandwidth = 0
    gSendBandwidth = 0
    global send_last
    global recv_last
    send_last = time.time()
    recv_last = time.time()
    global send_remain
    global recv_remain
    send_remain = 0
    recv_remain = 0
    if args.console_port:
        ws_server = await websockets.serve(local_console, '127.0.0.1', args.console_port)
        logger.info(f'CONSOLE LISTEN {ws_server.sockets[0].getsockname()}')
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
    # 输出log到标准控制流
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
    _parser.add_argument('--password', dest='password',
                         metavar='password', required=True, help='password')
    _parser.add_argument('--console_port', dest='console_port',
                         metavar='console_port', required=True, help='console_port')                     
    args = _parser.parse_args()
    logger.debug(f'{args}')

    if sys.platform == 'win32':
        asyncio.set_event_loop(asyncio.ProactorEventLoop())

    asyncio.run(main())

#  python local_server.py --listen_port 8888 --remote_port 8889 --remote_ip 127.0.0.1 --user aaaa --pw bbbb
```

## localGui代码

localGui代码嵌入下方的code bock中。

```python
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from PyQt5.QtNetwork import *
from PyQt5.QtWidgets import *
from PyQt5.QtWebSockets import *
import sys
import os
import logging
import traceback
import humanfriendly


class Window(QDialog):
    def __init__(self, parent=None):
        QDialog.__init__(self, parent,Qt.WindowMinMaxButtonsHint|Qt.WindowCloseButtonHint)
        self.setWindowTitle('Local APP')

        self.listenHostLine = QLineEdit('127.0.0.1')
        self.listenPortLine = QLineEdit('8888')
        self.listenPortLine.setPlaceholderText('1025-65535')

        self.remoteHostLine = QLineEdit('127.0.0.1')
        self.remotePortLine = QLineEdit('8889')
        self.remotePortLine.setPlaceholderText('1025-65535')

        self.consolePortLine = QLineEdit('8890')

        self.usernameLine = QLineEdit("aaaa")
        self.passwordLine = QLineEdit("bbbb")
        self.passwordLine.setEchoMode(QLineEdit.Password)

        self.startBtn = QPushButton("Start")
        self.startBtn.clicked.connect(self.startClicked)
        self.sendBandwidthLine = QLineEdit()
        self.recvBandwidthLine = QLineEdit()
        self.processIdLine = QLineEdit()
        self.closeBtn = QPushButton()
        self.closeBtn.clicked.connect(self.closeClicked)
        
        self.formLayout = QFormLayout()
        self.formLayout.addRow(QLabel('Listen Host:'), self.listenHostLine)
        self.formLayout.addRow(QLabel('Listen Port:'), self.listenPortLine)
        self.formLayout.addRow(QLabel('Remote Host:'), self.remoteHostLine)
        self.formLayout.addRow(QLabel('Remote Port:'), self.remotePortLine)
        self.formLayout.addRow(QLabel('Console Port:'), self.consolePortLine)
        self.formLayout.addRow(QLabel('Username:'), self.usernameLine)
        self.formLayout.addRow(QLabel('Password:'), self.passwordLine)
        self.formLayout.addRow(QLabel(''), self.startBtn)
           
        self.setLayout(self.formLayout)

        self.process = QProcess()
        self.process.setProcessChannelMode(QProcess.MergedChannels)
        self.process.started.connect(self.processStarted)
        self.process.readyReadStandardOutput.connect(self.processReadyRead)
        
    def processReadyRead(self):
        data = self.process.readAll()
        try:
            msg = data.data()
            logger.debug(f'msg={msg}')
        except Exception as exc:
            logger.error(f'{traceback.format_exc()}')
            exit(1)
        
    def processStarted(self):
        process = self.sender() # 此处等同于 self.process 只不过使用sender适应性更好
        processId = process.processId()
        logger.debug(f'pid={processId}')
        self.formLayout.removeRow(self.startBtn)
        self.formLayout.addRow(QLabel('process ID:'), self.processIdLine)
        self.formLayout.addRow(QLabel('Send Band(/s):'), self.sendBandwidthLine)
        self.formLayout.addRow(QLabel('Recv Band(/s):'), self.recvBandwidthLine)
        self.closeBtn.setText("Close")
        self.formLayout.addRow('',self.closeBtn)
        self.processIdLine.setText(str(processId))
        self.websocket = QWebSocket()
        self.websocket.connected.connect(self.websocketConnected)
        self.websocket.disconnected.connect(self.websocketDisconnected)
        self.websocket.textMessageReceived.connect(self.websocketMsgRcvd)
        try:
            self.websocket.open(QUrl(f'ws://127.0.0.1:{self.consolePortLine.text()}/'))
        except Exception as exc:
            print(exc)

    def startClicked(self):
        btn = self.sender()
        text = btn.text().lower()
        if text.startswith('start'):
            listenPort = self.listenPortLine.text()
            username = self.usernameLine.text()
            password = self.passwordLine.text()
            consolePort = self.consolePortLine.text()
            remoteHost = self.remoteHostLine.text()
            remotePort = self.remotePortLine.text()
            pythonExec = os.path.basename(sys.executable)
            cmdLine = f'{pythonExec} local_server.py --listen_port {listenPort} --user {username} --password {password} --remote_ip {remoteHost} --remote_port {remotePort} --console_port {consolePort}'
            logger.debug(f'cmd={cmdLine}')
            self.process.start(cmdLine)
        else:
            self.process.kill()

    def closeClicked(self):
        self.process.kill()
        exit(1)

    def websocketConnected(self):
        logger.info('websocket connected')

    def websocketDisconnected(self):
        logger.info('websocket disconnected')

    def websocketMsgRcvd(self, msg):
        logger.debug(f'band={msg}')
        sendBandwidth, recvBandwidth, *_ = msg.split()
        nowTime = QDateTime.currentDateTime().toString('hh:mm:ss')
        self.sendBandwidthLine.setText(f'{nowTime} {humanfriendly.format_size(float(sendBandwidth))}')
        self.recvBandwidthLine.setText(f'{nowTime} {humanfriendly.format_size(float(recvBandwidth))}')


if __name__ == '__main__':
    # logging
    logger = logging.getLogger(__name__)
    logger.setLevel(level=logging.DEBUG)
    handler = logging.FileHandler('local_gui.log')
    formatter = logging.Formatter(
        '%(asctime)s %(levelname).1s %(lineno)-3d %(funcName)-20s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    # 输出log到标准控制流
    chlr = logging.StreamHandler()
    logger.addHandler(chlr)

    app = QApplication(sys.argv)
    app.setStyle('Windows')
    win = Window()
    win.show()
    sys.exit(app.exec_())
```

## 代码说明

源代码中不要出现大段的说明注释，所有文字描述在本节中以行号引用说明。

本次作业实现本地代理服务器的图形界面，使用PyQt5实现，为此需要安装PyQt5和websockets。

### LocalProxy部分

这部分的修改是

1. 增加websockets服务器，跟GUI连接用于传输带宽信息
   开启websockets服务器在230-232行，直接使用相关函数即可。
   计算带宽使用的是当接收或发送信息时计算当前的速率为$本次信息量/(当前时间-上次时间)$，单位是b/s。但这种算法可能会出现当前时间和上次时间之差等于0的情况，此时可以设置一个remain量，如果当前时间和上次时间之差等于0，则不进行计算，而是记录本次的信息量到remain中，下次一起计算。所以改进的公式是$(本次信息量+上次未计算的信息量)/(当前时间-上次时间)$。若可以时间差不等于0，则可以计算， 重新设定上次时间（设为当前时间）、上次未计算的信息量（设为0）；若时间差等于0，则不改动上次时间，修改上次未计算的信息量为本次信息量。这部分改动在27行的`handle_local`函数和51行的`handle_remote`函数中。
   发送带宽在207-218行的`local_console`函数中，使用websockets的`send`函数即可。

2. 修改密码为执行LocalProxy的时候通过命令行参数输入
   这部分的修改涉及到发送给远程代理服务器和命令行参数的修改，修改较为简单，不再展开。



### LocalGUI部分

LocalGUI的界面如下所示：

![image-20201128161540568](E:\python\fig\image-20201128161540568.png)

![image-20201128161713080](E:\python\fig\image-20201128161713080.png)

这部分和在Qt中实现图形界面是一致的，只是修改为Python的编程习惯。

首先在创建一个应用，创建Window类。Window类中的各个函数就是核心的内容。

#### `__init__`函数

将该类涉及到的所有的组件先创建，并且设置初始图形界面，这部分是16-50行；创建一个进程对象，进行相关的信号槽绑定，例如进程开始的信号槽，捕获进程的标准输出流的信号槽。

#### `startClicked`函数

这是start按钮的信号槽，点击开始意味着用户请求开启连接，此时读取用户输入的所有内容，作为进程开启的命令行参数，然后开始进程。

#### `processStarted`函数

在点击start键后，正常执行的情况下进程会开启，即会调用`processStarted`函数，在该函数内，我们应该重新设定图形界面，因为此时需要展示带宽、进程编号等等信息，同时需要去掉开启按钮， 增加关闭按钮。

除了图形界面的工作外，还需要创建websocket连接以获取LocalProxy发出来的带宽信息，这部分在77-84行，创建websocket，进行连接，并且进行相关的信号槽连接，最重要的就是`textMessageReceived`信号的连接，该信号槽用来接收带宽信息并显示。

#### `websocketMsgRcvd`函数

这是`textMessageReceived`信号的槽函数，接收带宽信息，并且进行显示。

#### `closeClicked()`函数

该函数是点击close按钮的槽函数，用于关闭该代理服务器，需要做的事情是关闭进程并退出整个程序。

