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
