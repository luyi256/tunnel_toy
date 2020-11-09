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

async def handle_local(reader, remote_writer,writer):
    while True:
        req_data = await reader.read(4096)
        req_data = decrypt(req_data)
        if not req_data:
            return
        client_addr=writer.get_extra_info('peername')
        print('client {} want: {}'.format(client_addr,req_data[0:8]))
        remote_writer.write(req_data)
        await remote_writer.drain()

async def handle_remote(writer, remote_reader,remote_writer):
    while True:
        resp_data = await remote_reader.read(4096)
        # print(resp_data[0:8])
        if not resp_data:                                                                                                            
            return
        server_addr=remote_writer.get_extra_info('peername')
        print('server {} resp: {}'.format(server_addr,resp_data[0:8]))
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
    first_byte=await reader.read(1)
    if first_byte == b'\x05':
        data = await reader.read(2)
        print(f"receive {data}")
        message = decrypt(data)
        addr = writer.get_extra_info('peername')
        print(f"Request from local: {addr[1]!r}")

        nmethods, method_1 = struct.unpack("!BB", message)
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
                remote_reader, remote_writer = await asyncio.open_connection(args.remote_server_ip, args.remote_server_port)
                print('Connected to remote server')
                remote_writer.write(f'{bytes.decode(remote_addr)}:{remote_port[0]}\r\n'.encode())
                await remote_writer.drain()
                # bind_addr = remote_writer.get_extra_info('sockname')
                # print('Bind addr: {}'.format(bind_addr))
                # try:
                #     bind_ip = struct.unpack("!I", socket.inet_aton(bind_addr[0]))[0]
                # except socket.error:
                #     return
                # bind_port = bind_addr[1]
                bind_ip = struct.unpack("!I", socket.inet_aton(args.remote_server_ip))[0]
                resp = struct.pack('!BBBBIH', SOCKS_VER, 0, 0, 1, bind_ip,int(args.remote_server_port))
            else:
                resp = "\x05\x07\x00\x01"
                print('command not supported')
        except Exception as exc:
            print(exc)
            resp = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'.encode()
        resp = encrypt(resp)
        print('respon to client: {}'.format(resp))
        writer.write(resp)
        await writer.drain()
        if resp[1] == 0 and cmd == 1:
            try:
                await asyncio.gather(handle_local(reader, remote_writer,writer), handle_remote(writer, remote_reader,remote_writer))
            except (ConnectionResetError):
                writer.close()
                remote_writer.close()
    else:
        req = await reader.readline()
        req = bytes.decode(req)
        addr = req.split(" ")
        addr = addr[1].split(":")
        host, port = addr[0], addr[1]
        remote_reader, remote_writer = await asyncio.open_connection(args.remote_server_ip, args.remote_server_port)
        print('Connected to remote server')
        remote_writer.write(f'{host}:{port}\r\n'.encode())
        await remote_writer.drain()
        print(f'connect to {host} {port}')
        writer.write('HTTP/1.1 200 Connection Established\r\n\r\n'.encode())
        await writer.drain()
        data = await reader.read(4096)
        #print(data)
        try:
            await asyncio.gather(handle_local(reader, remote_writer,writer), handle_remote(writer, remote_reader,remote_writer))
        except Exception:
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
    formatter = logging.Formatter('%(asctime)s - %(funcName)s - %(levelname)s - %(message)s')
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