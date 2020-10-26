import asyncio
import struct
import socket
SOCKS_VER = 5

async def handle_local(reader, writer, remote_writer):
    while True:
        req_data = await reader.read(4096)
        if not req_data:
            return
        client_addr=writer.get_extra_info('peername')
        print('client {} want: {}'.format(client_addr,req_data[0:8]))
        remote_writer.write(req_data)
        await remote_writer.drain()

async def handle_remote(writer, remote_writer, remote_reader):
    while True:
        resp_data = await remote_reader.read(4096)
        if not resp_data:
            return
        server_addr=remote_writer.get_extra_info('peername')
        print('server {} resp: {}'.format(server_addr,resp_data[0:8]))
        writer.write(resp_data)
        await writer.drain()
    
def encrypt(data):
    return data

def decrypt(data):
    return data

async def handle(reader, writer):
    data = await reader.read(3)
    addr = writer.get_extra_info('peername')
    print(f"Request from local: {addr[1]!r}")

    version, nmethods, method_1 = struct.unpack("!BBB", data)
    assert version == SOCKS_VER
    assert nmethods > 0
    assert method_1 == 0

    resp = struct.pack("!BB", SOCKS_VER, 0)
    resp = encrypt(resp)
    writer.write(resp)
    await writer.drain()

    data = await reader.read(4096)
    message = decrypt(data)
    header = message[0:4]
    ver, cmd, _, atyp = struct.unpack("!BBBB", header)
    assert ver == SOCKS_VER
    if atyp == 1: # IPv4
        remote_addr = socket.inet_ntoa(message[4:8])
        remote_port = struct.unpack('!H',message[9:11])
    elif atyp == 3: # domain
        domain_len = message[4]
        remote_port = struct.unpack('!H',message[5 + domain_len:7 + domain_len])
        remote_addr = message[5:5 + domain_len]
    elif atyp == 4:  # IPv6
        remote_addr = socket.inet_ntop(socket.AF_INET6, message[5:21])
        remote_port=struct.unpack('!H',message[22:24])
    else:
        stream.close()
        await stream.wait_closed()
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
                # bind_ip = struct.unpack("!II",socket.inet_ntop(socket.AF_INET6, bind_addr[0]))[0]
            bind_port = bind_addr[1]
            resp = struct.pack('!BBBBIH', SOCKS_VER, 0, 0, 1, bind_ip, bind_port)
            print('respon to client: {}'.format(resp))
        else:
            resp = "\x05\x07\x00\x01"  #cannot resp to the request
            print('command not supported')
    except:
        resp = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
    writer.write(resp)
    await writer.drain()
    if resp[1] == 0 and cmd == 1:
        try:
            await asyncio.gather(handle_local(reader, writer, remote_writer), handle_remote(writer, remote_writer, remote_reader))
        except (ConnectionResetError):
            writer.close()
            remote_writer.close()
    
async def main():
    server = await asyncio.start_server(
        handle, '127.0.0.1', 8888)
    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

asyncio.run(main())