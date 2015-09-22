import asyncio
import socks3
import socket
import traceback
import logging
import threading

VERSION = 'socks2http/0.01'
HTTPVER = 'HTTP/1.1'

@asyncio.coroutine
def get_request(reader, writer):
    req = ''
    while True:
        data = yield from reader.read(8192)
        if len(data) <= 0:
            return None, None, None, None
        req += data.decode()
        end = req.find('\n')
        if end != -1:
            break
    addr = writer.get_extra_info('peername')
    print('%r: %s'%(req[:end], addr))
    return req[:end+1].split() + [req[end+1:],]

def connect_target(host):
    i = host.find(':')
    if i!=-1:
        port = int(host[i+1:])
        host = host[:i]
    else:
        port = 80
    (soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
    target = socks3.socksocket()
    target.setproxy(socks3.PROXY_TYPE_SOCKS5, '127.0.0.1', 8087)
    target.connect(address)
    return target

@asyncio.coroutine
def handle_socks(socks_reader, http_writer):
    while True:
        data = yield from socks_reader.read(8192)
        if len(data) <= 0:
            break
        http_writer.write(data)
        yield from http_writer.drain()
    http_writer.close()
    print("handle_socks returned")

@asyncio.coroutine
def handle_echo(reader, writer):
    #print(asyncio.Task.all_tasks())
    method, path, protocol, data = yield from get_request(reader, writer) 
    if method == None:
        writer.close()
        return
    elif method == 'CONNECT':
        try:
            target = yield from loop.run_in_executor(None, lambda :connect_target(path))
        except:
            writer.close()
            return 
        writer.write((HTTPVER+' 200 Connection established\n'+
                                         'Proxy-agent: %s\n\n'%VERSION).encode())
        yield from writer.drain()
    elif method in ('OPTIONS', 'GET', 'HEAD', 'POST', 'PUT',
                                 'DELETE', 'TRACE'):
        path = path[7:]
        i = path.find('/')
        host = path[:i]
        path = path[i:]
        try:
            target = yield from loop.run_in_executor(None, lambda :connect_target(host))
        except:
            writer.close()
            return
        target.send(('%s %s %s\n'%(method, path, protocol)+ data).encode())
    else:
        print("HTTPProxy protocol error")

    target.setblocking(0)
    socks_reader, socks_writer = yield from asyncio.open_connection(sock=target, loop=loop)
    asyncio.ensure_future(handle_socks(socks_reader, writer))
    while True:
        data = yield from reader.read(512)
        print('handle_echo')
        if len(data) <= 0:
            break
        socks_writer.write(data)
        yield from socks_writer.drain()

    print("Close the client socket", writer.transport, socks_writer.transport)
    writer.close()
    socks_writer.close()

logging.basicConfig(level=logging.DEBUG)
loop = asyncio.get_event_loop()
coro = asyncio.start_server(handle_echo, '127.0.0.1', 8080, loop=loop)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    #traceback.print_exc()
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
