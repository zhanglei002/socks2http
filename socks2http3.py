import asyncio
import socks3
import socket
import traceback
import logging
import threading

VERSION = 'socks2http/0.01'
HTTPVER = 'HTTP/1.1'

async def get_request(reader, writer):
    req = ''
    while True:
        data = await reader.read(8192)
        if len(data) <= 0:
            return None, None, None, None
        req += data.decode()
        end = req.find('\n')
        if end != -1:
            break
    addr = writer.get_extra_info('peername')
    print('%r: %s'%(req[:end], addr))
    return req[:end+1].split() + [req[end+1:],]

async def connect_target(host):
    i = host.find(':')
    if i!=-1:
        port = int(host[i+1:])
        host = host[:i]
    else:
        port = 80
    (soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
    target = socks3.socksocket()
    target.setproxy(socks3.PROXY_TYPE_SOCKS5, '127.0.0.1', 8087)
    try:
        await target.connect(address)
    except:
        target.close()
        target = None
    return target

async def handle_socks(socks_reader, http_writer, stats):
    while True:
        data = await socks_reader.read(8192)
        if len(data) <= 0:
            break
        stats["down"] += len(data)
        http_writer.write(data)
        await http_writer.drain()
    http_writer.close()

async def handle_http(reader, writer):
    stats = {"up":0, "down":0}
    method, path, protocol, data = await get_request(reader, writer) 
    if method == None:
        writer.close()
        return
    elif method == 'CONNECT':
        target = await connect_target(path)
        if not target:
            writer.close()
            return
        writer.write((HTTPVER+' 200 Connection established\n'+
                                         'Proxy-agent: %s\n\n'%VERSION).encode())
        await writer.drain()
    elif method in ('OPTIONS', 'GET', 'HEAD', 'POST', 'PUT',
                                 'DELETE', 'TRACE'):
        url = path[7:]
        i = url.find('/')
        host = url[:i]
        url = url[i:]
        target = await connect_target(host)
        if not target:
            writer.close()
            return
        target.send(('%s %s %s\n'%(method, url, protocol)+ data).encode())
    else:
        print("HTTPProxy protocol error")

    socks_reader, socks_writer = await asyncio.open_connection(sock=target, loop=loop)
    asyncio.ensure_future(handle_socks(socks_reader, writer, stats))
    while True:
        data = await reader.read(512)
        if len(data) <= 0:
            break
        stats["up"] += len(data)
        socks_writer.write(data)
        await socks_writer.drain()

    print("FINISH", path, stats)
    writer.close()
    socks_writer.close()

logging.basicConfig(level=logging.DEBUG)
loop = asyncio.get_event_loop()
coro = asyncio.start_server(handle_http, '127.0.0.1', 8080, loop=loop)
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
