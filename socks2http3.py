import asyncio
import socks3
import socket
import traceback
import logging
import threading

VERSION = 'socks2http/0.01'
HTTPVER = 'HTTP/1.1'

async def get_request(reader, writer):
    req = b''
    while True:
        data = await reader.read(8192)
        if len(data) <= 0:
            return None, None, None, None
        req += data
        end = req.find(b'\n')
        if end != -1:
            break
    addr = writer.get_extra_info('peername')
    print('%r: %s'%(req[:end].decode('utf-8', 'replace'), addr))
    return req[:end+1].split(b' ') + [req[end+1:],]

async def connect_target(host):
    host = host.decode('utf-8')
    i = host.find(':')
    if i!=-1:
        port = int(host[i+1:])
        host = host[:i]
    else:
        port = 80
    #(soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
    target = socks3.socksocket()
    target.setproxy(socks3.PROXY_TYPE_SOCKS5, '127.0.0.1', 12948)
    try:
        await target.connect((host,port))
    except Exception as e:
        target.close()
        target = None
        import traceback
        traceback.print_exc()
    #print("target connected")
    return target
quit = False
async def pump(reader, writer, stats, mychan, killevent, timeout = 15, bulk = 8192):
    killwait = loop.create_task(killevent.wait())
    readwait = loop.create_task(reader.read(bulk))
    global quit
    while not quit:
        if readwait is None: readwait = loop.create_task(reader.read(bulk))
        done, pending = await asyncio.wait([killwait, readwait], loop = loop, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        if readwait in done:
            data = await readwait
            if len(data) <= 0:
                break
            stats[mychan+'timeout'] = False
            stats[mychan] += len(data)
            writer.write(data)
            readwait = None
        if killwait in done:
            break #To kill
        if len(done)==0:
            #A timeout
            stats[mychan+'timeout'] = True
            #If all timeout, stop
            if stats['uptimeout'] and stats['downtimeout']:
                break
    #To kill
    killevent.set()
    writer.close()

async def handle_http(reader, writer):
    stats = {"up":0, "down":0, "uptimeout":False, "downtimeout":False}
    method, path, protocol, data = await get_request(reader, writer)
    pendingsend = None
    if method == None:
        return
    elif method == b'CONNECT':
        target = await connect_target(path)
        if not target:
            return
        writer.write((HTTPVER+' 200 Connection established\n'+
                                         'Proxy-agent: %s\n\n'%VERSION).encode())
    elif method in (b'OPTIONS', b'GET', b'HEAD', b'POST', b'PUT',
                                 b'DELETE', b'TRACE'):
        url = path[7:]
        i = url.find(b'/')
        host = url[:i]
        url = url[i:]
        target = await connect_target(host)
        if not target:
            print("Not target", target)
            return
        pendingsend = b'%s %s %s'%(method, url, protocol)+ data
    else:
        print("HTTPProxy protocol error", method)
        return

    killpipeevent = asyncio.Event(loop = loop)
    socks_reader, socks_writer = await asyncio.open_connection(sock=target, loop=loop)
    if pendingsend is not None:
        socks_writer.write(pendingsend)

    downpump = pump(socks_reader, writer, stats, 'down', killpipeevent)
    uppump = pump(reader, socks_writer, stats, 'up', killpipeevent)
    await asyncio.wait([uppump, downpump], loop = loop)

    print("FINISH", path, stats)
    socks_writer.close()

logging.basicConfig(level=logging.DEBUG)
loop = asyncio.get_event_loop()
coro = asyncio.start_server(handle_http, '127.0.0.1', 12949, loop=loop)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print('Serving on {}'.format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    #traceback.print_exc()
    pass

# Close the server
quit = True
server.close()
loop.run_until_complete(server.wait_closed())
loop.run_until_complete(asyncio.sleep(5,loop=loop))
loop.close()
