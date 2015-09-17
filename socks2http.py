import asyncore
import socket
import socks
import traceback
from threading import Thread
from Queue import Queue

VERSION = 'socks2http/0.01'
HTTPVER = 'HTTP/1.1'

SOCKS_SERVER_ADDR = '127.0.0.1'
SOCKS_SERVER_PORT = 8087

conn_q = Queue()

def connection_worker():
    while True:
        c = conn_q.get()
	try:
	    c.connect_target(c.host)
	    if c.init_req:
	        c.socks.addbuf(c.init_req)
	    else:
	        c.addbuf(HTTPVER+' 200 Connection established\n'+ 
			    	         'Proxy-agent: %s\n\n'%VERSION)
	except Exception as e:
	    traceback.print_exc()
	conn_q.task_done()

class SocksProxyHandler(asyncore.dispatcher):
    def __init__(self, sock, src):
    	asyncore.dispatcher.__init__(self, sock)
	self.sock = sock
	self.src = src
	self.sendbuf = ''

    def handle_read(self):
        data = self.recv(8192)
	try:
	    self.src.addbuf(data)
	except Exception as e:
	    traceback.print_exc()
	    self.close()
    def handle_close(self):
	self.close()
        self.src.close()

    def addbuf(self, data):
        self.sendbuf += data

    def handle_write(self):
        sent = self.send(self.sendbuf)
        self.sendbuf = self.sendbuf[sent:]

    def writable(self):
        return (len(self.sendbuf) > 0)

class HTTPProxyHandler(asyncore.dispatcher):
    def __init__(self, sock):
    	asyncore.dispatcher.__init__(self, sock)
	self.connected = False
	self.client_buffer = ''
	self.sock = sock
	self.target = socks.socksocket()
	self.socks = None
	self.sendbuf = ''
    
    def connect_target(self, host):
        i = host.find(':')
        if i!=-1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            port = 80
        (soc_family, _, _, _, address) = socket.getaddrinfo(host, port)[0]
	self.target.setproxy(socks.PROXY_TYPE_SOCKS5, SOCKS_SERVER_ADDR, SOCKS_SERVER_PORT)
        self.target.connect(address)
	self.socks = SocksProxyHandler(self.target, self)
    
    def handle_close(self):
	self.close()
	if self.socks:
            self.socks.close()

    def addbuf(self, data):
        self.sendbuf += data

    def handle_write(self):
        sent = self.send(self.sendbuf)
        self.sendbuf = self.sendbuf[sent:]

    def writable(self):
        return (len(self.sendbuf) > 0)

    def handle_read(self):
        if not self.connected:
	    self.client_buffer += self.recv(8192)
	    end = self.client_buffer.find('\n')
	    if end != -1:
                print '%s'%self.client_buffer[:end]
		method, path, protocol = (self.client_buffer[:end+1]).split()
		self.client_buffer = self.client_buffer[end+1:]
		if method == 'CONNECT':
		    self.host = path
		    self.init_req = None
		    conn_q.put(self)
		elif method in ('OPTIONS', 'GET', 'HEAD', 'POST', 'PUT',
		                             'DELETE', 'TRACE'):
		    path = path[7:]
		    i = path.find('/')
		    host = path[:i]
		    path = path[i:]
		    self.host = host
		    self.init_req = '%s %s %s\n'%(method, path, protocol)+ \
		                             self.client_buffer
		    conn_q.put(self)
		else:
		    print("HTTPProxy protocol error")
		    self.close()
		self.client_buffer = ''
	    self.connected = True
	    return None

        data = self.recv(8192)
	try:
	    self.socks.addbuf(data)
	except Exception as e:
	    traceback.print_exc()
	    self.close()

class HTTPProxyServer(asyncore.dispatcher):
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
	print "serving on http://%s:%d" %(host, port)

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            handler = HTTPProxyHandler(sock)

#This thread pool is used for socks connection which only supports blocking connect
for i in range(3):
    t = Thread(target=connection_worker)
    t.daemon =True
    t.start()
server = HTTPProxyServer('localhost', 8080)
asyncore.loop(timeout=0.05)
