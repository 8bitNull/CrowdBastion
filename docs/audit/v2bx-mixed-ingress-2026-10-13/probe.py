import socket,secrets,json,sys,time,ipaddress
class InvalidReply(Exception):pass

def exact(s,n):
 d=b''
 while len(d)<n:
  c=s.recv(n-len(d))
  if not c:raise OSError('EOF')
  d+=c
 return d

def address(s,atype):
 if atype in (1,4):return socket.inet_ntop(socket.AF_INET if atype==1 else socket.AF_INET6,exact(s,4 if atype==1 else 16))
 if atype==3:
  n=exact(s,1)[0]
  if not n:raise InvalidReply()
  return exact(s,n).decode('ascii')
 raise InvalidReply()

def probe(port,mode,host):
 start=time.monotonic();token=secrets.token_bytes(48);neg=False;valid=True;connected=False
 try:
  with socket.create_connection(('127.0.0.1',port),timeout=5) as s:
   s.settimeout(5);s.sendall(b'\x05\x01\x00')
   if exact(s,2)!=b'\x05\x00':raise InvalidReply()
   neg=True;family=socket.AF_INET6 if ':' in host else socket.AF_INET
   addr=bytes([4 if family==socket.AF_INET6 else 1])+socket.inet_pton(family,host)+(28801).to_bytes(2,'big')
   s.sendall(b'\x05'+bytes([3 if mode=='udp' else 1])+b'\x00'+(b'\x01'+b'\x00'*6 if mode=='udp' else addr))
   h=exact(s,4)
   if h[0]!=5 or h[2]!=0 or h[1]>8:raise InvalidReply()
   relayhost=address(s,h[3]);p=int.from_bytes(exact(s,2),'big')
   if h[1]:return dict(verified=False,negotiated=neg,probe_valid=True,outcome='socks_rejected',start=start,end=time.monotonic())
   connected=True
   if mode=='udp':
    try:
     ip=ipaddress.ip_address(relayhost)
     if ip.is_unspecified:relayhost='127.0.0.1' if ip.version==4 else '::1'
    except ValueError:raise InvalidReply()
    with socket.socket(socket.AF_INET6 if ':' in relayhost else socket.AF_INET,socket.SOCK_DGRAM) as u:
     u.settimeout(5);u.connect((relayhost,p));u.send(b'\x00\x00\x00'+addr+token);time.sleep(.4);d=u.recv(4096)
     if len(d)<4 or d[:3]!=b'\x00\x00\x00' or d[3] not in (1,4):raise InvalidReply()
     n=4 if d[3]==1 else 16;header=4+n+2
     if len(d)<header or d[3:]!=addr+token:raise InvalidReply()
     ok=d[header:]==token
   else:
    s.sendall(token);time.sleep(.4);ok=exact(s,len(token))==token
  return dict(verified=ok,negotiated=neg,probe_valid=True,outcome='response',start=start,end=time.monotonic())
 except (InvalidReply,UnicodeError):return dict(verified=False,negotiated=neg,probe_valid=False,outcome='invalid_probe_reply',start=start,end=time.monotonic())
 except OSError:return dict(verified=False,negotiated=neg,probe_valid=True,outcome='transport_closed_or_timeout',start=start,end=time.monotonic())
if __name__=='__main__':
 if len(sys.argv)>4:time.sleep(max(0,float(sys.argv[4])-time.monotonic()))
 print(json.dumps(probe(int(sys.argv[1]),sys.argv[2],sys.argv[3])))
