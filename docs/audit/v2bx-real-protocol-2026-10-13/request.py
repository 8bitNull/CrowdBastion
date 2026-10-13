import socket,secrets,json,sys

def exact(s,n):
 data=b''
 while len(data)<n:
  chunk=s.recv(n-len(data))
  if not chunk:raise RuntimeError('unexpected EOF')
  data+=chunk
 return data

def request():
 token=secrets.token_hex(12);negotiated=False
 global state
 state={'socks_negotiated':False,'upstream_connected':False}
 with socket.create_connection(('127.0.0.1',21100),timeout=8) as s:
  s.settimeout(8);s.sendall(b'\x05\x01\x00')
  if exact(s,2)!=b'\x05\x00':raise RuntimeError('SOCKS negotiation')
  negotiated=True;state['socks_negotiated']=True
  s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+(28800).to_bytes(2,'big'))
  head=exact(s,4)
  if head[0]!=5 or head[2]!=0:raise RuntimeError('invalid SOCKS reply')
  if head[1]!=0:return {'response_verified':False,'socks_negotiated':True,'outcome':'socks_upstream_rejected'}
  length={1:4,4:16}.get(head[3])
  if head[3]==3:length=exact(s,1)[0]
  if length is None:raise RuntimeError('invalid SOCKS address type')
  exact(s,length+2);state['upstream_connected']=True
  s.sendall(('GET /'+token+' HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n').encode())
  data=b''
  while chunk:=s.recv(4096):
   data+=chunk
   if len(data)>8192:raise RuntimeError('oversized response')
  return {'response_verified':data.split(b'\r\n\r\n',1)[-1]==token.encode(),'socks_negotiated':negotiated,'outcome':'response_received' if data else 'upstream_closed'}
if __name__=='__main__':
 try:result=request()
 except (OSError,RuntimeError) as error:
  result={'response_verified':False,**state,'outcome':'upstream_transport_closed' if state['socks_negotiated'] and isinstance(error,OSError) else 'probe_error'}
 print(json.dumps(result))
