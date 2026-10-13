"""Controlled UniProxy and token target. Temporary lab credentials only."""
import http.server,json,threading,urllib.parse
from pathlib import Path
UUID='11111111-2222-4333-8444-555555555555'
BAD='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
COMBINATIONS=[(core,p) for core,protocols in [('xray',['vmess','vless','shadowsocks','trojan']),('sing',['vmess','vless','shadowsocks','trojan','tuic','anytls','hysteria','hysteria2']),('hysteria2',['hysteria2'])] for p in protocols]

def nodes(base,host='127.0.0.1'):
 result=[]
 for index,(core,protocol) in enumerate(COMBINATIONS,1):
  result.append({'Core':core,'ApiHost':'http://127.0.0.1:28900','ApiKey':'lab-only','NodeID':index,'NodeType':protocol,'Timeout':10,'ListenIP':host,'SendIP':'0.0.0.0','CertConfig':{'CertMode':'file','CertDomain':'lab.invalid','CertFile':str(base/'cert.pem'),'KeyFile':str(base/'key.pem')}})
 return result

def start():
 calls=[]
 class Panel(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def do_GET(self):
   parsed=urllib.parse.urlparse(self.path);params=urllib.parse.parse_qs(parsed.query)
   if params.get('token')!=['lab-only']:self.send_error(403);return
   ident=int(params['node_id'][0]);core,protocol=COMBINATIONS[ident-1]
   calls.append({'node':ident,'endpoint':parsed.path.rsplit('/',1)[-1]})
   if parsed.path.endswith('/config'):
    data={'host':'lab.invalid','server_name':'lab.invalid','server_port':29000+ident,'base_config':{'push_interval':3600,'pull_interval':3600},'routes':[], 'tls':0,'network':'tcp','network_settings':{},'networkSettings':{},'cipher':'chacha20-ietf-poly1305','congestion_control':'bbr','up_mbps':100,'down_mbps':100,'ignore_client_bandwidth':True}
   elif parsed.path.endswith('/user'):data={'users':[{'id':42,'uuid':UUID,'speed_limit':0,'device_limit':0}]}
   elif parsed.path.endswith('/alivelist'):data={'alive':{}}
   else:self.send_error(404);return
   if parsed.path.endswith('/config') and protocol=='hysteria2':data.update(up_mbps=0,down_mbps=0)
   raw=json.dumps(data).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
  def do_POST(self):
   self.rfile.read(int(self.headers.get('Content-Length',0)));raw=b'{}';self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length','2');self.end_headers();self.wfile.write(raw)
 class Target(http.server.BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def do_GET(self):
   raw=self.path.removeprefix('/').encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 servers=[http.server.ThreadingHTTPServer(('127.0.0.1',port),handler) for port,handler in [(28900,Panel),(28800,Target)]]
 for server in servers:threading.Thread(target=server.serve_forever,daemon=True).start()
 return servers,calls

def client_config(base,index,valid=True,host='127.0.0.1',port=None):
 core,protocol=COMBINATIONS[index-1];secret=UUID if valid else BAD
 out={'type':protocol,'tag':'proxy','server':host,'server_port':port or 29000+index}
 if protocol in ('vmess','vless'):out['uuid']=secret
 elif protocol=='tuic':out.update(uuid=secret,password=secret,congestion_control='bbr')
 elif protocol=='hysteria':out.update(auth_str=secret,up_mbps=100,down_mbps=100)
 elif protocol=='shadowsocks':out.update(method='chacha20-ietf-poly1305',password=secret)
 else:out['password']=secret
 if protocol in ('trojan','tuic','anytls','hysteria','hysteria2'):
  out['tls']={'enabled':True,'server_name':'lab.invalid','certificate_path':str(base/'cert.pem')}
 if protocol=='tuic':out['tls']['alpn']=['h3']
 return {'log':{'level':'info','timestamp':True},'inbounds':[{'type':'socks','tag':'socks','listen':'127.0.0.1','listen_port':21100}],'outbounds':[out],'route':{'final':'proxy'}}

if __name__=='__main__':
 start();threading.Event().wait()
