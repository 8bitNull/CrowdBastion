// Real local QUIC controls; never print credentials or raw errors.
package main
import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "io"
 "net/http"
 "os"
 "time"
 "github.com/sagernet/quic-go"
 "github.com/sagernet/quic-go/http3"
)
func main(){
 cert,err:=os.ReadFile(os.Args[1]);if err!=nil{panic("certificate read")}
 roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(cert){panic("certificate parse")}
 tlsConfig:=&tls.Config{RootCAs:roots,ServerName:"lab.invalid",MinVersion:tls.VersionTLS13,NextProtos:[]string{"h3"}}
 mode:=os.Args[2];endpoint:="127.0.0.1:"+os.Args[3]
 if mode=="auth_timeout"{
  ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second);defer cancel()
  conn,err:=quic.DialAddr(ctx,endpoint,tlsConfig,nil);if err!=nil{panic("QUIC connect")};defer conn.CloseWithError(0,"")
  closed:=false;select{case <-conn.Context().Done():closed=true;case <-ctx.Done():}
  json.NewEncoder(os.Stdout).Encode(map[string]any{"closed_without_auth":closed});return
 }
 transport:=&http3.Transport{TLSClientConfig:tlsConfig};defer transport.Close()
 client:=&http.Client{Transport:transport,Timeout:8*time.Second}
 path:="/auth";method:="POST";host:="hysteria"
 if mode=="masquerade"{path="/ordinary";method="GET";host="lab.invalid"}
 statuses:=[]int{};repeats:=1
 if mode=="repeated_bad"{repeats=2};if mode=="flood"{repeats=46}
 for i:=0;i<repeats;i++{
  if mode=="flood" && i==45{time.Sleep(1100*time.Millisecond)}
  req,err:=http.NewRequest(method,"https://"+endpoint+path,nil);if err!=nil{panic("request")}
  req.Host=host;credential:="not-a-valid-lab-credential"
  if mode=="policy"{credential="11111111-2222-4333-8444-555555555555"}
  req.Header.Set("Hysteria-Auth",credential);req.Header.Set("Hysteria-CC-RX","0")
  resp,err:=client.Do(req);if err!=nil{panic("HTTP3 request")};io.Copy(io.Discard,resp.Body);resp.Body.Close();statuses=append(statuses,resp.StatusCode)
 }
 json.NewEncoder(os.Stdout).Encode(map[string]any{"http_statuses":statuses})
}
