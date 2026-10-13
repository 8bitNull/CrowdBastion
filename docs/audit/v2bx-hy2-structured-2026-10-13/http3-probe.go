// Local-only real HTTP/3 control, never prints auth or response contents.
package main
import (
 "crypto/tls"
 "crypto/x509"
 "encoding/json"
 "io"
 "net/http"
 "os"
 "time"
 "github.com/apernet/quic-go/http3"
)
func main(){
 cert,err:=os.ReadFile(os.Args[1]);if err!=nil{panic(err)}
 roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(cert){panic("certificate")}
 transport:=&http3.Transport{TLSClientConfig:&tls.Config{RootCAs:roots,ServerName:"lab.invalid",MinVersion:tls.VersionTLS13}}
 defer transport.Close()
 client:=&http.Client{Transport:transport,Timeout:8*time.Second}
 path:="/auth";method:="POST";host:="hysteria"
 if os.Args[2]=="masquerade" {path="/ordinary";method="GET";host="lab.invalid"}
 statuses:=[]int{}
 repeats:=1;if os.Args[2]=="repeated_bad"{repeats=2}
 for i:=0;i<repeats;i++ {
  req,err:=http.NewRequest(method,"https://127.0.0.1:29013"+path,nil);if err!=nil{panic(err)}
  req.Host=host;req.Header.Set("Hysteria-Auth","not-a-valid-lab-credential");req.Header.Set("Hysteria-CC-RX","0")
  resp,err:=client.Do(req);if err!=nil{panic(err)}
  io.Copy(io.Discard,resp.Body);resp.Body.Close();statuses=append(statuses,resp.StatusCode)
 }
 json.NewEncoder(os.Stdout).Encode(map[string]interface{}{"http_statuses":statuses})
}
