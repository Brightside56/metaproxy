package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
  "net/url"
  "crypto/tls"
	"strings"
  "context"
  "time"
  "bufio"
	"strconv"
	"os"
	"github.com/gorilla/mux"
	"encoding/json"
)

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

type Route struct {
    Name        string
    Method      string
    Pattern     string
    HandlerFunc http.HandlerFunc
}

type Routes []Route

func NewRouter() *mux.Router {

    router := mux.NewRouter().StrictSlash(true)
    for _, route := range apiRoutes {
        router.
            Methods(route.Method).
            Path(route.Pattern).
            Name(route.Name).
            Handler(route.HandlerFunc)
    }

    return router
}

var apiRoutes = Routes{
    Route{
        "Index",
        "GET",
        "/",
        Index,
    },
}



func Index(w http.ResponseWriter, r *http.Request) {
    var listeners proxyListeners

    json.NewEncoder(w).Encode(listeners)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func delHopHeaders(header http.Header) {
	for _, h := range hopHeaders {
		header.Del(h)
	}
}

func parseProxyFile(proxyFile string) proxyServers {
		var file, err = os.OpenFile(proxyFile, os.O_RDONLY, 0600)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
		var proxies proxyServers
		for scanner.Scan() {
				proxy := strings.Split(scanner.Text(), ":")
				if port, err := strconv.Atoi(proxy[1]); err == nil {
					proxies = append(proxies, proxyServer{Host:proxy[0],Port: port})
				}
    }

    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }

		return proxies
}

func appendHostToXForwardHeader(header http.Header, host string) {
	// If we aren't the first proxy retain prior
	// X-Forwarded-For information as a comma+space
	// separated list and fold multiple headers into one.
	if prior, ok := header["X-Forwarded-For"]; ok {
		host = strings.Join(prior, ", ") + ", " + host
	}
	header.Set("X-Forwarded-For", host)
}

type proxyServer struct {
	Host string `json:"host"`
	Port int		`json:"port"`
}

type proxyServers []proxyServer

type proxyListener struct {
  Proxy proxyServer 	`json:"proxyinfo"`
  Address string
  Port int						`json:"name"`
  Server http.Server
}

type proxyListeners []proxyListener

func handleTunneling(w http.ResponseWriter, r *http.Request) {
    dest_conn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
    if err != nil {
        http.Error(w, err.Error(), http.StatusServiceUnavailable)
        return
    }
    w.WriteHeader(http.StatusOK)
    hijacker, ok := w.(http.Hijacker)
    if !ok {
        http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
        return
    }
    client_conn, _, err := hijacker.Hijack()
    if err != nil {
        http.Error(w, err.Error(), http.StatusServiceUnavailable)
    }
    go transfer(dest_conn, client_conn)
    go transfer(client_conn, dest_conn)
}
func transfer(destination io.WriteCloser, source io.ReadCloser) {
    defer destination.Close()
    defer source.Close()
    io.Copy(destination, source)
}

func (p *proxyListener) ServeHTTP(wr http.ResponseWriter, req *http.Request) {

  if req.Method == http.MethodConnect {
      handleTunneling(wr, req)
  } else {

  	log.Println(req.RemoteAddr, " ", req.Method, " ", req.URL)

  	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
  	  	msg := "unsupported protocal scheme "+req.URL.Scheme
  		http.Error(wr, msg, http.StatusBadRequest)
  		log.Println(msg)
  		return
  	}


    // log.Print(p.proxy)
		rawProxyUrl := "https://" + p.Proxy.Host + strconv.Itoa(p.Proxy.Port)
		proxyUrl, err := url.Parse(rawProxyUrl)
    client := &http.Client{Transport: &http.Transport{TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper), ProxyConnectHeader: req.Header, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, Proxy: http.ProxyURL(proxyUrl)}}
  	// client := &http.Client{}
    // client.Transport = transport
  	//http: Request.RequestURI can't be set in client requests.
  	//http://golang.org/src/pkg/net/http/client.go
  	req.RequestURI = ""

  	delHopHeaders(req.Header)

  	// if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
  	// 	appendHostToXForwardHeader(req.Header, clientIP)
  	// }

  	resp, err := client.Do(req)
  	if err != nil {
  		http.Error(wr, "Server Error", http.StatusInternalServerError)
  		log.Print("ServeHTTP:", err)
  	}
  	defer resp.Body.Close()

  	log.Println(req.RemoteAddr, " ", resp.Status)

  	delHopHeaders(resp.Header)

  	copyHeader(wr.Header(), resp.Header)
  	wr.WriteHeader(resp.StatusCode)
  	io.Copy(wr, resp.Body)
  }
}

func (p *proxyListener) start(address string, proto string) {
  p.Server = http.Server{Addr: address, Handler: p}
  p.Address = address
  log.Println("Address", p.Address)
  log.Println("Starting proxy server on", address)
  if proto == "https" {
    if err := p.Server.ListenAndServeTLS("host.com.crt","host.com.key"); err != nil {
  		log.Print("ListenAndServe:", err)
  	}
  } else {
    if err := p.Server.ListenAndServe(); err != nil {
      log.Print("ListenAndServe:", err)
  	}
  }
}


func (p *proxyListener) shutdown() {
  log.Println("Stopping proxy server on", p.Address)
  if err := p.Server.Shutdown(context.Background()); err != nil {
      log.Print(err)
  }
}



func main() {

  var pemPath string
  flag.StringVar(&pemPath, "pem", "server.pem", "path to pem file")
  var keyPath string
  flag.StringVar(&keyPath, "key", "server.key", "path to key file")
  var proto string
  flag.StringVar(&proto, "proto", "https", "Proxy protocol (http or https)")
	var startPort int
	flag.IntVar(&startPort, "start-port", 8000, "First port in range where application will listen")
	var lastPort int
	flag.IntVar(&lastPort, "last-port", 60000, "First port in range where application will listen")
	var statusPort int
	flag.IntVar(&statusPort, "status-port", 7090, "Port with status page ui")
	var proxyList string
	flag.StringVar(&proxyList, "proxy-list", "./proxies.txt", "File which containing list of http/https proxies in host:port format")

	flag.Parse()
	proxies := parseProxyFile(proxyList)
	flag.Parse()

	var currentPort = startPort

	var listeners proxyListeners

	for _, proxy := range proxies {
		if currentPort < lastPort {
			listener := proxyListener{Proxy: proxy, Port: currentPort}
			go listener.start("0.0.0.0:"+strconv.Itoa(currentPort),"")
			listeners = append(listeners, listener)
			currentPort++
		}
	}


	router := NewRouter()

	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(statusPort), router))

  select {}

}
