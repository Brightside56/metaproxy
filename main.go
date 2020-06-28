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
  // "context"
  "time"
  "bufio"
	"strconv"
	"os"
	// "sort"
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

func Index(w http.ResponseWriter, r *http.Request, listeners proxyListeners) {
    // json.NewEncoder(w).Encode(listeners)
		js, err := json.Marshal(listeners)
		w.Header().Set("Content-Type", "application/json")
		// json.NewEncoder(w).Encode(listeners)
		if err != nil {
	    http.Error(w, err.Error(), http.StatusInternalServerError)
	    return
	  }

	  w.Write(js)
}

func Reload(w http.ResponseWriter, r *http.Request, listeners proxyListeners, proxies string, firstPort int, lastPort int) {

		listeners.reloadProxies(proxies, firstPort, lastPort)
    // json.NewEncoder(w).Encode(listeners)
		js, err := json.Marshal(nil)
		w.Header().Set("Content-Type", "application/json")
		// json.NewEncoder(w).Encode(listeners)
		if err != nil {
	    http.Error(w, err.Error(), http.StatusInternalServerError)
	    return
	  }

	  w.Write(js)
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
//
// type listenerStatus struct {
// 	LastRequestUrl string				`json:"-"`
// 	LastRequestSourceIP string	`json:"-"`
// 	LastRequestStatus string		`json:"-"`
// 	LastRequestTime time				`json:"-"`
// }

type proxyListener struct {
  Proxy proxyServer 		`json:"proxyserver"`
  Address string				`json:"-"`
  Port int							`json:"host_port"`
  Server http.Server  	`json:"-"`
	Listener net.Listener `json:"-"`
	// Status listenerStatus `json:"status"`
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

func (p *proxyListener) start(address string, proto string) (msg string) {
  p.Server = http.Server{Addr: address, Handler: p}
  p.Address = address
	// msg = "ok"
  // log.Println("Address", p.Address)
  log.Println("Starting proxy listener on port", p.Port, "matching proxy", p.Proxy.Host+":"+strconv.Itoa(p.Proxy.Port))
  if proto == "https" {
    if err := p.Server.ListenAndServeTLS("host.com.crt","host.com.key"); err != nil {
  		log.Print("ListenAndServe:", err)
  	}
  } else {
		listener, err := net.Listen("tcp", address)

		// if err != nil && err.Error() == "bind: address already in use" {
		//     msg = "port is used"
		// }
		if err != nil {
				msg = "port is used"
		    log.Print("Listen:", err)
		} else {
			p.Listener = listener
			// p.Listener = listener
			go p.Server.Serve(p.Listener)

		}
	  // if err := p.Server.Serve(p.Listener); err != nil {
    //   log.Print("ListenAndServe:", err)
  	// }

  }

	return msg
}

// func (listeners *proxyListeners) removeProxy(listeners proxyListeners, proxy proxyListener) {
// 	slice = append(slice[:i], slice[i+1:]...)
// }


func (p *proxyListener) shutdown() {
	log.Println("Stopping proxy listener on port", p.Port, "matching proxy", p.Proxy.Host+":"+strconv.Itoa(p.Proxy.Port))
  // log.Println("Stopping proxy server on", p.Address)
	// kek := &p.Listener
	// log.Print(&p.Listener)
  if err := p.Listener.Close(); err != nil {
      log.Print(err)
  }
}

func RemoveIndex(s []proxyListener, index int) []proxyListener {
	return append(s[:index], s[index+1:]...)
}

func (listeners *proxyListeners) reloadProxies(proxyList string, firstPort int, lastPort int) {
	proxyServers := parseProxyFile(proxyList)

	var currentPort = firstPort
	for i, listener := range *listeners {
		matcher := 0
		for _, proxy := range proxyServers {
        if listener.Proxy.Host == proxy.Host && listener.Proxy.Port == proxy.Port {
				matcher = 1
        }
    }
		if matcher == 0 {
			if listener.Proxy.Host != "localhost" {
				listener.shutdown()
				*listeners = RemoveIndex(*listeners, i)
				// *listeners = append(listeners[:i], listeners[i+1:]...)

				// listener = proxyListener{Proxy: proxyServer{Host:"",Port: 0}, Port: 0}
			}
		}
	}
	for _, proxy := range proxyServers {
		if currentPort < lastPort {
			IteratePort:
			for _, listener := range *listeners {
				if listener.Port == currentPort {
					// port is occupied
					currentPort++
					goto IteratePort
				}
			}
			// if len(*listeners) > 0 {
			  matcher := 0
				for _, listener := range *listeners {
					if (proxy.Host == listener.Proxy.Host && proxy.Port == listener.Proxy.Port) {
						log.Print("Proxy "+proxy.Host+":"+strconv.Itoa(proxy.Port)+" is known, matching "+strconv.Itoa(listener.Port)+" skipping")
						matcher = 1
					}
				}
				if matcher == 0 {
					log.Print("Proxy "+proxy.Host+":"+strconv.Itoa(proxy.Port)+" is not known, adding")
					listener := proxyListener{Proxy: proxy, Port: currentPort}
					msg := listener.start("0.0.0.0:"+strconv.Itoa(currentPort),"")
					if msg == "port is used" {
						currentPort++
					} else {
						*listeners = append(*listeners, listener)
						currentPort++
					}
				}
			// } else {
			//  	listener := proxyListener{Proxy: proxy, Port: currentPort}
			//  	msg := listener.start("0.0.0.0:"+strconv.Itoa(currentPort),"")
			//  	if msg == "port is used" {
			//  		currentPort++
			//  	} else {
			//  		*listeners = append(*listeners, listener)
			//  		currentPort++
			//  	}
		 // }
		}
	}
}


func main() {

  var pemPath string
  flag.StringVar(&pemPath, "pem", "server.pem", "path to pem file")
  var keyPath string
  flag.StringVar(&keyPath, "key", "server.key", "path to key file")
  var proto string
  flag.StringVar(&proto, "proto", "https", "Proxy protocol (http or https)")
	var firstPort int
	flag.IntVar(&firstPort, "first-port", 8000, "First port in range where application will listen")
	var lastPort int
	flag.IntVar(&lastPort, "last-port", 60000, "First port in range where application will listen")
	var statusPort int
	flag.IntVar(&statusPort, "status-port", 7090, "Port with status page ui")
	var proxyList string
	flag.StringVar(&proxyList, "proxy-list", "./proxies.txt", "File which containing list of http/https proxies in host:port format")

	flag.Parse()

	var listeners proxyListeners

	listeners = append(listeners,proxyListener{Proxy: proxyServer{Host:"localhost",Port: 7090}, Port: 7090})
	listeners.reloadProxies(proxyList, firstPort, lastPort)

	r := mux.NewRouter()
	r.HandleFunc("/", func (response http.ResponseWriter, request *http.Request) {
		Index(response, request, listeners)
	}).Methods("GET")
	r.HandleFunc("/reload", func (response http.ResponseWriter, request *http.Request) {
		listeners.reloadProxies(proxyList, firstPort, lastPort)
	}).Methods("GET")

	// log.Fatal(http.ListenAndServe(":"+strconv.Itoa(statusPort), r))
	go http.ListenAndServe(":"+strconv.Itoa(statusPort), r)

	// log.Print(listeners)
  select {}

}
