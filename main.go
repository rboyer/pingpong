package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	bind        = flag.String("bind", ":8080", "required: address to bind (host:port or :port)")
	dial        = flag.String("dial", "", "optional: address to ping (host:port or :port)")
	dialFreq    = flag.Duration("dialfreq", 5*time.Second, "period between pings")
	dumpToLogs  = flag.Bool("dump-to-logs", false, "dump ping data to logs")
	name        = flag.String("name", "pingpong", "name to send with ping")
	logRequests = flag.Bool("log-requests", true, "log requests to some endpoints to stdout")
)

func main() {
	flag.Parse()

	if !isValidAddr(*bind) {
		log.Fatal("missing required -bind argument")
	}

	d := &Daemon{BindAddr: *bind, DialAddr: *dial}
	http.HandleFunc("/", d.handleIndex)
	http.HandleFunc("/pong", d.handlePong)
	http.HandleFunc("/healthz", d.handleHealthz)

	if *dial != "" {
		if !isValidAddr(*dial) {
			log.Fatal("invalid optional -dial argument")
		}
		if *dialFreq <= 0 {
			log.Fatal("invalid -dialfreq value")
		}

		proxyURL, err := url.Parse("http://" + *dial + "/")
		if err != nil {
			log.Fatalf("bad dial url: %v", err)
		}
		d.Proxy = httputil.NewSingleHostReverseProxy(proxyURL)

		d.Client = &http.Client{
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout:   5 * time.Second,
					KeepAlive: 5 * time.Second,
					DualStack: false,
				}).DialContext,
				MaxIdleConns:          10,
				IdleConnTimeout:       10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			},
		}

		go func() {
			for {
				<-time.After(*dialFreq)
				d.pingOnce()
			}
		}()
	}

	log.Printf("Listening on %s", *bind)
	if err := http.ListenAndServe(*bind, nil); err != nil {
		log.Printf("ERROR: %v", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func (d *Daemon) pingOnce() {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		log.Printf("WARN: ping: problem with random generation: %v", err)
		return
	}

	v := *name + "--" + hex.EncodeToString(b)

	p := Ping{Value: v}
	defer func() {
		d.AddPing(p)
	}()

	url := "http://" + *dial + "/pong"
	req, err := http.NewRequest("POST", url, strings.NewReader(v))
	if err != nil {
		p.Err = "failed to make request object: " + err.Error()
		return
	}
	req.Header.Set("Content-Type", "text/plain")

	client := d.Client // TODO
	resp, err := client.Do(req)
	if err != nil {
		p.Err = "failed to make do request: " + err.Error()
		return
	}

	if resp.StatusCode != http.StatusOK {
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
		p.Err = "unexpected status: " + resp.Status
		return
	}

	b, err = ioutil.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		p.Err = "failed to read body: " + err.Error()
		return
	}

	if string(b) != "OK" {
		p.Err = "unexpected response body: " + string(b)
	}
}

func isValidAddr(addr string) bool {
	if addr == "" {
		return false
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	v, err := strconv.Atoi(port)
	return err == nil && v > 0
}

type Daemon struct {
	BindAddr string
	DialAddr string

	Proxy  *httputil.ReverseProxy
	Client *http.Client

	mu    sync.Mutex
	pings []Ping // outbound
	pongs []Ping // inbound
}

const maxPxngs = 100

func (d *Daemon) AddPing(p Ping) {
	if *dumpToLogs {
		defer func() {
			out, err := json.Marshal(p)
			if err != nil {
				out = []byte("ERROR: " + err.Error())
			}
			log.Printf("PING: %s", string(out))
		}()
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	d.pings = append(d.pings, p)

	if len(d.pings) > maxPxngs {
		copy(d.pings, d.pings[len(d.pings)-maxPxngs:])
		d.pings = d.pings[0:maxPxngs]
	}
}
func (d *Daemon) AddPong(p Ping) {
	if *dumpToLogs {
		defer func() {
			out, err := json.Marshal(p)
			if err != nil {
				out = []byte("ERROR: " + err.Error())
			}
			log.Printf("PONG: %s", string(out))
		}()
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	d.pongs = append(d.pongs, p)

	if len(d.pongs) > maxPxngs {
		copy(d.pongs, d.pongs[len(d.pongs)-maxPxngs:])
		d.pongs = d.pongs[0:maxPxngs]
	}
}

func (d *Daemon) GetPings() []Ping {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]Ping, len(d.pings))
	copy(out, d.pings)
	return out
}

func (d *Daemon) GetPongs() []Ping {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]Ping, len(d.pongs))
	copy(out, d.pongs)
	return out
}

type Ping struct {
	Addr  string `json:"addr,omitempty"`
	Value string `json:"value,omitempty"`
	Err   string `json:"err,omitempty"`
}

type reqInfo struct {
	Method string
	URL    string
	Header http.Header
}

func (d *Daemon) handleIndex(w http.ResponseWriter, r *http.Request) {
	if *logRequests {
		ri := reqInfo{
			Method: r.Method,
			URL:    r.URL.String(),
			Header: r.Header,
		}
		jd, err := json.MarshalIndent(ri, "", "  ")
		if err != nil {
			log.Printf("ERROR: could not generate request log: %v", err)
		} else {
			log.Printf("<Request>\n%s\n</Request>", string(jd))
		}
	}
	if r.Method != "GET" {
		errNotAllowed(w)
		return
	}

	if r.URL.Query().Get("proxy") == "1" {
		if d.Proxy != nil {
			// Avoid infinite recursion.
			q := r.URL.Query()
			q.Del("proxy")
			r.URL.RawQuery = q.Encode()
			d.Proxy.ServeHTTP(w, r)
			return
		}
	}

	justPxngs := "1" == r.URL.Query().Get("p")

	out := IndexData{
		Name: *name,
	}

	if !justPxngs {
		// proc environment vars
		if err := supplyEnv(&out); err != nil {
			errDone(w, err)
			return
		}

		// http header
		if err := supplyHTTP(&out, r); err != nil {
			errDone(w, err)
			return
		}
	}

	// pings
	out.Pings = d.GetPings()
	out.Pongs = d.GetPongs()

	enc := json.NewEncoder(w)

	w.Header().Set("content-type", "application/json")
	if err := enc.Encode(&out); err != nil {
		log.Printf("ERROR: %v", err)
	}
}

type IndexData struct {
	Name    string            `json:"name"`
	Env     []string          `json:"env"`
	Request *IndexDataRequest `json:"request"`
	Pings   []Ping            `json:"pings"`
	Pongs   []Ping            `json:"pongs"`
}
type IndexDataRequest struct {
	Method  string   `json:"method,omitempty"`
	URI     string   `json:"uri,omitempty"`
	Proto   string   `json:"proto,omitempty"`
	Host    string   `json:"host,omitempty"`
	Headers []string `json:"headers,omitempty"`
}

func (d *Daemon) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errNotAllowed(w)
		return
	}

	w.Header().Set("content-type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

func (d *Daemon) handlePong(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errNotAllowed(w)
		return
	}
	defer r.Body.Close()

	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		errDone(w, err)
		return
	}

	// TODO
	d.AddPong(Ping{Addr: r.RemoteAddr, Value: string(b)})

	w.Header().Set("content-type", "text/plain")
	_, _ = w.Write([]byte("OK"))
}

func supplyEnv(out *IndexData) error {
	env := os.Environ()
	sort.Strings(env)

	out.Env = env
	return nil
}

func supplyHTTP(out *IndexData, r *http.Request) error {
	out.Request = &IndexDataRequest{
		Method: r.Method,
		URI:    r.URL.String(),
		Proto:  r.Proto,
		Host:   r.Host,
	}

	var hdr []string
	for k, vl := range r.Header {
		for _, v := range vl {
			hdr = append(hdr, k+"="+v)
		}
	}
	sort.Strings(hdr)
	out.Request.Headers = hdr

	return nil
}

func errDone(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	log.Printf("ERROR: %v", err)
}

func errNotAllowed(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}
