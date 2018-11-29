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
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	bind     = flag.String("bind", ":8080", "required: address to bind (host:port or :port)")
	dial     = flag.String("dial", "", "optional: address to ping (host:port or :port)")
	dialFreq = flag.Duration("dialfreq", 5*time.Second, "period between pings")
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

	v := hex.EncodeToString(b)

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

	Client *http.Client

	mu    sync.Mutex
	pings []Ping // outbound
	pongs []Ping // inbound
}

const maxPxngs = 100

func (d *Daemon) AddPing(p Ping) {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.pings = append(d.pings, p)

	if len(d.pings) > maxPxngs {
		copy(d.pings, d.pings[len(d.pings)-maxPxngs:])
		d.pings = d.pings[0:maxPxngs]
	}
}
func (d *Daemon) AddPong(p Ping) {
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

func (d *Daemon) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		errNotAllowed(w)
		return
	}

	justPxngs := "1" == r.URL.Query().Get("p")

	m := make(map[string]interface{})

	if !justPxngs {
		// proc environment vars
		if err := supplyEnv(m); err != nil {
			errDone(w, err)
			return
		}

		// http header
		if err := supplyHTTP(m, r); err != nil {
			errDone(w, err)
			return
		}
	}

	// pings
	m["pings"] = d.GetPings()
	m["pongs"] = d.GetPongs()

	enc := json.NewEncoder(w)

	w.Header().Set("content-type", "application/json")
	if err := enc.Encode(m); err != nil {
		log.Printf("ERROR: %v", err)
	}
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

func supplyEnv(m map[string]interface{}) error {
	env := os.Environ()
	sort.Strings(env)
	m["env"] = env
	return nil
}

func supplyHTTP(m map[string]interface{}, r *http.Request) error {
	var hdr []string
	for k, vl := range r.Header {
		for _, v := range vl {
			hdr = append(hdr, k+"="+v)
		}
	}
	sort.Strings(hdr)
	m["hdr"] = hdr
	return nil
}

func errDone(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	log.Printf("ERROR: %v", err)
}

func errNotAllowed(w http.ResponseWriter) {
	http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
}
