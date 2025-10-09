package app

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

type bucket struct {
	sec  int64
	sent uint64
	recv uint64
}

type ByteWindow struct {
	mu      sync.Mutex
	buckets []bucket // len = windowSeconds
	window  int      // seconds
}

func NewByteWindow(windowSeconds int) *ByteWindow {
	return &ByteWindow{
		buckets: make([]bucket, windowSeconds),
		window:  windowSeconds,
	}
}

func (bw *ByteWindow) add(now time.Time, sent, recv uint64) {
	sec := now.Unix()
	idx := int(sec % int64(bw.window))

	bw.mu.Lock()
	defer bw.mu.Unlock()

	b := &bw.buckets[idx]
	if b.sec != sec {
		// this slot is stale; reset
		b.sec = sec
		b.sent = 0
		b.recv = 0
	}
	b.sent += sent
	b.recv += recv
}

func (bw *ByteWindow) Totals() (sent, recv uint64) {
	now := time.Now().Unix()
	bw.mu.Lock()
	defer bw.mu.Unlock()
	for i := range bw.buckets {
		if now-bw.buckets[i].sec < int64(bw.window) {
			sent += bw.buckets[i].sent
			recv += bw.buckets[i].recv
		}
	}
	return
}

type countingReadCloser struct {
	rc io.ReadCloser
	bw *ByteWindow
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.bw.add(time.Now(), 0, uint64(n))
	}
	return n, err
}
func (c *countingReadCloser) Close() error { return c.rc.Close() }

type countingResponseWriter struct {
	http.ResponseWriter
	bw *ByteWindow
}

func (w *countingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.bw.add(time.Now(), uint64(n), 0)
	}
	return n, err
}

// Support Flush for streaming/SSE.
func (w *countingResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Implement Hijacker so reverse proxy can upgrade to WS,
// and we can wrap the net.Conn to count both directions.
func (w *countingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrHijacked
	}
	c, rw, err := hj.Hijack()
	if err != nil {
		return nil, nil, err
	}
	return &countingConn{Conn: c, bw: w.bw}, rw, nil
}

type countingConn struct {
	net.Conn
	bw *ByteWindow
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.bw.add(time.Now(), 0, uint64(n)) // client -> proxy
	}
	return n, err
}
func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.bw.add(time.Now(), uint64(n), 0) // proxy -> client
	}
	return n, err
}

// Tracker is a reverse proxy with byte count tracking
type Tracker struct {
	bw    *ByteWindow
	proxy *httputil.ReverseProxy
}

func NewTracker(proxy *httputil.ReverseProxy, windowSeconds int) *Tracker {
	return &Tracker{
		bw:    NewByteWindow(windowSeconds),
		proxy: proxy,
	}
}

func (t *Tracker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Count request bytes (body) for non-upgraded requests.
	if r.Body != nil {
		r.Body = &countingReadCloser{rc: r.Body, bw: t.bw}
	}
	crw := &countingResponseWriter{ResponseWriter: w, bw: t.bw}
	t.proxy.ServeHTTP(crw, r)
}

// Accessor to read the rolling totals.
func (t *Tracker) GetRollingTotals() (sent, recv uint64) {
	return t.bw.Totals()
}
