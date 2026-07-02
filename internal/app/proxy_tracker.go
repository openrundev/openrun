package app

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openrundev/openrun/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
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
	attrs   []attribute.KeyValue
}

func NewByteWindow(windowSeconds int, attrs ...attribute.KeyValue) *ByteWindow {
	if windowSeconds < 1 {
		windowSeconds = 1
	}
	return &ByteWindow{
		buckets: make([]bucket, windowSeconds),
		window:  windowSeconds,
		attrs:   append([]attribute.KeyValue(nil), attrs...),
	}
}

func (bw *ByteWindow) add(ctx context.Context, now time.Time, sent, recv uint64) {
	sec := now.Unix()
	idx := int(sec % int64(bw.window))

	bw.mu.Lock()
	b := &bw.buckets[idx]
	if b.sec != sec {
		// this slot is stale; reset
		b.sec = sec
		b.sent = 0
		b.recv = 0
	}
	b.sent += sent
	b.recv += recv
	bw.mu.Unlock()

	if ctx == nil {
		ctx = context.Background()
	}
	telemetry.RecordAppProxyBytes(ctx, recv, sent, bw.attrs...)
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

// dirCounter accumulates byte counts for one transfer direction and flushes
// them to the ByteWindow when the wall-clock second changes (and on stream
// end). This bounds the ByteWindow mutex and telemetry record cost to about
// once per second per direction instead of once per 32KB copied chunk, while
// keeping the per-second window buckets (used for idle detection) accurate.
type dirCounter struct {
	bw      *ByteWindow
	sent    bool // true counts proxy->client bytes, false counts client->proxy
	pending atomic.Uint64
	lastSec atomic.Int64
}

func (c *dirCounter) count(ctx context.Context, n int) {
	c.pending.Add(uint64(n))
	now := time.Now()
	sec := now.Unix()
	last := c.lastSec.Load()
	if sec != last && c.lastSec.CompareAndSwap(last, sec) {
		c.flush(ctx, now)
	}
}

func (c *dirCounter) flush(ctx context.Context, now time.Time) {
	n := c.pending.Swap(0)
	if n == 0 {
		return
	}
	if c.sent {
		c.bw.add(ctx, now, n, 0)
	} else {
		c.bw.add(ctx, now, 0, n)
	}
}

type countingReadCloser struct {
	rc  io.ReadCloser
	c   *dirCounter
	ctx context.Context
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.rc.Read(p)
	if n > 0 {
		c.c.count(c.ctx, n)
	}
	return n, err
}
func (c *countingReadCloser) Close() error { return c.rc.Close() }

type countingResponseWriter struct {
	http.ResponseWriter
	c   *dirCounter
	ctx context.Context
}

func (w *countingResponseWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.c.count(w.ctx, n)
	}
	return n, err
}

func (w *countingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
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
	return &countingConn{
		Conn: c,
		ctx:  w.ctx,
		recv: &dirCounter{bw: w.c.bw},
		sent: &dirCounter{bw: w.c.bw, sent: true},
	}, rw, nil
}

type countingConn struct {
	net.Conn
	ctx  context.Context
	recv *dirCounter // client -> proxy
	sent *dirCounter // proxy -> client
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.recv.count(c.ctx, n)
	}
	return n, err
}
func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.sent.count(c.ctx, n)
	}
	return n, err
}

func (c *countingConn) Close() error {
	err := c.Conn.Close()
	now := time.Now()
	c.recv.flush(c.ctx, now)
	c.sent.flush(c.ctx, now)
	return err
}

// proxyBufPool provides the copy buffers for all reverse proxies. Without it
// httputil.ReverseProxy allocates a fresh 32KB buffer per proxied response.
var proxyBufPool httputil.BufferPool = &proxyBufferPool{
	pool: sync.Pool{
		New: func() any {
			buf := make([]byte, 32*1024)
			return &buf
		},
	},
}

type proxyBufferPool struct {
	pool sync.Pool
}

func (p *proxyBufferPool) Get() []byte {
	return *p.pool.Get().(*[]byte)
}

func (p *proxyBufferPool) Put(buf []byte) {
	p.pool.Put(&buf)
}

// Tracker is a reverse proxy with byte count tracking
type Tracker struct {
	bw    *ByteWindow
	proxy *httputil.ReverseProxy
}

func NewTracker(proxy *httputil.ReverseProxy, windowSeconds int, attrs ...attribute.KeyValue) *Tracker {
	return &Tracker{
		bw:    NewByteWindow(windowSeconds, attrs...),
		proxy: proxy,
	}
}

func (t *Tracker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// Count request bytes (body) for non-upgraded requests.
	var recvCounter *dirCounter
	if r.Body != nil {
		recvCounter = &dirCounter{bw: t.bw}
		r.Body = &countingReadCloser{rc: r.Body, c: recvCounter, ctx: ctx}
	}
	sentCounter := &dirCounter{bw: t.bw, sent: true}
	crw := &countingResponseWriter{ResponseWriter: w, c: sentCounter, ctx: ctx}
	t.proxy.ServeHTTP(crw, r)

	// Flush counts accumulated since the last second rollover. For upgraded
	// (websocket) connections the countingConn flushes on close instead.
	now := time.Now()
	sentCounter.flush(ctx, now)
	if recvCounter != nil {
		recvCounter.flush(ctx, now)
	}
}

// Accessor to read the rolling totals.
func (t *Tracker) GetRollingTotals() (sent, recv uint64) {
	return t.bw.Totals()
}
