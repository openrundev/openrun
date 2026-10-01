package app

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestReverseProxy(t *testing.T, target *url.URL) *httputil.ReverseProxy {
	t.Helper()

	proxy := httputil.NewSingleHostReverseProxy(target)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableKeepAlives = true
	proxy.Transport = transport
	t.Cleanup(transport.CloseIdleConnections)

	return proxy
}

func TestTracker_StreamingResponse(t *testing.T) {
	t.Parallel()

	// Create backend that streams data over time
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter doesn't support flushing")
		}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)

		// Stream 1000 bytes over 1 second
		chunk := strings.Repeat("X", 200) // 200 bytes per chunk
		for i := 0; i < 5; i++ {
			w.Write([]byte(chunk)) //nolint:errcheck
			flusher.Flush()
			time.Sleep(200 * time.Millisecond)
		}
	}))
	defer backend.Close() //nolint:errcheck

	// Create reverse proxy and tracker
	backendURL, _ := url.Parse(backend.URL)
	proxy := newTestReverseProxy(t, backendURL)
	tracker := NewTracker(proxy, 5)

	frontend := httptest.NewServer(tracker)
	defer frontend.Close() //nolint:errcheck

	// Make streaming request
	resp, err := http.Get(frontend.URL)
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Read all streamed data
	totalRead := 0
	buf := make([]byte, 100)
	for {
		n, err := resp.Body.Read(buf)
		totalRead += n
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Error reading stream: %v", err)
		}
	}

	// Verify we got the expected data
	if totalRead != 1000 {
		t.Errorf("Read %d bytes, want 1000", totalRead)
	}

	// Check rolling totals
	sent, recv := tracker.GetRollingTotals()

	// Should have sent ~1000 bytes
	if sent < 1000 || sent > 1100 {
		t.Errorf("Sent bytes = %d, want ~1000", sent)
	}

	// Minimal received bytes (just request headers, no body)
	if recv > 500 {
		t.Errorf("Received bytes = %d, want < 500", recv)
	}
}

func TestTracker_ConcurrentRequests(t *testing.T) {
	t.Parallel()

	// Create backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		// Send back double the data
		w.Write(body) //nolint:errcheck
		w.Write(body) //nolint:errcheck
	}))
	defer backend.Close() //nolint:errcheck

	// Create reverse proxy and tracker
	backendURL, _ := url.Parse(backend.URL)
	proxy := newTestReverseProxy(t, backendURL)
	tracker := NewTracker(proxy, 5)

	frontend := httptest.NewServer(tracker)
	defer frontend.Close() //nolint:errcheck

	// Send concurrent requests
	var wg sync.WaitGroup
	numGoroutines := 10
	payloadSize := 100

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			payload := strings.Repeat("D", payloadSize)
			resp, err := http.Post(frontend.URL, "text/plain", strings.NewReader(payload))
			if err != nil {
				t.Errorf("Goroutine %d: request failed: %v", id, err)
				return
			}
			defer resp.Body.Close() //nolint:errcheck
			io.ReadAll(resp.Body)   //nolint:errcheck
		}(i)
	}

	wg.Wait()

	// Check totals
	sent, recv := tracker.GetRollingTotals()

	// Should have sent ~2000 bytes (10 * 100 * 2) and received ~1000 bytes (10 * 100)
	expectedSent := uint64(numGoroutines * payloadSize * 2)
	expectedRecv := uint64(numGoroutines * payloadSize)

	if sent < expectedSent || sent > expectedSent+1000 {
		t.Errorf("Sent bytes = %d, want ~%d", sent, expectedSent)
	}
	if recv < expectedRecv || recv > expectedRecv+1000 {
		t.Errorf("Received bytes = %d, want ~%d", recv, expectedRecv)
	}
}

func TestTracker_RollingWindow(t *testing.T) {
	t.Parallel()

	// Create backend
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(strings.Repeat("E", 100))) //nolint:errcheck
	}))
	defer backend.Close() //nolint:errcheck

	// Create reverse proxy and tracker with SHORT 2-second window
	backendURL, _ := url.Parse(backend.URL)
	proxy := newTestReverseProxy(t, backendURL)
	tracker := NewTracker(proxy, 2)

	frontend := httptest.NewServer(tracker)
	defer frontend.Close() //nolint:errcheck

	// Make first request
	resp1, err := http.Get(frontend.URL)
	if err != nil {
		t.Fatalf("Request 1 failed: %v", err)
	}
	io.ReadAll(resp1.Body) //nolint:errcheck
	resp1.Body.Close()     //nolint:errcheck

	// Check totals immediately
	sent1, _ := tracker.GetRollingTotals()
	if sent1 < 100 {
		t.Errorf("After request 1: sent = %d, want >= 100", sent1)
	}

	// Wait for window to expire (2.5 seconds)
	time.Sleep(2500 * time.Millisecond)

	// Check totals - should be near zero (window expired)
	sent2, _ := tracker.GetRollingTotals()
	if sent2 > 50 {
		t.Errorf("After window expiry: sent = %d, want ~0", sent2)
	}

	// Make another request
	resp3, err := http.Get(frontend.URL)
	if err != nil {
		t.Fatalf("Request 2 failed: %v", err)
	}
	io.ReadAll(resp3.Body) //nolint:errcheck
	resp3.Body.Close()     //nolint:errcheck

	// Check totals - should show new request only
	sent3, _ := tracker.GetRollingTotals()
	if sent3 < 100 || sent3 > 200 {
		t.Errorf("After request 2: sent = %d, want ~100", sent3)
	}
}
