package app

import (
	"bytes"
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

func TestTracker_BasicByteTracking(t *testing.T) {
	t.Parallel()

	// Create backend server that echoes the request body
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer backend.Close() //nolint:errcheck

	// Create reverse proxy to backend
	backendURL, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(backendURL)

	// Create tracker with 5 second window
	tracker := NewTracker(proxy, 5)

	// Create frontend server with tracker
	frontend := httptest.NewServer(tracker)
	defer frontend.Close() //nolint:errcheck

	// Send request with known payload
	payload := strings.Repeat("A", 1000) // 1000 bytes
	resp, err := http.Post(frontend.URL, "text/plain", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Read response
	respBody, _ := io.ReadAll(resp.Body)

	// Verify response matches payload
	if string(respBody) != payload {
		t.Errorf("Response body mismatch, got %d bytes, want %d bytes", len(respBody), len(payload))
	}

	// Check rolling totals
	sent, recv := tracker.GetRollingTotals()

	// Should have sent ~1000 bytes (response) and received ~1000 bytes (request body)
	if sent < 1000 || sent > 1100 {
		t.Errorf("Sent bytes = %d, want ~1000", sent)
	}
	if recv < 1000 || recv > 1100 {
		t.Errorf("Received bytes = %d, want ~1000", recv)
	}
}

func TestTracker_MultipleRequests(t *testing.T) {
	t.Parallel()

	// Create backend server that sends fixed response
	responseData := strings.Repeat("B", 500) // 500 bytes per response
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.ReadAll(r.Body) //nolint:errcheck
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseData)) //nolint:errcheck
	}))
	defer backend.Close() //nolint:errcheck

	// Create reverse proxy and tracker
	backendURL, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	tracker := NewTracker(proxy, 5)

	frontend := httptest.NewServer(tracker)
	defer frontend.Close() //nolint:errcheck

	// Send multiple requests over time
	requestPayload := strings.Repeat("C", 300) // 300 bytes per request
	numRequests := 5

	for i := 0; i < numRequests; i++ {
		resp, err := http.Post(frontend.URL, "text/plain", strings.NewReader(requestPayload))
		if err != nil {
			t.Fatalf("Request %d failed: %v", i, err)
		}
		io.ReadAll(resp.Body) //nolint:errcheck
		resp.Body.Close()     //nolint:errcheck

		// Small delay between requests
		time.Sleep(100 * time.Millisecond)
	}

	// Check totals
	sent, recv := tracker.GetRollingTotals()

	// Should have sent ~2500 bytes (5 * 500) and received ~1500 bytes (5 * 300)
	expectedSent := uint64(numRequests * len(responseData))
	expectedRecv := uint64(numRequests * len(requestPayload))

	// Allow some margin for headers
	if sent < expectedSent || sent > expectedSent+500 {
		t.Errorf("Sent bytes = %d, want ~%d", sent, expectedSent)
	}
	if recv < expectedRecv || recv > expectedRecv+500 {
		t.Errorf("Received bytes = %d, want ~%d", recv, expectedRecv)
	}
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
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
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
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
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
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
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

func TestTracker_LargePayloads(t *testing.T) {
	t.Parallel()

	// Create backend that echoes
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		w.Write(body) //nolint:errcheck
	}))
	defer backend.Close() //nolint:errcheck

	// Create reverse proxy and tracker
	backendURL, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	tracker := NewTracker(proxy, 5)

	frontend := httptest.NewServer(tracker)
	defer frontend.Close() //nolint:errcheck

	// Send large payload (1MB)
	largePayload := bytes.Repeat([]byte("F"), 1024*1024)
	resp, err := http.Post(frontend.URL, "application/octet-stream", bytes.NewReader(largePayload))
	if err != nil {
		t.Fatalf("Large request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	respBody, _ := io.ReadAll(resp.Body)

	// Verify response
	if len(respBody) != len(largePayload) {
		t.Errorf("Response size = %d, want %d", len(respBody), len(largePayload))
	}

	// Check totals
	sent, recv := tracker.GetRollingTotals()

	expectedBytes := uint64(len(largePayload))

	// Allow margin for headers
	if sent < expectedBytes || sent > expectedBytes+10000 {
		t.Errorf("Sent bytes = %d, want ~%d", sent, expectedBytes)
	}
	if recv < expectedBytes || recv > expectedBytes+10000 {
		t.Errorf("Received bytes = %d, want ~%d", recv, expectedBytes)
	}
}

func TestTracker_SpreadOver5Seconds(t *testing.T) {
	t.Parallel()

	// Create backend that streams data
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter doesn't support flushing")
		}

		// Read request body
		reqBody, _ := io.ReadAll(r.Body)
		reqSize := len(reqBody)

		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)

		// Send data over 5 seconds in chunks
		chunkSize := 1000
		numChunks := 50 // 50 chunks over 5 seconds = 100ms per chunk
		chunk := bytes.Repeat([]byte("G"), chunkSize)

		for i := 0; i < numChunks; i++ {
			w.Write(chunk) //nolint:errcheck
			flusher.Flush()
			time.Sleep(100 * time.Millisecond)
		}

		// Note the request size for verification
		t.Logf("Backend received %d bytes in request", reqSize)
	}))
	defer backend.Close() //nolint:errcheck

	// Create reverse proxy and tracker with 10-second window
	backendURL, _ := url.Parse(backend.URL)
	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	tracker := NewTracker(proxy, 10)

	frontend := httptest.NewServer(tracker)
	defer frontend.Close() //nolint:errcheck

	// Prepare request with body
	requestPayload := bytes.Repeat([]byte("H"), 5000) // 5KB request

	// Start the request
	startTime := time.Now()
	resp, err := http.Post(frontend.URL, "application/octet-stream", bytes.NewReader(requestPayload))
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	// Read streamed response
	totalRead := uint64(0)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		totalRead += uint64(n)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Error reading stream: %v", err)
		}
	}

	duration := time.Since(startTime)

	// Verify duration is approximately 5 seconds
	if duration < 4*time.Second || duration > 6*time.Second {
		t.Errorf("Duration = %v, want ~5 seconds", duration)
	}

	// Verify total bytes read
	expectedSent := uint64(50 * 1000) // 50 chunks of 1000 bytes
	if totalRead != expectedSent {
		t.Errorf("Total read = %d, want %d", totalRead, expectedSent)
	}

	// Check rolling totals
	sent, recv := tracker.GetRollingTotals()

	// Should have sent ~50KB (response) and received ~5KB (request)
	if sent < expectedSent || sent > expectedSent+5000 {
		t.Errorf("Sent bytes = %d, want ~%d", sent, expectedSent)
	}

	expectedRecv := uint64(len(requestPayload))
	if recv < expectedRecv || recv > expectedRecv+5000 {
		t.Errorf("Received bytes = %d, want ~%d", recv, expectedRecv)
	}

	t.Logf("Test completed in %v: sent=%d, recv=%d", duration, sent, recv)
}
