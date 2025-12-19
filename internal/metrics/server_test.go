package metrics

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	server := NewServer(9091)
	if server == nil {
		t.Fatal("Expected non-nil server")
	}
	if server.port != 9091 {
		t.Errorf("Expected port 9091, got %d", server.port)
	}
}

func TestServerStartStop(t *testing.T) {
	server := NewServer(9092)

	// Start server
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Verify server is running by fetching metrics
	resp, err := http.Get("http://localhost:9092/metrics")
	if err != nil {
		t.Fatalf("Failed to fetch metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Verify we got Prometheus metrics output
	if !strings.Contains(string(body), "nfstrail_") {
		t.Error("Expected Prometheus metrics output containing 'nfstrail_'")
	}

	// Stop server
	if err := server.Stop(); err != nil {
		t.Fatalf("Failed to stop server: %v", err)
	}

	// Give server time to stop
	time.Sleep(100 * time.Millisecond)

	// Verify server is stopped
	_, err = http.Get("http://localhost:9092/metrics")
	if err == nil {
		t.Error("Expected error when fetching from stopped server")
	}
}

func TestServerRootPage(t *testing.T) {
	server := NewServer(9093)

	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start server: %v", err)
	}
	defer server.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Fetch root page
	resp, err := http.Get("http://localhost:9093/")
	if err != nil {
		t.Fatalf("Failed to fetch root page: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	// Verify HTML page contains expected content
	html := string(body)
	if !strings.Contains(html, "NFS Trail Metrics") {
		t.Error("Expected root page to contain 'NFS Trail Metrics'")
	}
	if !strings.Contains(html, "/metrics") {
		t.Error("Expected root page to contain link to /metrics")
	}
}

func TestServerStopWithoutStart(t *testing.T) {
	server := NewServer(9094)

	// Should not panic or error when stopping a server that was never started
	if err := server.Stop(); err != nil {
		t.Errorf("Expected no error when stopping unstarted server, got: %v", err)
	}
}
