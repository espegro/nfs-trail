package metrics

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/espegro/nfs-trail/internal/logger"
)

// Server handles the Prometheus metrics HTTP endpoint
type Server struct {
	server *http.Server
	port   int
}

// NewServer creates a new metrics server
func NewServer(port int) *Server {
	return &Server{
		port: port,
	}
}

// Start starts the metrics HTTP server
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html>
<head><title>NFS Trail Metrics</title></head>
<body>
<h1>NFS Trail Metrics Exporter</h1>
<p><a href="/metrics">Metrics</a></p>
</body>
</html>`)
	})

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("Metrics server listening on :%d", s.port)
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("Metrics server error: %v", err)
		}
	}()

	return nil
}

// Stop gracefully stops the metrics server
func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}

	logger.Info("Shutting down metrics server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}
