package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

// version is overridden at build time via: -ldflags "-X main.version=x.y.z"
var version = "dev"

// maxBodyBytes caps the request body size to mitigate body-based DoS attacks.
const maxBodyBytes = 1 << 20 // 1 MiB

// helloResponse is the JSON payload returned by GET /.
type helloResponse struct {
	Message   string `json:"message"`
	Version   string `json:"version"`
	Hostname  string `json:"hostname"`
	RequestID string `json:"request_id"`
}

// config holds all runtime configuration derived from the environment.
type config struct {
	port            string
	shutdownTimeout time.Duration
}

// configFromEnv reads configuration from environment variables, applying defaults.
// It validates PORT early so startup fails with a clear message rather than
// an obscure bind error from ListenAndServe.
func configFromEnv() (config, error) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	// Validate that PORT is a valid TCP port number (1–65535).
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return config{}, fmt.Errorf("invalid PORT %q: must be an integer between 1 and 65535", port)
	}
	return config{
		port:            port,
		shutdownTimeout: 10 * time.Second,
	}, nil
}

// contextKey is a private type for context keys to avoid collisions with other packages.
type contextKey int

const requestIDKey contextKey = iota

// requestIDFromContext returns the request ID stored in the context, or empty string.
func requestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// application owns all shared, immutable dependencies.
type application struct {
	logger   *slog.Logger
	version  string
	hostname string
}

// newApplication constructs an application, resolving the hostname once at startup.
func newApplication(logger *slog.Logger, ver string) (*application, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("resolve hostname: %w", err)
	}
	return &application{
		logger:   logger,
		version:  ver,
		hostname: hostname,
	}, nil
}

// routes registers all HTTP handlers on a fresh ServeMux and applies middleware.
// Middleware is applied outermost-first: requestID → bodyLimit → logging → mux.
func (a *application) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handleHello)
	mux.HandleFunc("GET /healthz", a.handleHealthz)
	mux.HandleFunc("GET /readyz", a.handleReadyz)

	// Stack middleware. withRequestID must be outermost so subsequent layers can
	// read the ID from context. withBodyLimit is next so all handlers are protected.
	var h http.Handler = mux
	h = a.withRequestLogging(h)
	h = a.withBodyLimit(h)
	h = a.withRequestID(h)
	return h
}

// handleHello responds with a JSON body containing message, version, and hostname.
func (a *application) handleHello(w http.ResponseWriter, r *http.Request) {
	// "GET /" in Go 1.22+ is a catch-all for unregistered paths; reject non-root.
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	resp := helloResponse{
		Message:   "Hello from EKS/Hello from GitOps",
		Version:   a.version,
		Hostname:  a.hostname,
		RequestID: requestIDFromContext(r.Context()),
	}
	if err := writeJSON(w, http.StatusOK, resp); err != nil {
		a.logger.Error("handleHello: write response",
			slog.Any("error", err),
			slog.String("request_id", requestIDFromContext(r.Context())),
		)
	}
}

// handleHealthz is a liveness probe: returns 200 "ok" as long as the process is alive.
func (a *application) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// Write errors after WriteHeader are ignorable; the status is already committed.
	_, _ = fmt.Fprint(w, "ok")
}

// handleReadyz is a readiness probe: returns 200 "ready" when the service can accept traffic.
// TODO: gate on real dependency health checks (DB, cache, etc.) before shipping to production.
func (a *application) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "ready")
}

// writeJSON marshals v as JSON and writes it with the given status code.
// It returns an error so callers can log it; the response may be partially written.
func writeJSON(w http.ResponseWriter, status int, v any) error {
	// Marshal before touching the wire so a marshalling error can still produce a
	// 500 response (writing headers is not yet committed at this point).
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return fmt.Errorf("json.Marshal: %w", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("response write: %w", err)
	}
	return nil
}

// captureWriter wraps http.ResponseWriter to record the status code for logging.
type captureWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// WriteHeader records the status code and delegates to the underlying writer.
func (cw *captureWriter) WriteHeader(code int) {
	if cw.wroteHeader {
		return // guard against double-write (same semantics as net/http internals)
	}
	cw.status = code
	cw.wroteHeader = true
	cw.ResponseWriter.WriteHeader(code)
}

// Write ensures that an implicit 200 (triggered by the first Write call without a
// preceding WriteHeader) is captured rather than left as the zero value.
func (cw *captureWriter) Write(b []byte) (int, error) {
	if !cw.wroteHeader {
		cw.WriteHeader(http.StatusOK)
	}
	return cw.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController (Go 1.20+) reach through to the underlying
// ResponseWriter and access optional interfaces such as http.Flusher and http.Hijacker.
func (cw *captureWriter) Unwrap() http.ResponseWriter {
	return cw.ResponseWriter
}

// newRequestID returns a 16-byte random hex string suitable for use as a request ID.
// Using crypto/rand keeps this zero-dependency and cryptographically unpredictable.
func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is catastrophic; fall back to timestamp-based ID.
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// withRequestID is middleware that reads X-Request-ID from the inbound request (for
// upstream propagation) or generates a new random ID, stores it in the context, and
// echoes it back in the response header.
func (a *application) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newRequestID()
		}
		// Surface the ID to the client so it can be correlated in client-side logs.
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// withBodyLimit wraps each request body with a MaxBytesReader so oversized bodies
// are rejected before handlers attempt to read them.
func (a *application) withBodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// withRequestLogging is middleware that emits a structured log line after each request.
// It logs the real client IP from X-Forwarded-For (when present behind a proxy) in
// addition to RemoteAddr, so neither piece of information is silently lost.
func (a *application) withRequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		// Default status 200 covers handlers that call Write without WriteHeader.
		cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(cw, r)

		// X-Forwarded-For is set by reverse proxies (nginx, ALB, Cloudflare).
		// Log it alongside RemoteAddr so the real origin is always visible.
		xff := r.Header.Get("X-Forwarded-For")

		a.logger.Info("request",
			slog.String("request_id", requestIDFromContext(r.Context())),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", cw.status),
			slog.Duration("duration", time.Since(start)),
			slog.String("remote_addr", r.RemoteAddr),
			slog.String("x_forwarded_for", xff),
		)
	})
}

// run is the real entry-point, extracted from main so it can be called from tests
// and so its error return avoids os.Exit scattered throughout main.
func run(logger *slog.Logger) error {
	cfg, err := configFromEnv()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	app, err := newApplication(logger, version)
	if err != nil {
		return fmt.Errorf("init application: %w", err)
	}

	srv := &http.Server{
		Addr:    net.JoinHostPort("", cfg.port), // bind all interfaces
		Handler: app.routes(),
		// Mitigate Slowloris: cap the time allowed to read the full request header.
		ReadHeaderTimeout: 5 * time.Second,
		// Cap the total time for reading the request (header + body).
		ReadTimeout: 10 * time.Second,
		// Cap the total time to write the response.
		WriteTimeout: 10 * time.Second,
		// Reclaim idle keep-alive connections sooner under load.
		IdleTimeout: 60 * time.Second,
	}

	// serveErr carries any fatal error from ListenAndServe so run() can react.
	serveErr := make(chan error, 1)

	go func() {
		logger.Info("server starting",
			slog.String("addr", srv.Addr),
			slog.String("version", version),
		)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			// http.ErrServerClosed is the expected result of Shutdown; anything else is fatal.
			serveErr <- fmt.Errorf("ListenAndServe: %w", err)
		}
		close(serveErr)
	}()

	// Block until a termination signal arrives or the server exits on its own.
	quit := make(chan os.Signal, 1)
	// SIGINT = Ctrl-C in development; SIGTERM = kubectl delete pod / systemd stop.
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	// signal.Stop ensures the channel is de-registered when run() returns, which
	// matters for tests that invoke run() multiple times in-process.
	defer signal.Stop(quit)

	select {
	case sig := <-quit:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))
	case err := <-serveErr:
		if err != nil {
			return err // ListenAndServe failed before we could even start
		}
		// Channel closed without error: Shutdown was already called elsewhere.
		return nil
	}

	// Give in-flight requests up to shutdownTimeout to complete.
	ctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		// Shutdown failed; return immediately — the drain below is not safe.
		return fmt.Errorf("server shutdown: %w", err)
	}

	// Drain serveErr to confirm the ListenAndServe goroutine has fully exited.
	// This is only reachable when Shutdown succeeded (err == nil above).
	if err := <-serveErr; err != nil {
		return fmt.Errorf("server error after shutdown: %w", err)
	}

	logger.Info("server stopped gracefully")
	return nil
}

func main() {
	// JSON handler so log aggregators (Fluentd, Datadog, etc.) can parse fields.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if err := run(logger); err != nil {
		logger.Error("fatal", slog.Any("error", err))
		os.Exit(1)
	}
}
