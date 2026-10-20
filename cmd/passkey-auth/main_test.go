package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// freePort returns a loopback address nobody listens on.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// rawRequest sends a request line exactly as written, so that no client
// cleans or re-encodes the path, and returns the status and error code.
func rawRequest(t *testing.T, addr, method, target string) (int, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("%s: %v", addr, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	body := `{"account":"a","displayName":"A"}`
	fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		method, target, addr, len(body), body)
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	var v struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(b, &v)
	return res.StatusCode, v.Error.Code
}

// waitListening waits until addr accepts connections.
func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("nothing listens on %s: %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// startService runs the service on two free loopback ports and returns them
// with a function that stops it and returns run's error.
func startService(t *testing.T) (public, host string, stop func() error) {
	t.Helper()
	dir := t.TempDir()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyFile := filepath.Join(dir, "signing-key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	public, host = freePort(t), freePort(t)
	for k, v := range map[string]string{
		"PA_LISTEN": public, "PA_HOST_LISTEN": host,
		"PA_RP_ID": "localhost", "PA_ORIGINS": "http://localhost", "PA_ISSUER": "http://localhost/auth",
		"PA_AUDIENCE": "host", "PA_SIGNING_KEY_FILE": keyFile, "PA_DB_PATH": filepath.Join(dir, "db"),
		"PA_HOST_DID": "did:web:host.invalid",
	} {
		t.Setenv(k, v)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- run(ctx, slog.New(slog.DiscardHandler)) }()
	stop = func() error {
		cancel()
		select {
		case err := <-errc:
			return err
		case <-time.After(shutdownTimeout + 5*time.Second):
			return fmt.Errorf("run did not return after cancel")
		}
	}
	t.Cleanup(func() { _ = stop() })
	waitListening(t, public)
	waitListening(t, host)
	return public, host, stop
}

// Host paths, and spellings of them that a proxy or a router might read as
// the same route.
var hostPaths = []struct{ method, target string }{
	{"POST", "/v1/registration-tickets"},
	{"POST", "/v1/registration-tickets/"},
	{"POST", "/V1/registration-tickets"},
	{"POST", "/v1/Registration-Tickets"},
	{"POST", "/v1/REGISTRATION-TICKETS"},
	{"POST", "//v1/registration-tickets"},
	{"POST", "/v1//registration-tickets"},
	{"POST", "/./v1/registration-tickets"},
	{"POST", "/v1/./registration-tickets"},
	{"POST", "/v1/x/../registration-tickets"},
	{"POST", "/v1/registration-tickets/."},
	{"POST", "/v1%2Fregistration-tickets"},
	{"POST", "/v1%2fregistration-tickets"},
	{"POST", "/%76%31/registration-tickets"},
	{"POST", "/v1/registration%2Dtickets"},
	{"POST", "/v1/registration-tickets%2F"},
	{"POST", "/v1/registration-tickets;x"},
	{"POST", "/v1/registration-tickets?x=1"},
	{"POST", "/auth/v1/registration-tickets"},
	{"GET", "/v1/accounts/alice/credentials"},
	{"GET", "/v1/accounts/alice%2Fbob/credentials"},
	{"GET", "/v1/accounts/alice/credentials/"},
	{"GET", "//v1/accounts/alice/credentials"},
	{"GET", "/v1/Accounts/alice/credentials"},
	{"GET", "/v1%2Faccounts%2Falice%2Fcredentials"},
	{"DELETE", "/v1/accounts/alice/credentials/AAAA"},
	{"DELETE", "/v1/accounts/alice/credentials/AAAA/"},
	{"DELETE", "/v1//accounts/alice/credentials/AAAA"},
}

// The public listener never serves a host route, in any spelling; the host
// listener serves them, and asks for a host token.
func TestTwoListeners(t *testing.T) {
	public, host, _ := startService(t)
	for _, p := range hostPaths {
		if status, code := rawRequest(t, public, p.method, p.target); status != http.StatusNotFound || code != "not_found" {
			t.Errorf("public %s %s: %d %q, want 404 not_found", p.method, p.target, status, code)
		}
	}
	for _, p := range hostPaths[:1] {
		if status, code := rawRequest(t, host, p.method, p.target); status != http.StatusUnauthorized || code != "host_unauthorized" {
			t.Errorf("host %s %s: %d %q, want 401 host_unauthorized", p.method, p.target, status, code)
		}
	}
	for _, target := range []string{"/v1/accounts/alice/credentials", "/v1/accounts/alice%2Fbob/credentials"} {
		if status, code := rawRequest(t, host, "GET", target); status != http.StatusUnauthorized || code != "host_unauthorized" {
			t.Errorf("host GET %s: %d %q, want 401 host_unauthorized", target, status, code)
		}
	}
	if status, code := rawRequest(t, host, "DELETE", "/v1/accounts/alice/credentials/AAAA"); status != http.StatusUnauthorized || code != "host_unauthorized" {
		t.Errorf("host DELETE: %d %q, want 401 host_unauthorized", status, code)
	}
	// And the public routes are not served by the host listener.
	if status, _ := rawRequest(t, host, "GET", "/v1/jwks.json"); status != http.StatusNotFound {
		t.Errorf("host GET /v1/jwks.json: %d, want 404", status)
	}
	if status, _ := rawRequest(t, public, "GET", "/v1/jwks.json"); status != http.StatusOK {
		t.Errorf("public GET /v1/jwks.json: %d, want 200", status)
	}
}

// Cancelling run stops both listeners, and run returns nil.
func TestBothListenersStopTogether(t *testing.T) {
	public, host, stop := startService(t)
	if err := stop(); err != nil {
		t.Fatalf("run: %v", err)
	}
	for _, addr := range []string{public, host} {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			t.Errorf("%s still listens after the shutdown", addr)
		}
	}
}

// If the host listener cannot start, run fails and the public one stops too.
func TestHostListenerFailureStopsTheService(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	dir := t.TempDir()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	keyFile := filepath.Join(dir, "signing-key.pem")
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
	public := freePort(t)
	for k, v := range map[string]string{
		"PA_LISTEN": public, "PA_HOST_LISTEN": busy.Addr().String(),
		"PA_RP_ID": "localhost", "PA_ORIGINS": "http://localhost", "PA_ISSUER": "http://localhost/auth",
		"PA_AUDIENCE": "host", "PA_SIGNING_KEY_FILE": keyFile, "PA_DB_PATH": filepath.Join(dir, "db"),
		"PA_HOST_DID": "did:web:host.invalid",
	} {
		t.Setenv(k, v)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- run(ctx, slog.New(slog.DiscardHandler)) }()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("run returned nil with its host port taken")
		}
	case <-time.After(shutdownTimeout + 5*time.Second):
		t.Fatal("run kept serving with its host port taken")
	}
	if c, err := net.DialTimeout("tcp", public, 200*time.Millisecond); err == nil {
		c.Close()
		t.Error("the public listener still listens")
	}
}
