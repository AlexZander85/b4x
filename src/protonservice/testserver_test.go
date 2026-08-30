// Test-only HTTP server shim: an httptest.Server wrapper whose base URL the
// rewrite transport targets (the fake Proton API stand).
package protonservice

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type testServer struct {
	*httptest.Server
}

func (s *testServer) url() string { return s.Server.URL }

func newTestServer(t *testing.T, h http.Handler) *testServer {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &testServer{Server: srv}
}
