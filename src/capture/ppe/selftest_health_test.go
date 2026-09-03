package ppe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPHealthCheckerStrictProtocol(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"protocol":"b4-ppe-self-test/v1","healthy":true}`))
	}))
	defer server.Close()
	if err := (HTTPHealthChecker{}).Check(context.Background(), server.URL); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPHealthCheckerRejectsGenericSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"healthy":true}`))
	}))
	defer server.Close()
	if err := (HTTPHealthChecker{}).Check(context.Background(), server.URL); err == nil {
		t.Fatal("expected protocol rejection")
	}
}
