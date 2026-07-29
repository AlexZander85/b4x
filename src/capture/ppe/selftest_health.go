package ppe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type HTTPHealthChecker struct {
	Client *http.Client
}

func (h HTTPHealthChecker) Check(ctx context.Context, endpoint string) error {
	parsed, err := url.Parse(endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("controlled endpoint must be an absolute HTTP(S) URL")
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("controlled endpoint returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Protocol string `json:"protocol"`
		Healthy  bool   `json:"healthy"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4096))
	if err := decoder.Decode(&payload); err != nil {
		return fmt.Errorf("decode controlled endpoint health: %w", err)
	}
	if payload.Protocol != SelfTestProtocol || !payload.Healthy {
		return errors.New("controlled endpoint did not confirm b4-ppe-self-test/v1 health")
	}
	return nil
}
