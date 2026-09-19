package transportwg

// WG enrollment client tests (httptest only — no live Cloudflare traffic may
// ever originate from unit tests, the consent rule shared with the MASQUE
// client). Verifies: the REAL key rides the POST (not a placeholder), the
// GET config projects onto a cf_warp Identity, and the hex client_id bridge
// lands exactly the first three API bytes into the reserved routing bytes.
import (
        "context"
        "encoding/base64"
        "encoding/hex"
        "encoding/json"
        "net/http"
        "net/http/httptest"
        "sync/atomic"
        "testing"
        "time"
)

type enrollFakeAPI struct {
        t        *testing.T
        posts    atomic.Int64
        gets     atomic.Int64
        postBody map[string]any
        servedID string
}

func (f *enrollFakeAPI) handler() http.Handler {
        mux := http.NewServeMux()
        mux.HandleFunc("/v0a4471/reg", func(w http.ResponseWriter, r *http.Request) {
                if r.Method != http.MethodPost {
                        http.Error(w, "method", http.StatusMethodNotAllowed)
                        return
                }
                f.posts.Add(1)
                var body map[string]any
                if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
                        http.Error(w, "bad body", http.StatusBadRequest)
                        return
                }
                f.postBody = body
                if key, _ := body["key"].(string); key == "" {
                        http.Error(w, `{"success":false,"errors":[{"code":1001,"message":"InvalidPublicKey"}]}`, http.StatusBadRequest)
                        return
                }
                f.servedID = "dev-1234"
                _ = json.NewEncoder(w).Encode(map[string]any{
                        "id":    f.servedID,
                        "token": "tok-5678",
                        "account": map[string]any{
                                "license":      "",
                                "account_type": "free",
                        },
                })
        })
        mux.HandleFunc("/v0a4471/reg/dev-1234", func(w http.ResponseWriter, r *http.Request) {
                if r.Method != http.MethodGet {
                        http.Error(w, "method", http.StatusMethodNotAllowed)
                        return
                }
                f.gets.Add(1)
                if got := r.Header.Get("Authorization"); got != "Bearer tok-5678" {
                        http.Error(w, "auth", http.StatusUnauthorized)
                        return
                }
                _ = json.NewEncoder(w).Encode(map[string]any{
                        "id":    f.servedID,
                        "token": "tok-5678",
                        "config": map[string]any{
                                "client_id": "a1b2c3d4e5f60718",
                                "peers": []map[string]any{{
                                        "public_key": "qmY5ZCOxDcf3KzXWQcWp3CgXJcHwSib4YhFGpPZKjEo=",
                                        "endpoint":   map[string]any{"v4": "162.159.193.5:2408"},
                                }},
                                "interface": map[string]any{
                                        "addresses": map[string]any{
                                                "v4": "172.16.0.2",
                                                "v6": "fd01:5ca1:ab1e:80fa::2",
                                        },
                                },
                        },
                })
        })
        return mux
}

func TestWGEnrollClientEnroll(t *testing.T) {
        api := &enrollFakeAPI{t: t}
        srv := httptest.NewServer(api.handler())
        defer srv.Close()

        c := &EnrollClient{
                BaseURL: srv.URL + "/v0a4471",
                Sleep:   func(context.Context, time.Duration) error { return nil },
                Now:     func() time.Time { return time.Unix(1700000000, 0) },
        }
        ident, out, err := c.Enroll(context.Background())
        if err != nil {
                t.Fatalf("enroll: %v", err)
        }
        if out != EnrollOK {
                t.Fatalf("outcome = %d, want EnrollOK", out)
        }

        // The POST carried the REAL key (WARP-WG shape: pinned at registration,
        // no placeholder + PATCH dance).
        if key, _ := api.postBody["key"].(string); key == "" {
                t.Fatal("POST body missing the real client key")
        } else if raw, derr := base64.StdEncoding.DecodeString(key); derr != nil || len(raw) != 32 {
                t.Fatalf("POST key is not a raw 32-byte b64 public key: %q", key)
        }
        if tos, _ := api.postBody["tos"].(string); tos == "" {
                t.Fatal("POST body missing tos")
        }

        // Identity projection: cf_warp pin + edge key + assigned addresses.
        if !ident.CFWarp {
                t.Fatal("identity must be cf_warp (reserved bytes allowed on the wire)")
        }
        if ident.PeerPublicKey == (Key{}) {
                t.Fatal("identity missing the edge peer public key")
        }
        if ident.AssignedV4 != "172.16.0.2" {
                t.Fatalf("assigned v4 = %q", ident.AssignedV4)
        }
        if ident.AssignedV6 != "fd01:5ca1:ab1e:80fa::2" {
                t.Fatalf("assigned v6 = %q", ident.AssignedV6)
        }
        if ident.EndpointHint != "162.159.193.5:2408" {
                t.Fatalf("endpoint hint = %q", ident.EndpointHint)
        }

        // The hex client_id bridge: "a1b2c3" are exactly the first three API
        // bytes that must land in the reserved routing bytes.
        res, err := ident.Reserved()
        if err != nil {
                t.Fatalf("reserved: %v", err)
        }
        want, _ := hex.DecodeString("a1b2c3")
        if res != [3]byte{want[0], want[1], want[2]} {
                t.Fatalf("reserved bytes = %x, want a1b2c3", res)
        }
        if err := ident.Validate(); err != nil {
                t.Fatalf("identity validation: %v", err)
        }
}

func TestWGEnrollClientRefused(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                http.Error(w, `{"success":false,"errors":[{"code":0,"message":"gone"}]}`, http.StatusGone)
        }))
        defer srv.Close()

        c := &EnrollClient{BaseURL: srv.URL + "/v0a4471",
                Sleep: func(context.Context, time.Duration) error { return nil }}
        _, out, err := c.Enroll(context.Background())
        if err == nil {
                t.Fatal("expected error")
        }
        if out != EnrollRefused {
                t.Fatalf("outcome = %d, want EnrollRefused", out)
        }
}

func TestWGEnrollBridgeClientID(t *testing.T) {
        // Hex 64 chars -> first 3 bytes as base64.
        b64, err := bridgeClientID("0011aaffedcb00112233445566778899001122334455667788990011223344556677")
        if err != nil {
                t.Fatalf("bridge: %v", err)
        }
        raw, _ := base64.StdEncoding.DecodeString(b64)
        if len(raw) != 3 || raw[0] != 0x00 || raw[1] != 0x11 || raw[2] != 0xaa {
                t.Fatalf("bridge bytes = %x, want 0011aa", raw)
        }
        // Short hex.
        b64, err = bridgeClientID("a1")
        if err != nil {
                t.Fatalf("bridge short: %v", err)
        }
        raw, _ = base64.StdEncoding.DecodeString(b64)
        if len(raw) != 1 || raw[0] != 0xa1 {
                t.Fatalf("short bridge bytes = %x", raw)
        }
        // API drift: the current /v0a4471 form is 4-char base64 ("NCwq" -> 0x342c2a).
        b64, err = bridgeClientID("NCwq")
        if err != nil {
                t.Fatalf("bridge base64: %v", err)
        }
        raw, _ = base64.StdEncoding.DecodeString(b64)
        if len(raw) != 3 || raw[0] != 0x34 || raw[1] != 0x2c || raw[2] != 0x2a {
                t.Fatalf("base64 bridge bytes = %x, want 342c2a", raw)
        }
        // Non-hex input is a structural rejection (fail closed).
        if _, err := bridgeClientID("not-hex!!"); err == nil {
                t.Fatal("expected non-hex rejection")
        }
}
