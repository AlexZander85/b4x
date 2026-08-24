package transportwg

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReservedFromClientID pins the warp-socks lineage: base64 decode with
// padding tolerance, first <=3 bytes, zero-filled tail.
func TestReservedFromClientID(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want [3]byte
	}{
		{"3 bytes unpadded", "uS9/", [3]byte{0xb9, 0x2f, 0x7f}},
		{"3 bytes padded", base64.StdEncoding.EncodeToString([]byte{1, 2, 3}), [3]byte{1, 2, 3}},
		{"2 bytes padded tail", base64.StdEncoding.EncodeToString([]byte{0xaa, 0xbb})[:3], [3]byte{0xaa, 0xbb, 0}},
		{"longer decodes truncate to 3", base64.StdEncoding.EncodeToString([]byte{9, 8, 7, 6, 5}), [3]byte{9, 8, 7}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReservedFromClientID(tc.in)
			if err != nil {
				t.Fatalf("ReservedFromClientID(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	for _, bad := range []string{"", "!!!not-base64!!!", "QQ==QQ=="} {
		if _, err := ReservedFromClientID(bad); err == nil {
			t.Fatalf("ReservedFromClientID(%q): expected error", bad)
		}
	}
}

// TestReservedHookPatchUnpatch is the design §10 WG2 unit gate: patch and
// unpatch round-trip per message type.
func TestReservedHookPatchUnpatch(t *testing.T) {
	h := ReservedHook{Reserved: [3]byte{0xde, 0xad, 0x01}}
	for typ := byte(1); typ <= 4; typ++ {
		buf := []byte{typ, 0, 0, 0, 0xff, 0xee}
		before := append([]byte(nil), buf...)
		h.PatchOutbound(buf)
		if buf[1] != 0xde || buf[2] != 0xad || buf[3] != 0x01 {
			t.Fatalf("type %d: stamp wrong: % x", typ, buf)
		}
		if buf[4] != 0xff || buf[5] != 0xee {
			t.Fatalf("type %d: stamp bled past [1:4]", typ)
		}
		h.AdjustInbound(buf)
		if buf[1]|buf[2]|buf[3] != 0 {
			t.Fatalf("type %d: scrub left residue: % x", typ, buf)
		}
		if buf[0] != before[0] || buf[4] != before[4] {
			t.Fatalf("type %d: scrub touched non-reserved bytes", typ)
		}
	}
	// Non-WG first byte must NOT be stamped.
	foreign := []byte{0x42, 1, 2, 3}
	h.PatchOutbound(foreign)
	if foreign[1] != 1 || foreign[2] != 2 || foreign[3] != 3 {
		t.Fatalf("non-type buffer was stamped: % x", foreign)
	}
	// Short buffers are safe no-ops in both directions.
	short := []byte{1, 2, 3}
	h.PatchOutbound(short)
	h.AdjustInbound(short)
	if len(short) != 3 {
		t.Fatal("short buffer resized")
	}
}

// TestDatagramHookOrNilGate pins red line §11.3 at the wiring point: the
// hook exists iff cf_warp is set.
func TestDatagramHookOrNilGate(t *testing.T) {
	priv, _, pub, _ := mustKeys(t)

	cf, err := NewIdentity(priv.B64(), pub.B64(), "uS9/", "172.16.0.2", "", true)
	if err != nil {
		t.Fatal(err)
	}
	hook, err := cf.DatagramHookOrNil()
	if err != nil || hook == nil {
		t.Fatalf("cf_warp=true must yield a hook: %v %v", hook, err)
	}

	generic, err := NewIdentity(priv.B64(), pub.B64(), "uS9/", "172.16.0.2", "", false)
	if err != nil {
		t.Fatal(err)
	}
	hook, err = generic.DatagramHookOrNil()
	if err != nil || hook != nil {
		t.Fatalf("cf_warp=false must yield nil hook (zero reserved on the wire): %v %v", hook, err)
	}
}

// TestIdentityValidation covers the strict-decode table.
func TestIdentityValidation(t *testing.T) {
	priv, privOther, pub, _ := mustKeys(t)
	good := func() (string, string, string, string) {
		return priv.B64(), pub.B64(), "uS9/", "10.0.0.2"
	}

	pk, peer, cid, v4 := good()
	if _, err := NewIdentity(pk, peer, cid, v4, "2606:4700::1", true); err != nil {
		t.Fatalf("golden v6 identity rejected: %v", err)
	}
	if _, err := NewIdentity(pk, peer, cid, v4, "", false); err != nil {
		t.Fatalf("golden identity rejected: %v", err)
	}

	badPriv := base64.StdEncoding.EncodeToString(make([]byte, 31))
	if _, err := NewIdentity(badPriv, peer, cid, v4, "", false); err == nil {
		t.Fatal("31-byte private key accepted")
	}
	if _, err := NewIdentity(pk, pk, cid, v4, "", false); err == nil {
		t.Fatal("private==peer-public accepted")
	}
	if _, err := NewIdentity(pk, peer, "", v4, "", false); err == nil {
		t.Fatal("empty client_id accepted")
	}
	if _, err := NewIdentity(pk, peer, cid, "not-an-ip", "", false); err == nil {
		t.Fatal("bad assigned_v4 accepted")
	}
	if _, err := NewIdentity(pk, peer, cid, "2606:4700::1", "", false); err == nil {
		t.Fatal("v6 address in assigned_v4 accepted")
	}
	if _, err := NewIdentity(pk, peer, cid, v4, "10.0.0.9", false); err == nil {
		t.Fatal("v4 address in assigned_v6 accepted")
	}

	other, err := NewIdentity(privOther.B64(), peer, cid, v4, "", false)
	if err != nil {
		t.Fatal(err)
	}
	other.Format = 99
	if err := other.Validate(); err == nil {
		t.Fatal("unknown format version accepted")
	}
}

// TestIdentityStoreRoundTrip covers the atomic store transaction shapes:
// save->load equality, absent path, corrupt quarantine.
func TestIdentityStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "slot-a.json")
	store := &IdentityStore{Path: path}

	if _, err := store.Load(); err != ErrIdentityAbsent {
		t.Fatalf("absent slot: got %v", err)
	}

	id, err := NewIdentity(mustB64Key(t), mustB64Key(t), "uS9/", "10.0.0.2", "", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(id); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm()&0o077 != 0 {
		t.Logf("note: perms %s wider than 0600 (platform-dependent)", info.Mode())
	}

	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.PrivateKey != id.PrivateKey || got.ClientID != id.ClientID || !got.CFWarp {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	// Corrupt file -> quarantine + ErrIdentityCorrupt.
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrIdentityCorrupt) {
		t.Fatalf("corrupt slot: got %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("quarantine file missing: %v", err)
	}

	// Tampered-but-parseable (bad client_id) also quarantines via Validate.
	tampered := `{"format":1,"wg_private_key":"` + strings.Repeat("AA", 32) +
		`","wg_peer_public_key":"` + strings.Repeat("BB", 32) +
		`","wg_client_id":"","wg_assigned_v4":"10.0.0.2","cf_warp":true}`
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrIdentityCorrupt) {
		t.Fatalf("tampered slot: got %v", err)
	}
}

func mustB64Key(t *testing.T) string {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k.B64()
}
