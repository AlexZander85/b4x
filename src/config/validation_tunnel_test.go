package config

import "testing"

func TestValidateRoutingTunnelMode(t *testing.T) {
	base := func() *Config {
		c := NewConfig()
		set := NewSetConfig()
		c.Sets = []*SetConfig{&set}
		c.Sets[0].Id = "t1"
		c.Sets[0].Name = "tunnel-set"
		c.Sets[0].Routing.Enabled = true
		c.Sets[0].Routing.Mode = RoutingModeTunnel
		return &c
	}

	t.Run("valid kind accepted", func(t *testing.T) {
		c := base()
		c.Sets[0].Routing.Tunnel = TunnelKindProton
		if err := c.Validate(); err != nil {
			t.Fatalf("expected valid, got %v", err)
		}
		if c.Sets[0].Routing.Tunnel != TunnelKindProton {
			t.Fatalf("kind mutated: %q", c.Sets[0].Routing.Tunnel)
		}
	})

	t.Run("kind normalized and accepted", func(t *testing.T) {
		c := base()
		c.Sets[0].Routing.Tunnel = "  TOR "
		if err := c.Validate(); err != nil {
			t.Fatalf("expected valid, got %v", err)
		}
		if c.Sets[0].Routing.Tunnel != TunnelKindTor {
			t.Fatalf("kind not normalized: %q", c.Sets[0].Routing.Tunnel)
		}
	})

	t.Run("missing kind rejected", func(t *testing.T) {
		c := base()
		c.Sets[0].Routing.Tunnel = ""
		if err := c.Validate(); err == nil {
			t.Fatal("expected tunnel_kind_required error")
		}
	})

	t.Run("unknown kind rejected", func(t *testing.T) {
		c := base()
		c.Sets[0].Routing.Tunnel = "openvpn"
		if err := c.Validate(); err == nil {
			t.Fatal("expected unknown_tunnel_kind error")
		}
	})

	t.Run("quic policy normalized and accepted", func(t *testing.T) {
		for _, in := range []string{"", "auto", "  BLOCK "} {
			c := base()
			c.Sets[0].Routing.Tunnel = TunnelKindFxvpn
			c.Sets[0].Routing.Quic = in
			if err := c.Validate(); err != nil {
				t.Fatalf("quic %q: expected valid, got %v", in, err)
			}
		}
		c := base()
		c.Sets[0].Routing.Tunnel = TunnelKindFxvpn
		c.Sets[0].Routing.Quic = "  BLOCK "
		if err := c.Validate(); err != nil {
			t.Fatalf("expected valid, got %v", err)
		}
		if c.Sets[0].Routing.Quic != QuicBlock {
			t.Fatalf("quic not normalized: %q", c.Sets[0].Routing.Quic)
		}
		if !c.Sets[0].Routing.BlocksQuic() {
			t.Fatal("BlocksQuic must be true for block")
		}
	})

	t.Run("invalid quic policy rejected", func(t *testing.T) {
		c := base()
		c.Sets[0].Routing.Tunnel = TunnelKindFxvpn
		c.Sets[0].Routing.Quic = "maybe"
		if err := c.Validate(); err == nil {
			t.Fatal("expected invalid_quic_policy error")
		}
	})

	t.Run("sparse marshal keeps tunnel kind", func(t *testing.T) {
		c := base()
		c.Sets[0].Routing.Tunnel = TunnelKindOpera
		if err := c.Validate(); err != nil {
			t.Fatalf("expected valid, got %v", err)
		}
		data, err := MarshalSparse(c)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		t.Logf("sparse sets: %.200s", string(data))
	})
}
