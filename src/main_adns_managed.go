package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	b4dns "github.com/daniellavrushin/b4/dns"
	"github.com/daniellavrushin/b4/log"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/managed"
	"github.com/daniellavrushin/b4/transport/dns/providers"
)

const (
	managedDNSBinaryEnv      = "B4X_DNSCRYPT_BINARY"
	managedDNSManifestEnv    = "B4X_DNSCRYPT_MANIFEST"
	managedDNSCatalogEnv     = "B4X_DNSCRYPT_CATALOG"
	managedDNSCatalogSigEnv  = "B4X_DNSCRYPT_CATALOG_SIG"
	managedDNSCatalogKeyEnv  = "B4X_DNSCRYPT_CATALOG_KEY"
	managedDNSWorkDirEnv     = "B4X_DNSCRYPT_WORKDIR"
	managedDNSMaxCandidates  = 2
	managedDNSDefaultWorkDir = "/tmp/b4x-adns"
)

// buildADNSManagedProviders loads only locally provisioned, fully verified
// dnscrypt-proxy material. Runtime download is intentionally absent. Missing
// configuration means "not applicable"; partially configured or unverified
// material is rejected as a whole instead of silently falling back to an
// unsafe/default backend source.
func buildADNSManagedProviders(policy dnspath.AdaptivePolicy, readinessName string) []dnspath.DNSPathProvider {
	if !policy.AllowManagedDNSCrypt {
		return nil
	}
	binaryPath := strings.TrimSpace(os.Getenv(managedDNSBinaryEnv))
	manifestPath := strings.TrimSpace(os.Getenv(managedDNSManifestEnv))
	catalogPath := strings.TrimSpace(os.Getenv(managedDNSCatalogEnv))
	sigPath := strings.TrimSpace(os.Getenv(managedDNSCatalogSigEnv))
	pinnedKey := strings.TrimSpace(os.Getenv(managedDNSCatalogKeyEnv))
	configured := binaryPath != "" || manifestPath != "" || catalogPath != "" || sigPath != "" || pinnedKey != ""
	if !configured {
		return nil
	}
	if binaryPath == "" || manifestPath == "" || catalogPath == "" || sigPath == "" || pinnedKey == "" {
		log.Warnf("adaptive dns: managed DNSCrypt disabled: binary, manifest, catalog, signature and pinned catalog key must all be configured")
		return nil
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		log.Warnf("adaptive dns: managed DNSCrypt manifest unavailable: %v", err)
		return nil
	}
	var manifest managed.BinaryManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		log.Warnf("adaptive dns: managed DNSCrypt manifest invalid: %v", err)
		return nil
	}
	if err := managed.VerifyBinary(binaryPath, manifest); err != nil {
		log.Warnf("adaptive dns: managed DNSCrypt binary rejected: %v", err)
		return nil
	}

	catalogBytes, err := os.ReadFile(catalogPath)
	if err != nil {
		log.Warnf("adaptive dns: managed DNSCrypt catalog unavailable: %v", err)
		return nil
	}
	sigBytes, err := os.ReadFile(sigPath)
	if err != nil {
		log.Warnf("adaptive dns: managed DNSCrypt catalog signature unavailable: %v", err)
		return nil
	}
	var signature managed.SignaturePayload
	if err := json.Unmarshal(sigBytes, &signature); err != nil {
		log.Warnf("adaptive dns: managed DNSCrypt catalog signature invalid: %v", err)
		return nil
	}
	if err := managed.VerifyCatalogSignature(catalogBytes, signature, pinnedKey); err != nil {
		log.Warnf("adaptive dns: managed DNSCrypt catalog rejected: %v", err)
		return nil
	}
	catalog, err := managed.ParseCatalog(catalogBytes, 512)
	if err != nil {
		log.Warnf("adaptive dns: managed DNSCrypt catalog parse failed: %v", err)
		return nil
	}
	if catalog.Version == "" {
		log.Warnf("adaptive dns: managed DNSCrypt catalog has no version")
		return nil
	}
	// Profile.Valid() treats a non-empty registry as an allowlist. Register
	// both the built-in reference catalog and this verified managed catalog.
	dnspath.KnownCatalogVersions[adnsReferenceCatalog] = true
	dnspath.KnownCatalogVersions[catalog.Version] = true

	workRoot := strings.TrimSpace(os.Getenv(managedDNSWorkDirEnv))
	if workRoot == "" {
		workRoot = managedDNSDefaultWorkDir
	}
	readiness := managedReadinessProbe(readinessName)
	out := make([]dnspath.DNSPathProvider, 0, managedDNSMaxCandidates)
	for _, entry := range catalog.Entries {
		if len(out) >= managedDNSMaxCandidates {
			break
		}
		if !entry.ProductionReady() {
			continue
		}
		family := managedCatalogFamily(entry.Family)
		if family == "" || !policy.AllowsFamily(family) {
			continue
		}
		if policy.RequireDNSSECCapable && !entry.DNSSEC {
			continue
		}
		if policy.RequireNoLogClaim && !entry.NoLog {
			continue
		}
		if policy.RequireNoFilterClaim && !entry.NoFilter {
			continue
		}
		listenAddr, err := managed.AllocateLoopbackPort()
		if err != nil {
			log.Warnf("adaptive dns: managed DNSCrypt listener allocation failed for %s: %v", entry.Name, err)
			continue
		}
		spec := managed.InstanceSpec{
			Family: entry.Family, ServerName: entry.Name, ServerStamp: entry.Stamp,
			ListenAddr: listenAddr, IPv4: true, IPv6: false,
			Cache: true, CacheSize: 1024,
			RequireNoLog: entry.NoLog, RequireNoFilter: entry.NoFilter, RequireDNSSEC: entry.DNSSEC,
		}
		entryKey := managedInstanceKey(entry.Name, entry.Family)
		factory := func(s managed.InstanceSpec, _ string) *managed.Supervisor {
			return managed.NewSupervisor(manifest, binaryPath, filepath.Join(workRoot, entryKey), s, readiness)
		}
		out = append(out, providers.NewManagedProvider(spec, catalog.Version, factory))
	}
	if len(out) == 0 {
		log.Warnf("adaptive dns: verified managed catalog %s contains no production-ready entry allowed by active policy", catalog.Version)
	} else {
		log.Infof("adaptive dns: loaded %d verified managed provider(s) from catalog %s", len(out), catalog.Version)
	}
	return out
}

func managedCatalogFamily(family string) dnspath.DNSPathFamily {
	switch strings.ToLower(strings.TrimSpace(family)) {
	case "dnscrypt":
		return dnspath.DNSPathDNSCrypt
	case "pqdnscrypt":
		return dnspath.DNSPathPQDNSCrypt
	case "doh":
		return dnspath.DNSPathDoH
	default:
		// Anonymized DNSCrypt/ODoH need an explicit signed relay stamp and
		// route identity; until that producer exists they remain inapplicable.
		return ""
	}
}

func managedInstanceKey(name, family string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(family)) + "|" + strings.ToLower(strings.TrimSpace(name))))
	return "instance-" + hex.EncodeToString(sum[:8])
}

func managedReadinessProbe(name string) managed.QueryFunc {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		name = "example.com"
	}
	return func(ctx context.Context, listenAddr string) error {
		d := &net.Dialer{}
		conn, err := d.DialContext(ctx, "udp", listenAddr)
		if err != nil {
			return err
		}
		defer conn.Close()
		deadline := time.Now().Add(2 * time.Second)
		if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
			deadline = dl
		}
		_ = conn.SetDeadline(deadline)
		const txid uint16 = 0xb4d5
		query := b4dns.BuildQuery(name, txid, 1)
		if _, err := conn.Write(query); err != nil {
			return err
		}
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		payload := buf[:n]
		gotTxID, ok := b4dns.ParseTransactionID(payload)
		if !ok || gotTxID != txid {
			return fmt.Errorf("managed readiness transaction mismatch")
		}
		qname, qtype, _, ok := b4dns.ParseQuestion(payload)
		if !ok || !sameDNSName(qname, name) || qtype != 1 {
			return fmt.Errorf("managed readiness question mismatch")
		}
		meta, err := b4dns.InspectResponseMetadata(payload)
		if err != nil {
			return err
		}
		if meta.Truncated || meta.RCode != 0 {
			return fmt.Errorf("managed readiness returned rcode=%d truncated=%v", meta.RCode, meta.Truncated)
		}
		return nil
	}
}
