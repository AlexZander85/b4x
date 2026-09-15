package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// combinedADNSCatalogVersion binds a profile to every catalog version that
// contributed provider identities to the run. A managed catalog replacement
// therefore changes profile provenance/freshness even when the built-in
// reference resolver list is unchanged.
func combinedADNSCatalogVersion(items []dnspath.DNSPathProvider) string {
	seen := map[string]bool{}
	versions := make([]string, 0)
	for _, provider := range items {
		v := strings.TrimSpace(provider.ID().CatalogVersion)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		versions = append(versions, v)
	}
	if len(versions) == 0 {
		return adnsReferenceCatalog
	}
	sort.Strings(versions)
	if len(versions) == 1 {
		return versions[0]
	}
	sum := sha256.Sum256([]byte(strings.Join(versions, "\x00")))
	return "catalog-set-" + hex.EncodeToString(sum[:12])
}
