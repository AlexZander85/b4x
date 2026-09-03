package geodat

import (
	"bufio"
	"encoding/binary"
	"io"
	"os"
	"sort"
	"sync"

	"github.com/daniellavrushin/b4/log"
)

type GeodataType int

const (
	GEOSITE GeodataType = iota
	GEOIP
)

// GeodataManager handles geodata file operations with caching and statistics
type GeodataManager struct {
	mu          sync.RWMutex
	geositePath string
	geoipPath   string

	categoryDomains       map[string][]string // category -> domains (cached)
	categoryDomainsCounts map[string]int      // category -> domain count (fast lookup)

	categoryIps       map[string][]string // category -> IPs (cached)
	categoryIpsCounts map[string]int      // category -> IP count (fast lookup)
}

// NewGeodataManager creates a new geodata manager instance
func NewGeodataManager(geositePath, geoipPath string) *GeodataManager {
	return &GeodataManager{
		geositePath:           geositePath,
		geoipPath:             geoipPath,
		categoryDomains:       make(map[string][]string),
		categoryDomainsCounts: make(map[string]int),
		categoryIps:           make(map[string][]string),
		categoryIpsCounts:     make(map[string]int),
	}
}

// UpdatePaths updates the geodata file paths and clears cache if paths changed
func (gm *GeodataManager) UpdatePaths(geositePath, geoipPath string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	pathsChanged := gm.geositePath != geositePath || gm.geoipPath != geoipPath

	gm.geositePath = geositePath
	gm.geoipPath = geoipPath

	if pathsChanged {
		gm.categoryDomains = make(map[string][]string)
		gm.categoryDomainsCounts = make(map[string]int)
		gm.categoryIps = make(map[string][]string)
		gm.categoryIpsCounts = make(map[string]int)
		log.Infof("Geodata paths updated, cache cleared")
	}
}

func (gm *GeodataManager) LoadGeoipCategory(category string) ([]string, error) {
	gm.mu.RLock()
	if ips, exists := gm.categoryIps[category]; exists {
		gm.mu.RUnlock()
		log.Tracef("Using cached domains for category: %s (%d domains)", category, len(ips))
		return ips, nil
	}
	gm.mu.RUnlock()

	// Load from file
	if gm.geoipPath == "" {
		return nil, log.Errorf("geoip path not configured")
	}

	ips, err := LoadIpsFromCategories(gm.geoipPath, []string{category})
	if err != nil {
		return nil, err
	}

	// Cache the result
	gm.mu.Lock()
	gm.categoryIps[category] = ips
	gm.categoryIpsCounts[category] = len(ips)
	gm.mu.Unlock()

	log.Tracef("Loaded and cached %d domains for category: %s", len(ips), category)
	return ips, nil
}

// loads domains for a single category (uses cache if available)
func (gm *GeodataManager) LoadGeositeCategory(category string) ([]string, error) {
	gm.mu.RLock()
	if domains, exists := gm.categoryDomains[category]; exists {
		gm.mu.RUnlock()
		log.Tracef("Using cached domains for category: %s (%d domains)", category, len(domains))
		return domains, nil
	}
	gm.mu.RUnlock()

	// Load from file
	if gm.geositePath == "" {
		return nil, log.Errorf("geosite path not configured")
	}

	domains, err := LoadDomainsFromCategories(gm.geositePath, []string{category})
	if err != nil {
		return nil, err
	}

	// Cache the result
	gm.mu.Lock()
	gm.categoryDomains[category] = domains
	gm.categoryDomainsCounts[category] = len(domains)
	gm.mu.Unlock()

	log.Tracef("Loaded and cached %d domains for category: %s", len(domains), category)
	return domains, nil
}

// loads domains for multiple categories and returns combined domains + counts
func (gm *GeodataManager) LoadGeositeCategories(categories []string) ([]string, map[string]int, error) {
	if len(categories) == 0 {
		return []string{}, make(map[string]int), nil
	}

	if gm.geositePath == "" {
		return nil, nil, log.Errorf("geosite path not configured")
	}

	// Create a set of requested categories for easy lookup
	requestedCategories := make(map[string]bool)
	for _, cat := range categories {
		requestedCategories[cat] = true
	}

	// Remove categories from cache that are no longer requested
	gm.mu.Lock()
	for cachedCategory := range gm.categoryDomains {
		if !requestedCategories[cachedCategory] {
			delete(gm.categoryDomains, cachedCategory)
			delete(gm.categoryDomainsCounts, cachedCategory)
			log.Tracef("Removed category %s from cache (no longer selected)", cachedCategory)
		}
	}
	gm.mu.Unlock()

	uniqueDomains := make(map[string]bool)
	categoryStats := make(map[string]int)

	for _, category := range categories {
		domains, err := gm.LoadGeositeCategory(category)
		if err != nil {
			log.Errorf("Failed to load category %s: %v", category, err)
			continue
		}

		for _, domain := range domains {
			uniqueDomains[domain] = true
		}
		categoryStats[category] = len(domains)
	}

	allDomains := make([]string, 0, len(uniqueDomains))
	for domain := range uniqueDomains {
		allDomains = append(allDomains, domain)
	}

	log.Tracef("Loaded %d total domains from %d categories", len(allDomains), len(categories))
	return allDomains, categoryStats, nil
}

// returns domain counts for specified categories (loads if not cached)
func (gm *GeodataManager) GetGeositeCategoryCounts(categories []string) (map[string]int, error) {
	if len(categories) == 0 {
		return make(map[string]int), nil
	}

	counts := make(map[string]int)

	for _, category := range categories {
		// Check cache first
		gm.mu.RLock()
		if count, exists := gm.categoryDomainsCounts[category]; exists {
			counts[category] = count
			gm.mu.RUnlock()
			continue
		}
		gm.mu.RUnlock()

		// Not in cache, load it
		domains, err := gm.LoadGeositeCategory(category)
		if err != nil {
			log.Errorf("Failed to get count for category %s: %v", category, err)
			counts[category] = 0
			continue
		}
		counts[category] = len(domains)
	}

	return counts, nil
}

func (gm *GeodataManager) GetGeoipCategoryCounts(categories []string) (map[string]int, error) {
	if len(categories) == 0 {
		return make(map[string]int), nil
	}

	counts := make(map[string]int)

	for _, category := range categories {
		// Check cache first
		gm.mu.RLock()
		if count, exists := gm.categoryIpsCounts[category]; exists {
			counts[category] = count
			gm.mu.RUnlock()
			continue
		}
		gm.mu.RUnlock()

		// Not in cache, load it
		ips, err := gm.LoadGeoipCategory(category)
		if err != nil {
			log.Errorf("Failed to get count for category %s: %v", category, err)
			counts[category] = 0
			continue
		}
		counts[category] = len(ips)
	}

	return counts, nil
}

func (gm *GeodataManager) ListCategories(filePath string) ([]string, error) {

	log.Tracef("Listing geo dat tags from %s", filePath)
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	set := map[string]struct{}{}
	r := bufio.NewReaderSize(f, 32*1024)
	for {
		b, err := r.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if b != 0x0A {
			return nil, log.Errorf("unexpected wire tag %02X", b)
		}
		l, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, log.Errorf("failed to read varint: %w", err)
		}
		msg := make([]byte, l)
		if _, err := io.ReadFull(r, msg); err != nil {
			return nil, err
		}
		tag, err := readCountryCode(msg)
		if err != nil {
			return nil, err
		}
		set[tag] = struct{}{}
	}

	tags := make([]string, 0, len(set))
	for t := range set {
		tags = append(tags, t)
	}
	sort.Strings(tags)

	return tags, nil
}

// PreloadCategories loads and caches categories at startup
func (gm *GeodataManager) PreloadCategories(t GeodataType, categories []string) (map[string]int, error) {
	log.Infof("Preloading %d geosite categories...", len(categories))

	totalDomains := 0
	var counts map[string]int
	var err error

	if t == GEOIP {
		counts, err = gm.GetGeoipCategoryCounts(categories)
		if err != nil {
			return nil, err
		}
	} else {
		counts, err = gm.GetGeositeCategoryCounts(categories)
		if err != nil {
			return nil, err
		}
	}

	for _, count := range counts {
		totalDomains += count
	}

	log.Infof("Preloaded %d domains across %d categories", totalDomains, len(counts))
	return counts, nil
}

// ClearCache clears all cached data
func (gm *GeodataManager) ClearCache() {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	gm.categoryDomains = make(map[string][]string)
	gm.categoryDomainsCounts = make(map[string]int)
	gm.categoryIps = make(map[string][]string)
	gm.categoryIpsCounts = make(map[string]int)
	log.Infof("Geodata cache cleared")
}

func (gm *GeodataManager) IsGeositeConfigured() bool {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	return gm.geositePath != ""
}

func (gm *GeodataManager) IsGeoipConfigured() bool {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	return gm.geoipPath != ""
}

// GetGeositePath returns the current geosite path
func (gm *GeodataManager) GetGeositePath() string {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	return gm.geositePath
}

func (gm *GeodataManager) GetGeoipPath() string {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	return gm.geoipPath
}
