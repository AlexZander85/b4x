// AWG obfuscation chain DSL parser and hard validator.
//
// Upstream grammar (amneziawg-go v3 device/obf.go:34-96): a spec is a
// sequence of `<...>` tags; inside a tag the first whitespace-separated field
// is the key (`b t r rc rd d ds dz`, obf.go:11-20) and the optional second
// field is its argument. Two upstream behaviors are dangerous for us and are
// closed here (research §1 "validation holes"):
//
//  1. Text OUTSIDE tags is silently ignored by newObfChain — e.g. a typo'd
//     colon-separated chain would silently degrade to a shorter chain.
//     Our parser rejects any non-whitespace outside tags.
//  2. r/rc/rd/dz lengths go through strconv.Atoi with no range check —
//     negatives pass upstream and underflow at obfuscate time. We require
//     0 <= n <= maxChainElemLen.
//
// Note for reviewers: upstream's own manual test uses an invalid `<c>` tag
// (device_test.go:267, skipped test) — proof the DSL had no regression
// coverage. This file plus chain_test.go is that coverage.
package transportwg

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Hard limits (our hardening beyond upstream; generous vs. real profiles —
// Nova's biggest static blob is ~1252 bytes).
const (
	maxChainElems   = 16    // elements per chain
	maxChainElemLen = 4096  // bytes per fixed-length element (b/r/rc/rd/dz)
	maxChainSpecLen = 16384 // raw spec length
)

// ElemKind enumerates the upstream builder tags.
type ElemKind string

const (
	ElemBytes     ElemKind = "b"  // static hex bytes
	ElemTimestamp ElemKind = "t"  // 4-byte unix timestamp (no arg)
	ElemRand      ElemKind = "r"  // N random bytes
	ElemRandChar  ElemKind = "rc" // N random letters
	ElemRandDigit ElemKind = "rd" // N random digits
	ElemData      ElemKind = "d"  // copy of payload (no arg)
	ElemDataStr   ElemKind = "ds" // base64 of payload (no arg)
	ElemDataSize  ElemKind = "dz" // N-byte size marker
)

// ChainElem is one validated element of an obfuscation chain.
type ChainElem struct {
	Kind  ElemKind
	Bytes []byte // ElemBytes payload (decoded)
	Count int    // element length for r/rc/rd/dz
}

// ParseChain parses a full chain spec with the HARD grammar described above.
// It returns the structured elements so callers can re-render canonically.
func ParseChain(spec string) ([]ChainElem, error) {
	if len(spec) == 0 {
		return nil, fmt.Errorf("transportwg: empty chain spec")
	}
	if len(spec) > maxChainSpecLen {
		return nil, fmt.Errorf("transportwg: chain spec longer than %d bytes", maxChainSpecLen)
	}
	var (
		elems []ChainElem
		pos   int
	)
	for pos < len(spec) {
		start := strings.IndexByte(spec[pos:], '<')
		if start == -1 {
			tail := spec[pos:]
			if strings.TrimSpace(tail) != "" {
				return nil, fmt.Errorf("transportwg: text outside tags %q at offset %d", tail, pos)
			}
			break
		}
		if strings.TrimSpace(spec[pos:pos+start]) != "" {
			return nil, fmt.Errorf("transportwg: text outside tags %q before offset %d", spec[pos:pos+start], pos+start)
		}
		relEnd := strings.IndexByte(spec[pos+start:], '>')
		if relEnd == -1 {
			return nil, fmt.Errorf("transportwg: unclosed tag at offset %d", pos+start)
		}
		end := pos + start + relEnd

		fields := strings.Fields(spec[pos+start+1 : end])
		if len(fields) == 0 {
			return nil, fmt.Errorf("transportwg: empty tag <> at offset %d", pos+start)
		}
		key := ElemKind(fields[0])
		arg := ""
		hasArg := len(fields) > 1
		if hasArg {
			arg = fields[1]
		}
		if len(fields) > 2 {
			return nil, fmt.Errorf("transportwg: tag <%s> has more than one argument", key)
		}
		builder, ok := kindArity(key)
		if !ok {
			return nil, fmt.Errorf("transportwg: unknown tag <%s>", key)
		}
		if !builder && hasArg {
			return nil, fmt.Errorf("transportwg: tag <%s> takes no argument", key)
		}
		if builder && !hasArg {
			return nil, fmt.Errorf("transportwg: tag <%s> requires an argument", key)
		}

		el := ChainElem{Kind: key}
		switch key {
		case ElemBytes:
			b, err := parseHexBlob(arg)
			if err != nil {
				return nil, fmt.Errorf("transportwg: tag <b>: %w", err)
			}
			el.Bytes = b
		case ElemRand, ElemRandChar, ElemRandDigit, ElemDataSize:
			n, err := strconv.Atoi(arg)
			if err != nil {
				return nil, fmt.Errorf("transportwg: tag <%s>: bad count %q", key, arg)
			}
			if n < 0 || n > maxChainElemLen {
				return nil, fmt.Errorf("transportwg: tag <%s>: count %d out of [0,%d]", key, n, maxChainElemLen)
			}
			el.Count = n
		}
		elems = append(elems, el)
		pos = end + 1
	}
	if len(elems) == 0 {
		return nil, fmt.Errorf("transportwg: chain spec contains no tags")
	}
	if len(elems) > maxChainElems {
		return nil, fmt.Errorf("transportwg: chain has %d elements, max %d", len(elems), maxChainElems)
	}
	return elems, nil
}

// kindArity reports whether the tag requires an argument and whether it exists.
func kindArity(k ElemKind) (needsArg bool, known bool) {
	switch k {
	case ElemBytes, ElemRand, ElemRandChar, ElemRandDigit, ElemDataSize:
		return true, true
	case ElemTimestamp, ElemData, ElemDataStr:
		return false, true
	default:
		return false, false
	}
}

// ValidateChainSpec validates without materializing elements.
func ValidateChainSpec(spec string) error {
	_, err := ParseChain(spec)
	return err
}

// RenderChain renders elements in canonical adjacent-tag form
// ("<b 0x..><r 10>") — deterministic storage representation.
func RenderChain(elems []ChainElem) string {
	var sb strings.Builder
	for _, el := range elems {
		switch el.Kind {
		case ElemBytes:
			fmt.Fprintf(&sb, "<%s 0x%s>", el.Kind, hex.EncodeToString(el.Bytes))
		case ElemTimestamp, ElemData, ElemDataStr:
			fmt.Fprintf(&sb, "<%s>", el.Kind)
		default:
			fmt.Fprintf(&sb, "<%s %d>", el.Kind, el.Count)
		}
	}
	return sb.String()
}

// parseHexBlob accepts an optional 0x prefix and requires even-length hex
// (upstream newBytesObf semantics, obf_bytes.go).
func parseHexBlob(arg string) ([]byte, error) {
	v := strings.TrimPrefix(arg, "0x")
	if v == "" {
		return nil, fmt.Errorf("empty argument")
	}
	if len(v)%2 != 0 {
		return nil, fmt.Errorf("odd amount of symbols")
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}
