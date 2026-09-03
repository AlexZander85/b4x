package ppe

import (
	"fmt"
	"strings"
)

func splitRuleLine(line string) ([]string, error) {
	var out []string
	var current strings.Builder
	var quote rune
	escaped := false
	flush := func() {
		if current.Len() > 0 {
			out = append(out, current.String())
			current.Reset()
		}
	}
	for _, r := range strings.TrimSpace(line) {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
		case ' ', '\t', '\r', '\n':
			flush()
		default:
			current.WriteRune(r)
		}
	}
	if escaped || quote != 0 {
		return nil, fmt.Errorf("unterminated rule quoting: %q", line)
	}
	flush()
	return out, nil
}

func isOwnedJump(args []string, hook, chain, comment string) bool {
	if len(args) < 3 || args[0] != "-A" || args[1] != hook {
		return false
	}
	return hasArgPair(args, "--comment", comment) && hasArgPair(args, "-j", chain)
}

func hasArgPair(args []string, key, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == key && args[i+1] == value {
			return true
		}
	}
	return false
}

func cloneArgs(in []string) []string { return append([]string(nil), in...) }
