package ppe

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
)

type memoryIPTablesRunner struct {
	chains map[string][][]string
	hooks  map[string][][]string
}

func newMemoryIPTablesRunner() *memoryIPTablesRunner {
	return &memoryIPTablesRunner{
		chains: map[string][][]string{},
		hooks:  map[string][][]string{"PREROUTING": {}, "FORWARD": {}},
	}
}

func (m *memoryIPTablesRunner) ReadFile(string) ([]byte, error)      { return nil, os.ErrNotExist }
func (m *memoryIPTablesRunner) Stat(string) (os.FileInfo, error)     { return nil, os.ErrNotExist }
func (m *memoryIPTablesRunner) LookPath(file string) (string, error) { return file, nil }
func (m *memoryIPTablesRunner) Run(_ context.Context, _ string, args ...string) (string, error) {
	args = stripTablePrefix(args)
	if len(args) == 0 {
		return "", errors.New("missing command")
	}
	switch args[0] {
	case "-S":
		if len(args) == 2 {
			return m.renderChain(args[1])
		}
		return m.renderAll(), nil
	case "-N":
		if _, ok := m.chains[args[1]]; ok {
			return "", errors.New("chain already exists")
		}
		m.chains[args[1]] = nil
	case "-F":
		if _, ok := m.chains[args[1]]; !ok {
			return "", errors.New("chain does not exist")
		}
		m.chains[args[1]] = nil
	case "-X":
		if _, ok := m.chains[args[1]]; !ok {
			return "", errors.New("chain does not exist")
		}
		for _, rules := range m.hooks {
			for _, rule := range rules {
				if hasArgPair(rule, "-j", args[1]) {
					return "", errors.New("chain is referenced")
				}
			}
		}
		delete(m.chains, args[1])
	case "-A":
		return "", m.appendRule(args[1], args)
	case "-I":
		position, err := strconv.Atoi(args[2])
		if err != nil {
			return "", err
		}
		rule := append([]string{"-A", args[1]}, args[3:]...)
		return "", m.insertHook(args[1], position, rule)
	case "-D":
		return "", m.deleteRule(args[1], append([]string{"-A", args[1]}, args[2:]...))
	default:
		return "", errors.New("unsupported command")
	}
	return "", nil
}

func stripTablePrefix(args []string) []string {
	if len(args) > 0 && args[0] == "-w" {
		args = args[1:]
	}
	if len(args) >= 2 && args[0] == "-t" && args[1] == "mangle" {
		args = args[2:]
	}
	return args
}

func (m *memoryIPTablesRunner) renderAll() string {
	var lines []string
	for _, chain := range []string{ChainPre, ChainFwd} {
		if _, ok := m.chains[chain]; ok {
			lines = append(lines, "-N "+chain)
		}
	}
	for _, hook := range []string{"PREROUTING", "FORWARD"} {
		for _, rule := range m.hooks[hook] {
			lines = append(lines, strings.Join(rule, " "))
		}
	}
	for _, chain := range []string{ChainPre, ChainFwd} {
		for _, rule := range m.chains[chain] {
			lines = append(lines, strings.Join(rule, " "))
		}
	}
	return strings.Join(lines, "\n")
}

func (m *memoryIPTablesRunner) renderChain(chain string) (string, error) {
	if rules, ok := m.hooks[chain]; ok {
		var lines []string
		for _, rule := range rules {
			lines = append(lines, strings.Join(rule, " "))
		}
		return strings.Join(lines, "\n"), nil
	}
	if rules, ok := m.chains[chain]; ok {
		var lines []string
		for _, rule := range rules {
			lines = append(lines, strings.Join(rule, " "))
		}
		return strings.Join(lines, "\n"), nil
	}
	return "", errors.New("chain does not exist")
}

func (m *memoryIPTablesRunner) appendRule(chain string, rule []string) error {
	if _, ok := m.hooks[chain]; ok {
		m.hooks[chain] = append(m.hooks[chain], cloneArgs(rule))
		return nil
	}
	if _, ok := m.chains[chain]; !ok {
		return errors.New("chain does not exist")
	}
	m.chains[chain] = append(m.chains[chain], cloneArgs(rule))
	return nil
}

func (m *memoryIPTablesRunner) insertHook(hook string, position int, rule []string) error {
	rules, ok := m.hooks[hook]
	if !ok {
		return errors.New("chain does not exist")
	}
	if position < 1 {
		position = 1
	}
	if position > len(rules)+1 {
		position = len(rules) + 1
	}
	index := position - 1
	rules = append(rules, nil)
	copy(rules[index+1:], rules[index:])
	rules[index] = cloneArgs(rule)
	m.hooks[hook] = rules
	return nil
}

func (m *memoryIPTablesRunner) deleteRule(chain string, wanted []string) error {
	var rules [][]string
	var ok bool
	if rules, ok = m.hooks[chain]; !ok {
		if rules, ok = m.chains[chain]; !ok {
			return errors.New("chain does not exist")
		}
	}
	for i, rule := range rules {
		if strings.Join(rule, "\x00") == strings.Join(wanted, "\x00") {
			rules = append(rules[:i], rules[i+1:]...)
			if _, hook := m.hooks[chain]; hook {
				m.hooks[chain] = rules
			} else {
				m.chains[chain] = rules
			}
			return nil
		}
	}
	return errors.New("bad rule")
}
