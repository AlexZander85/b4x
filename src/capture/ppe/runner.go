package ppe

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Runner interface {
	ReadFile(path string) ([]byte, error)
	Stat(path string) (os.FileInfo, error)
	LookPath(file string) (string, error)
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type OSRunner struct{}

func (OSRunner) ReadFile(path string) ([]byte, error)  { return os.ReadFile(path) }
func (OSRunner) Stat(path string) (os.FileInfo, error) { return os.Stat(path) }
func (OSRunner) LookPath(file string) (string, error)  { return exec.LookPath(file) }
func (OSRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err := cmd.Run()
	text := strings.TrimSpace(output.String())
	if err != nil {
		if text == "" {
			return "", fmt.Errorf("%s: %w", strings.Join(append([]string{name}, args...), " "), err)
		}
		return text, fmt.Errorf("%s: %w: %s", strings.Join(append([]string{name}, args...), " "), err, text)
	}
	return text, nil
}
