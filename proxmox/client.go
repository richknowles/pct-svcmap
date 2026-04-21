package proxmox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// ExecConfig holds timeout and verbosity settings for all command executions.
type ExecConfig struct {
	TimeoutSecs int
	Verbose     bool
}

// RunCommand executes a command with a per-call context timeout.
// Every pvesh, pct, and qm invocation flows through this function.
// Returns stdout bytes; stderr is captured for error messages when verbose.
func RunCommand(cfg ExecConfig, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(cfg.TimeoutSecs)*time.Second,
	)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("timeout after %ds: %s %v", cfg.TimeoutSecs, name, args)
		}
		if cfg.Verbose {
			return nil, fmt.Errorf("%s %v: %w (stderr: %s)", name, args, err, stderr.String())
		}
		return nil, fmt.Errorf("%s %v: %w", name, args, err)
	}
	return stdout.Bytes(), nil
}
