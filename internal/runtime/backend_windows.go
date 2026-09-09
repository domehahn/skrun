//go:build windows

package runtime

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

type windowsSandboxBackend struct{}

func (w windowsSandboxBackend) Name() string { return "windows-dev" }
func (w windowsSandboxBackend) Secure() bool { return false }

func secureBackend() (Backend, error) {
	return nil, fmt.Errorf("windows production AppContainer sandbox is not yet fully implemented; refusing insecure fallback")
}

func (w windowsSandboxBackend) Run(ctx context.Context, req Request, stdout, stderr io.Writer) error {
	cmdAbs, err := cleanAbs(req.Command)
	if err != nil {
		return err
	}

	cmd := exec.CommandContext(ctx, cmdAbs, req.Args...)
	cmd.Dir = req.Workspace
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = filteredEnv(req.Policy)

	return cmd.Run()
}
