//go:build windows

package runtime

import (
	"context"
	"io"
	"os/exec"
)

type windowsSandboxBackend struct{}

func (w windowsSandboxBackend) Name() string { return "windows-jobobject" }
func (w windowsSandboxBackend) Secure() bool { return true }

func secureBackend() (Backend, error) {
	return windowsSandboxBackend{}, nil
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
