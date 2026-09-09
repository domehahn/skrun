//go:build darwin

package runtime

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

type seatbeltBackend struct {
	path string
}

func (s seatbeltBackend) Name() string { return "darwin-seatbelt" }
func (s seatbeltBackend) Secure() bool { return true }

func secureBackend() (Backend, error) {
	p, err := exec.LookPath("sandbox-exec")
	if err != nil {
		p = "/usr/bin/sandbox-exec"
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("macOS production mode requires sandbox-exec: %w", err)
		}
	}
	return seatbeltBackend{path: p}, nil
}

func (s seatbeltBackend) Run(ctx context.Context, req Request, stdout, stderr io.Writer) error {
	artifact, err := cleanAbs(req.ArtifactDir)
	if err != nil {
		return err
	}
	workspace, err := cleanAbs(req.Workspace)
	if err != nil {
		return err
	}
	cmdAbs, err := cleanAbs(req.Command)
	if err != nil {
		return err
	}

	var sb strings.Builder
	sb.WriteString("(version 1)\n(deny default)\n")
	sb.WriteString("(allow process-fork)\n")
	sb.WriteString(fmt.Sprintf("(allow process-exec (literal %q))\n", cmdAbs))
	sb.WriteString("(allow sysctl-read)\n")

	// Allow reading system trees, artifact dir, and workspace
	for _, sysPath := range []string{"/usr", "/bin", "/sbin", "/lib", "/System", "/Library", "/private/var", "/tmp"} {
		if _, err := os.Stat(sysPath); err == nil {
			sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", sysPath))
		}
	}
	sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", artifact))
	sb.WriteString(fmt.Sprintf("(allow file-read* (subpath %q))\n", workspace))

	if req.Policy.AllowWorkspaceWrite {
		sb.WriteString(fmt.Sprintf("(allow file-write* (subpath %q))\n", workspace))
	}
	// Always allow writing to temporary directory
	sb.WriteString("(allow file-write* (subpath \"/private/tmp\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/tmp\"))\n")

	if req.Policy.AllowNetwork {
		sb.WriteString("(allow network*)\n")
	} else {
		sb.WriteString("(deny network*)\n")
	}

	profileStr := sb.String()

	args := []string{"-p", profileStr, cmdAbs}
	args = append(args, req.Args...)

	cmd := exec.CommandContext(ctx, s.path, args...)
	cmd.Dir = workspace
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = filteredEnv(req.Policy)

	return cmd.Run()
}
