//go:build linux

package runtime

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

type bubblewrapBackend struct{ path string }

func (b bubblewrapBackend) Name() string { return "linux-bubblewrap" }
func (b bubblewrapBackend) Secure() bool { return true }
func secureBackend() (Backend, error) {
	p, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("production mode requires bubblewrap: %w", err)
	}
	return bubblewrapBackend{path: p}, nil
}
func (b bubblewrapBackend) Run(ctx context.Context, req Request, stdout, stderr io.Writer) error {
	artifact, err := cleanAbs(req.ArtifactDir)
	if err != nil {
		return err
	}
	workspace, err := cleanAbs(req.Workspace)
	if err != nil {
		return err
	}
	args := []string{"--die-with-parent", "--new-session", "--unshare-all", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--dir", "/workspace", "--dir", "/artifact"}
	for _, p := range []string{"/usr", "/bin", "/lib", "/lib64", "/usr/local"} {
		if _, err := os.Stat(p); err == nil {
			args = append(args, "--ro-bind", p, p)
		}
	}
	args = append(args, "--ro-bind", artifact, "/artifact")
	if req.Policy.AllowWorkspaceWrite {
		args = append(args, "--bind", workspace, "/workspace")
	} else {
		args = append(args, "--ro-bind", workspace, "/workspace")
	}
	if req.Policy.AllowNetwork {
		args = append(args, "--share-net")
	}
	if limits := req.Policy.ResourceLimits; limits != nil {
		if limits.MaxMemoryMB > 0 {
			bytes := int64(limits.MaxMemoryMB) * 1024 * 1024
			args = append(args, "--rlimit-as", fmt.Sprintf("%d", bytes))
		}
		if limits.MaxPIDs > 0 {
			args = append(args, "--rlimit-nproc", fmt.Sprintf("%d", limits.MaxPIDs))
		}
		if limits.MaxFDs > 0 {
			args = append(args, "--rlimit-nofile", fmt.Sprintf("%d", limits.MaxFDs))
		}
	}
	args = append(args, "--chdir", "/workspace", "--clearenv", "--setenv", "PATH", os.Getenv("PATH"), "--setenv", "HOME", "/tmp", "--setenv", "LANG", "C.UTF-8")
	for _, name := range req.Policy.AllowedSecrets {
		if v, ok := os.LookupEnv("SKRUN_SECRET_" + name); ok {
			args = append(args, "--setenv", name, v)
		}
	}
	// Command identity was resolved before entering the sandbox and the containing system trees are read-only.
	if !filepath.IsAbs(req.Command) {
		return fmt.Errorf("resolved command must be absolute")
	}
	args = append(args, "--", req.Command)
	args = append(args, req.Args...)
	cmd := exec.CommandContext(ctx, b.path, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	return cmd.Run()
}
