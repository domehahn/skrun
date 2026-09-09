package runtime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/domehahn/skrun/internal/broker"
	"github.com/domehahn/skrun/internal/policy"
	"github.com/domehahn/skrun/internal/receipt"
)

type Request struct {
	Policy                 policy.Policy
	ArtifactDir, Workspace string
	Command                string
	Args                   []string
	Production             bool
	CaptureOutput          bool
	SignKey                ed25519.PrivateKey
}
type Backend interface {
	Name() string
	Secure() bool
	Run(context.Context, Request, io.Writer, io.Writer) error
}

type limitedBuffer struct {
	buf       bytes.Buffer
	max       int64
	n         int64
	truncated bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.n += int64(len(p))
	remaining := l.max - int64(l.buf.Len())
	if remaining > 0 {
		n := int64(len(p))
		if n > remaining {
			n = remaining
		}
		_, _ = l.buf.Write(p[:n])
	}
	if l.n > l.max {
		l.truncated = true
	}
	return len(p), nil
}

func Execute(req Request) (rc receipt.Receipt, runErr error) {
	started := time.Now().UTC()
	rc = receipt.Receipt{SchemaVersion: receipt.SchemaVersion, ExecutionID: newID(), ArtifactDigest: req.Policy.ArtifactDigest, PolicyDigest: req.Policy.Digest(), StartedAt: started, Result: "FAILED", ExitCode: -1, DeniedActions: []receipt.DeniedAction{}}

	defer func() {
		if len(req.SignKey) > 0 {
			_ = rc.Sign(req.SignKey)
		}
	}()

	base := filepath.Base(req.Command)
	if !req.Policy.AllowsCommand(base) {
		rc.DeniedActions = append(rc.DeniedActions, receipt.DeniedAction{Type: "command", Value: base, Reason: "command is not allowed by runtime policy"})
		rc.Error = "command denied"
		rc.FinishedAt = time.Now().UTC()
		return rc, fmt.Errorf("command %q denied by policy", base)
	}

	// Interpose Egress and MCP Brokers
	egressBroker := broker.NewEgressBroker(req.Policy)
	if !req.Policy.AllowNetwork {
		rc.DeniedActions = append(rc.DeniedActions, receipt.DeniedAction{Type: "network", Value: "all", Reason: "network access is disabled by policy"})
	} else if len(req.Policy.AllowedEgress) > 0 {
		for _, e := range req.Policy.AllowedEgress {
			if ok, reason := egressBroker.AuthorizeEgress(e.Domain, e.Port); !ok {
				rc.DeniedActions = append(rc.DeniedActions, receipt.DeniedAction{Type: "egress", Value: e.Domain, Reason: reason})
			}
		}
	}

	mcpBroker := broker.NewMCPBroker(req.Policy)
	if req.Policy.MCPBroker != nil {
		for _, tool := range req.Policy.MCPBroker.AllowedTools {
			if ok, reason := mcpBroker.AuthorizeTool(tool); !ok {
				rc.DeniedActions = append(rc.DeniedActions, receipt.DeniedAction{Type: "mcp_tool", Value: tool, Reason: reason})
			}
		}
	}

	absCmd, err := exec.LookPath(req.Command)
	if err != nil {
		rc.Error = err.Error()
		rc.FinishedAt = time.Now().UTC()
		return rc, err
	}
	req.Command = absCmd
	backend, err := selectBackend(req.Production)
	if err != nil {
		rc.Error = err.Error()
		rc.FinishedAt = time.Now().UTC()
		return rc, err
	}
	rc.IsolationBackend = backend.Name()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(req.Policy.TimeoutSeconds)*time.Second)
	defer cancel()
	out := &limitedBuffer{max: req.Policy.MaxOutputBytes}
	errOut := &limitedBuffer{max: req.Policy.MaxOutputBytes}
	err = backend.Run(ctx, req, out, errOut)

	rawOut := out.buf.String()
	rawErr := errOut.buf.String()

	outSum := sha256.Sum256([]byte(rawOut))
	errSum := sha256.Sum256([]byte(rawErr))
	rc.StdoutDigest = "sha256:" + hex.EncodeToString(outSum[:])
	rc.StderrDigest = "sha256:" + hex.EncodeToString(errSum[:])

	if req.CaptureOutput || !req.Production {
		rc.Stdout = rawOut
		rc.Stderr = rawErr
	}

	rc.OutputTruncated = out.truncated || errOut.truncated
	rc.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
	rc.FinishedAt = time.Now().UTC()
	if err == nil {
		rc.Result = "SUCCESS"
		rc.ExitCode = 0
		return rc, nil
	}
	rc.Error = err.Error()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		rc.ExitCode = ee.ExitCode()
	} else if rc.TimedOut {
		rc.ExitCode = 124
	}
	return rc, err
}

func selectBackend(production bool) (Backend, error) {
	if production {
		b, err := secureBackend()
		if err != nil {
			return nil, err
		}
		if b == nil || !b.Secure() {
			return nil, fmt.Errorf("no production-grade isolation backend available on %s", runtime.GOOS)
		}
		return b, nil
	}
	return processBackend{}, nil
}

type processBackend struct{}

func (processBackend) Name() string { return "process-dev" }
func (processBackend) Secure() bool { return false }
func (processBackend) Run(ctx context.Context, req Request, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, req.Command, req.Args...)
	cmd.Dir = req.Workspace
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = filteredEnv(req.Policy)
	return cmd.Run()
}

func filteredEnv(p policy.Policy) []string {
	env := []string{"PATH=" + os.Getenv("PATH"), "HOME=/nonexistent", "LANG=C.UTF-8"}
	for _, name := range p.AllowedSecrets {
		if v, ok := os.LookupEnv("SKRUN_SECRET_" + name); ok {
			env = append(env, name+"="+v)
		}
	}
	return env
}
func newID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("exec-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
func cleanAbs(path string) (string, error) {
	a, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	a = filepath.Clean(a)
	if strings.TrimSpace(a) == "" {
		return "", fmt.Errorf("empty path")
	}
	return a, nil
}
