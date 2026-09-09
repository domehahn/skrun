package runtime

import (
	"github.com/domehahn/skrun/internal/policy"
	"os"
	"testing"
)

func p() policy.Policy {
	return policy.Policy{SchemaVersion: "1.0.0", ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", AllowedCommands: []string{"echo"}, TimeoutSeconds: 5, MaxOutputBytes: 8}
}
func TestDeniedCommand(t *testing.T) {
	pp := p()
	pp.AllowedCommands = []string{"false"}
	rc, err := Execute(Request{Policy: pp, Workspace: t.TempDir(), ArtifactDir: t.TempDir(), Command: "echo", Args: []string{"x"}})
	if err == nil || len(rc.DeniedActions) == 0 {
		t.Fatalf("expected denial rc=%+v err=%v", rc, err)
	}
}
func TestDevExecutionAndOutputCap(t *testing.T) {
	if _, err := os.Stat("/bin/echo"); err != nil {
		t.Skip(err)
	}
	rc, err := Execute(Request{Policy: p(), Workspace: t.TempDir(), ArtifactDir: t.TempDir(), Command: "echo", Args: []string{"0123456789012345"}})
	if err != nil {
		t.Fatal(err)
	}
	if !rc.OutputTruncated {
		t.Fatalf("expected truncation %+v", rc)
	}
	if len(rc.Stdout) > 8 {
		t.Fatal("stdout exceeded cap")
	}
}
