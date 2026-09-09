package runtime

import (
	"os"
	"testing"

	"github.com/domehahn/skrun/internal/artifact"
	"github.com/domehahn/skrun/internal/policy"
)

func p(artDir string) policy.Policy {
	d, _ := artifact.DigestDirectory(artDir)
	return policy.Policy{SchemaVersion: "1.0.0", ArtifactDigest: d, AllowedCommands: []string{"echo"}, TimeoutSeconds: 5, MaxOutputBytes: 8}
}
func TestDeniedCommand(t *testing.T) {
	artDir := t.TempDir()
	pp := p(artDir)
	pp.AllowedCommands = []string{"false"}
	rc, err := Execute(Request{Policy: pp, Workspace: t.TempDir(), ArtifactDir: artDir, Command: "echo", Args: []string{"x"}})
	if err == nil || len(rc.DeniedActions) == 0 {
		t.Fatalf("expected denial rc=%+v err=%v", rc, err)
	}
}
func TestDevExecutionAndOutputCap(t *testing.T) {
	if _, err := os.Stat("/bin/echo"); err != nil {
		t.Skip(err)
	}
	artDir := t.TempDir()
	rc, err := Execute(Request{Policy: p(artDir), Workspace: t.TempDir(), ArtifactDir: artDir, Command: "echo", Args: []string{"0123456789012345"}})
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
