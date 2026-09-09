package runtime

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/domehahn/skrun/internal/artifact"
	"github.com/domehahn/skrun/internal/policy"
)

func defaultTestPolicy() policy.Policy {
	return policy.Policy{
		SchemaVersion:   "1.0.0",
		ArtifactDigest:  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AllowedCommands: []string{"echo", "sh", "bash"},
		TimeoutSeconds:  5,
		MaxOutputBytes:  1024,
	}
}

func TestBreakout_SymlinkRejection(t *testing.T) {
	dir := t.TempDir()
	targetFile := filepath.Join(dir, "real_file.txt")
	_ = os.WriteFile(targetFile, []byte("hello"), 0o600)
	symlinkPath := filepath.Join(dir, "symlink_file.txt")

	if err := os.Symlink(targetFile, symlinkPath); err != nil {
		t.Skip("symlinks not supported on this platform/user environment")
	}

	_, err := artifact.DigestDirectory(dir)
	if err == nil {
		t.Fatal("expected symlink in artifact directory to be rejected")
	}
}

func TestBreakout_PathTraversalCommandDenial(t *testing.T) {
	pol := defaultTestPolicy()
	pol.AllowedCommands = []string{"echo"}

	// Attempt path traversal command injection like "../../bin/sh"
	rc, err := Execute(Request{
		Policy:      pol,
		Workspace:   t.TempDir(),
		ArtifactDir: t.TempDir(),
		Command:     "../../bin/sh",
		Args:        []string{"-c", "id"},
	})

	if err == nil {
		t.Fatal("expected execution failure for path traversal command")
	}
	if len(rc.DeniedActions) == 0 {
		t.Fatal("expected denied actions in receipt for path traversal command attempt")
	}
}

func TestBreakout_AmbientSecretIsolation(t *testing.T) {
	pol := defaultTestPolicy()
	pol.AllowedSecrets = []string{"MY_ALLOWED_SECRET"}

	os.Setenv("SENSITIVE_API_KEY", "super-secret-12345")
	os.Setenv("SKRUN_SECRET_MY_ALLOWED_SECRET", "allowed-val-999")
	defer os.Unsetenv("SENSITIVE_API_KEY")
	defer os.Unsetenv("SKRUN_SECRET_MY_ALLOWED_SECRET")

	env := filteredEnv(pol)
	envMap := make(map[string]string)
	for _, e := range env {
		kv := stringsSplit2(e, "=")
		if len(kv) == 2 {
			envMap[kv[0]] = kv[1]
		}
	}

	if _, found := envMap["SENSITIVE_API_KEY"]; found {
		t.Fatal("ambient SENSITIVE_API_KEY leaked into sandbox environment!")
	}

	if val, found := envMap["MY_ALLOWED_SECRET"]; !found || val != "allowed-val-999" {
		t.Fatalf("allowed secret missing or incorrect: got %v", val)
	}
}

func TestBreakout_SignedReceiptVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pol := defaultTestPolicy()
	pol.AllowedCommands = []string{"echo"}

	rc, err := Execute(Request{
		Policy:      pol,
		Workspace:   t.TempDir(),
		ArtifactDir: t.TempDir(),
		Command:     "echo",
		Args:        []string{"hello"},
		SignKey:     priv,
	})

	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	if err := rc.Verify(pub); err != nil {
		t.Fatalf("receipt verification failed: %v", err)
	}

	// Modify receipt output to test tampering detection
	tampered := rc
	tampered.Stdout = "hacked output"
	if err := tampered.Verify(pub); err == nil {
		t.Fatal("expected verification error on tampered receipt")
	}
}

func TestBreakout_TimeoutEnforcement(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}

	pol := defaultTestPolicy()
	pol.AllowedCommands = []string{"sleep"}
	pol.TimeoutSeconds = 1

	start := time.Now()
	rc, err := Execute(Request{
		Policy:      pol,
		Workspace:   t.TempDir(),
		ArtifactDir: t.TempDir(),
		Command:     "sleep",
		Args:        []string{"10"},
	})

	elapsed := time.Since(start)
	if elapsed > 4*time.Second {
		t.Fatalf("timeout enforcement took too long: %v", elapsed)
	}

	if !rc.TimedOut {
		t.Fatalf("expected receipt to mark TimedOut=true, got rc=%+v err=%v", rc, err)
	}
}

func stringsSplit2(s, sep string) []string {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}
