package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeSnapshotTOCTOUProtection(t *testing.T) {
	sourceDir := t.TempDir()
	file1 := filepath.Join(sourceDir, "script.sh")
	if err := os.WriteFile(file1, []byte("#!/bin/sh\necho safe"), 0o600); err != nil {
		t.Fatalf("failed writing file: %v", err)
	}

	snapDir, digest1, cleanup, err := MaterializeSnapshot(sourceDir)
	if err != nil {
		t.Fatalf("MaterializeSnapshot failed: %v", err)
	}
	defer cleanup()

	// Mutate host source directory file mid-execution
	if err := os.WriteFile(file1, []byte("#!/bin/sh\necho MALICIOUS_MUTATION"), 0o600); err != nil {
		t.Fatalf("failed mutating file: %v", err)
	}

	// Verify snapshot file content remains unchanged
	snapFile := filepath.Join(snapDir, "script.sh")
	snapContent, err := os.ReadFile(snapFile)
	if err != nil {
		t.Fatalf("failed reading snapshot file: %v", err)
	}

	if string(snapContent) != "#!/bin/sh\necho safe" {
		t.Fatalf("TOCTOU mutation compromised snapshot! got %q", string(snapContent))
	}

	snapDigest, err := DigestDirectory(snapDir)
	if err != nil {
		t.Fatalf("failed digesting snapshot: %v", err)
	}

	if snapDigest != digest1 {
		t.Fatalf("snapshot digest changed after host directory mutation! original=%s snap=%s", digest1, snapDigest)
	}
}
