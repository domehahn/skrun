package artifact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDigestDeterministic(t *testing.T) {
	d := t.TempDir()
	_ = os.WriteFile(filepath.Join(d, "b"), []byte("2"), 0o600)
	_ = os.WriteFile(filepath.Join(d, "a"), []byte("1"), 0o600)
	x, err := DigestDirectory(d)
	if err != nil {
		t.Fatal(err)
	}
	y, err := DigestDirectory(d)
	if err != nil || x != y {
		t.Fatalf("%s %s %v", x, y, err)
	}
}
func TestDigestRejectsSymlink(t *testing.T) {
	d := t.TempDir()
	target := filepath.Join(d, "a")
	_ = os.WriteFile(target, []byte("x"), 0o600)
	if err := os.Symlink(target, filepath.Join(d, "link")); err != nil {
		t.Skip(err)
	}
	if _, err := DigestDirectory(d); err == nil {
		t.Fatal("expected symlink rejection")
	}
}
