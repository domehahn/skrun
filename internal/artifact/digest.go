package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DigestDirectory computes a deterministic digest over relative file paths and bytes.
// Symlinks and non-regular files are rejected so the digest cannot hide traversal or device semantics.
func DigestDirectory(root string) (string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink rejected: %s", path)
		}
		if d.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular file rejected: %s", path)
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "../") || rel == ".." {
			return fmt.Errorf("path escaped artifact root: %s", rel)
		}
		files = append(files, rel)
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, rel := range files {
		_, _ = io.WriteString(h, "path\x00"+rel+"\x00")
		f, err := os.Open(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return "", err
		}
		if _, err := io.Copy(h, f); err != nil {
			_ = f.Close()
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		_, _ = io.WriteString(h, "\x00end\x00")
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func ValidateSHA256(v string) error {
	if !strings.HasPrefix(v, "sha256:") {
		return fmt.Errorf("digest must use sha256:<hex>")
	}
	raw := strings.TrimPrefix(v, "sha256:")
	if len(raw) != 64 {
		return fmt.Errorf("sha256 digest must contain 64 hex characters")
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return fmt.Errorf("invalid sha256 digest: %w", err)
	}
	return nil
}
