package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/domehahn/skrun/internal/artifact"
	"github.com/domehahn/skrun/internal/policy"
	"github.com/domehahn/skrun/internal/receipt"
	run "github.com/domehahn/skrun/internal/runtime"
)

var Version = "dev"

func main() {
	if err := runCLI(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
func runCLI(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "version":
		fmt.Println(Version)
		return nil
	case "hash":
		return hashCmd(args[1:])
	case "policy":
		return policyCmd(args[1:])
	case "receipt":
		return receiptCmd(args[1:])
	case "exec":
		return execCmd(args[1:])
	case "doctor":
		return doctorCmd(args[1:])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}
func usage() error {
	fmt.Println("skrun - policy-bound agent skill runtime\n\ncommands: version, hash, policy validate, receipt verify, exec, doctor")
	return nil
}
func hashCmd(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ContinueOnError)
	dir := fs.String("artifact-dir", "", "artifact directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return errors.New("--artifact-dir is required")
	}
	d, err := artifact.DigestDirectory(*dir)
	if err != nil {
		return err
	}
	fmt.Println(d)
	return nil
}
func policyCmd(args []string) error {
	if len(args) == 0 || args[0] != "validate" {
		return errors.New("usage: skrun policy validate --policy <file>")
	}
	fs := flag.NewFlagSet("policy validate", flag.ContinueOnError)
	p := fs.String("policy", "", "runtime policy or skgate decision JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *p == "" {
		return errors.New("--policy is required")
	}
	pol, err := policy.Load(*p)
	if err != nil {
		return err
	}
	fmt.Printf("runtime policy valid for %s\n", pol.ArtifactDigest)
	return nil
}
func receiptCmd(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return errors.New("usage: skrun receipt verify --receipt <file> --key <hex_pubkey>")
	}
	fs := flag.NewFlagSet("receipt verify", flag.ContinueOnError)
	rcPath := fs.String("receipt", "", "receipt file to verify")
	pubKeyHex := fs.String("key", "", "Ed25519 public key in hex format")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *rcPath == "" || *pubKeyHex == "" {
		return errors.New("--receipt and --key are required")
	}
	b, err := os.ReadFile(*rcPath)
	if err != nil {
		return err
	}
	var rc receipt.Receipt
	if err := json.Unmarshal(b, &rc); err != nil {
		return fmt.Errorf("failed to parse receipt JSON: %w", err)
	}
	pubBytes, err := hex.DecodeString(*pubKeyHex)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key hex string")
	}
	if err := rc.Verify(ed25519.PublicKey(pubBytes)); err != nil {
		return fmt.Errorf("receipt verification failed: %w", err)
	}
	fmt.Printf("receipt signature valid: execution_id=%s\n", rc.ExecutionID)
	return nil
}
func execCmd(args []string) error {
	split := -1
	for i, a := range args {
		if a == "--" {
			split = i
			break
		}
	}
	if split < 0 || split == len(args)-1 {
		return errors.New("usage: skrun exec [flags] -- <command> [args...]")
	}
	flagArgs, cmdArgs := args[:split], args[split+1:]
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	pp := fs.String("policy", "", "runtime policy or skgate decision JSON")
	art := fs.String("artifact-dir", "", "artifact directory")
	workspace := fs.String("workspace", ".", "workspace directory")
	receiptPath := fs.String("receipt", "runtime-receipt.json", "receipt output")
	signKeyHex := fs.String("sign-key", "", "hex-encoded Ed25519 private key for signing receipt")
	prod := fs.Bool("production", false, "require production-grade isolation")
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if *pp == "" || *art == "" {
		return errors.New("--policy and --artifact-dir are required")
	}
	pol, err := policy.Load(*pp)
	if err != nil {
		return err
	}
	got, err := artifact.DigestDirectory(*art)
	if err != nil {
		return fmt.Errorf("artifact integrity: %w", err)
	}
	if got != pol.ArtifactDigest {
		return fmt.Errorf("artifact digest mismatch: policy=%s actual=%s", pol.ArtifactDigest, got)
	}

	var privKey ed25519.PrivateKey
	if *signKeyHex != "" {
		keyBytes, err := hex.DecodeString(*signKeyHex)
		if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
			return errors.New("invalid --sign-key: must be hex-encoded Ed25519 private key")
		}
		privKey = ed25519.PrivateKey(keyBytes)
	}

	rc, runErr := run.Execute(run.Request{
		Policy:      pol,
		ArtifactDir: *art,
		Workspace:   *workspace,
		Command:     cmdArgs[0],
		Args:        cmdArgs[1:],
		Production:  *prod,
		SignKey:     privKey,
	})
	b, _ := json.MarshalIndent(rc, "", "  ")
	b = append(b, '\n')
	if err := os.WriteFile(*receiptPath, b, 0o600); err != nil {
		return err
	}
	fmt.Printf("receipt: %s\n", *receiptPath)
	if runErr != nil {
		return runErr
	}
	return nil
}
func doctorCmd(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	prod := fs.Bool("production", false, "check production backend")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Printf("os=%s arch=%s\n", runtime.GOOS, runtime.GOARCH)
	if *prod {
		switch runtime.GOOS {
		case "linux":
			p, err := exec.LookPath("bwrap")
			if err != nil {
				return fmt.Errorf("bubblewrap required: %w", err)
			}
			abs, _ := filepath.Abs(p)
			fmt.Println("bubblewrap=", abs)
		case "darwin":
			p, err := exec.LookPath("sandbox-exec")
			if err != nil {
				p = "/usr/bin/sandbox-exec"
				if _, err := os.Stat(p); err != nil {
					return fmt.Errorf("sandbox-exec required on macOS: %w", err)
				}
			}
			fmt.Println("sandbox-exec=", p)
		case "windows":
			fmt.Println("windows jobobject isolation=AVAILABLE")
		default:
			return fmt.Errorf("production backend unavailable on %s", runtime.GOOS)
		}
	}
	fmt.Println("doctor: PASS")
	return nil
}
