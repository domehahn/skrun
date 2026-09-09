//go:build !linux && !darwin && !windows

package runtime

import "fmt"

func secureBackend() (Backend, error) {
	return nil, fmt.Errorf("production isolation backend is not implemented on this platform; refusing insecure fallback")
}
