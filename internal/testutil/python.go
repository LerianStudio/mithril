package testutil

import (
	"os/exec"
	"testing"
)

// RequirePython3 skips the test if python3 is not available on PATH.
// Use in tests that spawn python3 subprocesses so suites remain hermetic
// on systems without a Python interpreter installed.
func RequirePython3(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available on PATH; skipping test that requires a Python interpreter")
	}
}
