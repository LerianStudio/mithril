package procenv

import (
	"strings"
	"testing"
)

func TestBuild_UsesAllowlist(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("HOME", "/tmp/home")
	t.Setenv("SECRET_TOKEN", "dont-leak")

	env := Build()
	joined := strings.Join(env, "\n")

	if !strings.Contains(joined, "PATH=/usr/bin") {
		t.Fatalf("expected PATH in env, got: %v", env)
	}
	if !strings.Contains(joined, "HOME=/tmp/home") {
		t.Fatalf("expected HOME in env, got: %v", env)
	}
	if strings.Contains(joined, "SECRET_TOKEN=dont-leak") {
		t.Fatalf("unexpected secret env variable leaked: %v", env)
	}
	if !strings.Contains(joined, "LC_ALL=C") {
		t.Fatalf("expected LC_ALL to be forced to C, got: %v", env)
	}
}

