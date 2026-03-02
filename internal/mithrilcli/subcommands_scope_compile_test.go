package mithrilcli

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunScopeDetector_InvalidModeCombinations(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "staged and unstaged conflict",
			args:    []string{"--staged", "--unstaged"},
			wantErr: "mutually exclusive",
		},
		{
			name:    "all-modified and staged conflict",
			args:    []string{"--all-modified", "--staged"},
			wantErr: "mutually exclusive",
		},
		{
			name:    "files with staged conflict",
			args:    []string{"--files=*.go", "--staged"},
			wantErr: "--files/--files-from cannot be used",
		},
		{
			name:    "staged with refs conflict",
			args:    []string{"--staged", "--base=main"},
			wantErr: "--staged cannot be used with --base/--head",
		},
		{
			name:    "all-modified with refs conflict",
			args:    []string{"--all-modified", "--head=HEAD"},
			wantErr: "--all-modified cannot be used with --base/--head",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := runScopeDetector(tc.args, &bytes.Buffer{}, &bytes.Buffer{})
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
