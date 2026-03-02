package mithrilcli

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestValidateRunAllFlags(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		wantErr         bool
		wantCompare     bool
		wantBase        string
		wantHead        string
		wantErrContains string
	}{
		{
			name:        "defaults to compare mode",
			args:        nil,
			wantCompare: true,
			wantBase:    "main",
			wantHead:    "HEAD",
		},
		{
			name:        "base implies compare",
			args:        []string{"--base=develop"},
			wantCompare: true,
			wantBase:    "develop",
			wantHead:    "HEAD",
		},
		{
			name:        "staged mode clears refs",
			args:        []string{"--staged"},
			wantCompare: false,
			wantBase:    "",
			wantHead:    "",
		},
		{
			name:        "all-modified mode clears refs",
			args:        []string{"--all-modified"},
			wantCompare: false,
			wantBase:    "",
			wantHead:    "",
		},
		{
			name:            "rejects mutually exclusive modes",
			args:            []string{"--staged", "--unstaged"},
			wantErr:         true,
			wantErrContains: "choose only one mode",
		},
		{
			name:            "rejects files with refs",
			args:            []string{"--files=a.go", "--base=main"},
			wantErr:         true,
			wantErrContains: "choose only one mode",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("run-all", flag.ContinueOnError)
			var stderr bytes.Buffer
			fs.SetOutput(&stderr)

			cfg := &runAllConfig{}
			fs.StringVar(&cfg.baseRef, "base", "main", "")
			fs.StringVar(&cfg.headRef, "head", "HEAD", "")
			fs.BoolVar(&cfg.compare, "compare", false, "")
			fs.BoolVar(&cfg.staged, "staged", false, "")
			fs.StringVar(&cfg.files, "files", "", "")
			fs.StringVar(&cfg.filesFrom, "files-from", "", "")
			fs.BoolVar(&cfg.unstaged, "unstaged", false, "")
			fs.BoolVar(&cfg.allMod, "all-modified", false, "")

			if err := fs.Parse(tc.args); err != nil {
				t.Fatalf("parse failed: %v", err)
			}

			err := validateRunAllFlags(fs, cfg, &stderr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				if tc.wantErrContains != "" && !strings.Contains(stderr.String(), tc.wantErrContains) {
					t.Fatalf("stderr %q does not contain %q", stderr.String(), tc.wantErrContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.compare != tc.wantCompare {
				t.Fatalf("compare=%v want %v", cfg.compare, tc.wantCompare)
			}
			if cfg.baseRef != tc.wantBase {
				t.Fatalf("baseRef=%q want %q", cfg.baseRef, tc.wantBase)
			}
			if cfg.headRef != tc.wantHead {
				t.Fatalf("headRef=%q want %q", cfg.headRef, tc.wantHead)
			}
		})
	}
}
