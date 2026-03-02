package lint

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateTargetArgs(t *testing.T) {
	absPath := t.TempDir()

	tests := []struct {
		name    string
		targets []string
		wantErr bool
	}{
		{
			name:    "valid relative paths",
			targets: []string{"internal/lint/tsc.go", "pkg/service.py"},
			wantErr: false,
		},
		{
			name:    "valid package patterns",
			targets: []string{"./...", "github.com/lerianstudio/mithril/internal/lint"},
			wantErr: false,
		},
		{
			name:    "rejects dash prefix",
			targets: []string{"--fix"},
			wantErr: true,
		},
		{
			name:    "rejects traversal",
			targets: []string{"../escape.py"},
			wantErr: true,
		},
		{
			name:    "rejects absolute path",
			targets: []string{absPath},
			wantErr: true,
		},
		{
			name:    "rejects empty target",
			targets: []string{"   "},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTargetArgs(tt.targets)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateTargetArgs_PathLikeTempDirIsAbsolute(t *testing.T) {
	err := validateTargetArgs([]string{os.TempDir()})
	require.Error(t, err)
}
