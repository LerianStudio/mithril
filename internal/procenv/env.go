package procenv

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var defaultAllowlist = []string{
	"PATH",
	"HOME",
	"USER",
	"LOGNAME",
	"SHELL",
	"TERM",
	"TMPDIR",
	"TMP",
	"TEMP",
	"PWD",
	"TZ",
	"LANG",
	"LC_CTYPE",
	"LC_MESSAGES",
	"CI",
	"GITHUB_ACTIONS",
	"XDG_CACHE_HOME",
	"XDG_CONFIG_HOME",
	"XDG_DATA_HOME",
	"GOCACHE",
	"GOMODCACHE",
	"GOPATH",
	"GOROOT",
	"GOENV",
	"GOFLAGS",
	"GOPROXY",
	"GONOPROXY",
	"GONOSUMDB",
	"GOSUMDB",
	"GOPRIVATE",
	"CGO_ENABLED",
	"CC",
	"CXX",
	"PKG_CONFIG",
	"NODE_PATH",
	"NPM_CONFIG_CACHE",
	"NPM_CONFIG_PREFIX",
	"PNPM_HOME",
	"YARN_CACHE_FOLDER",
	"COREPACK_HOME",
	"VIRTUAL_ENV",
	"PIP_CACHE_DIR",
	"PIP_INDEX_URL",
	"PIP_EXTRA_INDEX_URL",
	"HTTP_PROXY",
	"HTTPS_PROXY",
	"NO_PROXY",
	"http_proxy",
	"https_proxy",
	"no_proxy",
	"SSL_CERT_FILE",
	"SSL_CERT_DIR",
}

// Build returns a sanitized subprocess environment using an allowlist.
// LC_ALL is always forced to C for stable tool output.
func Build(extraKeys ...string) []string {
	allowlist := make(map[string]struct{}, len(defaultAllowlist)+len(extraKeys))
	for _, key := range defaultAllowlist {
		allowlist[key] = struct{}{}
	}
	for _, key := range extraKeys {
		if key != "" {
			allowlist[key] = struct{}{}
		}
	}

	envMap := map[string]string{"LC_ALL": "C"}
	for key := range allowlist {
		if value, ok := os.LookupEnv(key); ok {
			if key == "PATH" {
				value = sanitizePATH(value)
				if value == "" {
					continue
				}
			}
			envMap[key] = value
		}
	}

	keys := make([]string, 0, len(envMap))
	for key := range envMap {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	env := make([]string, 0, len(keys))
	for _, key := range keys {
		env = append(env, key+"="+envMap[key])
	}
	return env
}

func sanitizePATH(raw string) string {
	parts := strings.Split(raw, string(os.PathListSeparator))
	cleaned := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" || part == "." {
			continue
		}
		if !filepath.IsAbs(part) {
			continue
		}
		part = filepath.Clean(part)
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		cleaned = append(cleaned, part)
	}

	return strings.Join(cleaned, string(os.PathListSeparator))
}
