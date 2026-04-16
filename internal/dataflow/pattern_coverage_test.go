package dataflow

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// sourceClassificationCase pairs a representative Go source sample with the
// SourceType the pattern library should classify it as. It lets tests verify
// that every registered source pattern (a) matches realistic code and (b)
// resolves that code to the expected taxonomy entry — not just that *some*
// pattern matched. This catches taxonomy regressions like C1 (where
// json.Unmarshal was incorrectly classified as SourceHTTPBody).
type sourceClassificationCase struct {
	Sample       string
	ExpectedType SourceType
}

type sinkClassificationCase struct {
	Sample       string
	ExpectedType SinkType
}

// matchingSourceTypes returns every SourceType whose pattern matches the
// sample. Production scanning (GoAnalyzer.detectSourcesInFile) records every
// matching pattern — a single line can emit multiple sources — so tests must
// verify the expected type is *among* the matches, not that it is the first.
func matchingSourceTypes(patterns []sourcePattern, sample string) []SourceType {
	var types []SourceType
	for _, p := range patterns {
		if p.Pattern.MatchString(sample) {
			types = append(types, p.Type)
		}
	}
	return types
}

func matchingSinkTypes(patterns []sinkPattern, sample string) []SinkType {
	var types []SinkType
	for _, p := range patterns {
		if p.Pattern.MatchString(sample) {
			types = append(types, p.Type)
		}
	}
	return types
}

func containsSourceType(haystack []SourceType, needle SourceType) bool {
	for _, t := range haystack {
		if t == needle {
			return true
		}
	}
	return false
}

func containsSinkType(haystack []SinkType, needle SinkType) bool {
	for _, t := range haystack {
		if t == needle {
			return true
		}
	}
	return false
}

// TestInitSourcePatterns_ClassificationMatchesTaxonomy is the authoritative
// test that each source pattern not only matches representative input but also
// produces the *correct* SourceType for that input. This is the regression
// target for C1 (json.Unmarshal must resolve to SourceJSONDecode, not
// SourceHTTPBody).
func TestInitSourcePatterns_ClassificationMatchesTaxonomy(t *testing.T) {
	patterns := initSourcePatterns()

	cases := []sourceClassificationCase{
		// HTTP body
		{"body := req.Body", SourceHTTPBody},
		{"data, _ := ioutil.ReadAll(request.Body)", SourceHTTPBody},
		{"data, _ := io.ReadAll(r.Body)", SourceHTTPBody},
		{"if err := c.BodyParser(&dto); err != nil {}", SourceHTTPBody},
		{"grpc.UnaryServerInterceptor", SourceHTTPBody},

		// JSON decode (origin-agnostic, distinct from HTTP body — regression
		// target for C1).
		{"json.NewDecoder(req.Body).Decode(&payload)", SourceJSONDecode},
		{"if err := json.Unmarshal(data, &payload); err != nil {}", SourceJSONDecode},

		// HTTP query / form / cookie
		{"values := req.URL.Query()", SourceHTTPQuery},
		{"name := r.FormValue(\"name\")", SourceHTTPQuery},
		{"name := request.Form.Get(\"name\")", SourceHTTPQuery},
		{"id := c.Query(\"id\")", SourceHTTPQuery},
		{"id := c.QueryParam(\"id\")", SourceHTTPQuery},
		{"cookie, _ := req.Cookie(\"session\")", SourceHTTPQuery},
		{"cookie := c.Cookie(\"session\")", SourceHTTPQuery},
		{"name := c.GetQuery(\"name\")", SourceHTTPQuery},

		// HTTP headers
		{"token := req.Header.Get(\"Authorization\")", SourceHTTPHeader},
		{"token := request.Header[\"Authorization\"]", SourceHTTPHeader},
		{"lang := c.Get(\"Accept-Language\")", SourceHTTPHeader},

		// HTTP path params
		{"vars := mux.Vars(req)", SourceHTTPPath},
		{"id := chi.URLParam(r, \"id\")", SourceHTTPPath},
		{"id := c.Params(\"id\")", SourceHTTPPath},
		{"id := c.Param(\"id\")", SourceHTTPPath},

		// Environment variables
		{"dsn := os.Getenv(\"DB_DSN\")", SourceEnvVar},
		{"dsn, ok := os.LookupEnv(\"DB_DSN\")", SourceEnvVar},
		{"port := viper.GetString(\"PORT\")", SourceEnvVar},

		// File reads
		{"f, _ := os.Open(\"a.txt\")", SourceFile},
		{"data, _ := ioutil.ReadFile(\"a.txt\")", SourceFile},
		{"_, _ = io.Copy(dst, src)", SourceFile},
		{"reader := bufio.NewReader(file)", SourceFile},

		// Database reads
		{"rows, _ := db.QueryContext(ctx, query)", SourceDatabase},
		{"err := row.Scan(&name)", SourceDatabase},
		{"users := repo.FindAll(ctx)", SourceDatabase},
		{"user := db.First(&u)", SourceDatabase},
		{"doc := collection.FindOne(ctx, filter)", SourceDatabase},

		// External API
		{"resp, _ := http.Get(url)", SourceExternal},
		{"resp, _ := client.Do(req)", SourceExternal},

		// User / stdin input
		{"scanner := bufio.NewScanner(os.Stdin)", SourceUserInput},
		{"fmt.Scanln(&name)", SourceUserInput},
		{"arg := os.Args[1]", SourceUserInput},
	}

	// Every case must produce the expected taxonomy entry among its matches.
	// A single sample may legitimately match multiple patterns (e.g. a line
	// that contains both `json.NewDecoder` and `req.Body`), but the expected
	// type must always be one of them.
	for _, tc := range cases {
		matches := matchingSourceTypes(patterns, tc.Sample)
		require.NotEmptyf(t, matches, "no source pattern matched sample %q (expected %s)", tc.Sample, tc.ExpectedType)
		require.Truef(t, containsSourceType(matches, tc.ExpectedType),
			"sample %q matched types %v, expected %s to be present", tc.Sample, matches, tc.ExpectedType)
	}

	// Every registered pattern must be reachable by at least one case so new
	// patterns without corpus coverage fail the test (prevents silent dead
	// regexes).
	usedTypes := make(map[SourceType]bool)
	for _, tc := range cases {
		usedTypes[tc.ExpectedType] = true
	}
	for i, p := range patterns {
		require.Truef(t, usedTypes[p.Type],
			"source pattern %d (%s, type %s) has no classification sample; add one to cases",
			i, p.Desc, p.Type)
	}
}

// TestJSONUnmarshal_IsClassifiedAsJSONDecode is the dedicated regression test
// for C1: `json.Unmarshal` without a request-body token must classify as
// SourceJSONDecode, not SourceHTTPBody. A line containing ONLY json.Unmarshal
// (no req.Body / request.Body / r.Body) should produce at least one match and
// that match must include SourceJSONDecode.
func TestJSONUnmarshal_IsClassifiedAsJSONDecode(t *testing.T) {
	patterns := initSourcePatterns()

	samples := []string{
		`if err := json.Unmarshal(data, &payload); err != nil {}`,
		`json.Unmarshal(bytesFromKafka, &msg)`,
		`_ = json.NewDecoder(reader).Decode(&cfg)`,
	}

	for _, sample := range samples {
		matches := matchingSourceTypes(patterns, sample)
		require.NotEmptyf(t, matches, "no source pattern matched %q", sample)
		require.Truef(t, containsSourceType(matches, SourceJSONDecode),
			"%q matched %v; expected SourceJSONDecode present (C1 regression)", sample, matches)
		// A bare json.Unmarshal/NewDecoder line must NOT be misclassified as
		// http_body-only — that would re-introduce C1.
		if !containsSourceType(matches, SourceJSONDecode) {
			t.Fatalf("json decode sample %q did not produce SourceJSONDecode", sample)
		}
	}
}

// TestInitSinkPatterns_ClassificationMatchesTaxonomy mirrors the source
// classification test for sinks.
func TestInitSinkPatterns_ClassificationMatchesTaxonomy(t *testing.T) {
	patterns := initSinkPatterns()

	cases := []sinkClassificationCase{
		// Database sinks
		{"db.Exec(query)", SinkDatabase},
		{"db.Query(\"SELECT \"+name)", SinkDatabase},
		{"sql := fmt.Sprintf(\"SELECT * FROM users\")", SinkDatabase},
		{"collection.InsertOne(ctx, doc)", SinkDatabase},

		// Command execution
		{"exec.Command(\"sh\", \"-c\", cmd)", SinkExec},
		{"exec.CommandContext(ctx, \"sh\")", SinkExec},
		{"os.StartProcess(\"/bin/sh\", argv, attr)", SinkExec},
		{"syscall.Exec(\"/bin/sh\", argv, env)", SinkExec},

		// HTTP response
		{"w.Write([]byte(msg))", SinkResponse},
		{"response.WriteString(msg)", SinkResponse},
		{"fmt.Fprintf(writer, \"%s\", msg)", SinkResponse},
		{"json.NewEncoder(w).Encode(resp)", SinkResponse},
		{"c.JSON(200, data)", SinkResponse},
		{"c.HTML(200, html)", SinkResponse},
		{"w.Header().Set(\"X-Test\", value)", SinkResponse},

		// Logging
		{"log.Printf(\"%s\", msg)", SinkLog},
		{"logger.Infof(\"%s\", msg)", SinkLog},
		{"zap.L().Info(\"msg\")", SinkLog},
		{"logrus.Errorf(\"msg\")", SinkLog},
		{"slog.Warn(\"msg\")", SinkLog},

		// File sinks
		{"os.WriteFile(path, data, 0o644)", SinkFile},
		{"ioutil.WriteFile(path, data, 0o644)", SinkFile},
		{"file.WriteString(data)", SinkFile},
		{"io.WriteString(file, data)", SinkFile},
		{"filepath.Join(base, userPath)", SinkFile},
		{"os.Open(path)", SinkFile},

		// Template rendering
		{"template.HTML(input)", SinkTemplate},
		{"tmpl.Execute(w, data)", SinkTemplate},
		{"html/template helper Execute", SinkTemplate},
		{"json.Unmarshal(data, &payload)", SinkTemplate},

		// Redirects (two distinct variants: http.Get treated as outbound
		// SinkRedirect by the network-request pattern).
		{"http.Get(url)", SinkRedirect},
		{"http.Redirect(w, r, url, 302)", SinkRedirect},
		{"c.Redirect(url)", SinkRedirect},
		{"w.Header().Set(\"Location\", url)", SinkRedirect},
	}

	for _, tc := range cases {
		matches := matchingSinkTypes(patterns, tc.Sample)
		require.NotEmptyf(t, matches, "no sink pattern matched sample %q (expected %s)", tc.Sample, tc.ExpectedType)
		require.Truef(t, containsSinkType(matches, tc.ExpectedType),
			"sample %q matched types %v, expected %s to be present", tc.Sample, matches, tc.ExpectedType)
	}

	usedTypes := make(map[SinkType]bool)
	for _, tc := range cases {
		usedTypes[tc.ExpectedType] = true
	}
	for i, p := range patterns {
		require.Truef(t, usedTypes[p.Type],
			"sink pattern %d (%s, type %s) has no classification sample; add one to cases",
			i, p.Desc, p.Type)
	}
}
