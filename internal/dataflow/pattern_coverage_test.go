package dataflow

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInitSourcePatterns_AllPatternsMatchRepresentativeInput(t *testing.T) {
	patterns := initSourcePatterns()
	samples := []string{
		"body := req.Body",
		"json.NewDecoder(req.Body).Decode(&payload)",
		"data, _ := ioutil.ReadAll(request.Body)",
		"data, _ := io.ReadAll(r.Body)",
		"if err := c.BodyParser(&dto); err != nil {}",
		"values := req.URL.Query()",
		"name := r.FormValue(\"name\")",
		"name := request.Form.Get(\"name\")",
		"id := c.Query(\"id\")",
		"id := c.QueryParam(\"id\")",
		"cookie, _ := req.Cookie(\"session\")",
		"cookie := c.Cookie(\"session\")",
		"name := c.GetQuery(\"name\")",
		"token := req.Header.Get(\"Authorization\")",
		"token := request.Header[\"Authorization\"]",
		"lang := c.Get(\"Accept-Language\")",
		"vars := mux.Vars(req)",
		"id := chi.URLParam(r, \"id\")",
		"id := c.Params(\"id\")",
		"id := c.Param(\"id\")",
		"dsn := os.Getenv(\"DB_DSN\")",
		"dsn, ok := os.LookupEnv(\"DB_DSN\")",
		"port := viper.GetString(\"PORT\")",
		"f, _ := os.Open(\"a.txt\")",
		"data, _ := ioutil.ReadFile(\"a.txt\")",
		"_, _ = io.Copy(dst, src)",
		"reader := bufio.NewReader(file)",
		"rows, _ := db.QueryContext(ctx, query)",
		"err := row.Scan(&name)",
		"users := repo.FindAll(ctx)",
		"user := db.First(&u)",
		"doc := collection.FindOne(ctx, filter)",
		"resp, _ := http.Get(url)",
		"resp, _ := client.Do(req)",
		"size := resp.Body.Len()",
		"scanner := bufio.NewScanner(os.Stdin)",
		"fmt.Scanln(&name)",
		"arg := os.Args[1]",
		"grpc.UnaryServerInterceptor",
	}

	for i, pattern := range patterns {
		matched := false
		for _, sample := range samples {
			if pattern.Pattern.MatchString(sample) {
				matched = true
				break
			}
		}
		require.Truef(t, matched, "source pattern %d (%s) did not match any representative sample", i, pattern.Desc)
	}
}

func TestInitSinkPatterns_AllPatternsMatchRepresentativeInput(t *testing.T) {
	patterns := initSinkPatterns()
	samples := []string{
		"db.Exec(query)",
		"db.Query(\"SELECT \"+name)",
		"sql := fmt.Sprintf(\"SELECT * FROM users\")",
		"collection.InsertOne(ctx, doc)",
		"exec.Command(\"sh\", \"-c\", cmd)",
		"exec.CommandContext(ctx, \"sh\")",
		"os.StartProcess(\"/bin/sh\", argv, attr)",
		"syscall.Exec(\"/bin/sh\", argv, env)",
		"http.Get(url)",
		"w.Write([]byte(msg))",
		"response.WriteString(msg)",
		"fmt.Fprintf(writer, \"%s\", msg)",
		"json.NewEncoder(w).Encode(resp)",
		"c.JSON(200, data)",
		"c.HTML(200, html)",
		"w.Header().Set(\"X-Test\", value)",
		"log.Printf(\"%s\", msg)",
		"logger.Infof(\"%s\", msg)",
		"zap.L().Info(\"msg\")",
		"logrus.Errorf(\"msg\")",
		"slog.Warn(\"msg\")",
		"os.WriteFile(path, data, 0o644)",
		"ioutil.WriteFile(path, data, 0o644)",
		"file.WriteString(data)",
		"io.WriteString(file, data)",
		"filepath.Join(base, userPath)",
		"os.Open(path)",
		"template.HTML(input)",
		"tmpl.Execute(w, data)",
		"html/template helper Execute",
		"json.Unmarshal(data, &payload)",
		"http.Redirect(w, r, url, 302)",
		"c.Redirect(url)",
		"w.Header().Set(\"Location\", url)",
	}

	for i, pattern := range patterns {
		matched := false
		for _, sample := range samples {
			if pattern.Pattern.MatchString(sample) {
				matched = true
				break
			}
		}
		require.Truef(t, matched, "sink pattern %d (%s) did not match any representative sample", i, pattern.Desc)
	}
}
