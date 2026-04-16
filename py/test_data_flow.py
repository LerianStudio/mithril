import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from data_flow import (
    AnalysisOutput,
    Flow,
    MAX_MANIFEST_SIZE,
    NilSource,
    Sink,
    Source,
    calculate_risk,
    check_sanitization,
    detect_null_sources,
    detect_sinks,
    detect_sources,
    output_to_json,
    sandbox_path,
    track_flows,
)


class DataFlowTests(unittest.TestCase):
    def test_output_to_json_includes_language_and_statistics(self):
        source = Source(
            type="http_query",
            variable="user_id",
            file="handler.py",
            line=10,
            column=5,
            pattern="request.args.get",
            context="user_id = request.args.get('id')",
        )
        sink = Sink(
            type="database",
            function="cursor.execute",
            file="repo.py",
            line=20,
            column=3,
            pattern="cursor.execute",
            context="cursor.execute(query)",
        )
        flow = Flow(
            id="flow-1",
            source=source,
            sink=sink,
            risk="critical",
            sanitized=False,
            sanitizers=[],
            path=["handler.py:10", "repo.py:20"],
            description="Data from http_query flows to database",
        )
        nil_source = NilSource(
            variable="record",
            file="service.ts",
            line=30,
            column=7,
            pattern=".findOne()",
            origin="database_query",
            is_checked=False,
            usage_line=35,
            risk="high",
        )

        output = AnalysisOutput(
            sources=[source], sinks=[sink], flows=[flow], nil_sources=[nil_source]
        )
        data = json.loads(output_to_json(output, "python"))

        self.assertEqual(data["language"], "python")
        self.assertEqual(data["statistics"]["total_sources"], 1)
        self.assertEqual(data["statistics"]["total_sinks"], 1)
        self.assertEqual(data["statistics"]["total_flows"], 1)
        self.assertEqual(data["statistics"]["critical_flows"], 1)
        self.assertEqual(data["statistics"]["unchecked_nil_risks"], 1)

    def test_detect_null_sources_populates_check_and_risk_fields(self):
        files = [
            (
                "service.ts",
                """
const user = await repo.findOne({ where: { id } })
if (user !== null) {
  user.name
}
""",
            )
        ]

        nil_sources = detect_null_sources(files, "typescript")
        self.assertGreaterEqual(len(nil_sources), 1)

        candidate = nil_sources[0]
        self.assertIn(candidate.risk, {"low", "medium", "high"})
        self.assertIsInstance(candidate.is_checked, bool)
        self.assertGreaterEqual(candidate.check_line, 0)
        self.assertGreaterEqual(candidate.usage_line, 0)

    def test_calculate_risk_sanitized_matches_go_behavior(self):
        source = Source("http_query", "input", "api.ts", 1, 1, "req.query")
        sink = Sink("command_exec", "exec", "api.ts", 2, 1, "exec")

        # Go's calculateRisk returns RiskInfo ("info") when sanitized, regardless
        # of source/sink types (see internal/dataflow/golang.go calculateRisk).
        self.assertEqual(calculate_risk(source, sink, sanitized=True), "info")

    def test_calculate_risk_env_var_to_database_is_medium(self):
        source = Source("env_var", "dsn", "config.py", 1, 1, "os.getenv")
        sink = Sink("database", "cursor.execute", "repo.py", 2, 1, "cursor.execute")

        # Go treats env_var -> database as RiskMedium ("medium"), not "high" —
        # "critical"/"high" are reserved for http_* sources in the Go impl.
        self.assertEqual(calculate_risk(source, sink, sanitized=False), "medium")

    def test_detect_sources_and_sinks_for_python_patterns(self):
        files = [
            (
                "handler.py",
                """
user_id = request.args.get('id')
cursor.execute("SELECT * FROM users WHERE id = %s", [user_id])
""",
            )
        ]

        sources = detect_sources(files, "python")
        sinks = detect_sinks(files, "python")

        self.assertGreaterEqual(len(sources), 1)
        self.assertTrue(any(src.type == "http_query" for src in sources))
        self.assertGreaterEqual(len(sinks), 1)
        self.assertTrue(any(sink.type == "database" for sink in sinks))

    def test_track_flows_and_sanitization_detection(self):
        source = Source(
            type="http_query",
            variable="name",
            file="handler.py",
            line=1,
            column=1,
            pattern="request.args.get",
            context="name = request.args.get('name')",
        )
        sink = Sink(
            type="database",
            function="cursor.execute",
            file="handler.py",
            line=2,
            column=1,
            pattern="cursor.execute",
            context="cursor.execute(query, [name])",
        )

        sanitized, sanitizer = check_sanitization(source, sink, "python")
        self.assertTrue(sanitized)
        self.assertIsNotNone(sanitizer)

        flows = track_flows([source], [sink], "python")
        self.assertEqual(len(flows), 1)
        self.assertTrue(flows[0].sanitized)
        # Sanitized flows get RiskInfo in Go's calculateRisk.
        self.assertEqual(flows[0].risk, "info")

    def test_check_sanitization_scans_source_to_sink_window(self):
        source = Source(
            type="http_query",
            variable="name",
            file="handler.py",
            line=1,
            column=1,
            pattern="request.args.get",
            context="name = request.args.get('name')",
        )
        sink = Sink(
            type="database",
            function="cursor.execute",
            file="handler.py",
            line=3,
            column=1,
            pattern="cursor.execute",
            context="cursor.execute(query)",
        )

        lines = [
            "name = request.args.get('name')",
            "cursor.execute(query, [name])",
            "cursor.execute(query)",
        ]

        sanitized, sanitizer = check_sanitization(source, sink, "python", lines)
        self.assertTrue(sanitized)
        self.assertIsNotNone(sanitizer)

    def test_check_sanitization_does_not_trust_printf_percent_s(self):
        source = Source(
            type="http_query",
            variable="name",
            file="handler.py",
            line=1,
            column=1,
            pattern="request.args.get",
            context="name = request.args.get('name')",
        )
        sink = Sink(
            type="database",
            function="cursor.execute",
            file="handler.py",
            line=2,
            column=1,
            pattern="cursor.execute",
            context='query = "SELECT * FROM users WHERE name = %s" % name',
        )

        sanitized, sanitizer = check_sanitization(source, sink, "python")
        self.assertFalse(sanitized)
        self.assertIsNone(sanitizer)

    def test_typescript_bare_json_does_not_match_http_body(self):
        files = [
            (
                "client.ts",
                """
const data = await fetch(url).then(r => r.json());
const parsed = JSON.parse(raw).json();
""",
            )
        ]
        sources = detect_sources(files, "typescript")
        http_body_sources = [s for s in sources if s.type == "http_body"]
        self.assertEqual(
            http_body_sources,
            [],
            f"bare .json() must not be typed as http_body; got {http_body_sources}",
        )

    def test_typescript_receiver_scoped_json_still_matches_http_body(self):
        files = [
            (
                "handler.ts",
                """
const body = await req.json();
""",
            )
        ]
        sources = detect_sources(files, "typescript")
        self.assertTrue(
            any(s.type == "http_body" for s in sources),
            "req.json() should still be classified as http_body",
        )

    def test_typescript_database_query_requires_db_receiver(self):
        files = [
            (
                "search.ts",
                """
const results = esClient.search({ query: { match: { name: q } } });
const items = array.find(x => x.id === id);
""",
            )
        ]
        sources = detect_sources(files, "typescript")
        db_sources = [s for s in sources if s.type == "database"]
        self.assertEqual(
            db_sources,
            [],
            f"Elasticsearch DSL / array.find must not match database; got {db_sources}",
        )

    def test_typescript_database_query_matches_real_db_receiver(self):
        files = [
            (
                "repo.ts",
                """
const users = await db.query('SELECT * FROM users');
const one = await pool.findOne({ id });
""",
            )
        ]
        sources = detect_sources(files, "typescript")
        self.assertTrue(
            any(s.type == "database" for s in sources),
            "db.query() / pool.findOne() should still match database",
        )


class SandboxAndManifestTests(unittest.TestCase):
    """Tests for the --base-dir sandbox and --files-from manifest size cap."""

    SCRIPT = os.path.join(os.path.dirname(__file__), "data_flow.py")

    def test_sandbox_path_rejects_outside(self):
        with tempfile.TemporaryDirectory() as base:
            with tempfile.TemporaryDirectory() as outside:
                outside_file = os.path.join(outside, "x.py")
                Path(outside_file).touch()
                self.assertIsNone(sandbox_path(outside_file, base))

    def test_sandbox_path_allows_inside(self):
        with tempfile.TemporaryDirectory() as base:
            inside = os.path.join(base, "x.py")
            Path(inside).touch()
            self.assertIsNotNone(sandbox_path(inside, base))

    def test_manifest_too_large_is_rejected(self):
        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, dir=tempfile.gettempdir()
        ) as m:
            manifest_path = m.name
            # Write slightly more than the cap
            chunk = "a" * 1024
            written = 0
            target = MAX_MANIFEST_SIZE + 4096
            while written < target:
                m.write(chunk + "\n")
                written += len(chunk) + 1
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    self.SCRIPT,
                    "python",
                    "--files-from",
                    manifest_path,
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest exceeds maximum size", result.stderr)
        finally:
            os.unlink(manifest_path)

    def test_manifest_drops_out_of_base_entries(self):
        with tempfile.TemporaryDirectory() as base:
            inside = os.path.join(base, "inside.py")
            with open(inside, "w") as f:
                f.write("x = 1\n")
            # Create an out-of-base file
            with tempfile.TemporaryDirectory() as outside:
                outside_file = os.path.join(outside, "leak.py")
                with open(outside_file, "w") as f:
                    f.write("x = 1\n")

                manifest_path = os.path.join(base, "manifest.txt")
                with open(manifest_path, "w") as f:
                    f.write(f"{inside}\n{outside_file}\n")

                result = subprocess.run(
                    [
                        sys.executable,
                        self.SCRIPT,
                        "python",
                        "--base-dir",
                        base,
                        "--files-from",
                        manifest_path,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                # Should succeed (inside.py still analyzable) but warn about outside
                self.assertIn("dropping manifest entry outside base dir", result.stderr)


if __name__ == "__main__":
    unittest.main()
