import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from data_flow import (
    AnalysisOutput,
    Flow,
    NilSource,
    Sink,
    Source,
    calculate_risk,
    check_sanitization,
    detect_null_sources,
    detect_sinks,
    detect_sources,
    output_to_json,
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

        self.assertEqual(calculate_risk(source, sink, sanitized=True), "low")

    def test_calculate_risk_env_var_to_database_is_high(self):
        source = Source("env_var", "dsn", "config.py", 1, 1, "os.getenv")
        sink = Sink("database", "cursor.execute", "repo.py", 2, 1, "cursor.execute")

        self.assertEqual(calculate_risk(source, sink, sanitized=False), "high")

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
        self.assertEqual(flows[0].risk, "low")

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


if __name__ == "__main__":
    unittest.main()
