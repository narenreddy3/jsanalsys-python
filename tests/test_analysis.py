"""
Tests for jsanalsys analysis engine, patterns, and core modules.
"""
import pytest
from jsanalsys.analysis.engine import AnalysisEngine, analyze_for_endpoints, analyze_for_hostnames
from jsanalsys.analysis.patterns import ALL_PATTERNS, SECRET_PATTERNS, DOM_SINK_PATTERNS
from jsanalsys.core.beautifier import beautify, is_minified, extract_string_literals
from jsanalsys.core.fetcher import normalize_url, extract_origin, same_origin


# ---------------------------------------------------------------------------
# Analysis engine tests
# ---------------------------------------------------------------------------

class TestAnalysisEngine:

    def setup_method(self):
        self.engine = AnalysisEngine()

    def test_detects_aws_key(self):
        js = 'var accessKey = "AKIAIOSFODNN7EXAMPLE";'
        result = self.engine.analyze(js)
        aws_findings = [f for f in result.findings if f.category == "aws_access_key"]
        assert len(aws_findings) > 0
        assert "AKIAIOSFODNN7EXAMPLE" in aws_findings[0].value

    def test_detects_google_api_key(self):
        js = 'const key = "AIzaSyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQE";'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "google_api_key"]
        assert len(findings) > 0

    def test_detects_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        js = f'var token = "{jwt}";'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "jwt_token"]
        assert len(findings) > 0

    def test_detects_innerhtml_sink(self):
        js = 'document.getElementById("output").innerHTML = userInput;'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "innerHTML"]
        assert len(findings) > 0

    def test_detects_eval(self):
        js = 'eval(document.location.hash.substring(1));'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "eval"]
        assert len(findings) > 0

    def test_detects_postmessage_wildcard(self):
        js = 'window.parent.postMessage({token: authToken}, "*");'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "postMessage_wildcard"]
        assert len(findings) > 0

    def test_detects_api_endpoint(self):
        js = 'fetch("/api/v1/users/profile", { method: "GET" });'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.finding_type == "endpoint"]
        assert len(findings) > 0

    def test_detects_s3_bucket(self):
        js = 'var url = "https://my-bucket.s3.amazonaws.com/uploads/file.png";'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "s3_bucket"]
        assert len(findings) > 0

    def test_detects_stripe_key(self):
        js = 'stripe.init("pk_live_51AbcDefGHIjklMNopQRsTuV");'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "stripe_key"]
        assert len(findings) > 0

    def test_detects_github_token(self):
        js = 'const token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "github_token"]
        assert len(findings) > 0

    def test_detects_document_write(self):
        js = 'document.write("<script>alert(1)</script>");'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "document_write"]
        assert len(findings) > 0

    def test_detects_private_ip(self):
        js = 'var backend = "http://192.168.1.100:8080/api";'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "private_ip"]
        assert len(findings) > 0

    def test_detects_sensitive_storage(self):
        js = 'localStorage.setItem("auth_token", response.token);'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "sensitive_storage"]
        assert len(findings) > 0

    def test_detects_dangerously_set_html(self):
        js = 'return <div dangerouslySetInnerHTML={{__html: userContent}} />;'
        result = self.engine.analyze(js)
        findings = [f for f in result.findings if f.category == "react_dangerouslySetInnerHTML"]
        assert len(findings) > 0

    def test_deduplication(self):
        # Same API key repeated 10 times should produce 1 finding
        js = '\n'.join(['var k = "AKIAIOSFODNN7EXAMPLE";'] * 10)
        result = self.engine.analyze(js)
        aws_findings = [f for f in result.unique_findings if f.category == "aws_access_key"]
        assert len(aws_findings) == 1

    def test_empty_content(self):
        result = self.engine.analyze("")
        assert result.findings == []

    def test_min_severity_filter(self):
        # Engine with high minimum severity should not return info findings
        engine_high = AnalysisEngine(min_severity="high")
        js = 'localStorage.getItem("user");'  # info severity
        result = engine_high.analyze(js)
        info_findings = [f for f in result.findings if f.severity == "info"]
        assert len(info_findings) == 0

    def test_summary_counts(self):
        js = """
        var key = "AKIAIOSFODNN7EXAMPLE";
        document.getElementById("x").innerHTML = data;
        localStorage.getItem("user");
        """
        result = self.engine.analyze(js)
        summary = result.summary()
        assert "total" in summary
        assert summary["total"] > 0


# ---------------------------------------------------------------------------
# Endpoint extraction
# ---------------------------------------------------------------------------

class TestEndpointExtraction:

    def test_absolute_urls(self):
        js = 'fetch("https://api.example.com/v1/users")'
        endpoints = analyze_for_endpoints(js)
        assert any("api.example.com" in e for e in endpoints)

    def test_relative_paths(self):
        js = 'axios.get("/api/v2/items")'
        endpoints = analyze_for_endpoints(js)
        assert any("/api/v2/items" in e for e in endpoints)

    def test_nested_paths(self):
        js = 'const url = "/admin/dashboard/users/123";'
        endpoints = analyze_for_endpoints(js)
        assert any("admin" in e for e in endpoints)


# ---------------------------------------------------------------------------
# Hostname extraction
# ---------------------------------------------------------------------------

class TestHostnameExtraction:

    def test_external_hostname(self):
        js = '"api.example.com"'
        hostnames = analyze_for_hostnames(js)
        assert "api.example.com" in hostnames

    def test_ignores_js_extensions(self):
        js = '"bundle.chunk.js"'
        hostnames = analyze_for_hostnames(js)
        # Should not include .js files as hostnames
        assert not any(h.endswith(".js") for h in hostnames)


# ---------------------------------------------------------------------------
# Beautifier
# ---------------------------------------------------------------------------

class TestBeautifier:

    def test_detects_minified(self):
        minified = "function a(){return 1;}function b(){return 2;}var c=a()+b();" * 10
        assert is_minified(minified)

    def test_not_minified(self):
        normal = """
function hello() {
    return "world";
}
"""
        assert not is_minified(normal)

    def test_beautify_runs(self):
        minified = "function a(){var b=1;var c=2;return b+c;}"
        result = beautify(minified)
        assert "function" in result
        assert len(result) >= len(minified)

    def test_extract_strings(self):
        js = """
        var a = "hello world";
        var b = 'secret_token_123';
        var c = `template ${literal}`;
        """
        strings = extract_string_literals(js)
        assert "hello world" in strings
        assert "secret_token_123" in strings


# ---------------------------------------------------------------------------
# Fetcher utilities
# ---------------------------------------------------------------------------

class TestFetcherUtils:

    def test_normalize_relative_url(self):
        result = normalize_url("https://example.com/static/js/", "bundle.js")
        assert result == "https://example.com/static/js/bundle.js"

    def test_normalize_absolute_url(self):
        result = normalize_url("https://example.com/", "https://cdn.example.com/app.js")
        assert result == "https://cdn.example.com/app.js"

    def test_normalize_protocol_relative(self):
        result = normalize_url("https://example.com/", "//cdn.example.com/app.js")
        assert result == "https://cdn.example.com/app.js"

    def test_extract_origin(self):
        origin = extract_origin("https://example.com/path/to/file.js")
        assert origin == "https://example.com"

    def test_same_origin(self):
        assert same_origin("https://example.com/a", "https://example.com/b")
        assert not same_origin("https://example.com/a", "https://api.example.com/b")


# ---------------------------------------------------------------------------
# Pattern coverage
# ---------------------------------------------------------------------------

class TestPatternCoverage:

    def test_all_patterns_compile(self):
        import re
        for p in ALL_PATTERNS:
            try:
                re.compile(p.regex)
            except re.error as e:
                pytest.fail(f"Pattern {p.name} has invalid regex: {e}")

    def test_all_patterns_have_required_fields(self):
        for p in ALL_PATTERNS:
            assert p.name, f"Pattern missing name"
            assert p.regex, f"Pattern {p.name} missing regex"
            assert p.finding_type, f"Pattern {p.name} missing finding_type"
            assert p.severity in ("critical", "high", "medium", "low", "info"), \
                f"Pattern {p.name} has invalid severity: {p.severity}"

    def test_pattern_count(self):
        # Ensure we have a meaningful number of patterns
        assert len(ALL_PATTERNS) >= 30
