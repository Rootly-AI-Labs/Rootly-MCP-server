"""scikit-learn is optional (the `similarity` extra).

With it, incident similarity uses TF-IDF; without it, keyword matching. These
tests pin both paths: that a missing sklearn costs nothing at import and still
answers, that a present sklearn is used (and only imported on first use), and
that a broken sklearn install degrades instead of failing the tool.
"""

from __future__ import annotations

import logging
import subprocess
import sys
import textwrap

import pytest

from rootly_mcp_server import smart_utils
from rootly_mcp_server.smart_utils import TextSimilarityAnalyzer

HISTORICAL = [
    {
        "id": "1",
        "attributes": {
            "title": "Postgres connection pool exhausted",
            "summary": "API pods unable to acquire database connections",
        },
    },
    {
        "id": "2",
        "attributes": {
            "title": "SSL certificate expired on api domain",
            "summary": "Clients receiving TLS handshake errors",
        },
    },
    {
        "id": "3",
        "attributes": {
            "title": "Billing invoice totals incorrect",
            "summary": "Rounding error in tax calculation",
        },
    },
]
TARGET = {
    "id": "target",
    "attributes": {
        "title": "Database connection pool exhaustion",
        "summary": "Postgres connections maxed out, API returning 500s",
    },
}


def _run_isolated(code: str) -> subprocess.CompletedProcess[str]:
    """Run code in a fresh interpreter so module-level detection runs again."""
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


@pytest.mark.unit
class TestWithoutScikitLearn:
    def test_missing_sklearn_is_detected_without_importing_anything(self):
        # sys.modules[name] = None makes both find_spec and import treat the
        # package as absent, exactly as when the extra is not installed.
        result = _run_isolated(
            """
            import sys
            sys.modules["sklearn"] = None
            from rootly_mcp_server import smart_utils
            assert smart_utils.ML_AVAILABLE is False
            assert "numpy" not in sys.modules and "scipy" not in sys.modules
            """
        )
        assert result.returncode == 0, result.stderr

    def test_missing_sklearn_still_ranks_with_keywords(self, monkeypatch):
        monkeypatch.setattr(smart_utils, "ML_AVAILABLE", False)
        results = TextSimilarityAnalyzer().calculate_similarity(HISTORICAL, TARGET)
        assert results, "keyword fallback should still return matches"
        assert results[0].incident_id == "1"

    def test_fallback_is_logged_at_debug_not_warning(self, monkeypatch, caplog):
        monkeypatch.setattr(smart_utils, "ML_AVAILABLE", False)
        with caplog.at_level(logging.DEBUG, logger=smart_utils.__name__):
            TextSimilarityAnalyzer()
        records = [r for r in caplog.records if r.name == smart_utils.__name__]
        assert [r.levelno for r in records] == [logging.DEBUG]
        assert "rootly-mcp-server[similarity]" in records[0].getMessage()

    def test_broken_sklearn_install_falls_back_to_keywords(self, monkeypatch, caplog):
        # find_spec found sklearn, but importing its submodules fails.
        monkeypatch.setattr(smart_utils, "ML_AVAILABLE", True)
        monkeypatch.setitem(sys.modules, "sklearn.feature_extraction.text", None)
        analyzer = TextSimilarityAnalyzer()
        with caplog.at_level(logging.DEBUG, logger=smart_utils.__name__):
            results = analyzer.calculate_similarity(HISTORICAL, TARGET)

        monkeypatch.setattr(smart_utils, "ML_AVAILABLE", False)
        expected = analyzer.calculate_similarity(HISTORICAL, TARGET)

        assert results == expected
        assert any(
            r.levelno == logging.DEBUG and "keyword matching" in r.getMessage()
            for r in caplog.records
        )


@pytest.mark.unit
class TestWithScikitLearn:
    @pytest.fixture(autouse=True)
    def _require_sklearn(self):
        pytest.importorskip("sklearn")

    def test_sklearn_is_detected_but_imported_lazily(self):
        result = _run_isolated(
            """
            import sys
            from rootly_mcp_server import smart_utils
            assert smart_utils.ML_AVAILABLE is True
            assert "sklearn" not in sys.modules, "sklearn imported at module load"
            smart_utils.TextSimilarityAnalyzer().calculate_similarity(
                [
                    {"id": "1", "attributes": {"title": "redis out of memory"}},
                    {"id": "2", "attributes": {"title": "kafka consumer lag"}},
                ],
                {"id": "t", "attributes": {"title": "redis memory full"}},
            )
            assert "sklearn" in sys.modules, "TF-IDF path did not use sklearn"
            """
        )
        assert result.returncode == 0, result.stderr

    def test_tfidf_path_is_used_and_ranks_the_related_incident_first(self, monkeypatch):
        monkeypatch.setattr(smart_utils, "ML_AVAILABLE", True)
        calls = []
        original = TextSimilarityAnalyzer._calculate_tfidf_similarity

        def spy(self, *args, **kwargs):
            out = original(self, *args, **kwargs)
            calls.append(out)
            return out

        monkeypatch.setattr(TextSimilarityAnalyzer, "_calculate_tfidf_similarity", spy)
        results = TextSimilarityAnalyzer().calculate_similarity(HISTORICAL, TARGET)

        assert len(calls) == 1 and calls[0] is not None
        assert results[0].incident_id == "1"
        # TF-IDF drops incidents with no shared vocabulary; the keyword path
        # scores them on bonuses alone.
        assert "3" not in {r.incident_id for r in results}

    def test_tfidf_and_keyword_paths_agree_on_the_best_match(self, monkeypatch):
        analyzer = TextSimilarityAnalyzer()
        monkeypatch.setattr(smart_utils, "ML_AVAILABLE", True)
        tfidf = analyzer.calculate_similarity(HISTORICAL, TARGET)
        monkeypatch.setattr(smart_utils, "ML_AVAILABLE", False)
        keyword = analyzer.calculate_similarity(HISTORICAL, TARGET)
        assert tfidf[0].incident_id == keyword[0].incident_id == "1"
