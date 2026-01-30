"""
Unit tests for smart utilities functionality.

Tests the text similarity analysis, solution extraction, and AI-powered
incident analysis features.
"""

from unittest.mock import MagicMock, patch

from rootly_mcp_server.smart_utils import (
    IncidentSimilarity,
    SolutionExtractor,
    TextSimilarityAnalyzer,
)


class TestTextSimilarityAnalyzer:
    """Test the TextSimilarityAnalyzer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = TextSimilarityAnalyzer()

    def test_preprocess_text(self):
        """Test text preprocessing functionality."""
        # Test basic preprocessing
        result = self.analyzer.preprocess_text("Payment API returning 500 errors!")
        expected = "payment api returning 500 errors"
        assert result == expected

        # Test with special characters and multiple spaces
        result = self.analyzer.preprocess_text("Auth service is down - users can't login")
        expected = "auth service down users can login"
        assert result == expected

        # Test empty text
        result = self.analyzer.preprocess_text("")
        assert result == ""

        # Test None input
        result = self.analyzer.preprocess_text(None)
        assert result == ""

    def test_extract_services(self):
        """Test service name extraction from text."""
        # Test hyphenated service names
        text = "payment-service is throwing errors"
        services = self.analyzer.extract_services(text)
        assert "payment" in services

        # Test API services
        text = "authapi connection timeout"
        services = self.analyzer.extract_services(text)
        assert "auth" in services

        # Test dotted service names
        text = "Error connecting to user.service"
        services = self.analyzer.extract_services(text)
        assert "user" in services

        # Test multiple services
        text = "payment-api and auth-service are both down"
        services = self.analyzer.extract_services(text)
        assert "payment" in services
        assert "auth" in services

    def test_extract_error_patterns(self):
        """Test error pattern extraction."""
        # Test HTTP status codes
        text = "API returning 500 internal server error"
        patterns = self.analyzer.extract_error_patterns(text)
        assert "http-500" in patterns

        # Test database errors
        text = "Database connection timeout occurred"
        patterns = self.analyzer.extract_error_patterns(text)
        assert "database-error" in patterns

        # Test memory errors
        text = "Out of memory error in the application"
        patterns = self.analyzer.extract_error_patterns(text)
        assert "resource-error" in patterns

        # Test network errors
        text = "Network unreachable error"
        patterns = self.analyzer.extract_error_patterns(text)
        assert "network-error" in patterns

    def test_combine_incident_text(self):
        """Test incident text combination."""
        incident = {
            "attributes": {
                "title": "Payment API Error",
                "summary": "Users cannot checkout",
                "description": "500 errors from payment service",
            }
        }

        result = self.analyzer._combine_incident_text(incident)
        assert "payment api error" in result
        assert "users cannot checkout" in result
        assert "500 errors from payment service" in result

    def test_combine_incident_text_backward_compatibility(self):
        """Test incident text combination with root-level fields."""
        incident = {
            "title": "Auth Service Down",
            "summary": "Login failures",
            "description": "Cannot authenticate users",
        }

        result = self.analyzer._combine_incident_text(incident)
        assert "auth service down" in result
        assert "login failures" in result
        assert "cannot authenticate users" in result

    def test_calculate_resolution_time(self):
        """Test resolution time calculation."""
        # Test with valid timestamps
        incident = {
            "attributes": {
                "created_at": "2024-01-01T10:00:00Z",
                "resolved_at": "2024-01-01T12:30:00Z",
            }
        }

        result = self.analyzer._calculate_resolution_time(incident)
        assert result == 2.5  # 2.5 hours

        # Test with missing timestamps
        incident = {
            "attributes": {
                "created_at": "2024-01-01T10:00:00Z"
                # No resolved_at
            }
        }

        result = self.analyzer._calculate_resolution_time(incident)
        assert result is None

        # Test with invalid timestamps
        incident = {
            "attributes": {"created_at": "invalid-date", "resolved_at": "2024-01-01T12:00:00Z"}
        }

        result = self.analyzer._calculate_resolution_time(incident)
        assert result is None

    @patch("rootly_mcp_server.smart_utils.ML_AVAILABLE", True)
    def test_calculate_similarity_with_ml(self):
        """Test similarity calculation with ML libraries available."""
        incidents = [
            {
                "id": "1",
                "attributes": {
                    "title": "Payment API timeout",
                    "summary": "Users cannot complete payments",
                },
            },
            {
                "id": "2",
                "attributes": {
                    "title": "Auth service error",
                    "summary": "Login failures occurring",
                },
            },
        ]

        target_incident = {
            "id": "target",
            "attributes": {
                "title": "Payment service down",
                "summary": "Payment processing failures",
            },
        }

        # Mock the TF-IDF components - patch the sklearn module imports
        with (
            patch("sklearn.feature_extraction.text.TfidfVectorizer") as mock_vectorizer,
            patch("sklearn.metrics.pairwise.cosine_similarity") as mock_similarity,
        ):

            mock_vectorizer_instance = MagicMock()
            mock_vectorizer.return_value = mock_vectorizer_instance

            # Mock TF-IDF matrix
            mock_tfidf_matrix = MagicMock()
            mock_vectorizer_instance.fit_transform.return_value = mock_tfidf_matrix

            # Mock similarity scores (payment incident should be more similar)
            import numpy as np

            mock_similarity.return_value = np.array(
                [[0.8, 0.3]]
            )  # High similarity to incident 1, low to incident 2

            results = self.analyzer.calculate_similarity(incidents, target_incident)

            # Should return results sorted by similarity
            assert len(results) >= 1
            assert isinstance(results[0], IncidentSimilarity)
            assert results[0].incident_id == "1"  # Most similar incident
            assert results[0].similarity_score > 0.5

    @patch("rootly_mcp_server.smart_utils.ML_AVAILABLE", False)
    def test_calculate_similarity_fallback(self):
        """Test similarity calculation fallback without ML libraries."""
        incidents = [
            {
                "id": "1",
                "attributes": {
                    "title": "Payment API timeout error",
                    "summary": "Users cannot complete payments due to timeout",
                },
            },
            {
                "id": "2",
                "attributes": {
                    "title": "Database connection error",
                    "summary": "Cannot connect to user database",
                },
            },
        ]

        target_incident = {
            "id": "target",
            "attributes": {
                "title": "Payment API timeout",
                "summary": "Payment processing timeout errors",
            },
        }

        results = self.analyzer.calculate_similarity(incidents, target_incident)

        # Should use keyword-based similarity
        assert len(results) >= 1
        assert isinstance(results[0], IncidentSimilarity)
        # Payment incident should be more similar due to matching keywords
        assert results[0].incident_id == "1"
        assert results[0].similarity_score > 0

    def test_extract_common_keywords(self):
        """Test common keyword extraction."""
        text1 = "payment api timeout error service"
        text2 = "payment service timeout connection error"

        common = self.analyzer._extract_common_keywords(text1, text2)

        assert "payment" in common
        assert "timeout" in common
        assert "error" in common
        assert "service" in common
        assert len(common) <= 8  # Should limit to top 8 (increased for fuzzy matching)


class TestSolutionExtractor:
    """Test the SolutionExtractor class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = SolutionExtractor()

    def test_extract_action_items(self):
        """Test action item extraction from resolution text."""
        # Test restart actions
        text = "We restarted the payment service and the issue was resolved"
        actions = self.extractor._extract_action_items(text)
        assert any("restart" in action.lower() for action in actions)

        # Test clear actions
        text = "Cleared the Redis cache to fix the connection issue"
        actions = self.extractor._extract_action_items(text)
        assert any("clear" in action.lower() for action in actions)

        # Test update actions
        text = "Updated the database configuration and deployed the fix"
        actions = self.extractor._extract_action_items(text)
        assert any("update" in action.lower() for action in actions)

        # Test with no actions
        text = "The issue resolved itself after some time"
        actions = self.extractor._extract_action_items(text)
        # Should still extract some context
        assert isinstance(actions, list)

    def test_identify_common_patterns(self):
        """Test common pattern identification."""
        similar_incidents = [
            IncidentSimilarity(
                incident_id="1",
                title="Payment API error",
                similarity_score=0.8,
                matched_services=["payment", "auth"],
                matched_keywords=["timeout", "error"],
                resolution_time_hours=1.5,
            ),
            IncidentSimilarity(
                incident_id="2",
                title="Payment timeout",
                similarity_score=0.7,
                matched_services=["payment"],
                matched_keywords=["timeout", "connection"],
                resolution_time_hours=0.5,
            ),
        ]

        patterns = self.extractor._identify_common_patterns(
            ["timeout", "error", "timeout", "connection"], similar_incidents
        )

        # Should identify common services
        assert any("payment" in pattern.lower() for pattern in patterns)

        # Should identify resolution time patterns (average is 1.0 hour, so in middle range)
        time_pattern_found = any("hour" in pattern.lower() for pattern in patterns)
        assert time_pattern_found, f"Expected time pattern in {patterns}"

    def test_extract_solutions(self):
        """Test complete solution extraction."""
        similar_incidents = [
            IncidentSimilarity(
                incident_id="123",
                title="Payment API timeout",
                similarity_score=0.85,
                matched_services=["payment"],
                matched_keywords=["timeout", "api"],
                resolution_summary="Restarted payment service and cleared cache",
                resolution_time_hours=1.0,
            )
        ]

        result = self.extractor.extract_solutions(similar_incidents)

        assert "solutions" in result
        assert "common_patterns" in result
        assert "average_resolution_time" in result
        assert "total_similar_incidents" in result

        # Check solution structure
        solutions = result["solutions"]
        assert len(solutions) > 0

        solution = solutions[0]
        assert "incident_id" in solution
        assert "title" in solution
        assert "similarity" in solution
        assert "resolution_summary" in solution

        # Check average resolution time
        assert result["average_resolution_time"] == 1.0
        assert result["total_similar_incidents"] == 1

    def test_extract_solutions_empty_input(self):
        """Test solution extraction with empty input."""
        result = self.extractor.extract_solutions([])

        assert result["solutions"] == []
        assert result["common_patterns"] == []
        assert result["average_resolution_time"] is None
        assert result["total_similar_incidents"] == 0


class TestIncidentSimilarity:
    """Test the IncidentSimilarity dataclass."""

    def test_incident_similarity_creation(self):
        """Test creating an IncidentSimilarity object."""
        similarity = IncidentSimilarity(
            incident_id="123",
            title="Test Incident",
            similarity_score=0.85,
            matched_services=["api", "db"],
            matched_keywords=["error", "timeout"],
            resolution_summary="Fixed by restart",
            resolution_time_hours=2.0,
        )

        assert similarity.incident_id == "123"
        assert similarity.title == "Test Incident"
        assert similarity.similarity_score == 0.85
        assert similarity.matched_services == ["api", "db"]
        assert similarity.matched_keywords == ["error", "timeout"]
        assert similarity.resolution_summary == "Fixed by restart"
        assert similarity.resolution_time_hours == 2.0

    def test_incident_similarity_defaults(self):
        """Test IncidentSimilarity with default values."""
        similarity = IncidentSimilarity(
            incident_id="123",
            title="Test Incident",
            similarity_score=0.85,
            matched_services=[],
            matched_keywords=[],
        )

        assert similarity.resolution_summary == ""
        assert similarity.resolution_time_hours is None


class TestIntegrationScenarios:
    """Test realistic end-to-end scenarios."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = TextSimilarityAnalyzer()
        self.extractor = SolutionExtractor()

    def test_payment_api_scenario(self):
        """Test a realistic payment API incident scenario."""
        # Historical incidents
        historical_incidents = [
            {
                "id": "100",
                "attributes": {
                    "title": "Payment API timeout errors",
                    "summary": "Users cannot complete payments due to API timeouts",
                    "created_at": "2024-01-01T10:00:00Z",
                    "resolved_at": "2024-01-01T11:30:00Z",
                },
            },
            {
                "id": "101",
                "attributes": {
                    "title": "Database connection issues",
                    "summary": "Cannot connect to user database",
                    "created_at": "2024-01-02T14:00:00Z",
                    "resolved_at": "2024-01-02T18:00:00Z",
                },
            },
        ]

        # Current incident
        target_incident = {
            "id": "200",
            "attributes": {
                "title": "Payment service returning 500 errors",
                "summary": "Users getting errors during checkout payment processing",
            },
        }

        # Calculate similarities
        similar_incidents = self.analyzer.calculate_similarity(
            historical_incidents, target_incident
        )

        # Should find the payment incident as more similar
        assert len(similar_incidents) > 0
        most_similar = similar_incidents[0]
        assert most_similar.incident_id == "100"  # Payment incident should be most similar
        assert most_similar.similarity_score > 0

        # Extract solutions
        solutions = self.extractor.extract_solutions(similar_incidents[:1])
        assert len(solutions["solutions"]) > 0
        assert solutions["average_resolution_time"] == 1.5  # 1.5 hours resolution time

    @patch("rootly_mcp_server.smart_utils.ML_AVAILABLE", False)
    def test_fallback_scenario(self):
        """Test that fallback works when ML libraries aren't available."""
        historical_incidents = [
            {
                "id": "300",
                "attributes": {
                    "title": "Auth service connection timeout",
                    "summary": "Authentication failures due to connection timeout",
                },
            }
        ]

        target_incident = {
            "id": "400",
            "attributes": {
                "title": "Auth API timeout errors",
                "summary": "User login timeout errors",
            },
        }

        # Should work with keyword-based fallback
        similar_incidents = self.analyzer.calculate_similarity(
            historical_incidents, target_incident
        )

        assert len(similar_incidents) > 0
        assert similar_incidents[0].incident_id == "300"
        assert similar_incidents[0].similarity_score > 0

        # Should have matched keywords
        assert (
            "auth" in similar_incidents[0].matched_keywords
            or "timeout" in similar_incidents[0].matched_keywords
        )
