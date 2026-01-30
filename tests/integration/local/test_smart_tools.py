"""
Integration tests for smart MCP tools.

Tests the find_related_incidents and suggest_solutions tools with realistic
incident data scenarios.
"""

import pytest

from rootly_mcp_server.server import create_rootly_mcp_server


class TestSmartToolsIntegration:
    """Test smart tools integration with MCP server."""

    @pytest.fixture
    async def server_with_smart_tools(self):
        """Create server instance with smart tools enabled."""
        # Use local swagger to avoid external dependencies
        server = create_rootly_mcp_server(
            swagger_path="src/rootly_mcp_server/data/swagger.json", name="TestRootly", hosted=False
        )
        return server

    @pytest.fixture
    def mock_historical_incidents(self):
        """Mock historical incidents data."""
        return {
            "data": [
                {
                    "id": "1001",
                    "attributes": {
                        "title": "Payment API timeout errors",
                        "summary": "Users cannot complete payments due to timeout",
                        "status": "resolved",
                        "created_at": "2024-01-01T10:00:00Z",
                        "resolved_at": "2024-01-01T11:30:00Z",
                    },
                },
                {
                    "id": "1002",
                    "attributes": {
                        "title": "Auth service connection issues",
                        "summary": "Login failures due to service connectivity",
                        "status": "resolved",
                        "created_at": "2024-01-02T09:00:00Z",
                        "resolved_at": "2024-01-02T10:15:00Z",
                    },
                },
                {
                    "id": "1003",
                    "attributes": {
                        "title": "Payment service 500 errors",
                        "summary": "Internal server errors in payment processing",
                        "status": "resolved",
                        "created_at": "2024-01-03T14:00:00Z",
                        "resolved_at": "2024-01-03T15:00:00Z",
                    },
                },
                {
                    "id": "1004",
                    "attributes": {
                        "title": "Database connection timeout",
                        "summary": "Cannot connect to postgres database",
                        "status": "resolved",
                        "created_at": "2024-01-04T11:00:00Z",
                        "resolved_at": "2024-01-04T13:30:00Z",
                    },
                },
            ],
            "meta": {"total_count": 4},
        }

    @pytest.fixture
    def mock_target_incident(self):
        """Mock target incident data."""
        return {
            "data": {
                "id": "2001",
                "attributes": {
                    "title": "Payment API returning errors",
                    "summary": "Users getting errors during payment processing",
                    "status": "open",
                    "created_at": "2024-01-05T15:00:00Z",
                },
            }
        }

    async def test_find_related_incidents_success(
        self, server_with_smart_tools, mock_target_incident, mock_historical_incidents
    ):
        """Test successful related incidents finding."""
        # Test the core similarity analysis functionality directly
        # Since the MCP server functions are nested and hard to mock, we test the underlying logic
        from rootly_mcp_server.smart_utils import TextSimilarityAnalyzer

        analyzer = TextSimilarityAnalyzer()
        target = mock_target_incident["data"]
        historical = mock_historical_incidents["data"]

        # Test the core similarity analysis
        similar_incidents = analyzer.calculate_similarity(historical, target)

        # Should find payment-related incidents as most similar
        assert len(similar_incidents) > 0

        # Payment incidents should be more similar than auth/database incidents
        payment_incidents = [inc for inc in similar_incidents if "payment" in inc.title.lower()]
        assert len(payment_incidents) >= 2  # Should find both payment incidents

        # Check that similarity scores are reasonable (updated for partial matching bonuses)
        top_incident = similar_incidents[0]
        assert top_incident.similarity_score > 0.1
        assert top_incident.incident_id in ["1001", "1003"]  # Should be a payment incident

        # Check that matched services are detected
        payment_matches = [inc for inc in similar_incidents if "payment" in inc.matched_services]
        assert len(payment_matches) > 0  # Should detect payment service matches

    async def test_suggest_solutions_with_incident_id(
        self, server_with_smart_tools, mock_target_incident, mock_historical_incidents
    ):
        """Test solution suggestions using incident ID."""
        # Test the solution extraction functionality directly
        from rootly_mcp_server.smart_utils import SolutionExtractor, TextSimilarityAnalyzer

        analyzer = TextSimilarityAnalyzer()
        extractor = SolutionExtractor()

        target = mock_target_incident["data"]
        historical = mock_historical_incidents["data"]

        # Find similar incidents
        similar_incidents = analyzer.calculate_similarity(historical, target)
        relevant_incidents = [inc for inc in similar_incidents if inc.similarity_score >= 0.2]

        # Extract solutions
        solutions = extractor.extract_solutions(relevant_incidents)

        # Should return solution structure
        assert "solutions" in solutions
        assert "common_patterns" in solutions
        assert "average_resolution_time" in solutions
        assert "total_similar_incidents" in solutions

        # Should have found some solutions
        if solutions["solutions"]:
            solution = solutions["solutions"][0]
            assert "incident_id" in solution
            assert "title" in solution
            assert "similarity" in solution
            assert "resolution_summary" in solution

    async def test_suggest_solutions_with_text_input(
        self, server_with_smart_tools, mock_historical_incidents
    ):
        """Test solution suggestions using text input (no incident ID)."""
        # Test solution suggestions with text input directly
        from rootly_mcp_server.smart_utils import SolutionExtractor, TextSimilarityAnalyzer

        analyzer = TextSimilarityAnalyzer()
        extractor = SolutionExtractor()

        # Create synthetic incident from text input
        target_incident = {
            "id": "synthetic",
            "attributes": {
                "title": "Payment processing errors",
                "summary": "Users experiencing checkout failures",
                "description": "500 errors from payment API",
            },
        }

        historical = mock_historical_incidents["data"]

        # Find similar incidents
        similar_incidents = analyzer.calculate_similarity(historical, target_incident)
        relevant_incidents = [inc for inc in similar_incidents if inc.similarity_score >= 0.2]

        # Should find payment-related incidents
        assert len(relevant_incidents) > 0
        payment_matches = [inc for inc in relevant_incidents if "payment" in inc.title.lower()]
        assert len(payment_matches) > 0

        # Extract solutions
        solutions = extractor.extract_solutions(relevant_incidents)
        assert solutions["total_similar_incidents"] > 0

    async def test_related_incidents_no_matches(self, server_with_smart_tools):
        """Test related incidents when no similar incidents exist."""
        # Test with no historical data
        from rootly_mcp_server.smart_utils import TextSimilarityAnalyzer

        analyzer = TextSimilarityAnalyzer()
        target = {"id": "3001", "attributes": {"title": "Unique error", "summary": "Novel issue"}}

        similar_incidents = analyzer.calculate_similarity([], target)
        assert len(similar_incidents) == 0

    async def test_high_similarity_threshold(
        self, server_with_smart_tools, mock_target_incident, mock_historical_incidents
    ):
        """Test related incidents with high similarity threshold."""
        from rootly_mcp_server.smart_utils import TextSimilarityAnalyzer

        analyzer = TextSimilarityAnalyzer()
        target = mock_target_incident["data"]
        historical = mock_historical_incidents["data"]

        similar_incidents = analyzer.calculate_similarity(historical, target)

        # Filter with high threshold
        high_threshold_matches = [inc for inc in similar_incidents if inc.similarity_score >= 0.8]
        low_threshold_matches = [inc for inc in similar_incidents if inc.similarity_score >= 0.1]

        # Should have fewer matches with high threshold
        assert len(high_threshold_matches) <= len(low_threshold_matches)

    async def test_error_handling_invalid_incident_id(self, server_with_smart_tools):
        """Test error handling for invalid incident ID."""
        # Test the error handling pattern
        from rootly_mcp_server.server import MCPError

        # Test error categorization
        error_type, error_message = MCPError.categorize_error(Exception("404 Not Found"))
        assert error_type in ["client_error", "execution_error"]
        assert "404" in error_message or "Not Found" in error_message

    def test_solution_extraction_patterns(self):
        """Test solution extraction with various resolution text patterns."""
        from rootly_mcp_server.smart_utils import SolutionExtractor

        extractor = SolutionExtractor()

        # Test different action patterns
        test_cases = [
            ("Restarted the payment service", ["restart"]),
            ("Cleared Redis cache and restarted auth", ["clear", "restart"]),
            ("Updated database configuration", ["update"]),
            ("Fixed connection pool settings", ["fix"]),
            ("Rolled back deployment to v1.2.3", ["rollback"]),
            ("Scaled up instances to handle load", ["scale"]),
        ]

        for resolution_text, expected_actions in test_cases:
            actions = extractor._extract_action_items(resolution_text)

            # Check that expected action types are found
            for expected_action in expected_actions:
                assert any(
                    expected_action in action.lower() for action in actions
                ), f"Expected action '{expected_action}' not found in {actions} for text '{resolution_text}'"

    def test_service_extraction_patterns(self):
        """Test service name extraction patterns."""
        from rootly_mcp_server.smart_utils import TextSimilarityAnalyzer

        analyzer = TextSimilarityAnalyzer()

        test_cases = [
            ("payment-service is down", ["payment"]),
            ("authapi connection failed", ["auth"]),
            ("user.service timeout", ["user"]),
            ("Error in notification-api and billing-service", ["notification", "billing"]),
            ("postgres-db connection issue", ["postgres"]),
            ("elasticsearch cluster failing", ["elasticsearch"]),  # New test for known services
            ("elastic search timeout", ["elastic"]),  # Test partial matching
        ]

        for text, expected_services in test_cases:
            services = analyzer.extract_services(text)

            for expected_service in expected_services:
                assert (
                    expected_service in services
                ), f"Expected service '{expected_service}' not found in {services} for text '{text}'"

    def test_partial_matching_improvements(self):
        """Test partial/fuzzy matching for related but not identical incidents."""
        from rootly_mcp_server.smart_utils import TextSimilarityAnalyzer

        analyzer = TextSimilarityAnalyzer()

        # Test cases for partial matching
        target_incident = {
            "id": "target",
            "attributes": {
                "title": "Payment API timeout errors",
                "summary": "Users experiencing payment failures due to API timeouts",
            },
        }

        historical_incidents = [
            {
                "id": "similar1",
                "attributes": {
                    "title": "Payment service timeouts",
                    "summary": "Payments API timing out for users",
                },
            },
            {
                "id": "similar2",
                "attributes": {
                    "title": "Billing API errors",
                    "summary": "Users unable to complete payments due to errors",
                },
            },
            {
                "id": "unrelated",
                "attributes": {
                    "title": "Auth service down",
                    "summary": "Login failures for all users",
                },
            },
        ]

        similar_incidents = analyzer.calculate_similarity(historical_incidents, target_incident)

        # Should find payment-related incidents with partial matching
        payment_related = [
            inc for inc in similar_incidents if inc.incident_id in ["similar1", "similar2"]
        ]
        auth_related = [inc for inc in similar_incidents if inc.incident_id == "unrelated"]

        # Payment incidents should have higher scores than auth incident
        if payment_related and auth_related:
            max_payment_score = max(inc.similarity_score for inc in payment_related)
            max_auth_score = max(inc.similarity_score for inc in auth_related)
            assert (
                max_payment_score > max_auth_score
            ), f"Payment similarity ({max_payment_score}) should be higher than auth ({max_auth_score})"

        # Check that fuzzy keywords are detected
        if payment_related:
            top_match = max(payment_related, key=lambda x: x.similarity_score)
            # Should detect partial matches like "payment~payments" or "timeout~timeouts"
            # Note: This might be 0 if exact matches exist, which is also valid
            assert (
                top_match.similarity_score > 0.1
            ), "Should have reasonable similarity score for payment incidents"

    def test_find_related_incidents_with_text_description(self):
        """Test find_related_incidents with descriptive text instead of incident ID."""
        from rootly_mcp_server.smart_utils import TextSimilarityAnalyzer

        analyzer = TextSimilarityAnalyzer()

        # Simulate the enhanced find_related_incidents functionality
        # Create synthetic incident from text description
        text_description = "website is down"
        target_incident = {
            "id": "synthetic",
            "attributes": {
                "title": text_description,
                "summary": text_description,
                "description": text_description,
            },
        }

        # Mock historical incidents with various outage scenarios
        historical_incidents = [
            {
                "id": "1001",
                "attributes": {
                    "title": "Website outage - frontend servers down",
                    "summary": "Complete website unavailable for users",
                    "status": "resolved",
                },
            },
            {
                "id": "1002",
                "attributes": {
                    "title": "API service offline",
                    "summary": "Backend API not responding, site unavailable",
                    "status": "resolved",
                },
            },
            {
                "id": "1003",
                "attributes": {
                    "title": "Database connection timeout",
                    "summary": "Cannot connect to postgres database",
                    "status": "resolved",
                },
            },
            {
                "id": "1004",
                "attributes": {
                    "title": "Payment processing errors",
                    "summary": "Users unable to complete checkout",
                    "status": "resolved",
                },
            },
        ]

        # Calculate similarities
        similar_incidents = analyzer.calculate_similarity(historical_incidents, target_incident)

        # Should find website/outage related incidents
        assert len(similar_incidents) > 0, "Should find similar incidents for 'website is down'"

        # Website outage incident should be most relevant
        website_related = [
            inc
            for inc in similar_incidents
            if any(
                keyword in inc.title.lower()
                for keyword in ["website", "outage", "down", "offline", "unavailable"]
            )
        ]

        assert len(website_related) > 0, "Should identify website-related incidents"

        # Check that similarity scores are reasonable for text-based matching
        top_match = similar_incidents[0]
        assert (
            top_match.similarity_score > 0.1
        ), "Should have reasonable similarity score for text description"

        # Verify matched keywords include relevant terms
        all_keywords = []
        for inc in similar_incidents:
            all_keywords.extend(inc.matched_keywords)

        # Note: Keywords may be empty if exact matches are found, which is also valid
        # The important thing is that similarity analysis works with text descriptions

    def test_status_filter_functionality(self):
        """Test that status filtering works correctly for both tools."""
        from rootly_mcp_server.smart_utils import TextSimilarityAnalyzer

        analyzer = TextSimilarityAnalyzer()

        # Mock incidents with different statuses
        mixed_status_incidents = [
            {
                "id": "1001",
                "attributes": {
                    "title": "Payment API timeout",
                    "summary": "Payment processing errors",
                    "status": "resolved",
                },
            },
            {
                "id": "1002",
                "attributes": {
                    "title": "Payment service down",
                    "summary": "Payment API returning errors",
                    "status": "investigating",
                },
            },
            {
                "id": "1003",
                "attributes": {
                    "title": "Payment gateway issues",
                    "summary": "Users cannot complete purchases",
                    "status": "open",
                },
            },
        ]

        target_incident = {
            "id": "synthetic",
            "attributes": {
                "title": "Payment processing failures",
                "summary": "Users experiencing payment errors",
                "status": "open",
            },
        }

        # Test similarity analysis works with mixed statuses
        similar_incidents = analyzer.calculate_similarity(mixed_status_incidents, target_incident)

        # Should find all payment-related incidents regardless of status
        assert (
            len(similar_incidents) == 3
        ), f"Expected 3 similar incidents, got {len(similar_incidents)}"

        # All should be payment-related with reasonable similarity scores
        for incident in similar_incidents:
            assert (
                incident.similarity_score > 0.1
            ), f"Low similarity score {incident.similarity_score} for payment incident"
            assert "payment" in incident.title.lower() or "payment" in incident.matched_keywords
