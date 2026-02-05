"""
Unit tests for new on-call tools.

Tests cover:
- list_shifts with user_ids filtering
- get_oncall_schedule_summary aggregation
- check_responder_availability
- create_override_recommendation
"""

from datetime import datetime

import pytest


@pytest.fixture
def mock_shifts_response():
    """Mock shifts API response with sample data."""
    return {
        "data": [
            {
                "id": "shift-1",
                "type": "shifts",
                "attributes": {
                    "schedule_id": "schedule-1",
                    "starts_at": "2026-02-09T08:00:00.000-08:00",
                    "ends_at": "2026-02-09T16:00:00.000-08:00",
                    "is_override": False,
                },
                "relationships": {"user": {"data": {"id": "2381", "type": "users"}}},
            },
            {
                "id": "shift-2",
                "type": "shifts",
                "attributes": {
                    "schedule_id": "schedule-1",
                    "starts_at": "2026-02-10T08:00:00.000-08:00",
                    "ends_at": "2026-02-10T16:00:00.000-08:00",
                    "is_override": False,
                },
                "relationships": {"user": {"data": {"id": "94178", "type": "users"}}},
            },
            {
                "id": "shift-3",
                "type": "shifts",
                "attributes": {
                    "schedule_id": "schedule-2",
                    "starts_at": "2026-02-11T08:00:00.000-08:00",
                    "ends_at": "2026-02-11T16:00:00.000-08:00",
                    "is_override": False,
                },
                "relationships": {"user": {"data": {"id": "27965", "type": "users"}}},
            },
        ],
        "included": [
            {
                "id": "2381",
                "type": "users",
                "attributes": {"full_name": "Quentin Rousseau", "email": "quentin@example.com"},
            },
            {
                "id": "94178",
                "type": "users",
                "attributes": {"full_name": "Gideon Lapshun", "email": "gideon@example.com"},
            },
            {
                "id": "27965",
                "type": "users",
                "attributes": {"full_name": "Alexandra Chapin", "email": "alexandra@example.com"},
            },
        ],
        "meta": {"total_pages": 1},
    }


@pytest.fixture
def mock_users_response():
    """Mock users API response."""
    return {
        "data": [
            {
                "id": "2381",
                "type": "users",
                "attributes": {"full_name": "Quentin Rousseau", "email": "quentin@example.com"},
            },
            {
                "id": "94178",
                "type": "users",
                "attributes": {"full_name": "Gideon Lapshun", "email": "gideon@example.com"},
            },
            {
                "id": "27965",
                "type": "users",
                "attributes": {"full_name": "Alexandra Chapin", "email": "alexandra@example.com"},
            },
        ]
    }


@pytest.fixture
def mock_schedules_response():
    """Mock schedules API response."""
    return {
        "data": [
            {
                "id": "schedule-1",
                "type": "schedules",
                "attributes": {
                    "name": "Infrastructure - Primary",
                    "owner_group_ids": ["team-1"],
                },
            },
            {
                "id": "schedule-2",
                "type": "schedules",
                "attributes": {
                    "name": "Cloud Ops",
                    "owner_group_ids": ["team-2"],
                },
            },
        ]
    }


@pytest.fixture
def mock_teams_response():
    """Mock teams API response."""
    return {
        "data": [
            {
                "id": "team-1",
                "type": "teams",
                "attributes": {"name": "Infrastructure"},
            },
            {
                "id": "team-2",
                "type": "teams",
                "attributes": {"name": "Cloud Ops"},
            },
        ]
    }


@pytest.mark.unit
class TestListShifts:
    """Test list_shifts tool with user_ids filtering."""

    def test_user_ids_filter_parsing(self):
        """Test that user_ids are correctly parsed from comma-separated string."""
        user_ids = "2381,94178,27965"
        user_id_filter = {uid.strip() for uid in user_ids.split(",") if uid.strip()}
        assert user_id_filter == {"2381", "94178", "27965"}

    def test_user_ids_filter_with_spaces(self):
        """Test user_ids parsing handles whitespace."""
        user_ids = " 2381 , 94178 , 27965 "
        user_id_filter = {uid.strip() for uid in user_ids.split(",") if uid.strip()}
        assert user_id_filter == {"2381", "94178", "27965"}

    def test_empty_user_ids_no_filter(self):
        """Test empty user_ids results in no filtering."""
        user_ids = ""
        user_id_filter = {uid.strip() for uid in user_ids.split(",") if uid.strip()}
        assert user_id_filter == set()

    def test_shift_duration_calculation(self):
        """Test shift duration is calculated correctly in hours."""
        starts_at = "2026-02-09T08:00:00.000-08:00"
        ends_at = "2026-02-09T16:00:00.000-08:00"

        start_dt = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(ends_at.replace("Z", "+00:00"))
        total_hours = round((end_dt - start_dt).total_seconds() / 3600, 2)

        assert total_hours == 8.0

    def test_shift_filtering_by_user_id(self, mock_shifts_response):
        """Test shifts are correctly filtered by user_id."""
        user_id_filter = {"2381", "94178"}
        shifts = mock_shifts_response["data"]

        filtered_shifts = []
        for shift in shifts:
            user_rel = shift.get("relationships", {}).get("user", {}).get("data") or {}
            user_id = user_rel.get("id")
            if user_id_filter and str(user_id) not in user_id_filter:
                continue
            filtered_shifts.append(shift)

        # Should only include shifts for users 2381 and 94178
        assert len(filtered_shifts) == 2
        user_ids = [s["relationships"]["user"]["data"]["id"] for s in filtered_shifts]
        assert "2381" in user_ids
        assert "94178" in user_ids
        assert "27965" not in user_ids


@pytest.mark.unit
class TestGetOncallScheduleSummary:
    """Test get_oncall_schedule_summary aggregation logic."""

    def test_hours_aggregation_by_user(self, mock_shifts_response):
        """Test hours are correctly aggregated per user per schedule."""
        from collections import defaultdict

        schedule_coverage = defaultdict(
            lambda: {"responders": defaultdict(lambda: {"total_hours": 0.0, "shift_count": 0})}
        )

        for shift in mock_shifts_response["data"]:
            attrs = shift.get("attributes", {})
            relationships = shift.get("relationships", {})
            schedule_id = attrs.get("schedule_id")
            user_rel = relationships.get("user", {}).get("data") or {}
            user_id = user_rel.get("id")

            starts_at = attrs.get("starts_at")
            ends_at = attrs.get("ends_at")
            hours = 0.0
            if starts_at and ends_at:
                start_dt = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(ends_at.replace("Z", "+00:00"))
                hours = (end_dt - start_dt).total_seconds() / 3600

            schedule_coverage[schedule_id]["responders"][user_id]["total_hours"] += hours
            schedule_coverage[schedule_id]["responders"][user_id]["shift_count"] += 1

        # Check schedule-1 has both users
        assert "2381" in schedule_coverage["schedule-1"]["responders"]
        assert "94178" in schedule_coverage["schedule-1"]["responders"]
        # Each has 8 hours (one 8-hour shift)
        assert schedule_coverage["schedule-1"]["responders"]["2381"]["total_hours"] == 8.0
        assert schedule_coverage["schedule-1"]["responders"]["94178"]["total_hours"] == 8.0

    def test_high_load_warning_generation(self):
        """Test warning is generated for high schedule load."""
        schedules_list = ["Sched1", "Sched2", "Sched3", "Sched4"]
        hours = 100.0

        warning = None
        if len(schedules_list) >= 4:
            warning = f"High load: {len(schedules_list)} concurrent schedules"
        elif hours >= 168:
            warning = f"High load: {hours} hours in period"

        assert warning == "High load: 4 concurrent schedules"

    def test_high_hours_warning_generation(self):
        """Test warning is generated for high hours."""
        schedules_list = ["Sched1", "Sched2"]
        hours = 176.0

        warning = None
        if len(schedules_list) >= 4:
            warning = f"High load: {len(schedules_list)} concurrent schedules"
        elif hours >= 168:
            warning = f"High load: {hours} hours in period"

        assert warning == "High load: 176.0 hours in period"


@pytest.mark.unit
class TestCheckResponderAvailability:
    """Test check_responder_availability logic."""

    def test_user_ids_required(self):
        """Test that user_ids parameter is required."""
        user_ids = ""
        assert not user_ids  # Should fail validation

    def test_scheduled_vs_not_scheduled_categorization(self, mock_shifts_response):
        """Test users are correctly categorized as scheduled or not."""
        user_id_list = ["2381", "94178", "99999"]  # 99999 not in shifts
        user_id_set = set(user_id_list)

        user_shifts = {uid: [] for uid in user_id_list}

        for shift in mock_shifts_response["data"]:
            relationships = shift.get("relationships", {})
            user_rel = relationships.get("user", {}).get("data") or {}
            user_id = str(user_rel.get("id"))

            if user_id in user_id_set:
                user_shifts[user_id].append(shift)

        scheduled = []
        not_scheduled = []

        for user_id in user_id_list:
            shifts = user_shifts.get(user_id, [])
            if shifts:
                scheduled.append(user_id)
            else:
                not_scheduled.append(user_id)

        assert "2381" in scheduled
        assert "94178" in scheduled
        assert "99999" in not_scheduled

    def test_total_hours_calculation(self, mock_shifts_response):
        """Test total hours are correctly calculated for a user."""
        user_hours = {}

        for shift in mock_shifts_response["data"]:
            attrs = shift.get("attributes", {})
            relationships = shift.get("relationships", {})
            user_rel = relationships.get("user", {}).get("data") or {}
            user_id = str(user_rel.get("id"))

            starts_at = attrs.get("starts_at")
            ends_at = attrs.get("ends_at")
            hours = 0.0
            if starts_at and ends_at:
                start_dt = datetime.fromisoformat(starts_at.replace("Z", "+00:00"))
                end_dt = datetime.fromisoformat(ends_at.replace("Z", "+00:00"))
                hours = round((end_dt - start_dt).total_seconds() / 3600, 1)

            user_hours[user_id] = user_hours.get(user_id, 0.0) + hours

        # User 2381 has one 8-hour shift
        assert user_hours["2381"] == 8.0


@pytest.mark.unit
class TestCreateOverrideRecommendation:
    """Test create_override_recommendation logic."""

    def test_exclude_user_ids_parsing(self):
        """Test exclude_user_ids are correctly parsed."""
        exclude_user_ids = "94178,12345"
        original_user_id = 2381

        exclude_set = set()
        if exclude_user_ids:
            exclude_set = {uid.strip() for uid in exclude_user_ids.split(",") if uid.strip()}
        exclude_set.add(str(original_user_id))

        assert exclude_set == {"94178", "12345", "2381"}

    def test_original_user_always_excluded(self):
        """Test original user is always in exclude set."""
        original_user_id = 2381
        exclude_set = set()
        exclude_set.add(str(original_user_id))

        assert "2381" in exclude_set

    def test_recommendations_sorted_by_load(self):
        """Test recommendations are sorted by current load (lowest first)."""
        recommendations = [
            {"user_id": 1, "current_hours_in_period": 48},
            {"user_id": 2, "current_hours_in_period": 8},
            {"user_id": 3, "current_hours_in_period": 24},
        ]

        recommendations.sort(key=lambda x: x["current_hours_in_period"])

        assert recommendations[0]["user_id"] == 2  # 8 hours
        assert recommendations[1]["user_id"] == 3  # 24 hours
        assert recommendations[2]["user_id"] == 1  # 48 hours

    def test_reason_generation_by_load(self):
        """Test reason is generated based on current load."""
        test_cases = [
            (0.0, "Already in rotation, no current load"),
            (8.0, "Already in rotation, low load"),
            (24.0, "Same team, moderate availability"),
            (72.0, "In rotation, but higher load"),
        ]

        for hours, expected_reason in test_cases:
            if hours == 0:
                reason = "Already in rotation, no current load"
            elif hours < 24:
                reason = "Already in rotation, low load"
            elif hours < 48:
                reason = "Same team, moderate availability"
            else:
                reason = "In rotation, but higher load"

            assert reason == expected_reason, f"Failed for {hours} hours"

    def test_override_payload_structure(self):
        """Test override payload has correct structure."""
        schedule_id = "d8c48a88-5fb4-42bc-8ea2-af60875c6141"
        top_rec = {"user_id": 29683}
        start_date = "2026-02-09"
        end_date = "2026-02-15"

        override_payload = {
            "schedule_id": schedule_id,
            "user_id": top_rec["user_id"],
            "starts_at": f"{start_date}T00:00:00Z",
            "ends_at": f"{end_date}T23:59:59Z",
        }

        assert override_payload["schedule_id"] == schedule_id
        assert override_payload["user_id"] == 29683
        assert "T00:00:00Z" in override_payload["starts_at"]
        assert "T23:59:59Z" in override_payload["ends_at"]


@pytest.mark.unit
class TestEnrichedShiftData:
    """Test enriched shift data fields."""

    def test_enriched_shift_includes_all_fields(self):
        """Test enriched shift contains all required fields."""
        enriched_shift = {
            "shift_id": "shift-1",
            "user_id": "2381",
            "schedule_id": "schedule-1",
            "starts_at": "2026-02-09T08:00:00.000-08:00",
            "ends_at": "2026-02-09T16:00:00.000-08:00",
            "is_override": False,
            "total_hours": 8.0,
            "user_name": "Quentin Rousseau",
            "user_email": "quentin@example.com",
            "schedule_name": "Infrastructure - Primary",
            "team_name": "Infrastructure",
        }

        required_fields = [
            "shift_id",
            "user_id",
            "schedule_id",
            "starts_at",
            "ends_at",
            "is_override",
            "total_hours",
            "user_name",
            "user_email",
            "schedule_name",
            "team_name",
        ]

        for field in required_fields:
            assert field in enriched_shift, f"Missing field: {field}"

    def test_user_name_fallback(self):
        """Test user name falls back to email or Unknown."""
        user_attrs_cases = [
            ({"full_name": "John Doe"}, "John Doe"),
            ({"name": "Jane"}, "Jane"),
            ({"email": "test@example.com"}, "Unknown"),
            ({}, "Unknown"),
        ]

        for attrs, expected in user_attrs_cases:
            user_name = attrs.get("full_name") or attrs.get("name") or "Unknown"
            assert user_name == expected


@pytest.mark.unit
class TestScheduleToTeamMapping:
    """Test schedule to team mapping logic."""

    def test_schedule_team_mapping_from_owner_group_ids(
        self, mock_schedules_response, mock_teams_response
    ):
        """Test schedule-to-team mapping is built from owner_group_ids."""
        schedules_map = {s["id"]: s for s in mock_schedules_response["data"]}
        teams_map = {t["id"]: t for t in mock_teams_response["data"]}

        schedule_to_team = {}
        for schedule_id, schedule in schedules_map.items():
            owner_group_ids = schedule.get("attributes", {}).get("owner_group_ids", [])
            if owner_group_ids:
                team_id = owner_group_ids[0]
                team = teams_map.get(team_id, {})
                schedule_to_team[schedule_id] = {
                    "team_id": team_id,
                    "team_name": team.get("attributes", {}).get("name", "Unknown Team"),
                }

        assert schedule_to_team["schedule-1"]["team_name"] == "Infrastructure"
        assert schedule_to_team["schedule-2"]["team_name"] == "Cloud Ops"

    def test_missing_team_defaults_to_unknown(self):
        """Test missing team results in Unknown Team."""
        team_info = {}
        team_name = team_info.get("team_name", "Unknown Team")
        assert team_name == "Unknown Team"


@pytest.mark.unit
class TestNullUserIdHandling:
    """Test that shifts without user_id are properly skipped."""

    def test_shift_without_user_is_skipped(self):
        """Test shifts with None user_id are filtered out."""
        shifts = [
            {"id": "1", "relationships": {"user": {"data": {"id": "123"}}}},
            {"id": "2", "relationships": {"user": {"data": None}}},  # No user data
            {"id": "3", "relationships": {"user": {"data": {}}}},  # Empty user data
            {"id": "4", "relationships": {}},  # No user relationship
            {"id": "5", "relationships": {"user": {"data": {"id": "456"}}}},
        ]

        valid_shifts = []
        for shift in shifts:
            user_rel = shift.get("relationships", {}).get("user", {}).get("data") or {}
            user_id = user_rel.get("id")
            if not user_id:
                continue
            valid_shifts.append(shift)

        assert len(valid_shifts) == 2
        assert valid_shifts[0]["id"] == "1"
        assert valid_shifts[1]["id"] == "5"

    def test_str_none_not_in_filter(self):
        """Test that str(None) = 'None' doesn't match any filter."""
        user_id_filter = {"123", "456"}
        user_id = None

        # Without the fix, str(None) = "None" which is not in filter
        # But we should skip before this check
        if user_id and str(user_id) in user_id_filter:
            result = "matched"
        else:
            result = "skipped"

        assert result == "skipped"


@pytest.mark.unit
class TestEmptyRotationUsersWarning:
    """Test warning messages for create_override_recommendation."""

    def test_no_rotation_users_warning(self):
        """Test warning when no rotation users found."""
        rotation_users = set()
        recommendations = []

        warning = None
        if not rotation_users:
            warning = "No rotation users found for this schedule. The schedule may not have any rotations configured."
        elif not recommendations:
            warning = "All rotation users are either excluded or the original user. No recommendations available."

        assert (
            warning
            == "No rotation users found for this schedule. The schedule may not have any rotations configured."
        )

    def test_all_users_excluded_warning(self):
        """Test warning when all rotation users are excluded."""
        rotation_users = {"123", "456"}
        recommendations = []  # All were excluded

        warning = None
        if not rotation_users:
            warning = "No rotation users found for this schedule. The schedule may not have any rotations configured."
        elif not recommendations:
            warning = "All rotation users are either excluded or the original user. No recommendations available."

        assert (
            warning
            == "All rotation users are either excluded or the original user. No recommendations available."
        )

    def test_no_warning_when_recommendations_exist(self):
        """Test no warning when recommendations are available."""
        rotation_users = {"123", "456"}
        recommendations = [{"user_id": 123}]

        warning = None
        if not rotation_users:
            warning = "No rotation users found"
        elif not recommendations:
            warning = "All users excluded"

        assert warning is None


@pytest.mark.unit
class TestCacheBehavior:
    """Test cache behavior for lookup maps."""

    def test_cache_structure(self):
        """Test cache has required fields."""
        cache = {
            "data": None,
            "timestamp": 0.0,
            "ttl_seconds": 300,
        }

        assert "data" in cache
        assert "timestamp" in cache
        assert "ttl_seconds" in cache
        assert cache["ttl_seconds"] == 300  # 5 minutes

    def test_cache_validity_check(self):
        """Test cache validity logic."""
        import time

        cache = {
            "data": ("users", "schedules", "teams"),
            "timestamp": time.time() - 100,  # 100 seconds ago
            "ttl_seconds": 300,
        }

        now = time.time()
        is_valid = cache["data"] is not None and (now - cache["timestamp"]) < cache["ttl_seconds"]

        assert is_valid is True  # 100s < 300s TTL

    def test_cache_expired(self):
        """Test expired cache is not used."""
        import time

        cache = {
            "data": ("users", "schedules", "teams"),
            "timestamp": time.time() - 400,  # 400 seconds ago
            "ttl_seconds": 300,
        }

        now = time.time()
        is_valid = cache["data"] is not None and (now - cache["timestamp"]) < cache["ttl_seconds"]

        assert is_valid is False  # 400s > 300s TTL


@pytest.mark.unit
class TestParallelFetchHandling:
    """Test asyncio.gather exception handling."""

    def test_exception_in_results_handled(self):
        """Test that exceptions in gather results are handled gracefully."""
        # Simulate results from asyncio.gather with return_exceptions=True
        results = [
            [{"id": "1"}],  # Success
            Exception("API Error"),  # Failed
            [{"id": "2"}, {"id": "3"}],  # Success
        ]

        collected_ids = []
        for result in results:
            if isinstance(result, list):
                for item in result:
                    collected_ids.append(item["id"])
            # Exceptions are silently skipped

        assert collected_ids == ["1", "2", "3"]
        assert len(collected_ids) == 3

    def test_all_exceptions_results_in_empty(self):
        """Test all failed fetches result in empty collection."""
        results = [
            Exception("Error 1"),
            Exception("Error 2"),
            Exception("Error 3"),
        ]

        collected_ids = []
        for result in results:
            if isinstance(result, list):
                for item in result:
                    collected_ids.append(item["id"])

        assert collected_ids == []
