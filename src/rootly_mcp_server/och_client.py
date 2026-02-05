"""On-Call Health API client for burnout risk analysis."""

import os

import httpx


class OnCallHealthClient:
    def __init__(self, api_key: str = None, base_url: str = None):
        self.api_key = api_key or os.environ.get("ONCALLHEALTH_API_KEY")
        self.base_url = base_url or os.environ.get(
            "ONCALLHEALTH_API_URL", "https://api.oncallhealth.ai"
        )

    async def get_analysis(self, analysis_id: int) -> dict:
        """Fetch analysis by ID."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/analyses/{analysis_id}",
                headers={"X-API-Key": self.api_key},
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def get_latest_analysis(self) -> dict:
        """Fetch most recent analysis."""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.base_url}/analyses",
                headers={"X-API-Key": self.api_key},
                params={"limit": 1},
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()
            analyses = data.get("analyses", [])
            if not analyses:
                raise ValueError("No analyses found")
            return analyses[0]

    def extract_at_risk_users(self, analysis: dict, threshold: float = 50.0) -> tuple[list, list]:
        """Extract at-risk and safe users from analysis."""
        members = analysis.get("analysis_data", {}).get("team_analysis", {}).get("members", [])

        at_risk = []
        safe = []

        for member in members:
            user_data = {
                "user_name": member.get("user_name"),
                "rootly_user_id": member.get("rootly_user_id"),
                "och_score": member.get("och_score", 0),
                "risk_level": member.get("risk_level", "unknown"),
                "burnout_score": member.get("burnout_score", 0),
                "incident_count": member.get("incident_count", 0),
            }

            if user_data["och_score"] >= threshold:
                at_risk.append(user_data)
            elif user_data["och_score"] < 20:  # Safe threshold
                safe.append(user_data)

        # Sort at-risk by score descending, safe by score ascending
        at_risk.sort(key=lambda x: x["och_score"], reverse=True)
        safe.sort(key=lambda x: x["och_score"])

        return at_risk, safe
