#!/usr/bin/env python3
"""
Example: Using get_oncall_shift_metrics tool

This example demonstrates different ways to query on-call shift metrics.
"""

import asyncio
import os
from rootly_mcp_server.server import create_rootly_mcp_server


async def example_monthly_report():
    """Example 1: Get monthly metrics for all users."""
    print("\n=== Example 1: Monthly Report (All Users) ===")

    # Create the server
    server = create_rootly_mcp_server()

    # Get the tool
    tools = await server.get_tools()
    metrics_tool = None
    for tool in tools:
        if hasattr(tool, 'name') and tool.name == "get_oncall_shift_metrics":
            metrics_tool = tool
            break

    if not metrics_tool:
        print("Tool not found!")
        return

    # Call the tool - this would actually call the Rootly API
    # For this example, we're just showing the parameters
    params = {
        "start_date": "2025-10-01",
        "end_date": "2025-10-31",
        "group_by": "user"
    }

    print(f"Would call: get_oncall_shift_metrics({params})")
    print("\nExpected output:")
    print("""
    {
      "period": {
        "start_date": "2025-10-01",
        "end_date": "2025-10-31"
      },
      "total_shifts": 120,
      "grouped_by": "user",
      "metrics": [
        {
          "user_id": "123",
          "user_name": "John Doe",
          "shift_count": 10,
          "total_hours": 80.0,
          "regular_shifts": 8,
          "override_shifts": 2,
          "average_shift_hours": 8.0
        },
        ...
      ],
      "summary": {
        "total_hours": 960.0,
        "total_regular_shifts": 100,
        "total_override_shifts": 20,
        "unique_people": 15
      }
    }
    """)


async def example_specific_users():
    """Example 2: Get metrics for specific users."""
    print("\n=== Example 2: Specific Users ===")

    params = {
        "start_date": "2025-10-01",
        "end_date": "2025-10-31",
        "user_ids": "123,456,789",  # Comma-separated user IDs
        "group_by": "user"
    }

    print(f"Parameters: {params}")
    print("\nUse case: Track on-call hours for specific team members")


async def example_team_filtering():
    """Example 3: Get metrics for specific teams."""
    print("\n=== Example 3: Filter by Team ===")

    params = {
        "start_date": "2025-10-01",
        "end_date": "2025-10-31",
        "team_ids": "team-backend,team-frontend",  # Comma-separated team IDs
        "group_by": "user"
    }

    print(f"Parameters: {params}")
    print("\nNote: This will:")
    print("1. Query /v1/schedules to find schedules for these teams")
    print("2. Get schedule IDs")
    print("3. Query /v1/shifts filtered by those schedule IDs")


async def example_schedule_filtering():
    """Example 4: Get metrics for specific schedules."""
    print("\n=== Example 4: Filter by Schedule ===")

    params = {
        "start_date": "2025-10-01",
        "end_date": "2025-10-31",
        "schedule_ids": "schedule-1,schedule-2",
        "group_by": "schedule"
    }

    print(f"Parameters: {params}")
    print("\nUse case: Compare on-call load across different schedules")


async def example_quarterly_report():
    """Example 5: Quarterly report grouped by team."""
    print("\n=== Example 5: Quarterly Report ===")

    params = {
        "start_date": "2025-10-01",
        "end_date": "2025-12-31",
        "group_by": "team"
    }

    print(f"Parameters: {params}")
    print("\nUse case: Q4 2025 compensation report for finance")


async def example_override_analysis():
    """Example 6: Analyze override shifts (holidays, swaps)."""
    print("\n=== Example 6: Override Shift Analysis ===")

    params = {
        "start_date": "2025-12-15",  # Holiday period
        "end_date": "2026-01-05",
        "group_by": "user"
    }

    print(f"Parameters: {params}")
    print("\nUse case: See who covered holiday shifts")
    print("The response will include 'override_shifts' count for each user")


async def example_with_api_call():
    """Example 7: Actual API call (requires ROOTLY_API_TOKEN)."""
    print("\n=== Example 7: Real API Call ===")

    if not os.getenv("ROOTLY_API_TOKEN"):
        print("⚠️  ROOTLY_API_TOKEN not set - skipping actual API call")
        print("\nTo run this example:")
        print("  export ROOTLY_API_TOKEN='your-token-here'")
        print("  python examples/oncall_metrics_example.py")
        return

    try:
        _ = create_rootly_mcp_server()

        # This would make actual API calls to Rootly
        print("Making real API call to Rootly...")
        print("(Implementation depends on MCP server being fully initialized)")

    except Exception as e:
        print(f"Error: {e}")


async def main():
    """Run all examples."""
    print("=" * 60)
    print("ON-CALL SHIFT METRICS - USAGE EXAMPLES")
    print("=" * 60)

    await example_monthly_report()
    await example_specific_users()
    await example_team_filtering()
    await example_schedule_filtering()
    await example_quarterly_report()
    await example_override_analysis()
    await example_with_api_call()

    print("\n" + "=" * 60)
    print("COMMON USE CASES")
    print("=" * 60)
    print("""
    1. Monthly Compensation Reports:
       - Group by user
       - Filter by team if needed
       - Export total_hours for payroll

    2. Workload Distribution Analysis:
       - Group by user
       - Sort by shift_count
       - Identify overworked team members

    3. Team Performance Metrics:
       - Group by team
       - Compare shift coverage across teams

    4. Holiday Coverage Tracking:
       - Set date range around holidays
       - Check override_shifts count
       - Ensure fair distribution

    5. Schedule Effectiveness:
       - Group by schedule
       - Compare regular vs override ratios
       - Optimize rotation schedules
    """)


if __name__ == "__main__":
    asyncio.run(main())
