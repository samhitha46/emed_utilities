from dataclasses import dataclass
from datetime import date, timedelta

from google.analytics.data_v1beta import BetaAnalyticsDataClient
from google.analytics.data_v1beta.types import (
    DateRange,
    Dimension,
    FilterExpression,
    FilterExpressionList,
    Filter,
    Metric,
    RunReportRequest,
)
from google.oauth2 import service_account

from emed_utilities.config import get_settings
from emed_utilities.logging_config import get_logger

log = get_logger(__name__)


@dataclass
class PageMetrics:
    page_path: str
    users: int
    pageviews: int


@dataclass
class WeeklyPlatformMetrics:
    year_week: str           # GA4 YYYYWW, e.g. "202501"
    week_start: str          # ISO date of the Sunday that opens that week
    total_users: int
    new_users: int
    returning_users: int
    sessions: int
    engagement_rate: float   # 0.0–1.0
    avg_session_duration_sec: float
    pageviews: int


def _yearweek_to_date(yw: str) -> date:
    """Convert GA4 yearWeek (YYYYWW, Sunday-based) to the opening Sunday."""
    year, week = int(yw[:4]), int(yw[4:])
    jan1 = date(year, 1, 1)
    # Sunday on or before Jan 1 = start of GA4 week 1
    # weekday(): Mon=0 … Sun=6, so days back to prior Sunday = (weekday+1) % 7
    week1_sunday = jan1 - timedelta(days=(jan1.weekday() + 1) % 7)
    return week1_sunday + timedelta(weeks=week - 1)


def _get_client() -> BetaAnalyticsDataClient:
    settings = get_settings()
    credentials = service_account.Credentials.from_service_account_file(
        settings.ga4_credentials_file,
        scopes=["https://www.googleapis.com/auth/analytics.readonly"],
    )
    return BetaAnalyticsDataClient(credentials=credentials)


def get_page_metrics(
    page_paths: list[str],
    start_date: str,
    end_date: str,
) -> dict[str, PageMetrics]:
    """Query GA4 for Users and Pageviews for a list of page paths.

    Args:
        page_paths: list of emed_url slugs e.g. ['bahamas-liveaboard-...']
        start_date: 'YYYY-MM-DD'
        end_date:   'YYYY-MM-DD'

    Returns:
        dict keyed by page_path slug → PageMetrics
    """
    settings = get_settings()
    client   = _get_client()

    # GA4 stores paths like /c/bahamas-liveaboard-...
    # Build one filter per path joined with OR
    path_filters = FilterExpressionList(
        expressions=[
            FilterExpression(
                filter=Filter(
                    field_name="pagePath",
                    string_filter=Filter.StringFilter(
                        value=slug,
                        match_type=Filter.StringFilter.MatchType.CONTAINS,
                    ),
                )
            )
            for slug in page_paths
        ]
    )

    request = RunReportRequest(
        property=f"properties/{settings.ga4_property_id}",
        date_ranges=[DateRange(start_date=start_date, end_date=end_date)],
        dimensions=[Dimension(name="pagePath")],
        metrics=[
            Metric(name="totalUsers"),
            Metric(name="screenPageViews"),
        ],
        dimension_filter=FilterExpression(or_group=path_filters),
    )

    response = client.run_report(request)
    log.info("ga4_query_complete", rows=len(response.rows), paths=len(page_paths))

    results: dict[str, PageMetrics] = {}
    for row in response.rows:
        full_path = row.dimension_values[0].value
        users     = int(row.metric_values[0].value)
        pageviews = int(row.metric_values[1].value)
        for slug in page_paths:
            if slug in full_path:
                if slug in results:
                    results[slug] = PageMetrics(
                        page_path=results[slug].page_path,
                        users=results[slug].users + users,
                        pageviews=results[slug].pageviews + pageviews,
                    )
                else:
                    results[slug] = PageMetrics(
                        page_path=full_path,
                        users=users,
                        pageviews=pageviews,
                    )
                break

    return results


def get_weekly_platform_metrics(weeks: int = 52) -> list[WeeklyPlatformMetrics]:
    """Query GA4 for platform-level metrics aggregated by week.

    Args:
        weeks: how many weeks of history to fetch (default 52 = 1 year)

    Returns:
        list of WeeklyPlatformMetrics sorted oldest → newest
    """
    settings = get_settings()
    client = _get_client()

    request = RunReportRequest(
        property=f"properties/{settings.ga4_property_id}",
        date_ranges=[DateRange(
            start_date=f"{weeks * 7}daysAgo",
            end_date="yesterday",
        )],
        dimensions=[Dimension(name="yearWeek")],
        metrics=[
            Metric(name="totalUsers"),
            Metric(name="newUsers"),
            Metric(name="sessions"),
            Metric(name="engagementRate"),
            Metric(name="averageSessionDuration"),
            Metric(name="screenPageViews"),
        ],
    )

    response = client.run_report(request)
    log.info("ga4_weekly_query_complete", rows=len(response.rows), weeks=weeks)

    results: list[WeeklyPlatformMetrics] = []
    for row in response.rows:
        yw = row.dimension_values[0].value
        total_users = int(row.metric_values[0].value)
        new_users = int(row.metric_values[1].value)
        sessions = int(row.metric_values[2].value)
        engagement_rate = float(row.metric_values[3].value)
        avg_duration = float(row.metric_values[4].value)
        pageviews = int(row.metric_values[5].value)

        results.append(WeeklyPlatformMetrics(
            year_week=yw,
            week_start=_yearweek_to_date(yw).isoformat(),
            total_users=total_users,
            new_users=new_users,
            returning_users=max(0, total_users - new_users),
            sessions=sessions,
            engagement_rate=round(engagement_rate, 4),
            avg_session_duration_sec=round(avg_duration, 1),
            pageviews=pageviews,
        ))

    return sorted(results, key=lambda r: r.year_week)
