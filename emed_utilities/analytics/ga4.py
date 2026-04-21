from dataclasses import dataclass

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
