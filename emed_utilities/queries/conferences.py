from dataclasses import dataclass
from datetime import date, datetime

from sqlalchemy import text

from emed_utilities.db.connection import get_session
from emed_utilities.logging_config import get_logger

log = get_logger(__name__)


@dataclass
class Conference:
    id: int
    title: str
    status: str
    startdate: date | None
    enddate: date | None
    created_date: datetime | None
    emed_url: str | None


@dataclass
class ConferenceResult:
    conferences: list[Conference]
    total_found: int
    ignored_status: int
    ignored_date: int

    @property
    def considered(self) -> int:
        return len(self.conferences)


def get_conferences_by_ids(conference_ids: list[int]) -> list[Conference]:
    """Fetch conferences directly by a list of IDs — no organizer or date filtering."""
    if not conference_ids:
        return []
    with get_session() as session:
        rows = session.execute(
            text(
                "SELECT id, title, status, startdate, enddate, created_date, emed_url "
                "FROM tbl_conferences "
                "WHERE id IN :ids"
            ),
            {"ids": tuple(conference_ids)},
        ).fetchall()
    return [
        Conference(
            id=row.id,
            title=row.title,
            status=row.status,
            startdate=row.startdate,
            enddate=row.enddate,
            created_date=row.created_date,
            emed_url=row.emed_url,
        )
        for row in rows
    ]


def get_conferences_by_organizer(
    organizer_name: str,
    from_date: date,
) -> ConferenceResult:
    with get_session() as session:
        org_row = session.execute(
            text("SELECT id FROM tbl_organizations WHERE name = :name"),
            {"name": organizer_name},
        ).fetchone()

        if org_row is None:
            log.warning("organizer_not_found", name=organizer_name)
            return ConferenceResult(conferences=[], total_found=0, ignored_status=0, ignored_date=0)

        org_id = org_row.id
        log.info("organizer_found", name=organizer_name, id=org_id)

        conf_ids = [
            row.conference_id
            for row in session.execute(
                text(
                    "SELECT conference_id FROM tbl_organization_conferences "
                    "WHERE organization_id = :org_id"
                ),
                {"org_id": org_id},
            ).fetchall()
        ]

        if not conf_ids:
            log.info("no_conferences_found", org_id=org_id)
            return ConferenceResult(conferences=[], total_found=0, ignored_status=0, ignored_date=0)

        rows = session.execute(
            text(
                "SELECT id, title, status, startdate, enddate, created_date, emed_url "
                "FROM tbl_conferences "
                "WHERE id IN :ids"
            ),
            {"ids": tuple(conf_ids)},
        ).fetchall()

    total_found = len(rows)
    ignored_status = 0
    ignored_date = 0
    considered: list[Conference] = []

    for row in rows:
        if str(row.status) != "1":
            ignored_status += 1
            continue
        if row.enddate is not None and row.enddate < from_date:
            ignored_date += 1
            continue
        considered.append(
            Conference(
                id=row.id,
                title=row.title,
                status=row.status,
                startdate=row.startdate,
                enddate=row.enddate,
                created_date=row.created_date,
                emed_url=row.emed_url,
            )
        )

    log.info(
        "conferences_filtered",
        total=total_found,
        ignored_status=ignored_status,
        ignored_date=ignored_date,
        considered=len(considered),
    )

    return ConferenceResult(
        conferences=considered,
        total_found=total_found,
        ignored_status=ignored_status,
        ignored_date=ignored_date,
    )
