"""Fake Google Drive API for credential-free local demos.

A standalone FastAPI app that mimics just enough of the Drive v3 ``files.list``
endpoint that the full grant -> invoke -> audit loop runs locally with zero
Google credentials: point the broker at it via
``CREDBROKER_DRIVE_API_BASE_URL`` (docker-compose does this) and
``drive.read`` invocations return the canned listing below instead of calling
Google.

Faithful only where the broker cares: a ``Bearer`` Authorization header is
required (401 without one — the token's value is never checked, it is a fake
credential anyway), the response is Drive-shaped (``{"files": [{id, name,
mimeType, modifiedTime}, ...]}``), and ``pageSize`` / ``q`` are honored
superficially (truncation and a substring filter on the file name). There is
no pagination, so no ``nextPageToken``.

Run it with ``python -m credbroker.demo.fake_drive`` (port
``CREDBROKER_FAKE_DRIVE_PORT``, default 9100). Deliberately dependency-free
beyond fastapi/uvicorn — no database, no settings object, no broker imports.
"""

import os

from fastapi import FastAPI, Header, HTTPException, Query

SAMPLE_FILES: list[dict] = [
    {
        "id": "1a2b3c4d5e6f-quarterly-report",
        "name": "Quarterly Report Q3.pdf",
        "mimeType": "application/pdf",
        "modifiedTime": "2026-08-14T09:12:33.000Z",
    },
    {
        "id": "2b3c4d5e6f7a-roadmap",
        "name": "Product Roadmap 2027",
        "mimeType": "application/vnd.google-apps.document",
        "modifiedTime": "2026-08-21T16:45:01.000Z",
    },
    {
        "id": "3c4d5e6f7a8b-budget",
        "name": "Budget Forecast.xlsx",
        "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "modifiedTime": "2026-07-30T11:02:47.000Z",
    },
    {
        "id": "4d5e6f7a8b9c-onboarding",
        "name": "Onboarding Checklist",
        "mimeType": "application/vnd.google-apps.document",
        "modifiedTime": "2026-06-18T08:20:15.000Z",
    },
    {
        "id": "5e6f7a8b9c0d-team-photo",
        "name": "Team Offsite Photo.png",
        "mimeType": "image/png",
        "modifiedTime": "2026-05-09T19:33:58.000Z",
    },
    {
        "id": "6f7a8b9c0d1e-metrics",
        "name": "Metrics Dashboard Notes",
        "mimeType": "application/vnd.google-apps.spreadsheet",
        "modifiedTime": "2026-08-27T14:07:22.000Z",
    },
    {
        "id": "7a8b9c0d1e2f-launch-plan",
        "name": "Launch Plan Draft.docx",
        "mimeType": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "modifiedTime": "2026-08-02T10:55:09.000Z",
    },
]


def _name_needle(q: str) -> str:
    """Reduce a Drive query to a plain substring to match against names.

    Real Drive queries look like ``name contains 'report'``; a demo caller may
    also send a bare word. Either way, use the single-quoted term when there
    is one, the raw string otherwise.
    """
    _, quote, rest = q.partition("'")
    if quote and "'" in rest:
        return rest[: rest.index("'")]
    return q


def create_app() -> FastAPI:
    app = FastAPI(title="Fake Google Drive", docs_url=None, redoc_url=None)

    @app.get("/healthz")
    async def healthz() -> dict:
        # The shared Docker image bakes in a HEALTHCHECK; compose points it
        # here for this service.
        return {"status": "ok"}

    @app.get("/files")
    async def list_files(
        authorization: str | None = Header(default=None),
        pageSize: int | None = Query(default=None),  # camelCase: Drive API parameter
        q: str | None = Query(default=None),
    ) -> dict:
        if authorization is None or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing Bearer authorization")

        files = SAMPLE_FILES
        if q:
            needle = _name_needle(q).lower()
            files = [f for f in files if needle in f["name"].lower()]
        if pageSize is not None and pageSize >= 0:
            files = files[:pageSize]
        return {"files": files}

    return app


app = create_app()


def main() -> None:
    import uvicorn

    port = int(os.environ.get("CREDBROKER_FAKE_DRIVE_PORT", "9100"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")


if __name__ == "__main__":
    main()
