"""Tests for the fake Drive provider (credbroker.demo.fake_drive).

Driven through httpx.ASGITransport against the app object — no sockets, no
uvicorn. The fake exists so the demo stack works with zero Google
credentials; these tests pin the contract the broker's drive.read tool relies
on: Drive-v3-shaped payload, Bearer auth required, superficial pageSize/q
handling.
"""

import httpx
import pytest

from credbroker.demo.fake_drive import SAMPLE_FILES, app

AUTH = {"Authorization": "Bearer demo-access-token-not-a-real-credential"}


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://fake-drive") as c:
        yield c


async def test_files_payload_is_drive_shaped(client):
    response = await client.get("/files", headers=AUTH)

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"files"}  # no nextPageToken: the fake never paginates
    assert 6 <= len(body["files"]) <= 8
    for entry in body["files"]:
        assert set(entry) == {"id", "name", "mimeType", "modifiedTime"}
        assert all(isinstance(value, str) and value for value in entry.values())


async def test_files_requires_bearer_authorization(client):
    no_header = await client.get("/files")
    assert no_header.status_code == 401

    wrong_scheme = await client.get(
        "/files", headers={"Authorization": "Basic ZGVtbzpkZW1v"}
    )
    assert wrong_scheme.status_code == 401


async def test_page_size_truncates(client):
    response = await client.get("/files", params={"pageSize": 2}, headers=AUTH)

    assert response.status_code == 200
    assert len(response.json()["files"]) == 2


async def test_q_filters_by_name_substring(client):
    response = await client.get("/files", params={"q": "Roadmap"}, headers=AUTH)

    assert response.status_code == 200
    names = [f["name"] for f in response.json()["files"]]
    assert names == [f["name"] for f in SAMPLE_FILES if "Roadmap" in f["name"]]
    assert names  # the fixture data must actually exercise the filter


async def test_q_accepts_drive_query_syntax(client):
    # The broker forwards agent-supplied Drive queries verbatim; the fake
    # extracts the quoted term so `name contains '...'` behaves sensibly.
    response = await client.get(
        "/files", params={"q": "name contains 'budget'"}, headers=AUTH
    )

    assert response.status_code == 200
    names = [f["name"] for f in response.json()["files"]]
    assert names == ["Budget Forecast.xlsx"]


async def test_q_with_no_match_returns_empty_list(client):
    response = await client.get(
        "/files", params={"q": "no-such-file-anywhere"}, headers=AUTH
    )

    assert response.status_code == 200
    assert response.json() == {"files": []}
