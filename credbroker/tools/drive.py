"""Google Drive tool adapters."""

import httpx

from credbroker.errors import ProviderCallError
from credbroker.tools.base import ToolAdapter

DRIVE_FILES_URL = "https://www.googleapis.com/drive/v3/files"


class DriveListFilesTool(ToolAdapter):
    """List files in the connected Google Drive (read-only)."""

    name = "drive.read"
    provider = "google"
    scope = "read"
    side_effectful = False

    async def call(
        self, access_token: str, arguments: dict, http_client: httpx.AsyncClient
    ) -> dict:
        params: dict = {
            "pageSize": int(arguments.get("page_size", 25)),
            "fields": "nextPageToken,files(id,name,mimeType,modifiedTime)",
        }
        if query := arguments.get("query"):
            params["q"] = str(query)
        if page_token := arguments.get("page_token"):
            params["pageToken"] = str(page_token)

        response = await http_client.get(
            DRIVE_FILES_URL,
            params=params,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if response.status_code >= 400:
            # Never echo the response body: error payloads are not under our
            # control and must not flow back toward the agent.
            raise ProviderCallError(
                f"drive.read failed with HTTP {response.status_code}",
                status_code=response.status_code,
            )
        return response.json()
