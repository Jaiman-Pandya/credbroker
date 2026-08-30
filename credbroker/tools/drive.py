"""Google Drive tool adapters."""

import httpx

from credbroker.config import Settings
from credbroker.errors import ProviderCallError
from credbroker.tools.base import ToolAdapter

DRIVE_API_DEFAULT = "https://www.googleapis.com/drive/v3"


class DriveListFilesTool(ToolAdapter):
    """List files in the connected Google Drive (read-only)."""

    name = "drive.read"
    provider = "google"
    scope = "read"
    side_effectful = False

    # Class-level default so an unconfigured instance targets the real API.
    _base_url = DRIVE_API_DEFAULT

    def configure(self, settings: Settings) -> None:
        # Overridable so local demos can point at the fake Drive service
        # (credbroker.demo.fake_drive) instead of Google.
        self._base_url = settings.drive_api_base_url or DRIVE_API_DEFAULT

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
            f"{self._base_url}/files",
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
