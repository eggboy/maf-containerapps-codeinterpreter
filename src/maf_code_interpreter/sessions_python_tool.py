import inspect
import logging
import os
import re
from collections.abc import Awaitable, Callable
from io import BytesIO
from typing import Annotated, Any

from azure.core.credentials import TokenCredential
from httpx import AsyncClient, HTTPStatusError
from pydantic import BaseModel, Field, ValidationError

logger = logging.getLogger(__name__)

SESSIONS_API_VERSION = "2024-02-02-preview"


class SessionsRemoteFileMetadata(BaseModel):
    """Metadata for a remote file in a session."""

    filename: str
    size_in_bytes: int
    full_path: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SessionsRemoteFileMetadata":
        """Create from API response dictionary."""
        return cls(
            filename=data.get("filename", ""),
            size_in_bytes=data.get("sizeInBytes", 0),
            full_path=data.get("fullPath"),
        )


class ACASessionsSettings(BaseModel):
    """Settings for Azure Container Apps Sessions."""

    pool_management_endpoint: str
    token_endpoint: str | None = None

    def __init__(
        self,
        env_file_path: str | None = None,
        pool_management_endpoint: str | None = None,
        token_endpoint: str | None = None,
    ):
        """Initialize settings from environment or parameters."""
        if env_file_path:
            from dotenv import load_dotenv

            load_dotenv(env_file_path)

        endpoint = pool_management_endpoint or os.getenv(
            "AZURE_CONTAINER_APP_SESSION_POOL_MANAGEMENT_ENDPOINT"
        )
        if not endpoint:
            raise ValueError(
                "pool_management_endpoint must be provided or set in "
                "AZURE_CONTAINER_APP_SESSION_POOL_MANAGEMENT_ENDPOINT environment variable"
            )

        super().__init__(
            pool_management_endpoint=endpoint,
            token_endpoint=token_endpoint
            or os.getenv("AZURE_CONTAINER_APP_SESSION_TOKEN_ENDPOINT"),
        )

    def get_sessions_auth_token(
        self, credential: TokenCredential | None = None
    ) -> str | None:
        """Get authentication token for sessions."""
        if credential:
            token = credential.get_token("https://dynamicsessions.io/.default")
            return token.token
        return None


class SessionsPythonSettings(BaseModel):
    """Settings for Python code execution in sessions."""

    session_id: str = Field(default="default", alias="identifier")
    python_code: str | None = Field(default=None, alias="code")
    code_input_type: str = Field(default="Inline", alias="codeInputType")
    execution_type: str = Field(default="Synchronous", alias="executionType")
    sanitize_input: bool = True

    model_config = {"populate_by_name": True}


class SessionsPythonTool:
    """A tool for running Python code in Azure Container Apps dynamic sessions code interpreter."""

    def __init__(
        self,
        auth_callback: Callable[..., Any | Awaitable[Any]] | None = None,
        pool_management_endpoint: str | None = None,
        settings: SessionsPythonSettings | None = None,
        http_client: AsyncClient | None = None,
        env_file_path: str | None = None,
        token_endpoint: str | None = None,
        credential: TokenCredential | None = None,
        enable_dangerous_file_uploads: bool = False,
        allowed_upload_directories: set[str] | list[str] | None = None,
        allowed_download_directories: set[str] | list[str] | None = None,
    ):
        """Initialize the SessionsPythonTool.

        Args:
            auth_callback: Callback to retrieve authentication token.
            pool_management_endpoint: The ACA pool management endpoint URL.
            settings: Python session settings.
            http_client: HTTP client for making requests.
            env_file_path: Path to .env file.
            token_endpoint: Token endpoint for authentication.
            credential: Azure credential for authentication.
            enable_dangerous_file_uploads: Flag to enable file upload operations.
                Must be True along with allowed_upload_directories to enable file uploads.
                Default is False (file uploads disabled).
            allowed_upload_directories: Set or list of allowed directories for file uploads.
                If None, upload_file will be disabled (deny-by-default).
            allowed_download_directories: Set or list of allowed directories for file downloads.
                If None, all paths are allowed (permissive-by-default).
        """
        try:
            aca_settings = ACASessionsSettings(
                env_file_path=env_file_path,
                pool_management_endpoint=pool_management_endpoint,
                token_endpoint=token_endpoint,
            )
        except ValidationError as e:
            logger.error(f"Failed to load the ACASessionsSettings: {e!s}")
            raise ValueError(f"Failed to load the ACASessionsSettings: {e!s}") from e

        if not settings:
            settings = SessionsPythonSettings()

        if not http_client:
            http_client = AsyncClient(timeout=30)

        if auth_callback is None:
            auth_callback = self._default_auth_callback(aca_settings, credential)

        # Convert lists to sets and filter out empty strings (which resolve to CWD - a security risk)
        upload_dirs = (
            {d for d in allowed_upload_directories if d}
            if allowed_upload_directories is not None
            else None
        )
        download_dirs = (
            {d for d in allowed_download_directories if d}
            if allowed_download_directories is not None
            else None
        )

        # Warn if empty set provided
        if upload_dirs is not None and len(upload_dirs) == 0:
            logger.warning(
                "allowed_upload_directories is empty - no uploads will be allowed"
            )

        self.pool_management_endpoint = aca_settings.pool_management_endpoint
        self.settings = settings
        self.auth_callback = auth_callback
        self.http_client = http_client
        self.enable_dangerous_file_uploads = enable_dangerous_file_uploads
        self.allowed_upload_directories = upload_dirs
        self.allowed_download_directories = download_dirs

        # Set __name__ so MAF's tool() auto-conversion uses a meaningful tool name
        self.__name__ = "execute_python_code"

    async def __call__(self, code: Annotated[str, "The Python code to execute"]) -> str:
        """Execute Python code in a secure Azure Container Apps dynamic session.

        This method allows the tool instance to be passed directly to Microsoft Agent Framework
        as a callable tool, e.g. ``tools=[sessions_tool]``, without needing a wrapper function.

        Args:
            code: The Python code to execute

        Returns:
            The execution result including stdout, stderr, and return value
        """
        return await self.execute_code(code)

    def _default_auth_callback(
        self, aca_settings: ACASessionsSettings, credential: TokenCredential | None
    ) -> Callable[..., Any | Awaitable[Any]]:
        """Generate a default authentication callback."""
        token = aca_settings.get_sessions_auth_token(credential=credential)

        if token is None:
            raise ValueError("Failed to retrieve the client auth token.")

        def auth_callback() -> str:
            """Retrieve the client auth token."""
            return token

        return auth_callback

    async def _ensure_auth_token(self) -> str:
        """Ensure the auth token is valid and handle both sync and async callbacks."""
        try:
            if inspect.iscoroutinefunction(self.auth_callback):
                auth_token = await self.auth_callback()
            else:
                auth_token = self.auth_callback()
        except Exception as e:
            logger.error(f"Failed to retrieve the client auth token: {e!s}")
            raise RuntimeError(
                f"Failed to retrieve the client auth token: {e!s}"
            ) from e

        return auth_token

    async def _set_auth_headers(self) -> None:
        """Set authorization headers for HTTP client."""
        auth_token = await self._ensure_auth_token()
        self.http_client.headers.update(
            {
                "Authorization": f"Bearer {auth_token}",
            }
        )

    def _sanitize_input(self, code: str) -> str:
        """Sanitize input to the python REPL.

        Remove whitespace, backtick & python (if llm mistakes python console as terminal).

        Args:
            code: The code to sanitize

        Returns:
            The sanitized code
        """
        # Removes `, whitespace & python from start
        code = re.sub(r"^(\s|`)*(?i:python)?\s*", "", code)
        # Removes whitespace & ` from end
        return re.sub(r"(\s|`)*$", "", code)

    def _construct_remote_file_path(self, remote_file_path: str) -> str:
        """Construct the remote file path.

        Args:
            remote_file_path: The remote file path.

        Returns:
            The remote file path.
        """
        if not remote_file_path.startswith("/mnt/data/"):
            remote_file_path = f"/mnt/data/{remote_file_path}"
        return remote_file_path

    def _build_url_with_version(
        self, base_url: str, endpoint: str, params: dict[str, str]
    ) -> str:
        """Build a URL with the provided base URL, endpoint, and query parameters."""
        params["api-version"] = SESSIONS_API_VERSION
        query_string = "&".join([f"{key}={value}" for key, value in params.items()])
        if not base_url.endswith("/"):
            base_url += "/"
        if endpoint.endswith("/"):
            endpoint = endpoint[:-1]
        return f"{base_url}{endpoint}?{query_string}"

    def _validate_local_path_for_upload(self, local_file_path: str) -> str:
        """Validate local path is within allowed upload directories.

        Args:
            local_file_path: The path to validate.

        Returns:
            The canonicalized absolute path.

        Raises:
            RuntimeError: If file operations are disabled or path is not within allowed directories.
        """
        if not self.enable_dangerous_file_uploads:
            raise RuntimeError(
                "File upload is disabled. Set 'enable_dangerous_file_uploads=True' "
                "and configure 'allowed_upload_directories' to enable."
            )

        if self.allowed_upload_directories is None:
            raise RuntimeError(
                "File upload requires 'allowed_upload_directories' to be configured."
            )

        canonical_path = os.path.realpath(local_file_path)

        for allowed_dir in self.allowed_upload_directories:
            allowed_canonical = os.path.realpath(allowed_dir)
            try:
                common = os.path.commonpath([allowed_canonical, canonical_path])
                if common == allowed_canonical:
                    return canonical_path
            except ValueError:
                continue  # Different drives on Windows

        logger.warning(
            f"Upload denied for path: {local_file_path} (resolved: {canonical_path})"
        )
        raise RuntimeError(
            f"Access denied: '{local_file_path}' is not within allowed upload directories."
        )

    def _validate_local_path_for_download(self, local_file_path: str) -> str:
        """Validate local path is within allowed download directories.

        Args:
            local_file_path: The path to validate.

        Returns:
            The canonicalized absolute path.

        Raises:
            RuntimeError: If allowed_download_directories is set and path is not within.
        """
        # Permissive by default - if no restrictions configured, allow all paths
        if self.allowed_download_directories is None:
            return os.path.realpath(local_file_path)

        parent_dir = os.path.dirname(local_file_path) or "."
        canonical_parent = os.path.realpath(parent_dir)
        filename = os.path.basename(local_file_path)
        canonical_path = os.path.join(canonical_parent, filename)

        for allowed_dir in self.allowed_download_directories:
            allowed_canonical = os.path.realpath(allowed_dir)
            try:
                common = os.path.commonpath([allowed_canonical, canonical_parent])
                if common == allowed_canonical:
                    return canonical_path
            except ValueError:
                continue

        logger.warning(f"Download denied for path: {local_file_path}")
        raise RuntimeError(
            f"Access denied: '{local_file_path}' is not within allowed download directories."
        )

    async def execute_code(
        self, code: Annotated[str, "The valid Python code to execute"]
    ) -> str:
        """Execute Python code in a dynamic session.

        This function is designed to be used as a tool with Microsoft Agent Framework.
        It executes the provided Python code and returns the result, stdout, and stderr.

        Args:
            code: The valid Python code to execute

        Returns:
            The result of the Python code execution including Result, Stdout, and Stderr

        Raises:
            ValueError: If the provided code is empty.
            RuntimeError: If code execution fails.
        """

        if not code:
            raise ValueError("The provided code is empty")

        if self.settings.sanitize_input:
            code = self._sanitize_input(code)

        logger.info(f"Executing Python code: {code}")

        await self._set_auth_headers()
        self.http_client.headers["Content-Type"] = "application/json"

        self.settings.python_code = code

        request_body = {
            "properties": self.settings.model_dump(
                exclude_none=True, exclude={"sanitize_input"}, by_alias=True
            ),
        }

        url = self._build_url_with_version(
            base_url=self.pool_management_endpoint,
            endpoint="code/execute/",
            params={"identifier": self.settings.session_id},
        )

        try:
            response = await self.http_client.post(
                url=url,
                json=request_body,
            )
            response.raise_for_status()
            result = response.json()["properties"]
            return (
                f"Status:\n{result['status']}\n"
                f"Result:\n{result['result']}\n"
                f"Stdout:\n{result['stdout']}\n"
                f"Stderr:\n{result['stderr']}"
            )
        except HTTPStatusError as e:
            error_message = (
                e.response.text if e.response.text else e.response.reason_phrase
            )
            raise RuntimeError(
                f"Code execution failed with status code {e.response.status_code} and error: {error_message}"
            ) from e

    async def upload_file(
        self,
        local_file_path: Annotated[str, "The path to the local file on the machine"],
        remote_file_path: Annotated[
            str | None,
            "The remote path to the file in the session. Defaults to /mnt/data",
        ] = None,
    ) -> SessionsRemoteFileMetadata:
        """Upload a file to the session pool.

        Args:
            local_file_path: The path to the file on the local machine.
                Must be within allowed_upload_directories.
            remote_file_path: The path to the file in the session.

        Returns:
            The metadata of the uploaded file.

        Raises:
            ValueError: If local_file_path is not provided.
            RuntimeError: If upload fails or path is not in allowed directories.
        """
        if not local_file_path:
            raise ValueError("Please provide a local file path to upload.")

        # Validate path is in allowed directories (deny-by-default)
        validated_path = self._validate_local_path_for_upload(local_file_path)

        remote_file_path = self._construct_remote_file_path(
            remote_file_path or os.path.basename(validated_path)
        )

        await self._set_auth_headers()

        url = self._build_url_with_version(
            base_url=self.pool_management_endpoint,
            endpoint="files/upload",
            params={"identifier": self.settings.session_id},
        )

        try:
            with open(validated_path, "rb") as data:
                files = {
                    "file": (remote_file_path, data.read(), "application/octet-stream")
                }
                response = await self.http_client.post(url=url, files=files)
                response.raise_for_status()
                uploaded_files = await self.list_files()
                # Extract filename from remote_file_path for comparison
                expected_filename = os.path.basename(remote_file_path)
                matching_file = next(
                    (
                        file_metadata
                        for file_metadata in uploaded_files
                        if file_metadata.full_path == remote_file_path
                        or file_metadata.filename == expected_filename
                        or file_metadata.full_path == expected_filename
                    ),
                    None,
                )
                if matching_file is None:
                    raise RuntimeError(
                        f"Uploaded file '{remote_file_path}' not found in session file list"
                    )
                return matching_file
        except HTTPStatusError as e:
            error_message = (
                e.response.text if e.response.text else e.response.reason_phrase
            )
            raise RuntimeError(
                f"Upload failed with status code {e.response.status_code} and error: {error_message}"
            ) from e

    async def list_files(self) -> list[SessionsRemoteFileMetadata]:
        """List the files in the session pool.

        Returns:
            The metadata for the files in the session pool

        Raises:
            RuntimeError: If listing files fails.
        """
        await self._set_auth_headers()

        url = self._build_url_with_version(
            base_url=self.pool_management_endpoint,
            endpoint="files",
            params={"identifier": self.settings.session_id},
        )

        try:
            response = await self.http_client.get(
                url=url,
            )
            response.raise_for_status()
            response_json = response.json()
            return [
                SessionsRemoteFileMetadata.from_dict(entry["properties"])
                for entry in response_json["value"]
            ]
        except HTTPStatusError as e:
            error_message = (
                e.response.text if e.response.text else e.response.reason_phrase
            )
            raise RuntimeError(
                f"List files failed with status code {e.response.status_code} and error: {error_message}"
            ) from e

    async def download_file(
        self,
        remote_file_name: Annotated[
            str, "The name of the file to download, relative to /mnt/data"
        ],
        local_file_path: Annotated[
            str | None, "The local file path to save the file to, optional"
        ] = None,
    ) -> str | BytesIO:
        """Download a file from the session pool.

        Args:
            remote_file_name: The name of the file to download, relative to `/mnt/data`.
            local_file_path: The path to save the downloaded file to. Should include the extension.
                If not provided, the file is returned as a BytesIO object.

        Returns:
            The saved file path (str) if local_file_path provided, otherwise BytesIO content.

        Raises:
            RuntimeError: If download fails or local_file_path is not in allowed directories.
        """
        await self._set_auth_headers()

        url = self._build_url_with_version(
            base_url=self.pool_management_endpoint,
            endpoint=f"files/content/{remote_file_name}",
            params={"identifier": self.settings.session_id},
        )

        try:
            response = await self.http_client.get(
                url=url,
            )
            response.raise_for_status()
            if local_file_path:
                # Validate path is in allowed directories (optional, permissive by default)
                validated_path = self._validate_local_path_for_download(local_file_path)
                with open(validated_path, "wb") as f:
                    f.write(response.content)
                return validated_path

            return BytesIO(response.content)
        except HTTPStatusError as e:
            error_message = (
                e.response.text if e.response.text else e.response.reason_phrase
            )
            raise RuntimeError(
                f"Download failed with status code {e.response.status_code} and error: {error_message}"
            ) from e
