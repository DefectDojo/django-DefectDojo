"""
Lacework API v2.0 Client for DefectDojo integration.

This module provides a client to interact with the Lacework API v2.0,
handling authentication, pagination, and rate limiting.

Based on the Lacework OpenAPI specification (lacework-api-v2.0.yaml).
"""

import logging
import time
from datetime import datetime, timedelta, timezone

import requests
from django.conf import settings
from requests.exceptions import JSONDecodeError as RequestsJSONDecodeError

logger = logging.getLogger(__name__)


class LaceworkAPI:
    """Client for Lacework API v2.0.
    
    Handles authentication via X-LW-UAKS header, Bearer token management,
    pagination, and rate limiting for Lacework API calls.
    """

    def __init__(self, tool_config):
        """Initialize the Lacework API client.
        
        Args:
            tool_config: ToolConfiguration instance with Lacework credentials.
                - url: Base URL of Lacework instance (e.g., https://yourinstance.lacework.net)
                - username: The keyId (used as the POST body to obtain the Bearer token)
                - api_key: The secret key (X-LW-UAKS header value)
                - authentication_type: Should be "API"
                - extras: Comma-separated options:
                    "include_containers=true" - Import container vulnerabilities
                    "include_hosts=true" - Import host vulnerabilities
                    Default (empty): both containers and hosts are imported.
        """
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "DefectDojo"})
        
        self.base_url = tool_config.url.rstrip("/")
        self.api_key = tool_config.api_key  # X-LW-UAKS value
        self.key_id = tool_config.username  # keyId required in the POST body
        
        # Parse extras for import options
        self.include_containers = True  # default: import containers
        self.include_hosts = True  # default: import hosts
        self._parse_extras(tool_config.extras)
        
        # Token caching
        self._bearer_token = None
        self._token_expiry = None
        
        # Rate limiting
        self._rate_limit_reset = None
        
        if not self.key_id:
            raise Exception(
                "Lacework keyId is required. Set it in the 'Username' field of the "
                "Tool Configuration. The 'API Key' field should contain the X-LW-UAKS secret."
            )

    def _parse_extras(self, extras: str | None):
        """Parse the extras field for import options.
        
        Supported options (comma-separated):
        - include_containers=true/false: Import container vulnerabilities
        - include_hosts=true/false: Import host vulnerabilities
        
        Examples:
        - "" or None: Import both containers and hosts (default)
        - "include_containers=true,include_hosts=false": Only containers
        - "include_hosts=true,include_containers=false": Only hosts
        - "include_containers=false": Only hosts
        """
        if not extras:
            return
        
        for entry in extras.split(","):
            entry = entry.strip().lower()
            if "=" in entry:
                key, value = entry.split("=", 1)
                key = key.strip()
                value = value.strip().lower()
                
                if key == "include_containers":
                    self.include_containers = value == "true"
                elif key == "include_hosts":
                    self.include_hosts = value == "true"

    def _get_bearer_token(self) -> str:
        """Obtain a Bearer token from Lacework using the API key.
        
        Makes a POST request to /api/v2/access/tokens with:
        - Header X-LW-UAKS: The secret key
        - Body: {"keyId": "<the key id>"}
        
        The returned token is cached and reused until it expires.
        
        Returns:
            str: The Bearer token to use for API requests.
            
        Raises:
            Exception: If the token request fails.
        """
        # Check if we have a valid cached token
        if self._bearer_token and self._token_expiry:
            if datetime.now(timezone.utc) < self._token_expiry:
                return self._bearer_token
        
        url = f"{self.base_url}/api/v2/access/tokens"
        headers = {
            "X-LW-UAKS": self.api_key,
            "Content-Type": "application/json",
        }
        body = {"keyId": self.key_id}
        
        try:
            response = self.session.post(
                url,
                headers=headers,
                json=body,
                timeout=getattr(settings, "REQUESTS_TIMEOUT", 30),
            )
            
            if not response.ok:
                msg = (
                    f"Unable to obtain Lacework Bearer token. "
                    f"HTTP {response.status_code}: {response.content.decode('utf-8')}"
                )
                logger.error(msg)
                raise Exception(msg)
            
            data = response.json()
            logger.debug("Lacework token response: %s", data)
            
            # The token response is flat, not wrapped in "data": {}
            # Response: {"expiresAt": "...", "token": "..."}
            self._bearer_token = data.get("token")
            
            if not self._bearer_token:
                msg = (
                    f"Lacework token response did not contain a token. "
                    f"HTTP {response.status_code}. Response: {data}"
                )
                logger.error(msg)
                raise Exception(msg)
            
            # Calculate expiry (tokens typically expire in 1 hour)
            # Refresh 5 minutes before expiry
            expires_at_str = data.get("expiresAt")
            if expires_at_str:
                try:
                    expires_at = datetime.fromisoformat(
                        expires_at_str.replace("Z", "+00:00")
                    )
                    self._token_expiry = expires_at - timedelta(minutes=5)
                except (ValueError, AttributeError):
                    # If we can't parse the expiry, use a default 55 minutes
                    self._token_expiry = datetime.now(timezone.utc) + timedelta(minutes=55)
            else:
                self._token_expiry = datetime.now(timezone.utc) + timedelta(minutes=55)
            
            logger.info("Successfully obtained Lacework Bearer token")
            return self._bearer_token
            
        except requests.exceptions.RequestException as e:
            msg = f"Network error when obtaining Lacework token: {e}"
            logger.error(msg)
            raise Exception(msg)
        except RequestsJSONDecodeError as e:
            msg = f"Invalid JSON response from Lacework token endpoint: {e}"
            logger.error(msg)
            raise Exception(msg)

    def _request(self, method: str, path: str, **kwargs) -> dict:
        """Make a generic API request with Bearer token authentication.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            path: API path (e.g., /api/v2/Vulnerabilities/Containers/search)
            **kwargs: Additional arguments passed to requests
            
        Returns:
            dict: The JSON response data.
            
        Raises:
            Exception: If the request fails.
        """
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self._get_bearer_token()}",
            "Content-Type": "application/json",
        }
        
        # Handle rate limiting with retry
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.session.request(
                    method,
                    url,
                    headers=headers,
                    timeout=getattr(settings, "REQUESTS_TIMEOUT", 30),
                    **kwargs,
                )
                
                # Handle rate limiting
                if response.status_code == 429:
                    reset_seconds = int(response.headers.get("RateLimit-Reset", 60))
                    logger.warning(
                        "Lacework rate limit hit. Waiting %d seconds...", reset_seconds
                    )
                    time.sleep(min(reset_seconds, 300))  # Cap at 5 minutes
                    continue
                
                if not response.ok:
                    msg = (
                        f"Lacework API error: HTTP {response.status_code} - "
                        f"{response.content.decode('utf-8')}"
                    )
                    logger.error(msg)
                    raise Exception(msg)
                
                return response.json()
                
            except requests.exceptions.RequestException as e:
                if attempt < max_retries - 1:
                    logger.warning(
                        "Request failed, retrying (%d/%d): %s",
                        attempt + 1,
                        max_retries,
                        e,
                    )
                    time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise

    def _get_all_pages(self, get_page_func) -> list:
        """Helper to automatically paginate through all results.
        
        Lacework API returns paginated results with a nextPage URL.
        This method collects all pages until there are no more.
        
        Strategy:
        - First page is fetched via get_page_func (POST with filters)
        - Subsequent pages are fetched via GET on the nextPage URL
          returned in paging.urls.nextPage (full URLs like
          https://instance.lacework.net/api/v2/Vulnerabilities/Containers/abc123)
        
        Args:
            get_page_func: A callable that returns (page_data, next_page_url)
            
        Returns:
            list: All items from all pages.
        """
        all_items = []
        current_page_url = None
        page_count = 0
        
        while True:
            try:
                if current_page_url is None:
                    # First page: use the provided POST function
                    page_data, next_page_url = get_page_func()
                else:
                    page_count += 1
                    logger.debug(
                        "Fetching page %d: %s...",
                        page_count, current_page_url[:100],
                    )
                    # Longer timeout for subsequent pages (dataset can be large)
                    response = self.session.get(
                        current_page_url,
                        headers={
                            "Authorization": f"Bearer {self._get_bearer_token()}",
                            "Content-Type": "application/json",
                        },
                        timeout=getattr(settings, "REQUESTS_TIMEOUT", 120),
                    )
                    
                    if not response.ok:
                        logger.warning(
                            "Failed to fetch next page: HTTP %d", response.status_code
                        )
                        break
                    
                    data = response.json()
                    page_data = data
                    paging = data.get("paging", {})
                    urls = paging.get("urls", {})
                    next_page_url = urls.get("nextPage")
                
                if not page_data:
                    break
                    
                items = page_data.get("data", [])
                if items:
                    all_items.extend(items)
                    logger.debug(
                        "Fetched %d items, total so far: %d", len(items), len(all_items)
                    )
                
                if not next_page_url:
                    break
                
                current_page_url = next_page_url
                
            except requests.exceptions.Timeout:
                logger.warning(
                    "Timeout fetching page %d (got %d items so far). "
                    "The dataset may be too large. Try a shorter time range.",
                    page_count, len(all_items),
                )
                break
            except Exception as e:
                logger.warning(
                    "Pagination error on page %d: %s (got %d items so far)",
                    page_count, e, len(all_items),
                )
                break
        
        logger.info(
            "Pagination complete: fetched %d items across %d pages",
            len(all_items), page_count,
        )
        return all_items

    def list_container_registries(self) -> list:
        """List all container registries configured in Lacework.
        
        Returns:
            list: List of container registry configurations.
            
        Raises:
            Exception: If the request fails.
        """
        url = f"{self.base_url}/api/v2/ContainerRegistries"
        
        try:
            response = self.session.get(
                url,
                headers={
                    "Authorization": f"Bearer {self._get_bearer_token()}",
                    "Content-Type": "application/json",
                },
                timeout=getattr(settings, "REQUESTS_TIMEOUT", 30),
            )
            
            if not response.ok:
                msg = (
                    f"Unable to list Lacework container registries. "
                    f"HTTP {response.status_code}: {response.content.decode('utf-8')}"
                )
                logger.error(msg)
                raise Exception(msg)
            
            data = response.json()
            return data.get("data", [])
            
        except requests.exceptions.RequestException as e:
            msg = f"Network error when listing container registries: {e}"
            logger.error(msg)
            raise Exception(msg)

    def search_container_vulnerabilities(
        self,
        start_time: str,
        end_time: str,
        filters: list | None = None,
    ) -> list:
        """Search for container vulnerabilities in Lacework.
        
        Uses the POST /api/v2/Vulnerabilities/Containers/search endpoint
        with automatic pagination.
        
        Args:
            start_time: Start time in ISO 8601 format (e.g., 2024-01-25T00:00:00.000Z)
            end_time: End time in ISO 8601 format
            filters: Optional list of filter dicts for additional filtering
            
        Returns:
            list: All container vulnerabilities found.
            
        Raises:
            Exception: If the request fails.
        """
        body = {
            "timeFilter": {
                "startTime": start_time,
                "endTime": end_time,
            }
        }
        
        if filters:
            body["filters"] = filters
        
        def get_page():
            response = self.session.post(
                f"{self.base_url}/api/v2/Vulnerabilities/Containers/search",
                json=body,
                headers={
                    "Authorization": f"Bearer {self._get_bearer_token()}",
                    "Content-Type": "application/json",
                },
                timeout=getattr(settings, "REQUESTS_TIMEOUT", 30),
            )
            
            if not response.ok:
                msg = (
                    f"Unable to search container vulnerabilities. "
                    f"HTTP {response.status_code}: {response.content.decode('utf-8')}"
                )
                logger.error(msg)
                raise Exception(msg)
            
            data = response.json()
            paging = data.get("paging", {})
            urls = paging.get("urls", {})
            next_page_url = urls.get("nextPage")
            
            return data, next_page_url
        
        return self._get_all_pages(get_page)

    def search_host_vulnerabilities(
        self,
        start_time: str,
        end_time: str,
        filters: list | None = None,
    ) -> list:
        """Search for host vulnerabilities in Lacework.
        
        Uses the POST /api/v2/Vulnerabilities/Hosts/search endpoint
        with automatic pagination.
        
        Args:
            start_time: Start time in ISO 8601 format
            end_time: End time in ISO 8601 format
            filters: Optional list of filter dicts for additional filtering
            
        Returns:
            list: All host vulnerabilities found.
            
        Raises:
            Exception: If the request fails.
        """
        body = {
            "timeFilter": {
                "startTime": start_time,
                "endTime": end_time,
            }
        }
        
        if filters:
            body["filters"] = filters
        
        def get_page():
            response = self.session.post(
                f"{self.base_url}/api/v2/Vulnerabilities/Hosts/search",
                json=body,
                headers={
                    "Authorization": f"Bearer {self._get_bearer_token()}",
                    "Content-Type": "application/json",
                },
                timeout=getattr(settings, "REQUESTS_TIMEOUT", 30),
            )
            
            if not response.ok:
                msg = (
                    f"Unable to search host vulnerabilities. "
                    f"HTTP {response.status_code}: {response.content.decode('utf-8')}"
                )
                logger.error(msg)
                raise Exception(msg)
            
            data = response.json()
            paging = data.get("paging", {})
            urls = paging.get("urls", {})
            next_page_url = urls.get("nextPage")
            
            return data, next_page_url
        
        return self._get_all_pages(get_page)

    def test_connection(self) -> str:
        """Test the connection to Lacework API.
        
        Verifies that we can obtain a Bearer token and make a simple
        API call. Does NOT require container registry permissions.
        
        Returns:
            str: A message describing the connection status.
            
        Raises:
            Exception: If the connection fails.
        """
        try:
            # First verify we can get a Bearer token
            token = self._get_bearer_token()
            if not token:
                raise Exception("Failed to obtain Bearer token")
            
            # Try to list container registries for a meaningful response
            try:
                registries = self.list_container_registries()
                return (
                    f"Successfully connected to Lacework. "
                    f"Bearer token obtained and found {len(registries)} "
                    f"container registries."
                )
            except Exception:
                # If listing registries fails (permissions), at least we have a token
                return (
                    "Successfully connected to Lacework. "
                    "Bearer token obtained successfully."
                )
        except Exception as e:
            msg = f"Failed to connect to Lacework: {e}"
            logger.error(msg)
            raise Exception(msg)

    def test_product_connection(self, api_scan_configuration) -> str:
        """Test connection for a specific product/repository.
        
        Verifies that the Lacework instance is accessible by obtaining
        a Bearer token. Does NOT require container registry permissions.
        
        Args:
            api_scan_configuration: APIScanConfiguration instance for the product
            
        Returns:
            str: A message describing the connection status.
        """
        try:
            # Verify we can get a Bearer token
            token = self._get_bearer_token()
            if not token:
                raise Exception("Failed to obtain Bearer token")
            
            repo_pattern = api_scan_configuration.service_key_1 or ""
            
            if repo_pattern:
                return (
                    f"Successfully connected to Lacework. "
                    f"Repository filter pattern: '{repo_pattern}'."
                )
            else:
                return (
                    "Successfully connected to Lacework. "
                    "No repository filter configured (will import all repositories)."
                )
        except Exception as e:
            msg = f"Failed to connect to Lacework for product: {e}"
            logger.error(msg)
            raise Exception(msg)
