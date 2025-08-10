#!/usr/bin/env python3
"""
Google Ads MCP Server - FastMCP Implementation with Authentication
Uses FastMCP's built-in authentication system
"""

import os
import json
import base64
import logging
import secrets
import time
import warnings  # Add this import
from datetime import datetime, timezone, timedelta
from dateutil import parser
from typing import Dict, Optional, Any

# Suppress deprecation warnings from websockets library
warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn")

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as AuthRequest
import requests

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import OAuthProvider
from fastmcp.server.auth.auth import ClientRegistrationOptions, RevocationOptions
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import Field, AnyHttpUrl

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('google_ads_server')

# Constants
SCOPES = ['https://www.googleapis.com/auth/adwords']
API_VERSION = "v20"  # Updated to v20

class SimpleOAuthProvider(OAuthProvider):
    """
    Secure OAuth provider for Google Ads MCP Server.
    Only allows pre-configured clients with correct credentials.
    """
    
    def __init__(
        self,
        base_url: str,
        allowed_clients: Dict[str, str] | None = None,
        **kwargs
    ):
        """Initialize the OAuth provider with strict authentication."""
        super().__init__(
            base_url=base_url,
            issuer_url=base_url,
            service_documentation_url=f"{base_url}/docs",
            client_registration_options=ClientRegistrationOptions(
                enabled=False,  # DISABLE dynamic registration - only pre-configured clients
                initial_access_token=None,
                scopes_supported=["read", "write", "admin"],
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=["read"],
            resource_server_url=base_url,
            **kwargs
        )
        
        # In-memory storage
        self.clients: Dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: Dict[str, AuthorizationCode] = {}
        self.access_tokens: Dict[str, AccessToken] = {}
        self.refresh_tokens: Dict[str, RefreshToken] = {}
        
        # Pre-configured client ID/secret pairs - ONLY these can connect
        self.allowed_clients = allowed_clients or {}
        
        if not self.allowed_clients:
            logger.error("=" * 60)
            logger.error("SECURITY WARNING: No OAuth clients configured!")
            logger.error("Set OAUTH_CLIENTS environment variable with format:")
            logger.error("OAUTH_CLIENTS=clientid1:secret1,clientid2:secret2")
            logger.error("=" * 60)
            raise ValueError("No OAuth clients configured. Server cannot start without authentication.")
        
        # Pre-register ONLY the allowed clients
        for client_id, client_secret in self.allowed_clients.items():
            client = OAuthClientInformationFull(
                client_id=client_id,
                client_secret=client_secret,
                client_name=f"Pre-configured client {client_id}",
                redirect_uris=[
                    "https://claude.ai/api/mcp/auth_callback",
                    "http://localhost:8080/callback",
                    "http://localhost:3000/callback",
                    "https://localhost:8080/callback",
                    "https://localhost:3000/callback"
                ],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="client_secret_post",
                scope="read write admin"
            )
            self.clients[client_id] = client
            logger.info(f"Pre-registered secure client: {client_id}")
        
        logger.info(f"OAuth security enabled with {len(self.allowed_clients)} authorized client(s)")
    
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get client information by ID - only returns pre-configured clients."""
        # ONLY return pre-configured clients
        client = self.clients.get(client_id)
        if client:
            logger.info(f"Authorized client found: {client_id}")
        else:
            logger.warning(f"UNAUTHORIZED: Unknown client attempted access: {client_id}")
        return client
    
    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """
        DISABLED: Dynamic client registration is not allowed for security.
        Only pre-configured clients from environment variables can connect.
        """
        logger.error(f"BLOCKED: Dynamic registration attempt from client: {client_info.client_id}")
        raise ValueError("Dynamic client registration is disabled. Only pre-configured clients are allowed.")
    
    async def authorize(
        self, 
        client: OAuthClientInformationFull, 
        params: AuthorizationParams
    ) -> str:
        """
        Handle authorization request - only for validated clients.
        """
        # Double-check this is an allowed client
        if client.client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Unauthorized client in authorize: {client.client_id}")
            raise ValueError("Unauthorized client")
        
        logger.info(f"Authorization request from authorized client: {client.client_id}")
        logger.info(f"Requested scopes: {params.scopes}")
        
        # Get the requested scopes
        requested_scopes = params.scopes or ["read"]
        
        # Generate authorization code
        auth_code = f"auth_{secrets.token_urlsafe(32)}"
        expires_at = time.time() + 600  # 10 minutes
        
        # Store authorization code
        self.auth_codes[auth_code] = AuthorizationCode(
            code=auth_code,
            client_id=client.client_id,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            scopes=requested_scopes,
            expires_at=expires_at,
            code_challenge=params.code_challenge,
        )
        
        # Construct redirect URI with code
        redirect_url = construct_redirect_uri(
            str(params.redirect_uri),
            code=auth_code,
            state=params.state
        )
        
        logger.info(f"Authorization granted for client {client.client_id}")
        return redirect_url
    
    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str
    ) -> AuthorizationCode | None:
        """Load and validate authorization code."""
        auth_code = self.auth_codes.get(authorization_code)
        
        if not auth_code:
            logger.warning(f"Invalid auth code attempted: {authorization_code}")
            return None
        
        # Check if code belongs to this client
        if auth_code.client_id != client.client_id:
            logger.error(f"SECURITY: Auth code hijack attempt - code for {auth_code.client_id} used by {client.client_id}")
            return None
        
        # Check if code is expired
        if auth_code.expires_at < time.time():
            logger.info(f"Auth code expired: {authorization_code}")
            del self.auth_codes[authorization_code]
            return None
        
        logger.info(f"Auth code validated for client: {client.client_id}")
        return auth_code
    
    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for access token."""
        # Verify client is still authorized
        if client.client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Unauthorized token exchange attempt: {client.client_id}")
            raise ValueError("Unauthorized client")
        
        # Verify client secret matches
        if client.client_secret != self.allowed_clients[client.client_id]:
            logger.error(f"SECURITY: Invalid client secret for: {client.client_id}")
            raise ValueError("Invalid client credentials")
        
        # Remove used authorization code
        if authorization_code.code in self.auth_codes:
            del self.auth_codes[authorization_code.code]
        
        # Generate tokens
        access_token = f"access_{secrets.token_urlsafe(32)}"
        refresh_token = f"refresh_{secrets.token_urlsafe(32)}"
        
        expires_in = 3600  # 1 hour
        expires_at = int(time.time() + expires_in)
        
        # Store tokens
        self.access_tokens[access_token] = AccessToken(
            token=access_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=expires_at,
        )
        
        self.refresh_tokens[refresh_token] = RefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=None,
        )
        
        logger.info(f"Tokens issued for authorized client: {client.client_id}")
        
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=refresh_token,
            scope=" ".join(authorization_code.scopes),
        )
    
    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str
    ) -> RefreshToken | None:
        """Load and validate refresh token."""
        token = self.refresh_tokens.get(refresh_token)
        
        if not token:
            logger.warning(f"Invalid refresh token attempted")
            return None
        
        if token.client_id != client.client_id:
            logger.error(f"SECURITY: Refresh token hijack attempt - token for {token.client_id} used by {client.client_id}")
            return None
        
        # Verify client is still authorized
        if client.client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Unauthorized refresh attempt: {client.client_id}")
            return None
        
        if token.expires_at and token.expires_at < time.time():
            del self.refresh_tokens[refresh_token]
            return None
        
        return token
    
    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str]
    ) -> OAuthToken:
        """Exchange refresh token for new access token."""
        # Verify client is still authorized
        if client.client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Unauthorized refresh token exchange: {client.client_id}")
            raise ValueError("Unauthorized client")
        
        # Verify client secret matches
        if client.client_secret != self.allowed_clients[client.client_id]:
            logger.error(f"SECURITY: Invalid client secret on refresh: {client.client_id}")
            raise ValueError("Invalid client credentials")
        
        # Validate requested scopes are subset of original scopes
        if not set(scopes).issubset(set(refresh_token.scopes)):
            raise ValueError("Requested scopes exceed original grant")
        
        # Generate new access token
        new_access_token = f"access_{secrets.token_urlsafe(32)}"
        expires_in = 3600
        expires_at = int(time.time() + expires_in)
        
        # Store new access token
        self.access_tokens[new_access_token] = AccessToken(
            token=new_access_token,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=expires_at,
        )
        
        logger.info(f"Access token refreshed for client: {client.client_id}")
        
        return OAuthToken(
            access_token=new_access_token,
            token_type="Bearer",
            expires_in=expires_in,
            refresh_token=refresh_token.token,
            scope=" ".join(scopes),
        )
    
    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate access token."""
        access_token = self.access_tokens.get(token)
        
        if not access_token:
            logger.warning(f"Invalid access token attempted: {token[:20] if len(token) > 20 else token}...")
            return None
        
        # Verify the client is still authorized
        if access_token.client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Access token for revoked client: {access_token.client_id}")
            del self.access_tokens[token]
            return None
        
        # Check if token is expired
        if access_token.expires_at and access_token.expires_at < time.time():
            logger.info(f"Access token expired for client: {access_token.client_id}")
            del self.access_tokens[token]
            return None
        
        return access_token
    
    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        """Revoke an access or refresh token."""
        if isinstance(token, AccessToken):
            if token.token in self.access_tokens:
                del self.access_tokens[token.token]
                logger.info(f"Access token revoked for client: {token.client_id}")
        elif isinstance(token, RefreshToken):
            if token.token in self.refresh_tokens:
                del self.refresh_tokens[token.token]
                logger.info(f"Refresh token revoked for client: {token.client_id}")

def initialize_credentials():
    """Initialize OAuth credentials from base64 encoded token file"""
    oauth_tokens_base64 = os.environ.get("GOOGLE_ADS_OAUTH_TOKENS_BASE64")
    if not oauth_tokens_base64:
        raise ValueError("GOOGLE_ADS_OAUTH_TOKENS_BASE64 environment variable not set")
    
    try:
        oauth_tokens_json = base64.b64decode(oauth_tokens_base64).decode('utf-8')
        oauth_tokens = json.loads(oauth_tokens_json)
        
        credentials = Credentials(
            token=oauth_tokens.get('token'),
            refresh_token=oauth_tokens.get('refresh_token'),
            token_uri=oauth_tokens.get('token_uri', 'https://oauth2.googleapis.com/token'),
            client_id=oauth_tokens.get('client_id'),
            client_secret=oauth_tokens.get('client_secret'),
            scopes=oauth_tokens.get('scopes', SCOPES)
        )
        
        if 'expiry' in oauth_tokens:
            expiry_str = oauth_tokens['expiry']
            credentials.expiry = parser.parse(expiry_str)
            
            if credentials.expiry and credentials.expiry < datetime.now(timezone.utc):
                logger.info("Token expired, refreshing...")
                auth_req = AuthRequest()
                credentials.refresh(auth_req)
                logger.info("Token refreshed successfully")
        
        return credentials
        
    except Exception as e:
        logger.error(f"Error initializing OAuth credentials: {str(e)}")
        raise

# Initialize credentials
try:
    _credentials = initialize_credentials()
    logger.info("Google Ads credentials initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Google Ads credentials: {str(e)}")
    _credentials = None

def get_credentials():
    """Get the initialized credentials"""
    if not _credentials:
        raise ValueError("Google Ads credentials not initialized")
    return _credentials

def format_customer_id(customer_id: str) -> str:
    """Format customer ID to ensure it's 10 digits without dashes."""
    customer_id = str(customer_id)
    customer_id = customer_id.replace('\"', '').replace('"', '')
    customer_id = ''.join(char for char in customer_id if char.isdigit())
    return customer_id.zfill(10)

def get_headers(creds):
    """Get headers for Google Ads API requests."""
    developer_token = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
    if not developer_token:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN environment variable not set")
    
    login_customer_id = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
    
    auth_req = AuthRequest()
    creds.refresh(auth_req)
    
    headers = {
        'Authorization': f'Bearer {creds.token}',
        'developer-token': developer_token,
        'content-type': 'application/json'
    }
    
    if login_customer_id:
        headers['login-customer-id'] = format_customer_id(login_customer_id)
    
    return headers

# Get server URL from environment
public_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
if public_domain:
    base_url = f"https://{public_domain}"
else:
    base_url = "http://localhost:8080"

# Load client ID/secret pairs from environment
# Format: CLIENT_ID1:SECRET1,CLIENT_ID2:SECRET2
allowed_clients = {}
oauth_clients_config = os.environ.get("OAUTH_CLIENTS", "")

if not oauth_clients_config:
    logger.error("=" * 60)
    logger.error("SECURITY ERROR: No OAuth clients configured!")
    logger.error("Set the OAUTH_CLIENTS environment variable in Railway:")
    logger.error("OAUTH_CLIENTS=your_client_id:your_client_secret")
    logger.error("Example: OAUTH_CLIENTS=my-secure-client:super-secret-password-123")
    logger.error("")
    logger.error("Then use the same credentials in Claude Desktop:")
    logger.error('  "clientId": "my-secure-client"')
    logger.error('  "clientSecret": "super-secret-password-123"')
    logger.error("=" * 60)
    raise ValueError("OAUTH_CLIENTS environment variable is required for security")
# Parse OAuth clients
for client_pair in oauth_clients_config.split(","):
    parts = client_pair.strip().split(":")
    if len(parts) != 2:
        logger.error(f"Invalid OAuth client format: {client_pair}")
        logger.error("Format should be: CLIENT_ID:CLIENT_SECRET")
        raise ValueError(f"Invalid OAuth client configuration: {client_pair}")
    
    client_id, client_secret = parts
    if not client_id or not client_secret:
        raise ValueError("OAuth client ID and secret cannot be empty")
    
    allowed_clients[client_id] = client_secret
    logger.info(f"Loaded secure OAuth client: {client_id}")

logger.info(f"Security: {len(allowed_clients)} OAuth client(s) configured")

# Create OAuth provider with strict security
oauth_provider = SimpleOAuthProvider(
    base_url=base_url,
    allowed_clients=allowed_clients
)

# Create FastMCP server with OAuth authentication
mcp = FastMCP(
    name="Google Ads MCP",
    auth=oauth_provider
)

logger.info("=" * 60)
logger.info("🔒 SECURE Google Ads MCP Server Started")
logger.info(f"📍 URL: {base_url}")
logger.info(f"🔐 Authentication: OAuth 2.0 (Strict Mode)")
logger.info(f"✅ Authorized Clients: {len(allowed_clients)}")
for client_id in allowed_clients.keys():
    logger.info(f"   - {client_id}")
logger.info("=" * 60)
logger.info("⚠️  Only pre-configured OAuth clients can connect")
logger.info("⚠️  Dynamic registration is DISABLED for security")
logger.info("=" * 60)

# ===========================
# Health Check Resources
# ===========================

@mcp.resource("health://status")
def mcp_health_status() -> str:
    """MCP health check endpoint for monitoring"""
    status = {
        "status": "healthy",
        "auth_enabled": True,
        "auth_method": "oauth",
        "oauth_endpoints": {
            "authorization": f"{base_url}/oauth/authorize",
            "token": f"{base_url}/oauth/token",
            "discovery": f"{base_url}/.well-known/oauth-authorization-server",
            "registration": f"{base_url}/oauth/register"
        },
        "google_ads_connected": _credentials is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "3.0.0"
    }
    return json.dumps(status, indent=2)


# Internal function for shared GAQL query logic
def _execute_gaql_query_internal(customer_id: str, query: str) -> str:
    """Internal function to execute a custom GAQL query"""
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error executing query: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No results found for the query."
        
        # Format results
        result_lines = [f"Query Results for Account {formatted_customer_id}:"]
        result_lines.append("-" * 80)
        
        for i, result in enumerate(results['results'][:50], 1):
            result_lines.append(f"\nResult {i}:")
            result_lines.append(json.dumps(result, indent=2))
        
        return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"
    
# Tool implementations
@mcp.tool()
async def list_accounts() -> str:
    """Lists all accessible Google Ads accounts."""
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return f"Error accessing accounts: {response.text}"
        
        customers = response.json()
        if not customers.get('resourceNames'):
            return "No accessible accounts found."
        
        result_lines = ["Accessible Google Ads Accounts:"]
        result_lines.append("-" * 50)
        
        for resource_name in customers['resourceNames']:
            customer_id = resource_name.split('/')[-1]
            formatted_id = format_customer_id(customer_id)
            result_lines.append(f"Account ID: {formatted_id}")
        
        return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error listing accounts: {str(e)}"

@mcp.tool()
async def execute_gaql_query(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax. Note: GAQL only supports AND conditions in WHERE clause, not OR. Use REGEXP_MATCH for pattern matching."),
) -> str:
    """Execute a custom GAQL (Google Ads Query Language) query.
    
    IMPORTANT GAQL SYNTAX NOTES:
    - WHERE clause only supports AND conditions (OR is not supported)
    - For case-insensitive string matching, use REGEXP_MATCH operator
    - Example: WHERE customer_client.descriptive_name REGEXP_MATCH "(?i).*arvest.*"
    - The (?i) flag makes the regex case-insensitive
    """
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def get_campaign_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)"),
) -> str:
    """Get campaign performance metrics for the specified time period."""
    query = f"""
        SELECT
            campaign.id,
            campaign.name,
            campaign.status,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions,
            metrics.average_cpc
        FROM campaign
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.cost_micros DESC
        LIMIT 50
    """
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def get_ad_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)"),
) -> str:
    """Get ad performance metrics for the specified time period."""
    query = f"""
        SELECT
            ad_group_ad.ad.id,
            ad_group_ad.ad.name,
            ad_group_ad.status,
            campaign.name,
            ad_group.name,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions
        FROM ad_group_ad
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
        LIMIT 50
    """
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def run_gaql(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    query: str = Field(description="Valid GAQL query string. Remember: WHERE clause only supports AND, not OR. Use REGEXP_MATCH for pattern matching."),
    format: str = Field(default="table", description="Output format: 'table', 'json', or 'csv'"),
) -> str:
    """Execute any arbitrary GAQL (Google Ads Query Language) query with custom formatting options.
    
    GAQL Query Tips:
    - WHERE clause only supports AND conditions (no OR)
    - For case-insensitive matching: WHERE field REGEXP_MATCH "(?i)pattern"
    - For multiple values: WHERE field IN ('value1', 'value2', 'value3')
    - For pattern matching: WHERE field LIKE '%pattern%'
    """
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def get_ad_creatives(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=7, description="Number of days to look back (7, 30, 90, etc.)"),
) -> str:
    """Get ad creative details including headlines, descriptions, and URLs with performance metrics."""
    query = f"""
        SELECT
            ad_group_ad.ad.responsive_search_ad.headlines,
            ad_group_ad.ad.responsive_search_ad.descriptions,
            ad_group_ad.ad.final_urls,
            campaign.name,
            ad_group.name,
            ad_group_ad.policy_summary.approval_status,
            ad_group_ad.ad.type,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros
        FROM ad_group_ad
        WHERE segments.date DURING LAST_{days}_DAYS
            AND ad_group_ad.status != 'REMOVED'
        LIMIT 50
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving ad creatives: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No ad creatives found for this customer ID."
        
        output_lines = [f"Ad Creatives for Customer ID {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        for i, result in enumerate(results['results'], 1):
            ad_group_ad = result.get('adGroupAd', {})
            ad = ad_group_ad.get('ad', {})
            ad_group = result.get('adGroup', {})
            campaign = result.get('campaign', {})
            metrics = result.get('metrics', {})
            
            output_lines.append(f"\n{i}. Campaign: {campaign.get('name', 'N/A')}")
            output_lines.append(f"   Ad Group: {ad_group.get('name', 'N/A')}")
            output_lines.append(f"   Status: {ad_group_ad.get('policySummary', {}).get('approvalStatus', 'N/A')}")
            output_lines.append(f"   Type: {ad.get('type', 'N/A')}")
            
            # Handle Responsive Search Ads
            rsa = ad.get('responsiveSearchAd', {})
            if rsa:
                if 'headlines' in rsa:
                    output_lines.append("   Headlines:")
                    for headline in rsa['headlines']:
                        output_lines.append(f"     - {headline.get('text', 'N/A')}")
                
                if 'descriptions' in rsa:
                    output_lines.append("   Descriptions:")
                    for desc in rsa['descriptions']:
                        output_lines.append(f"     - {desc.get('text', 'N/A')}")
            
            # Handle Final URLs
            final_urls = ad.get('finalUrls', [])
            if final_urls:
                output_lines.append(f"   Final URLs: {', '.join(final_urls)}")
            
            # Add performance metrics
            output_lines.append(f"   Performance:")
            output_lines.append(f"     - Impressions: {metrics.get('impressions', 0):,}")
            output_lines.append(f"     - Clicks: {metrics.get('clicks', 0):,}")
            output_lines.append(f"     - CTR: {metrics.get('ctr', 0):.2%}")
            output_lines.append(f"     - Avg CPC: ${metrics.get('averageCpc', 0)/1000000:.2f}")
            output_lines.append(f"     - Cost: ${metrics.get('costMicros', 0)/1000000:.2f}")
            
            output_lines.append("-" * 80)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error retrieving ad creatives: {str(e)}"

@mcp.tool()
async def get_account_currency(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
) -> str:
    """Retrieve the default currency code used by the Google Ads account."""
    query = """
        SELECT
            customer.id,
            customer.currency_code
        FROM customer
        LIMIT 1
    """
    
    try:
        creds = get_credentials()
        if not creds.valid:
            logger.info("Credentials not valid, attempting refresh...")
            if hasattr(creds, 'refresh_token') and creds.refresh_token:
                creds.refresh(AuthRequest())
                logger.info("Credentials refreshed successfully")
            else:
                raise ValueError("Invalid credentials and no refresh token available")
        
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving account currency: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No account information found for this customer ID."
        
        customer = results['results'][0].get('customer', {})
        currency_code = customer.get('currencyCode', 'Not specified')
        
        return f"Account {formatted_customer_id} uses currency: {currency_code}"
    
    except Exception as e:
        logger.error(f"Error retrieving account currency: {str(e)}")
        return f"Error retrieving account currency: {str(e)}"

@mcp.tool()
async def get_image_assets(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    limit: int = Field(default=50, description="Maximum number of image assets to return"),
) -> str:
    """Retrieve all image assets in the account including their full-size URLs."""
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.type,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.height_pixels,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.file_size
        FROM
            asset
        WHERE
            asset.type = 'IMAGE'
        LIMIT {limit}
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving image assets: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No image assets found for this customer ID."
        
        output_lines = [f"Image Assets for Customer ID {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        for i, result in enumerate(results['results'], 1):
            asset = result.get('asset', {})
            image_asset = asset.get('imageAsset', {})
            full_size = image_asset.get('fullSize', {})
            
            output_lines.append(f"\n{i}. Asset ID: {asset.get('id', 'N/A')}")
            output_lines.append(f"   Name: {asset.get('name', 'N/A')}")
            
            if full_size:
                output_lines.append(f"   Image URL: {full_size.get('url', 'N/A')}")
                output_lines.append(f"   Dimensions: {full_size.get('widthPixels', 'N/A')} x {full_size.get('heightPixels', 'N/A')} px")
            
            file_size = image_asset.get('fileSize', 'N/A')
            if file_size != 'N/A':
                file_size_kb = int(file_size) / 1024
                output_lines.append(f"   File Size: {file_size_kb:.2f} KB")
            
            output_lines.append("-" * 80)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error retrieving image assets: {str(e)}"

@mcp.tool()
async def download_image_asset(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    asset_id: str = Field(description="The ID of the image asset to download"),
    output_dir: str = Field(default="./ad_images", description="Directory to save the downloaded image"),
) -> str:
    """Download a specific image asset from a Google Ads account."""
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url
        FROM
            asset
        WHERE
            asset.type = 'IMAGE'
            AND asset.id = {asset_id}
        LIMIT 1
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving image asset: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return f"No image asset found with ID {asset_id}"
        
        asset = results['results'][0].get('asset', {})
        image_url = asset.get('imageAsset', {}).get('fullSize', {}).get('url')
        asset_name = asset.get('name', f"image_{asset_id}")
        
        if not image_url:
            return f"No download URL found for image asset ID {asset_id}"
        
        os.makedirs(output_dir, exist_ok=True)
        
        image_response = requests.get(image_url)
        if image_response.status_code != 200:
            return f"Failed to download image: HTTP {image_response.status_code}"
        
        safe_name = ''.join(c for c in asset_name if c.isalnum() or c in ' ._-')
        filename = f"{asset_id}_{safe_name}.jpg"
        file_path = os.path.join(output_dir, filename)
        
        with open(file_path, 'wb') as f:
            f.write(image_response.content)
        
        return f"Successfully downloaded image asset {asset_id} to {file_path}"
    
    except Exception as e:
        return f"Error downloading image asset: {str(e)}"

@mcp.tool()
async def get_asset_usage(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    asset_id: str = Field(default=None, description="Optional: specific asset ID to look up"),
    asset_type: str = Field(default="IMAGE", description="Asset type to search for"),
) -> str:
    """Find where specific assets are being used in campaigns, ad groups, and ads."""
    where_clause = f"asset.type = '{asset_type}'"
    if asset_id:
        where_clause += f" AND asset.id = {asset_id}"
    
    # Query for campaign-level assets
    campaign_query = f"""
        SELECT
            campaign.id,
            campaign.name,
            asset.id,
            asset.name,
            asset.type
        FROM
            campaign_asset
        WHERE
            {where_clause}
        LIMIT 500
    """
    
    # Query for ad group-level assets
    ad_group_query = f"""
        SELECT
            ad_group.id,
            ad_group.name,
            asset.id,
            asset.name,
            asset.type,
            campaign.name
        FROM
            ad_group_asset
        WHERE
            {where_clause}
        LIMIT 500
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        # Get campaign assets
        payload = {"query": campaign_query}
        campaign_response = requests.post(url, headers=headers, json=payload)
        
        # Get ad group assets
        payload = {"query": ad_group_query}
        ad_group_response = requests.post(url, headers=headers, json=payload)
        
        output_lines = [f"Asset Usage for Customer ID {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        # Process campaign results
        if campaign_response.status_code == 200:
            campaign_results = campaign_response.json()
            if campaign_results.get('results'):
                output_lines.append("\nCampaign-Level Usage:")
                output_lines.append("-" * 60)
                for result in campaign_results['results']:
                    campaign = result.get('campaign', {})
                    asset = result.get('asset', {})
                    output_lines.append(f"Campaign: {campaign.get('name', 'N/A')} (ID: {campaign.get('id', 'N/A')})")
                    output_lines.append(f"  Asset: {asset.get('name', 'N/A')} (ID: {asset.get('id', 'N/A')})")
        
        # Process ad group results
        if ad_group_response.status_code == 200:
            ad_group_results = ad_group_response.json()
            if ad_group_results.get('results'):
                output_lines.append("\nAd Group-Level Usage:")
                output_lines.append("-" * 60)
                for result in ad_group_results['results']:
                    ad_group = result.get('adGroup', {})
                    campaign = result.get('campaign', {})
                    asset = result.get('asset', {})
                    output_lines.append(f"Campaign: {campaign.get('name', 'N/A')}")
                    output_lines.append(f"  Ad Group: {ad_group.get('name', 'N/A')} (ID: {ad_group.get('id', 'N/A')})")
                    output_lines.append(f"  Asset: {asset.get('name', 'N/A')} (ID: {asset.get('id', 'N/A')})")
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error retrieving asset usage: {str(e)}"

@mcp.tool()
async def analyze_image_assets(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)"),
) -> str:
    """Analyze image assets with their performance metrics across campaigns."""
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.full_size.height_pixels,
            campaign.name,
            metrics.impressions,
            metrics.clicks,
            metrics.conversions,
            metrics.cost_micros
        FROM
            campaign_asset
        WHERE
            asset.type = 'IMAGE'
            AND segments.date DURING LAST_{days}_DAYS
        ORDER BY
            metrics.impressions DESC
        LIMIT 200
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error analyzing image assets: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No image asset performance data found for this customer ID and time period."
        
        # Group results by asset ID
        assets_data = {}
        for result in results.get('results', []):
            asset = result.get('asset', {})
            asset_id = asset.get('id')
            
            if asset_id not in assets_data:
                assets_data[asset_id] = {
                    'name': asset.get('name', f"Asset {asset_id}"),
                    'url': asset.get('imageAsset', {}).get('fullSize', {}).get('url', 'N/A'),
                    'dimensions': f"{asset.get('imageAsset', {}).get('fullSize', {}).get('widthPixels', 'N/A')} x {asset.get('imageAsset', {}).get('fullSize', {}).get('heightPixels', 'N/A')}",
                    'impressions': 0,
                    'clicks': 0,
                    'conversions': 0,
                    'cost_micros': 0,
                    'campaigns': set()
                }
            
            metrics = result.get('metrics', {})
            assets_data[asset_id]['impressions'] += int(metrics.get('impressions', 0))
            assets_data[asset_id]['clicks'] += int(metrics.get('clicks', 0))
            assets_data[asset_id]['conversions'] += float(metrics.get('conversions', 0))
            assets_data[asset_id]['cost_micros'] += int(metrics.get('costMicros', 0))
            
            campaign = result.get('campaign', {})
            if campaign.get('name'):
                assets_data[asset_id]['campaigns'].add(campaign.get('name'))
        
        # Format the results
        output_lines = [f"Image Asset Performance Analysis for Customer ID {formatted_customer_id} (Last {days} days):"]
        output_lines.append("=" * 100)
        
        # Sort assets by impressions
        sorted_assets = sorted(assets_data.items(), key=lambda x: x[1]['impressions'], reverse=True)
        
        for asset_id, data in sorted_assets:
            output_lines.append(f"\nAsset ID: {asset_id}")
            output_lines.append(f"Name: {data['name']}")
            output_lines.append(f"Dimensions: {data['dimensions']}")
            
            # Calculate CTR if there are impressions
            ctr = (data['clicks'] / data['impressions'] * 100) if data['impressions'] > 0 else 0
            
            output_lines.append(f"\nPerformance Metrics:")
            output_lines.append(f"  Impressions: {data['impressions']:,}")
            output_lines.append(f"  Clicks: {data['clicks']:,}")
            output_lines.append(f"  CTR: {ctr:.2f}%")
            output_lines.append(f"  Conversions: {data['conversions']:.2f}")
            output_lines.append(f"  Cost: ${data['cost_micros']/1000000:.2f}")
            
            output_lines.append(f"\nUsed in {len(data['campaigns'])} campaigns:")
            for campaign in list(data['campaigns'])[:5]:
                output_lines.append(f"  - {campaign}")
            if len(data['campaigns']) > 5:
                output_lines.append(f"  - ... and {len(data['campaigns']) - 5} more")
            
            if data['url'] != 'N/A':
                output_lines.append(f"\nImage URL: {data['url']}")
            
            output_lines.append("-" * 100)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error analyzing image assets: {str(e)}"

@mcp.tool()
async def list_resources(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
) -> str:
    """List valid resources that can be used in GAQL FROM clauses."""
    query = """
        SELECT
            google_ads_field.name,
            google_ads_field.category,
            google_ads_field.data_type
        FROM
            google_ads_field
        WHERE
            google_ads_field.category = 'RESOURCE'
        ORDER BY
            google_ads_field.name
    """
    return _execute_gaql_query_internal(customer_id, query)

# New tools based on Query Cookbook

@mcp.tool()
async def get_search_keywords(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=7, description="Number of days to look back"),
) -> str:
    """Get search keywords overview with performance metrics."""
    query = f"""
        SELECT
            ad_group_criterion.keyword.text,
            campaign.name,
            ad_group.name,
            ad_group_criterion.system_serving_status,
            ad_group_criterion.keyword.match_type,
            ad_group_criterion.approval_status,
            ad_group_criterion.final_urls,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros
        FROM keyword_view
        WHERE segments.date DURING LAST_{days}_DAYS
            AND ad_group_criterion.status != 'REMOVED'
        ORDER BY metrics.impressions DESC
        LIMIT 100
    """
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def get_search_terms(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=7, description="Number of days to look back"),
) -> str:
    """Get search terms report showing what users actually searched for."""
    query = f"""
        SELECT
            search_term_view.search_term,
            segments.keyword.info.match_type,
            search_term_view.status,
            campaign.name,
            ad_group.name,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros,
            campaign.advertising_channel_type
        FROM search_term_view
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
        LIMIT 100
    """
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def get_audiences(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=7, description="Number of days to look back"),
) -> str:
    """Get audiences overview with performance metrics."""
    query = f"""
        SELECT
            ad_group_criterion.resource_name,
            ad_group_criterion.type,
            campaign.name,
            ad_group.name,
            ad_group_criterion.system_serving_status,
            ad_group_criterion.bid_modifier,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros,
            campaign.advertising_channel_type
        FROM ad_group_audience_view
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
        LIMIT 100
    """
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def get_age_demographics(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=7, description="Number of days to look back"),
) -> str:
    """Get age demographics performance data."""
    query = f"""
        SELECT
            ad_group_criterion.age_range.type,
            campaign.name,
            ad_group.name,
            ad_group_criterion.system_serving_status,
            ad_group_criterion.bid_modifier,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros,
            campaign.advertising_channel_type
        FROM age_range_view
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
    """
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def get_gender_demographics(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=7, description="Number of days to look back"),
) -> str:
    """Get gender demographics performance data."""
    query = f"""
        SELECT
            ad_group_criterion.gender.type,
            campaign.name,
            ad_group.name,
            ad_group_criterion.system_serving_status,
            ad_group_criterion.bid_modifier,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros,
            campaign.advertising_channel_type
        FROM gender_view
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
    """
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def get_locations(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days: int = Field(default=7, description="Number of days to look back"),
) -> str:
    """Get location-based performance data."""
    query = f"""
        SELECT
            campaign_criterion.resource_name,
            campaign_criterion.criterion_id,
            campaign.name,
            campaign_criterion.bid_modifier,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros
        FROM location_view
        WHERE segments.date DURING LAST_{days}_DAYS
            AND campaign_criterion.status != 'REMOVED'
        ORDER BY metrics.impressions DESC
        LIMIT 100
    """
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def lookup_geo_constant(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    location_name: str = Field(default=None, description="Location name to search for (e.g., 'Mountain View')"),
    resource_name: str = Field(default=None, description="Geo target constant resource name (e.g., 'geoTargetConstants/1014044')"),
    country_code: str = Field(default="US", description="Country code for location search"),
    target_type: str = Field(default=None, description="Target type: City, State, Country, etc."),
) -> str:
    """Look up geographic constants by name or resource name."""
    if resource_name:
        query = f"""
            SELECT
                geo_target_constant.canonical_name,
                geo_target_constant.country_code,
                geo_target_constant.id,
                geo_target_constant.name,
                geo_target_constant.status,
                geo_target_constant.target_type
            FROM geo_target_constant
            WHERE geo_target_constant.resource_name = '{resource_name}'
        """
    elif location_name:
        query = f"""
            SELECT
                geo_target_constant.canonical_name,
                geo_target_constant.country_code,
                geo_target_constant.id,
                geo_target_constant.name,
                geo_target_constant.status,
                geo_target_constant.target_type,
                geo_target_constant.resource_name
            FROM geo_target_constant
            WHERE geo_target_constant.country_code = '{country_code}'
                AND geo_target_constant.name = '{location_name}'
                AND geo_target_constant.status = 'ENABLED'
        """
        if target_type:
            query = query.replace("AND geo_target_constant.status", f"AND geo_target_constant.target_type = '{target_type}'\n                AND geo_target_constant.status")
    else:
        return "Please provide either a location_name or resource_name to search for."
    
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def search_customer_by_name(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    search_term: str = Field(description="Search term to find in customer names (case-insensitive)"),
) -> str:
    """Search for customer clients by name using case-insensitive pattern matching.
    
    This tool helps find customer accounts when you only know part of their name.
    It uses REGEXP_MATCH with case-insensitive flag for flexible searching.
    """
    # Escape special regex characters in the search term
    escaped_term = search_term.replace('\\', '\\\\').replace('.', '\\.').replace('*', '\\*').replace('+', '\\+').replace('?', '\\?').replace('[', '\\[').replace(']', '\\]').replace('^', '\\^').replace('$', '\\$').replace('(', '\\(').replace(')', '\\)').replace('{', '\\{').replace('}', '\\}').replace('|', '\\|')
    
    query = f"""
        SELECT 
            customer_client.id,
            customer_client.descriptive_name,
            customer_client.manager,
            customer_client.status,
            customer_client.level
        FROM customer_client
        WHERE customer_client.descriptive_name REGEXP_MATCH "(?i).*{escaped_term}.*"
        ORDER BY customer_client.descriptive_name
        LIMIT 100
    """
    
    return _execute_gaql_query_internal(customer_id, query)

@mcp.tool()
async def get_change_history(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days_back: int = Field(default=14, description="Number of days to look back (max 30)"),
    limit: int = Field(default=50, description="Maximum number of changes to return"),
    resource_type: str = Field(default=None, description="Filter by resource type (e.g., 'CAMPAIGN', 'AD_GROUP', 'AD')"),
) -> str:
    """
    Get recent changes made to the Google Ads account.
    
    This tool shows what changes were made, when, by whom, and what fields were modified.
    Useful for auditing account changes and understanding recent modifications.
    
    Args:
        customer_id: The Google Ads customer ID
        days_back: Number of days to look back (maximum 30 days)
        limit: Maximum number of changes to return
        resource_type: Optional filter by resource type
        
    Returns:
        Formatted list of recent changes with details
    """
    # Ensure days_back doesn't exceed 30 days (API limitation)
    if days_back > 30:
        days_back = 30
        
    # Calculate date range
    from datetime import datetime, timedelta
    tomorrow = (datetime.now() + timedelta(1)).strftime("%Y-%m-%d")
    start_date = (datetime.now() - timedelta(days_back)).strftime("%Y-%m-%d")
    
    # Build query
    query = f"""
        SELECT
            change_event.resource_name,
            change_event.change_date_time,
            change_event.change_resource_name,
            change_event.user_email,
            change_event.client_type,
            change_event.change_resource_type,
            change_event.resource_change_operation,
            change_event.changed_fields
        FROM change_event
        WHERE change_event.change_date_time <= '{tomorrow}'
            AND change_event.change_date_time >= '{start_date}'
    """
    
    # Add resource type filter if specified
    if resource_type:
        query += f"\n            AND change_event.change_resource_type = '{resource_type}'"
        
    query += f"\n        ORDER BY change_event.change_date_time DESC"
    query += f"\n        LIMIT {limit}"
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving change history: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return f"No changes found in the last {days_back} days."
        
        # Format the results
        output_lines = [f"Change History for Customer ID {formatted_customer_id} (Last {days_back} days):"]
        output_lines.append("=" * 100)
        
        for i, result in enumerate(results['results'], 1):
            change_event = result.get('changeEvent', {})
            
            # Extract change details
            change_time = change_event.get('changeDateTime', 'N/A')
            user_email = change_event.get('userEmail', 'Unknown')
            client_type = change_event.get('clientType', 'Unknown')
            resource_type = change_event.get('changeResourceType', 'Unknown')
            operation = change_event.get('resourceChangeOperation', 'Unknown')
            resource_name = change_event.get('changeResourceName', 'N/A')
            changed_fields = change_event.get('changedFields', {}).get('paths', [])
            
            output_lines.append(f"\n{i}. Change Event:")
            output_lines.append(f"   Date/Time: {change_time}")
            output_lines.append(f"   User: {user_email}")
            output_lines.append(f"   Client: {client_type}")
            output_lines.append(f"   Resource Type: {resource_type}")
            output_lines.append(f"   Operation: {operation}")
            output_lines.append(f"   Resource: {resource_name}")
            
            if changed_fields:
                output_lines.append(f"   Changed Fields:")
                for field in changed_fields:
                    output_lines.append(f"     - {field}")
            
            output_lines.append("-" * 100)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error retrieving change history: {str(e)}"

@mcp.tool()
async def get_detailed_change_history(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    days_back: int = Field(default=7, description="Number of days to look back (max 30)"),
    limit: int = Field(default=20, description="Maximum number of changes to return"),
) -> str:
    """
    Get detailed change history including old and new values for recent account modifications.
    
    This provides more detailed information than get_change_history, showing exact field 
    values before and after changes. Due to the complexity, it returns fewer results.
    
    Args:
        customer_id: The Google Ads customer ID
        days_back: Number of days to look back (maximum 30 days)
        limit: Maximum number of changes to return (default 20)
        
    Returns:
        Detailed change history with before/after values
    """
    # Ensure days_back doesn't exceed 30 days
    if days_back > 30:
        days_back = 30
        
    from datetime import datetime, timedelta
    tomorrow = (datetime.now() + timedelta(1)).strftime("%Y-%m-%d")
    start_date = (datetime.now() - timedelta(days_back)).strftime("%Y-%m-%d")
    
    query = f"""
        SELECT
            change_event.resource_name,
            change_event.change_date_time,
            change_event.change_resource_name,
            change_event.user_email,
            change_event.client_type,
            change_event.change_resource_type,
            change_event.old_resource,
            change_event.new_resource,
            change_event.resource_change_operation,
            change_event.changed_fields
        FROM change_event
        WHERE change_event.change_date_time <= '{tomorrow}'
            AND change_event.change_date_time >= '{start_date}'
        ORDER BY change_event.change_date_time DESC
        LIMIT {limit}
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving detailed change history: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return f"No changes found in the last {days_back} days."
        
        output_lines = [f"Detailed Change History for Customer ID {formatted_customer_id} (Last {days_back} days):"]
        output_lines.append("=" * 100)
        
        for i, result in enumerate(results['results'], 1):
            change_event = result.get('changeEvent', {})
            
            change_time = change_event.get('changeDateTime', 'N/A')
            user_email = change_event.get('userEmail', 'Unknown')
            client_type = change_event.get('clientType', 'Unknown')
            resource_type = change_event.get('changeResourceType', 'Unknown')
            operation = change_event.get('resourceChangeOperation', 'Unknown')
            resource_name = change_event.get('changeResourceName', 'N/A')
            changed_fields = change_event.get('changedFields', {}).get('paths', [])
            
            output_lines.append(f"\n{i}. {operation} on {resource_type}")
            output_lines.append(f"   Date/Time: {change_time}")
            output_lines.append(f"   User: {user_email}")
            output_lines.append(f"   Client: {client_type}")
            output_lines.append(f"   Resource: {resource_name}")
            
            # Handle different operations
            if operation in ['UPDATE', 'CREATE'] and changed_fields:
                output_lines.append(f"\n   Field Changes:")
                
                old_resource = change_event.get('oldResource', {})
                new_resource = change_event.get('newResource', {})
                
                for field_path in changed_fields[:10]:  # Limit to first 10 fields
                    # Clean field name
                    field_name = field_path
                    if field_name == 'type':
                        field_name = 'type_'
                    
                    output_lines.append(f"\n     {field_name}:")
                    
                    if operation == 'CREATE':
                        # For CREATE, only show new value
                        new_value = _extract_field_value(new_resource, resource_type.lower(), field_name)
                        output_lines.append(f"       Set to: {new_value}")
                    else:
                        # For UPDATE, show old and new values
                        old_value = _extract_field_value(old_resource, resource_type.lower(), field_name)
                        new_value = _extract_field_value(new_resource, resource_type.lower(), field_name)
                        output_lines.append(f"       From: {old_value}")
                        output_lines.append(f"       To: {new_value}")
                
                if len(changed_fields) > 10:
                    output_lines.append(f"\n     ... and {len(changed_fields) - 10} more fields")
            
            elif operation == 'REMOVE':
                output_lines.append(f"\n   Resource was removed")
            
            output_lines.append("-" * 100)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error retrieving detailed change history: {str(e)}"

def _extract_field_value(resource_data: dict, resource_type: str, field_path: str) -> str:
    """Helper function to extract field value from resource data"""
    try:
        # Navigate to the resource type first
        if resource_type in resource_data:
            resource = resource_data[resource_type]
        else:
            # Try alternative naming conventions
            type_mapping = {
                'campaign': 'campaign',
                'ad_group': 'adGroup',
                'ad_group_ad': 'adGroupAd',
                'ad': 'ad',
                'campaign_budget': 'campaignBudget',
                'ad_group_criterion': 'adGroupCriterion'
            }
            mapped_type = type_mapping.get(resource_type.lower(), resource_type)
            resource = resource_data.get(mapped_type, {})
        
        # Navigate through the field path
        value = resource
        for part in field_path.split('.'):
            if isinstance(value, dict):
                value = value.get(part, 'N/A')
            else:
                return 'N/A'
        
        # Format the value
        if isinstance(value, dict):
            # For complex objects, try to get a meaningful representation
            if 'text' in value:
                return value['text']
            elif 'value' in value:
                return str(value['value'])
            else:
                return json.dumps(value, indent=2)
        elif isinstance(value, list):
            return f"[{len(value)} items]"
        else:
            return str(value)
            
    except Exception:
        return 'N/A'

# Resources and Prompts
@mcp.resource("gaql://reference")
def gaql_reference() -> str:
    """Google Ads Query Language (GAQL) reference documentation."""
    return """
    # Google Ads Query Language (GAQL) Reference
    
    GAQL is similar to SQL but with specific syntax for Google Ads. Here's a quick reference:
    
    ## Basic Query Structure
    ```
    SELECT field1, field2, ... 
    FROM resource_type
    WHERE condition
    ORDER BY field [ASC|DESC]
    LIMIT n
    ```
    
    ## Important GAQL Limitations
    - **NO OR operator** - WHERE clause only supports AND conditions
    - **Use REGEXP_MATCH for pattern matching** - For case-insensitive search: REGEXP_MATCH "(?i)pattern"
    - **Use IN for multiple values** - WHERE field IN ('value1', 'value2')
    
    ## Common Resources (FROM clause)
    - campaign - Campaign data
    - ad_group - Ad group data
    - ad_group_ad - Ads data
    - keyword_view - Keyword performance
    - search_term_view - Search terms report
    - age_range_view - Age demographics
    - gender_view - Gender demographics
    - location_view - Geographic performance
    - asset - Assets (images, videos, etc.)
    - campaign_asset - Campaign-level assets
    - ad_group_asset - Ad group-level assets
    - customer_client - Client accounts under MCC
    
    ## Common Field Types
    
    ### Resource Fields
    - campaign.id, campaign.name, campaign.status
    - ad_group.id, ad_group.name, ad_group.status
    - ad_group_ad.ad.id, ad_group_ad.ad.final_urls
    - keyword.text, keyword.match_type
    - customer_client.descriptive_name, customer_client.id
    
    ### Metric Fields
    - metrics.impressions
    - metrics.clicks
    - metrics.cost_micros (in millionths of currency)
    - metrics.conversions
    - metrics.ctr
    - metrics.average_cpc
    
    ### Segment Fields
    - segments.date
    - segments.device
    - segments.day_of_week
    
    ## Common WHERE Clauses
    
    ### Date Ranges
    - WHERE segments.date DURING LAST_7_DAYS
    - WHERE segments.date DURING LAST_30_DAYS
    - WHERE segments.date BETWEEN '2023-01-01' AND '2023-01-31'
    
    ### Filtering (NO OR OPERATOR!)
    - WHERE campaign.status = 'ENABLED'
    - WHERE metrics.clicks > 100
    - WHERE campaign.name LIKE '%Brand%'
    - WHERE ad_group_criterion.status != 'REMOVED'
    
    ### Pattern Matching (Case-Insensitive)
    - WHERE field REGEXP_MATCH "(?i).*pattern.*"
    - WHERE field REGEXP_MATCH "(?i)^starts with.*"
    - WHERE field REGEXP_MATCH "(?i).*ends with$"
    
    ### Multiple Values
    - WHERE campaign.id IN ('123', '456', '789')
    - WHERE campaign.status IN ('ENABLED', 'PAUSED')
    
    ## Tips
    - Always check account currency before analyzing cost data
    - Cost values are in micros (millionths): 1000000 = 1 unit of currency
    - Use LIMIT to avoid large result sets
    - Check resource status to exclude removed items
    - Remember: OR is not supported - use REGEXP_MATCH or IN instead
    """

@mcp.prompt("google_ads_workflow")
def google_ads_workflow() -> str:
    """Provides guidance on the recommended workflow for using Google Ads tools."""
    return """
    I'll help you analyze your Google Ads account data. Here's the recommended workflow:
    
    1. First, let's list all the accounts you have access to:
       - Run the `list_accounts()` tool to get available account IDs
    
    2. Search for specific accounts by name:
       - Use `search_customer_by_name(customer_id="MCC_ID", search_term="arvest")`
       - This uses case-insensitive pattern matching
    
    3. Before analyzing cost data, let's check which currency the account uses:
       - Run `get_account_currency(customer_id="ACCOUNT_ID")` with your selected account
    
    4. Now we can explore the account data:
       - Campaign performance: `get_campaign_performance(customer_id="ACCOUNT_ID", days=30)`
       - Ad performance: `get_ad_performance(customer_id="ACCOUNT_ID", days=30)`
       - Ad creatives: `get_ad_creatives(customer_id="ACCOUNT_ID")`
       - Search keywords: `get_search_keywords(customer_id="ACCOUNT_ID")`
       - Search terms: `get_search_terms(customer_id="ACCOUNT_ID")`
       - Demographics: `get_age_demographics()` and `get_gender_demographics()`
       - Geographic data: `get_locations(customer_id="ACCOUNT_ID")`
       - Change history: `get_change_history(customer_id="ACCOUNT_ID")`
       - Detailed change history: `get_detailed_change_history(customer_id="ACCOUNT_ID")`
       - Image assets: `get_image_assets(customer_id="ACCOUNT_ID")`
    
    5. For custom queries, use the GAQL query tool:
       - `run_gaql(customer_id="ACCOUNT_ID", query="YOUR_QUERY", format="table")`
       - Remember: GAQL doesn't support OR - use REGEXP_MATCH or IN instead
    
    6. For asset analysis:
       - List image assets: `get_image_assets(customer_id="ACCOUNT_ID")`
       - Analyze performance: `analyze_image_assets(customer_id="ACCOUNT_ID")`
       - Check usage: `get_asset_usage(customer_id="ACCOUNT_ID", asset_id="ASSET_ID")`
       - Download assets: `download_image_asset(customer_id="ACCOUNT_ID", asset_id="ASSET_ID")`
    
    Important: Always provide the customer_id as a string.
    For example: customer_id="1234567890"
    """

@mcp.prompt("gaql_help")
def gaql_help() -> str:
    """Provides assistance for writing GAQL queries."""
    return """
    I'll help you write a Google Ads Query Language (GAQL) query. Here are some examples based on common use cases:
    
    ## IMPORTANT: GAQL Syntax Limitations
    - **NO OR operator** - Use REGEXP_MATCH or IN instead
    - **Case-insensitive search** - Use REGEXP_MATCH "(?i)pattern"
    
    ## Campaign Performance (Default UI View)
    ```
    SELECT campaign.name,
        campaign_budget.amount_micros,
        campaign.status,
        campaign.optimization_score,
        campaign.advertising_channel_type,
        metrics.clicks,
        metrics.impressions,
        metrics.ctr,
        metrics.average_cpc,
        metrics.cost_micros,
        campaign.bidding_strategy_type
    FROM campaign
    WHERE segments.date DURING LAST_7_DAYS
        AND campaign.status != 'REMOVED'
    ```
    
    ## Search for Accounts by Name (Case-Insensitive)
    ```
    SELECT 
        customer_client.id,
        customer_client.descriptive_name,
        customer_client.status
    FROM customer_client
    WHERE customer_client.descriptive_name REGEXP_MATCH "(?i).*arvest.*"
    ```
    
    ## Ad Groups Overview
    ```
    SELECT ad_group.name,
        campaign.name,
        ad_group.status,
        ad_group.type,
        metrics.clicks,
        metrics.impressions,
        metrics.ctr,
        metrics.average_cpc,
        metrics.cost_micros
    FROM ad_group
    WHERE segments.date DURING LAST_7_DAYS
        AND ad_group.status != 'REMOVED'
    ```
    
    ## Responsive Search Ads with Headlines
    ```
    SELECT
        ad_group_ad.ad.responsive_search_ad.headlines,
        ad_group_ad.ad.responsive_search_ad.descriptions,
        ad_group_ad.ad.final_urls,
        campaign.name,
        ad_group.name,
        metrics.impressions,
        metrics.clicks
    FROM ad_group_ad
    WHERE segments.date DURING LAST_7_DAYS
        AND ad_group_ad.status != 'REMOVED'
    ```
    
    ## Keyword Performance
    ```
    SELECT
        ad_group_criterion.keyword.text,
        ad_group_criterion.keyword.match_type,
        metrics.impressions,
        metrics.clicks,
        metrics.cost_micros,
        metrics.conversions
    FROM keyword_view
    WHERE segments.date DURING LAST_30_DAYS
    ORDER BY metrics.clicks DESC
    ```
    
    ## Multiple Status Values (Using IN)
    ```
    SELECT campaign.name, campaign.status, metrics.clicks
    FROM campaign
    WHERE campaign.status IN ('ENABLED', 'PAUSED')
        AND segments.date DURING LAST_7_DAYS
    ```
    
    ## Geographic Performance
    ```
    SELECT
        campaign_criterion.criterion_id,
        campaign.name,
        metrics.impressions,
        metrics.clicks,
        metrics.conversions
    FROM location_view
    WHERE segments.date DURING LAST_30_DAYS
    ```
    
    Once you've chosen a query, use it with:
    ```
    run_gaql(customer_id="YOUR_ACCOUNT_ID", query="YOUR_QUERY_HERE")
    ```
    
    Remember:
    - Always provide the customer_id as a string
    - Cost values are in micros (1,000,000 = 1 unit of currency)
    - Use LIMIT to avoid large result sets
    - Check the account currency before analyzing cost data
    - Use segments.date for date filtering
    - Exclude REMOVED status items for cleaner results
    - NO OR operator - use REGEXP_MATCH "(?i)pattern" for case-insensitive search
    """

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    
    # Log server configuration
    logger.info("=" * 60)
    logger.info("🚀 Starting Google Ads MCP Server with OAuth")
    logger.info(f"📍 Port: {port}")
    logger.info(f"🔐 Authentication: OAuth 2.1 with Client Credentials")
    logger.info(f"🌐 Base URL: {base_url}")
    logger.info("=" * 60)
    logger.info("OAuth Configuration:")
    if len(allowed_clients) > 0 and "default_client" not in allowed_clients:
        logger.info(f"  Configured Clients: {len(allowed_clients)}")
        for client_id in allowed_clients.keys():
            logger.info(f"    - {client_id}")
    logger.info("OAuth Endpoints:")
    logger.info(f"  Authorization: {base_url}/oauth/authorize")
    logger.info(f"  Token: {base_url}/oauth/token")
    logger.info(f"  Discovery: {base_url}/.well-known/oauth-authorization-server")
    logger.info(f"  Registration: {base_url}/oauth/register")
    logger.info("=" * 60)
    
    # Run FastMCP server with streamable-http transport
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port
    )
