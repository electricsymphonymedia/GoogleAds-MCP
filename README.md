# Google Ads MCP Server 🚀

A secure Model Context Protocol (MCP) server that enables Claude Desktop to interact with Google Ads accounts through OAuth-authenticated API access. Built with FastMCP and deployed on Railway for seamless cloud hosting.

## 🌟 Features

- **Secure OAuth 2.0 Authentication**: Only authorized clients with valid credentials can access
- **Full Google Ads API Integration**: Query campaigns, ads, keywords, demographics, and more
- **GAQL Query Support**: Execute custom Google Ads Query Language queries
- **Real-time Performance Metrics**: Access campaign performance, cost data, and conversion metrics
- **Asset Management**: View and analyze image assets and their usage
- **Change History Tracking**: Monitor account modifications and audit trails
- **MCP Protocol Compliance**: Full integration with Claude Desktop via Model Context Protocol
- **Cloud-Ready**: Optimized for Railway deployment with Docker containerization

## 🔒 Security Features

- **Strict Client Authentication**: No dynamic registration - only pre-configured OAuth clients
- **Token-Based Access Control**: Secure token exchange with automatic expiration
- **Secret Validation**: Both client ID and secret must match exactly
- **Audit Logging**: All authentication attempts are logged
- **No Default Credentials**: Server refuses to start without proper OAuth configuration

## 📋 Prerequisites

- Google Ads Developer Token
- Google Ads API OAuth credentials
- Railway account (for deployment)
- Claude Desktop application

## 🚀 Quick Start

### 1. Deploy to Railway

[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template)

### 2. Set Environment Variables in Railway

```bash
# REQUIRED - OAuth Client Configuration (for MCP authentication)
OAUTH_CLIENTS=your-client-id:your-client-secret

# REQUIRED - Google Ads API Credentials
GOOGLE_ADS_OAUTH_TOKENS_BASE64=<base64_encoded_oauth_tokens>
GOOGLE_ADS_DEVELOPER_TOKEN=<your_developer_token>
GOOGLE_ADS_LOGIN_CUSTOMER_ID=<your_login_customer_id>

# Optional
PORT=8080
```

### 3. Configure Claude Desktop
You would need a Claude Team or Enterprise Plan for this deployment.
Add to Claude Desktop settings (Settings → Manage Connectors → Organization Connectors → Add Custom Connector):

Name: Google Ads MCP 
URL: https://your-app.up.railway.app/mcp/sse

Click Advance Setting:

OAuth Client ID: your-client-id-same-as-railway-deployment
OAuth Client Secret: your-client-secret-same-as-railway-deployment

⚠️ **Important**: The `clientId` and `clientSecret` in Claude MUST match exactly what you set in `OAUTH_CLIENTS` environment variable.

## 🔧 Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `OAUTH_CLIENTS` | OAuth client credentials for MCP authentication | `my-app:secret123` |
| `GOOGLE_ADS_OAUTH_TOKENS_BASE64` | Base64 encoded Google Ads OAuth tokens | `ase234aswersvlbiI6I...` |
| `GOOGLE_ADS_DEVELOPER_TOKEN` | Your Google Ads API developer token | `abc123xyz789` |
| `GOOGLE_ADS_LOGIN_CUSTOMER_ID` | Manager account customer ID (optional for some setups) | `1234567890` |

### OAuth Tokens Format

The `GOOGLE_ADS_OAUTH_TOKENS_BASE64` should be a base64-encoded JSON object:

```json
{
  "token": "access_token_here",
  "refresh_token": "refresh_token_here",
  "token_uri": "https://oauth2.googleapis.com/token",
  "client_id": "your_google_oauth_client_id",
  "client_secret": "your_google_oauth_client_secret",
  "scopes": ["https://www.googleapis.com/auth/adwords"],
  "expiry": "2024-01-01T00:00:00Z"
}
```

Encode it: `echo '<json_above>' | base64`

### Multiple OAuth Clients

To allow multiple Claude instances or users:

```bash
OAUTH_CLIENTS=client1:secret1,client2:secret2,client3:secret3
```

## 📚 Available Tools

### Account Management
- `list_accounts()` - List all accessible Google Ads accounts
- `search_customer_by_name()` - Search for customer accounts by name
- `get_account_currency()` - Get account currency code

### Performance Analytics
- `get_campaign_performance()` - Campaign metrics and performance
- `get_ad_performance()` - Ad-level performance data
- `get_ad_creatives()` - Ad headlines, descriptions, and URLs

### Keyword & Search
- `get_search_keywords()` - Keyword performance metrics
- `get_search_terms()` - Actual search terms report

### Demographics & Targeting
- `get_audiences()` - Audience performance data
- `get_age_demographics()` - Age-based performance
- `get_gender_demographics()` - Gender-based performance
- `get_locations()` - Geographic performance data

### Asset Management
- `get_image_assets()` - List all image assets
- `analyze_image_assets()` - Image performance analysis
- `get_asset_usage()` - Where assets are being used
- `download_image_asset()` - Download specific assets

### Advanced Queries
- `execute_gaql_query()` - Execute custom GAQL queries
- `run_gaql()` - Run GAQL with formatting options

### Change History
- `get_change_history()` - Recent account changes
- `get_detailed_change_history()` - Detailed changes with before/after values

## 💬 Usage Examples in Claude

Once connected, you can ask Claude:

```
"List all my Google Ads accounts"
"Show campaign performance for account 1234567890 for the last 30 days"
"What are the top performing keywords?"
"Run a GAQL query to get all active campaigns"
"Show me the change history for the last week"
"Analyze image asset performance"
```

## 🏗️ Architecture

```
┌─────────────┐       OAuth 2.0          ┌──────────────┐
│   Claude    │ ◄──────────────────────► │  MCP Server  │
│   Desktop   │                          │  (Railway)   │
└─────────────┘                          └──────────────┘
                                                 │
                                          Google Ads API
                                                 ▼
                                         ┌──────────────┐
                                         │ Google Ads   │
                                         │   Account    │
                                         └──────────────┘
```

## 🐳 Local Development

### Clone the Repository

```bash
git clone https://github.com/yourusername/google-ads-mcp-server.git
cd google-ads-mcp-server
```

### Create `.env` File

```bash
# OAuth Configuration
OAUTH_CLIENTS=dev-client:dev-secret

# Google Ads Configuration
GOOGLE_ADS_OAUTH_TOKENS_BASE64=your_base64_token
GOOGLE_ADS_DEVELOPER_TOKEN=your_dev_token
GOOGLE_ADS_LOGIN_CUSTOMER_ID=your_customer_id
```

### Run with Docker

```bash
# Build the image
docker build -t google-ads-mcp .

# Run the container
docker run -p 8080:8080 --env-file .env google-ads-mcp
```

### Run with Python

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python server-fastmcp-simple.py
```

## 🚨 Troubleshooting

### Connection Issues

1. **"Unauthorized" error in Claude**
   - Verify `clientId` and `clientSecret` match exactly in both Railway and Claude
   - Check Railway logs for specific authentication errors

2. **"No OAuth clients configured" error**
   - Ensure `OAUTH_CLIENTS` environment variable is set in Railway
   - Format: `CLIENT_ID:CLIENT_SECRET`

3. **Google Ads API errors**
   - Verify your developer token is active
   - Check that OAuth tokens are properly base64 encoded
   - Ensure customer ID format is correct (10 digits, no dashes)

### Common GAQL Issues

- **"OR not supported" error**: Use `REGEXP_MATCH` or `IN` operator instead
- **Case-sensitive searches**: Use `REGEXP_MATCH "(?i)pattern"` for case-insensitive
- **Date ranges**: Use `DURING LAST_X_DAYS` format

### Viewing Logs

In Railway dashboard:
1. Go to your deployment
2. Click on "View Logs"
3. Look for authentication and API call logs

## 📝 GAQL Query Examples

```sql
-- Get campaign performance
SELECT campaign.name, metrics.clicks, metrics.impressions
FROM campaign
WHERE segments.date DURING LAST_30_DAYS

-- Search for accounts (case-insensitive)
SELECT customer_client.id, customer_client.descriptive_name
FROM customer_client
WHERE customer_client.descriptive_name REGEXP_MATCH "(?i).*search_term.*"

-- Get keyword performance
SELECT ad_group_criterion.keyword.text, metrics.clicks, metrics.cost_micros
FROM keyword_view
WHERE segments.date DURING LAST_7_DAYS
ORDER BY metrics.clicks DESC
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License - see LICENSE file for details

## 🔗 Resources

- [MCP Documentation](https://modelcontextprotocol.io)
- [Google Ads API Documentation](https://developers.google.com/google-ads/api/docs/start)
- [GAQL Reference](https://developers.google.com/google-ads/api/docs/query/overview)
- [Railway Documentation](https://docs.railway.app)
- [FastMCP Documentation](https://github.com/jlowin/fastmcp)

## 🙏 Acknowledgments

- Built with [FastMCP](https://github.com/jlowin/fastmcp) framework
- Deployed on [Railway](https://railway.app)
- Integrated with [Claude Desktop](https://claude.ai)

## 📧 Support

For issues, questions, or suggestions, please open an issue on GitHub or contact the maintainers.

---

**Security Note**: Never commit your actual credentials to version control. Always use environment variables for sensitive data.
