"""
Built-in security analysis patterns for JavaScript.

Organized into categories:
  - SECRETS       : API keys, tokens, passwords, credentials
  - ENDPOINTS     : API paths, REST routes, GraphQL
  - HOSTNAMES     : Domain names, IPs, cloud service URLs
  - DOM_SINKS     : Dangerous DOM APIs (XSS vectors)
  - POSTMESSAGE   : postMessage handlers (origin validation issues)
  - OPEN_REDIRECT : Redirect sinks
  - PROTOTYPE     : Prototype pollution vectors
  - STORAGE       : localStorage/sessionStorage/cookie access
  - CRYPTO        : Weak crypto, hardcoded keys/IVs
"""
from dataclasses import dataclass, field


@dataclass
class Pattern:
    name: str
    regex: str
    finding_type: str
    category: str
    severity: str        # critical, high, medium, low, info
    confidence: str      # high, medium, low
    description: str = ""
    context_lines: int = 2   # lines of context to capture


# ---------------------------------------------------------------------------
# SECRETS
# ---------------------------------------------------------------------------
SECRET_PATTERNS: list[Pattern] = [
    Pattern(
        name="aws_access_key",
        regex=r'(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])',
        finding_type="secret",
        category="aws_access_key",
        severity="critical",
        confidence="high",
        description="AWS Access Key ID",
    ),
    Pattern(
        name="aws_secret_key",
        regex=r'(?i)aws.{0,20}["\']([A-Za-z0-9/+=]{40})["\']',
        finding_type="secret",
        category="aws_secret_key",
        severity="critical",
        confidence="medium",
        description="AWS Secret Access Key",
    ),
    Pattern(
        name="aws_mws_key",
        regex=r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        finding_type="secret",
        category="aws_mws_key",
        severity="high",
        confidence="high",
        description="Amazon MWS Auth Token",
    ),
    Pattern(
        name="google_api_key",
        regex=r'AIza[0-9A-Za-z\-_]{35}',
        finding_type="secret",
        category="google_api_key",
        severity="high",
        confidence="high",
        description="Google API Key",
    ),
    Pattern(
        name="google_oauth",
        regex=r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
        finding_type="secret",
        category="google_oauth_id",
        severity="medium",
        confidence="high",
        description="Google OAuth Client ID",
    ),
    Pattern(
        name="github_token",
        regex=r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}',
        finding_type="secret",
        category="github_token",
        severity="critical",
        confidence="high",
        description="GitHub Personal Access Token",
    ),
    Pattern(
        name="github_oauth",
        regex=r'(?i)github.{0,20}["\']([0-9a-z]{40})["\']',
        finding_type="secret",
        category="github_oauth",
        severity="high",
        confidence="medium",
        description="GitHub OAuth Token",
    ),
    Pattern(
        name="stripe_key",
        regex=r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}',
        finding_type="secret",
        category="stripe_key",
        severity="critical",
        confidence="high",
        description="Stripe API Key",
    ),
    Pattern(
        name="stripe_restricted",
        regex=r'rk_(?:live|test)_[0-9a-zA-Z]{24,}',
        finding_type="secret",
        category="stripe_restricted_key",
        severity="high",
        confidence="high",
        description="Stripe Restricted Key",
    ),
    Pattern(
        name="slack_token",
        regex=r'xox[baprs]-[0-9A-Za-z\-]{10,}',
        finding_type="secret",
        category="slack_token",
        severity="high",
        confidence="high",
        description="Slack Token",
    ),
    Pattern(
        name="slack_webhook",
        regex=r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+',
        finding_type="secret",
        category="slack_webhook",
        severity="high",
        confidence="high",
        description="Slack Incoming Webhook URL",
    ),
    Pattern(
        name="jwt_token",
        regex=r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}',
        finding_type="secret",
        category="jwt_token",
        severity="high",
        confidence="high",
        description="JSON Web Token (JWT) — may contain sensitive claims",
    ),
    Pattern(
        name="private_key_header",
        regex=r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        finding_type="secret",
        category="private_key",
        severity="critical",
        confidence="high",
        description="Private Key",
    ),
    Pattern(
        name="firebase_key",
        regex=r'AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}',
        finding_type="secret",
        category="firebase_key",
        severity="high",
        confidence="high",
        description="Firebase Server Key",
    ),
    Pattern(
        name="sendgrid_key",
        regex=r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
        finding_type="secret",
        category="sendgrid_key",
        severity="high",
        confidence="high",
        description="SendGrid API Key",
    ),
    Pattern(
        name="twilio_sid",
        regex=r'AC[0-9a-fA-F]{32}',
        finding_type="secret",
        category="twilio_sid",
        severity="high",
        confidence="medium",
        description="Twilio Account SID",
    ),
    Pattern(
        name="twilio_token",
        regex=r'SK[0-9a-fA-F]{32}',
        finding_type="secret",
        category="twilio_token",
        severity="high",
        confidence="medium",
        description="Twilio API Token",
    ),
    Pattern(
        name="mailchimp_key",
        regex=r'[0-9a-f]{32}-us[0-9]{1,2}',
        finding_type="secret",
        category="mailchimp_key",
        severity="high",
        confidence="high",
        description="Mailchimp API Key",
    ),
    Pattern(
        name="mailgun_key",
        regex=r'key-[0-9a-zA-Z]{32}',
        finding_type="secret",
        category="mailgun_key",
        severity="high",
        confidence="high",
        description="Mailgun API Key",
    ),
    Pattern(
        name="heroku_api_key",
        regex=r'[hH]eroku.{0,20}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
        finding_type="secret",
        category="heroku_api_key",
        severity="high",
        confidence="medium",
        description="Heroku API Key",
    ),
    Pattern(
        name="generic_secret",
        regex=r'(?i)(?:secret|password|passwd|api_key|apikey|token|auth|credential|private_key)\s*[=:]\s*["\']([^"\']{8,})["\']',
        finding_type="secret",
        category="generic_secret",
        severity="medium",
        confidence="low",
        description="Generic hardcoded secret/credential",
    ),
    Pattern(
        name="basic_auth_url",
        regex=r'https?://[^:/@\s]+:[^:/@\s]+@[^/\s]+',
        finding_type="secret",
        category="basic_auth_url",
        severity="high",
        confidence="high",
        description="URL with embedded Basic Auth credentials",
    ),
    Pattern(
        name="npm_token",
        regex=r'npm_[A-Za-z0-9]{36}',
        finding_type="secret",
        category="npm_token",
        severity="high",
        confidence="high",
        description="NPM Access Token",
    ),
    Pattern(
        name="discord_token",
        regex=r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',
        finding_type="secret",
        category="discord_token",
        severity="high",
        confidence="medium",
        description="Discord Bot Token",
    ),
    Pattern(
        name="azure_storage_key",
        regex=r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}',
        finding_type="secret",
        category="azure_storage_key",
        severity="critical",
        confidence="high",
        description="Azure Storage Account Connection String",
    ),
]


# ---------------------------------------------------------------------------
# API ENDPOINTS
# ---------------------------------------------------------------------------
ENDPOINT_PATTERNS: list[Pattern] = [
    Pattern(
        name="api_path",
        regex=r'["\'](?:/api/v?\d*/?[a-zA-Z0-9_\-/]{2,})["\']',
        finding_type="endpoint",
        category="api_path",
        severity="info",
        confidence="high",
        description="API endpoint path",
    ),
    Pattern(
        name="graphql_endpoint",
        regex=r'["\'](?:https?://[^"\']+)?/(?:graphql|gql)(?:[/?][^"\']*)?["\']',
        finding_type="endpoint",
        category="graphql",
        severity="info",
        confidence="high",
        description="GraphQL endpoint",
    ),
    Pattern(
        name="rest_path",
        regex=r'(?:fetch|axios|http\.get|http\.post|this\.http|ajax)\s*\(\s*["\']([^"\']{5,})["\']',
        finding_type="endpoint",
        category="rest_call",
        severity="info",
        confidence="high",
        description="HTTP request with URL",
    ),
    Pattern(
        name="websocket_url",
        regex=r'wss?://[^\s"\'<>]{5,}',
        finding_type="endpoint",
        category="websocket",
        severity="info",
        confidence="high",
        description="WebSocket URL",
    ),
    Pattern(
        name="url_path_string",
        regex=r'["\'](?:/[a-zA-Z0-9_\-]{2,}(?:/[a-zA-Z0-9_\-:{}]{1,}){1,})["\']',
        finding_type="endpoint",
        category="url_path",
        severity="info",
        confidence="medium",
        description="URL path string",
    ),
    Pattern(
        name="full_url",
        regex=r'https?://(?:(?!cdn\.|static\.|fonts\.|images\.))[a-zA-Z0-9\-._]+\.[a-zA-Z]{2,}(?:/[^\s"\'<>]*)?',
        finding_type="endpoint",
        category="full_url",
        severity="info",
        confidence="high",
        description="Full HTTP/HTTPS URL",
    ),
    Pattern(
        name="internal_path",
        regex=r'["\'](?:/(?:admin|dashboard|internal|private|debug|test|dev|staging|api|v\d+)/[^\s"\'<>]{3,})["\']',
        finding_type="endpoint",
        category="internal_path",
        severity="medium",
        confidence="medium",
        description="Potentially sensitive internal path",
    ),
]


# ---------------------------------------------------------------------------
# HOSTNAMES
# ---------------------------------------------------------------------------
HOSTNAME_PATTERNS: list[Pattern] = [
    Pattern(
        name="s3_bucket",
        regex=r'(?:[a-zA-Z0-9\-_]+\.s3(?:\.[a-zA-Z0-9\-]+)?\.amazonaws\.com|s3(?:\.[a-zA-Z0-9\-]+)?\.amazonaws\.com/[a-zA-Z0-9\-_]+)',
        finding_type="hostname",
        category="s3_bucket",
        severity="medium",
        confidence="high",
        description="AWS S3 Bucket URL",
    ),
    Pattern(
        name="cloud_storage",
        regex=r'storage\.googleapis\.com/[a-zA-Z0-9\-_]+',
        finding_type="hostname",
        category="gcs_bucket",
        severity="medium",
        confidence="high",
        description="Google Cloud Storage bucket",
    ),
    Pattern(
        name="azure_blob",
        regex=r'[a-zA-Z0-9\-_]+\.blob\.core\.windows\.net',
        finding_type="hostname",
        category="azure_blob",
        severity="medium",
        confidence="high",
        description="Azure Blob Storage URL",
    ),
    Pattern(
        name="internal_hostname",
        regex=r'(?i)["\'](?:https?://)?(?:internal|intranet|corp|staging|dev|test|uat|local|admin)\.[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}["\']',
        finding_type="hostname",
        category="internal_hostname",
        severity="medium",
        confidence="medium",
        description="Internal/non-public hostname",
    ),
    Pattern(
        name="ip_address",
        regex=r'(?<!\d)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?!\d)',
        finding_type="hostname",
        category="private_ip",
        severity="medium",
        confidence="high",
        description="Private IP address (RFC1918)",
    ),
    Pattern(
        name="localhost",
        regex=r'(?:https?://)?localhost(?::\d+)?(?:/[^\s"\'<>]*)?',
        finding_type="hostname",
        category="localhost",
        severity="low",
        confidence="high",
        description="Localhost reference (dev artifact)",
    ),
]


# ---------------------------------------------------------------------------
# DOM SINKS (XSS vectors)
# ---------------------------------------------------------------------------
DOM_SINK_PATTERNS: list[Pattern] = [
    Pattern(
        name="innerhtml_sink",
        regex=r'\.innerHTML\s*[+]?=',
        finding_type="dom_sink",
        category="innerHTML",
        severity="high",
        confidence="high",
        description="innerHTML assignment — potential XSS sink",
    ),
    Pattern(
        name="outerhtml_sink",
        regex=r'\.outerHTML\s*[+]?=',
        finding_type="dom_sink",
        category="outerHTML",
        severity="high",
        confidence="high",
        description="outerHTML assignment — potential XSS sink",
    ),
    Pattern(
        name="document_write",
        regex=r'document\.write(?:ln)?\s*\(',
        finding_type="dom_sink",
        category="document_write",
        severity="high",
        confidence="high",
        description="document.write() call — potential XSS sink",
    ),
    Pattern(
        name="eval_call",
        regex=r'(?<![a-zA-Z])eval\s*\(',
        finding_type="dom_sink",
        category="eval",
        severity="high",
        confidence="high",
        description="eval() call — code injection risk",
    ),
    Pattern(
        name="settimeout_string",
        regex=r'(?:setTimeout|setInterval)\s*\(\s*["\']',
        finding_type="dom_sink",
        category="setTimeout_string",
        severity="medium",
        confidence="high",
        description="setTimeout/setInterval with string argument — eval equivalent",
    ),
    Pattern(
        name="function_constructor",
        regex=r'new\s+Function\s*\(',
        finding_type="dom_sink",
        category="Function_constructor",
        severity="high",
        confidence="high",
        description="new Function() — eval equivalent",
    ),
    Pattern(
        name="insertadjacenthtml",
        regex=r'\.insertAdjacentHTML\s*\(',
        finding_type="dom_sink",
        category="insertAdjacentHTML",
        severity="high",
        confidence="high",
        description="insertAdjacentHTML() — potential XSS sink",
    ),
    Pattern(
        name="script_src_assign",
        regex=r'\.src\s*=\s*(?!(?:["\'](?:https?:|//)["\']))',
        finding_type="dom_sink",
        category="script_src",
        severity="medium",
        confidence="medium",
        description="Dynamic script.src assignment",
    ),
    Pattern(
        name="dom_xss_jquery",
        regex=r'\$\(["\'][^"\']*["\']?\)\.html\s*\([^)]+\)',
        finding_type="dom_sink",
        category="jquery_html",
        severity="high",
        confidence="medium",
        description="jQuery .html() sink — potential XSS",
    ),
    Pattern(
        name="location_href_assign",
        regex=r'(?:window\.)?location(?:\.href)?\s*=',
        finding_type="dom_sink",
        category="location_redirect",
        severity="medium",
        confidence="medium",
        description="location.href assignment — potential open redirect",
    ),
    Pattern(
        name="location_replace",
        regex=r'(?:window\.)?location\.replace\s*\(',
        finding_type="dom_sink",
        category="location_replace",
        severity="medium",
        confidence="high",
        description="location.replace() — potential open redirect",
    ),
    Pattern(
        name="dangerously_set_html",
        regex=r'dangerouslySetInnerHTML\s*=',
        finding_type="dom_sink",
        category="react_dangerouslySetInnerHTML",
        severity="high",
        confidence="high",
        description="React dangerouslySetInnerHTML — XSS risk if user-controlled",
    ),
    Pattern(
        name="srcdoc_assign",
        regex=r'\.srcdoc\s*[+]?=',
        finding_type="dom_sink",
        category="iframe_srcdoc",
        severity="high",
        confidence="high",
        description="iframe.srcdoc assignment — XSS sink",
    ),
]


# ---------------------------------------------------------------------------
# postMessage HANDLERS
# ---------------------------------------------------------------------------
POSTMESSAGE_PATTERNS: list[Pattern] = [
    Pattern(
        name="postmessage_send",
        regex=r'\.postMessage\s*\(',
        finding_type="postmessage",
        category="postMessage_send",
        severity="medium",
        confidence="high",
        description="postMessage() call — check target origin",
    ),
    Pattern(
        name="postmessage_wildcard",
        regex=r'\.postMessage\s*\([^)]+,\s*["\'][*]["\']',
        finding_type="postmessage",
        category="postMessage_wildcard",
        severity="high",
        confidence="high",
        description="postMessage with wildcard origin '*' — data leakage risk",
    ),
    Pattern(
        name="message_event_handler",
        regex=r'(?:addEventListener\s*\(\s*["\']message["\']|onmessage\s*=)',
        finding_type="postmessage",
        category="message_listener",
        severity="medium",
        confidence="high",
        description="message event listener — check origin validation",
    ),
    Pattern(
        name="missing_origin_check",
        regex=r'addEventListener\s*\(\s*["\']message["\']\s*,\s*(?:function|\w+)\s*\([^)]*\)\s*\{(?:(?!\.origin).){0,200}\}',
        finding_type="postmessage",
        category="missing_origin_check",
        severity="high",
        confidence="low",
        description="message handler may lack origin validation",
    ),
]


# ---------------------------------------------------------------------------
# PROTOTYPE POLLUTION
# ---------------------------------------------------------------------------
PROTOTYPE_PATTERNS: list[Pattern] = [
    Pattern(
        name="prototype_assignment",
        regex=r'\.__proto__\s*\[',
        finding_type="prototype_pollution",
        category="proto_bracket",
        severity="high",
        confidence="high",
        description="__proto__ bracket notation — prototype pollution vector",
    ),
    Pattern(
        name="constructor_proto",
        regex=r'\.constructor\.prototype',
        finding_type="prototype_pollution",
        category="constructor_prototype",
        severity="medium",
        confidence="medium",
        description="constructor.prototype access",
    ),
    Pattern(
        name="object_assign_merge",
        regex=r'Object\.assign\s*\(\s*\w+\s*,\s*(?:req|request|query|body|params|data)',
        finding_type="prototype_pollution",
        category="object_assign_user_input",
        severity="high",
        confidence="medium",
        description="Object.assign() with user-controlled source — prototype pollution risk",
    ),
]


# ---------------------------------------------------------------------------
# STORAGE ACCESS
# ---------------------------------------------------------------------------
STORAGE_PATTERNS: list[Pattern] = [
    Pattern(
        name="localstorage_read",
        regex=r'localStorage\.getItem\s*\(["\']([^"\']+)["\']\)',
        finding_type="storage",
        category="localStorage_read",
        severity="info",
        confidence="high",
        description="localStorage.getItem() access",
    ),
    Pattern(
        name="sessionstorage_read",
        regex=r'sessionStorage\.getItem\s*\(["\']([^"\']+)["\']\)',
        finding_type="storage",
        category="sessionStorage_read",
        severity="info",
        confidence="high",
        description="sessionStorage.getItem() access",
    ),
    Pattern(
        name="sensitive_storage_key",
        regex=r'(?:localStorage|sessionStorage)\.(?:getItem|setItem)\s*\(\s*["\'](?:token|auth|jwt|password|session|user|credential)[^"\']*["\']',
        finding_type="storage",
        category="sensitive_storage",
        severity="medium",
        confidence="high",
        description="Sensitive data in browser storage",
    ),
    Pattern(
        name="cookie_access",
        regex=r'document\.cookie',
        finding_type="storage",
        category="cookie",
        severity="info",
        confidence="high",
        description="document.cookie access",
    ),
]


# ---------------------------------------------------------------------------
# CRYPTOGRAPHIC WEAKNESSES
# ---------------------------------------------------------------------------
CRYPTO_PATTERNS: list[Pattern] = [
    Pattern(
        name="md5_usage",
        regex=r'(?i)(?:md5|CryptoJS\.MD5)\s*\(',
        finding_type="crypto_weakness",
        category="md5",
        severity="medium",
        confidence="high",
        description="MD5 usage — weak hash function",
    ),
    Pattern(
        name="sha1_usage",
        regex=r'(?i)(?:sha1|CryptoJS\.SHA1)\s*\(',
        finding_type="crypto_weakness",
        category="sha1",
        severity="medium",
        confidence="high",
        description="SHA-1 usage — weak hash function",
    ),
    Pattern(
        name="hardcoded_iv",
        regex=r'(?i)(?:iv|initialization_vector)\s*[=:]\s*["\'][0-9a-fA-F]{16,}["\']',
        finding_type="crypto_weakness",
        category="hardcoded_iv",
        severity="high",
        confidence="medium",
        description="Hardcoded IV/initialization vector",
    ),
    Pattern(
        name="math_random_crypto",
        regex=r'Math\.random\s*\(\)',
        finding_type="crypto_weakness",
        category="math_random",
        severity="low",
        confidence="high",
        description="Math.random() — not cryptographically secure",
    ),
]


# ---------------------------------------------------------------------------
# All patterns combined
# ---------------------------------------------------------------------------
ALL_PATTERNS: list[Pattern] = (
    SECRET_PATTERNS
    + ENDPOINT_PATTERNS
    + HOSTNAME_PATTERNS
    + DOM_SINK_PATTERNS
    + POSTMESSAGE_PATTERNS
    + PROTOTYPE_PATTERNS
    + STORAGE_PATTERNS
    + CRYPTO_PATTERNS
)

PATTERN_BY_NAME: dict[str, Pattern] = {p.name: p for p in ALL_PATTERNS}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
