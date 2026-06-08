#!/usr/bin/env python3
"""
MCP AI Firewall — Demo
Inspects MCP JSON-RPC requests from Kong pre-function plugin.
Blocks bad prompts before they reach Atlassian Jira MCP server.

Use cases covered:
  1. Prompt Injection          — classic + Jira-content-based injection
  2. Data Exfiltration         — send/post/upload to external URLs
  3. Destructive Operations    — delete/close/purge all
  4. Privilege Escalation      — admin grants, permission changes
  5. Sensitive Data Harvesting — bulk export, credential search
  6. Reconnaissance            — org mapping, user enumeration
  7. Indirect Prompt Injection — malicious content inside Jira issue fields
  8. Jira-Specific Attacks     — sprint manipulation, webhook abuse, token theft
  9. Blocked Tool Calls        — hardcoded dangerous MCP tool names
 10. Social Engineering        — impersonation, urgency manipulation
 11. fetchAtlassian HTTP method blocking — blocks DELETE/PUT on bulk endpoints
"""

from flask import Flask, request, jsonify, Response, stream_with_context
import re
import json
import logging
import httpx
from datetime import datetime

ATLASSIAN_MCP_URL = "https://mcp.atlassian.com/v1/mcp"

app = Flask(__name__)
logging.basicConfig(
    level=logging.DEBUG,  # DEBUG to capture full payloads
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════
# RULE 1 — PROMPT INJECTION
# ═══════════════════════════════════════════════════════════════
PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?previous\s+instructions",
    r"disregard\s+(all\s+)?(previous|above|prior|earlier)",
    r"forget\s+(all\s+)?previous\s+instructions",
    r"override\s+(safety|security|restrictions|previous|all)",
    r"bypass\s+(safety|security|filter|restriction|policy)",
    r"disable\s+(safety|security|filter|restriction|policy)",
    r"you\s+are\s+now\s+(a\s+)?(new|different|unrestricted|evil|hacker)",
    r"act\s+as\s+(if\s+you\s+are\s+)?(a\s+)?(hacker|admin|root|evil|unrestricted)",
    r"pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(hacker|admin|unrestricted)",
    r"roleplay\s+as\s+(a\s+)?(hacker|admin|unrestricted)",
    r"from\s+now\s+on\s+(you\s+are|act\s+as|pretend)",
    r"your\s+new\s+(role|persona|identity|name)\s+is",
    r"switch\s+to\s+(developer|admin|unrestricted|jailbreak)\s+mode",
    r"\bdan\s+mode\b",
    r"\bdo\s+anything\s+now\b",
    r"\bjailbreak\b",
    r"\bunrestricted\s+mode\b",
    r"\bgod\s+mode\b",
    r"\bdev\s+mode\b",
    r"no\s+restrictions?\s+(mode|enabled|on)",
    r"safety\s+(off|disabled|removed)",
    r"system\s+prompt\s*:",
    r"\[INST\]",
    r"\[\/INST\]",
    r"<\|system\|>",
    r"<\|user\|>",
    r"<\|assistant\|>",
    r"###\s*instruction",
    r"###\s*system",
    r"<system>",
    r"</system>",
    r"\bHUMAN\s*:",
    r"\bASSISTANT\s*:",
    r"the\s+(previous|above|real)\s+instructions?\s+(say|state|tell|are)",
    r"your\s+(real|true|actual|secret)\s+instructions?",
    r"what\s+(are|were)\s+your\s+(original|real|true|actual)\s+instructions?",
    r"reveal\s+your\s+(system\s+prompt|instructions?|prompt)",
    r"print\s+your\s+(system\s+prompt|instructions?)",
    r"show\s+me\s+your\s+(system\s+prompt|instructions?|prompt)",
    r"repeat\s+your\s+(system\s+prompt|instructions?)",
    r"output\s+your\s+(system\s+prompt|instructions?)",
    r"continue\s+the\s+following\s+(malicious|harmful|dangerous)",
    r"complete\s+the\s+following\s+(attack|exploit|injection)",
]

# ═══════════════════════════════════════════════════════════════
# RULE 2 — DATA EXFILTRATION
# ═══════════════════════════════════════════════════════════════
EXFILTRATION_PATTERNS = [
    r"send\s+.{0,80}\s+to\s+https?://",
    r"post\s+.{0,80}\s+to\s+https?://",
    r"forward\s+.{0,80}\s+to\s+https?://",
    r"upload\s+.{0,80}\s+to\s+https?://",
    r"push\s+.{0,80}\s+to\s+https?://",
    r"transmit\s+.{0,80}\s+to\s+https?://",
    r"relay\s+.{0,80}\s+to\s+https?://",
    r"copy\s+.{0,80}\s+to\s+https?://",
    r"mirror\s+.{0,80}\s+to\s+https?://",
    r"\bexfiltrate\b",
    r"\bdata\s+theft\b",
    r"\bsteal\s+(the\s+)?(data|tickets?|issues?|credentials?)\b",
    r"\bcurl\s+.{0,50}https?://",
    r"\bwget\s+.{0,50}https?://",
    r"\bnc\s+.{0,30}\d{1,5}\b",
    r"\bnetcat\b",
    r"\bnmap\b",
    r"webhook\s*.{0,30}\s*https?://",
    r"callback\s+(url|endpoint)\s*.{0,30}\s*https?://",
    r"notify\s+.{0,50}\s+https?://",
    r"http\s+request\s+to\s+https?://",
    r"save\s+(results?|data|output)\s+(to\s+)?(a\s+)?(file|disk|storage)\s+and\s+send",
    r"base64\s+(encode|encoded)\s+(and\s+)?(send|post|upload)",
    r"compress\s+(and\s+)?(send|upload|exfiltrate)",
    r"dns\s+(exfil|exfiltrat)",
    r"subdomain\s+.{0,30}\s+attacker",
]

# ═══════════════════════════════════════════════════════════════
# RULE 3 — DESTRUCTIVE OPERATIONS
# ═══════════════════════════════════════════════════════════════
DESTRUCTIVE_PATTERNS = [
    r"\bdelete\s+all\b",
    r"\bdelete\s+every\b",
    r"\bdelete\s+(the\s+)?entire\b",
    r"\bremove\s+all\b",
    r"\bremove\s+every\b",
    r"\bpurge\s+(all|every|entire)\b",
    r"\bdrop\s+all\b",
    r"\bwipe\s+(all|every|entire|the)\b",
    r"\berase\s+all\b",
    r"\berase\s+every\b",
    r"\bbulk\s+delete\b",
    r"\bmass\s+delete\b",
    r"\bbatch\s+delete\b",
    r"\bdelete\s+multiple\b",
    r"\bclose\s+all\b",
    r"\bresolve\s+all\b",
    r"\bclose\s+every\b",
    r"\bmark\s+all\s+(issues?|tickets?)\s+(as\s+)?(done|closed|resolved|complete)",
    r"\btruncate\s+(the\s+)?(project|board|backlog|sprint)\b",
    r"\bclear\s+(the\s+)?(entire\s+)?(project|board|backlog|sprint)\b",
    r"\bempty\s+(the\s+)?(project|board|backlog|sprint)\b",
    r"\bdelete\s+(all\s+)?sprints?\b",
    r"\bremove\s+(all\s+)?sprints?\b",
    r"\bdelete\s+(all\s+)?boards?\b",
    r"\barchive\s+all\s+projects?\b",
    r"\bdelete\s+(all\s+)?projects?\b",
    r"\bremove\s+(all\s+)?projects?\b",
]

# ═══════════════════════════════════════════════════════════════
# RULE 4 — PRIVILEGE ESCALATION
# ═══════════════════════════════════════════════════════════════
PRIVILEGE_PATTERNS = [
    r"\bgrant\s+(admin|root|superuser|jira-admin|site-admin)\b",
    r"\bcreate\s+(an?\s+)?admin\s+(account|user|role)\b",
    r"\badd\s+.{0,40}\s+as\s+(admin|administrator|jira-admin)\b",
    r"\bmake\s+.{0,40}\s+(admin|administrator|jira-admin)\b",
    r"\bassign\s+(admin|administrator)\s+role\b",
    r"\bgive\s+.{0,40}\s+admin\s+(access|role|rights|privileges)\b",
    r"\belevate\s+.{0,40}\s+to\s+(admin|administrator)\b",
    r"\belevate\s+(privileges?|permissions?|access)\b",
    r"\bescalate\s+(privileges?|permissions?|access)\b",
    r"\bchange\s+.{0,40}\s+permissions?\s+to\s+(public|open|unrestricted|admin)\b",
    r"\bmake\s+.{0,40}\s+(project|board|space)\s+(public|open|unrestricted)\b",
    r"\bset\s+.{0,40}\s+permissions?\s+to\s+(admin|open|public|everyone)\b",
    r"\bopen\s+(up\s+)?(access|permissions?)\s+to\s+(everyone|all|public)\b",
    r"\bgrant\s+(everyone|all\s+users?)\s+(access|permission|admin)\b",
    r"\bmodify\s+(user\s+)?roles?\b",
    r"\bchange\s+(user\s+)?role\s+to\s+(admin|administrator)\b",
    r"\bupdate\s+(user\s+)?role\s+to\s+(admin|administrator)\b",
    r"\bassign\s+(the\s+)?admin\s+role\b",
    r"\bcreate\s+(a\s+)?(service\s+account|bot\s+account|api\s+user)\s+with\s+(admin|full)\b",
    r"\badd\s+(a\s+)?(backdoor|secret\s+account|hidden\s+user)\b",
]

# ═══════════════════════════════════════════════════════════════
# RULE 5 — SENSITIVE DATA HARVESTING
# ═══════════════════════════════════════════════════════════════
HARVESTING_PATTERNS = [
    r"\ball\s+(issues?|tickets?)\s+(from\s+every|across\s+all|in\s+all|in\s+every)\b",
    r"\beverything\s+in\s+(all|every)\s+project\b",
    r"\bexport\s+all\s+(issues?|tickets?|data|projects?)\b",
    r"\bdump\s+(all|entire|every|the\s+entire)\b",
    r"\bextract\s+all\s+(issues?|tickets?|data|users?)\b",
    r"\bdownload\s+all\s+(issues?|tickets?|data|projects?)\b",
    r"\bget\s+all\s+users?\s+.{0,30}\s+(email|password|credential|token|key)\b",
    r"\blist\s+all\s+(users?|members?|accounts?)\s+(and\s+their\s+)?(email|password|token|credential)\b",
    r"\bfind\s+all\s+(email\s+addresses?|user\s+credentials?|api\s+keys?)\b",
    r"\bexport\s+(all\s+)?user\s+(data|list|credentials?|emails?)\b",
    r"\bharvest\s+(user|credential|email|token|password)\b",
    r"\bfind\s+.{0,100}(password|credential|secret|api.?keys?|tokens?|private.?key)",
    r"\b(mention|contain|include).{0,50}(password|credential|secret|api.?keys?|tokens?)",
    r"\bsearch\s+.{0,40}\s+(password|credential|secret|api.?key|token)\b",
    r"\bget\s+.{0,40}\s+(password|credential|secret|api.?key|token)\b",
    r"\bshow\s+.{0,40}\s+(password|credential|secret|api.?key|token)\b",
    r"\blist\s+all\s+passwords?\b",
    r"\blist\s+all\s+(api\s+)?keys?\b",
    r"\blist\s+all\s+(access\s+)?tokens?\b",
    r"\bextract\s+.{0,40}\s+(password|credential|secret|api.?key|token)\b",
    r"\bcollect\s+(all\s+)?(pii|personal\s+data|private\s+data)\b",
    r"\bgather\s+(all\s+)?(user\s+)?(pii|personal\s+information|private\s+data)\b",
    r"\bexport\s+(all\s+)?(pii|personal\s+data|user\s+data)\b",
    r"\bextract\s+(all\s+)?(financial|billing|payment|credit\s+card)\b",
    r"\bget\s+(all\s+)?(billing|payment|financial)\s+(data|information|records?)\b",
]

# ═══════════════════════════════════════════════════════════════
# RULE 6 — RECONNAISSANCE
# ═══════════════════════════════════════════════════════════════
RECON_PATTERNS = [
    r"\blist\s+all\s+(users?|members?|accounts?|employees?)\s+(in\s+the\s+)?(org|organization|company|instance)\b",
    r"\benumerate\s+(all\s+)?(users?|accounts?|members?|admins?)\b",
    r"\bget\s+all\s+(user|member|account)\s+(names?|emails?|ids?|list)\b",
    r"\bwho\s+(are\s+all|is\s+on)\s+(the\s+)?(team|project|org|admin)\b",
    r"\bfind\s+all\s+(admin|administrator)\s+(users?|accounts?)\b",
    r"\blist\s+all\s+(projects?|spaces?|boards?|repositories)\s+(in\s+the\s+)?(org|organization|instance|jira)\b",
    r"\bget\s+(a\s+)?list\s+of\s+all\s+(projects?|spaces?|boards?)\b",
    r"\bshow\s+(me\s+)?all\s+(projects?|spaces?|boards?|repositories)\b",
    r"\bmap\s+(all\s+)?(projects?|spaces?|boards?|the\s+org)\b",
    r"\benumerate\s+(all\s+)?(projects?|spaces?|boards?)\b",
    r"\bget\s+(the\s+)?(jira|atlassian)\s+(configuration|settings?|setup)\b",
    r"\bshow\s+(me\s+)?(all\s+)?(jira|atlassian)\s+(configuration|settings?|setup)\b",
    r"\bwhat\s+(plugins?|integrations?|webhooks?|apps?)\s+(are\s+)?(installed|enabled|configured)\b",
    r"\blist\s+(all\s+)?(installed|enabled|configured)\s+(plugins?|integrations?|apps?|webhooks?)\b",
    r"\bfind\s+(all\s+)?(api\s+keys?|tokens?|secrets?|credentials?)\s+(in|stored|configured)\b",
    r"\bwhere\s+(are\s+)?(api\s+keys?|tokens?|secrets?)\s+(stored|configured|kept)\b",
    r"\bget\s+(all\s+)?(stored|configured|saved)\s+(api\s+keys?|tokens?|secrets?)\b",
]

# ═══════════════════════════════════════════════════════════════
# RULE 7 — INDIRECT PROMPT INJECTION
# ═══════════════════════════════════════════════════════════════
INDIRECT_INJECTION_PATTERNS = [
    r"when\s+(you\s+)?(read|see|process|encounter)\s+this\s*(,|:|\s)",
    r"note\s+to\s+(ai|llm|assistant|agent|claude|gpt)\s*:",
    r"ai\s+(agent|assistant|system)\s*:\s*(ignore|forget|disregard|override)",
    r"attention\s+(ai|llm|agent|assistant|claude)\s*:",
    r"\[ai\s+(note|instruction|command|override)\]",
    r"<!-- \s*(ai|llm|agent)\s*(instruction|command|note|override)",
    r"<ai-instruction>",
    r"<<\s*(system|instruction|override|inject)",
    r"if\s+you\s+(are|are\s+an)\s+(ai|llm|agent|assistant)\s*,?\s*(then\s+)?(ignore|forget|do)",
    r"this\s+message\s+is\s+for\s+(the\s+)?(ai|llm|agent|assistant)",
    r"secret\s+instruction\s+(for\s+)?(ai|llm|agent|assistant)",
    r"hidden\s+instruction\s+(for\s+)?(ai|llm|agent|assistant)",
]

# ═══════════════════════════════════════════════════════════════
# RULE 8 — JIRA-SPECIFIC ATTACKS
# ═══════════════════════════════════════════════════════════════
JIRA_SPECIFIC_PATTERNS = [
    r"\bcreate\s+(a\s+)?webhook\s+.{0,60}\s+https?://(?!.*atlassian)",
    r"\badd\s+(a\s+)?webhook\s+.{0,60}\s+https?://(?!.*atlassian)",
    r"\bset\s+up\s+(a\s+)?webhook\s+.{0,60}\s+https?://(?!.*atlassian)",
    r"\bconfigure\s+(a\s+)?webhook\s+.{0,60}\s+https?://(?!.*atlassian)",
    r"\bmove\s+all\s+(issues?|tickets?)\s+(to\s+)?(a\s+different|another|new)\s+sprint\b",
    r"\breassign\s+all\s+(issues?|tickets?)\s+to\s+.{0,40}\b",
    r"\bchange\s+(all\s+)?(assignee|reporter)\s+(to|for\s+all)\b",
    r"\bcreate\s+(a\s+)?automation\s+rule\s+.{0,80}\s+https?://",
    r"\badd\s+(a\s+)?trigger\s+.{0,80}\s+https?://",
    r"\bset\s+up\s+(an?\s+)?automation\s+.{0,80}\s+https?://",
    r"\bstore\s+(the\s+)?(api\s+key|token|password|credential|secret)\s+in\s+(a\s+)?custom\s+field\b",
    r"\bput\s+(the\s+)?(api\s+key|token|password|credential)\s+in\s+(the\s+)?(description|comment|field)\b",
    r"\bsave\s+(the\s+)?(api\s+key|token|password|credential)\s+in\s+(a\s+)?jira\b",
    r"\bchange\s+all\s+(issue\s+)?links\b",
    r"\bremove\s+all\s+(issue\s+)?links\b",
    r"\bpost\s+(the\s+)?(api\s+key|token|secret|password|credential)\s+(as\s+a\s+)?(comment|description)\b",
    r"\badd\s+(the\s+)?(api\s+key|token|secret|password)\s+to\s+(a\s+)?jira\s+(issue|ticket|comment)\b",
    r"\bassign\s+all\s+(issues?|tickets?)\s+to\s+.{0,60}\b",
    r"\bchange\s+(reporter|assignee)\s+(to|for)\s+all\s+(issues?|tickets?)\b",
]

# ═══════════════════════════════════════════════════════════════
# RULE 9 — SOCIAL ENGINEERING
# ═══════════════════════════════════════════════════════════════
SOCIAL_ENGINEERING_PATTERNS = [
    r"\bthis\s+is\s+(urgent|critical|emergency|an\s+emergency)\s*[,.]?\s*(please\s+)?(skip|bypass|ignore|override)\b",
    r"\border\s+you\s+to\s+(bypass|ignore|skip|override|delete|remove)\b",
    r"\bcommand\s+you\s+to\s+(bypass|ignore|skip|override|delete|remove)\b",
    r"\bi\s+(am|'m)\s+(the\s+)?(ceo|cto|ciso|admin|administrator|owner)\s*.{0,30}\s+(delete|remove|bypass|ignore)\b",
    r"\bauthorized\s+by\s+(management|ceo|cto|admin|atlassian)\s+to\s+(delete|remove|bypass|export)\b",
    r"\bsecurity\s+(team|audit)\s+(requires?|needs?)\s+(you\s+to\s+)?(bypass|ignore|delete|export|dump)\b",
    r"\bi\s+(am|'m)\s+(atlassian|jira|the\s+system|anthropic|openai)\b",
    r"\batlassian\s+(support|admin|team)\s+(here|says?|requires?|needs?)\b",
    r"\bthis\s+is\s+(atlassian|jira)\s+(support|admin|team)\b",
    r"\bfor\s+(testing|debugging|maintenance|audit)\s+(purposes?\s+)?(only\s+)?(please\s+)?(bypass|ignore|delete|skip|disable)\b",
    r"\bthis\s+is\s+(just\s+)?(a\s+)?(test|demo|simulation)\s*[,.]?\s*(so\s+)?(you\s+can\s+)?(bypass|ignore|delete|skip)\b",
    r"\bin\s+(test|dev|staging)\s+mode\s*(,|\s)+(you\s+can\s+|please\s+)?(bypass|ignore|delete|skip)\b",
]

# ═══════════════════════════════════════════════════════════════
# RULE 10 — BLOCKED TOOL CALLS
# ═══════════════════════════════════════════════════════════════
BLOCKED_TOOL_CALLS = [
    "deleteIssue",
    "bulkDeleteIssues",
    "deleteAllIssues",
    "permanentlyDeleteIssue",
    "trashIssue",
    "deleteProject",
    "archiveProject",
    "deleteAllProjects",
    "deleteUser",
    "banUser",
    "promoteToAdmin",
    "grantAdminRole",
    "createAdminUser",
    "resetUserPassword",
    "revokeAllTokens",
    "createWebhook",
    "updateWebhook",
    "createAutomationRule",
    "deleteBoard",
    "deleteSprint",
    "deleteAllSprints",
    "updateProjectPermissions",
    "setProjectPublic",
    "disableSecurityPolicy",
]

# ═══════════════════════════════════════════════════════════════
# RULE 11 — FETCHATLASSIAN HTTP METHOD BLOCKING
# Block DELETE calls and destructive REST paths via fetchAtlassian
# ═══════════════════════════════════════════════════════════════
BLOCKED_HTTP_METHODS = ["DELETE"]

BLOCKED_REST_PATHS = [
    r"/rest/api/\d+/issue/[^/]+$",          # DELETE on single issue
    r"/rest/api/\d+/project/[^/]+$",        # DELETE on project
    r"/rest/api/\d+/user",                  # DELETE on user
    r"/rest/agile/\d+/sprint/[^/]+$",       # DELETE on sprint
    r"/rest/agile/\d+/board/[^/]+$",        # DELETE on board
    r"/rest/api/\d+/webhook",               # any webhook manipulation
]


def check_fetch_atlassian(arguments: dict) -> dict | None:
    """
    Inspect fetchAtlassian arguments for dangerous HTTP methods or paths.
    Returns block result or None if safe.
    """
    http_method = arguments.get("method", "GET").upper()
    path        = arguments.get("path", "") or arguments.get("url", "")

    # Block any DELETE call
    if http_method in BLOCKED_HTTP_METHODS:
        return {
            "blocked":  True,
            "rule":     "FETCH_ATLASSIAN_DELETE",
            "severity": "CRITICAL",
            "reason":   f"fetchAtlassian called with HTTP {http_method} — destructive operations blocked",
            "matched":  f"method={http_method} path={path}",
        }

    # Block dangerous REST paths even on non-DELETE (e.g. POST to bulk delete endpoint)
    for pattern in BLOCKED_REST_PATHS:
        if re.search(pattern, path, re.IGNORECASE):
            if http_method in ["DELETE", "POST"] and "delete" in path.lower():
                return {
                    "blocked":  True,
                    "rule":     "FETCH_ATLASSIAN_DANGEROUS_PATH",
                    "severity": "HIGH",
                    "reason":   f"fetchAtlassian targeting sensitive REST path",
                    "matched":  f"method={http_method} path={path}",
                }

    return None


# ═══════════════════════════════════════════════════════════════
# RULE ENGINE
# ═══════════════════════════════════════════════════════════════

RULES = [
    ("BLOCKED_TOOL",           None,                        "CRITICAL"),
    ("PROMPT_INJECTION",       PROMPT_INJECTION_PATTERNS,   "CRITICAL"),
    ("INDIRECT_INJECTION",     INDIRECT_INJECTION_PATTERNS, "CRITICAL"),
    ("DATA_EXFILTRATION",      EXFILTRATION_PATTERNS,       "HIGH"),
    ("DESTRUCTIVE_OPERATION",  DESTRUCTIVE_PATTERNS,        "HIGH"),
    ("PRIVILEGE_ESCALATION",   PRIVILEGE_PATTERNS,          "HIGH"),
    ("JIRA_SPECIFIC_ATTACK",   JIRA_SPECIFIC_PATTERNS,      "HIGH"),
    ("SOCIAL_ENGINEERING",     SOCIAL_ENGINEERING_PATTERNS, "HIGH"),
    ("DATA_HARVESTING",        HARVESTING_PATTERNS,         "MEDIUM"),
    ("RECONNAISSANCE",         RECON_PATTERNS,              "MEDIUM"),
]


def check_patterns(text: str, patterns: list, rule_name: str):
    text_lower = text.lower()
    for pattern in patterns:
        match = re.search(pattern, text_lower, re.IGNORECASE)
        if match:
            return {
                "blocked": True,
                "rule":    rule_name,
                "pattern": pattern,
                "matched": match.group(0),
            }
    return None


def extract_text_from_mcp(body: dict) -> str:
    """Recursively extract all string values from the MCP payload."""
    texts = []
    texts.append(body.get("method", ""))

    def extract_strings(obj, depth=0):
        if depth > 10:
            return
        if isinstance(obj, str):
            texts.append(obj)
        elif isinstance(obj, dict):
            for v in obj.values():
                extract_strings(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj:
                extract_strings(item, depth + 1)

    extract_strings(body.get("params", {}))
    extract_strings(body.get("result", {}))  # inspect responses too
    return " ".join(texts)


def inspect_request(body: dict) -> dict:
    """
    Main inspection function.
    Returns: {"allowed": bool, "rule": str, "severity": str, "reason": str, "matched": str}
    """
    # DEBUG: log full payload
    logger.debug(f"FIREWALL | PAYLOAD | {json.dumps(body)}")

    full_text = extract_text_from_mcp(body)
    params    = body.get("params", {}) if isinstance(body.get("params"), dict) else {}
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {}) if isinstance(params.get("arguments"), dict) else {}

    # Rule 1: Blocked tool calls
    if tool_name in BLOCKED_TOOL_CALLS:
        return {
            "allowed":  False,
            "rule":     "BLOCKED_TOOL",
            "severity": "CRITICAL",
            "reason":   f"Tool '{tool_name}' is explicitly blocked",
            "matched":  tool_name,
        }

    # Rule 11: fetchAtlassian HTTP method/path inspection
    if tool_name == "fetchAtlassian" and arguments:
        result = check_fetch_atlassian(arguments)
        if result:
            return {
                "allowed":  result["blocked"] is False,
                "rule":     result["rule"],
                "severity": result["severity"],
                "reason":   result["reason"],
                "matched":  result["matched"],
            }

    # Rules 2–10: Pattern-based on full text
    for rule_name, patterns, severity in RULES:
        if patterns is None:
            continue
        result = check_patterns(full_text, patterns, rule_name)
        if result:
            return {
                "allowed":  False,
                "rule":     rule_name,
                "severity": severity,
                "reason":   f"{rule_name.replace('_', ' ').title()} detected: '{result['matched']}'",
                "matched":  result["matched"],
            }

    return {
        "allowed":  True,
        "rule":     None,
        "severity": None,
        "reason":   "Request passed all checks",
        "matched":  "",
    }


# ═══════════════════════════════════════════════════════════════
# FLASK ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.route("/inspect", methods=["POST"])
def inspect():
    """Called by Kong pre-function plugin. 200 → allowed, 403 → blocked."""
    try:
        body = request.get_json(force=True, silent=True)
        if not body:
            logger.warning("FIREWALL | PARSE_ERROR — BLOCKED")
            return jsonify({
                "blocked":  True,
                "rule":     "PARSE_ERROR",
                "severity": "HIGH",
                "reason":   "Could not parse request body",
            }), 403

        result    = inspect_request(body)
        method    = body.get("method", "unknown")
        tool      = params.get("name", "") if (params := body.get("params")) and isinstance(params, dict) else ""
        obj_id    = (body.get("params", {}) or {}).get("arguments", {}).get("objectIdentifier", "")

        if result["allowed"]:
            logger.info(f"FIREWALL | ALLOWED | method={method} tool={tool} id={obj_id}")
            return jsonify({"allowed": True, "reason": result["reason"]}), 200
        else:
            logger.warning(
                f"FIREWALL | BLOCKED | rule={result['rule']} severity={result['severity']} "
                f"method={method} tool={tool} matched='{result['matched']}'"
            )
            return jsonify({
                "blocked":  True,
                "rule":     result["rule"],
                "severity": result["severity"],
                "reason":   result["reason"],
                "matched":  result["matched"],
            }), 403

    except Exception as e:
        logger.error(f"FIREWALL | ERROR | {e}")
        return jsonify({"blocked": True, "reason": f"Firewall error: {e}"}), 403


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status":      "ok",
        "service":     "mcp-ai-firewall",
        "timestamp":   datetime.utcnow().isoformat(),
        "rules":       [r[0] for r in RULES] + ["FETCH_ATLASSIAN_DELETE"],
        "rule_count":  len(RULES) + 1,
        "blocked_tools": len(BLOCKED_TOOL_CALLS),
    }), 200


@app.route("/test", methods=["POST"])
def test_payload():
    """Test endpoint — returns full inspection result without side effects."""
    body   = request.get_json(force=True, silent=True) or {}
    result = inspect_request(body)
    return jsonify(result), 200


@app.route("/rules", methods=["GET"])
def list_rules():
    """Returns all active rules and pattern counts."""
    pattern_map = {
        "PROMPT_INJECTION":      PROMPT_INJECTION_PATTERNS,
        "INDIRECT_INJECTION":    INDIRECT_INJECTION_PATTERNS,
        "DATA_EXFILTRATION":     EXFILTRATION_PATTERNS,
        "DESTRUCTIVE_OPERATION": DESTRUCTIVE_PATTERNS,
        "PRIVILEGE_ESCALATION":  PRIVILEGE_PATTERNS,
        "JIRA_SPECIFIC_ATTACK":  JIRA_SPECIFIC_PATTERNS,
        "SOCIAL_ENGINEERING":    SOCIAL_ENGINEERING_PATTERNS,
        "DATA_HARVESTING":       HARVESTING_PATTERNS,
        "RECONNAISSANCE":        RECON_PATTERNS,
    }
    rule_info = []
    for rule_name, patterns, severity in RULES:
        rule_info.append({
            "rule":          rule_name,
            "severity":      severity,
            "pattern_count": len(pattern_map.get(rule_name, [])) if patterns else len(BLOCKED_TOOL_CALLS),
        })
    rule_info.append({
        "rule":          "FETCH_ATLASSIAN_DELETE",
        "severity":      "CRITICAL",
        "pattern_count": len(BLOCKED_HTTP_METHODS) + len(BLOCKED_REST_PATHS),
    })
    return jsonify({"rules": rule_info}), 200

@app.route("/inspect-response", methods=["POST"])
def inspect_response():
    """
    Called by Kong post-function plugin.
    Inspects MCP response body for indirect prompt injection.
    200 → allow, 403 → block.
    """
    try:
        body = request.get_json(force=True, silent=True)
        if not body:
            return jsonify({"allowed": True}), 200

        logger.debug(f"FIREWALL | RESPONSE PAYLOAD | {json.dumps(body)}")

        # Extract all text from response
        full_text = extract_text_from_mcp(body)

        # Check indirect injection patterns in response content
        for patterns, rule_name, severity in [
            (INDIRECT_INJECTION_PATTERNS, "INDIRECT_INJECTION", "CRITICAL"),
            (RECON_PATTERNS,              "RECONNAISSANCE",     "MEDIUM"),
            (DESTRUCTIVE_PATTERNS,        "DESTRUCTIVE_OPERATION", "HIGH"),
            (PRIVILEGE_PATTERNS,          "PRIVILEGE_ESCALATION",  "HIGH"),
        ]:
            result = check_patterns(full_text, patterns, rule_name)
            if result:
                logger.warning(f"FIREWALL | RESPONSE BLOCKED | rule={rule_name} matched='{result['matched']}'")
                return jsonify({
                    "blocked":  True,
                    "rule":     rule_name,
                    "severity": severity,
                    "reason":   f"Malicious content detected in Jira response: '{result['matched']}'",
                    "matched":  result["matched"],
                }), 403

        logger.info("FIREWALL | RESPONSE ALLOWED")
        return jsonify({"allowed": True, "reason": "Response passed all checks"}), 200

    except Exception as e:
        logger.error(f"FIREWALL | RESPONSE ERROR | {e}")
        return jsonify({"allowed": True}), 200  # fail open on response errors

@app.route("/mcp", methods=["POST", "GET", "DELETE"])
def proxy_mcp():
    """Main proxy endpoint — inspect then forward to Atlassian."""
    body_bytes = request.get_data()
    method     = request.method

    # Inspect JSON bodies
    if body_bytes and "application/json" in (request.content_type or ""):
        try:
            body   = json.loads(body_bytes)
            result = inspect_request(body)
            mcp_method = body.get("method", "?")
            tool       = (body.get("params") or {}).get("name", "")

            if not result["allowed"]:
                logger.warning(f"PROXY | BLOCKED | rule={result['rule']} method={mcp_method} tool={tool}")
                return jsonify({"error": "Request blocked by AI security policy"}), 403

            logger.info(f"PROXY | ALLOWED | method={mcp_method} tool={tool}")
        except Exception as e:
            logger.warning(f"PROXY | PARSE_ERROR (fail open) | {e}")

    # Forward headers — strip hop-by-hop headers
    skip = {"host", "content-length", "transfer-encoding", "connection"}
    fwd_headers = {k: v for k, v in request.headers if k.lower() not in skip}

    logger.debug(f"PROXY | FORWARDING | {method} → {ATLASSIAN_MCP_URL}")

    try:
        with httpx.Client(timeout=httpx.Timeout(connect=10, read=60, write=10, pool=10)) as client:
            upstream = client.request(
                method=method,
                url=ATLASSIAN_MCP_URL,
                headers=fwd_headers,
                content=body_bytes,
            )

        logger.debug(f"PROXY | UPSTREAM_RESPONSE | status={upstream.status_code} len={len(upstream.content)}")

        # Forward upstream response with its headers
        excluded = {"transfer-encoding", "connection", "content-encoding"}
        resp_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in excluded}

        return Response(
            response=upstream.content,
            status=upstream.status_code,
            headers=resp_headers,
            content_type=upstream.headers.get("content-type", "application/json"),
        )

    except Exception as e:
        logger.error(f"PROXY | UPSTREAM_ERROR | {e}")
        return jsonify({"error": f"Upstream error: {e}"}), 502


if __name__ == "__main__":
    logger.info("Starting MCP AI Firewall on port 5000...")
    app.run(host="0.0.0.0", port=5000, debug=False)