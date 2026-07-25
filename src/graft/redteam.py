"""Bounded, deterministic red-team mutations used during rule discovery."""

from __future__ import annotations

import random
import re
from urllib.parse import quote

_SQLI_RE = re.compile(
    r"(?i)\b(?:union|select|sleep|benchmark|pg_sleep|waitfor|"
    r"information_schema|updatexml|extractvalue|or\s+\d+\s*=\s*\d+|"
    r"and\s+\d+\s*=\s*\d+)\b"
)
_XSS_RE = re.compile(r"(?is)<\s*script\b|on[a-z]{3,24}\s*=|javascript\s*:")
_RCE_RE = re.compile(
    r"(?i)(?:;|&&|\|\||`)\s*(?:id|whoami|curl|wget|bash|sh|cat)\b|"
    r"\${[^{}]{0,100}jndi\s*:"
)
_LFI_RE = re.compile(r"(?i)(?:\.\./|\.\.\\|/etc/passwd|win\.ini|WEB-INF)")
_SSRF_RE = re.compile(
    r"(?i)(?:https?://(?:127\.0\.0\.1|localhost|169\.254\.169\.254|10\.|"
    r"172\.(?:1[6-9]|2\d|3[0-1])|192\.168\.)|(?:file|gopher|dict)://)"
)
_SSTI_RE = re.compile(
    r"(?is)(?:\{\{.*?(?:config|request|class|mro|subclasses|os\.|popen|system)"
    r".*?\}\}|\$\{.*?(?:runtime|getruntime|processbuilder).*?\})"
)
_CRLF_RE = re.compile(
    r"(?i)(?:%0d|%0a|\\r|\\n|\r|\n)[a-z][a-z0-9-]{1,40}\s*(?::|%3a)"
)
_JNDI_RE = re.compile(r"(?i)\$\{[^{}]{0,160}jndi\s*:(?:ldap|rmi|dns|iiop)://")


def _infer_family(payload: str) -> str:
    text = payload.lower()
    if _SQLI_RE.search(text):
        return "sqli"
    if _XSS_RE.search(text):
        return "xss"
    if _JNDI_RE.search(text):
        return "jndi"
    if _RCE_RE.search(text):
        return "rce"
    if _LFI_RE.search(text):
        return "lfi"
    if _SSRF_RE.search(text):
        return "ssrf"
    if _SSTI_RE.search(text):
        return "ssti"
    if _CRLF_RE.search(text):
        return "crlf"
    if "content-type" in text or "boundary" in text:
        return "parser"
    return "generic"


def _mutate_payload(
    payload: str,
    *,
    family: str,
    rng: random.Random,
) -> list[str]:
    base = str(payload).strip()
    variants = [
        base,
        quote(base, safe="/?=&"),
        quote(quote(base, safe=""), safe="/?=&"),
        _case_toggle(base),
        _insert_sql_comments(base),
        _split_duplicate_parameter(base),
        _wrap_content_type_confusion(base),
    ]
    if family == "xss":
        variants.extend(
            [
                base.replace("<script", "<scr<script>ipt"),
                base.replace("javascript:", "java&#x73;cript:"),
                f"a=<scr&a=ipt>{base}</script>",
            ]
        )
    elif family == "sqli":
        variants.extend(
            [
                re.sub(r"(?i)union", "uni/**/on", base),
                re.sub(r"(?i)select", "sel/**/ect", base),
                f"id=1&id={base}",
            ]
        )
    elif family == "lfi":
        variants.extend(
            [
                base.replace("../", "..%2f"),
                base.replace("../", "%252e%252e%252f"),
                base.replace("/", "\\"),
            ]
        )
    elif family == "rce":
        variants.extend(
            [
                base.replace(";", "%0a"),
                base.replace("&&", "%26%26"),
                f"cmd=echo&cmd={base}",
            ]
        )
    elif family == "ssrf":
        variants.extend(
            [
                base.replace("127.0.0.1", "0177.0.0.1"),
                base.replace("localhost", "localtest.me"),
                base.replace("http://", "gopher://"),
                f"url=http://169.254.169.254/latest/meta-data/&next={quote(base, safe='')}",
            ]
        )
    elif family == "ssti":
        variants.extend(
            [
                base.replace("{{", "{% raw %}{{").replace("}}", "}}{% endraw %}"),
                base.replace("__", "%5f%5f"),
                f"tpl={{%25 set x={quote(base, safe='')} %25}}",
            ]
        )
    elif family == "crlf":
        variants.extend(
            [
                base.replace("%0d%0a", "%0a"),
                base.replace("\\r\\n", "%0d%0a"),
                f"next=/&x={quote(base, safe='')}",
            ]
        )
    elif family == "jndi":
        variants.extend(
            [
                base.replace("jndi:", "${::-j}${::-n}${::-d}${::-i}:"),
                base.replace("ldap://", "dns://"),
                base.replace("${", "${lower:"),
            ]
        )
    rng.shuffle(variants)
    return list(dict.fromkeys(item for item in variants if item))


def _case_toggle(text: str) -> str:
    output: list[str] = []
    upper = True
    for char in text:
        output.append(char.upper() if upper else char.lower())
        if char.isalpha():
            upper = not upper
    return "".join(output)


def _insert_sql_comments(text: str) -> str:
    return re.sub(r"(?i)\b(union|select|from|where|and|or)\b", r"/**/\1/**/", text)


def _split_duplicate_parameter(text: str) -> str:
    if "=" not in text:
        return f"q=clean&q={text}"
    key, value = text.split("=", 1)
    return f"{key}=clean&{key}={value}"


def _wrap_content_type_confusion(text: str) -> str:
    return (
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Type: application/json\r\n\r\n"
        f"{text}"
    )
