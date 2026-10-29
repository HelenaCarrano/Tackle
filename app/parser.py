"""Leitura de um .eml e extração de tudo que as heurísticas precisam."""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html import unescape
from html.parser import HTMLParser

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'`\]\)]+)""")


@dataclass
class Link:
    url: str
    text: str = ""          # texto visível do link (âncora), quando houver
    source: str = "html"    # html | text | form | qr | attachment


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str
    data: bytes = field(repr=False, default=b"")
    inline: bool = False


@dataclass
class ParsedEmail:
    message_id: str
    subject: str
    date: str | None
    from_name: str
    from_addr: str
    reply_to: list[str]
    return_path: str
    to: list[str]
    cc: list[str]
    headers: dict[str, list[str]]
    text: str               # texto visível (sem o que está escondido por CSS)
    html: str
    links: list[Link]
    attachments: list[Attachment]
    sha256: str
    size: int
    hidden_text: str = ""   # texto escondido no HTML (display:none, fonte 0 etc.)
    body_has_password_form: bool = False

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[-1].lower() if "@" in self.from_addr else ""

    def header(self, name: str) -> str:
        vals = self.headers.get(name.lower())
        return decode_header_value(vals[0]) if vals else ""

    def headers_all(self, name: str) -> list[str]:
        return self.headers.get(name.lower(), [])


VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}
HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0*(?:\.\d+)?(?:px|pt|em|rem)?\s*(?:;|$)"
    r"|font-size\s*:\s*[01](?:px|pt)|opacity\s*:\s*0(?:\.0+)?\s*(?:;|$)|max-height\s*:\s*0(?:px)?\s*(?:;|$)",
    re.I,
)
# Obs.: texto branco não entra aqui de propósito — botões com texto branco em fundo colorido são comuns.


def decode_header_value(v: str) -> str:
    """Decodifica '=?utf-8?q?...?=' para texto legível."""
    if "=?" not in v:
        return v
    try:
        from email.header import decode_header, make_header
        return str(make_header(decode_header(v)))
    except Exception:
        return v


class _AnchorParser(HTMLParser):
    """Extrai <a href>, <form action>, <area href>, texto visível e texto escondido."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._stack: list[list] = []  # [href, text_parts]
        self.text_parts: list[str] = []
        self.hidden_parts: list[str] = []
        self._tags: list[tuple[str, bool]] = []  # (tag, escondido?)
        self._skip = 0
        self.has_password_input = False
        self.form_actions: list[str] = []

    @property
    def _hidden(self) -> bool:
        return any(h for _, h in self._tags)

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag not in VOID_TAGS:
            hidden = bool(HIDDEN_STYLE_RE.search(a.get("style", ""))) or "hidden" in a
            self._tags.append((tag, hidden))
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in ("a", "area") and a.get("href"):
            self._stack.append([a["href"].strip(), []])
            if tag == "area":
                self.links.append(Link(a["href"].strip(), a.get("alt", ""), "html"))
                self._stack.pop()
        elif tag == "form":
            act = a.get("action", "").strip()
            self.form_actions.append(act)
            if act:
                self.links.append(Link(act, "[formulário]", "form"))
        elif tag == "input" and a.get("type", "").lower() == "password":
            self.has_password_input = True
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text_parts.append("\n")

    def handle_endtag(self, tag):
        for i in range(len(self._tags) - 1, -1, -1):
            if self._tags[i][0] == tag:
                del self._tags[i:]
                break
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._stack:
            href, parts = self._stack.pop()
            self.links.append(Link(href, " ".join("".join(parts).split()), "html"))

    def handle_data(self, data):
        if self._skip:
            return
        if self._hidden:
            if data.strip():
                self.hidden_parts.append(data.strip())
            return
        self.text_parts.append(data)
        for item in self._stack:
            item[1].append(data)


@dataclass
class HtmlInfo:
    text: str
    links: list[Link]
    hidden_text: str
    has_password_input: bool
    form_actions: list[str]


def analyze_html(html: str) -> HtmlInfo:
    p = _AnchorParser()
    try:
        p.feed(html)
        p.close()
    except Exception:
        pass
    # âncoras não fechadas
    for href, parts in p._stack:
        p.links.append(Link(href, " ".join("".join(parts).split()), "html"))
    text = re.sub(r"\n\s*\n+", "\n\n", unescape("".join(p.text_parts)))
    text = re.sub(r"[ \t ​‌‍⁠﻿]+", " ", text)
    return HtmlInfo(text.strip(), p.links, " ".join(p.hidden_parts)[:5000], p.has_password_input, p.form_actions)


def _decode_part(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", errors="replace")


def parse_eml(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)

    headers: dict[str, list[str]] = {}
    for k, v in msg.raw_items():
        headers.setdefault(k.lower(), []).append(str(v))

    def safe(name: str) -> str:
        try:
            return str(msg.get(name, "") or "")
        except Exception:
            vals = headers.get(name.lower())
            return vals[0] if vals else ""

    from_name, from_addr = parseaddr(safe("From"))
    reply_to = [a.lower() for _, a in getaddresses([safe("Reply-To")]) if a]
    return_path = parseaddr(safe("Return-Path"))[1].lower()
    to = [a.lower() for _, a in getaddresses([safe("To")]) if a]
    cc = [a.lower() for _, a in getaddresses([safe("Cc")]) if a]

    date_iso = None
    try:
        d = parsedate_to_datetime(safe("Date"))
        date_iso = d.isoformat() if d else None
    except Exception:
        pass

    texts: list[str] = []
    htmls: list[str] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename() or ""
        if ctype == "message/rfc822":
            payload = part.get_payload()
            data = payload[0].as_bytes() if isinstance(payload, list) and payload else (part.get_payload(decode=True) or b"")
            attachments.append(Attachment(filename or "mensagem.eml", ctype, len(data), hashlib.sha256(data).hexdigest(), data))
            continue
        if disp != "attachment" and not filename and ctype == "text/plain":
            texts.append(_decode_part(part))
        elif disp != "attachment" and not filename and ctype == "text/html":
            htmls.append(_decode_part(part))
        else:
            data = part.get_payload(decode=True) or b""
            attachments.append(Attachment(
                filename=filename or f"sem-nome.{ctype.split('/')[-1]}",
                content_type=ctype,
                size=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                data=data,
                inline=disp == "inline" or bool(part.get("Content-ID")),
            ))

    html = "\n".join(htmls)
    text = "\n".join(texts)
    links: list[Link] = []
    hidden_text = ""
    pw_form = False
    if html:
        info = analyze_html(html)
        links.extend(info.links)
        hidden_text = info.hidden_text
        pw_form = info.has_password_input
        plain = text
        # O que o usuário enxerga na maioria dos clientes é o HTML renderizado
        text = info.text or plain
    else:
        plain = text
    seen = {l.url for l in links}
    for m in URL_RE.finditer(text + "\n" + plain):
        u = m.group(1).rstrip(".,;:!?")
        if u not in seen:
            seen.add(u)
            links.append(Link(u, "", "text"))

    return ParsedEmail(
        message_id=safe("Message-ID").strip() or hashlib.sha256(raw).hexdigest()[:32],
        subject=safe("Subject"),
        date=date_iso,
        from_name=from_name,
        from_addr=from_addr.lower(),
        reply_to=reply_to,
        return_path=return_path,
        to=to,
        cc=cc,
        headers=headers,
        text=text,
        html=html,
        links=links,
        attachments=attachments,
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        hidden_text=hidden_text,
        body_has_password_form=pw_form,
    )
