"""Análise de anexos: extensões perigosas, macros (oletools), HTML/SVG armados, PDFs, ZIPs e QR codes."""
from __future__ import annotations

import base64
import io
import re
import zipfile
from dataclasses import dataclass, field

from .parser import Attachment, analyze_html

DANGEROUS_EXT = {
    "exe", "scr", "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "bat", "cmd", "ps1", "psm1", "lnk", "iso",
    "img", "vhd", "vhdx", "msi", "msix", "appx", "jar", "com", "pif", "cpl", "reg", "chm", "apk", "one",
    "xll", "iqy", "slk", "url", "library-ms", "settingcontent-ms", "application", "gadget", "msc", "inf",
    "scf", "dll", "sys", "py", "pyw", "ace", "arj", "cab", "xlam", "ppam",
}
MACRO_EXT = {"docm", "dotm", "xlsm", "xltm", "xlsb", "pptm", "potm", "ppsm", "sldm"}
OFFICE_EXT = MACRO_EXT | {"doc", "dot", "xls", "xlt", "ppt", "pps", "docx", "xlsx", "pptx", "rtf"}
ARCHIVE_EXT = {"zip", "rar", "7z", "gz", "tgz", "tar", "bz2", "xz", "zipx", "lzh"}
HTML_EXT = {"html", "htm", "shtml", "xhtml", "mht", "mhtml"}
IMAGE_TYPES = ("image/png", "image/jpeg", "image/jpg", "image/gif", "image/bmp", "image/webp")

HTML_SMUGGLING_RE = re.compile(
    r"atob\s*\(|window\.location|location\.(?:href|replace)|document\.write|unescape\s*\(|"
    r"fromCharCode|eval\s*\(|<meta[^>]+http-equiv=['\"]?refresh|new\s+Blob\s*\(|msSaveOrOpenBlob|"
    r"fetch\s*\(|XMLHttpRequest|\.submit\s*\(\)",
    re.I,
)
DATA_IMG_RE = re.compile(r"data:image/(?:png|jpe?g|gif|bmp|webp);base64,([A-Za-z0-9+/=\s]{200,})", re.I)


@dataclass
class AttachmentFinding:
    code: str
    title: str
    points: int
    detail: str
    critical: bool = False


@dataclass
class AttachmentReport:
    findings: list[AttachmentFinding] = field(default_factory=list)
    extra_links: list[tuple[str, str]] = field(default_factory=list)  # (url, origem)
    qr_codes: list[dict] = field(default_factory=list)
    summary: list[dict] = field(default_factory=list)


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def decode_qr(image_bytes: bytes) -> list[str]:
    try:
        from PIL import Image, ImageOps
        from pyzbar.pyzbar import ZBarSymbol, decode
    except Exception:
        return []
    out: list[str] = []
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.load()
        if getattr(img, "n_frames", 1) > 1:
            img.seek(0)
        img = img.convert("RGB")
        if max(img.size) > 3000:
            img.thumbnail((3000, 3000))
        candidates = [img, ImageOps.grayscale(img)]
        if max(img.size) < 400:
            candidates.append(img.resize((img.width * 3, img.height * 3)))
        for c in candidates:
            for sym in decode(c, symbols=[ZBarSymbol.QRCODE]):
                val = sym.data.decode("utf-8", errors="replace")
                if val not in out:
                    out.append(val)
            if out:
                break
    except Exception:
        return out
    return out


def qr_from_html(html: str) -> list[str]:
    """QR codes embutidos como imagem base64 dentro do corpo HTML."""
    found: list[str] = []
    for m in DATA_IMG_RE.finditer(html or ""):
        try:
            data = base64.b64decode(re.sub(r"\s+", "", m.group(1)), validate=False)
        except Exception:
            continue
        for v in decode_qr(data):
            if v not in found:
                found.append(v)
    return found


def _office_macros(att: Attachment) -> AttachmentFinding | None:
    try:
        from oletools.olevba import VBA_Parser
    except Exception:
        return None
    try:
        vp = VBA_Parser(att.filename, data=att.data)
        if not vp.detect_vba_macros():
            vp.close()
            return None
        results = vp.analyze_macros()
        vp.close()
    except Exception:
        return None
    autoexec = sorted({kw for t, kw, _ in results if t == "AutoExec"})
    suspicious = sorted({kw for t, kw, _ in results if t in ("Suspicious", "IOC")})
    if autoexec and suspicious:
        return AttachmentFinding(
            "macro_maliciosa", "Macro que executa sozinha com comandos suspeitos", 45,
            f"{att.filename}: auto-execução ({', '.join(autoexec[:4])}) e chamadas suspeitas ({', '.join(suspicious[:6])})",
            critical=True,
        )
    return AttachmentFinding(
        "macro", "Documento com macro VBA", 20 if autoexec else 12,
        f"{att.filename}: contém macro" + (f" com auto-execução ({', '.join(autoexec[:4])})" if autoexec else ""),
    )


def _pdf_checks(att: Attachment, rep: AttachmentReport) -> None:
    data = att.data[:5_000_000]
    flags = []
    for key, label in ((rb"/JavaScript", "JavaScript"), (rb"/JS", "JS"), (rb"/OpenAction", "ação ao abrir"),
                       (rb"/Launch", "Launch (executa programa)"), (rb"/EmbeddedFile", "arquivo embutido"),
                       (rb"/AA", "ação automática"), (rb"/SubmitForm", "envio de formulário")):
        if key in data:
            flags.append(label)
    for m in re.finditer(rb"/URI\s*\(([^)]{4,500})\)", data):
        rep.extra_links.append((m.group(1).decode("latin-1", errors="replace"), f"pdf:{att.filename}"))
    risky = [f for f in flags if f not in ("ação automática",)]
    if "Launch (executa programa)" in flags or ("JavaScript" in flags and "ação ao abrir" in flags):
        rep.findings.append(AttachmentFinding("pdf_ativo", "PDF com código que roda ao abrir", 35,
                                              f"{att.filename}: {', '.join(flags)}", critical=True))
    elif risky:
        rep.findings.append(AttachmentFinding("pdf_suspeito", "PDF com elementos ativos", 12,
                                              f"{att.filename}: {', '.join(flags)}"))


def _html_checks(att: Attachment, rep: AttachmentReport, label: str = "HTML") -> None:
    try:
        content = att.data.decode("utf-8", errors="replace")
    except Exception:
        return
    info = analyze_html(content)
    for l in info.links:
        rep.extra_links.append((l.url, f"anexo:{att.filename}"))
    smuggling = sorted({m.group(0)[:25] for m in HTML_SMUGGLING_RE.finditer(content)})
    if info.has_password_input:
        rep.findings.append(AttachmentFinding(
            "anexo_html_senha", f"Anexo {label} com campo de senha (página de login falsa)", 45,
            f"{att.filename}: formulário pedindo senha embutido no anexo", critical=True))
    elif smuggling:
        rep.findings.append(AttachmentFinding(
            "anexo_html_script", f"Anexo {label} com script de redirecionamento/ofuscação", 30,
            f"{att.filename}: {', '.join(smuggling[:5])}"))
    else:
        rep.findings.append(AttachmentFinding("anexo_html", f"Anexo {label}", 12,
                                              f"{att.filename}: anexos HTML/SVG são raros em e-mail legítimo"))


def analyze_attachments(attachments: list[Attachment]) -> AttachmentReport:
    rep = AttachmentReport()
    for att in attachments:
        name = att.filename or ""
        ext = _ext(name)
        rep.summary.append({"filename": name, "content_type": att.content_type, "size": att.size,
                            "sha256": att.sha256, "inline": att.inline})

        if "‮" in name or "‭" in name:
            rep.findings.append(AttachmentFinding("rtlo", "Nome de anexo com caractere invertido (RTLO)", 50,
                                                  f"'{name}' esconde a extensão real", critical=True))
        parts = name.lower().split(".")
        if len(parts) >= 3 and parts[-1] in DANGEROUS_EXT and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt"}:
            rep.findings.append(AttachmentFinding("extensao_dupla", "Extensão dupla para disfarçar executável", 45,
                                                  f"'{name}'", critical=True))
        elif ext in DANGEROUS_EXT:
            rep.findings.append(AttachmentFinding("anexo_perigoso", "Anexo de tipo executável/perigoso", 40,
                                                  f"'{name}' (.{ext})", critical=True))

        if ext in OFFICE_EXT or att.content_type in ("application/msword", "application/vnd.ms-excel"):
            f = _office_macros(att)
            if f:
                rep.findings.append(f)
            elif ext in MACRO_EXT:
                rep.findings.append(AttachmentFinding("macro_ext", "Documento com extensão de macro", 10, f"'{name}'"))
        if ext == "pdf" or att.content_type == "application/pdf":
            _pdf_checks(att, rep)
        if ext in HTML_EXT or att.content_type == "text/html":
            _html_checks(att, rep, "HTML")
        if ext == "svg" or att.content_type == "image/svg+xml":
            low = att.data[:2_000_000].lower()
            if b"<script" in low or b"foreignobject" in low or b"javascript:" in low:
                _html_checks(att, rep, "SVG")
            else:
                for m in re.finditer(rb"href=[\"']([^\"']+)", att.data[:2_000_000]):
                    rep.extra_links.append((m.group(1).decode("utf-8", "replace"), f"svg:{name}"))
        if ext in ARCHIVE_EXT or att.content_type in ("application/zip", "application/x-zip-compressed"):
            try:
                with zipfile.ZipFile(io.BytesIO(att.data)) as zf:
                    infos = zf.infolist()
                    encrypted = any(i.flag_bits & 0x1 for i in infos)
                    inner = [i.filename for i in infos]
                    bad = [n for n in inner if _ext(n) in DANGEROUS_EXT | HTML_EXT | {"svg"}]
                    if bad:
                        rep.findings.append(AttachmentFinding("zip_perigoso", "Arquivo compactado com executável/script", 40,
                                                              f"{name} contém: {', '.join(bad[:5])}", critical=True))
                    if encrypted:
                        rep.findings.append(AttachmentFinding("zip_senha", "Arquivo compactado protegido por senha", 25,
                                                              f"{name}: senha impede antivírus de inspecionar"))
                    for n in inner:
                        if _ext(n) in MACRO_EXT:
                            rep.findings.append(AttachmentFinding("zip_macro", "Documento com macro dentro do compactado", 15, f"{name} → {n}"))
            except zipfile.BadZipFile:
                if ext in {"rar", "7z", "ace", "arj"}:
                    rep.findings.append(AttachmentFinding("compactado_raro", "Formato compactado que o filtro não inspeciona", 10, f"'{name}'"))
            except Exception:
                pass

        if att.content_type.startswith(IMAGE_TYPES) or ext in {"png", "jpg", "jpeg", "gif", "bmp", "webp"}:
            for val in decode_qr(att.data):
                rep.qr_codes.append({"source": name, "value": val})
                if re.match(r"(?i)https?://|www\.", val):
                    rep.extra_links.append((val, f"qr:{name}"))
    return rep
