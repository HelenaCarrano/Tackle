"""API + painel web."""
from __future__ import annotations

import csv
import io
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response
from pydantic import BaseModel

from . import db
from . import urls as U
from .config import settings
from .parser import parse_eml
from .pipeline import analyze_all

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="Tackle")
_lock = threading.Lock()


def all_findings(r: dict) -> list[dict]:
    fs = (r.get("local_findings") or []) + (r.get("mailbox_findings") or []) + (r.get("enrich_findings") or [])
    return sorted(fs, key=lambda f: -f.get("points", 0))


def light(r: dict) -> dict:
    fs = all_findings(r)
    return {
        "id": r["id"], "date": r["date"], "subject": r["subject"], "from_name": r["from_name"], "from_addr": r["from_addr"],
        "from_domain": U.registered_domain(r["from_domain"] or ""), "score": r["score"], "level": r["level"],
        "campaign": r["campaign"], "label": r["label"], "folder": r["folder"],
        "reasons": [f["title"] for f in fs if f.get("points", 0) > 0][:3],
        "categories": sorted({f["category"] for f in fs if f.get("points", 0) >= 10}),
        # Em plataformas compartilhadas (web.app, bit.ly…) mostra o endereço completo: bloquear o domínio inteiro derrubaria sites legítimos
        "risky_domains": sorted({(l["host"] if U.domain_matches(l.get("host", ""), U.ABUSED_HOSTING | U.SHORTENERS) else l["registered"])
                                 for l in r.get("links") or [] if l.get("points", 0) >= 10 and l.get("registered")}),
        "n_links": len(r.get("links") or []), "n_attachments": len(r.get("attachments") or []),
        "ai": bool(r.get("ai")),
    }


def detail(r: dict) -> dict:
    d = light(r)
    d["findings"] = all_findings(r)
    d["links"] = sorted(r.get("links") or [], key=lambda l: -l.get("points", 0))
    d["attachments"] = r.get("attachments") or []
    d["qr_codes"] = r.get("qr_codes") or []
    d["auth"] = r.get("auth") or {}
    d["ai"] = r.get("ai") or {}
    d["reply_to"] = r.get("reply_to") or []
    d["to"] = r.get("to_addrs") or []
    try:
        e = parse_eml(Path(r["path"]).read_bytes())
        d["text"] = db.clean((e.text or "")[:8000])  # só texto: o HTML do e-mail nunca é renderizado no painel
        d["hidden_text"] = db.clean((e.hidden_text or "")[:1500])
        d["headers"] = {k: db.clean(e.header(k)[:400]) for k in
                        ("from", "reply-to", "return-path", "to", "date", "message-id", "x-mailer", "list-unsubscribe")
                        if e.header(k)}
        d["received_hops"] = len(e.headers_all("received"))
    except OSError:
        d["text"], d["hidden_text"], d["headers"], d["received_hops"] = "(arquivo original não encontrado)", "", {}, 0
    return d


@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/meta")
def meta():
    with db.session() as con:
        n = con.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
        usage = con.execute(
            """SELECT COUNT(*) AS requests,
                      COALESCE(SUM(prompt_tokens), 0) AS prompt_tokens,
                      COALESCE(SUM(completion_tokens), 0) AS completion_tokens,
                      COALESCE(SUM(total_tokens), 0) AS total_tokens,
                      SUM(cost) AS cost
               FROM provider_usage WHERE provider='openrouter'"""
        ).fetchone()
    return {
        "total": n,
        "openrouter_usage": dict(usage),
        "enrichers": {
            "VirusTotal": bool(settings.virustotal_api_key),
            "Idade de domínio": settings.domain_age_enabled,
            "eml_analyzer": bool(settings.eml_analyzer_url),
            "PhishSage": settings.phishsage_enabled,
            "Jev": settings.jev_enabled and bool(settings.typesafe_api_key),
            ("LLM via OpenRouter" if settings.llm_provider_effective == "openrouter" else "Claude"): settings.llm_ready,
        },
        "org_domains": settings.org_domains,
    }


@app.get("/api/emails")
def list_emails():
    with db.session() as con:
        return [light(db.row_to_dict(r)) for r in con.execute("SELECT * FROM emails ORDER BY score DESC, date DESC")]


@app.get("/api/emails/{eid}")
def get_email(eid: int):
    with db.session() as con:
        r = con.execute("SELECT * FROM emails WHERE id=?", (eid,)).fetchone()
    if not r:
        raise HTTPException(404, "E-mail não encontrado")
    return detail(db.row_to_dict(r))


@app.get("/api/emails/{eid}/raw")
def raw_email(eid: int):
    with db.session() as con:
        r = con.execute("SELECT path, sha256 FROM emails WHERE id=?", (eid,)).fetchone()
    if not r or not Path(r["path"]).exists():
        raise HTTPException(404, "Arquivo não encontrado")
    # Baixa como arquivo (nunca abre no navegador)
    return FileResponse(r["path"], media_type="application/octet-stream", filename=f"{r['sha256'][:12]}.eml")


class LabelIn(BaseModel):
    label: str | None


@app.post("/api/emails/{eid}/label")
def set_label(eid: int, body: LabelIn):
    if body.label not in (None, "phishing", "legitimo"):
        raise HTTPException(400, "Use 'phishing', 'legitimo' ou null")
    with db.session() as con:
        con.execute("UPDATE emails SET label=? WHERE id=?", (body.label, eid))
    return {"ok": True, "label": body.label}


class DomainIn(BaseModel):
    domain: str


@app.post("/api/allowlist")
def add_allow(body: DomainIn):
    d = U.registered_domain(body.domain.strip().lower())
    if not d or "." not in d:
        raise HTTPException(400, "Domínio inválido")
    existing = settings.allowlist()
    if d not in existing:
        with open(settings.allowlist_file, "a", encoding="utf-8") as f:
            f.write(f"\n{d}")
    return {"ok": True, "domain": d, "note": "Recalcule a análise para aplicar."}


@app.post("/api/reanalyze")
def reanalyze():
    """Recalcula scores sem consultas externas (rápido); usa o que já está em cache."""
    if not _lock.acquire(blocking=False):
        raise HTTPException(409, "Uma análise já está rodando")
    try:
        with db.session() as con:
            stats = analyze_all(con, do_enrich=False, log=lambda *_: None)
        return stats
    finally:
        _lock.release()


@app.get("/api/export.csv")
def export_csv():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "data", "score", "nivel", "rotulo", "remetente", "assunto", "motivos", "campanha"])
    with db.session() as con:
        for r in con.execute("SELECT * FROM emails ORDER BY score DESC"):
            d = light(db.row_to_dict(r))
            w.writerow([d["id"], d["date"], d["score"], d["level"], d["label"] or "", d["from_addr"], d["subject"],
                        " | ".join(d["reasons"]), d["campaign"] or ""])
    return Response(buf.getvalue().encode("utf-8-sig"), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=triagem.csv"})
