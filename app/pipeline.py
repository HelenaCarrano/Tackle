"""Orquestra: ingestão → heurísticas locais → contexto da caixa → enriquecimento → score final."""
from __future__ import annotations

import time
from pathlib import Path

from . import db, enrich
from . import urls as U
from .config import settings
from .heuristics import Finding, analyze_local
from .mailbox import MailboxContext
from .parser import parse_eml
from .scoring import compute

EXTERNAL_LINK_LIMIT = 3


def ingest_bytes(con, raw: bytes, folder: str = "", log=print) -> bool:
    """Guarda e analisa localmente um e-mail. Retorna False se já existia."""
    try:
        e = parse_eml(raw)
    except Exception as exc:  # noqa: BLE001
        log(f"  ! não consegui ler um e-mail: {exc}")
        return False
    if con.execute("SELECT 1 FROM emails WHERE sha256=?", (e.sha256,)).fetchone():
        return False
    settings.eml_store.mkdir(parents=True, exist_ok=True)
    path = settings.eml_store / f"{e.sha256}.eml"
    path.write_bytes(raw)
    try:
        local = analyze_local(e, settings.allowlist())
    except Exception as exc:  # noqa: BLE001 — um e-mail estranho não pode derrubar a importação inteira
        log(f"  ! falha analisando '{db.clean(e.subject)[:60]}': {exc}")
        return False
    snippet = " ".join((e.text or "").split())[:280]
    c = db.clean
    con.execute(
        """INSERT INTO emails (sha256, message_id, path, folder, subject, from_name, from_addr, from_domain, reply_to,
           to_addrs, date, size, snippet, auth, is_bulk, local_findings, links, attachments, qr_codes, ingested_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (e.sha256, c(e.message_id), str(path), c(folder), c(e.subject), c(e.from_name), c(e.from_addr), c(e.from_domain),
         db.dumps(e.reply_to), db.dumps(e.to + e.cc), e.date, e.size, c(snippet), db.dumps(local.auth), int(local.is_bulk),
         db.dumps([f.to_dict() for f in local.findings]), db.dumps([vars(l) for l in local.links]),
         db.dumps(local.attachments), db.dumps(local.qr_codes), time.time()),
    )
    return True


def _technical_summary(findings: list[dict]) -> list[str]:
    return [f"{f['title']}: {f.get('detail', '')}"[:200] for f in sorted(findings, key=lambda f: -f["points"]) if f["points"] > 0]


def enrich_one(con, row: dict, base_findings: list[dict], allow: set[str], full: bool = True) -> tuple[list[dict], dict, list[dict]]:
    """Consultas externas para um e-mail. Retorna (achados, resultado_ia, links_atualizados).
    full=False roda só a camada de IA (Jev/Claude), sem gastar cota de VirusTotal etc."""
    raw = Path(row["path"]).read_bytes()
    e = parse_eml(raw)
    out: list[Finding] = []
    links = row["links"]
    if full:
        _external(con, row, raw, links, allow, out)

    ai: dict = {}
    jf, jans = enrich.jev(con, e)
    out += jf
    if jans:
        ai["jev"] = jans

    prelim = base_findings + [f.to_dict() for f in out]
    score, _ = compute(prelim)
    if score >= settings.llm_min_score:
        cf, cres = enrich.claude(con, e, _technical_summary(prelim))
        out += cf
        if cres:
            ai["claude"] = cres
    return [f.to_dict() for f in out], ai, links


def _external(con, row: dict, raw: bytes, links: list[dict], allow: set[str], out: list[Finding]) -> None:
    # Idade do domínio do remetente e dos links arriscados
    reg = U.registered_domain(row["from_domain"] or "")
    domains = []
    if reg and reg not in U.FREEMAIL and reg not in allow:
        domains.append(("remetente", reg))
    for l in sorted(links, key=lambda x: -x.get("points", 0)):
        d = l.get("registered")
        if l.get("points", 0) >= 10 and d and d not in allow and not U.domain_matches(d, U.ABUSED_HOSTING) \
                and all(d != x for _, x in domains):
            domains.append(("link", d))
        if len(domains) >= 4:
            break
    for kind, d in domains:
        age = enrich.domain_age_days(con, d)
        if age is None:
            continue
        for l in links:
            if l.get("registered") == d:
                l.setdefault("enrichment", {})["idade_dias"] = age
        if age < 30:
            out.append(Finding(f"dominio_novo_{kind}", "reputacao", f"Domínio do {kind} criado há {age} dias", 25, d))
        elif age < 180:
            out.append(Finding(f"dominio_recente_{kind}", "reputacao", f"Domínio do {kind} criado há {age} dias", 10, d))

    # VirusTotal: links mais arriscados e anexos (não imagens)
    for l in [x for x in sorted(links, key=lambda x: -x.get("points", 0)) if x.get("points", 0) >= 8][:EXTERNAL_LINK_LIMIT]:
        res = enrich.vt_lookup(con, "url", l["final_url"])
        if res:
            l.setdefault("enrichment", {})["virustotal"] = res
        f = enrich._vt_finding("link", l["final_url"], res)
        if f:
            out.append(f)
    for a in [a for a in row["attachments"] if not a.get("content_type", "").startswith("image/")][:3]:
        res = enrich.vt_lookup(con, "file", a["sha256"])
        if res:
            a["virustotal"] = res
        f = enrich._vt_finding("anexo", a["filename"], res)
        if f:
            out.append(f)

    out += enrich.eml_analyzer(con, row["sha256"], raw)
    ps_findings, ps_flags = enrich.phishsage(row["path"])
    out += ps_findings
    for l in links:
        if l.get("url") in ps_flags or l.get("final_url") in ps_flags:
            l.setdefault("enrichment", {})["phishsage"] = ps_flags.get(l["url"]) or ps_flags.get(l["final_url"])


def analyze_all(con, *, do_enrich: bool = True, force: bool = False, log=print) -> dict:
    """Recalcula sinais da caixa e score de todos; enriquece só quem passa do limite."""
    allow = settings.allowlist()
    rows = [db.row_to_dict(r) for r in con.execute("SELECT * FROM emails")]
    ctx = MailboxContext(rows, allow)
    stats = {"total": len(rows), "enriquecidos": 0}
    for i, r in enumerate(rows, 1):
        mb, campaign = ctx.findings_for(r)
        mbd = [f.to_dict() for f in mb]
        base = r["local_findings"] + mbd
        enrich_findings, ai, links = r["enrich_findings"], r["ai"], r["links"]
        pre_score, _ = compute(base)
        full = do_enrich and pre_score >= settings.enrich_min_score and (force or not r["enriched"])
        ai_only = do_enrich and not full and (force or not r["enriched"]) and (
            settings.jev_enabled or (settings.llm_ready and pre_score >= settings.llm_min_score))
        enriched = bool(r["enriched"])
        if full or ai_only:
            log(f"  {'enriquecendo' if full else 'IA'} {i}/{len(rows)}: {r['subject'][:60]!r} (score local {pre_score})")
            enrich_findings, ai, links = enrich_one(con, r, base, allow, full=full)
            stats["enriquecidos"] += 1
            enriched = True
        score, level = compute(base + (enrich_findings or []))
        con.execute(
            """UPDATE emails SET mailbox_findings=?, enrich_findings=?, ai=?, links=?, attachments=?, campaign=?,
               score=?, level=?, enriched=?, analyzed_at=? WHERE id=?""",
            (db.dumps(mbd), db.dumps(enrich_findings or []), db.dumps(ai or {}), db.dumps(links),
             db.dumps(r["attachments"]), campaign, score, level, int(enriched), time.time(), r["id"]),
        )
    con.commit()
    return stats
