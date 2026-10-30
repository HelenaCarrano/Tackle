"""Gera um HTML único, sem servidor, com o painel e os dados embutidos (para compartilhar um relatório).

Uso: python scripts/export_static.py relatorio.html [--min-score 0] [--no-body]

Atenção: o arquivo contém assuntos, remetentes e (sem --no-body) o texto dos e-mails.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import db  # noqa: E402
from app.server import STATIC, detail, light, meta  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--min-score", type=int, default=0, help="Só incluir e-mails a partir deste score")
    ap.add_argument("--no-body", action="store_true", help="Não incluir o texto dos e-mails")
    ap.add_argument("--title", default="Tackle")
    ap.add_argument("--banner", default="", help="Aviso exibido no topo (ex.: 'Dados de exemplo')")
    ap.add_argument("--fragment", action="store_true", help="Sem <!doctype>/<html>/<head>/<body> (para embutir em outra página)")
    args = ap.parse_args()

    with db.session() as con:
        raw = [db.row_to_dict(r) for r in con.execute("SELECT * FROM emails WHERE score >= ? ORDER BY score DESC", (args.min_score,))]
    rows = [light(r) for r in raw]
    details = {}
    for r in raw:
        d = detail(r)
        if args.no_body:
            d["text"], d["hidden_text"] = "(texto omitido neste relatório)", ""
        details[r["id"]] = d
    m = meta()
    data = json.dumps({"meta": m, "rows": rows, "details": details}, ensure_ascii=False, default=str)
    data = data.replace("</", "<\\/")  # impede fechar a tag <script> por conteúdo de e-mail

    html = (STATIC / "index.html").read_text(encoding="utf-8")
    html = html.replace("<title>Tackle</title>", f"<title>{args.title}</title>")
    html = html.replace("<script>\n(() => {", f"<script>window.__DEMO__ = {data};</script>\n<script>\n(() => {{", 1)
    if args.banner:
        banner = ('<p style="margin:0 24px 6px;padding:6px 12px;border-left:4px solid var(--postal);background:var(--sheet);'
                  f'color:var(--ink-2);font-size:14px">{args.banner}</p>')
        html = html.replace('<div class="strip-wrap">', banner + '\n<div class="strip-wrap">', 1)
    if args.fragment:
        import re
        html = re.sub(r"<!doctype html>\s*<html[^>]*>\s*<head>|</head>\s*<body>|</body>\s*</html>\s*$", "", html, flags=re.I)
        html = re.sub(r'<meta charset="utf-8">\s*<meta name="viewport"[^>]*>', "", html)
    Path(args.out).write_text(html, encoding="utf-8")
    print(f"Relatório com {len(rows)} e-mails salvo em {args.out}")


if __name__ == "__main__":
    main()
