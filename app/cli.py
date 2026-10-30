"""Linha de comando.

  python -m app.cli imap --host imap.gmail.com --user voce@gmail.com [--folder INBOX] [--since 2026-01-01]
  python -m app.cli folder ./minha_pasta_de_emls
  python -m app.cli mbox ./export.mbox
  python -m app.cli analyze [--no-enrich] [--force]
  python -m app.cli evaluate samples/labels.csv
  python -m app.cli serve
"""
from __future__ import annotations

import argparse
import getpass
import imaplib
import mailbox
import os
import re
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path

from . import db
from .config import settings
from .metrics import metrics
from .pipeline import analyze_all, ingest_bytes


def _report(con, n_new: int, n_seen: int) -> None:
    print(f"\n{n_new} e-mails novos guardados ({n_seen} já estavam no banco).")


def cmd_folder(args) -> None:
    root = Path(args.path)
    files = [p for p in root.rglob("*") if p.suffix.lower() in (".eml",)]
    if not files:
        sys.exit(f"Nenhum .eml em {root}. (Arquivos .msg: converta com 'msgconvert' ou exporte como .eml.)")
    with db.session() as con:
        new = 0
        for i, p in enumerate(files, 1):
            new += ingest_bytes(con, p.read_bytes(), folder=str(p.parent.relative_to(root)) if p.parent != root else "")
            if i % 200 == 0:
                con.commit()
                print(f"  {i}/{len(files)}")
        _report(con, new, len(files) - new)
    if not args.no_analyze:
        cmd_analyze(args)


def cmd_mbox(args) -> None:
    with db.session() as con:
        new = total = 0
        for path in args.paths:
            p = Path(path)
            for folder, msg in _mailbox_messages(p):
                total += 1
                new += ingest_bytes(con, msg.as_bytes(), folder=folder)
                if total % 200 == 0:
                    con.commit()
                    print(f"  {total} lidos")
        _report(con, new, total - new)
    if not args.no_analyze:
        cmd_analyze(args)


def _mailbox_messages(path: Path):
    if path.is_dir():
        box = mailbox.Maildir(path, create=False)
        try:
            for msg in box:
                yield path.stem, msg
        finally:
            box.close()
        return

    if path.suffix.lower() != ".zip":
        box = mailbox.mbox(path, create=False)
        try:
            for msg in box:
                yield path.stem, msg
        finally:
            box.close()
        return

    try:
        archive = zipfile.ZipFile(path)
    except zipfile.BadZipFile as exc:
        raise SystemExit(f"Arquivo ZIP inválido: {path}") from exc

    with archive:
        members = [info for info in archive.infolist()
                   if not info.is_dir() and Path(info.filename).suffix.lower() == ".mbox"]
        if not members:
            raise SystemExit(f"Nenhum arquivo .mbox encontrado em {path}.")

        with tempfile.TemporaryDirectory(prefix="tackle-") as temp_dir:
            for index, info in enumerate(members):
                extracted = Path(temp_dir) / f"{index}.mbox"
                with archive.open(info) as source, extracted.open("wb") as target:
                    shutil.copyfileobj(source, target)
                box = mailbox.mbox(extracted, create=False)
                try:
                    for msg in box:
                        yield Path(info.filename).stem, msg
                finally:
                    box.close()


def _imap_folders(M: imaplib.IMAP4_SSL) -> list[str]:
    typ, data = M.list()
    out = []
    for raw in data or []:
        line = raw.decode(errors="replace")
        m = re.match(r'\((?P<flags>[^)]*)\) "(?P<sep>[^"]*)" (?P<name>.+)$', line)
        if not m or "\\Noselect" in m.group("flags"):
            continue
        out.append(m.group("name").strip().strip('"'))
    return out


def cmd_imap(args) -> None:
    password = os.getenv("IMAP_PASSWORD") or (None if args.oauth_token else getpass.getpass("Senha de app IMAP: "))
    print(f"Conectando em {args.host} como {args.user}...")
    M = imaplib.IMAP4_SSL(args.host, args.port)
    if args.oauth_token:
        token = os.getenv(args.oauth_token, args.oauth_token)
        M.authenticate("XOAUTH2", lambda _: f"user={args.user}\x01auth=Bearer {token}\x01\x01".encode())
    else:
        M.login(args.user, password)

    folders = args.folder or ["INBOX"]
    if folders == ["ALL"]:
        folders = [f for f in _imap_folders(M) if not re.search(r"trash|lixeira|spam|junk|drafts|rascunho|\[gmail\]/all", f, re.I)]
        print("Pastas:", ", ".join(folders))
    criteria = ["ALL"]
    if args.since:
        criteria = ["SINCE", datetime.strptime(args.since, "%Y-%m-%d").strftime("%d-%b-%Y")]

    with db.session() as con:
        new = total = 0
        for folder in folders:
            typ, _ = M.select(f'"{folder}"', readonly=True)  # somente leitura: não marca como lido
            if typ != "OK":
                print(f"  ! não consegui abrir {folder}")
                continue
            typ, data = M.uid("SEARCH", None, *criteria)
            uids = (data[0] or b"").split()
            if args.limit:
                uids = uids[-args.limit:]
            print(f"  {folder}: {len(uids)} mensagens")
            for start in range(0, len(uids), 50):
                batch = b",".join(uids[start:start + 50])
                typ, msgs = M.uid("FETCH", batch, "(BODY.PEEK[])")
                for part in msgs or []:
                    if isinstance(part, tuple) and len(part) == 2:
                        total += 1
                        new += ingest_bytes(con, part[1], folder=folder)
                con.commit()
                print(f"    {min(start + 50, len(uids))}/{len(uids)}")
        _report(con, new, total - new)
    M.logout()
    if not args.no_analyze:
        cmd_analyze(args)


def cmd_analyze(args) -> None:
    print("\nAnalisando a caixa (sinais da caixa inteira + enriquecimento seletivo)...")
    with db.session() as con:
        stats = analyze_all(con, do_enrich=not getattr(args, "no_enrich", False), force=getattr(args, "force", False))
        rows = con.execute("SELECT level, COUNT(*) c FROM emails GROUP BY level").fetchall()
    print(f"\nPronto: {stats['total']} e-mails, {stats['enriquecidos']} enriquecidos.")
    metrics.report(top=getattr(args, "top", 10))
    for r in sorted(rows, key=lambda r: ["crítico", "alto", "médio", "baixo", "limpo"].index(r["level"])):
        print(f"  {r['level']:>8}: {r['c']}")
    print("\nAbra o painel com:  python -m app.cli serve   →  http://localhost:8080")


def cmd_evaluate(args) -> None:
    from .evaluate import evaluate
    evaluate(Path(args.labels), threshold=args.threshold)


def cmd_serve(args) -> None:
    import uvicorn
    uvicorn.run("app.server:app", host=args.host, port=args.port, reload=False)


def cmd_reset(args) -> None:
    if settings.db_path.exists():
        settings.db_path.unlink()
        print(f"Banco apagado: {settings.db_path}")


def main(argv=None) -> None:
    p = argparse.ArgumentParser(prog="tackle", description="Triagem de phishing para caixas de e-mail inteiras")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("imap", help="Ler direto do servidor IMAP (somente leitura)")
    s.add_argument("--host", required=True)
    s.add_argument("--port", type=int, default=993)
    s.add_argument("--user", required=True)
    s.add_argument("--folder", action="append", help="Pasta (repita para várias). Use ALL para todas.")
    s.add_argument("--since", help="Só a partir de AAAA-MM-DD")
    s.add_argument("--limit", type=int, help="Só as N mais recentes por pasta")
    s.add_argument("--oauth-token", help="Token OAuth2 (ou nome da variável de ambiente que o contém)")
    s.add_argument("--no-analyze", action="store_true")
    s.add_argument("--no-enrich", action="store_true")
    s.add_argument("--force", action="store_true")
    s.add_argument("--top", type=int, default=10, help="Quantos e-mails mostrar no relatório de tempo (0 = todos)")
    s.set_defaults(func=cmd_imap)

    s = sub.add_parser("folder", help="Importar uma pasta de arquivos .eml")
    s.add_argument("path")
    s.add_argument("--no-analyze", action="store_true")
    s.add_argument("--no-enrich", action="store_true")
    s.add_argument("--force", action="store_true")
    s.add_argument("--top", type=int, default=10, help="Quantos e-mails mostrar no relatório de tempo (0 = todos)")
    s.set_defaults(func=cmd_folder)

    s = sub.add_parser("mbox", help="Importar .mbox, ZIP do Google Takeout ou Maildir")
    s.add_argument("paths", nargs="+")
    s.add_argument("--no-analyze", action="store_true")
    s.add_argument("--no-enrich", action="store_true")
    s.add_argument("--force", action="store_true")
    s.add_argument("--top", type=int, default=10, help="Quantos e-mails mostrar no relatório de tempo (0 = todos)")
    s.set_defaults(func=cmd_mbox)

    s = sub.add_parser("analyze", help="Recalcular score de tudo")
    s.add_argument("--no-enrich", action="store_true", help="Sem consultas externas")
    s.add_argument("--force", action="store_true", help="Refazer enriquecimento de quem já foi enriquecido")
    s.add_argument("--top", type=int, default=10, help="Quantos e-mails mostrar no relatório de tempo (0 = todos)")
    s.set_defaults(func=cmd_analyze)

    s = sub.add_parser("evaluate", help="Medir acerto contra uma amostra rotulada (CSV file,label)")
    s.add_argument("labels")
    s.add_argument("--threshold", type=int, default=30, help="Score a partir do qual conta como phishing")
    s.set_defaults(func=cmd_evaluate)

    s = sub.add_parser("serve", help="Abrir o painel web")
    s.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    s.add_argument("--port", type=int, default=int(os.getenv("PORT", 8080)))
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("reset", help="Apagar o banco e começar de novo")
    s.set_defaults(func=cmd_reset)

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
