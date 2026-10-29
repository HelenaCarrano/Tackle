"""Mede o acerto do sistema contra e-mails rotulados (CSV ou rótulos marcados no painel)."""
from __future__ import annotations

import csv
import hashlib
from pathlib import Path

from . import db


def _metrics(pairs: list[tuple[int, bool]], threshold: int) -> dict:
    tp = sum(1 for s, y in pairs if y and s >= threshold)
    fn = sum(1 for s, y in pairs if y and s < threshold)
    fp = sum(1 for s, y in pairs if not y and s >= threshold)
    tn = sum(1 for s, y in pairs if not y and s < threshold)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / len(pairs) if pairs else 0.0
    return {"threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precisao": prec, "recall": rec, "f1": f1, "acuracia": acc}


def collect(labels: Path | None) -> list[dict]:
    with db.session() as con:
        if labels is None or str(labels) == "db":
            rows = con.execute("SELECT subject, score, label FROM emails WHERE label IN ('phishing','legitimo')").fetchall()
            return [{"name": r["subject"], "score": r["score"], "phish": r["label"] == "phishing"} for r in rows]
        out = []
        base = labels.parent
        with open(labels, encoding="utf-8") as f:
            for row in csv.DictReader(f):
                p = base / row["file"]
                if not p.exists():
                    continue
                sha = hashlib.sha256(p.read_bytes()).hexdigest()
                r = con.execute("SELECT subject, score FROM emails WHERE sha256=?", (sha,)).fetchone()
                if r is None:
                    print(f"  ! {row['file']} não foi importado ainda")
                    continue
                out.append({"name": f"{row['file']} — {r['subject']}", "score": r["score"],
                            "phish": row["label"].strip().lower() in ("phishing", "phish", "malicioso", "1", "sim")})
        return out


def evaluate(labels: Path | None, threshold: int = 30) -> dict:
    items = collect(labels)
    if not items:
        print("Nenhum e-mail rotulado encontrado.")
        return {}
    pairs = [(i["score"], i["phish"]) for i in items]
    m = _metrics(pairs, threshold)
    n_ph = sum(1 for _, y in pairs if y)
    print(f"\nAmostra: {len(items)} e-mails ({n_ph} phishing, {len(items) - n_ph} legítimos) — corte em score ≥ {threshold}\n")
    print(f"  Recall (phishing pego):        {m['recall']:.0%}  ({m['tp']}/{m['tp'] + m['fn']})")
    print(f"  Precisão (alertas corretos):   {m['precisao']:.0%}  ({m['tp']}/{m['tp'] + m['fp']})")
    print(f"  F1:                            {m['f1']:.2f}")
    print(f"  Acurácia geral:                {m['acuracia']:.0%}")
    print("\n  Corte  Recall  Precisão  Falsos+  Perdidos")
    for t in (12, 20, 30, 40, 55, 70):
        x = _metrics(pairs, t)
        print(f"  {t:>5}  {x['recall']:>6.0%}  {x['precisao']:>8.0%}  {x['fp']:>7}  {x['fn']:>8}")
    misses = [i for i in items if i["phish"] and i["score"] < threshold]
    fps = [i for i in items if not i["phish"] and i["score"] >= threshold]
    if misses:
        print("\n  Phishing que passou:")
        for i in misses:
            print(f"    score {i['score']:>3}  {i['name'][:90]}")
    if fps:
        print("\n  Falsos positivos:")
        for i in fps:
            print(f"    score {i['score']:>3}  {i['name'][:90]}")
    return m
