"""Score combinado (0–100) a partir de todos os achados, com explicação."""
from __future__ import annotations

LEVELS = ((80, "crítico"), (55, "alto"), (30, "médio"), (12, "baixo"), (0, "limpo"))


def level_for(score: int) -> str:
    for limit, name in LEVELS:
        if score >= limit:
            return name
    return "limpo"


def compute(findings: list[dict]) -> tuple[int, str]:
    """Soma pontos positivos com retorno decrescente por categoria; mitigações subtraem.

    - Achados críticos (ex.: executável, sósia de marca, injeção escondida) garantem score mínimo de 70,
      e mitigações não conseguem baixar abaixo disso.
    - Sinais de IA (Jev/Claude) só somam; nunca reduzem o score.
    """
    by_cat: dict[str, list[int]] = {}
    negatives = 0
    critical = False
    for f in findings:
        p = int(f.get("points", 0))
        if p < 0:
            negatives += p
            continue
        by_cat.setdefault(f.get("category", "outros"), []).append(p)
        critical = critical or bool(f.get("critical"))

    positive = 0.0
    for pts in by_cat.values():
        pts.sort(reverse=True)
        # 1º achado vale inteiro, 2º vale 70%, demais 40% (evita inflar por repetição na mesma categoria)
        positive += sum(p * (1.0 if i == 0 else 0.7 if i == 1 else 0.4) for i, p in enumerate(pts))

    # Corroboração: sinais vindos de 3+ categorias diferentes reforçam
    strong_cats = sum(1 for pts in by_cat.values() if pts and pts[0] >= 10)
    if strong_cats >= 3:
        positive *= 1.15

    score = positive + negatives
    if critical:
        score = max(score, 70)
    score = int(round(max(0, min(100, score))))
    return score, level_for(score)
