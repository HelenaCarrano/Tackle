"""Medição de tempo por e-mail e consumo de tokens da IA numa execução, com relatório para o terminal.

Só guarda números (sha256 do e-mail, segundos, contagem de tokens) em memória: nada aqui sai da máquina.
"""
from __future__ import annotations

import time
from collections import defaultdict
from contextlib import contextmanager

STAGES = ("importar", "caixa", "externo", "jev", "llm")
STAGE_LABELS = {"importar": "importar", "caixa": "caixa", "externo": "externo", "jev": "Jev", "llm": "LLM"}


class RunMetrics:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.started = time.perf_counter()
        self.subjects: dict[str, str] = {}
        self.timings: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
        self.llm_calls: list[dict] = []
        self.llm_cached = 0

    @contextmanager
    def stage(self, sha: str, name: str, subject: str = ""):
        t0 = time.perf_counter()
        try:
            yield
        finally:
            self.timings[sha][name] += time.perf_counter() - t0
            if subject:
                self.subjects[sha] = subject

    def add_llm(self, sha: str, provider: str, model: str, usage: dict | None) -> None:
        usage = usage or {}
        self.llm_calls.append({"sha": sha, "provider": provider, "model": model,
                               "prompt": usage.get("prompt_tokens") or 0, "completion": usage.get("completion_tokens") or 0,
                               "cost": usage.get("cost")})

    def add_llm_cached(self) -> None:
        self.llm_cached += 1

    # ------------------------------------------------------------------ relatório

    def _tokens_by_sha(self) -> dict[str, tuple[int, int]]:
        out: dict[str, list[int]] = defaultdict(lambda: [0, 0])
        for c in self.llm_calls:
            out[c["sha"]][0] += c["prompt"]
            out[c["sha"]][1] += c["completion"]
        return {k: (v[0], v[1]) for k, v in out.items()}

    def report(self, top: int = 10, log=print) -> None:
        if not self.timings:
            return
        wall = time.perf_counter() - self.started
        tokens = self._tokens_by_sha()
        rows = []
        for sha, st in self.timings.items():
            rows.append((sum(st.values()), sha, st))
        rows.sort(key=lambda r: -r[0])
        shown = rows if top <= 0 else rows[:top]

        log("\n" + "=" * 100)
        log(f"RELATÓRIO DE TEMPO  ({len(rows)} e-mails medidos"
            f"{'' if len(shown) == len(rows) else f', mostrando os {len(shown)} mais lentos'})")
        log("=" * 100)
        head = f"{'e-mail':<34}" + "".join(f"{STAGE_LABELS[s]:>10}" for s in STAGES) + f"{'total':>10}{'tok. in':>9}{'tok. out':>9}"
        log(head)
        log("-" * len(head))
        for total, sha, st in shown:
            subj = (self.subjects.get(sha) or sha[:12]).replace("\n", " ")
            subj = subj if len(subj) <= 32 else subj[:31] + "…"
            tin, tout = tokens.get(sha, (0, 0))
            log(f"{subj:<34}" + "".join(f"{_fmt(st.get(s)):>10}" for s in STAGES) + f"{_fmt(total):>10}{tin or '-':>9}{tout or '-':>9}")

        totals = defaultdict(float)
        for _, _, st in rows:
            for k, v in st.items():
                totals[k] += v
        busy = sum(totals.values())
        log("-" * len(head))
        log(f"{'SOMA POR ETAPA':<34}" + "".join(f"{_fmt(totals.get(s)):>10}" for s in STAGES) + f"{_fmt(busy):>10}")
        log(f"\nTempo total de relógio: {_fmt(wall)}   |   média por e-mail: {_fmt(busy / len(rows))}   |   "
            f"mais lento: {_fmt(rows[0][0])}")
        log("(\"externo\" inclui a espera pelo limite de consultas do VirusTotal.)")

        log("\nTOKENS (LLM)")
        if not self.llm_calls:
            log(f"  Nenhuma chamada ao LLM nesta execução" + (f" ({self.llm_cached} respostas vieram do cache, sem custo)." if self.llm_cached else "."))
        else:
            p = sum(c["prompt"] for c in self.llm_calls)
            o = sum(c["completion"] for c in self.llm_calls)
            costs = [c["cost"] for c in self.llm_calls if c["cost"] is not None]
            models = ", ".join(sorted({f"{c['provider']}/{c['model']}" for c in self.llm_calls}))
            log(f"  Modelo: {models}")
            log(f"  Chamadas: {len(self.llm_calls)} novas, {self.llm_cached} do cache (não gastam tokens)")
            log(f"  Entrada: {p}   Saída: {o}   Total: {p + o}")
            if costs:
                log(f"  Custo reportado pelo provedor: US$ {sum(costs):.5f}")
            if len(self.llm_calls):
                log(f"  Média por chamada: {p // len(self.llm_calls)} entrada / {o // len(self.llm_calls)} saída")
        log("  Jev (TypeSafe) e as consultas de VirusTotal/RDAP não informam tokens, por isso ficam fora desta conta.")
        log("=" * 100)


def _fmt(seconds: float | None) -> str:
    if not seconds:
        return "-"
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    return f"{seconds:.2f}s"


metrics = RunMetrics()
