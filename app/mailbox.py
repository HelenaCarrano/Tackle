"""Sinais que só aparecem olhando a caixa inteira: remetente novo, sósia de contato, nome conhecido
com endereço trocado e campanhas (mesmo link suspeito vindo de vários remetentes)."""
from __future__ import annotations

import re
import unicodedata
from collections import Counter, defaultdict

from . import urls as U
from .config import settings
from .heuristics import Finding


def _norm_name(name: str) -> str:
    n = unicodedata.normalize("NFKD", name or "").encode("ascii", "ignore").decode().lower()
    n = re.sub(r"[^a-z ]", " ", n)
    return " ".join(n.split())


class MailboxContext:
    def __init__(self, rows: list[dict], allow: set[str]):
        self.allow = allow
        self.domain_count: Counter = Counter()
        self.addr_count: Counter = Counter()
        self.name_addrs: dict[str, Counter] = defaultdict(Counter)
        self.risky_link_senders: dict[str, set[str]] = defaultdict(set)
        for r in rows:
            reg = U.registered_domain(r.get("from_domain") or "")
            self.domain_count[reg] += 1
            self.addr_count[r.get("from_addr") or ""] += 1
            nn = _norm_name(r.get("from_name") or "")
            if len(nn) >= 6 and " " in nn:
                self.name_addrs[nn][r.get("from_addr") or ""] += 1
            for l in r.get("links") or []:
                if l.get("points", 0) >= 10 and l.get("registered"):
                    self.risky_link_senders[l["registered"]].add(reg)
        self.known_domains = [d for d, c in self.domain_count.items()
                              if c >= 3 and d and d not in U.FREEMAIL]
        # Domínios da própria organização sempre contam como "conhecidos"
        for d in settings.org_domains:
            if d not in self.known_domains:
                self.known_domains.append(d)

    def findings_for(self, r: dict) -> tuple[list[Finding], str | None]:
        out: list[Finding] = []
        reg = U.registered_domain(r.get("from_domain") or "")
        addr = r.get("from_addr") or ""
        allowed = reg in self.allow
        count = self.domain_count.get(reg, 0)

        if reg in U.FREEMAIL:
            if self.addr_count.get(addr, 0) == 1:
                out.append(Finding("remetente_novo", "caixa", "Primeira vez que este endereço aparece na caixa", 5, addr))
        elif reg and count == 1 and not allowed:
            out.append(Finding("remetente_novo", "caixa", "Primeira vez que este domínio aparece na caixa", 5, reg))

        # Sósia de um domínio que escreve com frequência (fraude de fornecedor)
        if reg and count <= 2 and not allowed and reg not in U.FREEMAIL:
            label = reg.split(".")[0]
            for known in self.known_domains:
                if known == reg:
                    continue
                kl = known.split(".")[0]
                if len(kl) < 4:
                    continue
                same_skel = U.skeleton(label) == U.skeleton(kl)
                dist = U.levenshtein(label, kl)
                flat, kflat = label.replace("-", ""), kl.replace("-", "")
                contains = len(kflat) >= 5 and kflat in flat and flat != kflat
                tld_only = label == kl and reg != known
                if same_skel or (0 < dist <= (1 if len(kl) <= 6 else 2)) or tld_only or contains:
                    own = known in settings.org_domains
                    # Mesmo nome com outro final (.com x .com.br) é comum em empresas legítimas: pesa menos
                    pts, crit = (20, False) if tld_only and not own else (40, True)
                    out.append(Finding("sosia_contato", "caixa",
                                       "Domínio imita o da sua organização" if own else "Domínio quase igual ao de um contato frequente",
                                       pts, f"'{reg}' imita '{known}'" + ("" if own else
                                           f" ({self.domain_count[known]} e-mails legítimos na caixa)"),
                                       critical=crit))
                    break

        # Nome de um contato conhecido, endereço diferente
        nn = _norm_name(r.get("from_name") or "")
        if nn in self.name_addrs and self.addr_count.get(addr, 0) == 1:
            others = [(a, c) for a, c in self.name_addrs[nn].items() if a != addr and c >= 2]
            if others:
                best, c = max(others, key=lambda x: x[1])
                if U.registered_domain(best.split("@")[-1]) != reg:
                    pts = 30 if reg in U.FREEMAIL else 25
                    out.append(Finding("nome_contato_trocado", "caixa", "Nome de contato conhecido com endereço diferente", pts,
                                       f"'{r.get('from_name')}' normalmente escreve de {best} ({c}x); agora de {addr}"))

        # Campanha: mesmo link suspeito vindo de remetentes diferentes
        campaign = None
        for l in r.get("links") or []:
            d = l.get("registered")
            if d and l.get("points", 0) >= 10 and len(self.risky_link_senders.get(d, ())) >= 3:
                campaign = d
                out.append(Finding("campanha", "caixa", "Faz parte de uma campanha", 12,
                                   f"Link para '{d}' aparece em e-mails de {len(self.risky_link_senders[d])} remetentes diferentes"))
                break

        # Mitigação: remetente autenticado que já escreve com frequência
        auth = r.get("auth") or {}
        if count >= 5 and auth.get("dmarc") == "pass" and not out:
            out.append(Finding("contato_frequente", "caixa", "Contato frequente e autenticado", -8, f"{count} e-mails de {reg}"))
        return out, campaign
