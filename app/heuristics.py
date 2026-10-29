"""Heurísticas locais (sem internet): autenticação, remetente, links, anexos, conteúdo e injeção."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass, field

from . import urls as U
from .attachments import analyze_attachments, qr_from_html
from .parser import ParsedEmail

SEVERITY_BY_POINTS = ((40, "crítico"), (25, "alto"), (12, "médio"), (1, "baixo"), (-1000, "mitigação"))


@dataclass
class Finding:
    code: str
    category: str      # autenticacao | remetente | links | anexos | conteudo | injecao | caixa | reputacao | ia
    title: str
    points: int
    detail: str = ""
    critical: bool = False
    severity: str = ""

    def __post_init__(self):
        if not self.severity:
            for limit, name in SEVERITY_BY_POINTS:
                if self.points >= limit:
                    self.severity = name
                    break

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class LinkReport:
    url: str
    final_url: str
    text: str
    source: str
    host: str
    registered: str
    flags: list[str] = field(default_factory=list)
    points: int = 0
    enrichment: dict = field(default_factory=dict)


@dataclass
class LocalAnalysis:
    findings: list[Finding]
    links: list[LinkReport]
    attachments: list[dict]
    qr_codes: list[dict]
    auth: dict
    is_bulk: bool


# --------------------------------------------------------------------------- autenticação

AUTH_RE = {
    "spf": re.compile(r"\bspf=(\w+)", re.I),
    "dkim": re.compile(r"\bdkim=(\w+)", re.I),
    "dmarc": re.compile(r"\bdmarc=(\w+)", re.I),
}


def parse_auth(email: ParsedEmail) -> dict:
    res = {"spf": "ausente", "dkim": "ausente", "dmarc": "ausente", "raw": ""}
    candidates = email.headers_all("authentication-results") or email.headers_all("arc-authentication-results")
    if not candidates:
        spf = email.header("received-spf")
        if spf:
            res["spf"] = spf.split()[0].lower()
        return res
    raw = candidates[0]  # o mais alto foi adicionado pelo seu servidor
    res["raw"] = raw[:500]
    for k, rx in AUTH_RE.items():
        m = rx.search(raw)
        if m:
            res[k] = m.group(1).lower()
    return res


def check_auth(auth: dict) -> list[Finding]:
    out: list[Finding] = []
    spf, dkim, dmarc = auth["spf"], auth["dkim"], auth["dmarc"]
    if dmarc == "fail":
        out.append(Finding("dmarc_fail", "autenticacao", "DMARC falhou: remetente provavelmente falsificado", 35,
                           "O domínio do From não autorizou este envio"))
    elif spf in ("fail", "softfail") and dkim in ("fail", "none", "ausente", "neutral"):
        out.append(Finding("spf_dkim_fail", "autenticacao", "SPF e DKIM sem aprovação", 25,
                           f"spf={spf}, dkim={dkim}"))
    elif spf in ("fail",):
        out.append(Finding("spf_fail", "autenticacao", "SPF falhou", 10, f"spf={spf}"))
    elif dkim == "fail":
        out.append(Finding("dkim_fail", "autenticacao", "Assinatura DKIM inválida", 10, "Conteúdo pode ter sido alterado"))
    if spf == "ausente" and dkim == "ausente" and dmarc == "ausente":
        out.append(Finding("auth_ausente", "autenticacao", "Sem resultado de autenticação nos cabeçalhos", 3,
                           "Pode ser e-mail interno ou exportação sem cabeçalhos completos"))
    return out


# --------------------------------------------------------------------------- remetente

LOGIN_STRICT = re.compile(r"login|log-in|signin|sign-in|senha|password|passwd|webmail|verif(y|ica)|autentica", re.I)
FAKE_THREAD_RE =re.compile(r"^\s*(re|res|fw|fwd|enc|tr|aw|wg|rv)\s*(\(\d+\))?\s*:", re.I)
INVISIBLE_RE = re.compile("[­͏​-‏⁠-⁤﻿︀-︎\U000e0000-\U000e007f\U000e0100-\U000e01ef]")
LATIN = re.compile(r"[A-Za-z]")
CONFUSABLE_SCRIPT = re.compile(r"[Ͱ-ϿЀ-ӿ]")  # grego e cirílico
RANDOM_TOKEN = re.compile(r"(?=(?:[A-Za-z0-9]*\d){2})(?=(?:[A-Za-z0-9]*[A-Z]){3})(?=[A-Za-z0-9]*[a-z])[A-Za-z0-9]{9,}")


def clean_name(s: str) -> str:
    return INVISIBLE_RE.sub("", s or "")


# Letras cirílicas/gregas que se parecem com latinas (as usadas em golpe). Texto com codificação quebrada
# (ex.: 'пїЅ') usa outras letras e não deve contar.
LOOKALIKE_CHARS = set("аеорсухіјѕԁɡһӏԛԝаАВЕКМНОРСТХІЈЅοΑΒΕΗΙΚΜΝΟΡΤΥΧνκ")


def mixed_script_words(text: str) -> list[str]:
    out = []
    for w in re.findall(r"\w+", text or ""):
        foreign = [ch for ch in w if CONFUSABLE_SCRIPT.match(ch)]
        if foreign and LATIN.search(w) and all(ch in LOOKALIKE_CHARS for ch in foreign) and len(foreign) * 2 <= len(w):
            out.append(w)
    return out


def check_obfuscation(e: ParsedEmail) -> list[Finding]:
    """Truques para burlar filtro: caracteres invisíveis, letras cirílicas no meio de palavras, códigos aleatórios."""
    out: list[Finding] = []
    head = f"{e.from_name} {e.subject}"
    inv = len(INVISIBLE_RE.findall(head))
    if inv >= 2:
        out.append(Finding("invisiveis", "conteudo", "Caracteres invisíveis no nome/assunto para burlar filtros", 30,
                           f"{inv} caracteres ocultos em “{clean_name(head)[:70]}”", critical=True))
    mixed = mixed_script_words(f"{head} {(e.text or '')[:4000]}")
    if len(mixed) >= 2 or (mixed and any(w in head for w in mixed)):
        out.append(Finding("homoglifos", "conteudo", "Letras de outro alfabeto disfarçadas (ex.: cirílico no lugar de latim)", 30,
                           f"palavras: {', '.join(sorted(set(mixed))[:5])}", critical=True))
    tokens = [m.group(0) for m in RANDOM_TOKEN.finditer(clean_name(head))]
    tokens = [t for t in tokens if not re.fullmatch(r"[A-Z]{2}\d{9}[A-Z]{2}", t)]  # código de rastreio dos Correios
    if tokens:
        out.append(Finding("token_aleatorio", "conteudo", "Código aleatório no nome/assunto (técnica anti-filtro)", 10,
                           ", ".join(tokens[:3])))
    return out


def check_sender(e: ParsedEmail, auth: dict, allow: set[str]) -> list[Finding]:
    out: list[Finding] = []
    fd = e.from_domain
    freg = U.registered_domain(fd) if fd else ""
    name = clean_name(e.from_name or "").strip()
    name_l = name.lower()

    if not e.from_addr or "@" not in e.from_addr:
        out.append(Finding("sem_remetente", "remetente", "Remetente ausente ou inválido", 20, f"From: '{e.header('from')[:80]}'"))
    elif "." not in fd or freg == fd and "." not in freg:
        out.append(Finding("dominio_invalido", "remetente", "Domínio do remetente não existe (sem TLD)", 25, e.from_addr))
    elif U.domain_matches(fd, U.ABUSED_HOSTING) or fd.endswith(".onmicrosoft.com"):
        out.append(Finding("remetente_plataforma", "remetente", "Remetente em domínio gratuito de plataforma (firebase, onmicrosoft…)", 18, fd))
    if re.search(r"\d{8,}", e.from_addr.split("@")[0] if e.from_addr else ""):
        out.append(Finding("remetente_numerico", "remetente", "Endereço do remetente com sequência numérica aleatória", 6, e.from_addr))
    if freg in U.FREEMAIL and U.AUTHORITY_WORDS.search(name):
        out.append(Finding("autoridade_freemail", "remetente", "Nome de órgão/empresa enviando de e-mail gratuito", 20,
                           f"'{name}' <{e.from_addr}>"))

    # Nome de exibição com e-mail diferente do real
    m = U.EMAIL_IN_TEXT.search(name)
    if m and U.registered_domain(m.group(0).lower().rsplit("@", 1)[-1]) != freg:
        out.append(Finding("nome_com_email", "remetente", "Nome de exibição mostra outro endereço", 15,
                           f"Mostra '{m.group(0)}' mas o envio é de '{e.from_addr}'"))

    # Nome de exibição (ou assunto) usa marca, domínio não é da marca
    name_flat = re.sub(r"[^a-z0-9+ ]", "", unicodedata.normalize("NFKD", name_l).encode("ascii", "ignore").decode())
    subj_l = clean_name(e.subject or "").lower()
    brand_hit = False
    for brand, doms in U.BRANDS.items():
        b_flat = re.sub(r"[^a-z0-9+ ]", "", unicodedata.normalize("NFKD", brand).encode("ascii", "ignore").decode())
        rx = rf"(?<![a-z]){re.escape(b_flat)}(?![a-z])"
        if (re.search(rx, name_flat) or re.search(rx, name_flat.replace(" ", ""))) and not U.domain_matches(fd, doms):
            if freg in allow:
                break
            pts = 30 if freg in U.FREEMAIL else 22
            out.append(Finding("marca_no_nome", "remetente", f"Se apresenta como '{brand.title()}' sem ser da marca", pts,
                               f"'{name}' <{e.from_addr}>"))
            brand_hit = True
            break
    if not brand_hit and freg not in allow:
        for brand, doms in U.BRANDS.items():
            if len(brand) >= 4 and re.search(rf"(?<![a-zà-ú]){re.escape(brand)}(?![a-zà-ú])", subj_l) \
                    and not U.domain_matches(fd, doms):
                out.append(Finding("marca_no_assunto", "remetente", f"Assunto cita '{brand.title()}', remetente não é da marca", 8,
                                   f"{e.from_addr}"))
                break

    look = U.lookalike_brand(fd)
    if look:
        out.append(Finding("remetente_sosia", "remetente", "Domínio do remetente imita uma marca", 35, look[1], critical=True))
    if fd.startswith("xn--") or ".xn--" in fd:
        out.append(Finding("remetente_punycode", "remetente", "Domínio do remetente com caracteres internacionais (punycode)", 20, fd))

    is_list = bool(e.header("list-id") or e.header("list-post") or e.header("mailing-list"))
    # Reply-To diferente (listas de discussão fazem isso normalmente)
    for rt in e.reply_to:
        rtd = rt.rsplit("@", 1)[-1]
        rreg = U.registered_domain(rtd)
        if rreg and rreg != freg:
            if rreg in U.FREEMAIL and freg not in U.FREEMAIL:
                out.append(Finding("replyto_freemail", "remetente", "Respostas vão para e-mail gratuito", 25,
                                   f"From: {e.from_addr} → Reply-To: {rt}"))
            elif not is_list:
                out.append(Finding("replyto_diferente", "remetente", "Respostas vão para outro domínio", 8,
                                   f"From: {e.from_addr} → Reply-To: {rt}"))
            break

    # Remetente = destinatário (comum em extorsão/spam)
    if e.from_addr and e.from_addr in e.to and len(e.to) == 1:
        out.append(Finding("de_para_igual", "remetente", "Remetente igual ao destinatário", 4, e.from_addr))

    # "RE:" sem histórico de conversa
    if FAKE_THREAD_RE.match(e.subject or "") and not e.header("in-reply-to") and not e.header("references") and not is_list:
        out.append(Finding("falsa_resposta", "remetente", "Assunto finge ser resposta, mas não há conversa anterior", 10,
                           e.subject[:120]))

    mailer = (e.header("x-mailer") + " " + e.header("user-agent")).lower()
    if any(x in mailer for x in ("phpmailer", "swiftmailer", "king-mailer", "gammadyne", "sendblaster", "atomic mail")):
        out.append(Finding("mailer_suspeito", "remetente", "Enviado por ferramenta de disparo em massa genérica", 6, mailer.strip()[:80]))
    return out


# --------------------------------------------------------------------------- links

def check_links(e: ParsedEmail, extra: list[tuple[str, str]], allow: set[str]) -> tuple[list[Finding], list[LinkReport]]:
    reports: list[LinkReport] = []
    seen: set[str] = set()
    from_reg = U.registered_domain(e.from_domain) if e.from_domain else ""
    sender_regs = {from_reg, U.registered_domain(e.return_path.rsplit("@", 1)[-1]) if e.return_path else ""}
    m = U.EMAIL_IN_TEXT.search(e.from_name or "")
    if m:
        sender_regs.add(U.registered_domain(m.group(0).rsplit("@", 1)[-1]))
    sender_regs.discard("")
    recipients = e.to + e.cc

    items = [(l.url, l.text, l.source) for l in e.links] + [(u, "", src) for u, src in extra]
    for raw, text, source in items:
        if raw in seen or raw.startswith(("mailto:", "tel:", "cid:", "#", "sms:")):
            continue
        seen.add(raw)
        low = raw.lower().strip()
        if low.startswith(("javascript:", "data:", "vbscript:", "file:")):
            reports.append(LinkReport(raw[:200], raw[:200], text, source, "", "", ["esquema perigoso (javascript/data/file)"], 15))
            continue
        info = U.parse_url(raw)
        if not info or not info.host:
            continue
        r = LinkReport(raw, info.url, text[:200], source, info.host, info.registered)
        add = lambda flag, pts: (r.flags.append(flag), setattr(r, "points", r.points + pts))

        allowed = info.registered in allow or U.domain_matches(info.host, allow)
        esp = U.domain_matches(info.host, U.ESP_TRACKING)

        if info.unwrapped_from:
            r.flags.append(f"desembrulhado de {info.unwrapped_from}")
        if info.is_ip:
            add("link aponta para IP em vez de domínio", 25)
        if "@" in (urlsplit_netloc(info.url)):
            add("usuário@ no endereço (esconde o domínio real)", 25)
        if "xn--" in info.host:
            add("domínio com punycode (caracteres internacionais)", 18)
        look = U.lookalike_brand(info.host)
        if look and not allowed:
            add(f"imita marca: {look[1]}", 30)
        if info.suffix.split(".")[-1] in U.SUSPICIOUS_TLDS and not allowed:
            add(f"TLD muito usado em golpes (.{info.suffix})", 10)
        if U.domain_matches(info.host, U.SHORTENERS):
            add("encurtador de link (esconde o destino)", 8)
        if (U.domain_matches(info.host, U.ABUSED_HOSTING) or "/ipfs/" in info.path) and not allowed:
            add("hospedagem gratuita muito usada para páginas falsas", 12)
        if info.port and info.port not in (80, 443):
            add(f"porta incomum ({info.port})", 10)
        risky_host = info.is_ip or bool(look) or U.domain_matches(info.host, U.ABUSED_HOSTING) \
            or info.suffix.split(".")[-1] in U.SUSPICIOUS_TLDS
        if info.scheme == "http" and LOGIN_STRICT.search(info.path + info.host) and not allowed:
            add("página de login sem HTTPS", 8)
        # Palavras de login só pesam quando o host já é arriscado (sozinhas disparam muito em e-mail legítimo)
        if risky_host and U.LOGIN_WORDS.search(info.host + info.path) and not allowed:
            add("palavras de login/verificação em endereço arriscado", 6)
        if info.subdomain.count(".") >= 3 or len(info.host) > 60:
            add("domínio muito longo/com muitos subdomínios", 6)
        where = U.recipient_in_url(info, recipients)
        if where == "fragment":
            add("seu e-mail está embutido no link após '#' (kit de phishing personalizado)", 25)
        elif where == "query":
            r.flags.append("seu e-mail está no link (comum em marketing)")

        # Texto do link mostra um domínio, destino é outro
        tm = U.DOMAINISH.match(text.strip()) if text else None
        if tm and source == "html":
            shown = U.registered_domain(tm.group(1))
            if shown and info.registered and shown != info.registered and "." in shown:
                own = info.registered in sender_regs or info.registered.split(".")[0] in (e.from_name or "").lower()
                if esp or allowed or own:
                    r.flags.append(f"texto mostra {shown}, passa por redirecionador do próprio remetente/marketing")
                else:
                    add(f"texto mostra '{shown}' mas leva para '{info.registered}'", 30)
        if source == "qr":
            add("link escondido em QR code", 12)
        if source == "form":
            if info.registered in sender_regs:
                r.flags.append("formulário no corpo do e-mail")
            else:
                add("formulário no corpo do e-mail envia dados para outro domínio", 6)
        if allowed and r.points:
            r.points = r.points // 3
        reports.append(r)

    findings: list[Finding] = []
    risky = sorted([r for r in reports if r.points >= 10], key=lambda r: -r.points)
    if risky:
        top = risky[0]
        total = min(45, top.points + sum(r.points for r in risky[1:4]) // 3)
        detail = "; ".join(f"{r.registered or r.url[:40]}: {', '.join(f for f in r.flags if not f.startswith('desembrulhado'))}" for r in risky[:3])
        findings.append(Finding("links_suspeitos", "links", "1 link suspeito" if len(risky) == 1 else f"{len(risky)} links suspeitos", total, detail,
                                critical=any("imita marca" in f or "embutido no link após" in f for f in top.flags)))
    elif any(r.points for r in reports):
        findings.append(Finding("links_atencao", "links", "Links com detalhes de atenção", 4,
                                "; ".join(f"{r.registered}: {', '.join(r.flags)}" for r in reports if r.points)[:300]))
    return findings, reports


def urlsplit_netloc(url: str) -> str:
    try:
        from urllib.parse import urlsplit
        return urlsplit(url).netloc
    except ValueError:
        return ""


# --------------------------------------------------------------------------- conteúdo

CONTENT_RULES: list[tuple[str, str, int, re.Pattern]] = [
    ("urgencia", "Pressão de tempo ou ameaça", 6, re.compile(
        r"urgente|imediatamente|em at[eé] \d+ ?(h|horas|dias)|nas pr[oó]ximas \d+|[uú]ltimo aviso|a[cç][aã]o necess[aá]ria|"
        r"ser[aá] (bloquead|suspens|encerrad|desativad|cancelad|exclu[ií]d)|evite o (bloqueio|cancelamento)|"
        r"prazo final|expira (hoje|em)|immediately|within \d+ hours|final notice|action required|will be (suspended|closed|locked|deleted)",
        re.I)),
    ("credenciais", "Pede para confirmar dados, senha ou login", 10, re.compile(
        r"confirm(e|ar) (seus|os) dados|atualiz(e|ar) (seus|os|o seu) (dados|cadastro)|verifi(que|car) (sua|a) conta|"
        r"recadastr|valid(e|ar|a) (sua|o seu|seu|o) (acesso|conta|cadastro|login|e-?mail)|informe (sua|a) senha|redefin(a|ir) (sua )?senha|"
        r"senha (expir|vence)|caixa( de (entrada|e-?mail|correio))? (est[aá] )?(cheia|lotada)|cota de (e-?mail|armazenamento)|"
        r"verify your (account|identity)|confirm your (account|password|identity)|password (expir|will expire)|"
        r"mailbox (is )?full|re-?activate your account|unusual sign-?in", re.I)),
    ("pagamento", "Fala de pagamento, Pix, boleto ou dados bancários", 6, re.compile(
        r"\bpix\b|boleto|transfer[eê]ncia|dados banc[aá]rios|nova conta (banc[aá]ria|para dep[oó]sito)|"
        r"alter(a[cç][aã]o|amos|ar) (de |a |nossa )?(conta|dados banc)|pagamento pendente|fatura (em aberto|vencida|em atraso)|"
        r"comprovante|gift ?card|cart[aã]o[- ]presente|wire transfer|bank (details|account)|invoice (attached|overdue)|remittance",
        re.I)),
    ("giftcard", "Pede compra de gift card / cartão-presente", 14, re.compile(
        r"(compr(e|ar|a)|adquir(a|ir)|buy|purchase)[\s\S]{0,60}(gift ?cards?|cart(ão|ões|ao|oes)[- ]presente|vale[- ]presente|"
        r"google play|itunes|steam)", re.I)),
    ("bec", "Tom de pedido pessoal/sigiloso de chefe (golpe do CEO)", 10, re.compile(
        r"(voc[eê]|vc) (est[aá]|t[aá]) dispon[ií]vel|est[aá]s? dispon[ií]vel ?\?|preciso de um favor|estou em (uma )?reuni[aã]o|n[aã]o comente com ningu[eé]m|"
        r"mantenha (isso )?em sigilo|assunto confidencial|me (passa|envie?) seu (whats|celular|n[uú]mero)|"
        r"are you available|quick favou?r|i'?m in a meeting|keep (this )?confidential", re.I)),
    ("premio", "Promete prêmio, reembolso ou restituição", 6, re.compile(
        r"voc[eê] (foi sorteado|ganhou)|restitui[cç][aã]o|reembolso dispon[ií]vel|valores a receber|resgat(e|ar) (seu|o) (pr[eê]mio|saldo|b[oô]nus)|"
        r"you('ve| have) won|claim your (prize|reward|refund)", re.I)),
    ("cassino", "Cassino, apostas ou prêmio fácil", 8, re.compile(
        r"cassino|casino|free ?spins|freispiel|rodadas gr[aá]tis|giros gr[aá]tis|jackpot|b[oô]nus de (boas[- ]vindas|\d)|"
        r"welcome bonus|gewonnen|gewinnspiel|geschenkkarte|cadeaukaart|prijs gewonnen|vous avez gagn|has ganado|hai vinto",
        re.I)),
    ("cripto", "Carteira cripto: verificação, saque ou frase de recuperação", 12, re.compile(
        r"seed phrase|recovery phrase|secret phrase|frase (de recupera[cç][aã]o|semente|secreta)|"
        r"(wallet|carteira)[\s\S]{0,80}(verif|suspen|sync|sincroniz|bloque|validat|disconnect)|"
        r"(verif|validat|sync)[\s\S]{0,40}(wallet|carteira)|\bkyc\b|withdraw(al)? (process|is|request)|"
        r"pending (transaction|withdrawal)", re.I)),
    ("multas", "Multa, CNH, imposto ou processo com prazo", 8, re.compile(
        r"multa de tr[aâ]nsito|suspens[aã]o da cnh|cnh (suspensa|bloqueada|em risco)|pend[eê]ncias? (no|na|do|da) (cpf|cnh|receita)|"
        r"cpf (irregular|cancelado|bloqueado|suspenso)|d[ií]vida ativa|intima[cç][aã]o|processo judicial|mandado|"
        r"irs (notice|refund)|tax refund|steuer(erstattung|r[uü]ckerstattung)", re.I)),
    ("extorsao", "Padrão de extorsão (bitcoin, vídeos íntimos)", 20, re.compile(
        r"(bitcoin|btc|carteira cripto)[\s\S]{0,300}(v[ií]deo|c[aâ]mera|webcam|contatos)|"
        r"(v[ií]deo|webcam|c[aâ]mera)[\s\S]{0,300}(bitcoin|btc)|hackeei (seu|sua)|i hacked your", re.I)),
]

INJECTION_RE = re.compile(
    r"ignore (all |any )?(the )?(previous|prior|above|earlier) (instructions|prompts?|rules)|disregard (the )?(previous|above)|"
    r"ignor(e|ar) (as |todas as )?instru[cç][oõ]es|desconsidere (as )?instru[cç]|"
    r"(this|the) (e-?mail|message) is (safe|legitimate|verified|not (a )?phishing|benign)|"
    r"(este|esse) (e-?mail|mensagem) (é|e) (seguro|leg[ií]tim|verificad)|n[aã]o (é|e) phishing|"
    r"classif(y|ique|icar)( (this|it|isto|isso|este e-?mail))? (as|como) (safe|legitimate|benign|seguro|leg[ií]timo)|"
    r"(you are|voc[eê] [eé]) (an? )?(ai|ia|assistente|language model|llm|security (scanner|filter))|"
    r"system prompt|pre-?approved by (it|security)|pr[eé]-?aprovado pel[ao] (ti|seguran)|"
    r"security (team|scan) (has )?(verified|approved)|\bas an ai\b|assistant:|<\|im_start\|>",
    re.I,
)


def check_content(e: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    text = f"{e.subject}\n{e.text}"[:60000]
    hits = []
    for code, title, pts, rx in CONTENT_RULES:
        m = rx.search(text)
        if m:
            hits.append((code, title, pts, m.group(0)))
    for code, title, pts, ev in hits:
        out.append(Finding(f"conteudo_{code}", "conteudo", title, pts, f"trecho: “{ev.strip()[:80]}”"))
    codes = {h[0] for h in hits}
    if {"urgencia", "credenciais"} <= codes:
        out.append(Finding("combo_urgencia_credencial", "conteudo", "Combina urgência com pedido de credenciais", 8, "Padrão clássico de phishing"))
    if e.body_has_password_form:
        out.append(Finding("form_senha_corpo", "conteudo", "Campo de senha dentro do próprio e-mail", 35, "E-mails legítimos não pedem senha no corpo", critical=True))
    return out


def check_injection(e: ParsedEmail) -> list[Finding]:
    out: list[Finding] = []
    hidden = e.hidden_text or ""
    mh = INJECTION_RE.search(hidden)
    if mh:
        out.append(Finding("injecao_escondida", "injecao", "Texto escondido tentando enganar filtros/IA", 45,
                           f"trecho oculto: “{mh.group(0)[:80]}”", critical=True))
    mv = INJECTION_RE.search(f"{e.subject}\n{e.text}")
    if mv:
        out.append(Finding("injecao_visivel", "injecao", "Texto dirigido a filtros/IA dizendo que o e-mail é seguro", 25,
                           f"trecho: “{mv.group(0)[:80]}”"))
    if not mh and len(hidden) > 400:
        out.append(Finding("texto_escondido", "injecao", "Muito texto escondido no HTML", 18 if len(hidden) > 1500 else 10,
                           f"{len(hidden)} caracteres invisíveis (pode ser tentativa de driblar filtros)"))
    return out


# --------------------------------------------------------------------------- orquestração local

def is_bulk_mail(e: ParsedEmail) -> bool:
    return bool(e.header("list-unsubscribe") or e.header("list-id") or "bulk" in e.header("precedence").lower())


def analyze_local(e: ParsedEmail, allow: set[str]) -> LocalAnalysis:
    auth = parse_auth(e)
    att = analyze_attachments(e.attachments)
    qr_codes = list(att.qr_codes)
    extra = list(att.extra_links)
    for val in qr_from_html(e.html):
        qr_codes.append({"source": "imagem no corpo", "value": val})
        if re.match(r"(?i)https?://|www\.", val):
            extra.append((val, "qr"))

    findings: list[Finding] = []
    findings += check_auth(auth)
    findings += check_sender(e, auth, allow)
    lf, link_reports = check_links(e, extra, allow)
    findings += lf
    for af in att.findings:
        findings.append(Finding(af.code, "anexos", af.title, af.points, af.detail, critical=af.critical))
    if qr_codes:
        findings.append(Finding("qr_code", "links", "QR code com link (quishing)", 12 if extra else 5,
                                "; ".join(q["value"][:80] for q in qr_codes[:3])))
    findings += check_content(e)
    findings += check_obfuscation(e)
    findings += check_injection(e)

    bulk = is_bulk_mail(e)
    freg = U.registered_domain(e.from_domain) if e.from_domain else ""
    authed = auth["dmarc"] == "pass" or (auth["dkim"] == "pass" and auth["spf"] == "pass")
    if freg and freg in allow and authed:
        findings.append(Finding("allowlist", "remetente", "Remetente confiável (lista de permitidos) e autenticado", -30,
                                freg))
    elif authed and bulk:
        findings.append(Finding("marketing_autenticado", "remetente", "Envio em massa autenticado (newsletter/marketing)", -6,
                                "Tem List-Unsubscribe e passou na autenticação"))
    return LocalAnalysis(findings, link_reports, att.summary, qr_codes, auth, bulk)
