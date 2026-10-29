"""Utilidades de URL e domínio: normalização, desembrulho de redirecionadores, sósias de marca."""
from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import parse_qs, unquote, urlsplit

import tldextract

# Usa a lista pública de sufixos embutida no pacote (não precisa de internet)
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Marca -> domínios oficiais. Usado para detectar nome de exibição falso e domínios sósias.
BRANDS: dict[str, list[str]] = {
    "paypal": ["paypal.com", "paypal.com.br"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com",
                  "microsoftonline.com", "sharepoint.com", "onmicrosoft.com", "azure.com", "msft.net",
                  "microsoftstore.com", "teams.microsoft.com"],
    "office 365": ["microsoft.com", "office.com", "office365.com", "microsoftonline.com"],
    "outlook": ["outlook.com", "microsoft.com", "live.com", "office.com"],
    "sharepoint": ["sharepoint.com", "microsoft.com"],
    "onedrive": ["onedrive.com", "live.com", "microsoft.com", "sharepoint.com"],
    "google": ["google.com", "google.com.br", "gmail.com", "googleapis.com", "gstatic.com",
               "googleusercontent.com", "youtube.com", "goo.gl", "googlemail.com"],
    "gmail": ["gmail.com", "google.com", "googlemail.com"],
    "apple": ["apple.com", "icloud.com", "me.com", "apple.com.br"],
    "icloud": ["icloud.com", "apple.com"],
    "amazon": ["amazon.com", "amazon.com.br", "amazonaws.com", "amazonses.com", "a2z.com"],
    "netflix": ["netflix.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com", "dropboxmail.com"],
    "linkedin": ["linkedin.com", "lnkd.in"],
    "facebook": ["facebook.com", "facebookmail.com", "meta.com", "fb.com"],
    "instagram": ["instagram.com", "facebookmail.com", "meta.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net", "meta.com"],
    "itau": ["itau.com.br", "itau.com", "itaucard.com.br", "itauunibanco.com.br"],
    "itaú": ["itau.com.br", "itau.com", "itaucard.com.br", "itauunibanco.com.br"],
    "bradesco": ["bradesco.com.br", "bradescoseguros.com.br", "bradescard.com.br"],
    "nubank": ["nubank.com.br", "nu.com.br", "nubank.com"],
    "santander": ["santander.com.br", "santander.com"],
    "caixa": ["caixa.gov.br"],
    "banco do brasil": ["bb.com.br"],
    "mercado livre": ["mercadolivre.com.br", "mercadolivre.com", "mercadolibre.com"],
    "mercadolivre": ["mercadolivre.com.br", "mercadolivre.com", "mercadolibre.com"],
    "mercado pago": ["mercadopago.com.br", "mercadopago.com"],
    "picpay": ["picpay.com"],
    "correios": ["correios.com.br"],
    "receita federal": ["gov.br"],
    "gov.br": ["gov.br"],
    "serasa": ["serasa.com.br", "serasaexperian.com.br"],
    "shopee": ["shopee.com.br", "shopee.com"],
    "magalu": ["magazineluiza.com.br", "magalu.com", "magalu.com.br"],
    "ifood": ["ifood.com.br"],
    "github": ["github.com", "githubusercontent.com"],
    "adobe": ["adobe.com", "adobesign.com", "echosign.com"],
    "zoom": ["zoom.us", "zoom.com"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "dhl": ["dhl.com", "dhl.com.br", "dhl.de"],
    "fedex": ["fedex.com"],
    # governo / autoridades (BR)
    "detran": ["gov.br"],
    "cnh": ["gov.br"],
    "receita": ["gov.br"],
    "governo federal": ["gov.br"],
    "polícia federal": ["gov.br"],
    "serpro": ["serpro.gov.br", "gov.br"],
    "inss": ["gov.br", "inss.gov.br"],
    "banco central": ["bcb.gov.br", "gov.br"],
    # alvos frequentes de golpe
    "mcafee": ["mcafee.com"],
    "norton": ["norton.com", "nortonlifelock.com", "gen.com"],
    "ledger": ["ledger.com"],
    "metamask": ["metamask.io", "consensys.io"],
    "trust wallet": ["trustwallet.com"],
    "trustwallet": ["trustwallet.com"],
    "temu": ["temu.com"],
    "shein": ["shein.com", "shein.com.br"],
    "aliexpress": ["aliexpress.com", "alibaba.com"],
    "spotify": ["spotify.com"],
    "disney+": ["disneyplus.com", "disney.com"],
    "airbnb": ["airbnb.com", "airbnb.com.br"],
    "usps": ["usps.com"],
    "irs": ["irs.gov"],
    "roblox": ["roblox.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com", "bofa.com"],
    "american express": ["americanexpress.com", "aexp.com"],
    "mastercard": ["mastercard.com", "mastercard.com.br"],
    "c6 bank": ["c6bank.com.br"],
    "banco inter": ["bancointer.com.br", "inter.co"],
    "sicoob": ["sicoob.com.br"],
    "sicredi": ["sicredi.com.br"],
    "cemig": ["cemig.com.br"],
    "sabesp": ["sabesp.com.br"],
}

# Palavras de autoridade no nome de exibição (golpe usando e-mail gratuito para parecer órgão/empresa)
AUTHORITY_WORDS = re.compile(
    r"\b(gov|governo|gov-?br|pol[ií]cia|police|receita|tribunal|justi[cç]a|minist[eé]rio|prefeitura|detran|"
    r"banco|bank|suporte|support|security|seguran[cç]a|admin|administrador|helpdesk|help desk|service ?desk|"
    r"departamento|department|financeiro|cobran[cç]a|jur[ií]dico|rh|recursos humanos|ti|it team|webmaster|"
    r"postmaster|mail ?(admin|delivery)|account(s)? team|billing)\b",
    re.I,
)

# Rótulos usados na comparação de sósias (só os com 5+ letras para evitar falso positivo)
BRAND_LABELS: dict[str, str] = {}
for _b, _doms in BRANDS.items():
    for _d in _doms:
        _lab = _d.split(".")[0]
        if len(_lab) >= 5 and _lab not in {
            "office", "outlook", "googleapis", "gstatic", "teams", "azure", "facebookmail", "dropboxmail",
            "googleusercontent", "googlemail", "githubusercontent", "amazonses", "amazonaws", "itaucard",
            "onmicrosoft", "microsoftonline", "microsoftstore", "office365",
            "bradescard", "bradescoseguros", "itauunibanco", "serasaexperian", "mercadolibre", "adobesign",
            "echosign",
        }:
            BRAND_LABELS.setdefault(_lab, _d)

# Tokens de marca para checar em partes do domínio separadas por hífen/ponto (ex.: itau-seguranca.com)
BRAND_TOKENS: dict[str, str] = {}
for _b, _doms in BRANDS.items():
    for _d in _doms:
        _lab = _d.split(".")[0]
        if len(_lab) >= 4 and _lab not in {"mail", "live", "teams", "office", "outlook", "azure", "meta", "inter",
                                           "msft", "a2z", "googleapis", "gstatic", "amazonses", "amazonaws"}:
            BRAND_TOKENS.setdefault(_lab, _d)

FREEMAIL = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
    "yahoo.com.br", "ymail.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com",
    "bol.com.br", "uol.com.br", "terra.com.br", "ig.com.br", "zoho.com", "gmx.com", "mail.com",
    "yandex.com", "yandex.ru", "tutanota.com", "outlook.com.br", "hotmail.com.br",
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "work", "gq", "tk", "ml", "cf", "ga", "rest", "cam",
    "icu", "sbs", "cfd", "quest", "buzz", "monster", "lol", "cyou", "bond", "support", "su", "country",
    "kim", "men", "loan", "date", "racing", "download", "review", "accountant", "win", "bid", "stream",
    "gdn", "mom", "ink", "beauty", "hair", "skin", "makeup", "autos", "boats", "yachts", "homes",
}

SHORTENERS = {
    "bit.ly", "bitly.com", "tinyurl.com", "is.gd", "cutt.ly", "rebrand.ly", "ow.ly", "shorturl.at",
    "rb.gy", "s.id", "tiny.cc", "t.ly", "v.gd", "encurtador.com.br", "l.ead.me", "qrco.de", "short.io",
    "buff.ly", "soo.gd", "clck.ru", "u.to", "shorturl.gg", "x.gd", "t.co", "goo.su", "bl.ink",
}

# Plataformas legítimas muito abusadas para hospedar páginas de phishing
ABUSED_HOSTING = {
    "firebaseapp.com", "web.app", "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app",
    "glitch.me", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com", "blob.core.windows.net",
    "web.core.windows.net", "azurewebsites.net", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "weebly.com", "weeblysite.com", "wixsite.com",
    "000webhostapp.com", "square.site", "webflow.io", "framer.app", "framer.website", "notion.site",
    "canva.site", "my.canva.site", "godaddysites.com", "jimdosite.com", "sites.google.com", "forms.gle",
    "typeform.com", "jotform.com", "mystrikingly.com", "replit.app", "repl.co", "onrender.com",
    "herokuapp.com", "github.io", "gitbook.io", "s3.amazonaws.com", "surge.sh", "translate.goog",
    "carrd.co", "wordpress.com", "blogspot.com", "dropboxusercontent.com", "1drv.ms",
}

# Domínios de rastreamento de clique de serviços de e-mail marketing (reduzem falso positivo)
ESP_TRACKING = {
    "sendgrid.net", "list-manage.com", "mcusercontent.com", "mandrillapp.com", "rs6.net", "hubspotlinks.com",
    "hubspotemail.net", "hs-sites.com", "exct.net", "spgo.io", "mailgun.org", "awstrack.me", "rdstation.com.br",
    "rdtrk.com", "klclick.com", "klclick1.com", "klclick2.com", "klclick3.com", "sendibt2.com", "sendibt3.com",
    "sendibm1.com", "brevo.com", "substack.com", "beehiiv.com", "mlsend.com", "ck.page", "convertkit-mail.com",
    "mktdns.com", "ct.sendgrid.net", "mailchimp.com", "e.customeriomail.com", "customeriomail.com",
    "emarsys.net", "salesforce.com", "mkt.com", "pardot.com", "sparkpostmail.com", "amazonses.com",
    "mailjet.com", "mjt.lu", "cmail19.com", "cmail20.com", "createsend.com", "aweber.com", "getresponse.com",
    "e-goi.com", "egoiapp.com", "dinamize.com.br", "allin.com.br", "mailee.me", "lt.acemlna.com",
    "acemlna.com", "acemlnb.com", "activehosted.com",
}

LOGIN_WORDS = re.compile(
    r"login|log-in|signin|sign-in|verif|atualiz|update|secure|seguran|account|conta|senha|password|passwd|"
    r"wallet|unlock|desbloq|confirm|autentic|authent|validar|validate|recadastr|token|2fa|webmail|owa|"
    r"session|sessao|sessão|billing|fatura|resgat|reativ|suspen|bloquei",
    re.I,
)

EMAIL_IN_TEXT = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
DOMAINISH = re.compile(r"^(?:https?://)?(?:www\.)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?:[/:?#].*)?$", re.I)


@dataclass
class UrlInfo:
    original: str
    url: str            # após desembrulhar redirecionadores conhecidos
    scheme: str
    host: str
    registered: str     # domínio registrável (ex.: exemplo.com.br)
    suffix: str
    subdomain: str
    port: int | None
    path: str
    query: str
    fragment: str
    is_ip: bool
    unwrapped_from: str = ""


@lru_cache(maxsize=50000)
def registered_domain(host: str) -> str:
    host = host.lower().strip(".")
    if not host:
        return ""
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    ext = _extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def domain_matches(host: str, domains) -> bool:
    host = host.lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in domains)


def _unwrap(url: str) -> tuple[str, str]:
    """Desembrulha Safe Links (Microsoft), URLDefense (Proofpoint), redirecionador do Google etc."""
    try:
        sp = urlsplit(url)
    except ValueError:
        return url, ""
    host = (sp.hostname or "").lower()
    qs = parse_qs(sp.query)
    if host.endswith("safelinks.protection.outlook.com") and "url" in qs:
        return qs["url"][0], "Safe Links"
    if host in {"www.google.com", "google.com", "www.google.com.br"} and sp.path == "/url":
        target = (qs.get("q") or qs.get("url") or [""])[0]
        if target:
            return target, "redirecionador do Google"
    if host == "urldefense.com" and "/v3/__" in url:
        m = re.search(r"/v3/__(.+?)__;", url)
        if m:
            return m.group(1), "Proofpoint URLDefense"
    if host == "urldefense.proofpoint.com" and "u" in qs:
        u = qs["u"][0].replace("-", "%").replace("_", "/")
        return unquote(u), "Proofpoint URLDefense"
    if host.endswith("linkprotect.cudasvc.com") and "a" in qs:
        return qs["a"][0], "Barracuda"
    return url, ""


def parse_url(raw: str) -> UrlInfo | None:
    raw = raw.strip().strip("<>\"'")
    if not raw:
        return None
    if raw.lower().startswith("www."):
        raw = "http://" + raw
    url, via = raw, ""
    for _ in range(3):  # redirecionadores aninhados
        new, how = _unwrap(url)
        if not how:
            break
        url, via = new, how
    try:
        sp = urlsplit(url)
        port = sp.port
    except ValueError:
        return None
    scheme = sp.scheme.lower()
    host = (sp.hostname or "").lower().strip(".")
    is_ip = False
    try:
        ipaddress.ip_address(host.strip("[]"))
        is_ip = True
    except ValueError:
        # IP em decimal/hex (ex.: http://3232235777/)
        if re.fullmatch(r"(0x[0-9a-f]+|\d{8,10})", host or "x"):
            is_ip = True
    ext = _extract(host) if host and not is_ip else None
    return UrlInfo(
        original=raw, url=url, scheme=scheme, host=host,
        registered=registered_domain(host) if host else "",
        suffix=ext.suffix if ext else "",
        subdomain=ext.subdomain if ext else "",
        port=port, path=sp.path, query=sp.query, fragment=sp.fragment,
        is_ip=is_ip, unwrapped_from=via,
    )


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_CONFUSABLES = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("@", "a"), ("$", "s"), ("i", "l")]


def skeleton(s: str) -> str:
    """Forma 'esqueleto' para comparar domínios visualmente parecidos (paypa1 ~ paypal, rnicrosoft ~ microsoft)."""
    s = s.lower()
    try:
        if "xn--" in s:
            s = s.encode("ascii").decode("idna")
    except Exception:
        pass
    # homóglifos cirílicos/gregos mais comuns
    s = s.translate(str.maketrans("аеорсухіјԁɡոԛѕԝ", "aeopcyxijdgnqsw"))
    for a, b in _CONFUSABLES:
        s = s.replace(a, b)
    return s


def lookalike_brand(host: str) -> tuple[str, str] | None:
    """Retorna (marca, motivo) se o host imita uma marca conhecida sem ser oficial."""
    if not host:
        return None
    for brand, doms in BRANDS.items():
        if domain_matches(host, doms):
            return None  # é oficial
    reg = registered_domain(host)
    label = reg.split(".")[0]
    sk = skeleton(label)
    tokens = set(re.split(r"[-.]", host))
    for blabel, bdom in BRAND_LABELS.items():
        bsk = skeleton(blabel)
        if sk == bsk and label != blabel:
            return blabel, f"'{reg}' é visualmente igual a '{bdom}'"
        if len(label) >= 5 and 0 < levenshtein(sk, bsk) <= (1 if len(blabel) <= 6 else 2):
            return blabel, f"'{reg}' difere de '{bdom}' por poucas letras"
        if len(blabel) >= 6 and blabel in label and label != blabel:
            return blabel, f"'{reg}' contém '{blabel}' mas não é domínio oficial"
    for btoken, bdom in BRAND_TOKENS.items():
        if btoken in tokens and reg != bdom:
            return btoken, f"'{host}' usa o nome '{btoken}' mas não é domínio oficial"
    return None


def recipient_in_url(info: UrlInfo, recipients: list[str]) -> str:
    """Retorna 'fragment' ou 'query' se o e-mail do destinatário aparece no link (comum em kits de phishing)."""
    for r in recipients:
        if not r:
            continue
        variants = {r, r.replace("@", "%40")}
        try:
            variants.add(base64.b64encode(r.encode()).decode().rstrip("="))
            variants.add(base64.urlsafe_b64encode(r.encode()).decode().rstrip("="))
        except Exception:
            pass
        frag = unquote(info.fragment)
        if any(v and v in frag for v in variants) or any(v and v in info.fragment for v in variants):
            return "fragment"
        q = unquote(info.query) + unquote(info.path)
        if any(v and v in q for v in variants):
            return "query"
    return ""
