"""Configuração via variáveis de ambiente (ou arquivo .env)."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if v[:1] in ("'", '"') and v[:1] in v[1:]:
            v = v[1:v.index(v[0], 1)]          # valor entre aspas: mantém '#' dentro
        else:
            v = re.split(r"\s+#", v, maxsplit=1)[0].strip() if not v.startswith("#") else ""
        os.environ.setdefault(k.strip(), v)


ROOT = Path(__file__).resolve().parent.parent
_load_dotenv(ROOT / ".env")


def _bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "sim", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except ValueError:
        return default


def _list(name: str) -> list[str]:
    return [x.strip().lower() for x in os.getenv(name, "").split(",") if x.strip()]


@dataclass
class Settings:
    db_path: Path = field(default_factory=lambda: Path(os.getenv("DB_PATH", ROOT / "data" / "triage.db")))
    eml_store: Path = field(default_factory=lambda: Path(os.getenv("EML_STORE", ROOT / "data" / "eml")))

    # Domínios da sua organização (e-mails internos) e listas de confiança
    org_domains: list[str] = field(default_factory=lambda: _list("ORG_DOMAINS"))
    allowlist_file: Path = field(default_factory=lambda: Path(os.getenv("ALLOWLIST_FILE", ROOT / "allowlist.txt")))

    # Enriquecimento: só roda para e-mails com score >= este limite (economiza cota de API)
    enrich_min_score: int = field(default_factory=lambda: _int("ENRICH_MIN_SCORE", 25))

    virustotal_api_key: str = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", ""))
    virustotal_per_minute: int = field(default_factory=lambda: _int("VIRUSTOTAL_PER_MINUTE", 4))
    urlscan_api_key: str = field(default_factory=lambda: os.getenv("URLSCAN_API_KEY", ""))

    domain_age_enabled: bool = field(default_factory=lambda: _bool("DOMAIN_AGE_ENABLED", True))

    eml_analyzer_url: str = field(default_factory=lambda: os.getenv("EML_ANALYZER_URL", ""))  # ex.: http://eml-analyzer:8000
    phishsage_enabled: bool = field(default_factory=lambda: _bool("PHISHSAGE_ENABLED", False))

    # Jev (TypeSafe AI): triagem barata de conteúdo em TODOS os e-mails. Só soma pontos, nunca reduz.
    jev_enabled: bool = field(default_factory=lambda: _bool("JEV_ENABLED", False))
    typesafe_api_key: str = field(default_factory=lambda: os.getenv("TYPESAFE_API_KEY", ""))
    jev_model: str = field(default_factory=lambda: os.getenv("JEV_MODEL", "jev-1.13.0"))  # versão fixa de propósito

    # Classificação por LLM (opcional). Envia o conteúdo do e-mail para a API da Anthropic.
    llm_enabled: bool = field(default_factory=lambda: _bool("LLM_ENABLED", False))
    anthropic_api_key: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    openrouter_api_key: str = field(default_factory=lambda: os.getenv("OPENROUTER_API_KEY", ""))
    # anthropic | openrouter. Vazio = usa o que tiver chave (Anthropic primeiro).
    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "").strip().lower())
    llm_model_override: str = field(default_factory=lambda: os.getenv("LLM_MODEL", ""))

    @property
    def llm_provider_effective(self) -> str:
        if self.llm_provider in ("anthropic", "openrouter"):
            return self.llm_provider
        if self.anthropic_api_key:
            return "anthropic"
        return "openrouter" if self.openrouter_api_key else ""

    @property
    def llm_model(self) -> str:
        if self.llm_model_override:
            return self.llm_model_override
        return "anthropic/claude-haiku-5.5" if self.llm_provider_effective == "openrouter" else "claude-haiku-5-5"

    @property
    def llm_ready(self) -> bool:
        p = self.llm_provider_effective
        return self.llm_enabled and ((p == "anthropic" and bool(self.anthropic_api_key)) or
                                     (p == "openrouter" and bool(self.openrouter_api_key)))
    llm_min_score: int = field(default_factory=lambda: _int("LLM_MIN_SCORE", 15))

    http_timeout: int = field(default_factory=lambda: _int("HTTP_TIMEOUT", 15))

    def allowlist(self) -> set[str]:
        out: set[str] = set(self.org_domains)
        if self.allowlist_file.exists():
            for line in self.allowlist_file.read_text(encoding="utf-8").splitlines():
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    out.add(line)
        return out


settings = Settings()
