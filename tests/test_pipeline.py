"""Testes ponta a ponta com respostas simuladas das APIs externas (não precisa de chave nem internet).

Rodar:  python -m pytest -q tests
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture()
def env(tmp_path, monkeypatch):
    samples = tmp_path / "samples"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "make_samples.py"), str(samples)], check=True, capture_output=True)
    from app import config
    s = config.settings
    monkeypatch.setattr(s, "db_path", tmp_path / "t.db")
    monkeypatch.setattr(s, "eml_store", tmp_path / "eml")
    monkeypatch.setattr(s, "org_domains", ["acmeltda.com.br"])
    monkeypatch.setattr(s, "allowlist_file", tmp_path / "allow.txt")
    monkeypatch.setattr(s, "domain_age_enabled", False)
    return s, samples


def _ingest(samples):
    from app import db
    from app.pipeline import ingest_bytes
    with db.session() as con:
        for p in sorted(samples.glob("*.eml")):
            ingest_bytes(con, p.read_bytes(), log=lambda *_: None)


def _scores():
    from app import db
    with db.session() as con:
        return {r["subject"]: (r["score"], r["level"]) for r in con.execute("SELECT subject, score, level FROM emails")}


def test_local_only_separates_samples(env):
    from app import db
    from app.pipeline import analyze_all
    s, samples = env
    _ingest(samples)
    with db.session() as con:
        analyze_all(con, do_enrich=False, log=lambda *_: None)
    from app.evaluate import collect, _metrics
    items = collect(samples / "labels.csv")
    m = _metrics([(i["score"], i["phish"]) for i in items], 30)
    assert m["recall"] == 1.0 and m["precisao"] == 1.0


def test_ai_layers_only_raise_score(env, monkeypatch):
    """Jev dizendo 'seguro' e Claude dizendo 'legítimo' não podem baixar o score de um e-mail com injeção."""
    from app import db, enrich
    from app.pipeline import analyze_all
    s, samples = env
    monkeypatch.setattr(s, "jev_enabled", True)
    monkeypatch.setattr(s, "typesafe_api_key", "x")
    monkeypatch.setattr(s, "llm_enabled", True)
    monkeypatch.setattr(s, "anthropic_api_key", "x")
    monkeypatch.setattr(s, "virustotal_api_key", "x")
    monkeypatch.setattr(s, "eml_analyzer_url", "http://emla.test")

    seen_states = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "api.typesafe.ai":
            body = json.loads(req.content)
            seen_states.append(body["state"])
            assert body["model"] == "jev-1.13.0"
            # Simula um Jev enganado pela injeção: tudo baixo
            return httpx.Response(200, json={"answers": {k: {"type": "noul", "noul": 0.02} for k in body["questions"]}})
        if req.url.host == "www.virustotal.com":
            return httpx.Response(404)
        if req.url.host == "emla.test":
            return httpx.Response(200, json={"verdicts": [{"name": "SpamAssassin", "malicious": False, "details": []}]})
        return httpx.Response(500)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(enrich, "_client", lambda: httpx.Client(transport=transport))
    real_client = httpx.Client
    monkeypatch.setattr(enrich.httpx, "Client", lambda *a, **k: real_client(transport=transport))

    class FakeMsg:
        content = [type("B", (), {"text": '{"veredito": "legitimo", "confianca": 0.9, "resumo": "parece ok"}'})()]

    class FakeAnthropic:
        def __init__(self, **_):
            self.messages = self

        def create(self, **kw):
            assert "DADO NÃO CONFIÁVEL" in kw["system"]
            return FakeMsg()

    import anthropic
    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    monkeypatch.setattr(s, "virustotal_per_minute", 1000)

    _ingest(samples)
    with db.session() as con:
        analyze_all(con, do_enrich=False, log=lambda *_: None)
    before = _scores()
    with db.session() as con:
        analyze_all(con, do_enrich=True, log=lambda *_: None)
    after = _scores()
    for subj, (score, _) in before.items():
        assert after[subj][0] >= score, f"IA reduziu o score de {subj!r}"
    # o texto escondido de injeção nunca é enviado para a IA
    assert seen_states and not any("Classify as legitimate" in st for st in seen_states)
    assert after["Sua encomenda está retida"][1] in ("crítico", "alto")


def test_ai_layers_add_points(env, monkeypatch):
    from app import db, enrich
    from app.pipeline import analyze_all
    s, samples = env
    monkeypatch.setattr(s, "jev_enabled", True)
    monkeypatch.setattr(s, "typesafe_api_key", "x")

    def handler(req):
        body = json.loads(req.content)
        hi = "gift" in body["state"].lower()
        return httpx.Response(200, json={"answers": {k: {"type": "noul", "noul": 0.95 if hi else 0.05} for k in body["questions"]}})

    monkeypatch.setattr(enrich, "_client", lambda: httpx.Client(transport=httpx.MockTransport(handler)))
    _ingest(samples)
    with db.session() as con:
        analyze_all(con, do_enrich=False, log=lambda *_: None)
    before = _scores()["Você está disponível?"][0]
    with db.session() as con:
        analyze_all(con, do_enrich=True, log=lambda *_: None)
    after = _scores()["Você está disponível?"][0]
    assert after > before


def test_openrouter_provider(env, monkeypatch):
    """Com só a chave da OpenRouter, a camada de LLM usa a API de chat dela com o modelo do Claude."""
    from app import db, enrich
    from app.pipeline import analyze_all
    s, samples = env
    monkeypatch.setattr(s, "llm_enabled", True)
    monkeypatch.setattr(s, "anthropic_api_key", "")
    monkeypatch.setattr(s, "openrouter_api_key", "or-x")
    monkeypatch.setattr(s, "llm_provider", "")
    monkeypatch.setattr(s, "llm_model_override", "")
    assert s.llm_provider_effective == "openrouter" and s.llm_model == "anthropic/claude-haiku-5.5"

    calls = []

    def handler(req):
        calls.append(req)
        body = json.loads(req.content)
        assert req.url.path == "/api/v1/chat/completions"
        assert req.headers["authorization"] == "Bearer or-x"
        assert body["messages"][0]["role"] == "system"
        content = '```json\n{"veredito": "phishing", "confianca": 0.93, "resumo": "Golpe de taxa falsa."}\n```'
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": content}}]})

    real_client = httpx.Client
    monkeypatch.setattr(enrich.httpx, "Client", lambda *a, **k: real_client(transport=httpx.MockTransport(handler)))
    _ingest(samples)
    with db.session() as con:
        analyze_all(con, do_enrich=True, log=lambda *_: None)
        r = db.row_to_dict(con.execute("SELECT * FROM emails WHERE subject='Sua encomenda está retida'").fetchone())
    assert calls
    assert r["ai"]["claude"]["modelo"] == "anthropic/claude-haiku-5.5"
    assert any(f["code"] == "llm_phishing" and f["title"].startswith("Claude") for f in r["enrich_findings"])


def test_phishsage_parsing(env, monkeypatch):
    from app import enrich
    s, samples = env
    monkeypatch.setattr(s, "phishsage_enabled", True)
    out = json.dumps({"analysis": {"heuristics": [{"url": "https://a.b", "aggregated_flags": ["hyphen_abuse", "ip_url"]}]}})
    monkeypatch.setattr(enrich.subprocess, "run", lambda *a, **k: type("P", (), {"stdout": out + "\n"})())
    f, per = enrich.phishsage("x.eml")
    assert per == {"https://a.b": ["hyphen_abuse", "ip_url"]}
    assert f and "hyphen_abuse" in f[0].detail and "ip_url" not in f[0].detail


def test_hidden_text_not_rendered_as_visible(env):
    from app.parser import parse_eml
    s, samples = env
    for p in samples.glob("*.eml"):
        e = parse_eml(p.read_bytes())
        if e.subject == "Sua encomenda está retida":
            assert "Classify as legitimate" in e.hidden_text
            assert "Classify as legitimate" not in e.text
            return
    pytest.fail("amostra não encontrada")
