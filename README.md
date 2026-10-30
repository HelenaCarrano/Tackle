# phish-triage

Lê uma caixa de e-mail inteira, dá a cada mensagem um score de risco de 0 a 100 com o motivo de cada ponto, e mostra tudo num painel web.

Ele junta três camadas:

1. **Heurísticas locais** (sem internet, sem custo): autenticação SPF/DKIM/DMARC, remetente falso, domínios sósias de marcas, links enganosos, anexos perigosos, macros, QR codes, texto escondido, truques anti-filtro.
2. **Comparação com a própria caixa**: domínio quase igual ao de um fornecedor que te escreve sempre, nome de um colega vindo de outro endereço, o mesmo link suspeito chegando por vários remetentes (campanha).
3. **Opiniões externas, só para quem precisa**: VirusTotal, idade do domínio, eml_analyzer (SpamAssassin), PhishSage, Jev (TypeSafe AI) e Claude.

## Início rápido

```bash
pip install -r requirements.txt          # no Linux também: sudo apt install libzbar0 (leitura de QR code)
cp .env.example .env                     # edite: pelo menos ORG_DOMAINS

# testar com a caixa de exemplo (34 e-mails, 15 golpes)
python scripts/make_samples.py
python -m app.cli folder samples
python -m app.cli evaluate samples/labels.csv
python -m app.cli serve                  # http://localhost:8080
```

Com Docker:

```bash
cp .env.example .env
docker compose up -d                                  # painel em http://localhost:8080
docker compose --profile completo up -d               # + eml_analyzer e SpamAssassin
docker compose run --rm triage python -m app.cli imap --host imap.gmail.com --user voce@gmail.com --folder ALL
```

## Importar a caixa

| De onde | Comando |
|---|---|
| Gmail (IMAP) | `python -m app.cli imap --host imap.gmail.com --user voce@gmail.com --folder ALL` |
| Qualquer IMAP | `python -m app.cli imap --host imap.servidor.com --user ... --folder INBOX --since 2026-01-01` |
| Google Takeout (ZIP ou `.mbox`) / Thunderbird | `python -m app.cli mbox "Takeout.zip"` |
| Pasta de .eml | `python -m app.cli folder ./emails` |

- O ZIP é lido localmente; o comando encontra os arquivos `.mbox` dentro dele sem extrair a estrutura do arquivo para a pasta do projeto. Use `--no-enrich` para não enviar mensagens a serviços externos opcionais durante a análise.
- **Gmail:** use uma *senha de app* (myaccount.google.com/apppasswords), não a senha normal. Pode deixar em `IMAP_PASSWORD` no `.env`.
- **Microsoft 365 / Outlook:** a Microsoft desligou login por senha no IMAP. Use `--oauth-token NOME_DA_VARIAVEL` com um token OAuth2, ou exporte a caixa (PST → `readpst -r arquivo.pst` gera mbox) e importe com `mbox`.
- A leitura é **somente leitura**: nada é apagado, movido ou marcado como lido.
- Rodar de novo só importa o que é novo (deduplica pelo conteúdo).
- `--folder ALL` lê todas as pastas, exceto lixeira, spam e rascunhos.

Depois de importar, a análise roda sozinha. Para refazer: `python -m app.cli analyze` (ou o botão **Recalcular** no painel, que não gasta cota de API).

## O painel

- **Faixa da caixa:** cada traço é um e-mail, na ordem de chegada e colorido pelo risco. Picos de vermelho costumam ser campanhas. Clique numa coluna para filtrar o período.
- **Lista:** começa pelos mais arriscados, com os três motivos principais. Teclas `j`/`k` ou setas navegam.
- **Detalhe:** o peso de cada sinal, os endereços reais dos links (de propósito, não clicáveis), anexos, QR codes, autenticação, leitura da IA e o texto do e-mail. O HTML do e-mail **nunca** é aberto no painel.
- **É phishing / É legítimo:** rotula o e-mail. Os rótulos servem para medir o acerto na sua caixa (`python -m app.cli evaluate db`).
- **Confiar em …:** adiciona o domínio à `allowlist.txt`. Só reduz o score quando o e-mail passa na autenticação, então quem falsifica esse domínio continua sendo pego.
- **Campanhas e domínios:** campanhas detectadas, domínios mais suspeitos (bons candidatos para bloquear no servidor) e sinais mais frequentes.

O painel não tem login. Deixe-o em `127.0.0.1` (é o padrão) e não exponha na internet.

## Quanto ele acerta

Medido com phishing **real** e e-mail legítimo **real**, só com as heurísticas locais (sem nenhuma API):

- 300 golpes sorteados do [phishing_pot](https://github.com/rf-peixoto/phishing_pot) (capturados de verdade, vários idiomas).
- 500 legítimos do corpus público do SpamAssassin (250 comuns + 250 "difíceis", tipo newsletter).

| Corte do score | Phishing pego | Alertas corretos | Falsos positivos (de 500) |
|---|---|---|---|
| ≥ 12 | 84% | 83% | 51 |
| ≥ 20 | 74% | 92% | 20 |
| **≥ 30** (padrão "médio") | **62%** | **95%** | **9** |
| ≥ 55 | 31% | 99% | 1 |

Como ler isso:

- O que passa são principalmente golpes que só o **texto** denuncia (prêmio falso, cassino, pedido de pagamento sem link técnico suspeito). É exatamente o que o Jev e o Claude cobrem, por isso vale ligar pelo menos um deles.
- Os e-mails legítimos do teste são antigos (2002) e não têm cabeçalho de autenticação. Na sua caixa, com DMARC, os resultados devem ser melhores dos dois lados, mas **meça**.
- Os 34 exemplos de `samples/` dão 100%, mas eu escrevi esses exemplos. Eles servem para testar se as regras funcionam, não para medir acerto.

**Para saber o número real na sua caixa:** marque 100 a 200 e-mails no painel (misture golpes que você já recebeu com e-mails normais) e rode `python -m app.cli evaluate db`. Ele mostra recall e precisão em vários cortes e lista o que passou.

## Fontes externas (todas opcionais)

| Fonte | O que envia | Quando roda | Observação |
|---|---|---|---|
| Idade do domínio (RDAP) | só o domínio | score ≥ 25 | grátis, sem chave |
| VirusTotal | URL e hash do anexo (nunca o arquivo) | score ≥ 25 | conta grátis: 4/min, 500/dia; o limite é respeitado e tudo fica em cache |
| eml_analyzer | o .eml inteiro, para o seu container local | score ≥ 25 | traz o SpamAssassin; perfil `completo` do compose, `EML_ANALYZER_URL=http://eml-analyzer:8000` |
| PhishSage | nada (roda local) | score ≥ 25 | acrescenta padrões de URL que as regras daqui não cobrem |
| Jev (TypeSafe AI) | texto visível, remetente, assunto e lista de links | **todos** os e-mails | muito barato; pergunta 6 coisas (pede login? pede pagamento? se passa por empresa? pressão? isca? golpe?) |
| Claude (Anthropic ou OpenRouter) | o mesmo que o Jev + os sinais técnicos | score ≥ 15 | escreve a explicação em português que aparece no painel |

**Com chave da OpenRouter:** no `.env`, `LLM_ENABLED=true` e `OPENROUTER_API_KEY=...`. O padrão é `anthropic/claude-haiku-5.5`. Dá para trocar por outro modelo da OpenRouter em `LLM_MODEL`; nesse caso, meça de novo com `evaluate`, porque a qualidade varia muito entre modelos.

Ao fim de `imap`, `folder`, `mbox` e `analyze`, o terminal imprime um **relatório de tempo por e-mail** (importar, caixa, consultas externas, Jev, LLM), os mais lentos primeiro (`--top N`, `--top 0` mostra todos), e os **tokens de entrada/saída** gastos pelo LLM nessa execução. Respostas vindas do cache não gastam tokens e aparecem só como contagem.

O cabeçalho do painel mostra chamadas e tokens de entrada/saída reportados pelo OpenRouter, acumulados localmente desde que esse registro foi adicionado. O provedor não permite reconstruir esse total para chamadas anteriores; sem chamadas OpenRouter registradas, o painel mostra zero.

**Proteções da camada de IA:**

- Jev e Claude **só somam** pontos. Um veredito "legítimo" nunca reduz o score, então um golpe que escreve "este e-mail é seguro" para enganar a IA não consegue se limpar.
- O texto escondido no HTML (fonte zero, `display:none`) **não** é enviado para a IA. Se ele contiver frases dirigidas a filtros ("ignore as instruções", "classifique como seguro"), isso vira um alerta crítico por si só.
- O Claude recebe a instrução de tratar o e-mail como dado não confiável.
- O modelo do Jev fica fixo em `jev-1.13.0`, porque `jev-latest` pode mudar sem aviso. Teste antes de trocar.

**Privacidade:** e-mails e banco ficam na sua máquina (`data/`). Jev e Claude recebem o conteúdo dos e-mails que analisam; só ligue se isso for aceitável para a sua caixa.

## Sinais e pesos

O score soma os pontos com retorno decrescente dentro de cada categoria (o 2º sinal da mesma categoria vale 70%, os seguintes 40%), dá um bônus de 15% quando 3 categorias diferentes concordam, e garante no mínimo 70 quando há um achado crítico (executável, sósia de marca, injeção escondida, macro maliciosa…). Níveis: crítico ≥ 80, alto ≥ 55, médio ≥ 30, baixo ≥ 12.

Os pesos foram ajustados no teste acima. Por exemplo, "palavras de login no endereço" disparava em 133 legítimos e só 12 golpes, então hoje só pesa quando o domínio já é arriscado. Para mudar algo, os pesos estão em `app/heuristics.py`, `app/mailbox.py` e `app/enrich.py`; depois de mudar, rode `evaluate` de novo.

## E o Suspicious, da Thales?

Ficou de fora de propósito. Ele foi feito para usuários **encaminharem** e-mails suspeitos para um endereço dedicado, e não para varrer uma caixa existente. A instalação também é bem mais pesada. Se no futuro você quiser um canal "denuncie aqui" para a empresa, ele combina bem com isto: este projeto varre a caixa, o Suspicious recebe as denúncias.

## Estrutura

```
app/
  parser.py       leitura do .eml, links (com o texto da âncora), texto visível x escondido
  urls.py         domínios: sósias, homóglifos, encurtadores, plataformas abusadas, Safe Links
  attachments.py  extensões, macros (oletools), HTML/SVG armados, PDF ativo, ZIP, QR code
  heuristics.py   regras locais
  mailbox.py      sinais da caixa inteira
  enrich.py       VirusTotal, RDAP, eml_analyzer, PhishSage, Jev, Claude
  scoring.py      score final
  pipeline.py     orquestração
  server.py       API + painel (static/index.html)
  cli.py          comandos
scripts/make_samples.py   gera a caixa de exemplo rotulada
tests/                    testes com APIs simuladas (python -m pytest -q tests)
```
