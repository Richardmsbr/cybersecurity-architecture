# LGPD - Lei Geral de Protecao de Dados

Lei 13.709/2018 - Framework de protecao de dados pessoais do Brasil.

---

## Visao Geral

### Principios Fundamentais (Art. 6)

| Principio | Descricao | Controles |
|-----------|-----------|-----------|
| **Finalidade** | Tratamento para propositos legitimos e especificos | Documentar finalidade de cada coleta |
| **Adequacao** | Compatibilidade com finalidades informadas | Revisar se dados coletados sao necessarios |
| **Necessidade** | Limitacao ao minimo necessario | Data minimization, retention policies |
| **Livre Acesso** | Consulta facilitada sobre tratamento | Portal do titular, APIs de consulta |
| **Qualidade** | Exatidao e atualizacao dos dados | Data quality checks, update procedures |
| **Transparencia** | Informacoes claras e acessiveis | Privacy notices, consent management |
| **Seguranca** | Medidas tecnicas e administrativas | Encryption, access control, monitoring |
| **Prevencao** | Medidas para prevenir danos | Risk assessments, security testing |
| **Nao Discriminacao** | Proibicao de tratamento discriminatorio | Bias detection, audit trails |
| **Responsabilizacao** | Demonstracao de conformidade | Documentation, evidence collection |

---

## Bases Legais para Tratamento (Art. 7)

### Mapeamento de Bases Legais

```
+---------------------------+--------------------------------+---------------------------+
|      Base Legal           |         Quando Usar            |      Documentacao         |
+---------------------------+--------------------------------+---------------------------+
| Consentimento             | Coleta direta do titular       | Registro de consentimento |
| Obrigacao Legal           | Exigencia regulatoria          | Referencia a legislacao   |
| Execucao de Politicas     | Administracao publica          | Ato administrativo        |
| Estudos/Pesquisa          | Anonimizacao quando possivel   | Protocolo de pesquisa     |
| Execucao de Contrato      | Necessario para o contrato     | Contrato assinado         |
| Exercicio de Direitos     | Processo judicial/admin        | Documentacao processual   |
| Protecao da Vida          | Emergencias de saude           | Registro de emergencia    |
| Tutela da Saude           | Profissionais de saude         | Prontuario medico         |
| Interesse Legitimo        | Avaliacao de impacto (LIA)     | LIA documentado           |
| Protecao de Credito       | Analise de credito             | Politica de credito       |
+---------------------------+--------------------------------+---------------------------+
```

---

## Direitos do Titular (Art. 18)

### Implementacao Tecnica

| Direito | Endpoint API | SLA | Implementacao |
|---------|--------------|-----|---------------|
| Confirmacao de tratamento | `GET /api/v1/privacy/exists` | 15 dias | Query no data catalog |
| Acesso aos dados | `GET /api/v1/privacy/export` | 15 dias | Data export pipeline |
| Correcao | `PATCH /api/v1/privacy/data` | 15 dias | Update com audit trail |
| Anonimizacao | `POST /api/v1/privacy/anonymize` | 15 dias | Anonymization engine |
| Bloqueio | `POST /api/v1/privacy/block` | 15 dias | Processing flag |
| Eliminacao | `DELETE /api/v1/privacy/data` | 15 dias | Cascade delete + backup purge |
| Portabilidade | `GET /api/v1/privacy/portable` | 15 dias | JSON/CSV export |
| Revogacao consentimento | `DELETE /api/v1/privacy/consent` | Imediato | Consent management |
| Informacao compartilhamento | `GET /api/v1/privacy/sharing` | 15 dias | Data flow mapping |

### Arquitetura de Resposta ao Titular

```
                                    +------------------+
                                    |   Portal LGPD    |
                                    |   (Frontend)     |
                                    +--------+---------+
                                             |
                                             v
+------------------+              +----------+----------+              +------------------+
|   Identity       |              |                     |              |   Notification   |
|   Verification   +------------->+   Privacy API      +------------->+   Service        |
|   (KYC)          |              |   Gateway          |              |   (Email/SMS)    |
+------------------+              +----------+----------+              +------------------+
                                             |
                    +------------------------+------------------------+
                    |                        |                        |
                    v                        v                        v
           +--------+--------+      +--------+--------+      +--------+--------+
           |   Data          |      |   Consent       |      |   Audit         |
           |   Catalog       |      |   Management    |      |   Trail         |
           +-----------------+      +-----------------+      +-----------------+
```

---

## Dados Pessoais Sensiveis (Art. 11)

### Categorias e Controles

| Categoria | Exemplos | Controles Adicionais |
|-----------|----------|---------------------|
| Origem racial/etnica | Autodeclaracao | Consentimento especifico, encryption |
| Conviccao religiosa | Religiao declarada | Segregacao de dados, access control |
| Opiniao politica | Filiacao partidaria | Minimizacao, purpose limitation |
| Filiacao sindical | Registro sindical | Need-to-know access |
| Dados de saude | Prontuarios, exames | Encryption at rest/transit, HSM |
| Vida sexual | Orientacao sexual | Pseudonimizacao, audit logs |
| Dados geneticos | DNA, sequenciamento | Air-gapped storage, MFA |
| Dados biometricos | Facial, digital | Template protection, liveness |

### Controles Tecnicos para Dados Sensiveis

```yaml
# Configuracao de Protecao de Dados Sensiveis
sensitive_data_controls:
  encryption:
    algorithm: AES-256-GCM
    key_management: HSM
    key_rotation: 90_days

  access_control:
    authentication: MFA_required
    authorization: RBAC + ABAC
    session_timeout: 15_minutes

  monitoring:
    access_logging: enabled
    anomaly_detection: enabled
    alert_threshold: any_access

  storage:
    location: brazil_region_only
    backup_encryption: enabled
    retention: minimum_legal
```

---

## Transferencia Internacional (Art. 33-36)

### Mecanismos Permitidos

| Mecanismo | Requisitos | Documentacao |
|-----------|------------|--------------|
| Paises adequados | Lista ANPD | Verificar lista vigente |
| Clausulas-padrao | Aprovadas ANPD | Contrato assinado |
| Clausulas especificas | Autorizacao ANPD | Submissao previa |
| Cooperacao juridica | Acordos internacionais | Tratado aplicavel |
| Protecao da vida | Emergencia | Justificativa documentada |
| Politica publica | Execucao de acordo | Ato administrativo |
| Consentimento especifico | Informado e destacado | Registro de consentimento |
| Obrigacao legal | Cumprimento regulatorio | Referencia legal |

### Avaliacao de Transferencia (TIA)

```
+------------------------------------------------------------------+
|              Transfer Impact Assessment (TIA)                      |
+------------------------------------------------------------------+
| 1. Identificacao do Pais Destino                                  |
|    [ ] Pais na lista de adequacao ANPD?                           |
|    [ ] Legislacao de protecao de dados equivalente?               |
|    [ ] Acesso governamental aos dados?                            |
+------------------------------------------------------------------+
| 2. Analise de Riscos                                              |
|    [ ] Tipo de dados transferidos                                 |
|    [ ] Volume e frequencia                                        |
|    [ ] Finalidade da transferencia                                |
|    [ ] Medidas de seguranca do importador                         |
+------------------------------------------------------------------+
| 3. Medidas Suplementares                                          |
|    [ ] Encryption end-to-end                                      |
|    [ ] Pseudonimizacao pre-transferencia                          |
|    [ ] Contractual protections                                    |
|    [ ] Technical access controls                                  |
+------------------------------------------------------------------+
| 4. Documentacao                                                   |
|    [ ] Contrato com clausulas-padrao                              |
|    [ ] Registro de transferencias                                 |
|    [ ] Evidencia de due diligence                                 |
+------------------------------------------------------------------+
```

---

## Relatorio de Impacto (RIPD)

### Estrutura do RIPD (Art. 38)

```markdown
# Relatorio de Impacto a Protecao de Dados Pessoais

## 1. Identificacao
- Controlador: [Nome da empresa]
- Encarregado (DPO): [Nome e contato]
- Data: [Data de elaboracao]
- Versao: [Numero da versao]

## 2. Descricao do Tratamento
- Natureza: [Coleta, armazenamento, processamento]
- Escopo: [Volume, categorias de dados]
- Contexto: [Sistema, processo de negocio]
- Finalidade: [Objetivo do tratamento]

## 3. Necessidade e Proporcionalidade
- Base legal: [Justificativa]
- Minimizacao: [Dados estritamente necessarios]
- Retencao: [Periodo e justificativa]

## 4. Identificacao de Riscos
| Risco | Probabilidade | Impacto | Nivel |
|-------|---------------|---------|-------|
| Vazamento de dados | Media | Alto | Alto |
| Acesso nao autorizado | Baixa | Alto | Medio |
| Perda de dados | Baixa | Medio | Baixo |

## 5. Medidas de Mitigacao
| Risco | Controle | Responsavel | Prazo |
|-------|----------|-------------|-------|
| Vazamento | Encryption + DLP | Security | Implementado |
| Acesso | RBAC + MFA | IAM Team | Implementado |
| Perda | Backup + DR | Infra | Implementado |

## 6. Parecer do Encarregado
[Recomendacao do DPO]

## 7. Aprovacao
- Aprovado por: [Nome]
- Data: [Data]
- Proxima revisao: [Data]
```

---

## Incidentes de Seguranca (Art. 48)

### Processo de Notificacao

```
+------------------+     +------------------+     +------------------+
|   Deteccao       |     |   Avaliacao      |     |   Notificacao    |
|   do Incidente   +---->+   de Risco       +---->+   ANPD           |
|   (T+0)          |     |   (T+4h)         |     |   (Prazo Razoavel)|
+------------------+     +--------+---------+     +------------------+
                                  |
                                  v
                         +--------+---------+
                         |   Comunicacao    |
                         |   aos Titulares  |
                         |   (Se aplicavel) |
                         +------------------+
```

### Template de Comunicacao a ANPD

```yaml
notificacao_incidente:
  identificacao:
    controlador: "Razao Social"
    cnpj: "XX.XXX.XXX/0001-XX"
    encarregado: "Nome do DPO"
    contato: "dpo@empresa.com.br"

  incidente:
    data_ocorrencia: "YYYY-MM-DD HH:MM"
    data_conhecimento: "YYYY-MM-DD HH:MM"
    natureza: "vazamento|acesso_indevido|perda|outro"
    descricao: "Descricao detalhada do incidente"

  dados_afetados:
    categorias: ["nome", "cpf", "email", "dados_financeiros"]
    volume_titulares: 1000
    volume_registros: 5000
    dados_sensiveis: true|false

  consequencias:
    riscos_titulares: "Descricao dos riscos"
    impacto_avaliado: "alto|medio|baixo"

  medidas:
    contencao: "Acoes imediatas tomadas"
    mitigacao: "Medidas para reduzir impacto"
    prevencao: "Acoes para evitar recorrencia"

  comunicacao_titulares:
    realizada: true|false
    data: "YYYY-MM-DD"
    meio: "email|carta|publicacao"
    conteudo: "Resumo da comunicacao"
```

---

## Encarregado de Dados (DPO)

### Responsabilidades (Art. 41)

| Atribuicao | Atividades | Frequencia |
|------------|------------|------------|
| Canal de comunicacao | Atender titulares e ANPD | Continuo |
| Orientacao | Treinar funcionarios | Trimestral |
| Conformidade | Auditar processos | Semestral |
| Assessoria | Apoiar decisoes de privacidade | Sob demanda |
| RIPD | Elaborar/revisar relatorios | Por projeto |
| Incidentes | Coordenar resposta | Quando necessario |

### Estrutura de Governanca

```
                    +------------------+
                    |   Board/CEO      |
                    +--------+---------+
                             |
                    +--------v---------+
                    |   DPO/Encarregado|
                    +--------+---------+
                             |
        +--------------------+--------------------+
        |                    |                    |
+-------v-------+    +-------v-------+    +-------v-------+
|   Juridico    |    |   Seguranca   |    |   TI          |
|   - Contratos |    |   - Controles |    |   - Sistemas  |
|   - Compliance|    |   - Incidentes|    |   - Dados     |
+---------------+    +---------------+    +---------------+
```

---

## Sancoes Administrativas (Art. 52)

### Escala de Penalidades

| Sancao | Criterios | Valor Maximo |
|--------|-----------|--------------|
| Advertencia | Primeira infracao leve | - |
| Multa simples | Por infracao | 2% faturamento, max R$ 50M |
| Multa diaria | Descumprimento continuado | 2% faturamento, max R$ 50M |
| Publicizacao | Apos confirmacao | Dano reputacional |
| Bloqueio | Dados da infracao | Ate regularizacao |
| Eliminacao | Dados da infracao | Permanente |
| Suspensao parcial | Banco de dados | Ate 6 meses |
| Suspensao | Tratamento de dados | Ate 6 meses |
| Proibicao | Atividades de tratamento | Permanente |

---

## Checklist de Conformidade

### Governanca
- [ ] DPO nomeado e publicado
- [ ] Politica de privacidade atualizada
- [ ] Registro de operacoes de tratamento
- [ ] Programa de treinamento implementado

### Direitos dos Titulares
- [ ] Canal de atendimento disponivel
- [ ] Processos de resposta definidos
- [ ] SLAs dentro do prazo legal (15 dias)
- [ ] Portal de autoatendimento

### Seguranca
- [ ] Inventario de dados pessoais
- [ ] Controles de acesso implementados
- [ ] Criptografia em repouso e transito
- [ ] Monitoramento e logging
- [ ] Plano de resposta a incidentes

### Contratos
- [ ] Clausulas LGPD com fornecedores
- [ ] Avaliacao de operadores
- [ ] Clausulas de transferencia internacional

### Documentacao
- [ ] RIPD para tratamentos de risco
- [ ] Registros de consentimento
- [ ] Evidencias de conformidade
- [ ] Relatorios de auditoria

---

## Controles Tecnicos Recomendados

### Data Discovery e Classification

```python
# Exemplo de classificacao automatica
classification_rules = {
    "cpf": {
        "pattern": r"\d{3}\.\d{3}\.\d{3}-\d{2}",
        "category": "identificador_pessoal",
        "sensitivity": "high",
        "retention": "5_years"
    },
    "email": {
        "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "category": "contato",
        "sensitivity": "medium",
        "retention": "contract_duration"
    },
    "health_data": {
        "keywords": ["diagnostico", "medicamento", "CID", "prontuario"],
        "category": "dado_sensivel",
        "sensitivity": "critical",
        "retention": "20_years"
    }
}
```

### Consent Management Schema

```sql
CREATE TABLE consent_records (
    id UUID PRIMARY KEY,
    titular_id UUID NOT NULL,
    purpose VARCHAR(255) NOT NULL,
    legal_basis VARCHAR(50) NOT NULL,
    consent_given BOOLEAN NOT NULL,
    consent_date TIMESTAMP NOT NULL,
    expiration_date TIMESTAMP,
    revocation_date TIMESTAMP,
    evidence_hash VARCHAR(64) NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_consent_titular ON consent_records(titular_id);
CREATE INDEX idx_consent_purpose ON consent_records(purpose);
CREATE INDEX idx_consent_active ON consent_records(consent_given, revocation_date);
```

---

## Referencias

- Lei 13.709/2018 (LGPD)
- Decreto 10.474/2020 (ANPD)
- Guias e orientacoes ANPD
- ISO 27701:2019 (PIMS)
- NIST Privacy Framework

---

## Controle de Documento

| Versao | Data | Autor | Alteracoes |
|--------|------|-------|------------|
| 1.0 | 2024-01-15 | Security Architecture | Release inicial |
