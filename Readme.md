# Azure Sentinel SecOps Lab

Proyecto en progreso — actualizado con cada fase completada.

Cloud SIEM project on Azure: threat detection mapped to MITRE ATT&CK with
Microsoft Sentinel, custom KQL rules, and automated response via Logic Apps.

Proyecto de portfolio en Cloud Security: implementación de un SIEM en Azure
usando Microsoft Sentinel, con reglas de detección personalizadas en KQL y
respuesta automatizada mediante Logic Apps.

## Objetivo

Simular un flujo realista de SecOps en la nube: ingesta de logs, detección
de amenazas comunes sobre la capa de identidad (fuerza bruta, escalado de
privilegios, persistencia) y respuesta automatizada, todo documentado paso
a paso y mapeado al framework **MITRE ATT&CK**.

## Arquitectura

```
Fuentes de datos (Azure AD / Entra ID, Activity Log)
        │
        ▼
Log Analytics workspace
        │
        ▼
Microsoft Sentinel
        │
        ▼
Reglas de detección KQL ──► Incidentes/alertas ──► Logic Apps (respuesta)
```

## Fase 1 — Preparación del entorno ✅

- Presupuesto con alertas de coste configurado (80% / 100%)
- Resource group creado (`rg-secops-lab`)
- Log Analytics workspace creado (`rg-secops-lab-ana`, East US)
- Microsoft Sentinel habilitado sobre el workspace

Detalle completo en [`docs/fase1-preparacion.md`](./docs/fase1-preparacion.md).

## Fase 2 — Conectar las fuentes de datos ✅

- Conector nativo de Entra ID bloqueado por licencia P2 → resuelto con
  Diagnostic Settings como alternativa
- `SigninLogs`, `AuditLogs` y `AzureActivity` llegando al workspace,
  verificado con eventos reales generados a propósito

Detalle completo en [`docs/fase2-conectar-datos.md`](./docs/fase2-conectar-datos.md).

## Fase 3 — Detecciones KQL ✅

Tres Analytics Rules diseñadas, creadas y validadas contra datos reales:

| Regla | Táctica MITRE | Técnica | Severidad |
|---|---|---|---|
| Brute Force - Multiple Failed Logins | Credential Access | T1110 | Medium |
| Privilege Escalation - Out of Hours Role Assignment | Privilege Escalation | T1098 | High |
| Persistence - New Service Principal or Mail Forwarding Rule | Persistence | T1098.001, T1136, T1114.003 | Medium |

Fase funcionalmente completa: detección diseñada y validada contra datos
reales. La activación del flujo automático de incidentes (bloqueada por
un bug de plataforma en Sentinel, con ticket abierto a soporte de
Microsoft) queda como ampliación sobre esta base.

Detalle completo en [`docs/fase3-detecciones-kql.md`](./docs/fase3-detecciones-kql.md).

## Roadmap — próximos pasos

- **Fase 3.5 — VM + Atomic Red Team + Triage**: despliegue de una VM
  Windows con Azure Monitor Agent para ampliar la cobertura de detección
  a nivel de endpoint (persistencia, defense evasion, discovery)
  usando Atomic Red Team, y trabajo de triage sobre la cola de
  incidentes (clasificación, informes, tuning de reglas).
- **Fase 4 — Respuesta automatizada con Logic Apps**: diseño y creación
  de playbooks de respuesta conectados a las Analytics Rules.
- **Fase 5 — Purple Team**: simulación de ataque real contra el propio
  tenant (MicroBurst, ROADtools, PowerZure) para verificar que las
  detecciones disparan correctamente.
- **Fase 6 — Documentación final**: resumen completo del proyecto,
  incluyendo los hallazgos del Purple Team.

## Estructura del repositorio

```
/docs        → documentación detallada de cada fase
/detections  → queries KQL de las reglas de detección
/playbooks   → Logic Apps / plantillas de respuesta automatizada
/infra       → Infraestructura como código (si se añade más adelante)
```

## Stack

- Microsoft Sentinel (SIEM cloud-native)
- Log Analytics workspace
- KQL (Kusto Query Language)
- Azure Logic Apps
- Azure AD (Entra ID)
- MITRE ATT&CK (framework de referencia para las detecciones)

## Documentación

Ver [`/docs`](./docs) para el detalle técnico de cada fase, incluyendo
decisiones de diseño y conceptos clave.