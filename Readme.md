# Azure Sentinel SecOps Lab

Proyecto en progreso — actualizado con cada fase completada.

Cloud SIEM project on Azure: threat detection mapped to MITRE ATT&CK with
Microsoft Sentinel, custom KQL rules, and automated response via Logic Apps.

Proyecto de portfolio en Cloud Security: implementación de un SIEM en Azure
usando Microsoft Sentinel, con reglas de detección personalizadas en KQL y
respuesta automatizada mediante Logic Apps.

## Objetivo

Simular un flujo realista de SecOps en la nube: ingesta de logs, detección
de amenazas comunes (fuerza bruta, impossible travel, escalado de
privilegios) y respuesta automatizada, todo documentado paso a paso y
mapeado al framework **MITRE ATT&CK**.

## Arquitectura

```
Fuentes de datos (Azure AD, Activity Log, NSG flow logs, Defender)
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
