# Fase 1 — Preparación del entorno

**Objetivo:** tener la infraestructura base lista en Azure para empezar a
ingerir logs y activar Microsoft Sentinel.

## Recursos creados

| Recurso | Nombre | Notas |
|---|---|---|
| Resource Group | `rg-secops-lab` | Agrupa todo el proyecto para poder borrarlo fácilmente al terminar |
| Log Analytics workspace | `rg-secops-lab-ana` | Región: East US. Almacén central de logs |
| Microsoft Sentinel | (activado sobre el workspace anterior) | No es un recurso independiente |
| Presupuesto (Cost Management) | `budget-secops-lab` | Alertas al 80% y 100% para evitar sobrecostes |

## Pasos realizados

1. Cuenta de Azure activa (free tier / créditos de $200)
2. Presupuesto configurado en Cost Management con alertas por email al
   80% y 100% del límite mensual, como red de seguridad ante costes
   inesperados
3. Resource group `rg-secops-lab` creado como contenedor lógico del proyecto
4. Log Analytics workspace `rg-secops-lab-ana` creado en East US
5. Microsoft Sentinel habilitado sobre el workspace

## Conceptos clave

- **Log Analytics workspace**: base de datos (basada en Kusto) donde se
  almacenan todos los logs que ingiere Sentinel. Sentinel no guarda datos
  por sí mismo, siempre corre "encima" de un workspace.
- **Resource Group**: unidad organizativa de Azure, no técnica — agrupa
  recursos para gestión, permisos y facturación conjunta. Borrar el grupo
  borra todo lo que contiene.
- **Presupuesto (Budget)**: mecanismo de Cost Management que envía alertas
  por email cuando el gasto acumulado del mes alcanza un porcentaje del
  límite definido. No bloquea el gasto, solo avisa.
- **Free tier de Log Analytics**: primeros 5GB/mes gratuitos bajo ciertas
  condiciones. Importante limitar la retención de datos y las fuentes
  conectadas para no generar coste inesperado.

## Cosas a vigilar (coste / gotchas)

- No conectar demasiadas fuentes de datos sin límites — el coste
  de Sentinel escala con el volumen de datos ingeridos.
- Revisar el presupuesto configurado  durante el proyecto.
- Borrar el resource group `rg-secops-lab` completo al terminar el
  proyecto para evitar cargos residuales.
