---
name: log-forensics
description: Metodologia de analisis forense de logs de seguridad (autenticacion, firewall, netflow, antivirus/EDR, SIEM). Usar cuando haya que reconstruir una cadena de ataque, mapear MITRE ATT&CK, auditar reglas de deteccion, calcular MTTD/MTTR o evaluar controles a partir de logs en CSV. Trigger: logs, SIEM, firewall, netflow, autenticacion, incidente, cadena de ataque, ATT&CK, MTTD, IOC, telemetry gap.
---

# Analisis forense de logs de seguridad

Metodologia para convertir un conjunto de logs heterogeneos en un informe
soportado en evidencia. Regla que gobierna todo lo demas:

> **Cada afirmacion del informe cita identificadores de evento reales.**
> Si la afirmacion no se puede respaldar con un ID existente, no se escribe:
> se anota como vacio de telemetria.

## 1. Entradas tipicas

| Fichero | Contenido | Campos que importan |
|---|---|---|
| `raw/*_logs.csv` | originales | `event_id`, `timestamp` |
| `normalized/events.jsonl` | esquema unificado | `ts_epoch`, `source_type`, `actor`, `src_ip`, `dst_ip`, `severity` |
| `analysis/metrics.json` | metricas deterministas | `detection`, `dwell`, `volume_baseline`, `signals` |
| `analysis/integrity.json` | auditoria de calidad | `siem_correlation`, `tactic_technique`, `sequence_gaps` |

`metrics.json` e `integrity.json` ya estan calculados de forma determinista.
**No recalcules numeros que alli existen** (MTTD, dwell time, percentiles,
recuentos). Si un dato no esta en esos ficheros, calculalo tu con `python3`
y dejalo explicito en `metrics_review.discrepancies`.

## 2. Metodo

### Paso 1 - Baseline antes que anomalia

Un evento nocturno no es un incidente; un evento nocturno **fuera de la
baseline de volumen** si lo es. Usa `metrics.json`:

- `volume_baseline.threshold` es el umbral de anomalias (mediana + 8 MAD).
  Se calcula con mediana y desviacion absoluta mediana porque el p95 se
  contamina con los propios outliers y deja de detectarlos. Una transferencia
  que lo supera es candidata a exfiltracion: cita el valor y el ratio.
- `volume_baseline.p95` y `p95_clean` se reportan como referencia.
- `off_hours.by_source` da el ratio de actividad nocturna por fuente. Un
  ratio de 1.0 en antivirus o SIEM indica que **todo** el trafico es
  anomalo: la deteccion llega tarde por construccion.
- `signals` enumera los candidatos a "primer indicio" con su timestamp.

### Paso 2 - Reconstruir la cadena por fases

Ordena los hallazgos en fases ATT&CK. Para cada fase:

1. Marca el **primer evento** que la abre (con ID y timestamp).
2. Anota el actor, el host y la IP de origen/ destino.
3. Enumerala evidencia: todos los IDs que la sostienen.
4. Anota la confianza: `ALTA` (evidencia directa), `MEDIA` (inferida por
   correlacion de tiempo), `BAJA` (solo indiciaria).

Las fases tipicas de un incidente con exfiltracion: Initial Access ->
Execution -> Persistence -> Privilege Escalation -> Lateral Movement ->
Collection -> Exfiltration -> Containment.

### Paso 3 - Separar lo que la evidencia sostiene de lo que se supone

Preguntas obligatorias antes de dar por buena una fase:

- ¿Hay **autenticacion** que justifique el inicio de sesion? Un `SUCCESS` de
  VPN sin evento de autenticacion previo es una discontinuidad.
- ¿Hay **red** que justifique el salto entre hosts? Si el atacante pasa de
  un puesto a un servidor y no hay flujo que lo explique, ese salto es un
  **hueco de telemetria**, no un hecho. Se documenta como tal.
- ¿La accion sigue a la credencial usada, o solo coincide en el tiempo?

### Paso 4 - Auditar al propio SIEM (no solo al incidente)

Este es el valor differential del informe: **el SIEM tambien es un objeto de
analisis**. Revisa cada alerta contra `integrity.json`:

- `related_event_ids` con placeholders (`AUTH-000?`) -> la alerta no es
  accionable: el analista no puede saltar a la evidencia.
- Referencias que apuntan a eventos **benignos** (`service_start` y similar)
  -> el motor de correlacion empareja por indice/orden, no por contenido.
- Referencias a eventos **inexistentes** -> alerta construida sobre evidencia
  fantasma.
- `tactic` incoherente con la tecnica -> regla mal mapeada.
- Tecnica mal aplicada: verifica la **semantica exacta** en MITRE. Ejemplo
  canonico: `T1110.003 Password Spraying` significa "una o pocas contrasenas
  contra **muchas cuentas**". Si los fallos se concentran en **una sola
  cuenta**, la tecnica correcta es `T1110.001 Password Guessing`.
  Etiquetar como spraying cuando es guessing infla el numero de ataques
  distribuidos y falsea la priorizacion.

Para cada problema escribe en `siem_rule_review` la tecnica y la tactica
correctas, con la evidencia que lo demuestra.

### Paso 5 - Evaluar controles, no solo hechos

Para cada control implicado, responde:

- **Deteccion**: ¿llego una alerta? ¿en cuanto? (usa `detection.per_alert`)
- **Respuesta**: ¿se removio la amenaza? Busca el patron
  `detection_status=DETECTED` + `action_taken=NOT_REMOVED` y luego un
  evento posterior con `ACTIVE`: la deteccion sin remediacion es un fallo
  de control mas grave que la falta de deteccion, porque genera confianza
  falsa.
- **Prevencion**: ¿las reglas de firewall debieron bloquear? Usa
  `rule_name` y `action` para ver si la politica era la correcta y fallo la
  ejecucion, o si la politica era permisiva por diseno.
- **Contencion**: ¿cuando se contuvo? Compara con el fin de la
  exfiltracion: si la contencion es posterior a la exfiltracion completa,
  el control de contencion no mitigo el impacto.

### Paso 6 - Severidad

| Nivel | Criterio |
|---|---|
| CRITICAL | datos sensibles exfiltrados, o acceso persistente no remediationado, o credenciales de servicio comprometidas con capacidad de movimiento lateral |
| HIGH | deteccion fallida de un evento critico, remediacion no ejecutada, correlacion rota en alertas de exfiltracion |
| MEDIUM | cobertura de deteccion incompleta, etiquetado MITRE incorrecto, vacio de telemetria que impide reconstruir una fase |
| LOW | ruido, inconsistencias menores de calidad de datos, activos sin inventario |
| INFO | contexto, buenas practicas observadas |

La severidad se asigna por **impacto y por capacidad de deteccion/respuesta
fallida**, no por la severidad que el propio log declara.

## 3. Redaccion de vacios de telemetria

Un hallazgo honesto vale mas que una cadena de ataque completa e inventada.
Si la evidencia no cierra, escribe en `telemetry_gaps`:

- que se esperaba ver (ID o tipo de evento),
- por que su ausencia importa,
- que conclusion bloquea.

Ejemplos tipicos: ausencia de eventos de autenticacion fallida para una
cuenta que sufrio un bloqueo; ausencia de flujo de red entre dos hosts que
se moveron consecutivamente; IP interna sin nombre de activo en el
inventario.

## 4. Salida esperada

Escribe dos ficheros dentro del workspace:

- `report/report.json` -> objeto que cumple el esquema del informe (ver la
  seccion siguiente). **Respeta los nombres exactos de los campos.**
- `report/report.md` -> version legible para humanos, con las mismas cifras.

Ademas, tu respuesta final en el chat debe ser un resumen ejecutivo de 5-10
lineas: que paso, cuanto tiempo estuvo el atacante, que se perdio y cual es
la accion prioritaria.

## 5. Esquema de `report.json`

```json
{
  "schema_version": 1,
  "summary": "string, 3-5 frases",
  "executive_summary": "string, para direccion: impacto y decision que se pide",
  "incident_type": "string",
  "severity_overall": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "attack_chain": [
    {
      "phase": "Initial Access|Execution|Persistence|Privilege Escalation|Lateral Movement|Collection|Exfiltration|Containment|Discovery|Defense Evasion|Command and Control",
      "title": "string",
      "ts": "ISO 8601 con offset, copiado del log",
      "actor": "string, vacio si no aplica",
      "host": "string",
      "description": "string",
      "evidence": ["ID1", "ID2"],
      "techniques": ["T1110.001"],
      "confidence": "ALTA|MEDIA|BAJA"
    }
  ],
  "findings": [
    {
      "id": "H-01",
      "title": "string",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "deteccion|respuesta|prevencion|telemetria|calidad_datos|atribucion",
      "description": "string",
      "evidence": ["ID1"],
      "techniques": ["T1505.003"],
      "impact": "string",
      "recommendation": "string",
      "control_domain": "string"
    }
  ],
  "iocs": [
    {
      "type": "ip|domain|file_path|account|hostname|filename",
      "value": "string",
      "context": "string",
      "first_seen": "ISO 8601 o vacio",
      "last_seen": "ISO 8601 o vacio",
      "confidence": "ALTA|MEDIA|BAJA"
    }
  ],
  "mitre_attack": [
    {
      "technique_id": "T1110.001",
      "technique_name": "string",
      "tactics": ["Credential Access"],
      "evidence": ["ID1"],
      "confidence": "ALTA|MEDIA|BAJA"
    }
  ],
  "siem_rule_review": [
    {
      "alert_id": "SIEM-0001",
      "issue": "string",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "suggested_technique": "T1110.001",
      "suggested_tactic": "Credential Access",
      "evidence": ["ID1"]
    }
  ],
  "telemetry_gaps": ["string"],
  "data_quality_issues": ["string"],
  "recommendations": [
    {
      "priority": 1,
      "action": "string",
      "rationale": "string",
      "effort": "bajo|medio|alto",
      "references": ["H-01"]
    }
  ],
  "metrics_review": {
    "comment": "string",
    "discrepancies": ["string"]
  }
}
```

## 6. Reglas de estilo del informe

- Idioma: espanol. Sin anglicismos innecesarios (salvo nombres de tecnica).
- Cifras siempre con unidad y referencia: "25.8 MB salientes (73.7x el p95
  de 249 KB)".
- Toda cifra temporal como "6 d 8 h" o "16 min", nunca "aproximadamente".
- Nada de filler. Si un dato no existe, se dice que no existe.
- Los identificadores de evento van en `backticks` cuando se citan en prosa.
