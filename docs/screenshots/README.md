# 📸 Capturas de pantalla

Imágenes que se referencian desde los README (inglés y español).

## Nomenclatura

| Fichero | Contenido | Uso en el README |
|---|---|---|
| `01-inicio.png` | Subida de logs y selector de modelo | Sección de capturas |
| `02-cronologia.png` | Timeline, MTTD, permanencia | Sección de capturas |
| `03-hallazgos.png` | Hallazgos con evidencia y ATT&CK | Sección de capturas |
| `04-attack.png` | Tabla de mapeo MITRE ATT&CK | Tabla comparativa |
| `05-reglas-siem.png` | Revisión de las reglas de detección | Tabla comparativa |
| `06-iocs.png` | Indicadores de compromiso | Sección de capturas |
| `07-eventos.png` | Tabla de eventos filtrable | Sección de capturas |
| `08-informe.png` | Informe generado | Sección de capturas |
| `09-ajustes.png` | Presets y configuración efectiva | Sección de modelo |

## Cómo sustituirlas

1. Levanta la app y abre el análisis que quieras (`./scripts/run.sh`).
2. Captura con tu herramienta habitual o regenera todas con:

   ```bash
   ./scripts/screenshots.sh              # usa el análisis más reciente con informe
   ./scripts/screenshots.sh 20261120-090006-c9a632
   ```

3. Mantén los **mismos nombres**: los README los referencian por ruta.
4. Si añades una captura nueva, añádela con el siguiente número y
   referénciala en `README.md` y `README.es.md`.

## Recomendaciones

- **Ancho 1600 px**: en GitHub se renderiza a ~1012 px de ancho real.
- **Oculta las barras de desplazamiento** (`--hide-scrollbars`).
- Evita datos reales de clientes: usa un caso con IPs de documentación
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).
