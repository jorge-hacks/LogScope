# Espacios de trabajo

Cada analisis vive en su propio subdirectorio:

```
workspaces/<id>/
├── raw/            ficheros originales tal cual los subiste
├── normalized/     events.jsonl con el esquema unificado
├── analysis/       metrics.json, integrity.json, ingest.json
├── report/         report.json (validado) y report.md
└── analysis.json   metadatos del analisis
```

Este directorio esta en `.gitignore`: los logs son datos sensibles de los
clientes y no deben subir al repositorio ni por error.
