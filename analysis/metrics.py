"""Metricas deterministas sobre los eventos normalizados.

Todo lo que se calcula aqui es aritmetica verificable sobre los logs: no
involucra juicio del modelo. El agente de opencode usa estos numeros como
insumo, no tiene que estimarlos. Es la division de trabajo que evita que
un LLM "calcule" un MTTD de memoria.
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any

OFF_HOURS = range(0, 7)  # 00:00 - 06:59 en hora local del evento


def _fmt_duration(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    if not days and not hours:
        parts.append(f"{secs}s")
    return " ".join(parts)


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    position = (len(ordered) - 1) * pct
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return float(ordered[lower] * (1 - weight) + ordered[upper] * weight)


def _iso(epoch: float) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=UTC).isoformat(timespec="seconds")


def _robust_threshold(values: list[float]) -> float:
    """Umbral de anomalias por mediana y MAD.

    El p95 no sirve como umbral con muestras pequenas: un unico valor
    extremo infla el percentil y deja de ser detectado. La mediana y la
    desviacion absoluta mediana (MAD) no se contaminan con los outliers, asi
    que el umbral se mantiene estable sea cual sea la distribucion.
    """
    if not values:
        return 0.0
    median = statistics.median(values)
    mad = statistics.median([abs(value - median) for value in values])
    if mad == 0:
        # Distribucion degenerada (todos los valores iguales o casi).
        return median * 3
    return median + 8 * 1.4826 * mad


def compute_metrics(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {"events": 0}

    timestamps = [e["ts_epoch"] for e in events if e["ts_epoch"]]
    start, end = min(timestamps), max(timestamps)

    by_source: dict[str, int] = Counter(e["source_type"] for e in events)
    by_severity: dict[str, int] = Counter(e["severity"] for e in events)

    # --- actividad fuera de horario ---------------------------------------
    off_hours_total = sum(1 for e in events if e["hour"] in OFF_HOURS)
    off_hours_by_source: dict[str, dict[str, Any]] = {}
    for source, total in by_source.items():
        subset = [e for e in events if e["source_type"] == source]
        night = sum(1 for e in subset if e["hour"] in OFF_HOURS)
        off_hours_by_source[source] = {
            "total": total,
            "off_hours": night,
            "ratio": round(night / total, 3) if total else 0.0,
        }

    # --- baseline de volumen ------------------------------------------------
    flow_events = [e for e in events if e["source_type"] in {"netflow", "firewall"} and e["bytes_out"] > 0]
    byte_values = [float(e["bytes_out"]) for e in flow_events]

    # El p95 se calcula sobre el 95% inferior de la muestra: si no, un valor
    # extremo infla su propio umbral y deja de ser detectado (p95 lineales
    # con una sola muestra contaminada). Se reporta tambien el p95 bruto.
    clean_values = byte_values
    if len(byte_values) >= 20:
        clean_values = sorted(byte_values)[: max(int(len(byte_values) * 0.95), 1)]

    baseline = {
        "samples": len(byte_values),
        "p50": _percentile(byte_values, 0.50),
        "p95": _percentile(byte_values, 0.95),
        "p95_clean": _percentile(clean_values, 0.95),
        "p99": _percentile(byte_values, 0.99),
        "max": max(byte_values) if byte_values else 0.0,
        "mean": round(statistics.fmean(byte_values), 2) if byte_values else 0.0,
        "threshold": round(_robust_threshold(byte_values), 2),
    }
    threshold = baseline["threshold"]
    outliers = (
        sorted(
            (e for e in flow_events if e["bytes_out"] > threshold),
            key=lambda e: e["bytes_out"],
            reverse=True,
        )
        if threshold
        else []
    )

    # --- senales tecnicas ----------------------------------------------------
    signals = _detect_signals(events, baseline)

    # --- alertas SIEM --------------------------------------------------------
    alerts = [e for e in events if e["source_type"] == "siem"]
    detection = _detection_metrics(alerts, signals)

    # --- contencion ----------------------------------------------------------
    containment = _containment(events, alerts)

    # --- duracion total ------------------------------------------------------
    dwell_seconds = (containment["ts"] - signals[0]["ts"]) if (containment.get("ts") and signals) else 0

    return {
        "events": len(events),
        "window": {
            "start": _iso(start),
            "end": _iso(end),
            "span_seconds": end - start,
            "span_human": _fmt_duration(end - start),
        },
        "by_source": dict(by_source),
        "by_severity": dict(by_severity),
        "off_hours": {
            "total": off_hours_total,
            "ratio": round(off_hours_total / len(events), 3) if events else 0.0,
            "by_source": off_hours_by_source,
        },
        "volume_baseline": baseline,
        "volume_outliers": [
            {
                "event_id": e["event_id"],
                "source": e["source_type"],
                "ts": e["iso_utc"],
                "src": e["src_ip"],
                "dst": e["dst_ip"],
                "port": e["dst_port"],
                "bytes_out": e["bytes_out"],
                "ratio_vs_p95": (
                    round(e["bytes_out"] / (baseline["p95_clean"] or baseline["p95"]), 1)
                    if (baseline["p95_clean"] or baseline["p95"])
                    else 0
                ),
            }
            for e in outliers[:25]
        ],
        "signals": signals,
        "detection": detection,
        "containment": containment,
        "dwell": {
            "first_signal": _iso(signals[0]["ts"]) if signals else "",
            "contained_at": _iso(containment["ts"]) if containment.get("ts") else "",
            "seconds": dwell_seconds,
            "human": _fmt_duration(dwell_seconds) if dwell_seconds else "",
        },
    }


def _detect_signals(events: list[dict[str, Any]], baseline: dict[str, Any]) -> list[dict[str, Any]]:
    """Señales tecnicas: candidatos a "primer indicio" del incidente."""
    signals: list[dict[str, Any]] = []

    # 1. Rafagas de autenticacion fallida por usuario.
    failures: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        if event["source_type"] == "authentication" and event["result"].upper() == "FAILURE":
            failures[event["actor"]].append(event)

    for user, items in failures.items():
        items.sort(key=lambda e: e["ts_epoch"])
        window_start = 0
        for index, item in enumerate(items):
            if item["ts_epoch"] - items[window_start]["ts_epoch"] > 900:
                window_start = index
            burst = items[window_start : index + 1]
            if len(burst) >= 3:
                signals.append(
                    {
                        "ts": burst[0]["ts_epoch"],
                        "iso": burst[0]["iso_utc"],
                        "kind": "auth_failure_burst",
                        "actor": user,
                        "source": "authentication",
                        "event_id": burst[0]["event_id"],
                        "detail": f"{len(burst)} fallos de autenticacion en <15 min para {user}",
                        "refs": [b["event_id"] for b in burst],
                    }
                )

    # 2. Detecciones de antivirus / EDR.
    for event in events:
        if event["source_type"] == "antivirus" and event["severity"] in {"HIGH", "CRITICAL"}:
            signals.append(
                {
                    "ts": event["ts_epoch"],
                    "iso": event["iso_utc"],
                    "kind": "malware_detection",
                    "actor": event["actor"],
                    "source": "antivirus",
                    "event_id": event["event_id"],
                    "detail": f"{event['event_type']} ({event['action']}) en {event['host']}",
                    "refs": [event["event_id"]],
                }
            )

    # 3. Transferencias salientes anomalas.
    reference = baseline.get("threshold") or 0
    if reference:
        threshold = reference
        for event in events:
            if event["source_type"] in {"netflow", "firewall"} and event["bytes_out"] > threshold:
                signals.append(
                    {
                        "ts": event["ts_epoch"],
                        "iso": event["iso_utc"],
                        "kind": "exfil_volume",
                        "actor": "",
                        "source": event["source_type"],
                        "event_id": event["event_id"],
                        "detail": (
                            f"Salida anomala de {event['bytes_out']:,} B hacia {event['dst_ip']} "
                            f"({round(event['bytes_out'] / reference, 1)}x p95)"
                        ),
                        "refs": [event["event_id"]],
                    }
                )

    # 4. Ejecucion desde shell de cuenta de servicio.
    for event in events:
        if event["source_type"] == "system" and "service_account" in event["event_type"]:
            signals.append(
                {
                    "ts": event["ts_epoch"],
                    "iso": event["iso_utc"],
                    "kind": "service_account_abuse",
                    "actor": event["actor"],
                    "source": "system",
                    "event_id": event["event_id"],
                    "detail": event["detail"],
                    "refs": [event["event_id"]],
                }
            )

    # 5. Acceso a datos sensibles.
    for event in events:
        if event["source_type"] == "system" and event["event_type"] in {
            "sensitive_file_access",
            "archive_created",
            "large_outbound_transfer",
        }:
            signals.append(
                {
                    "ts": event["ts_epoch"],
                    "iso": event["iso_utc"],
                    "kind": "collection",
                    "actor": event["actor"],
                    "source": "system",
                    "event_id": event["event_id"],
                    "detail": event["detail"],
                    "refs": [event["event_id"]],
                }
            )

    signals.sort(key=lambda s: s["ts"])
    # Deduplica por (kind, event_id) mantendo el primero.
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for signal in signals:
        key = (signal["kind"], signal["event_id"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(signal)
    return unique


def _detection_metrics(alerts: list[dict[str, Any]], signals: list[dict[str, Any]]) -> dict[str, Any]:
    """MTTD: del primer indicio tecnico a la alerta que lo cubre."""
    per_alert = []
    deltas: list[float] = []
    for alert in alerts:
        best = None
        for signal in signals:
            delta = alert["ts_epoch"] - signal["ts"]
            if -300 <= delta <= 3600:
                if best is None or signal["ts"] < best[0]["ts"]:
                    best = (signal, delta)
        if best is None:
            per_alert.append(
                {
                    "alert_id": alert["event_id"],
                    "ts": alert["iso_utc"],
                    "severity": alert["severity"],
                    "mttd_seconds": None,
                    "mttd_human": "sin senal correlacionada",
                    "signal": None,
                }
            )
            continue
        signal, delta = best
        deltas.append(delta)
        per_alert.append(
            {
                "alert_id": alert["event_id"],
                "ts": alert["iso_utc"],
                "severity": alert["severity"],
                "mttd_seconds": int(delta),
                "mttd_human": _fmt_duration(delta),
                "signal": {
                    "kind": signal["kind"],
                    "event_id": signal["event_id"],
                    "iso": signal["iso"],
                    "detail": signal["detail"],
                },
            }
        )

    return {
        "alerts": len(alerts),
        "alerts_with_correlated_signal": len(deltas),
        "mttd_median_seconds": int(statistics.median(deltas)) if deltas else None,
        "mttd_median_human": _fmt_duration(statistics.median(deltas)) if deltas else "",
        "mttd_max_seconds": int(max(deltas)) if deltas else None,
        "mttd_max_human": _fmt_duration(max(deltas)) if deltas else "",
        "per_alert": per_alert,
    }


CONTAINMENT_TYPES = {
    "service_stop",
    "account_lockout",
    "emergency_isolation",
    "containment",
    "host_isolated",
    "session_terminated",
}


def _containment(events: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for event in events:
        if event["source_type"] == "system" and event["event_type"] in CONTAINMENT_TYPES:
            candidates.append(
                {
                    "ts": event["ts_epoch"],
                    "iso": event["iso_utc"],
                    "event_id": event["event_id"],
                    "source": "system",
                    "detail": event["detail"] or event["event_type"],
                }
            )
    for alert in alerts:
        tactic = (alert.get("raw", {}).get("tactic") or alert.get("event_type") or "").lower()
        if "contain" in tactic or "isolation" in (alert.get("raw", {}).get("technique_name") or "").lower():
            candidates.append(
                {
                    "ts": alert["ts_epoch"],
                    "iso": alert["iso_utc"],
                    "event_id": alert["event_id"],
                    "source": "siem",
                    "detail": alert["detail"],
                }
            )
    if not candidates:
        return {}
    candidates.sort(key=lambda c: c["ts"])
    last = candidates[-1]
    return {
        "ts": last["ts"],
        "iso": last["iso"],
        "event_id": last["event_id"],
        "source": last["source"],
        "detail": last["detail"],
        "all": candidates,
    }


def timeline_histogram(events: list[dict[str, Any]], buckets: int = 48) -> list[dict[str, Any]]:
    """Histograma temporal para pintar en el dashboard."""
    stamps = [e["ts_epoch"] for e in events if e["ts_epoch"]]
    if not stamps:
        return []
    start, end = min(stamps), max(stamps)
    span = max(end - start, 1)
    width = span / buckets
    counts = [0] * buckets
    severities: list[Counter] = [Counter() for _ in range(buckets)]
    for event in events:
        if not event["ts_epoch"]:
            continue
        index = min(int((event["ts_epoch"] - start) / width), buckets - 1)
        counts[index] += 1
        severities[index][event["severity"]] += 1
    return [
        {
            "bucket": index,
            "start": _iso(start + index * width),
            "end": _iso(start + (index + 1) * width),
            "count": counts[index],
            "severities": dict(severities[index]),
        }
        for index in range(buckets)
    ]


def hour_histogram(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Distribucion por hora del dia: delata actividad en horarioinhumano."""
    counts = [0] * 24
    critical = [0] * 24
    for event in events:
        if event["hour"] < 0:
            continue
        counts[event["hour"]] += 1
        if event["severity"] in {"HIGH", "CRITICAL"}:
            critical[event["hour"]] += 1
    return [{"hour": hour, "count": counts[hour], "high_severity": critical[hour]} for hour in range(24)]
