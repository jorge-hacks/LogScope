#!/usr/bin/env python3
"""Genera un conjunto de logs de demostracion para probar LogScope.

El dataset es sintetico y esta construido para que la aplicacion muestre
resultados representativos: una intrusion multietapa (acceso por credencial
valida, ejecucion en el puesto, persistencia, movimiento lateral, recoleccion
y exfiltracion) sobre un fondo de trafico empresarial normal.

No contiene datos reales: hostnames, usuarios, direcciones y volumetricos son
inventados y las direcciones externas pertenecen a los rangos de
documentacion de la RFC 5737.

Uso:
    python scripts/demo_dataset.py --output /tmp/demo_logs
"""

from __future__ import annotations

import argparse
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

TZ = timezone(timedelta(hours=-3))  # UTC-03:00, como en el caso de referencia

INICIO = datetime(2025, 5, 5, 8, 0, 0, tzinfo=TZ)
DIAS = 7

# Actores e infraestructura ficticios
USUARIOS = ["a.torres", "b.lopez", "c.ramos", "d.perez"]
HOSTS = {
    "WS-014": ("10.60.20.14", "Windows"),
    "WS-027": ("10.60.20.27", "Windows"),
    "SRV-APP01": ("10.60.30.21", "Linux"),
    "SRV-DB01": ("10.60.30.31", "Windows"),
    "SRV-FILE01": ("10.60.40.15", "Linux"),
    "SRV-AD01": ("10.60.10.10", "Windows"),
}
PERIMETRO = "10.60.10.5"
VPN = "VPN01"
SERVICIO = "svc_report"

EXTERNO_C2 = "198.51.100.10"
EXTERNO_EXFIL = "203.0.113.10"
EXTERNO_SCAN = "192.0.2.10"
EXTERNO_SCAN2 = "203.0.113.20"

random.seed(20250505)


def ts(dia: int, hora: int, minuto: int, segundo: int = 0) -> str:
    momento = INICIO + timedelta(days=dia, hours=hora, minutes=minuto, seconds=segundo)
    return momento.isoformat()


def escribir(nombre: str, cabeceras: list[str], filas: list[list]) -> None:
    ruta = Path(args.output) / nombre
    with ruta.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(cabeceras)
        writer.writerows(filas)
    print(f"  {nombre:26} {len(filas):4} filas")


# ---------------------------------------------------------------------------
# Autenticacion
# ---------------------------------------------------------------------------
def autenticacion() -> list[list]:
    filas = []
    n = 0

    def nuevo(usuario, origen, destino, tipo, resultado, detalle, dia, hora, minuto):
        nonlocal n
        n += 1
        filas.append(
            [
                f"AUTH-{n:05d}",
                ts(dia, hora, minuto),
                usuario,
                origen,
                destino,
                tipo,
                resultado,
                detalle,
                "",
            ]
        )

    # Trafico de fondo: inicio de sesion habitual en horario laboral
    for dia in range(DIAS):
        for _ in range(5):
            usuario = random.choice(USUARIOS)
            nuevo(
                usuario,
                random.choice([HOSTS["WS-014"][0], HOSTS["WS-027"][0]]),
                "SRV-APP01",
                "interactive_logon",
                "SUCCESS",
                "Inicio de sesion habitual",
                dia,
                random.randint(8, 18),
                random.randint(0, 59),
            )

    # Intrusion: ocho fallos contra el VPN y un acceso valido (dia 2, madrugada)
    for i in range(8):
        nuevo("a.torres", EXTERNO_C2, VPN, "vpn_login", "FAILURE", "Credenciales invalidas", 2, 1, 2 + i * 2)
    nuevo("a.torres", EXTERNO_C2, VPN, "vpn_login", "SUCCESS", "Acceso VPN fuera de horario", 2, 1, 21)
    nuevo("a.torres", HOSTS["WS-014"][0], "SRV-APP01", "interactive_logon", "SUCCESS", "Sesion remota posterior a VPN", 2, 1, 26)

    # Intrusion: uso de la cuenta de servicio (dia 3, madrugada)
    nuevo(SERVICIO, HOSTS["SRV-APP01"][0], "SRV-DB01", "service_logon", "SUCCESS", "Autenticacion de servicio inusual", 3, 0, 58)
    nuevo(
        SERVICIO,
        HOSTS["SRV-APP01"][0],
        "SRV-DB01",
        "privilege_escalation",
        "SUCCESS",
        "Asignacion temporal de privilegio elevado",
        3,
        1,
        2,
    )
    filas[-1][-1] = "LOCAL_ADMIN"

    # Intrusion: staging y acceso a base de datos (dia 4, madrugada)
    nuevo(SERVICIO, HOSTS["SRV-APP01"][0], "SRV-FILE01", "network_logon", "SUCCESS", "Acceso SMB fuera de horario", 4, 3, 35)
    nuevo(SERVICIO, HOSTS["SRV-APP01"][0], "SRV-DB01", "database_login", "SUCCESS", "Acceso a esquema de clientes", 4, 3, 39)

    # Reutilizacion de la credencial de servicio (dia 6)
    nuevo(SERVICIO, HOSTS["SRV-APP01"][0], "SRV-DB01", "service_logon", "SUCCESS", "Reutilizacion de credencial de servicio", 6, 1, 54)

    # Trafico de fondo en cuentas de servicio
    for dia in range(DIAS):
        nuevo(SERVICIO, HOSTS["SRV-DB01"][0], "SRV-AD01", "service_logon", "SUCCESS", "Sincronizacion programada", dia, 3, 0)

    # Cambio administrativo legitimate (dia 6)
    nuevo("admin.local", HOSTS["SRV-AD01"][0], "SRV-AD01", "privilege_escalation", "SUCCESS", "Cambio administrativo autorizado", 6, 2, 10)
    filas[-1][-1] = "DOMAIN_ADMIN"

    return filas


# ---------------------------------------------------------------------------
# Firewall
# ---------------------------------------------------------------------------
def firewall() -> list[list]:
    filas = []
    n = 0

    def nuevo(origen, puerto_o, destino, puerto_d, accion, regla, enviados, recibidos, app, usuario=""):
        nonlocal n
        n += 1
        filas.append(
            [
                f"FW-{n:05d}",
                ts(0, 0, 0),
                origen,
                puerto_o,
                destino,
                puerto_d,
                "TCP",
                accion,
                regla,
                enviados,
                recibidos,
                app,
                usuario,
            ]
        )

    def nuevo_en(momento, origen, puerto_o, destino, puerto_d, accion, regla, enviados, recibidos, app, usuario=""):
        nonlocal n
        n += 1
        filas.append(
            [
                f"FW-{n:05d}",
                momento,
                origen,
                puerto_o,
                destino,
                puerto_d,
                "TCP",
                accion,
                regla,
                enviados,
                recibidos,
                app,
                usuario,
            ]
        )

    # Trafico interno de fondo
    for _ in range(70):
        origen, destino = random.sample(list(HOSTS.values()), 2)
        nuevo_en(
            ts(random.randint(0, DIAS - 1), random.randint(8, 18), random.randint(0, 59)),
            origen[0],
            random.randint(30000, 65000),
            destino[0],
            random.choice([443, 445, 1433, 389, 53]),
            "ALLOW",
            "CORP_INTERNAL",
            random.randint(2000, 90000),
            random.randint(2000, 60000),
            "internal-service",
        )

    # Reconocimiento externo bloqueado en el perimetro
    for _ in range(12):
        nuevo_en(
            ts(random.randint(0, DIAS - 1), random.randint(0, 23), random.randint(0, 59)),
            random.choice([EXTERNO_SCAN, EXTERNO_SCAN2, EXTERNO_C2]),
            random.randint(40000, 65000),
            PERIMETRO,
            random.choice([22, 443, 445, 3389, 8080]),
            "DENY",
            "WAN_INBOUND_DEFAULT_DENY",
            random.randint(80, 420),
            0,
            "scan-or-probe",
        )

    # Trafico de mando y control saliente
    nuevo_en(ts(2, 2, 14), HOSTS["WS-014"][0], 53122, EXTERNO_C2, 443, "ALLOW", "USER_WEB_EGRESS", 184200, 1200, "TLS", "a.torres")
    nuevo_en(ts(2, 2, 19), HOSTS["WS-014"][0], 53129, EXTERNO_C2, 443, "ALLOW", "USER_WEB_EGRESS", 932100, 2200, "TLS", "a.torres")
    nuevo_en(ts(3, 1, 8), HOSTS["SRV-APP01"][0], 55001, EXTERNO_SCAN, 8443, "ALLOW", "SERVER_EGRESS_RESTRICTED", 48700, 900, "unknown-tls", SERVICIO)
    nuevo_en(ts(3, 1, 16), HOSTS["SRV-APP01"][0], 55009, EXTERNO_SCAN, 8443, "ALLOW", "SERVER_EGRESS_RESTRICTED", 1284000, 3100, "unknown-tls", SERVICIO)
    nuevo_en(ts(6, 2, 7), HOSTS["SRV-APP01"][0], 55311, EXTERNO_SCAN, 8443, "ALLOW", "SERVER_EGRESS_RESTRICTED", 956000, 2500, "unknown-tls", SERVICIO)

    # Intento de salida por SSH bloqueado
    nuevo_en(ts(5, 0, 32), HOSTS["WS-014"][0], 55201, EXTERNO_SCAN2, 22, "DENY", "OUTBOUND_SSH_BLOCK", 1200, 0, "SSH", "a.torres")

    # Exfiltracion
    nuevo_en(ts(4, 3, 42), HOSTS["SRV-DB01"][0], 55110, EXTERNO_EXFIL, 443, "ALLOW", "DB_EGRESS_LIMITED", 7420000, 4500, "TLS")
    nuevo_en(ts(4, 3, 51), HOSTS["SRV-DB01"][0], 55117, EXTERNO_EXFIL, 443, "ALLOW", "DB_EGRESS_LIMITED", 18400000, 6100, "TLS")

    return filas


# ---------------------------------------------------------------------------
# Netflow
# ---------------------------------------------------------------------------
def netflow() -> list[list]:
    filas = []
    n = 0

    def nuevo(momento, origen, destino, puerto_o, puerto_d, paquetes, bytes_, direccion, app):
        nonlocal n
        n += 1
        filas.append(
            [
                f"NF-{n:05d}",
                momento,
                origen,
                destino,
                puerto_o,
                puerto_d,
                "TCP",
                paquetes,
                bytes_,
                direccion,
                app,
            ]
        )

    for _ in range(110):
        origen, destino = random.sample(list(HOSTS.values()), 2)
        nuevo(
            ts(random.randint(0, DIAS - 1), random.randint(8, 18), random.randint(0, 59)),
            origen[0],
            destino[0],
            random.randint(30000, 65000),
            random.choice([443, 445, 1433]),
            random.randint(10, 500),
            random.randint(50000, 250000),
            "EAST_WEST",
            "business-traffic",
        )

    nuevo(ts(2, 2, 14), HOSTS["WS-014"][0], EXTERNO_C2, 50157, 443, 204, 184200, "OUTBOUND", "unknown-encrypted")
    nuevo(ts(2, 2, 19), HOSTS["WS-014"][0], EXTERNO_C2, 56124, 443, 1035, 932100, "OUTBOUND", "unknown-encrypted")
    nuevo(ts(3, 1, 8), HOSTS["SRV-APP01"][0], EXTERNO_SCAN, 55293, 8443, 54, 48700, "OUTBOUND", "unknown-encrypted")
    nuevo(ts(3, 1, 16), HOSTS["SRV-APP01"][0], EXTERNO_SCAN, 55894, 8443, 1426, 1284000, "OUTBOUND", "unknown-encrypted")
    nuevo(ts(4, 3, 35), HOSTS["SRV-APP01"][0], HOSTS["SRV-FILE01"][0], 51802, 445, 1171, 820000, "EAST_WEST", "smb-or-database")
    nuevo(ts(4, 3, 39), HOSTS["SRV-APP01"][0], HOSTS["SRV-DB01"][0], 51854, 1433, 178, 125000, "EAST_WEST", "smb-or-database")
    nuevo(ts(4, 3, 42), HOSTS["SRV-DB01"][0], EXTERNO_EXFIL, 57344, 443, 8244, 7420000, "OUTBOUND", "unknown-encrypted")
    nuevo(ts(4, 3, 51), HOSTS["SRV-DB01"][0], EXTERNO_EXFIL, 54968, 443, 20444, 18400000, "OUTBOUND", "unknown-encrypted")
    nuevo(ts(3, 1, 31), HOSTS["SRV-APP01"][0], HOSTS["SRV-DB01"][0], 50211, 445, 457, 320000, "EAST_WEST", "smb-or-database")

    return filas


# ---------------------------------------------------------------------------
# Antivirus
# ---------------------------------------------------------------------------
def antivirus() -> list[list]:
    return [
        ["AV-00001", ts(2, 2, 22), "WS-014", HOSTS["WS-014"][0], "Trojan.Generic.DLL", "HIGH", "DETECTED", "QUARANTINED", r"C:\Users\a.torres\AppData\Roaming\updater.dll", "a.torres"],
        ["AV-00002", ts(2, 2, 25), "WS-014", HOSTS["WS-014"][0], "PowerShell.Downloader", "HIGH", "DETECTED", "BLOCKED", "powershell.exe -enc [cadena_base64_redactada]", "a.torres"],
        ["AV-00003", ts(3, 1, 12), "SRV-APP01", HOSTS["SRV-APP01"][0], "Backdoor.WebShell", "CRITICAL", "DETECTED", "NOT_REMOVED", "/var/www/html/cache/cache.php", SERVICIO],
        ["AV-00004", ts(4, 3, 48), "SRV-DB01", HOSTS["SRV-DB01"][0], "HackTool.CredDump", "CRITICAL", "DETECTED", "QUARANTINED", r"C:\ProgramData\cache\dump_tool.exe", ""],
        ["AV-00005", ts(6, 2, 11), "SRV-APP01", HOSTS["SRV-APP01"][0], "Backdoor.WebShell", "CRITICAL", "DETECTED", "ACTIVE", "/var/www/html/cache/cache.php", SERVICIO],
        ["AV-00006", ts(6, 4, 30), "WS-027", HOSTS["WS-027"][0], "PUA.RemoteAdmin", "MEDIUM", "DETECTED", "QUARANTINED", r"C:\Temp\remote_support.exe", "d.perez"],
    ]


# ---------------------------------------------------------------------------
# Sistema
# ---------------------------------------------------------------------------
def sistema() -> list[list]:
    filas = []

    def nuevo(evento, momento, host, tipo, severidad, mensaje, usuario="", origen="Linux-Audit"):
        filas.append(
            [
                f"SYS-{len(filas) + 1:05d}",
                momento,
                host,
                HOSTS.get(host, ("", ""))[0],
                origen,
                tipo,
                severidad,
                mensaje,
                usuario,
            ]
        )

    for dia in range(DIAS):
        nuevo("service_start", ts(dia, 8, 0), "SRV-APP01", "service_start", "INFO", "Servicio web iniciado correctamente")
    nuevo("process_creation", ts(2, 2, 20), "WS-014", "process_creation", "HIGH", "Proceso powershell.exe ejecutado con parametros codificados", "a.torres", "Windows-Security")
    nuevo("scheduled_task_created", ts(2, 2, 23), "WS-014", "scheduled_task_created", "HIGH", "Tarea UpdateCheck creada para persistencia", "a.torres", "Windows-Security")
    nuevo("web_file_modified", ts(3, 1, 10), "SRV-APP01", "web_file_modified", "CRITICAL", "Archivo cache.php creado en directorio web publico", SERVICIO)
    nuevo("service_account_shell", ts(3, 1, 14), "SRV-APP01", "service_account_shell", "CRITICAL", "Shell interactiva iniciada por cuenta de servicio", SERVICIO)
    nuevo("remote_service_created", ts(3, 1, 30), "SRV-DB01", "remote_service_created", "HIGH", "Servicio remoto temporal instalado desde APP01", SERVICIO, "Windows-Security")
    nuevo("sensitive_file_access", ts(4, 3, 40), "SRV-DB01", "sensitive_file_access", "CRITICAL", "Lectura masiva de tabla customer_orders", SERVICIO, "Windows-Security")
    nuevo("archive_created", ts(4, 3, 46), "SRV-DB01", "archive_created", "HIGH", "Archivo comprimido orders_20250510.7z creado en directorio temporal", SERVICIO, "Windows-Security")
    nuevo("large_outbound_transfer", ts(4, 3, 53), "SRV-DB01", "large_outbound_transfer", "CRITICAL", "Transferencia saliente anomala detectada; volumen elevado", "", "Windows-Security")
    nuevo("scheduled_task_executed", ts(5, 0, 29), "WS-014", "scheduled_task_executed", "HIGH", "Tarea UpdateCheck ejecutada fuera de horario", "a.torres", "Windows-Security")
    nuevo("webshell_execution", ts(6, 2, 9), "SRV-APP01", "webshell_execution", "CRITICAL", "Ejecucion de comandos mediante cache.php", SERVICIO)
    nuevo("account_lockout", ts(6, 4, 35), "SRV-DB01", "account_lockout", "MEDIUM", "Cuenta svc_report bloqueada tras multiples intentos", SERVICIO, "Windows-Security")
    nuevo("service_stop", ts(6, 9, 15), "SRV-APP01", "service_stop", "INFO", "Servicio web detenido por mantenimiento de emergencia")

    return filas


# ---------------------------------------------------------------------------
# Alertas SIEM
# ---------------------------------------------------------------------------
def siem() -> list[list]:
    return [
        ["SIEM-0001", ts(2, 1, 18), "Credential Access", "T1110.003", "Password Spraying", EXTERNO_C2, VPN, "a.torres", "HIGH", "AUTH-000?", "8 fallos de autenticacion VPN en 15 minutos; origen externo"],
        ["SIEM-0002", ts(2, 1, 24), "Initial Access", "T1078", "Valid Accounts", EXTERNO_C2, VPN, "a.torres", "CRITICAL", "AUTH-000?", "Inicio de sesion VPN exitoso tras multiples fallos"],
        ["SIEM-0003", ts(2, 2, 26), "Execution", "T1059.001", "PowerShell", HOSTS["WS-014"][0], "WS-014", "a.torres", "HIGH", "AV-00002;SYS-00001", "PowerShell codificado y malware descargador detectado"],
        ["SIEM-0004", ts(2, 2, 28), "Command and Control", "T1071.001", "Web Protocols", HOSTS["WS-014"][0], "WS-014", "a.torres", "HIGH", "FW-00091;NF-00121", "Conexiones HTTPS repetitivas a destino externo no reconocido"],
        ["SIEM-0005", ts(3, 1, 15), "Persistence", "T1505.003", "Web Shell", HOSTS["SRV-APP01"][0], "SRV-APP01", SERVICIO, "CRITICAL", "AV-00003;SYS-00004", "Web shell detectada en directorio publico; remocion no confirmada"],
        ["SIEM-0006", ts(3, 1, 34), "Privilege Escalation", "T1068", "Exploitation for Privilege Escalation", HOSTS["SRV-APP01"][0], "SRV-DB01", SERVICIO, "CRITICAL", "AUTH-000?;SYS-00006", "Uso de cuenta de servicio con privilegios elevados y servicio remoto"],
        ["SIEM-0007", ts(4, 3, 44), "Collection", "T1005", "Data from Local System", HOSTS["SRV-APP01"][0], "SRV-DB01", SERVICIO, "CRITICAL", "SYS-00007;AUTH-000?", "Acceso masivo a datos de clientes"],
        ["SIEM-0008", ts(4, 3, 55), "Exfiltration", "T1041", "Exfiltration Over C2 Channel", HOSTS["SRV-DB01"][0], "SRV-DB01", "", "CRITICAL", "FW-000?;NF-000?", "Volumen saliente elevado hacia IP externa no reconocida"],
        ["SIEM-0009", ts(5, 0, 35), "Command and Control", "T1071.001", "Web Protocols", HOSTS["WS-014"][0], "WS-014", "a.torres", "MEDIUM", "SYS-00010;FW-000?", "Ejecucion de tarea programada y nuevo intento de conexion externa"],
        ["SIEM-0010", ts(6, 2, 14), "Execution", "T1505.003", "Web Shell", HOSTS["SRV-APP01"][0], "SRV-APP01", SERVICIO, "CRITICAL", "AV-00005;SYS-00011", "Web shell activa y ejecucion de comandos confirmada"],
        ["SIEM-0011", ts(6, 4, 38), "Credential Access", "T1110", "Brute Force", HOSTS["SRV-DB01"][0], "SRV-DB01", SERVICIO, "MEDIUM", "SYS-00012;AUTH-000?", "Multiples intentos y bloqueo de cuenta de servicio"],
        ["SIEM-0012", ts(6, 9, 20), "Containment", "N/A", "Emergency Isolation", HOSTS["SRV-APP01"][0], "SRV-APP01", "", "INFO", "SYS-00013", "Servicio web detenido durante mantenimiento de emergencia"],
    ]


def main() -> int:
    global args
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/tmp/logscope-demo"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)

    print(f"Generando dataset de demostracion en {args.output}")
    escribir(
        "authentication_logs.csv",
        ["event_id", "timestamp", "username", "source_ip", "destination_host", "event_type", "result", "details", "privilege_change"],
        autenticacion(),
    )
    escribir(
        "firewall_logs.csv",
        ["event_id", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "action", "rule_name", "bytes_sent", "bytes_received", "application", "username"],
        firewall(),
    )
    escribir(
        "netflow_logs.csv",
        ["flow_id", "start_time", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "packets", "bytes", "direction", "application"],
        netflow(),
    )
    escribir(
        "antivirus_logs.csv",
        ["event_id", "timestamp", "hostname", "host_ip", "threat_name", "severity", "detection_status", "action_taken", "file_path_or_command", "associated_user"],
        antivirus(),
    )
    escribir(
        "system_logs.csv",
        ["event_id", "timestamp", "hostname", "host_ip", "log_source", "event_type", "severity", "message", "username"],
        sistema(),
    )
    escribir(
        "siem_alerts.csv",
        ["alert_id", "timestamp", "tactic", "technique_id", "technique_name", "source_ip", "destination_or_host", "username", "severity", "related_event_ids", "description"],
        siem(),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
