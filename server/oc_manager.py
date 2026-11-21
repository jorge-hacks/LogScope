"""Gestion del servidor headless de opencode.

LogScope arranca y supervisa su propio `opencode serve`, de modo que la
aplicacion es autocontenida: basta con `uvicorn server.main:app`.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shutil
import signal
import subprocess
from pathlib import Path

from server.config import settings
from server.oc_client import OpencodeClient, OpencodeError


class OpencodeManager:
    """Arranca, supervisa y detiene el servidor de opencode."""

    def __init__(self) -> None:
        self.process: subprocess.Popen | None = None
        self.log_path: Path = settings.project_root / "logs" / "opencode.log"
        self._lock = asyncio.Lock()

    # -- binario -------------------------------------------------------------
    def binary(self) -> str:
        candidate = settings.opencode_bin
        if candidate and Path(candidate).exists():
            return candidate
        found = shutil.which("opencode")
        if found:
            return found
        raise OpencodeError(
            "No se encuentra el ejecutable de opencode. "
            "Define LOGSCOPE_OPENCODE_BIN en el .env o instalalo en el PATH."
        )

    # -- ciclo de vida -------------------------------------------------------
    async def start(self, timeout: float = 40.0) -> None:
        async with self._lock:
            if self.process and self.process.poll() is None:
                return
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            env = dict(os.environ)
            env.setdefault("OPENCODE_DISABLE_DEFAULT_PLUGINS", "0")

            command = [
                self.binary(),
                "serve",
                "--port",
                str(settings.opencode_port),
                "--hostname",
                "127.0.0.1",
            ]
            log_handle = self.log_path.open("ab")
            self.process = subprocess.Popen(  # noqa: S603
                command,
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                cwd=str(settings.project_root),
                env=env,
                start_new_session=True,
            )
            await self._wait_healthy(timeout)

    async def _wait_healthy(self, timeout: float) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        last_error: Exception | None = None
        while asyncio.get_running_loop().time() < deadline:
            if self.process and self.process.poll() is not None:
                raise OpencodeError(
                    f"opencode termino de forma inesperada (codigo {self.process.returncode}). "
                    f"Revisa {self.log_path}"
                )
            try:
                async with OpencodeClient(settings.opencode_base_url, timeout=5.0) as client:
                    await client.health()
                return
            except (OpencodeError, OSError) as exc:
                last_error = exc
                await asyncio.sleep(0.6)
        raise OpencodeError(f"opencode no arranco en {timeout:.0f}s: {last_error}")

    async def ensure_running(self) -> None:
        async with OpencodeClient(settings.opencode_base_url, timeout=5.0) as client:
            if await client.is_healthy():
                return
        await self.start()

    async def stop(self) -> None:
        async with self._lock:
            process = self.process
            self.process = None
            if process and process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(os.getpgid(process.pid), signal.SIGKILL)

    @property
    def running(self) -> bool:
        return self.process is not None and self.process.poll() is None


manager = OpencodeManager()
