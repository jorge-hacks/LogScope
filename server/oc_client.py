"""Cliente asincrono de la API de opencode (version 1.x, sin prefijo /api).

Contrato verificado contra opencode 1.19.6:

  POST /session?directory=<abs>      -> crea sesion (directory va en query)
  POST /session/{id}/message         -> envia mensaje (bloqueante hasta el fin)
  GET  /session/{id}/message         -> historial de mensajes
  GET  /event?directory=<abs>        -> SSE con los eventos de la sesion
  GET  /provider                     -> catalogo de proveedores y modelos
  GET  /global/health                -> {"healthy":true,...}

Dos trampas del servidor que este cliente neutraliza:
  1. Cualquier ruta desconocida devuelve 200 con el HTML de la web de
     opencode. Por eso se valida el content-type, no solo el codigo.
  2. El stream SSE solo entrega eventos de las sesiones del directorio
     indicado en ?directory=. Sin ese parametro no llega nada.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx


class OpencodeError(RuntimeError):
    """Error del servidor de opencode."""

    def __init__(self, message: str, status: int = 0, payload: dict | None = None):
        super().__init__(message)
        self.status = status
        self.payload = payload or {}


class ModelUnavailable(OpencodeError):
    """El modelo pedido no existe o ya no esta disponible."""


class OpencodeClient:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=httpx.Timeout(timeout, read=600.0, write=60.0, connect=10.0),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> OpencodeClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def _json(response: httpx.Response) -> dict[str, Any]:
        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            # Ruta desconocida servida por el SPA web: no es un error de API.
            raise OpencodeError(
                f"Respuesta no-JSON del servidor de opencode ({content_type or 'sin content-type'}). "
                "Probablemente ruta inexistente.",
                status=response.status_code,
            )
        try:
            return response.json()
        except json.JSONDecodeError as exc:
            raise OpencodeError("Respuesta JSON invalida del servidor de opencode", status=response.status_code) from exc

    @staticmethod
    def _split_model(full_id: str) -> tuple[str, str]:
        if "/" in full_id:
            provider, model = full_id.split("/", 1)
            return provider, model
        raise OpencodeError(f"Modelo con formato invalido: {full_id!r} (se espera provider/model)")

    # -- API -----------------------------------------------------------------
    async def health(self) -> dict[str, Any]:
        try:
            response = await self._client.get("/global/health")
        except httpx.HTTPError as exc:
            raise OpencodeError(f"No se puede contactar con opencode: {exc}") from exc
        if response.status_code != 200:
            raise OpencodeError("opencode no responde correctamente", status=response.status_code)
        return self._json(response)

    async def is_healthy(self) -> bool:
        try:
            await self.health()
        except OpencodeError:
            return False
        return True

    async def provider_payload(self) -> dict[str, Any]:
        response = await self._client.get("/provider")
        return self._json(response)

    async def create_session(self, directory: str, title: str) -> str:
        response = await self._client.post(
            "/session",
            params={"directory": directory},
            json={"title": title},
        )
        if response.status_code >= 400:
            raise OpencodeError(f"No se pudo crear la sesion: {response.text[:200]}", status=response.status_code)
        payload = self._json(response)
        session_id = payload.get("id")
        if not session_id:
            raise OpencodeError("opencode no devolvio id de sesion")
        return session_id

    async def send_message(
        self,
        session_id: str,
        text: str,
        model: str | None = None,
        agent: str | None = None,
    ) -> dict[str, Any]:
        """Envia un mensaje y espera a que termine el turno."""
        body: dict[str, Any] = {"parts": [{"type": "text", "text": text}]}
        if model:
            provider, model_id = self._split_model(model)
            body["model"] = {"providerID": provider, "modelID": model_id}
        if agent:
            body["agent"] = agent

        response = await self._client.post(f"/session/{session_id}/message", json=body)
        if response.status_code >= 500:
            # Formato observado cuando el modelo no existe o fue retirado.
            payload = self._json(response) if "json" in response.headers.get("content-type", "") else {}
            message = (payload.get("data") or {}).get("message", response.text[:200])
            raise ModelUnavailable(
                f"opencode no pudo ejecutar el modelo {model or '(por defecto)'}: {message}",
                status=response.status_code,
                payload=payload,
            )
        if response.status_code >= 400:
            raise OpencodeError(f"Error al enviar el mensaje: {response.text[:200]}", status=response.status_code)
        return self._json(response)

    async def messages(self, session_id: str) -> list[dict[str, Any]]:
        response = await self._client.get(f"/session/{session_id}/message")
        if response.status_code != 200:
            return []
        payload = self._json(response)
        return payload if isinstance(payload, list) else []

    async def delete_session(self, session_id: str) -> None:
        try:
            await self._client.delete(f"/session/{session_id}")
        except httpx.HTTPError:
            pass

    async def stream_events(self, directory: str) -> AsyncIterator[dict[str, Any]]:
        """Eventos SSE del servidor para las sesiones de un directorio."""
        async with self._client.stream(
            "GET", "/event", params={"directory": directory}
        ) as response:
            if response.status_code != 200:
                raise OpencodeError(
                    f"No se pudo abrir el stream de eventos ({response.status_code})",
                    status=response.status_code,
                )
            async for line in response.aiter_lines():
                if not line or not line.startswith("data: "):
                    continue
                chunk = line[6:].strip()
                if not chunk:
                    continue
                try:
                    yield json.loads(chunk)
                except json.JSONDecodeError:
                    continue

    async def agents(self) -> list[dict[str, Any]]:
        response = await self._client.get("/agent")
        if response.status_code != 200:
            return []
        payload = self._json(response)
        if isinstance(payload, dict):
            return [{"name": name, **(info if isinstance(info, dict) else {})} for name, info in payload.items()]
        return payload if isinstance(payload, list) else []
