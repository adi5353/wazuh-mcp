"""WebSocket real-time alert streaming.

Exposes a /ws/alerts endpoint that pushes new Wazuh alerts to connected
clients as they arrive. Clients can optionally filter by minimum rule level
and agent ID.

Protocol (JSON frames):
  Client → Server (on connect, optional):
    {"min_level": 7, "agent_id": "001"}

  Server → Client (continuous):
    {"type": "alert",  "alert": {...}}
    {"type": "ping",   "ts": "2025-05-26T..."}    — keepalive every 30s
    {"type": "error",  "message": "..."}

Query parameters (alternative to JSON frame):
  min_level=<int>     — minimum rule.level (default 7)
  agent_id=<str>      — filter to a specific agent ID
  interval=<float>    — poll interval in seconds (default 5.0, min 2.0)
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

log = logging.getLogger("wazuh-mcp.ws_alerts")

# Track the most-recent alert timestamp per connection to avoid re-sending.
_POLL_INTERVAL_DEFAULT = 5.0
_POLL_INTERVAL_MIN = 2.0
_KEEPALIVE_INTERVAL = 30.0


async def ws_alerts_handler(websocket: Any, idx: Any, cfg: Any) -> None:
    """Starlette WebSocket endpoint handler for /ws/alerts."""
    await websocket.accept()

    # ── Parse query params ────────────────────────────────────────────────────
    params = dict(websocket.query_params)
    min_level = int(params.get("min_level", 7))
    agent_id = params.get("agent_id", "")
    interval = max(
        _POLL_INTERVAL_MIN,
        float(params.get("interval", _POLL_INTERVAL_DEFAULT)),
    )

    # Allow client to override via initial JSON frame (optional)
    try:
        websocket.receive_timeout = 1.0
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
        client_cfg = json.loads(raw)
        min_level = int(client_cfg.get("min_level", min_level))
        agent_id = client_cfg.get("agent_id", agent_id)
        interval = max(_POLL_INTERVAL_MIN, float(client_cfg.get("interval", interval)))
    except (asyncio.TimeoutError, Exception):
        pass  # no config frame sent — use query-param defaults

    log.info(
        "WS /ws/alerts: client connected min_level=%d agent_id=%s interval=%.1fs",
        min_level, agent_id or "(all)", interval,
    )

    last_ts: str = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
    last_keepalive: float = time.monotonic()

    try:
        while True:
            now = time.monotonic()

            # ── Keepalive ping ────────────────────────────────────────────────
            if now - last_keepalive >= _KEEPALIVE_INTERVAL:
                await websocket.send_json({
                    "type": "ping",
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
                last_keepalive = now

            # ── Poll for new alerts ───────────────────────────────────────────
            filters: list[dict] = [
                {"range": {"timestamp": {"gt": last_ts}}},
                {"range": {"rule.level": {"gte": min_level}}},
            ]
            if agent_id:
                filters.append({"term": {"agent.id": agent_id}})

            body: dict = {
                "size": 20,
                "query": {"bool": {"filter": filters}},
                "sort": [{"timestamp": {"order": "asc"}}],
                "_source": [
                    "id", "timestamp", "rule.id", "rule.description",
                    "rule.level", "rule.mitre.id", "rule.mitre.tactic",
                    "agent.id", "agent.name", "data.srcip",
                ],
            }

            try:
                resp = await idx.search(body)
                hits = resp.get("hits", {}).get("hits", [])
            except Exception as exc:
                await websocket.send_json({"type": "error", "message": str(exc)[:200]})
                await asyncio.sleep(interval)
                continue

            for hit in hits:
                src = hit.get("_source", {})
                ts = src.get("timestamp", last_ts)
                if ts > last_ts:
                    last_ts = ts
                await websocket.send_json({"type": "alert", "alert": src})

            await asyncio.sleep(interval)

    except Exception as exc:
        log_msg = str(exc)
        if "disconnect" not in log_msg.lower() and "close" not in log_msg.lower():
            log.warning("WS /ws/alerts: connection error: %s", log_msg[:200])
    finally:
        log.info("WS /ws/alerts: client disconnected")
        try:
            await websocket.close()
        except Exception:
            pass


def mount_ws_route(app_routes: list, idx: Any, cfg: Any) -> None:
    """Append the /ws/alerts WebSocket route to an existing Starlette route list."""
    from starlette.routing import WebSocketRoute

    async def _handler(ws: Any) -> None:
        await ws_alerts_handler(ws, idx=idx, cfg=cfg)

    app_routes.append(WebSocketRoute("/ws/alerts", endpoint=_handler))
