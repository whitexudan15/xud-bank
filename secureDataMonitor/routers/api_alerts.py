# ============================================================
# XUD-BANK — secureDataMonitor/routers/api_alerts.py
# Endpoint WebSocket — Alertes temps réel
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================
#
# Flux WebSocket :
#   1. Client (dashboard) se connecte à ws://host/ws/alerts
#   2. Serveur envoie les nouvelles alertes dès création
#   3. Ping/pong heartbeat toutes les 30s
#   4. Broadcast à tous les clients connectés
# ============================================================

import json
import asyncio
import logging
from datetime import datetime
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from app.database import get_db, AsyncSessionLocal
from app.models.alert import Alert
from app.models.security_event import SecurityEvent, SeverityLevel
from app.services.auth_service import get_current_user_data
from app.config import get_settings

settings = get_settings()
log = logging.getLogger("xud_bank.ws")

router = APIRouter(tags=["alerts"])


# ════════════════════════════════════════════════════════════
# GESTIONNAIRE DE CONNEXIONS WEBSOCKET
# ════════════════════════════════════════════════════════════

class ConnectionManager:
    """
    Gère toutes les connexions WebSocket actives.
    Broadcast des alertes à tous les clients connectés.
    """

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        log.info(f"[WS] Nouvelle connexion — {len(self.active_connections)} client(s) actif(s)")

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        log.info(f"[WS] Déconnexion — {len(self.active_connections)} client(s) restant(s)")

    async def broadcast(self, data: dict) -> None:
        """Envoie un message JSON à tous les clients connectés."""
        if not self.active_connections:
            return

        message = json.dumps(data, default=str)
        dead = []

        for ws in self.active_connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)

        # Nettoie les connexions mortes
        for ws in dead:
            self.disconnect(ws)

    async def send_to(self, websocket: WebSocket, data: dict) -> None:
        """Envoie un message JSON à un client spécifique."""
        try:
            await websocket.send_text(json.dumps(data, default=str))
        except Exception:
            self.disconnect(websocket)

    @property
    def count(self) -> int:
        return len(self.active_connections)


# Instance globale du gestionnaire
ws_manager = ConnectionManager()


# ════════════════════════════════════════════════════════════
# FONCTION DE BROADCAST (appelée par les handlers)
# ════════════════════════════════════════════════════════════

async def broadcast_alert(alert: Alert) -> None:
    """
    Diffuse une nouvelle alerte à tous les clients WebSocket.
    Appelée depuis handlers.py après create_alert().
    """
    payload = {
        "type": "new_alert",
        "alert": {
            "id": str(alert.id),
            "timestamp": alert.timestamp.isoformat(),
            "alert_level": alert.alert_level.value,
            "message": alert.message,
            "resolved": alert.resolved,
            "source_event_id": str(alert.source_event_id),
        }
    }
    await ws_manager.broadcast(payload)
    log.info(f"[WS] Alerte broadcast : [{alert.alert_level.value}] {alert.message[:60]}")


async def broadcast_event(event: SecurityEvent) -> None:
    """
    Diffuse un nouvel événement de sécurité à tous les clients.
    """
    payload = {
        "type": "new_event",
        "event": {
            "id": str(event.id),
            "timestamp": event.timestamp.isoformat(),
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "username": event.username or "anonymous",
            "ip_address": str(event.ip_address),
            "description": event.description[:120],
        }
    }
    await ws_manager.broadcast(payload)


# ════════════════════════════════════════════════════════════
# ENDPOINT WEBSOCKET — ws://host/ws/alerts
# ════════════════════════════════════════════════════════════

@router.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    Endpoint WebSocket principal.
    - Accepte la connexion
    - Envoie l'état initial (dernières alertes)
    - Maintient le heartbeat
    - Diffuse les nouvelles alertes en temps réel
    """
    await ws_manager.connect(websocket)

    try:
        # Envoie l'état initial au client qui vient de se connecter
        async with AsyncSessionLocal() as db:
            # Dernières 5 alertes non résolues
            alerts_result = await db.execute(
                select(Alert)
                .where(Alert.resolved == False)
                .order_by(desc(Alert.timestamp))
                .limit(5)
            )
            recent_alerts = alerts_result.scalars().all()

            # Stats rapides
            unresolved_count = (await db.execute(
                select(func.count(Alert.id)).where(Alert.resolved == False)
            )).scalar_one()

            total_events = (await db.execute(
                select(func.count(SecurityEvent.id))
            )).scalar_one()

        await ws_manager.send_to(websocket, {
            "type": "init",
            "stats": {
                "unresolved_alerts": unresolved_count,
                "total_events": total_events,
                "connected_clients": ws_manager.count,
            },
            "recent_alerts": [
                {
                    "id": str(a.id),
                    "timestamp": a.timestamp.isoformat(),
                    "alert_level": a.alert_level.value,
                    "message": a.message[:100],
                }
                for a in recent_alerts
            ],
        })

        # Boucle principale — heartbeat + écoute messages client
        while True:
            try:
                # Attend un message client ou timeout (heartbeat)
                data = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=settings.WS_HEARTBEAT_INTERVAL,
                )
                # Traite les messages client (ping, demande refresh...)
                msg = json.loads(data)
                if msg.get("type") == "ping":
                    await ws_manager.send_to(websocket, {
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat(),
                        "connected_clients": ws_manager.count,
                    })

            except asyncio.TimeoutError:
                # Heartbeat serveur
                await ws_manager.send_to(websocket, {
                    "type": "heartbeat",
                    "timestamp": datetime.utcnow().isoformat(),
                    "connected_clients": ws_manager.count,
                })

    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

    except Exception as e:
        log.error(f"[WS] Erreur : {e}")
        ws_manager.disconnect(websocket)


# ════════════════════════════════════════════════════════════
# API REST — Données pour le dashboard (fallback polling)
# ════════════════════════════════════════════════════════════

@router.get("/api/alerts/recent")
async def get_recent_alerts(
    limit: int = 10,
    db: AsyncSession = Depends(get_db),
):
    """
    Endpoint REST : dernières alertes non résolues.
    Fallback si WebSocket indisponible.
    """
    result = await db.execute(
        select(Alert)
        .where(Alert.resolved == False)
        .order_by(desc(Alert.timestamp))
        .limit(limit)
    )
    alerts = result.scalars().all()

    return JSONResponse([
        {
            "id": str(a.id),
            "timestamp": a.timestamp.isoformat(),
            "alert_level": a.alert_level.value,
            "message": a.message,
            "resolved": a.resolved,
        }
        for a in alerts
    ])


@router.get("/api/stats")
async def get_stats(db: AsyncSession = Depends(get_db)):
    """Stats globales pour le dashboard."""
    from app.models.user import User

    return JSONResponse({
        "total_events": (await db.execute(select(func.count(SecurityEvent.id)))).scalar_one(),
        "unresolved_alerts": (await db.execute(
            select(func.count(Alert.id)).where(Alert.resolved == False)
        )).scalar_one(),
        "locked_accounts": (await db.execute(
            select(func.count(User.id)).where(User.is_locked == True)
        )).scalar_one(),
        "connected_ws_clients": ws_manager.count,
        "timestamp": datetime.utcnow().isoformat(),
    })