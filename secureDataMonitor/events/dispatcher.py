# ============================================================
# XUD-BANK — secureDataMonitor/events/dispatcher.py
# Dispatcher central — Pattern Pub/Sub (Observer)
# Université de Kara – FAST-LPSIC S6 | 2025-2026
# ============================================================
#
# Principe :
#   - Les routers publient des événements via dispatcher.emit()
#   - Les handlers s'abonnent via dispatcher.subscribe()
#   - Zéro couplage entre l'app bancaire et le moteur de surveillance
#
# Usage :
#   from secureDataMonitor.events.dispatcher import dispatcher
#   dispatcher.emit("login_failed", {"username": "x", "ip": "1.2.3.4"})
# ============================================================

import asyncio
import logging
from collections import defaultdict
from typing import Callable, Any

logger = logging.getLogger("secureDataMonitor.dispatcher")


class EventDispatcher:
    """
    Dispatcher événementiel central (Pub/Sub asynchrone).

    - subscribe(event_name, handler) : abonne un handler à un événement
    - emit(event_name, data)         : publie un événement à tous ses handlers
    - Les handlers sont des coroutines async
    """

    def __init__(self):
        self._listeners: dict[str, list[Callable]] = defaultdict(list)
        self._background_tasks: set[asyncio.Task] = set()

    # ── Abonnement ────────────────────────────────────────────
    def subscribe(self, event_name: str, handler: Callable) -> None:
        """
        Abonne un handler à un type d'événement.

        Args:
            event_name : nom de l'événement (ex: "login_failed")
            handler    : coroutine async appelée lors de l'émission
        """
        if handler not in self._listeners[event_name]:
            self._listeners[event_name].append(handler)
            logger.debug(f"Handler '{handler.__name__}' abonné à '{event_name}'")

    def unsubscribe(self, event_name: str, handler: Callable) -> None:
        """Désabonne un handler d'un événement."""
        if handler in self._listeners[event_name]:
            self._listeners[event_name].remove(handler)

    # ── Émission ──────────────────────────────────────────────
    async def emit(self, event_name: str, data: dict[str, Any]) -> None:
        """
        Publie un événement et appelle tous les handlers abonnés.
        Les handlers s'exécutent en arrière-plan (fire-and-forget).
        Cette méthode retourne immédiatement sans attendre les handlers.

        Args:
            event_name : nom de l'événement
            data       : dictionnaire de données de l'événement
        """
        handlers = self._listeners.get(event_name, [])

        if not handlers:
            logger.debug(f"Aucun handler pour l'événement '{event_name}'")
            return

        logger.debug(f"Émission '{event_name}' → {len(handlers)} handler(s)")

        # Fire-and-forget: lance chaque handler en tâche de fond
        for handler in handlers:
            task = asyncio.create_task(self._safe_call(handler, event_name, data))
            self._background_tasks.add(task)
            task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task) -> None:
        """Callback appelé quand une tâche de handler se termine."""
        self._background_tasks.discard(task)
        if task.exception():
            logger.error(f"Erreur dans handler de tâche : {task.exception()}")

    async def _safe_call(self, handler: Callable, event_name: str, data: dict) -> None:
        """Appelle un handler avec gestion d'erreur isolée."""
        try:
            await handler(data)
        except Exception as e:
            logger.error(f"Handler '{handler.__name__}' a échoué sur '{event_name}' : {e}")
            raise

    # ── Utilitaires ───────────────────────────────────────────
    def list_events(self) -> dict[str, list[str]]:
        """Retourne la liste des événements et leurs handlers enregistrés."""
        return {
            event: [h.__name__ for h in handlers]
            for event, handlers in self._listeners.items()
        }

    def handler_count(self, event_name: str) -> int:
        """Nombre de handlers abonnés à un événement."""
        return len(self._listeners.get(event_name, []))


# ── Instance globale (singleton) ──────────────────────────────
dispatcher = EventDispatcher()