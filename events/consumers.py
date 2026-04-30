import json
import logging
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.cache import cache
from incidents.models import Incident
from incidents.serializers import IncidentSerializer

logger = logging.getLogger(__name__)


class IncidentConsumer(AsyncJsonWebsocketConsumer):
    """WebSocket consumer for real-time incident notifications."""

    async def connect(self):
        """Handle WebSocket connection."""
        self.user = self.scope['user']

        if not self.user or not self.user.is_authenticated:
            await self.close()
            return

        # Create group name based on user role
        if self.user.is_admin:
            self.group_name = 'incidents_admin'
        elif self.user.is_group_leader:
            self.group_name = f'incidents_group_{self.user.group.id}'
        else:
            self.group_name = f'incidents_user_{self.user.id}'

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

        logger.info(f"[WS] User {self.user.username} connected to {self.group_name}")

        # Send recent incidents on connect
        await self.send_recent_incidents()

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection."""
        if hasattr(self, 'group_name'):
            await self.channel_layer.group_discard(self.group_name, self.channel_name)
        logger.info(f"[WS] User {self.user.username} disconnected")

    async def receive_json(self, content):
        """Handle incoming WebSocket messages."""
        action = content.get('action')

        if action == 'get_recent':
            await self.send_recent_incidents()
        elif action == 'acknowledge':
            incident_id = content.get('incident_id')
            if incident_id:
                await self.acknowledge_incident(incident_id)

    async def send_recent_incidents(self):
        """Send recent incidents to the connected client."""
        incidents = await self.get_recent_incidents()
        await self.send_json({
            'type': 'recent_incidents',
            'incidents': incidents
        })

    async def incident_notification(self, event):
        """Handle incident notification broadcast."""
        incident_data = event['incident']
        await self.send_json({
            'type': 'new_incident',
            'incident': incident_data
        })

    @database_sync_to_async
    def get_recent_incidents(self):
        """Get recent incidents for the user."""
        queryset = self.get_incident_queryset()
        incidents = queryset.order_by('-created_at')[:10]  # Last 10 incidents
        return IncidentSerializer(incidents, many=True).data

    @database_sync_to_async
    def get_incident_queryset(self):
        """Get filtered incident queryset based on user role."""
        if self.user.is_admin:
            return Incident.objects.select_related('host', 'event').all()
        elif self.user.is_group_leader:
            return Incident.objects.select_related('host', 'event').filter(host__group__leader=self.user)
        else:
            return Incident.objects.select_related('host', 'event').filter(host=self.user.host)

    @database_sync_to_async
    def acknowledge_incident(self, incident_id):
        """Mark incident as acknowledged (placeholder for future feature)."""
        # This could be extended to mark incidents as read/acknowledged
        logger.info(f"[WS] User {self.user.username} acknowledged incident {incident_id}")


# Utility functions for broadcasting incidents
async def broadcast_incident(incident_id):
    """Broadcast new incident to appropriate groups."""
    from channels.layers import get_channel_layer
    from asgiref.sync import async_to_sync

    try:
        incident = await database_sync_to_async(
            lambda: Incident.objects.select_related('host', 'event').get(incident_id=incident_id)
        )()

        incident_data = await database_sync_to_async(
            lambda: IncidentSerializer(incident).data
        )()

        channel_layer = get_channel_layer()

        # Broadcast to admin group
        async_to_sync(channel_layer.group_send)(
            'incidents_admin',
            {
                'type': 'incident_notification',
                'incident': incident_data
            }
        )

        # Broadcast to group leaders
        if incident.host.group:
            async_to_sync(channel_layer.group_send)(
                f'incidents_group_{incident.host.group.id}',
                {
                    'type': 'incident_notification',
                    'incident': incident_data
                }
            )

        # Broadcast to individual users of the affected host
        from accounts.models import User
        users = await database_sync_to_async(
            lambda: list(User.objects.filter(host=incident.host).values_list('id', flat=True))
        )()

        for user_id in users:
            async_to_sync(channel_layer.group_send)(
                f'incidents_user_{user_id}',
                {
                    'type': 'incident_notification',
                    'incident': incident_data
                }
            )

        logger.info(f"[WS] Broadcasted incident {incident_id} to {len(users) + 2} groups")

    except Exception as e:
        logger.error(f"[WS] Error broadcasting incident {incident_id}: {e}")


# Redis caching utilities
def cache_incident_data(incident_id, data, timeout=3600):
    """Cache incident data in Redis."""
    cache_key = f'incident:{incident_id}'
    cache.set(cache_key, data, timeout)
    logger.debug(f"[CACHE] Cached incident {incident_id}")


def get_cached_incident_data(incident_id):
    """Get cached incident data from Redis."""
    cache_key = f'incident:{incident_id}'
    data = cache.get(cache_key)
    if data:
        logger.debug(f"[CACHE] Retrieved cached incident {incident_id}")
    return data


def cache_user_incidents(user_id, incident_ids, timeout=1800):
    """Cache list of incident IDs for a user."""
    cache_key = f'user_incidents:{user_id}'
    cache.set(cache_key, incident_ids, timeout)
    logger.debug(f"[CACHE] Cached {len(incident_ids)} incidents for user {user_id}")


def get_cached_user_incidents(user_id):
    """Get cached incident IDs for a user."""
    cache_key = f'user_incidents:{user_id}'
    data = cache.get(cache_key)
    if data:
        logger.debug(f"[CACHE] Retrieved {len(data)} cached incidents for user {user_id}")
    return data or []
