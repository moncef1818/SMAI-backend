from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


class JWTAuthMiddleware(BaseMiddleware):
    """
    Custom WebSocket middleware to authenticate users via JWT tokens
    passed in query parameters.
    """

    def __init__(self, inner):
        super().__init__(inner)

    async def __call__(self, scope, receive, send):
        # Extract token from query parameters
        query_string = scope.get('query_string', b'').decode('utf-8')
        token = None

        logger.info(f"[WS MIDDLEWARE] Processing WebSocket connection to {scope.get('path')}")

        if query_string:
            params = dict(param.split('=', 1) for param in query_string.split('&') if '=' in param)
            token = params.get('token')
            logger.info(f"[WS MIDDLEWARE] Found token parameter: {token[:20] if token else 'None'}...")

        if token:
            try:
                # Validate the JWT token
                access_token = AccessToken(token)
                user_id = access_token.payload.get('user_id')

                logger.info(f"[WS MIDDLEWARE] Token valid, user_id: {user_id}")

                if user_id:
                    # Get user from database
                    user = await self.get_user(user_id)
                    if user and user.is_active:
                        scope['user'] = user
                        logger.info(f"[WS MIDDLEWARE] Authenticated user {user.username} via JWT token")
                    else:
                        scope['user'] = None
                        logger.warning(f"[WS MIDDLEWARE] User {user_id} not found or inactive")
                else:
                    scope['user'] = None
                    logger.warning("[WS MIDDLEWARE] No user_id in JWT token")

            except (InvalidToken, TokenError) as e:
                scope['user'] = None
                logger.warning(f"[WS MIDDLEWARE] Invalid JWT token: {e}")
            except Exception as e:
                scope['user'] = None
                logger.error(f"[WS MIDDLEWARE] Unexpected error during authentication: {e}")
        else:
            scope['user'] = None
            logger.info("[WS MIDDLEWARE] No token provided in WebSocket connection")

        logger.info(f"[WS MIDDLEWARE] Final scope user: {scope.get('user')}")
        return await super().__call__(scope, receive, send)

    @database_sync_to_async
    def get_user(self, user_id):
        """Get user from database."""
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None