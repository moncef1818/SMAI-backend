from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .models import Host

class HostAPIKeyAuthentication(BaseAuthentication):

    def authenticate(self,request):
        auth_header = request.headers.get('Authorization','')

        if not auth_header.startswith("ApiKey "):
            return None
        
        api_key = auth_header.split(' ',1)[1].strip()
        if not api_key:
            raise AuthenticationFailed("Empty API key.")

        try:
            host = Host.objects.get(api_key=api_key)
        except Host.DoesNotExist:
            raise AuthenticationFailed("Invalid API key.")
        
        return (host,host)
