"""
URL configuration for core project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from incidents.views import IncidentAlertsView, IncidentSummaryView, NetworkIncidentListView
from hosts.views import HostAgentStatusView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/auth/', include('accounts.urls')),
    path('api/hosts/', include('hosts.urls')),
    path('api/groups/', include('groups.urls')),
    path('api/events/', include('events.urls')),
    path('api/incidents/', include('incidents.urls')),
    path('api/overview/', IncidentSummaryView.as_view(), name='overview'),
    path('api/network/', NetworkIncidentListView.as_view(), name='network_overview'),
    path('api/alerts/', IncidentAlertsView.as_view(), name='alerts'),
    path('api/agents/', HostAgentStatusView.as_view(), name='agents_overview'),
]