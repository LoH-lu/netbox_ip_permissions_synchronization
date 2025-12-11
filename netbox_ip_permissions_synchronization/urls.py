from django.urls import path
from . import views


urlpatterns = [
    path('sync/<int:prefix_id>/', views.IPPermissionsSyncView.as_view(), name='ip_permissions_sync'),
]