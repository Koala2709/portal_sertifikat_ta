"""
URL configuration for core_project project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.1/topics/http/urls/
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
from django.urls import path
# PENTING: Ganti 'sertifikat_app' dengan nama folder aplikasi Django-mu yang sebenarnya
from sertifikat_app import views 

urlpatterns = [
    # Rute bawaan Django untuk database admin
    path('admin/', admin.site.urls),
    
    # Rute untuk Peserta (Login & Download)
    # String kosong '' berarti ini akan jadi halaman pertama yang terbuka (Landing Page)
    path('', views.login_view, name='login_peserta'), 
    
    # Rute BARU untuk Admin (Upload PDF & Lihat Log Enkripsi)
    # Cara aksesnya nanti: 192.168.18.128:8000/admin-sertif/
    path('admin-sertif/', views.admin_upload_view, name='admin_dashboard'),
]
