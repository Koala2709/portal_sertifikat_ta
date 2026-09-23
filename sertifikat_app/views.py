import os
import logging
from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
from .crypto_utils import HybridCrypto 

logger = logging.getLogger('security_logger')

mesin_kripto = HybridCrypto()

def get_client_ip(request):
    """Mendapatkan IP client untuk dicatat oleh Fail2Ban nanti"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if username == 'admin' and password == 'rahasia123':
            # === ALUR KRIPTOGRAFI DARI FOLDER KHUSUS ===
            
            # 1. Arahkan ke folder 'dokumen_sertifikat' yang baru dibuat
            folder_sertifikat = os.path.join(settings.BASE_DIR, 'dokumen_sertifikat')
            file_path = os.path.join(folder_sertifikat, 'sertifikat_dummy.pdf')
            
            try:
                # Membaca file PDF dari dalam folder khusus
                with open(file_path, 'rb') as pdf_file:
                    data_sertifikat_asli = pdf_file.read()
            except FileNotFoundError:
                return HttpResponse(f"Error: File tidak ditemukan di jalur {file_path}", status=404)
            
            # 2. Proses Enkripsi AES-RSA
            paket_enkripsi = mesin_kripto.encrypt_file(data_sertifikat_asli)
            
            # 3. Proses Dekripsi
            data_siap_unduh = mesin_kripto.decrypt_file(paket_enkripsi)
            
            # 4. Berikan perintah ke browser untuk men-download file sebagai PDF
            response = HttpResponse(data_siap_unduh, content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="E-Sertifikat_Terenkripsi_Bagas.pdf"'
            return response
            
        else:
           # === JIKA LOGIN GAGAL ===
            ip_address = get_client_ip(request)
            logger.warning(ip_address)
            return render(request, 'login.html', {
                'error_message': 'Login Gagal! Aktivitas mencurigakan dari IP Anda telah dicatat.'
            })
            
    return render(request, 'login.html')