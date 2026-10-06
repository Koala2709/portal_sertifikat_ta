import os
import logging
from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings
from .crypto_utils import HybridCrypto 

logger = logging.getLogger('security_logger')
mesin_kripto = HybridCrypto()

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        if username == 'admin' and password == 'rahasia123':
            # 1. Reset perhitungan error jika login sukses
            if 'failed_attempts' in request.session:
                del request.session['failed_attempts']
            
            # === ALUR KRIPTOGRAFI DARI FOLDER KHUSUS ===
            folder_sertifikat = os.path.join(settings.BASE_DIR, 'dokumen_sertifikat')
            file_path = os.path.join(folder_sertifikat, 'sertifikat_dummy.pdf')
            
            try:
                with open(file_path, 'rb') as pdf_file:
                    data_sertifikat_asli = pdf_file.read()
            except FileNotFoundError:
                return HttpResponse(f"Error: File tidak ditemukan di {file_path}", status=404)
            
            paket_enkripsi = mesin_kripto.encrypt_file(data_sertifikat_asli)
            data_siap_unduh = mesin_kripto.decrypt_file(paket_enkripsi)
            
            response = HttpResponse(data_siap_unduh, content_type='application/pdf')
            response['Content-Disposition'] = 'attachment; filename="E-Sertifikat_Terenkripsi_Bagas.pdf"'
            return response
            
        else:
            # 2. Hitung jumlah kegagalan menggunakan Session Django
            attempts = request.session.get('failed_attempts', 0) + 1
            request.session['failed_attempts'] = attempts
            
            # 3. Pancing Fail2Ban agar mencatat IP
            ip_address = get_client_ip(request)
            logger.warning(ip_address)
            
            # 4. Blokir instan di tampilan UI pada percobaan ke-3
            if attempts >= 3:
                # Hapus session agar saat di-unban nanti, hitungannya mulai dari 0 lagi
                del request.session['failed_attempts']
                return HttpResponse(
                    "<h1>Akses Ditolak</h1><p>Terlalu banyak percobaan login gagal. IP Anda telah diblokir secara sistem.</p>", 
                    status=403
                )
            
            # Jika belum 3x, kembalikan ke halaman login biasa dengan peringatan
            return render(request, 'login.html', {
                'error_message': f'Login Gagal! Aktivitas mencurigakan dicatat. (Percobaan {attempts}/3)'
            })
            
    return render(request, 'login.html')