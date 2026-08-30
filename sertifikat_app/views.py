import logging
from django.shortcuts import render
from django.http import HttpResponse
# Import mesin kripto yang sudah kita buat
from .crypto_utils import HybridCrypto 

logger = logging.getLogger('security_logger')

# Kita inisiasi mesin kriptonya di luar fungsi agar kunci RSA-nya tetap sama selama server menyala
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
        
        # Logika Login Sederhana
        if username == 'admin' and password == 'rahasia123':
            # === SIMULASI ALUR KRIPTOGRAFI ===
            
            # 1. Anggap ini adalah file PDF asli yang ada di dalam server
            data_sertifikat_asli = b"Ini adalah isi dokumen E-Sertifikat otentik atas nama Bagas Febriansyah Putra."
            
            # 2. Proses Enkripsi (Seolah-olah ini data yang tersimpan aman di Database)
            paket_enkripsi = mesin_kripto.encrypt_file(data_sertifikat_asli)
            
            # 3. Proses Dekripsi (Karena login berhasil, sistem membuka kuncinya)
            data_siap_unduh = mesin_kripto.decrypt_file(paket_enkripsi)
            
            # 4. Berikan perintah ke browser untuk langsung men-download file tersebut!
            response = HttpResponse(data_siap_unduh, content_type='text/plain')
            response['Content-Disposition'] = 'attachment; filename="E-Sertifikat_Bagas.txt"'
            return response
            
        else:
            # === JIKA LOGIN GAGAL ===
            # Catat IP penyerang ke file auth_fail.log
            ip_address = get_client_ip(request)
            logger.warning(ip_address)
            return HttpResponse("Login Gagal! IP Anda telah dicatat oleh sistem keamanan.", status=401)
            
    return render(request, 'login.html')