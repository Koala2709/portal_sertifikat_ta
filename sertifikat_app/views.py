import os
import logging
import binascii
import pickle  # <-- IMPORT BARU: Untuk mengubah Dictionary menjadi File Biner
from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.conf import settings
from django.core.files.base import ContentFile  
from .crypto_utils import HybridCrypto 
from .models import PesertaSertifikat           

logger = logging.getLogger('security_logger')
mesin_kripto = HybridCrypto()

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0]
    return request.META.get('REMOTE_ADDR')

def login_view(request):
    if request.GET.get('reset') == 'true':
        if 'failed_attempts' in request.session:
            del request.session['failed_attempts']
        return redirect(request.path)

    attempts = request.session.get('failed_attempts', 0)
    if attempts >= 3:
        return HttpResponse(
            "<h1>Akses Ditolak (Sistem Terkunci)</h1>"
            "<p>Terlalu banyak percobaan login gagal. IP Anda telah diblokir oleh sistem keamanan jaringan kami.</p>"
            "<br><p><i>(Mode Testing TA: Buka blokir Fail2Ban di terminal, lalu <a href='?reset=true'>Klik di sini untuk Reset IP dan kembali ke Login</a>)</i></p>", 
            status=403
        )

    if request.method == 'POST':
        username_input = request.POST.get('username')
        password_input = request.POST.get('password')
        
        try:
            peserta = PesertaSertifikat.objects.get(username=username_input, password=password_input)
            
            if 'failed_attempts' in request.session:
                del request.session['failed_attempts']
            
            if not peserta.status_enkripsi or not peserta.file_sertifikat:
                return HttpResponse(
                    "<h1>Sertifikat Belum Tersedia</h1>"
                    "<p>Sertifikat Anda belum diunggah atau belum diproses enkripsi oleh Admin.</p>", 
                    status=404
                )
            
            # === ALUR DEKRIPSI ===
            # 1. Baca data biner (.enc) dari database
            paket_bytes = peserta.file_sertifikat.read()
            
            # 2. Kembalikan wujud Bytes menjadi Dictionary menggunakan Pickle
            paket_enkripsi = pickle.loads(paket_bytes)
            
            try:
                # 3. Dekripsi file
                data_siap_unduh = mesin_kripto.decrypt_file(paket_enkripsi)
            except Exception as e:
                return HttpResponse(f"Gagal mendekripsi file! Sistem mendeteksi kerusakan data. Error: {str(e)}", status=500)
            
            response = HttpResponse(data_siap_unduh, content_type='application/pdf')
            response['Content-Disposition'] = f'attachment; filename="E-Sertifikat_{peserta.nama_peserta}.pdf"'
            return response
            
        except PesertaSertifikat.DoesNotExist:
            attempts += 1
            request.session['failed_attempts'] = attempts
            
            ip_address = get_client_ip(request)
            logger.warning(ip_address) 
            
            if attempts >= 3:
                return HttpResponse(
                    "<h1>Akses Ditolak (Sistem Terkunci)</h1>"
                    "<p>Terlalu banyak percobaan login gagal. IP Anda telah diblokir oleh sistem keamanan jaringan kami.</p>"
                    "<br><p><i>(Mode Testing TA: Buka blokir Fail2Ban di terminal, lalu <a href='?reset=true'>Klik di sini untuk Reset IP dan kembali ke Login</a>)</i></p>", 
                    status=403
                )
            
            return render(request, 'login.html', {
                'error_message': f'Kredensial Tidak Valid! Aktivitas mencurigakan dicatat. (Percobaan {attempts}/3)'
            })
            
    return render(request, 'login.html')

# ==========================================
# FUNGSI ADMIN UPLOAD
# ==========================================
def admin_upload_view(request):
    crypto_log = None 
    daftar_peserta = PesertaSertifikat.objects.all()

    if request.method == 'POST':
        peserta_id = request.POST.get('peserta_id')
        file_pdf_asli = request.FILES.get('file_sertifikat')
        
        if peserta_id and file_pdf_asli:
            peserta = PesertaSertifikat.objects.get(id=peserta_id)
            
            data_mentah = file_pdf_asli.read()
            ukuran_asli = len(data_mentah)
            
            # 1. Enkripsi (Menghasilkan Dictionary)
            paket_enkripsi = mesin_kripto.encrypt_file(data_mentah)
            
            # 2. Ubah Dictionary Kripto menjadi format Bytes biner menggunakan Pickle
            paket_bytes = pickle.dumps(paket_enkripsi)
            
            # 3. Simpan wujud biner tersebut sebagai file .enc
            nama_file_baru = f"Sertif_{peserta.username}.enc"
            peserta.file_sertifikat.save(nama_file_baru, ContentFile(paket_bytes))
            peserta.status_enkripsi = True
            peserta.save()
            
            # 4. TANGKAP LOG HEXADECIMAL UNTUK LAYAR
            sample_hex = binascii.hexlify(paket_bytes[:32]).decode('utf-8').upper()
            
            crypto_log = {
                'peserta': peserta.nama_peserta,
                'ukuran_asli': f"{ukuran_asli} bytes",
                'ukuran_enkripsi': f"{len(paket_bytes)} bytes",
                'info_aes': "AES-256-GCM (Keysize: 32 bytes)",
                'info_rsa': "RSA-OAEP (Keysize: 2048 bit)",
                'sample_ciphertext': f"{sample_hex}...",
                'status': 'SUKSES: File PDF asli telah dihancurkan dari memori dan diubah menjadi Ciphertext.'
            }

    return render(request, 'admin_dashboard.html', {
        'daftar_peserta': daftar_peserta,
        'crypto_log': crypto_log
    })