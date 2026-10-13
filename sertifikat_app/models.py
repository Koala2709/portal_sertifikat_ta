from django.db import models

class PesertaSertifikat(models.Model):
    nama_peserta = models.CharField(max_length=100)
    # Username dan Password untuk login peserta
    username = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=50) # (Catatan TA: Idealnya di-hash, tapi untuk demo kita buat plain/sederhana dulu)
    
    # Menyimpan file yang SUDAH terenkripsi
    file_sertifikat = models.FileField(upload_to='dokumen_sertifikat/', blank=True, null=True)
    status_enkripsi = models.BooleanField(default=False)
    waktu_dibuat = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.nama_peserta} - {self.username}"