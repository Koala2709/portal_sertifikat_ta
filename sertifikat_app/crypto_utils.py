import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

class HybridCrypto:
    def __init__(self):
        # 1. GENERATE RSA KEYS (Biasanya ini di-generate sekali dan disimpan di server)
        # Untuk keperluan TA, kita generate saat class dipanggil.
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048, # Ukuran standar aman RSA
        )
        self.public_key = self.private_key.public_key()

    def encrypt_file(self, file_data: bytes):
        """
        Proses 1: Mengenkripsi file E-Sertifikat menggunakan AES-256
        Proses 2: Mengenkripsi Kunci AES menggunakan RSA (Amplop Digital)
        """
        # A. Buat kunci rahasia AES-256 secara acak (256 bit = 32 bytes)
        aes_key = os.urandom(32)
        
        # B. Buat Nonce (Number Used Once) wajib untuk mode AES-GCM
        nonce = os.urandom(16)
        
        # C. Mulai proses enkripsi AES-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        # ciphertext_data adalah file PDF yang sudah acak/terkunci
        ciphertext_data = encryptor.update(file_data) + encryptor.finalize()
        
        # D. Bungkus (Enkripsi) Kunci AES menggunakan Public Key RSA
        encrypted_aes_key = self.public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Return semua komponen yang dibutuhkan untuk mendekripsi nanti
        # Tag itu semacam stempel sidik jari agar file tidak bisa dimodifikasi hacker
        return {
            'encrypted_aes_key': encrypted_aes_key,
            'nonce': nonce,
            'tag': encryptor.tag,
            'ciphertext_data': ciphertext_data
        }

    def decrypt_file(self, encrypted_package: dict):
        """
        Proses kebalikannya: Membuka kunci AES dengan RSA, lalu membuka file dengan AES.
        """
        # A. Buka (Dekripsi) Kunci AES menggunakan Private Key RSA
        aes_key = self.private_key.decrypt(
            encrypted_package['encrypted_aes_key'],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # B. Gunakan kunci AES yang sudah terbuka untuk mendekripsi file PDF
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(
            encrypted_package['nonce'], 
            encrypted_package['tag']
        ))
        decryptor = cipher.decryptor()
        
        # decrypted_data adalah file PDF asli yang siap di-download
        decrypted_data = decryptor.update(encrypted_package['ciphertext_data']) + decryptor.finalize()
        
        return decrypted_data