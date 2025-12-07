# Tugas 4: Digital Signature with Public Key Cryptography

**Mata Kuliah**: Keamanan Informasi  
**Kelas**: C

## Tim Pengembang

| Nama | NRP |
|------|-----|
| Muhammad Danis Hadriansyah | 5025221239 |
| Fathurazka Gamma Syuhada | 5025221128 |

## Deskripsi

Tugas 4 merupakan pengembangan dari Tugas 3 dengan menambahkan **Digital Signature** menggunakan RSA. Sistem ini mengimplementasikan komunikasi chat yang aman dengan:

- **RSA** untuk key exchange (distribusi kunci DES)
- **DES** untuk enkripsi pesan
- **RSA Digital Signature** untuk autentikasi dan integritas pesan

## Fitur Utama

### 1. Key Exchange dengan RSA
Server memiliki RSA keypair untuk mendistribusikan DES key secara aman ke setiap client.

### 2. Enkripsi Pesan dengan DES
Semua pesan chat dienkripsi menggunakan DES dengan kunci unik per client.

### 3. Digital Signature ⭐ (BARU)
- Setiap client memiliki RSA keypair sendiri untuk signing
- Client menandatangani setiap pesan dengan private key-nya
- Server memverifikasi signature menggunakan public key client
- Pesan ditampilkan dengan indikator verifikasi (✓ atau ✗)

## Cara Kerja Digital Signature

### Client Side (Signing)
1. Client membuat RSA keypair saat startup
2. Public key dikirim ke server saat key exchange
3. Saat mengirim pesan:
   - Hash pesan menggunakan SHA-256
   - Enkripsi hash dengan private key RSA → signature
   - Kirim pesan terenkripsi (DES) + signature ke server

```python
def sign_message(message, private_key):
    # Hash the message
    message_hash = hashlib.sha256(message.encode()).digest()
    hash_int = int.from_bytes(message_hash, 'big')
    
    # Sign with private key (encrypt hash)
    d, n = private_key
    signature = pow(hash_int, d, n)
    
    return signature
```

### Server Side (Verification)
1. Server menyimpan public key setiap client
2. Saat menerima pesan:
   - Dekripsi pesan dengan DES key pengirim
   - Verifikasi signature:
     - Dekripsi signature dengan public key pengirim
     - Hash plaintext pesan
     - Bandingkan hasil dekripsi signature dengan hash
   - Tandai pesan sebagai verified/unverified

```python
def verify_signature(message, signature, public_key):
    # Hash the message
    message_hash = hashlib.sha256(message.encode()).digest()
    hash_int = int.from_bytes(message_hash, 'big')
    
    # Decrypt signature with public key (verification)
    e, n = public_key
    decrypted_hash = pow(signature, e, n)
    
    # Compare
    return hash_int == decrypted_hash
```

## Alur Lengkap Komunikasi

```
1. CLIENT → SERVER: Join chat room
2. SERVER → CLIENT: Assign nama (Client_1, Client_2, ...)

3. CLIENT → SERVER: Request server RSA public key
4. SERVER → CLIENT: Send RSA public key (e, n)

5. CLIENT: Generate RSA keypair untuk signing
6. CLIENT: Generate/load DES key
7. CLIENT: Encrypt DES key dengan server RSA public key
8. CLIENT → SERVER: Send encrypted DES key + client RSA public key

9. SERVER: Decrypt DES key, simpan per client
10. SERVER: Simpan client RSA public key untuk verifikasi

11. CHAT LOOP:
    CLIENT:
    - User input message
    - Encrypt message dengan DES
    - Sign plaintext dengan RSA private key
    - Send (encrypted_message, signature) → SERVER
    
    SERVER:
    - Decrypt message dengan sender's DES key
    - Verify signature dengan sender's RSA public key
    - Log verification result (✓/✗)
    - Re-encrypt untuk tiap recipient
    - Attach signature_verified flag
    
    RECIPIENTS:
    - Poll messages dari server
    - Decrypt dengan DES key sendiri
    - Display dengan status verifikasi (✓ atau no signature)
```

## Komponen Program

### http_server.py
**Fitur Baru:**
- `client_public_keys` dictionary untuk menyimpan RSA public key setiap client
- `verify_signature()` function untuk verifikasi signature
- Endpoint `exchange_key` menerima client RSA public key
- Endpoint `send_message` memverifikasi signature setiap pesan
- Log menampilkan status verifikasi: `✓ (signature verified)` atau `✗ (INVALID SIGNATURE)`

**Output Log Server:**
```
[KEY] Client_1: received DES key a1b2c3d4e5f6g7h8
[KEY] Client_1: received RSA public key for signatures
[CHAT] Client_1: Halo semua! ✓ (signature verified)
[CHAT] Client_2: Hi Client_1 ✓ (signature verified)
```

### http_client.py
**Fitur Baru:**
- Generate RSA keypair saat startup untuk signing
- `sign_message()` function untuk membuat signature
- Kirim public key ke server saat key exchange
- Sign setiap pesan sebelum dikirim
- Display pesan dengan indikator verifikasi (✓)

**Output Client:**
```
=== RSA KEY EXCHANGE ===
Generating RSA keypair untuk digital signature...
RSA keypair generated!
Menerima RSA public key dari server
Generate DES key baru (disimpan)
DES Key: a1b2c3d4e5f6g7h8
Key exchange dengan server berhasil
Public key untuk signature verification dikirim ke server
========================================

Chat aktif! Ketik 'quit' untuk keluar
Semua pesan akan ditandatangani secara digital
============================================================

>>> Halo!

Client_2: Hi! ✓
>>> 
```

## Cara Menjalankan

### 1. Persiapan
```bash
pip install requests
```

### 2. Jalankan Server
Terminal 1:
```bash
cd Tugas-4-KeamananInformasi-C
python http_server.py
```

Output:
```
============================================================
SECURE CHAT SERVER (RSA + DES + DIGITAL SIGNATURE)
============================================================
Port: 65432
RSA Public Key (e): 65537
RSA Public Key (n): <n dipotong>
============================================================
Server siap menerima koneksi...
```

### 3. Jalankan Client Pertama
Terminal 2:
```bash
cd Tugas-4-KeamananInformasi-C
python http_client.py
```

Input:
```
Masukkan Server URL: http://localhost:65432
```

### 4. Jalankan Client Kedua (Opsional)
Terminal 3:
```bash
cd Tugas-4-KeamananInformasi-C
python http_client.py
```

Input:
```
Masukkan Server URL: http://localhost:65432
```

### 5. Mulai Chat
Ketik pesan di salah satu client, akan muncul di client lain dengan tanda ✓ jika signature valid.

### 6. Remote Access (Opsional)

Jika ingin akses dari device lain atau internet, gunakan cloudflared:

Terminal 4:
```bash
cloudflared tunnel --url http://localhost:65432
```

Output akan memberikan URL publik seperti `https://random-name.trycloudflare.com`

Gunakan URL tersebut di client untuk akses remote.

## Keamanan yang Diimplementasikan

### 1. Confidentiality (Kerahasiaan)
- DES encryption untuk semua pesan
- RSA encryption untuk key distribution
- Setiap client punya DES key unik

### 2. Authentication (Autentikasi) ⭐
- Digital signature membuktikan identitas pengirim
- Hanya pengirim yang memiliki private key dapat membuat signature valid

### 3. Integrity (Integritas) ⭐
- Digital signature memastikan pesan tidak diubah
- Perubahan sedikit saja pada pesan akan membuat signature invalid

### 4. Non-repudiation (Non-penyangkalan) ⭐
- Pengirim tidak dapat menyangkal telah mengirim pesan
- Signature hanya bisa dibuat dengan private key pengirim

## Perbedaan dengan Tugas 3

| Aspek | Tugas 3 | Tugas 4 |
|-------|---------|---------|
| RSA Keypair | Hanya server | Server + setiap client |
| Digital Signature | ❌ Tidak ada | ✅ RSA signature SHA-256 |
| Autentikasi Pengirim | ❌ Hanya nama | ✅ Cryptographic proof |
| Integritas Pesan | ⚠️ Partial (encryption) | ✅ Full (signature) |
| Non-repudiation | ❌ Tidak ada | ✅ Ada |
| Indikator Verifikasi | - | ✓ atau ✗ |
| Client Public Key | Tidak dikirim | Dikirim ke server |

## Contoh Skenario Penggunaan

### Skenario 1: Chat Normal
```
Client_1 >>> Halo semuanya!
[Server log: Client_1: Halo semuanya! ✓ (signature verified)]

Client_2 menerima: "Client_1: Halo semuanya! ✓"
```

### Skenario 2: Deteksi Pesan Palsu
Jika attacker mencoba mengirim pesan dengan nama Client_1 tanpa private key yang benar:
```
[Server log: Client_1: Pesan palsu ✗ (INVALID SIGNATURE)]
Client_2 menerima: "Client_1: Pesan palsu (no signature)"
```

### Skenario 3: Deteksi Modifikasi
Jika pesan dimodifikasi setelah di-sign:
```
[Server log: Client_1: Pesan diubah ✗ (INVALID SIGNATURE)]
```

## File yang Dihasilkan

- `.client_<nama>_des_key.bin` - Kunci DES persisten per client

**Catatan:** RSA keypair untuk signing di-generate ulang setiap kali client restart (tidak persisten). Ini memastikan forward secrecy untuk signature keys.

## Troubleshooting

### Signature Verification Failed
- Pastikan client sudah mengirim public key saat key exchange
- Restart client jika ada masalah dengan keypair

### Pesan Tidak Terkirim
- Cek koneksi ke server
- Pastikan DES key exchange berhasil

### Key Mismatch
```bash
# Hapus file DES key dan restart client
rm .client_*_des_key.bin
python http_client.py
```

## Keamanan dan Limitasi

### ⚠️ Disclaimer
Implementasi ini untuk tujuan **edukasi** dan **tidak disarankan untuk produksi**:

1. **RSA 1024-bit**: Terlalu lemah untuk standar modern (minimal 2048-bit)
2. **DES 56-bit**: Sudah deprecated, gunakan AES-256
3. **No TLS/HTTPS**: Transport tidak terenkripsi
4. **Signature keys tidak persisten**: Generate ulang setiap restart
5. **No certificate authority**: Tidak ada validasi identitas client

### 🔐 Rekomendasi untuk Produksi
1. Gunakan **RSA 2048/4096-bit** atau **ECDSA P-256**
2. Ganti DES dengan **AES-256-GCM**
3. Implementasi **TLS 1.3** untuk transport security
4. Gunakan **certificate-based authentication**
5. Implementasi **timestamp** dan **nonce** untuk mencegah replay attack
6. Persisten signature keys dengan enkripsi
7. Key rotation policy

## Testing

### Test 1: Signature Verification
1. Jalankan server dan 2 client
2. Client_1 kirim pesan
3. Verifikasi server log menunjukkan `✓ (signature verified)`
4. Verifikasi Client_2 menerima dengan `✓`

### Test 2: Multiple Messages
1. Kirim beberapa pesan dari berbagai client
2. Semua harus verified
3. Cek server log untuk semua verifikasi

### Test 3: Client Reconnect
1. Client join, kirim pesan (verified)
2. Client quit dan join lagi
3. Kirim pesan lagi (verified dengan keypair baru)

## Implementasi Teknis

### Hash Function
- **SHA-256** untuk hashing pesan
- Output 256-bit hash yang di-sign dengan RSA

### Signature Format
- Integer hasil enkripsi hash dengan RSA private key
- Dikirim sebagai string dalam JSON

### Key Storage
- **Server**: Menyimpan public key semua client di memory
- **Client**: Private key hanya di memory (tidak persisten)
- **DES Key**: Persisten di file `.client_*_des_key.bin`

### Message Flow
```
Plaintext → SHA-256 → Hash → RSA Private Key → Signature
                                                    ↓
                                            (Kirim ke server)
                                                    ↓
Signature → RSA Public Key → Hash' ← SHA-256 ← Plaintext
                                ↓
                         Hash == Hash' ? 
                              ↓
                         ✓ atau ✗
```

## Referensi

- RSA: Rivest, Shamir, Adleman (1977)
- DES: Data Encryption Standard (NIST, 1977)
- SHA-256: Secure Hash Algorithm 256-bit (NIST, 2001)
- Digital Signature Standard (DSS): FIPS 186-4

---

**Keamanan Informasi - Kelas C - 2025**

*Digital signatures provide authentication, integrity, and non-repudiation*
