# Tugas - Keamanan Informasi Kelas C

**Mata Kuliah**: Keamanan Informasi  
**Kelas**: C

## Tim Pengembang

| Nama | NRP |
|------|-----|
| Muhammad Danis Hadriansyah | 5025221239 |
| Fathurazka Gamma Syuhada | 5025231246 |

---

## 📚 Daftar Tugas

- [Tugas 1: DES Encryption](Tugas-1-KeamananInformasi-C/)
- [Tugas 2: HTTP Chat with DES](Tugas-2-KeamananInformasi-C/)
- [Tugas 3: RSA Key Exchange + DES Chat](Tugas-3-KeamananInformasi-C/)
- [Tugas 4: Digital Signature with RSA](Tugas-4-KeamananInformasi-C/)

---

## 🚀 Setup Umum

### Prerequisites
```bash
# Install Python dependencies
pip install requests
```

### Setup Cloudflared (Opsional - untuk Remote Access)

Cloudflared diperlukan jika Anda ingin mengakses server dari luar jaringan lokal (misalnya dari device lain atau internet).

#### Windows
1. Download cloudflared dari [https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/)
2. Extract dan tambahkan ke PATH, atau letakkan di folder project

#### Cara Menggunakan Cloudflared
Setelah server berjalan, buka terminal baru:
```bash
cloudflared tunnel --url http://localhost:65432
```

Output akan menampilkan URL publik seperti:
```
https://random-name.trycloudflare.com
```

Gunakan URL tersebut di client untuk akses dari mana saja.

**Catatan**: Untuk testing lokal normal, cloudflared **tidak diperlukan**. Cukup gunakan `http://localhost:65432`.

---

## 📖 Cara Menjalankan Setiap Tugas

### Tugas 1: DES Encryption
```bash
cd Tugas-1-KeamananInformasi-C
python DES.py
```

### Tugas 2: HTTP Chat with DES

**Server:**
```bash
cd Tugas-2-KeamananInformasi-C
python http_server.py
```

**Client (terminal baru):**
```bash
cd Tugas-2-KeamananInformasi-C
python http_client.py
```
Input URL: `http://localhost:65432` (atau URL cloudflared jika remote)

### Tugas 3: RSA Key Exchange + DES Chat

**Server:**
```bash
cd Tugas-3-KeamananInformasi-C
python http_server.py
```

**Client (terminal baru):**
```bash
cd Tugas-3-KeamananInformasi-C
python http_client.py
```
Input URL: `http://localhost:65432` (atau URL cloudflared jika remote)

### Tugas 4: Digital Signature with RSA

**Server:**
```bash
cd Tugas-4-KeamananInformasi-C
python http_server.py
```

**Client (terminal baru):**
```bash
cd Tugas-4-KeamananInformasi-C
python http_client.py
```
Input URL: `http://localhost:65432` (atau URL cloudflared jika remote)

---

## 🔧 Troubleshooting Umum

### Port Already in Use
```bash
# Tutup program yang menggunakan port 65432, atau ubah PORT di server
```

### Module Not Found
```bash
pip install requests
```

### Key Mismatch (Tugas 3 & 4)
```bash
# Hapus file DES key dan restart client
rm .client_*_des_key.bin
# atau di Windows:
del .client_*_des_key.bin
```

### Cloudflared Connection Issues
- Pastikan server sudah berjalan sebelum menjalankan cloudflared
- Periksa koneksi internet
- Coba restart cloudflared tunnel

---

## 🎯 Perbedaan Antar Tugas

| Fitur | Tugas 1 | Tugas 2 | Tugas 3 | Tugas 4 |
|-------|---------|---------|---------|---------|
| DES Encryption | ✅ | ✅ | ✅ | ✅ |
| HTTP Server/Client | ❌ | ✅ | ✅ | ✅ |
| RSA Key Exchange | ❌ | ❌ | ✅ | ✅ |
| Digital Signature | ❌ | ❌ | ❌ | ✅ |
| Shared DES Key | N/A | Ya (hardcoded) | Ya (per client) | Ya (per client) |
| Authentication | ❌ | ❌ | ⚠️ Partial | ✅ Full |
| Integrity Check | ❌ | ❌ | ⚠️ Partial | ✅ Full |

---

## 📝 Lisensi

Projek ini dibuat untuk keperluan pembelajaran mata kuliah Keamanan Informasi.

---

*Keamanan Informasi - Kelas C - 2025*
