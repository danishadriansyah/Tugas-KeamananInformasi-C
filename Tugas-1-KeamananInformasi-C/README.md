# Implementasi Manual Data Encryption Standard (DES)

## Deskripsi
Repositori ini berisi implementasi lengkap dari algoritma Data Encryption Standard (DES) yang dibuat dari nol tanpa menggunakan library kriptografi eksternal. Implementasi ini dibuat untuk tujuan edukatif untuk memahami cara kerja internal algoritma DES secara mendalam.

## Penjelasan Kode DES.py

Kode ini adalah implementasi lengkap dari algoritma Data Encryption Standard (DES) dari nol. Tujuannya adalah untuk menunjukkan pemahaman tentang cara kerja internalnya, bukan untuk digunakan pada aplikasi sungguhan.

Kode ini dibagi menjadi 5 bagian utama:

1. **Konstanta Standar DES**: Tabel-tabel inti yang menjadi dasar algoritma
2. **Fungsi-fungsi Pembantu**: Fungsi kecil untuk manipulasi data (bit dan byte)
3. **Logika Utama DES**: Fungsi inti yang menjalankan enkripsi/dekripsi sesuai standar DES
4. **Fungsi Wrapper**: Fungsi yang memudahkan pengguna untuk mengenkripsi/mendekripsi teks
5. **Fungsi main**: Bagian yang berinteraksi dengan pengguna

### 1. Konstanta Standar DES (Baris 3-96)

Bagian ini berisi semua tabel dan nilai tetap yang didefinisikan dalam standar DES:

- **IP dan FP**: Initial Permutation dan Final Permutation. Tabel ini digunakan untuk mengacak urutan bit pada blok data di awal dan mengembalikannya di akhir proses.

- **E**: Expansion Table. Digunakan dalam fungsi Feistel untuk memperluas blok data 32-bit menjadi 48-bit agar bisa di-XOR dengan subkunci.

- **P**: Permutation Table (P-box). Mengacak hasil keluaran dari S-box.

- **S_BOX**: Substitution Boxes. Ini adalah inti dari keamanan DES. Ada 8 S-box yang menggantikan 6-bit input menjadi 4-bit output secara non-linear. Proses ini menciptakan confusion (membuat hubungan antara ciphertext dan kunci menjadi rumit).

- **PC1 dan PC2**: Permuted Choice 1 & 2. Digunakan dalam proses pembuatan subkey (jadwal kunci). PC1 memilih 56 bit dari kunci 64-bit awal, dan PC2 memilih 48 bit dari 56 bit untuk membuat subkey di setiap putaran.

- **KEY_SHIFTS**: Menentukan berapa banyak pergeseran bit ke kiri yang harus dilakukan pada kunci di setiap putaran saat membuat subkey.

### 2. Fungsi-fungsi Pembantu (Baris 98-135)

Fungsi-fungsi ini melakukan tugas-tugas dasar yang dibutuhkan oleh algoritma:

- **`permute(block, table)`**: Fungsi serbaguna untuk mengacak block bit sesuai dengan urutan yang didefinisikan di table.

- **`string_to_bits(text)` dan `bits_to_string(bits)`**: Mengubah data dari format yang bisa dibaca manusia (string) ke format yang bisa diproses algoritma (list bit), dan sebaliknya.

- **`xor(bits1, bits2)`**: Melakukan operasi XOR bit per bit.

- **`left_shift(bits, n)`**: Melakukan pergeseran bit sirkular ke kiri.

- **`pad(data)` dan `unpad(data)`**: Menambah dan menghapus padding (byte tambahan). Ini penting karena DES hanya bisa memproses data dalam blok berukuran pas 64 bit (8 byte). Jika blok terakhir kurang dari 8 byte, fungsi pad akan menambahkannya menggunakan standar PKCS7.

### 3. Logika Utama DES (Baris 137-195)

Ini adalah jantung dari implementasi DES:

#### `generate_subkeys(key_bits)`: 
Fungsi ini mengimplementasikan **Jadwal Kunci (Key Schedule)**:
- Mengambil kunci 64-bit dan melakukan permutasi dengan PC1 untuk menghasilkan 56-bit
- Membagi 56-bit menjadi dua bagian (kiri dan kanan), masing-masing 28-bit  
- Melakukan 16 kali putaran:
  - Menggeser setiap bagian ke kiri sesuai jadwal KEY_SHIFTS
  - Menggabungkan kembali kedua bagian dan melakukan permutasi dengan PC2 untuk menghasilkan satu subkey 48-bit
- Menghasilkan total 16 subkey

#### `feistel_function(block_32_bits, subkey_48_bits)`: 
Ini adalah implementasi **Fungsi Feistel (F)**:
- `permute(..., E)`: Blok 32-bit diperluas menjadi 48-bit
- `xor(...)`: Hasilnya di-XOR dengan subkey 48-bit
- `S_BOX[...]`: Hasil XOR dibagi menjadi 8 bagian 6-bit, lalu dimasukkan ke 8 S-box. Setiap S-box menghasilkan output 4-bit
- `permute(..., P)`: Gabungan output S-box (32-bit) diacak dengan P-box

#### `process_block(block_64_bits, subkeys, mode)`: 
Fungsi ini memproses satu blok 64-bit:
- Blok diacak dengan IP
- Blok dibagi dua: left dan right (masing-masing 32-bit)
- Dilakukan 16 putaran **Jaringan Feistel**. Pada setiap putaran:
  - Bagian right dimasukkan ke feistel_function bersama subkey putaran tersebut
  - Hasilnya di-XOR dengan bagian left
  - Bagian left dan right ditukar (swap)
- Setelah 16 putaran, left dan right digabung kembali dan diacak dengan FP
- Jika mode adalah 'decrypt', subkey digunakan dalam urutan terbalik (dari 16 ke 1)

#### `des_algorithm(data_bits, subkeys, mode)`: 
Fungsi ini menerapkan proses enkripsi/dekripsi ke seluruh data. Ia memecah data menjadi blok-blok 64-bit dan memanggil process_block untuk setiap blok secara independen. Ini adalah implementasi dari **mode operasi ECB (Electronic Codebook)**.

### 4. Fungsi Wrapper untuk Pengguna (Baris 197-218)

Fungsi ini menyederhanakan proses bagi pengguna:

#### `encrypt_text(plain_text, key)`: 
Mengambil teks biasa dan kunci, lalu:
- Mengubah teks dan kunci ke format bit
- Memanggil generate_subkeys
- Memanggil pad untuk menambahkan padding
- Memanggil des_algorithm untuk mengenkripsi
- Mengubah hasil bit ke format hex yang bisa ditampilkan

#### `decrypt_text(encrypted_text_hex, key)`: 
Melakukan kebalikannya dari proses enkripsi.

### 5. Fungsi main (Baris 220-258)

Bagian ini adalah antarmuka pengguna berbasis terminal:
- Menampilkan menu pilihan (enkripsi, dekripsi, keluar)
- Meminta input dari pengguna (teks dan ciphertext)
- Memanggil fungsi encrypt_text atau decrypt_text dan menampilkan hasilnya

## Cara Penggunaan

1. Jalankan program:
```bash
python DES.py
```

2. Pilih menu yang tersedia:
   - **Menu 1**: Enkripsi teks - Masukkan teks yang ingin dienkripsi
   - **Menu 2**: Dekripsi teks - Masukkan ciphertext dalam format hexadecimal
   - **Menu 3**: Keluar dari program

3. Program akan menggunakan kunci default `'mysecret'` untuk semua operasi.

## Fitur Implementasi

-  **Implementasi Lengkap DES**: Semua komponen standar DES (IP, FP, E, P, S-boxes, PC1, PC2)
-  **Key Schedule**: Generasi 16 subkey dari kunci utama
-  **Feistel Network**: 16 putaran dengan fungsi Feistel lengkap
-  **Padding PKCS7**: Menangani data dengan ukuran yang tidak kelipatan 8 byte
-  **Mode ECB**: Electronic Codebook mode untuk memproses multiple blocks
-  **Interface User-Friendly**: Menu interaktif untuk enkripsi dan dekripsi

## Catatan Penting

 **Implementasi ini dibuat untuk tujuan edukatif**. Untuk aplikasi produksi, gunakan library kriptografi yang sudah teruji dan dioptimalkan.

## Struktur File

```
├── DES.py          # Implementasi lengkap algoritma DES
└── README.md       # Dokumentasi dan penjelasan kode
```

## Konsep Kriptografi yang Diimplementasikan

1. **Confusion**: Dicapai melalui S-boxes yang membuat hubungan kompleks antara plaintext dan ciphertext
2. **Diffusion**: Dicapai melalui permutasi (P-box) yang menyebarkan perubahan bit ke seluruh blok
3. **Key Schedule**: Proses sistematis untuk menghasilkan subkey dari kunci utama
4. **Feistel Network**: Struktur yang memungkinkan dekripsi dengan menggunakan fungsi yang sama seperti enkripsi
5. **Block Cipher**: Enkripsi data dalam blok-blok berukuran tetap (64-bit untuk DES)
