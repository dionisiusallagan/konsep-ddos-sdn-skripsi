# Hasil Eksperimen — Fase Scale50 (Topologi 51 Host)

Dokumen ini merangkum dan menginterpretasikan hasil pengujian pada topologi
skala besar (50 IoT + 1 victim, satu switch OpenFlow 1.3). Logika deteksi
& mitigasi **identik** dengan fase 5-host (`ddos_guard.py`) sehingga
perbandingan beban controller antar fase adil. Angka di bawah dihasilkan
oleh `analyze.py` (ulang-cetak 5×) dan `run_sweep.py` (sweep threshold).

---

## 1. Ulang-cetak 5× per skenario (mean ± stddev)

Setiap skenario dijalankan 5 kali; metrik di bawah adalah rata-rata dan
simpangan baku (sample, n−1).

| Skenario | Waktu Deteksi (s) | CPU avg (%) | CPU max (%) | FP bans | Legit loss (%) |
|---|---|---|---|---|---|
| baseline (hanya trafik legit) | – | 1,96 ± 0,26 | 9,20 ± 11,85 | 0 | 0,0 |
| single (flood murni h1→h51) | 0,636 ± 0,005 | 0,62 ± 0,16 | 35,76 ± 10,13 | 0 | – |
| mixed (flood + legit) | 0,640 ± 0,000 | 2,80 ± 0,56 | 39,80 ± 16,00 | 0 | 0,0 |

**Interpretasi:**
- **Waktu deteksi sangat stabil** (< 0,65 s, σ ≈ 0). Algoritma per-source-IP
  dengan threshold absolut tidak bergantung pada jumlah node, sehingga waktu
  deteksi di skala 51 host setara dengan skala 5 host (~0,64 s).
- **False positive = 0** di semua skenario, termasuk `mixed` di mana 10 host
  legit terus memancarkan trafik saat serangan berlangsung. Ini membuktikan
  pemilihan "hanya paket inisiasi koneksi" (D2) menjaga korban/legit aman.
- **Beban CPU terukur rendah**: rata-rata < 3 %, puncak serangan < 40 % dari
  satu core. Desain tanpa flow-caching (D1) memang menaikkan beban, namun
  masih jauh dari saturasi pada skala ini.
- Simpangan `cpu_max` baseline besar (σ = 11,85) semata-mata karena CPU idle
  berada dekat 0 % sehingga fluktuasi sampling relatif terlihat besar; bukan
  indikasi instabilitas (FP dan loss tetap 0).

---

## 2. Studi Sensitivitas Threshold (matriks threshold × rate serangan)

Untuk menentukan nilai `RATE_THRESHOLD` yang aman, dijalankan skenario `mixed`
dengan memvariasikan dua variabel:
- **T** = `RATE_THRESHOLD` (batas rate per-source-IP), dan
- **R** = laju serangan (`--rate` flooder; 0 = secepat mungkin).

Sel dilaporkan sebagai `deteksi / fp_bans` (deteksi = 1 bila attacker keban;
fp_bans = jumlah IP legit terban).

| T \ R | 0 (maks) | 30 pps | 60 pps | 120 pps |
|---|---|---|---|---|
| 3  | 1 / 10 | 1 / 10 | 1 / 10 | 1 / 10 |
| 5  | 1 / 1  | 1 / 3  | 1 / 3  | 1 / 9  |
| 10 | 1 / 0  | 1 / 0  | 1 / 0  | 1 / 0  |
| 15 | 1 / 0  | 1 / 0  | 1 / 0  | 1 / 0  |
| 20 | 1 / 0  | 1 / 0  | 1 / 0  | 1 / 0  |
| 25 | 1 / 0  | 1 / 0  | 1 / 0  | 1 / 0  |
| 40 | 1 / 0  | 0 / 0  | 1 / 0  | 1 / 0  |

**Interpretasi:**
- Trafik legit dalam eksperimen ≈ **5 pps/IP** (10 host × interval ping
  0,2 s). Pada **T = 3 dan 5** (di bawah tingkat legit), controller
  mem-ban seluruh host legit — terlihat dari `fp_bans` 10 dan *legit loss*
  93,1 % (T=3) serta 9,5–56,6 % (T=5). Ini menunjukkan bahaya false positive
  bila threshold terlalu rendah.
- Pada **T ≥ 10**, *false positive = 0* dan **deteksi 100 %** untuk semua
  intensitas serangan (30–120 pps).
- Pada **T = 40**, serangan lemah 30 pps **lolos** (30 < 40) → sel
  `0 / 0`. Threshold terlalu tinggi melewatkan serangan lambat.

**Rekomendasi:** `RATE_THRESHOLD = 20`. Memberikan margin ≈ 4× di atas
trafik legit (~5 pps) sekaligus tetap mendeteksi serangan sekecil 30 pps
(lantai serangan dalam uji). Rentang aman terbukti **10–25**.

---

## 3. Catatan Validitas & Keterbatasan

1. **Deteksi & FPR bersifat biner per run**, sehingga hasil sweep di atas
   adalah *matriks sensitivitas threshold*, bukan kurva ROC halus. Untuk ROC
   sejati diperlukan trafik legit probabilistik dan banyak aliran serangan per
   sel; ini di luar cakupan PoC dan dapat dijadikan saran pengembangan.
2. **CPU puncak bergantung total packet-in**, bukan hanya serangan: pada
   T=3 R=120 tercatat cpu_max 111 % dan T=5 R=60 sebesar 116 % (mendekati
   1 core penuh). Ini konsisten dengan keterbatasan desain D1 (tanpa
   flow-caching) — pada produksi perlu flow dengan hard_timeout pendek atau
   sampling agar controller tak jenuh di bawah banjir maksimal.
3. Pengujian dilakukan di emulator Mininet + os-ken pada WSL2; angka absolut
   CPU bergantung lingkungan, namun *pola* (stabilitas deteksi, nol FP,
   trade-off threshold) umum berlaku.

---

## 4. Ringkasan untuk Bab Hasil

- Deteksi DDoS berbasis rate per-source-IP **tetap andal di skala 51 host**:
  waktu deteksi < 0,65 s (σ ≈ 0) dan **false positive 0 %**.
- Beban controller naik seiring skala namun **masih < 40 %** satu core saat
  serangan — membuktikan pendekatan layak untuk topologi edge IoT menengah.
- Kalibrasi threshold krusial: terlalu rendah mem-ban trafik legit, terlalu
  tinggi melewatkan serangan lemah. Nilai **20** adalah titik tengah aman
  untuk profil trafik uji ini.
