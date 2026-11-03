# Catatan Tahap D — Load Sweep Perbandingan Algoritme

Status: **selesai & tervalidasi**. Tanggal: 3 November 2026.
Hasil: 45 run (5 rate × 3 algoritme × 3 repeat) dalam 34,7 menit, exit 0.
Skrip: `experiments/run_sweep_compare.py` (baru), dengan perluasan
`experiments/run_experiment.py` (`--repeat-start`, `--subdir`, metrik deteksi
presisi) dan `traffic/flood_scapy.py` (`t0_epoch` pada penanda mulai).

---

## 1. Tujuan

Tahap C hanya memberi **satu titik beban** (500 pps) per algoritme, sehingga
belum bisa menjawab pertanyaan skripsi: *bagaimana kinerja ketiga algoritme
berubah ketika beban serangan naik?* Tahap D memetakan:

- waktu deteksi,
- CPU controller,
- packet loss host legitimate,
- throughput per CPU,

pada beban **100 / 500 / 1000 / 1500 / 3000 pps**, masing-masing **3 kali
pengulangan** (36–45 run), lalu melaporkannya sebagai **mean ± stddev**.

---

## 2. Rancangan eksperimen

### 2.1 Variabel

| Jenis | Nilai |
|---|---|
| Variabel bebas | algoritme (baseline, S2TD, entropi) dan beban serangan (pps) |
| Variabel terikat | `detection_time_s`, `cpu_attack_avg_pct`, `legit_loss_max_pct`, `throughput_per_cpu` |
| Variabel kontrol | topologi (5 host: 1 penyerang, 3 legit, 1 victim), skenario `mixed`, durasi (warmup 5 s + serangan 10 s + observasi 20 s), `--legit-count 3`, protokol TCP port 80 |

### 2.2 Urutan eksekusi (rate terluar)

```
for rate in [100, 500, 1000, 1500, 3000]:
    for algo in [baseline, s2td, entropy]:
        for repeat in [1, 2, 3]:
            jalankan satu run independen
```

Rate dibuat sebagai loop **terluar** supaya ketiga algoritme diuji pada beban
yang sama secara berdekatan. Kalau algoritme yang jadi loop terluar, seluruh
pengukuran baseline selesai lebih dulu, lalu S2TD, lalu entropi — sehingga
drift lingkungan (suhu CPU, cache, beban latar WSL) bisa muncul sebagai
"perbedaan algoritme". Ini adalah kontrol bias yang penting untuk disebut di
bab metodologi.

### 2.3 Aturan berhenti (saturasi)

Setelah semua repeat pada satu titik `(algo, rate)` selesai, titik ditandai
**jenuh** bila:

```
cpu_attack_mean > 80 %   ATAU   legit_loss_max > 1 %
```

Algoritme yang sudah jenuh **dilewati** pada rate yang lebih tinggi (tidak ada
gunanya menekan beban lebih jauh), sedangkan algoritme lain tetap lanjut.
Alasan dicatat di kolom `stop_reason` dan `saturated` supaya keputusan ini
auditable, bukan tersembunyi di narasi.

Ambang 80 % CPU dipilih karena di atas itu pengukuran waktu deteksi mulai
tidak stabil (proses controller berebut CPU dengan eventlet/OVS); ambang 1 %
loss legitimate dipilih karena itu sudah ketara bagi pengguna akhir.

### 2.4 Satu run = satu proses bersih

Setiap run memanggil `run_experiment.py` sebagai **proses terpisah** yang:
1. mematikan controller yatim + membersihkan OVS (`mn -c`),
2. membangun ulang topologi,
3. menyalakan controller algoritme yang diminta,
4. menjalankan serangan dengan laju terjadwal,
5. menulis satu baris ke `results/exp_summary_compare.csv`.

Tidak ada state yang diwarisi antar-run (flow table, controller, counter),
sehingga tiap baris bisa diperlakukan sebagai sampel independen.

---

## 3. Definisi metrik (penting untuk bab hasil)

### 3.1 `detection_time_s` — diperbaiki di Tahap D

Versi Tahap C memakai polling `ovs-ofctl dump-flows` tiap 0,2 s. Itu punya dua
cacat yang **terbukti** pada data sweep pertama:

| Cacat | Bukti |
|---|---|
| Terkuantisasi 0,2 s | semua nilai kelipatan ~0,22 s |
| Punya "lantai" ~0,01–0,05 s | satu run baseline tercatat 0,01 s, run lain 0,22 s, padahal perilakunya sama |

Penyebab lantai: polling hanya bisa menyatakan *"rule sudah ada saat saya
memeriksa"*. Kalau ban terjadi lebih cepat daripada durasi satu pemanggilan
`ovs-ofctl`, hasilnya adalah durasi pemanggilan itu sendiri.

**Perbaikan (Tahap D):** `detection_time_s` dihitung dari **jam dinding**:

```
detection_time_s = ts_iso(event pertama di CSV algoritme) − t0_epoch(flooder)
```

- `t0_epoch` dicetak flooder tepat sebelum paket pertama dikirim
  (`[flood] started ... t0_epoch=<epoch>`), sehingga **tidak** terkena jeda
  pembacaan berkas oleh runner (yang di WSL/drvfs bisa puluhan milidetik).
- `ts_iso` ditulis controller tepat setelah rule DROP dipasang.
- Hasil polling tetap disimpan di kolom `detection_time_poll_s` sebagai
  pembanding/audit.

**Validasi silang analitis** (bukan sekadar "kelihatan masuk akal"):
baseline mem-ban saat paket ke-26 (ambang 25). Maka
`detection_time ≈ 26 / rate`:

| Rate | Perkiraan 26/rate | Terukur (presisi) |
|---|---|---|
| 500 pps | 52 ms | 51 ms |
| 1500 pps | 17 ms | 18 ms |

Kesesuaian ini menunjukkan metrik baru mengukur apa yang kita klaim.

### 3.2 Kenapa S2TD punya sebaran ±1 detik

S2TD membaca counter switch tiap `T_poll = 1 s` dan menuntut `T_confirm = 2`
konfirmasi berturut-turut. Akibatnya waktu deteksinya **terkuantisasi pada
grid 1 detik**, dan nilai rata-ratanya bergeser penuh 1 detik bila fase
polling bergeser relatif terhadap awal serangan (mis. karena waktu startup
controller berbeda).

**Ini bukan noise pengukuran, melainkan sifat algoritme** dan harus ditulis
apa adanya: S2TD "membayar" kecepatan dengan CPU rendah, dan harganya adalah
deteksi yang lebih lambat + terkuantisasi.

### 3.3 `throughput_per_cpu`

```
throughput_per_cpu = flood_actual_pps / cpu_attack_avg_pct   [pps per 1 % CPU]
```

- `flood_actual_pps` = laju yang **benar-benar** terkirim (dari baris akhir
  flooder), bukan nominal.
- `cpu_attack_avg_pct` = CPU controller pada **fase serangan** saja
  (warmup selesai → serangan selesai), bukan rata-rata seluruh run.

**Peringatan tafsir (wajib di bab pembahasan).** Karena ketiga algoritme
mem-ban dalam < 100 ms, controller praktis idle selama sisa 10 detik serangan.
Akibatnya CPU nyaris **tidak bergantung pada beban**, dan `throughput_per_cpu`
naik hampir linear mengikuti rate — itu **bukan** bukti skalabilitas tanpa
batas, melainkan konsekuensi dari mitigasi yang cepat. Metrik ini mengukur
"berapa paket serangan ditangani per 1 % CPU **sampai mitigasi aktif**",
bukan kapasitas sustained. Untuk mengukur kapasitas sustained, penyerang harus
memakai IP sumber berputar/spoofed agar ban tidak efektif — itu di luar
lingkup skripsi ini (lihat bagian Keterbatasan).

### 3.4 `detected_rate_pps`

Informatif saja, **tidak boleh** dibandingkan antar algoritme:

| Algo | Arti |
|---|---|
| baseline | selalu ≈ ambang+1 (26) — bukan intensitas serangan |
| S2TD | laju nyata (counter switch satu interval penuh) |
| entropi | isi window saat evaluasi, bisa setengah dari laju nyata |

---

## 4. Perbaikan teknis lain yang ditemukan saat Tahap D

1. **Kolom `repeat` selalu 1.** Skrip sweep memanggil runner sekali per
   repeat, dan runner selalu memulai penomoran dari 1. Ditambahkan opsi
   `--repeat-start` sehingga CSV mencatat 1..N dengan benar.
2. **`compare_stats.csv` tidak bisa digabung bertahap.** Semula file ditulis
   ulang hanya dari titik pada invokasi berjalan. Sekarang `merge_levels()`
   menggabungkan dengan isi file lama (kunci: algo + skenario + rate),
   sehingga sweep bisa dilanjutkan ke rate lebih tinggi tanpa kehilangan
   hasil sebelumnya dan tanpa duplikasi baris.
3. **`--subdir`** pada runner: log controller, timeseries, dan log flood
   disimpan di `results/tahapD/` agar `results/` tidak dipenuhi ratusan file.

---

## 5. Hasil

45 run, semua berhasil (`exit 0`), **tidak ada** run yang gagal deteksi,
**tidak ada** false positive, **tidak ada** packet loss pada host legitimate.
Laju nyata sama persis dengan nominal di kelima titik beban
(`flood_actual == flood_rate`, 100/500/1000/1500/3000 pps).

### 5.1 Waktu deteksi (detik, mean ± stddev, n=3)

| Rate (pps) | Baseline | Entropi | S2TD |
|---|---|---|---|
| 100 | **0,252 ± 0,000** | 0,966 ± 0,006 | 2,390 ± 0,116 |
| 500 | **0,052 ± 0,000** | 0,464 ± 0,003 | 2,450 ± 0,023 |
| 1000 | **0,028 ± 0,001** | 0,429 ± 0,063 | 2,438 ± 0,017 |
| 1500 | **0,019 ± 0,001** | 0,472 ± 0,018 | 2,463 ± 0,007 |
| 3000 | **0,011 ± 0,002** | 0,464 ± 0,006 | 2,460 ± 0,022 |

Tiga pola yang berbeda secara kualitatif:

1. **Baseline turun sebanding 1/rate.** Karena mem-ban tepat pada paket
   ke-26, waktu deteksinya = 26/rate. Diuji terhadap teori:

   | Rate | Teori 26/rate | Terukur | Error |
   |---|---|---|---|
   | 100 pps | 260,0 ms | 252,0 ms | −3,1 % |
   | 500 pps | 52,0 ms | 52,0 ms | 0,0 % |
   | 1000 pps | 26,0 ms | 27,7 ms | +6,4 % |
   | 1500 pps | 17,3 ms | 18,7 ms | +7,7 % |
   | 3000 pps | 8,7 ms | 11,0 ms | +26,9 % (≈ +2,3 ms absolut) |

   Selisih positif kecil di beban tinggi adalah biaya tetap pemasangan flow
   mod (±2 ms), bukan kesalahan pengukuran.

2. **Entropi punya lantai ±0,46 s** karena evaluasi berjalan tiap 0,5 s;
   nilai 0,966 s di 100 pps muncul karena window belum terisi `min_pkts=30`
   (30 paket butuh 0,3 s pada 100 pps) sehingga butuh satu siklus evaluasi
   tambahan. Artinya kecepatan entropi **tidak membaik** setelah beban cukup
   untuk mengisi window.

3. **S2TD datar ±2,45 s** di semua beban, sesuai desainnya: `T_poll=1 s` ×
   `T_confirm=2` + waktu trigger. Nilai ini **tidak** membaik pada serangan
   berat — inilah harga dari pengecekan berkala.

### 5.2 CPU controller fase serangan (%, mean ± stddev)

| Rate (pps) | Baseline | Entropi | S2TD |
|---|---|---|---|
| 100 | 1,10 ± 0,10 | 1,53 ± 0,06 | **0,13 ± 0,06** |
| 500 | 0,87 ± 0,06 | 1,77 ± 0,06 | **0,13 ± 0,06** |
| 1000 | 0,87 ± 0,06 | 2,47 ± 0,15 | **0,17 ± 0,06** |
| 1500 | 0,93 ± 0,15 | 3,47 ± 0,15 | **0,13 ± 0,06** |
| 3000 | 0,80 ± 0,17 | 4,40 ± 0,17 | **0,20 ± 0,00** |

**Temuan utama Tahap D:** CPU controller ditentukan oleh **berapa paket yang
masuk ke control plane**, bukan oleh rate serangan. Jumlah itu = rate × waktu
deteksi:

| Algo | Paket yang diproses selama jendela deteksi (100 → 3000 pps) | CPU (100 → 3000 pps) | Perilaku |
|---|---|---|---|
| Baseline | 25 → 33 paket (selalu ≈ ambang 26) | 1,10 → 0,80 % | **datar** — jumlah paket dibatasi ambang |
| Entropi | 97 → 1.393 paket | 1,53 → 4,40 % | **naik linear** |
| S2TD | 239 → 7.379 paket *melewati switch* | 0,13 → 0,20 % | **datar** — paket tidak pernah masuk control plane |

Regresi entropi: `CPU% ≈ 1,42 + 0,00228 × jumlah_paket` dengan **R² = 0,95**.
Artinya kenaikan CPU entropi murni akibat memproses lebih banyak paket,
bukan inefisiensi per paket (biaya per paket justru **turun**: 15,9 → 3,2
m%/paket karena biaya tetap 1,42 % terbagi ke lebih banyak paket).

Konsekuensi metodologis yang harus ditulis: **CPU rendah belum tentu
algoritme lebih efisien** — pada baseline, CPU rendah karena ia cepat
menutup pintu (26 paket), bukan karena pemrosesannya murah. S2TD unggul
karena alasan berbeda lagi: flow caching memindahkan trafik ke data plane.

### 5.3 Throughput per CPU (pps per 1 % CPU)

| Rate (pps) | Baseline | Entropi | S2TD |
|---|---|---|---|
| 100 | 90,91 | 65,22 | 750,00 |
| 500 | 576,92 | 283,02 | 3.750,00 |
| 1000 | 1.153,85 | 405,41 | 6.000,00 |
| 1500 | 1.607,14 | 432,69 | 11.250,00 |
| 3000 | 3.750,00 | 681,82 | 15.000,00 |

Angka ini **tidak boleh** dibaca sebagai kapasitas sustained (lihat §3.3):
karena CPU hampir datar, `tput/cpu` otomatis naik mengikuti rate. Yang sah
dibaca adalah **rasio antar algoritme pada rate yang sama**: S2TD 1–2 orde
lebih tinggi dari baseline, dan baseline 1,7–5,5× lebih tinggi dari entropi.

### 5.4 Saturasi

Tidak ada titik yang jenuh: CPU tertinggi hanya **4,60 %** (entropi @3000
pps) dan loss legitimate **0,00 %**. Aturan berhenti (CPU > 80 % / loss > 1 %)
karena itu tidak pernah aktif, dan semua algoritme diuji sampai 3000 pps
(30× titik terendah).

Artinya: **dalam rentang yang bisa dihasilkan flooder perangkat lunak
(≤ 3000 pps terjadwal, ±94.000 pps tanpa pacing di jalur lokal), ketiga
algoritme belum mendekati saturasi.** Menemukan titik jenuh butuh beban jauh
lebih besar atau mekanisme serangan yang membuat ban tidak efektif (IP
sumber berputar) — dicatat sebagai keterbatasan, bukan kegagalan eksperimen.

### 5.5 Perbandingan dengan hasil polling (arsip v1)

Sweep pertama (metrik polling) diarsipkan sebagai
`results/exp_summary_compare_v1-polling.csv`,
`results/compare_stats_v1-polling.csv`, dan `results/tahapD_v1-polling/`.
Perbandingan menunjukkan polling **selalu melebih-lebihkan** waktu deteksi
(bias −0,04 s s/d −0,19 s), paling parah pada algoritme cepat:

| Algo @ rate | Presisi | Polling | Bias |
|---|---|---|---|
| baseline @500 | 0,052 s | 0,22 s | −0,168 s |
| entropy @500 | 0,464 s | 0,63 s | −0,169 s |
| s2td @500 | 2,450 s | 2,52 s | −0,066 s |

Ini alasan metrik diganti sebelum menyimpulkan apa pun: dengan polling,
selisih baseline vs entropi (0,22 vs 0,63) tampak hanya 0,4 s; dengan
pengukuran presisi selisih sebenarnya **0,41 s vs 0,05 s = 9× lebih cepat**.

### 5.6 Verifikasi hasil

| Pemeriksaan | Hasil |
|---|---|
| Jumlah baris raw / kolom | 45 baris, 21 kolom |
| Titik unik (algo, rate) | 15, semuanya 3 run |
| Kolom `repeat` | 1, 2, 3 — tanpa duplikasi |
| `flood_actual_pps` vs nominal | sama persis di 100/500/1000/1500/3000 |
| Deteksi kosong / `det_miss` | 0 |
| False positive (total) | 0 (FPR 0 %) |
| Loss legitimate maksimum | 0,0 % |
| Validasi analitis baseline | error ≤ 0,0–7,7 % (kecuali 3000 pps: +2,3 ms absolut) |

### 5.7 Integritas data lama

`results/mitigation_events.csv` adalah berkas hasil lama yang **tidak boleh
diubah**. Setiap run baseline menambahkan satu baris ke sana, sehingga 27
baris baru dari kedua sweep dipindahkan ke
`results/mitigation_events_baseline_sweep.csv` (header sama, 27 event) dan
berkas asli dipulihkan ke kondisi git (`git checkout`). Kolom
`detection_time_s` tidak terpengaruh karena nilainya sudah dihitung saat run
berjalan. CSV S2TD/entropi tetap apa adanya karena keduanya berkas baru.



---

## 6. Verifikasi yang dilakukan

| Uji | Hasil |
|---|---|
| Unit test agregasi (`mean/stddev`, `det_miss`, `tput/cpu`, stop rule, `write_stats`) | lulus |
| Unit test metrik deteksi (`t0_epoch`, kasus gagal, batas `max_s`) | lulus |
| Unit test `merge_levels` (bertahap, tanpa duplikasi, baris rusak) | lulus |
| Mini-sweep nyata 1 run (`--rates 100 --repeats 1 --algos s2td`) | lulus, artefak tersimpan benar |
| Sweep mini 2 repeat (`--repeat-start`) | kolom `repeat` = 1, 2 |
| Validasi analitis deteksi baseline (26/rate) | 51 ms vs 52 ms; 18 ms vs 17 ms |
| Sweep final 45 run | exit 0, 15 titik × 3 repeat, tanpa duplikasi |

---

## 7. Cara mengulang

```bash
cd /mnt/c/Dionisius/SkripsiProject
sudo ~/ddos-venv/bin/python experiments/run_sweep_compare.py \
     --rates 100,500,1000,1500,3000 --repeats 3

# melihat rencana tanpa menjalankan
sudo ~/ddos-venv/bin/python experiments/run_sweep_compare.py --dry-run

# melanjutkan ke beban lebih tinggi (hasil lama dipertahankan)
sudo ~/ddos-venv/bin/python experiments/run_sweep_compare.py --rates 6000
```

Output:

| Berkas | Isi |
|---|---|
| `results/exp_summary_compare.csv` | satu baris per run (raw) |
| `results/compare_stats.csv` | mean ± stddev per titik (algo, rate) |
| `results/tahapD/` | log controller, timeseries, log flood per run |
