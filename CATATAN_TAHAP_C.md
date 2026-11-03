# Catatan Tahap C — Mode Perbandingan Algoritme (`--algo`)

Status: **selesai & tervalidasi**. Tanggal: 2 November 2026.
File yang diubah: `experiments/run_experiment.py`, `traffic/flood_scapy.py`.
File hasil baru: `results/exp_summary_compare.csv` (+ log/timeseries per run).

---

## 1. Apa yang ditambahkan

| Argumen | Fungsi |
|---|---|
| `--algo baseline\|s2td\|entropy` | Memilih controller yang dijalankan **dan** CSV event yang dibaca/ditulis |
| `--rate <pps>` | Diteruskan ke `flood_scapy.py` (0 = secepat mungkin, perilaku lama) |
| `--repeats N` | N run independen berurutan (controller + topologi dibangun ulang) |

Pemetaan algoritme (satu sumber kebenaran, `ALGO_CONFIG`):

| `--algo` | Controller | CSV event |
|---|---|---|
| `baseline` | `controller/ddos_guard.py` | `results/mitigation_events.csv` |
| `s2td` | `controller/ddos_guard_s2td.py` | `results/mitigation_events_s2td.csv` |
| `entropy` | `controller/ddos_guard_entropy.py` | `results/mitigation_events_entropy.csv` |

Tanpa `--algo`, runner berperilaku **persis** seperti sebelumnya (dibuktikan pada §6).

Runner juga otomatis meneruskan `S2TD_PROTECTED_IPS` / `ENTROPY_PROTECTED_IPS`
sesuai IP victim hasil turunan topologi, sehingga `--legit-count` berapa pun
victim tidak pernah di-ban.

---

## 2. Hasil uji 1 run per algoritme

Skenario `mixed`, beban nominal 500 pps, 3 host legitimate (ping 5 pps/host).

| Algo | detection_time_s | detected_rate_pps | CPU attack avg | CPU attack max | loss legit | FPR | drops | throughput_per_cpu |
|---|---|---|---|---|---|---|---|---|
| baseline | **0,22** | 26,0 | 0,9 % | 3,9 % | 0,0 % | 0 | 1 | 558,66 |
| s2td | **2,53** | 502,7 | 0,1 % | 2,0 % | 0,0 % | 0 | 1 | 5000,00 |
| entropy | **0,63** | 252,0 | 2,2 % | 17,6 % | 0,0 % | 0 | 1 | 230,95 |

Semua run: `flood_rate_pps = flood_actual_pps = 500` (pacing baru akurat),
tidak ada ban salah sasaran, tidak ada packet loss pada host legitimate.

### Bukti dari log controller

- **Baseline**: `MITIGASI ... 10.0.0.1` muncul < 1 dtk; `detected_rate=26` =
  ambang (25) + 1.
- **S2TD**: `TRIGGER agg=1033.9pps > thr=80.4 (k*mu=3.0*26.8)` →
  dua putaran `VERIFY` (konsekutif 1/2 lalu 2/2) → `MITIGASI`.
  Victim `10.0.0.5` terlihat 516 pps (balasan RST) tetapi `SKIP` karena
  diproteksi — bukti mekanisme S6 bekerja.
- **Entropy**: `ENTROPY: H=0.40 bit (thr=1.00) | N=267 | top=10.0.0.1
  252.0pps` → `MITIGASI`.

---

## 3. Cara membaca angka (penting untuk bab hasil)

### `detection_time_s`
Definisi sama untuk ketiga algoritme: dari penanda `[flood] started`
(paket pertama siap kirim) sampai rule `priority=100` pertama terlihat oleh
polling `ovs-ofctl dump-flows` tiap **0,2 detik**.

> **Diperbarui di Tahap D.** Angka-angka di catatan ini memakai polling
> (resolusi 0,2 dtk), sehingga baseline tercatat 0,22 s padahal ban terjadi
> ±0,05 s. Tahap D menggantinya dengan selisih jam dinding
> (`t0_epoch` flooder → `ts_iso` event controller) berpresisi milidetik;
> nilai polling tetap disimpan di kolom `detection_time_poll_s`.
> Lihat `CATATAN_TAHAP_D.md` §3.1.

Konsekuensi: angka ini punya **resolusi 0,2 detik**. Baseline (0,22 s)
sebenarnya sudah mem-ban pada ±0,05 s (paket ke-26), tetapi runner baru
melihatnya di poll pertama. Jadi jangan mengklaim presisi di bawah 0,2 s.

### `detected_rate_pps` — TIDAK boleh dibandingkan mentah antar algoritme
| Algo | Arti angka |
|---|---|
| baseline | Laju saat counter per-IP melewati ambang → selalu ≈ ambang+1 (26). Bukan intensitas serangan. |
| s2td | Counter switch satu interval penuh → ≈ laju sebenarnya (502,7). |
| entropy | Isi window saat evaluasi; jika evaluasi jatuh 0,5 s setelah window mulai terisi, angkanya bisa separuh (252 dari 500). |

Ini alasan `detection_time_s`, CPU, dan loss yang dibandingkan — bukan
`detected_rate_pps`.

### `cpu_attack_avg_pct` vs `cpu_avg_pct`
CPU rata-rata **seluruh run** (35 dtk) terencerkan karena setelah rule DROP
aktif controller sengaja idle. Karena itu ditambahkan kolom CPU **fase
serangan** (warmup selesai → flood selesai), dan `throughput_per_cpu` memakai
angka itu:

```
throughput_per_cpu = flood_actual_pps / cpu_attack_avg_pct   [pps per 1% CPU]
```

Diverifikasi silang terhadap `/proc/<pid>/stat` (jiffies, HZ=100):

| Algo | psutil | jiffies | selisih |
|---|---|---|---|
| baseline | 0,89 % | 0,93 % | 0,04 |
| s2td | 0,10 % | 0,10 % | 0,00 |
| entropy | 2,17 % | 2,16 % | 0,01 |

**Catatan penting:** CPU S2TD (0,1 %) berada di **lantai resolusi** pengukuran
(1 tick = 10 ms; selama 10 dtk serangan itu 0,1 %). Artinya
`throughput_per_cpu` S2TD adalah **perkiraan batas bawah** — nilai sebenarnya
bisa lebih tinggi. Tulis ini di laporan, jangan klaim 5000 pps/% CPU sebagai
angka eksak.

### Mengapa CPU S2TD jauh lebih rendah
Flow caching: setelah beberapa paket pertama, trafik diteruskan oleh flow
`priority=1` di switch dan **tidak** dikirim ke controller. Controller hanya
membaca counter lewat flow stats tiap 1 detik. Baseline dan entropi tanpa
caching, sehingga setiap paket harus diproses controller (parse scapy +
packet-out).

**Ini confounding factor yang wajib diakui** (sudah tercatat sejak Tahap A):
perbandingan CPU baseline/entropi vs S2TD mencampur *algoritme deteksi* dengan
*arsitektur forwarding*. Klaim yang sah: "S2TD lebih hemat CPU", bukan
"algoritme dua tahap lebih hemat CPU".

---

## 4. Temuan metodologis tambahan

1. **Artefak sampel CPU pertama (sudah diperbaiki).** Sebelum perbaikan,
   sampel `t=0` membaca CPU sejak proses controller lahir dan pernah terbaca
   **75 %** padahal puncak nyata 17,6 %. Bukti bahwa artefak ini juga ada di
   data lama: `exp_summary.csv` lama memuat `cpu_max_pct = 101,1`.
   Perbaikan: sampler memberi jeda 0,5 dtk sebelum sampel pertama.
2. **Pacing flooder diperbaiki.** Sebelumnya `sleep(1/rate)` per paket;
   pada `--rate 500` hanya tercapai ±402 pps. Sekarang jadwal absolut
   (`t_start + n/rate`) → **tepat 500 pps** (diuji 500 dan 1500 pps, error
   < 0,1 %). Tanpa perbaikan ini, load sweep Tahap D akan bias.
3. **Bug lama ditemukan (belum diperbaiki, di luar lingkup Tahap C):**
   `results/exp_summary.csv` punya **header 15 kolom** tetapi baris-barisnya
   **22 kolom** (sudah terjadi sebelum Tahap C). Penyebab: header hanya
   ditulis sekali saat file belum ada, sementara `summary` dict berkembang
   (kolom loss per-host + `is_legitimate`). Data lama tidak diubah; mode
   `--algo` memakai file terpisah (`exp_summary_compare.csv`) dengan header
   yang divalidasi setiap append, jadi masalah ini tidak menular.

---

## 5. Definisi kolom `exp_summary_compare.csv`

| Kolom | Arti |
|---|---|
| `algo` | Algoritme yang dijalankan |
| `scenario` | `baseline` / `single` / `mixed` / `flash_crowd` |
| `repeat` | Indeks pengulangan (1..N) |
| `flood_rate_pps` | Rate nominal `--rate` (0 = unpaced) |
| `flood_actual_pps` | Rate nyata dari baris akhir flooder |
| `detection_time_s` | Definisi seragam (lihat §3) |
| `detected_rate_pps` | Laju saat algoritme memutuskan (lihat §3) |
| `drops_max_concurrent` | Maksimum rule DROP simultan |
| `drops_total_events` | Jumlah event mitigasi milik run ini |
| `fp_bans` / `fpr_pct` | Ban yang mengenai IP selain attacker |
| `legit_loss_mean_pct` / `legit_loss_max_pct` | Loss host legitimate (rata-rata / terburuk) |
| `cpu_avg_pct` / `cpu_max_pct` | CPU seluruh run (pembanding data lama) |
| `cpu_attack_avg_pct` / `cpu_attack_max_pct` | CPU fase serangan |
| `mem_avg_pct` | Memori controller |
| `throughput_per_cpu` | `flood_actual_pps / cpu_attack_avg_pct` |

---

## 6. Verifikasi yang sudah dilakukan

| Uji | Hasil |
|---|---|
| Unit test helper (parse flood, marker, first event rate, append CSV, arsip skema lama) | 15/15 lulus |
| `--help`, validasi argumen (`--algo` salah, `--repeats 0`, `threshold_sweep --algo`) | pesan error benar |
| 1 run nyata per algoritme (mixed, 500 pps) | tabel §2, semua exit 0 |
| **Backward-compat** `--scenario single` tanpa `--algo` (di salinan proyek `/tmp`) | `exp_summary.csv` +1 baris, event +1, header lama utuh, **tidak** membuat `exp_summary_compare.csv` maupun log flood |
| `--repeats 2`, `--algo s2td` (di salinan) | 2 baris compare benar, tabel ringkasan akhir tampil |
| Pacing flooder 500 & 1500 pps (socket tiruan) | 501 & 1501 pps |

---

## 7. Batasan yang harus ditulis di laporan

1. Baru **1 run per algoritme** → belum ada ukuran variansi. Tahap D
   mengulang 3× per titik beban.
2. `detection_time_s` beresolusi 0,2 dtk (polling).
3. Ambang ketiga algoritme **tidak setara secara konsep**: baseline 25 pps
   per-IP, S2TD `T_verify` 50 pps + konfirmasi 2 interval, entropi 1,0 bit.
   Perbedaan `detection_time_s` karena itu mencampur kepekaan ambang dan
   logika deteksi — bukan murni "kecepatan algoritme".
4. CPU S2TD di lantai resolusi pengukuran.
5. Flow caching (S2TD) vs tanpa caching (baseline, entropi) = confounding
   factor arsitektural.

---

## 8. Cara mengulang

```bash
cd /mnt/c/Dionisius/SkripsiProject
sudo ~/ddos-venv/bin/python experiments/run_experiment.py \
     --scenario mixed --algo baseline --rate 500 --repeats 1
sudo ~/ddos-venv/bin/python experiments/run_experiment.py \
     --scenario mixed --algo s2td     --rate 500 --repeats 1
sudo ~/ddos-venv/bin/python experiments/run_experiment.py \
     --scenario mixed --algo entropy  --rate 500 --repeats 1
```

Hasil ditambahkan ke `results/exp_summary_compare.csv`; log controller,
timeseries, dan log flood tiap run tersimpan dengan tag algo di namanya.
