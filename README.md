# Automated DDoS Mitigation pada SDN

Proof-of-concept untuk skripsi S1 Teknik Komputer: deteksi dan mitigasi otomatis serangan DDoS bergaya Mirai pada jaringan Software-Defined Networking.

**Catatan**: Menggunakan **os-ken** (fork aktif Ryu, API kompatibel) karena Ryu asli tidak support Python 3.12+. Import pakai `os_ken`, command pakai `osken-manager`.

Fokus penelitian P1: membandingkan **tiga algoritme deteksi** (baseline threshold per-IP, S2TD dua tahap, dan Shannon entropy) pada beban serangan yang disapu bertahap (*load sweep*), dengan metrik utama **waktu deteksi**, **CPU controller**, **packet loss host legitimate**, dan **throughput per CPU**.

## Struktur Project

```
SkripsiProject/
├── topology/
│   └── basic_topo.py              # Topologi 5 host: h1 attacker, h2-h4 legit, h5 victim
├── controller/
│   ├── l2_switch.py               # L2 learning switch (baseline konektivitas)
│   ├── ddos_guard.py              # Algoritme A: threshold per-IP (tanpa flow caching)
│   ├── ddos_guard_s2td.py         # Algoritme B: S2TD dua tahap (flow caching)
│   └── ddos_guard_entropy.py      # Algoritme C: Shannon entropy (tanpa flow caching)
├── traffic/
│   └── flood_scapy.py             # Flooder TCP SYN/UDP + pacing rate
├── experiments/
│   ├── run_experiment.py          # Runner skenario + mode --algo
│   └── run_sweep_compare.py       # Load sweep 3 algoritme (Tahap D)
├── scale50/                       # Fase scale50: 50 IoT + victim (51 host)
├── results/                       # CSV, log controller, timeseries, ringkasan
├── CATATAN_TAHAP_C.md             # Analisis run perbandingan awal (500 pps)
├── CATATAN_TAHAP_D.md             # Analisis + hasil load sweep final
├── GLOSARIUM_LOG_S2TD.md          # Glosarium log/CSV S2TD
├── PENJELASAN_KODE.md             # Penjelasan kode per baris (BAGIAN I-III)
├── visualize_results.py           # Grafik dari CSV hasil
└── README.md
```

## Algoritme yang Dibandingkan

| Algoritme | File controller | Cara deteksi | Forwarding |
|---|---|---|---|
| **Baseline** (A) | `ddos_guard.py` | Sliding window 1 detik per source IP; rate > `RATE_THRESHOLD` (default 25 pps) → ban | Tanpa flow caching: setiap paket → packet-in |
| **S2TD** (B) | `ddos_guard_s2td.py` | `FlowStatsRequest` tiap `T_poll` (1 s); EWMA agregat sebagai pemicu; top-N per sumber diverifikasi `T_verify` (50 pps) selama `T_confirm` (2 poll berturut) | Flow caching per `(src_ip, dst_ip)`, idle timeout 10 s |
| **Entropy** (C) | `ddos_guard_entropy.py` | Sliding window 1 detik; Shannon entropy IP sumber < 1,0 bit (min. 30 paket) → ban sumber dominan | Tanpa flow caching (disamakan dengan baseline) |

Ketiga algoritme memakai **bentuk mitigasi yang identik**: flow DROP `priority=100`, match `ipv4_src`, `hard_timeout=15 s`. Yang dibandingkan adalah **logika deteksinya**, bukan bentuk rule. Masing-masing menulis CSV event terpisah dengan skema 10 kolom yang sama:

- `results/mitigation_events.csv` (baseline)
- `results/mitigation_events_s2td.csv` (S2TD)
- `results/mitigation_events_entropy.csv` (entropy)

---

## Tahap 1: Setup Environment (Ubuntu/WSL2)

Jalankan perintah berikut di **Ubuntu (VM/native/WSL2)**, **bukan** di Windows PowerShell:

### 1. Install Dependencies

```bash
# Update package list
sudo apt update

# Install Mininet (termasuk Open vSwitch) + tools pendukung
sudo apt install -y mininet hping3 python3.12-venv python3.12-dev
```

### 2. Setup Virtualenv + os-ken

```bash
# Buat virtualenv (Python 3.12)
python3 -m venv ~/ddos-venv
source ~/ddos-venv/bin/activate

# Ryu asli tidak support Python 3.12+ -> pakai os-ken (fork aktif, API kompatibel).
# PENTING: versi 3.1.1, karena wheel os-ken 4.x tidak menyertakan CLI manager.
pip install --no-build-isolation "setuptools<70" "os-ken==3.1.1"

# Fix: eventlet menarik pyOpenSSL lama bawaan sistem yang rusak di Ubuntu 24.04
pip install pyopenssl

# Scapy (traffic generator) + psutil (monitoring CPU utk eksperimen)
pip install scapy psutil
```

### 3. Izinkan venv melihat package system (modul `mininet` dari apt)

```bash
sed -i 's/include-system-site-packages = false/include-system-site-packages = true/' ~/ddos-venv/pyvenv.cfg
```

### 4. Verifikasi

```bash
source ~/ddos-venv/bin/activate
python -c "import mininet, os_ken, scapy, psutil; print('semua OK')"
osken-manager --version
sudo mn --version
```

---

## Menjalankan Tahap 1 (Topologi Dasar + L2 Switch)

### Terminal 1: Jalankan os-ken Controller

```bash
source ~/ddos-venv/bin/activate
cd /path/to/SkripsiProject/controller
osken-manager l2_switch.py
```

Output yang diharapkan:
```
loading app l2_switch.py
instantiating app l2_switch.py
```

### Terminal 2: Jalankan Mininet Topology

```bash
# Pastikan venv aktif agar python3 punya akses ke modul mininet + venv
cd /path/to/SkripsiProject/topology
sudo -E python3 basic_topo.py
```

### Terminal 3 (di dalam Mininet CLI): Test Konektivitas

```mininet
mininet> pingAll
```

Output yang diharapkan: **0% packet loss** (semua host bisa saling ping).

```mininet
mininet> h1 ping h5
```

Seharusnya berhasil (reply dari h5).

### Verifikasi Switch Terhubung ke Controller

Di terminal os-ken (Terminal 1), seharusnya muncul log:
```
Switch 1 terhubung, table-miss diinstall
```

### Keluar dari Mininet

```mininet
mininet> exit
```

> **Catatan**: Warning `sch_htb: quantum of class ... is big` saat link dibuat adalah **normal dan harmless** — hanya peringatan scheduler HTB untuk bandwidth 100Mbps, tidak mempengaruhi hasil.

### Hasil Verifikasi (sudah dites)

- `pingAll`: **0% dropped (20/20 received)**
- Flow table s1: 20 flow L2 (priority=1) + table-miss (priority=0 → CONTROLLER)
- Log controller: `Switch 1 terhubung, table-miss diinstall`

## Penjelasan Desain Awal

### Topologi (`topology/basic_topo.py`)
- **1 Switch (s1)**: OpenFlow 1.3, mewakili SDN switch tunggal
- **5 Host (h1-h5)**: h1-h4 = IoT edge nodes, h5 = victim/server
- **Link**: 100Mbps, 1ms delay, 0% loss (realistik untuk jaringan LAN)
- **Controller**: RemoteController ke `127.0.0.1:6633` (default Ryu)

### Controller (`controller/l2_switch.py`)
- **L2 Learning Switch** standar (mirip `simple_switch_13.py` bawaan Ryu/os-ken)
- Belajar MAC address dari packet-in (source MAC → in_port)
- Forward unicast ke port tujuan jika diketahui, else flood
- Install flow entry (priority=1) untuk menghindari packet-in berulang
- Table-miss flow (priority=0) mengirim semua packet baru ke controller

### Kenapa L2 Switch Dulu?
Memastikan **konektivitas dasar berfungsi** sebelum menambahkan logic deteksi DDoS. Jika pingAll gagal, masalah ada di layer infrastruktur (OVS, os-ken, topologi), bukan di logic deteksi.

---

## Tahap 1.5: Deteksi & Mitigasi Otomatis — Baseline (`controller/ddos_guard.py`)

Controller lengkap: forwarding L2 reaktif + deteksi rate + mitigasi otomatis.

### Menjalankan

Terminal 1:
```bash
source ~/ddos-venv/bin/activate
cd /mnt/c/Dionisius/SkripsiProject/controller
osken-manager --ofp-tcp-listen-port 6633 ddos_guard.py
```

Terminal 2:
```bash
source ~/ddos-venv/bin/activate
cd /mnt/c/Dionisius/SkripsiProject/topology
sudo -E python3 basic_topo.py
```

### Test Serangan Manual (di Mininet CLI)

```mininet
mininet> h1 ping h5                                  # normal: jalan
mininet> h1 /home/dionisius/ddos-venv/bin/python ../traffic/flood_scapy.py --target 10.0.0.5 --proto tcp --port 80 --duration 10 &
mininet> h1 ping h5                                  # ~1 detik kemudian: 100% loss (attacker di-drop)
mininet> h2 ping h5                                  # tetap jalan (tidak ada false positive)
# tunggu 15 detik (ban kedaluwarsa):
mininet> h1 ping h5                                  # jalan lagi (jaringan pulih otomatis)
```

Kejadian mitigasi tercatat di `results/mitigation_events.csv`.

### Hasil Verifikasi Otomatis (sudah dites)

| Fase | Hasil |
|---|---|
| Baseline (ping normal) | 0% loss |
| SYN flood 160.264 pps dari h1 | DROP rule terpasang dalam **0,80 detik** |
| Saat ban aktif: attacker (h1) | 100% loss — terisolasi |
| Saat ban aktif: host lain (h2) | 0% loss — tidak ada false positive |
| Setelah ban kedaluwarsa (15s) | h1 pulih, 0% loss |

### Keputusan Desain Baseline (ringkasan — detail & justifikasi di docstring `ddos_guard.py`)

| Parameter | Nilai | Alasan |
|---|---|---|
| Mode forwarding | Tanpa flow caching (semua paket ke controller) | Flow cache membuat flood tak terlihat controller (packet-in = 0); visibilitas penuh = rate akurat |
| Yang dihitung | Hanya paket inisiasi koneksi (TCP SYN murni, semua UDP, ICMP echo request) | Balasan victim (RST/SYN-ACK/ICMP-error) volumenya menyamai serangan; ikut dihitung akan membanned korban |
| Window | Sliding 1 detik per source IP | Tanpa artefak batas bucket fixed-window |
| Threshold | 25 paket/detik per IP | Baseline ping ≈ 4–8/s; serangan ≥ ratusan/s → margin aman dua arah |
| Masa ban | hard_timeout 15 detik | Pemulihan otomatis (batasi dampak false positive); eksperimen bisa diulang tanpa restart |

---

## Tahap 2: Eksperimen Otomatis (`experiments/run_experiment.py`)

Menjalankan skenario uji secara terpisah dan mencatat semua metrik ke `results/`.

### Menjalankan (mode lama, tetap backward-compatible)

```bash
source ~/ddos-venv/bin/activate
cd /mnt/c/Dionisius/SkripsiProject/experiments

# skenario dijalankan SATU PER SATU (masing-masing membangun jaringan sendiri):
sudo -E python run_experiment.py --scenario baseline   # trafik normal saja
sudo -E python run_experiment.py --scenario single     # flooding murni
sudo -E python run_experiment.py --scenario mixed      # flooding + trafik normal
```

Opsi: `--warmup` (default 5s), `--flood-duration` (10s), `--post` (20s, harus ≥ ban 15s), `--ping-interval` (0.2s), `--legit-count` (default 3).

### Output di `results/`

| File | Isi |
|---|---|
| `exp_summary.csv` | 1 baris per run (mode lama): waktu deteksi, jumlah drop rule, fp_bans, % loss per host legitimate, CPU/mem controller |
| `exp_timeseries_<skenario>_<ts>.csv` | sampel tiap 0.5s: t, cpu_pct, mem_pct, jiffies, jumlah drop rule aktif |
| `controller_<skenario>_<ts>.log` | log controller utk run tsb (bukti STATS/MITIGASI) |
| `mitigation_events.csv` | event mitigasi (dari `ddos_guard.py`) |

### Hasil Verifikasi Final (WSL2, SYN flood ±170rb pps, kode final)

| Metrik | baseline | single | mixed |
|---|---|---|---|
| Waktu deteksi | – (tidak ada deteksi ✓) | **0,64 s** | **0,86 s** |
| Drop rule terpasang | 0 ✓ | 1 | 1 |
| False-positive ban | 0 ✓ | 0 ✓ | **0 ✓** |
| Loss host legitimate | 0% | – (tanpa trafik legit) | **0%** ✓ |
| CPU controller (avg/max) | 1,0 / 3,9% | 0,5 / 27,5% | 1,8 / 54,9% |

Data lengkap: `results/exp_summary.csv` (histori run lama: `exp_summary_archive.csv`).

Interpretasi cepat: deteksi konsisten < 1 detik; trafik legitimate sama sekali tidak terpengaruh (FPR = 0); lonjakan CPU controller saat serangan turun setelah drop rule memblokir paket attacker di switch — efek mitigasi terlihat langsung di timeseries.

---

## Tahap 3: Mode Perbandingan Algoritme (`--algo`)

Menambahkan `--algo` membuat runner memilih controller dan CSV event yang sesuai, lalu menulis hasil ke **file terpisah** `results/exp_summary_compare.csv` (21 kolom, diawali `algo` dan `flood_rate_pps`). Tanpa `--algo`, perilaku runner **identik dengan sebelumnya** (baseline, `exp_summary.csv`).

```bash
sudo ~/ddos-venv/bin/python experiments/run_experiment.py \
     --scenario mixed --algo baseline --rate 500 --repeats 3
sudo ~/ddos-venv/bin/python experiments/run_experiment.py \
     --scenario mixed --algo s2td     --rate 500 --repeats 3
sudo ~/ddos-venv/bin/python experiments/run_experiment.py \
     --scenario mixed --algo entropy  --rate 500 --repeats 3
```

Argumen baru:

| Argumen | Arti |
|---|---|
| `--algo baseline\|s2td\|entropy` | Pilih controller + CSV event |
| `--rate N` | Batas laju flood (pps); `0` = secepat mungkin. Diabaikan tanpa `--algo` |
| `--repeats N` | Ulangi run; topologi + controller dibangun ulang tiap repeat |
| `--repeat-start N` | Indeks awal penomoran repeat (dipakai skrip sweep) |
| `--subdir NAME` | Simpan log bukti ke `results/<NAME>/` |

### Definisi metrik (sama untuk ketiga algoritme)

- `detection_time_s` — jeda dari **paket flood pertama** (penanda `[flood] started` + `t0_epoch` dari `flood_scapy.py`) sampai **rule DROP pertama** dipasang. Mode compare memakai selisih **jam dinding** antara `t0_epoch` dan `ts_iso` baris event pertama di CSV algoritme, sehingga resolusinya milidetik. Nilai polling `ovs-ofctl` (0,2 s) tetap disimpan di `detection_time_poll_s` sebagai pembanding/audit.
- `flood_actual_pps` — laju yang benar-benar terkirim (baris akhir flooder), bukan sekadar nominal.
- `cpu_attack_avg_pct` — CPU controller rata-rata **hanya fase serangan** (warmup..warmup+attack), bukan rata-rata seluruh run.
- `cpu_avg_pct` / `cpu_max_pct` — CPU seluruh run (termasuk fase idle setelah mitigasi).
- `throughput_per_cpu` — `flood_actual_pps / cpu_attack_avg_pct` (paket/detik nyata per 1% CPU controller).
- `detected_rate_pps` — laju yang dicatat algoritme saat event pertama. **Tidak boleh dibandingkan langsung antar algoritme** karena cara ukurnya berbeda (S2TD: counter switch satu interval penuh; entropi: isi window saat evaluasi, bisa setengah penuh).

### Hasil Tahap C (500 pps, 3 repeat)

Lihat `CATATAN_TAHAP_C.md` dan `results/exp_summary_compare_tahapC.csv`. Ringkasnya: baseline mendeteksi paling cepat (≈52 ms), entropi ≈464 ms, S2TD ≈2,45 s (terkuantisasi interval polling); CPU fase serangan baseline ≈0,87%, entropi ≈1,77%, S2TD ≈0,13%; 0 false positive dan 0% loss pada ketiganya.

---

## Tahap 4: Load Sweep Perbandingan (`experiments/run_sweep_compare.py`)

Skrip ini memetakan metrik terhadap **beban serangan yang dinaikkan bertahap**. Ia tidak menduplikasi logika eksperimen: satu titik = satu pemanggilan `run_experiment.py --algo ... --rate ... --repeats 1`, lalu baris baru di `exp_summary_compare.csv` dibaca dan diagregasi.

```bash
# cek rencana tanpa menjalankan
sudo ~/ddos-venv/bin/python experiments/run_sweep_compare.py --dry-run

# sweep final yang dipakai di laporan (15 titik = 5 rate x 3 algo, 3 repeat)
sudo ~/ddos-venv/bin/python experiments/run_sweep_compare.py \
     --rates 100,500,1000,1500,3000 --repeats 3 --scenario mixed
```

### Urutan eksekusi & aturan berhenti

- Urutan: **rate terluar (naik) → algoritme → repeat**. Ketiga algoritme diuji pada beban yang sama secara berdekatan agar drift lingkungan tidak pilih kasih.
- Setelah semua repeat pada satu titik `(algo, rate)`: algoritme dianggap **jenuh** bila `cpu_attack_mean > --stop-cpu` (default 80%) **atau** `loss_max > --stop-loss` (default 1%). Algoritme yang jenuh dilewati pada rate lebih tinggi; algoritme lain tetap lanjut.
- `merge_levels()` menggabungkan hasil baru dengan `compare_stats.csv` lama berdasarkan kunci `(algo, scenario, rate)`, sehingga sweep boleh dijalankan bertahap tanpa menduplikasi baris.
- Angka ditulis ulang ke `compare_stats.csv` **setiap titik selesai**, jadi hasil parsial tetap aman bila sweep dihentikan.

### Output

| File | Isi |
|---|---|
| `results/exp_summary_compare.csv` | Raw: 1 baris per run (45 baris untuk sweep final), 21 kolom |
| `results/compare_stats.csv` | Ringkasan per titik: mean ± stddev waktu deteksi, CPU, loss, tput/CPU, status jenuh |
| `results/tahapD/` | Log controller, timeseries, log flood per run (bukti) |

### Hasil Load Sweep Final (45 run, ±34,7 menit, exit 0)

Semua titik: **3/3 run terdeteksi**, **0 false-positive ban**, **0% packet loss** host legitimate, `flood_actual ≈ flood_rate` (pacing tercapai). Mean ± stddev waktu deteksi (detik), CPU fase serangan (%), dan throughput per CPU:

| Rate (pps) | Algoritme | Deteksi (s) | CPU serangan (%) | Loss max (%) | tput/CPU |
|---:|---|---:|---:|---:|---:|
| 100 | baseline | 0,252 ± 0,000 | 1,10 | 0 | 90,91 |
| 100 | S2TD | 2,390 ± 0,116 | 0,13 | 0 | 750,00 |
| 100 | entropy | 0,966 ± 0,006 | 1,53 | 0 | 65,22 |
| 500 | baseline | 0,052 ± 0,000 | 0,87 | 0 | 576,92 |
| 500 | S2TD | 2,450 ± 0,023 | 0,13 | 0 | 3.750,00 |
| 500 | entropy | 0,464 ± 0,003 | 1,77 | 0 | 283,02 |
| 1000 | baseline | 0,028 ± 0,001 | 0,87 | 0 | 1.153,85 |
| 1000 | S2TD | 2,438 ± 0,017 | 0,17 | 0 | 6.000,00 |
| 1000 | entropy | 0,429 ± 0,063 | 2,47 | 0 | 405,41 |
| 1500 | baseline | 0,019 ± 0,001 | 0,93 | 0 | 1.607,14 |
| 1500 | S2TD | 2,463 ± 0,007 | 0,13 | 0 | 11.250,00 |
| 1500 | entropy | 0,472 ± 0,018 | 3,47 | 0 | 432,69 |
| 3000 | baseline | 0,011 ± 0,002 | 0,80 | 0 | 3.750,00 |
| 3000 | S2TD | 2,460 ± 0,022 | 0,20 | 0 | 15.000,00 |
| 3000 | entropy | 0,464 ± 0,006 | 4,40 | 0 | 681,82 |

CPU puncak fase serangan: baseline ≤3,9%; S2TD ≤2,0%; entropi naik 5,9% → 13,8% → 25,6% → 39,4% → **55,1%** seiring beban.

### Analisis ringkas (bahan bab hasil)

1. **Baseline** — waktu deteksi mengikuti rumus `≈ 26/rate` karena ambangnya absolut 25 pps: 26/100 ≈ 0,26 s, 26/500 ≈ 0,052 s, 26/3000 ≈ 0,011 s. Semua nilai terukur cocok dengan prediksi analitis ini. Artinya baseline diuntungkan secara definisi pada beban tinggi: makin deras serangan, makin cepat ambang terlampaui.
2. **S2TD** — deteksi datar **≈2,4 s** pada semua beban, sesuai `T_poll = 1 s` dan `T_confirm = 2` poll berturut. Ini konsekuensi struktural (resolusi 1 s), bukan kelambatan komputasi. CPU-nya paling rendah (0,13–0,20%) karena flow caching memindahkan mayoritas pemrosesan paket dari controller ke switch.
3. **Entropy** — deteksi ≈0,43–0,47 s pada ≥500 pps; pada 100 pps menjadi 0,97 s karena window butuh waktu mengumpulkan `ENTROPY_MIN_PKTS = 30` paket. CPU naik **linier** terhadap beban (R² = 0,95; `CPU ≈ 1,42 + 0,00228 × paket/detik`) karena setiap paket harus masuk window dan distribusi dihitung ulang.
4. **Tidak ada saturasi** pada rentang ≤3000 pps: CPU **rata-rata fase serangan** tertinggi 4,40% (entropi @3000), loss 0%, dan tidak ada false positive. Puncak sesaat entropi mencapai 55,1% pada 3000 pps, tetapi itu lonjakan satu sampel 0,5 s — bukan kondisi sustained. Karena itu hasil ini belum menunjukkan titik jenuh; ia menunjukkan **tren biaya** pada beban rendah–menengah.
5. **Throughput per CPU** harus dibaca sebagai **indeks relatif pada intensitas serangan tertentu**, bukan kapasitas sustained perangkat. Setelah rule DROP terpasang, controller sengaja idle; normalisasi memakai CPU fase serangan agar tidak menghukum algoritme yang cepat mem-ban, tetapi tetap mengandung ekor idle di dalam fase tersebut.

Detail lengkap (tabel mentah, analisis per algoritme, integritas data): **`CATATAN_TAHAP_D.md`**.

---

## Keterbatasan & Catatan Metodologi (untuk bab pembahasan)

Poin-poin ini wajib disebut saat mengklaim "S2TD lebih hemat CPU" atau "baseline lebih cepat".

1. **Confounding flow caching vs algoritme (paling penting).** Baseline dan entropi memakai forwarding **tanpa** flow caching (setiap paket → packet-in), sedangkan S2TD **memasang flow forwarding** per `(src_ip, dst_ip)`. Jadi selisih CPU baseline/entropi vs S2TD mencampur dua variabel: (a) arsitektur forwarding dan (b) algoritme deteksi. Klaim yang sah adalah "S2TD sebagai **pendekatan keseluruhan** lebih hemat CPU controller", **bukan** "algoritme S2TD dua tahap secara murni lebih efisien daripada threshold/entropi". Untuk memisahkan pengaruh murni algoritme, kedua pembanding harus diberi flow caching yang setara (future work).
2. **`throughput_per_cpu` bukan kapasitas sustained.** Nilainya = `flood_actual_pps / cpu_attack_avg_pct` pada satu titik beban; setelah mitigasi aktif, controller berhenti memproses serangan. Angka ini hanya berlaku pada beban dan skenario yang diukur, tidak boleh diekstrapolasi menjadi "mampu menangani X pps".
3. **Tidak ada saturasi pada ≤3000 pps.** CPU rata-rata fase serangan maksimum 4,40% (puncak sesaat entropi 55,1%), loss 0%, FPR 0 pada semua 15 titik. Flooder tanpa pacing sanggup ≈93.769 pps, tetapi sweep berhenti di 3000 pps karena anggaran waktu; kurva belum mencapai lutut (knee) saturasi. Kesimpulan tentang efisiensi hanya berlaku di rentang ini.
4. **S2TD terkuantisasi oleh interval polling.** `detection_time` S2TD selalu kelipatan kasar `T_poll × T_confirm` (≈2–3 s). Perbedaan beberapa milidetik antar run tidak bermakna; yang bermakna adalah orde besarnya. Untuk perbandingan sub-detik, `T_poll` harus diperkecil (dengan konsekuensi overhead control-channel).
5. **Keunggulan waktu deteksi baseline sebagian bersifat definisi.** Ambang absolut 25 pps otomatis lebih cepat tercapai saat rate naik. Ini bukan "kecerdasan" algoritme, melainkan konsekuensi ambang tetap. Sebaliknya, pada serangan sangat rendah (<25 pps) baseline tidak pernah mendeteksi.
6. **`detected_rate_pps` tidak sebanding antar algoritme.** S2TD menghitung delta `packet_count` satu interval penuh; entropi menghitung isi window saat evaluasi (bisa baru setengah terisi, terlihat ≈0,46× nominal). Kolom ini hanya untuk audit internal tiap algoritme.
7. **Source IP spoofed acak** (`--rand-source`) belum ditangani: tiap IP muncul sekali sehingga rate per-IP rendah dan tidak mencapai `T_confirm`/threshold. Agregasi per subnet/port-switch adalah future work (berlaku untuk ketiga algoritme).
8. **Lingkungan uji terbatas.** Satu switch, satu victim, seluruh node di satu host WSL2; CPU controller diukur di host yang sama dengan Mininet/OVS sehingga dapat terpengaruh noise host. Sampel hanya 3 repeat per titik (stddev dilaporkan, tetapi ekor distribusi belum terpetakan).
9. **Proteksi victim masih eksplisit** via `S2TD_PROTECTED_IPS` / `ENTROPY_PROTECTED_IPS`. Untuk topologi scale50 (victim `10.0.0.51`) nilai ini wajib di-override; runner sudah melakukannya otomatis berdasarkan `--legit-count`.
10. **`ts_iso` di CSV adalah UTC**, sedangkan jam lokal WIB = UTC+7. Saat membaca manual, konversi dulu agar tidak salah menyimpulkan urutan waktu.

---

## Cara Reproduksi Cepat

```bash
# 1. aktifkan venv & masuk root
source ~/ddos-venv/bin/activate
cd /mnt/c/Dionisius/SkripsiProject

# 2. satu run per algoritme (500 pps, 3 repeat)
for a in baseline s2td entropy; do
  sudo -E python experiments/run_experiment.py \
       --scenario mixed --algo "$a" --rate 500 --repeats 3
done

# 3. load sweep penuh (opsional, ±35 menit)
sudo -E python experiments/run_sweep_compare.py \
     --rates 100,500,1000,1500,3000 --repeats 3 --scenario mixed

# 4. cek integritas hasil
python - <<'PY'
import csv
rows = list(csv.DictReader(open('results/exp_summary_compare.csv')))
print('baris:', len(rows), '| algo:', sorted({r['algo'] for r in rows}))
print('fp total:', sum(int(r['fp_bans']) for r in rows))
print('loss maks:', max(float(r['legit_loss_max_pct'] or 0) for r in rows))
PY
```

## Langkah Selanjutnya

1. ~~Topologi dasar + L2 switch~~ ✅
2. ~~Deteksi packet-in rate + auto-DROP + logging CSV (baseline)~~ ✅
3. ~~Traffic generator (`flood_scapy.py`; trafik normal = ping stream di runner)~~ ✅
4. ~~Skrip eksperimen 3 skenario + metrik~~ ✅
5. ~~Dua algoritme pembanding (S2TD + Shannon entropy) + mode `--algo`~~ ✅
6. ~~Load sweep 5 tingkat beban × 3 algoritme × 3 repeat~~ ✅
7. Lanjutan yang disarankan: (a) beri flow caching setara pada baseline/entropi untuk memisahkan confounding; (b) naikkan beban sampai saturasi nyata (≥10⁴ pps); (c) tangani source IP spoofed via agregasi subnet; (d) kurva ROC threshold vs FPR; (e) grafik matplotlib dari `compare_stats.csv`.

---

**Catatan**: File di folder ini dikembangkan di Windows (untuk editing), tapi **dijalankan di Ubuntu**. Pastikan path di perintah `cd` di atas disesuaikan dengan lokasi folder project di Ubuntu.
