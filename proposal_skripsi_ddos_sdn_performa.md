# PROPOSAL SKRIPSI

Judul : OPTIMASI ALGORITMA DETEKSI DAN MITIGASI DDOS YANG EFISIEN SUMBER DAYA UNTUK MENINGKATKAN THROUGHPUT PADA SOFTWARE-DEFINED NETWORKING DENGAN BATAS MTTR DAN PACKET LOSS

Nama : [Nama Mahasiswa]
NIM : [NIM]
Jurusan : Teknik Komputer
Program Studi : Teknik Komputer
Bidang Skripsi : Rekayasa Sistem Komputer

---

# BAB 1 PENDAHULUAN

## 1.1 Latar Belakang

Serangan Distributed Denial of Service (DDoS) merupakan ancaman yang terus berkembang seiring meluasnya perangkat Internet of Things (IoT). Botnet Mirai membuktikan bahwa teknik infeksi sederhana pada perangkat kelas rendah dapat menghimpun ratusan ribu node dan melumpuhkan bahkan target dengan pertahanan terbaik (Antonakakis et al., 2017). Pada skenario kota cerdas seperti jaringan CCTV, banyak sumber trafik kontinu dalam satu infrastruktur sehingga gangguan pada jalur atau server pusat berdampak luas.

Software-Defined Networking (SDN) memisahkan control plane dari data plane sehingga kebijakan jaringan dapat dikelola terpusat dan terprogram. Sentralisasi ini sekaligus menjadi titik lemah: paket table-miss memicu pesan packet-in ke controller, dan banjir paket palsu dapat dengan cepat menghabiskan CPU, memori, serta kanal controller-switch hingga seluruh jaringan kolaps (Wang et al., 2023). Oleh karena itu, evaluasi pertahanan DDoS pada SDN tidak cukup menilai akurasi deteksi; kapasitas controller, throughput, latensi, dan packet loss menentukan kelayakan sistem di dunia nyata (Tootoonchian et al., 2012).

Pendekatan deteksi yang ada berasumsi komputer controller dengan sumber daya melimpah. Pendekatan statistik ringan cepat tetapi bergantung threshold statis sehingga kurang adaptif (Rajper et al., 2026), sedangkan pendekatan machine learning akurat tetapi berat bila dijalankan terus-menerus dan membebani controller dengan sumber daya terbatas (Bai et al., 2026). Kerangka pertahanan seperti FloodGuard dan SDNShield menambah perangkat bantu (proactive flow rules, packet migration, unit mitigasi NFV) untuk melindungi controller (Wang et al., 2015; Chen et al., 2016). Solusi semacam itu efektif, tetapi mengubah atau menambah infrastruktur, bukan memperbaiki efisiensi algoritma pada infrastruktur yang sama.

Celah penelitian ini adalah pertanyaan praktis yang jarang dijawab literatur: pada laptop/VM dengan sumber daya tetap, algoritma deteksi-mitigasi mana yang menghasilkan throughput per satuan beban CPU terbaik, dengan waktu pemulihan (MTTR) dan packet loss legitimate sebagai batas yang tidak boleh dilanggar? Penulis telah membangun proof-of-concept (PoC) awal berupa controller os-ken dengan deteksi threshold reaktif yang terbukti mendeteksi flood TCP dalam 0,64–0,86 detik dengan false positive 0 pada topologi 5 dan 51 host, lengkap dengan harness eksperimen, uji flash crowd, dan sweep threshold yang sudah tereksekusi. Namun desain saat ini memproses setiap packet-in di controller — terlihat dari CPU controller yang melonjak hingga 54,9% pada topologi 5 host saat serangan — sehingga tidak skala dan menjadi baseline yang tepat untuk dibandingkan dengan algoritma yang lebih efisien.

Berdasarkan uraian tersebut, penelitian ini merancang dan mengevaluasi algoritma deteksi-mitigasi DDoS dua tahap berbasis statistik switch (S2TD) yang efisien sumber daya, lalu membandingkannya dengan baseline threshold reaktif pada sumber daya yang sama melalui load sweep terukur.

## 1.2 Rumusan Masalah

1. Seberapa besar throughput flood yang dapat ditangani algoritma S2TD dibandingkan baseline threshold reaktif pada sumber daya yang sama sebelum controller jenuh?
2. Bagaimana efisiensi S2TD bila throughput per satuan beban CPU/memori controller dibandingkan dengan baseline?
3. Apakah S2TD mempertahankan MTTR deteksi-mitigasi, packet loss legitimate, dan false positive rate dalam batas yang ditetapkan?

## 1.3 Batasan Masalah

1. Emulasi Mininet + Open vSwitch dengan controller os-ken (fork Ryu) pada satu laptop/WSL2; spesifikasi dikunci selama pengujian.
2. Jenis serangan dibatasi TCP SYN/UDP flood mirip Mirai dari satu hingga banyak host attacker terhadap satu victim.
3. Metrik performa: throughput flood maksimum, CPU/memori controller, MTTR, packet loss legitimate (ping/iperf), FPR.
4. Perbandingan dilakukan terhadap baseline PoC yang sudah ada, bukan terhadap sistem produksi.
5. Profil trafik IoT/CCTV dipakai sebagai karakterisasi beban (bursty, banyak sumber), bukan dataset asli.

## 1.4 Tujuan Penelitian

1. Merancang algoritma deteksi-mitigasi dua tahap berbasis statistik switch (S2TD) yang efisien sumber daya pada SDN.
2. Membuktikan peningkatan throughput per satuan CPU pada sumber daya yang sama dibandingkan baseline threshold reaktif.
3. Memverifikasi MTTR, packet loss legitimate, dan FPR tetap dalam batas yang ditetapkan.

## 1.5 Manfaat Penelitian

1. Ilmiah: bukti empiris trade-off efisiensi algoritma deteksi DDoS pada SDN dengan resource terbatas.
2. Praktis: pola integrasi algoritma ringan pada controller os-ken/Ryu yang dapat direplikasi untuk jaringan kampus atau kota cerdas berskala kecil-menengah.
3. Bagi penulis: penguasaan SDN, OpenFlow, dan metodologi evaluasi performa sistem terdistribusi.

## 1.6 Sistematika Penulisan

Bab 1 Pendahuluan; Bab 2 Tinjauan Pustaka; Bab 3 Perancangan Sistem dan Metodologi Penelitian; (Bab 4 Hasil dan Pembahasan; Bab 5 Penutup dikerjakan pada tahap skripsi).

---

# BAB 2 TINJAUAN PUSTAKA

## 2.1 DDoS pada IoT dan SDN

Antonakakis et al. (2017) melakukan analisis retrospektif tujuh bulan botnet Mirai yang tumbuh hingga 600 ribu infeksi dan menunjukkan bahwa teknik sederhana pada perangkat kelas rendah cukup untuk mengancam target terlindungi. Karakteristik inilah yang relevan bagi profil trafik IoT/CCTV: banyak sumber, volume besar, pola bursty.

Pada SDN, mekanisme table-miss menjadikan controller target implisit: banjir paket palsu memicu packet-in masif yang menghabiskan CPU dan memori controller hingga jaringan kolaps (Wang et al., 2023). Tootoonchian et al. (2012) menetapkan metodologi pengukuran performa controller (throughput flow setup, latensi, cbench) dan membuktikan throughput controller dapat ditingkatkan puluhan kali lipat murni lewat optimasi implementasi — dasar argumen bahwa efisiensi algoritma adalah variabel yang layak dioptimasi pada hardware tetap.

## 2.2 Deteksi Ringan Berbasis Statistik Flow

Braga et al. (2010) memperkenalkan deteksi flooding ringan di NOX/OpenFlow berbasis flow statistics (bukan inspeksi per-paket) dengan SVM sebagai klasifikasi — bukti awal bahwa memindahkan titik pengamatan dari paket ke flow menurunkan beban deteksi secara signifikan. FleXam (Shirali-Shahreza & Ganjali, 2013) memperluas prinsip ini dengan sampling fleksibel pada OpenFlow, sehingga controller memperoleh informasi level paket secara terbatas tanpa memindahkan seluruh trafik ke control plane.

## 2.3 Pertahanan Terhadap Saturasi Data-to-Control Plane

OF-GUARD (Wang et al., 2014) memigrasikan table-miss packet dan memakai proactive flow rules untuk membedakan paket palsu saat serangan berlangsung. FloodGuard (Wang et al., 2015) memadukan instalasi proactive flow rule dengan packet migration berbasis rate untuk menjaga controller tetap hidup saat disaturasi. SDNShield (Chen et al., 2016) menempatkan attack mitigation unit berbasis NFV di tepi jaringan dengan penyaringan dua tahap guna melindungi controller terpusat. CC-Guard (Wang et al., 2023) menambah koordinasi multi-controller, switch migration saat overload, dan deteksi dua tahap (entropi lalu CNN-GRU-Attention) untuk membedakan flash traffic dari serangan. Keluarga kerja ini mengubah infrastruktur (menambah perangkat/komponen); penelitian ini memilih jalur berbeda: algoritma yang lebih efisien pada infrastruktur tetap.

## 2.4 Deteksi Dua Tahap dan Threshold Adaptif

Rajper et al. (2026) mengusulkan mekanisme tiga tahap: CUSUM adaptif pada tier pertama, aktivasi decision tree berbasis event pada tier kedua (akurasi 99,99%, false positive turun 87%), dan mitigasi port-level yang menjaga packet loss legitimate 0%. ATS-DTA (Bai et al., 2026) memakai conditional entropy sebagai pemicu, penyesuaian threshold EWMA-ARIMA, dan ML dua tahap; eksperimennya menunjukkan keseimbangan kecepatan-akurasi-overhead. Keduanya mengonfirmasi pola yang sama: tahap ringan selalu aktif, tahap mahal hanya saat terpicu.

## 2.5 Evaluasi Performa Controller di Mininet

Abuabdallah (2026) mengevaluasi Ryu dan OpenDaylight di Mininet dengan metrik bandwidth (Iperf), RTT, throughput, packet loss, dan re-convergence, serta menegaskan pentingnya pengulangan pengukuran dan kondisi identik antar konfigurasi. Kerangka ini diadopsi sebagai protokol pengukuran penelitian ini.

## 2.6 Tabel Perbandingan Penelitian Terdahulu

| Referensi | Pendekatan | Kelebihan | Keterbatasan (celah) |
|---|---|---|---|
| Antonakakis et al. 2017 (Mirai) | Analisis botnet IoT | Bukti empiris skala ancaman | Non-SDN; bukan deteksi real-time |
| Tootoonchian et al. 2012 | Benchmark controller | Metodologi performa; optimasi 6–33× | Non-DDoS; fokus flow setup |
| Braga et al. 2010 | Flow statistics + SVM | Ringan; basis flow-level | Threshold/fitur statis; era NOX |
| FleXam 2013 | Sampling fleksibel | Kontrol beban monitoring | Perlu modifikasi switch; overhead sampling |
| OF-GUARD 2014 | Packet migration + proactive rules | Tahan saturasi | Komponen tambahan (data plane cache) |
| FloodGuard 2015 | Proactive rules + rate-limited migration | Efektif, protocol-independent | Kompleksitas operasional tambahan |
| SDNShield 2016 | NFV AMU + filtering 2 tahap | Skalabilitas tinggi | Butuh perangkat NFV ekstra |
| CC-Guard 2023 | Trigger + switch migration + 2 tahap | Adaptive, multi-controller | ML berat (CNN-GRU) di tahap kedua |
| ATS-DTA 2026 | Entropi + EWMA-ARIMA + ML 2 tahap | Threshold adaptif | Fokus akurasi, bukan throughput/CPU |
| Rajper et al. 2026 | CUSUM adaptif + DT event-driven | Ringan; FP −87%; loss legit 0% | Evaluasi akurasi, bukan headroom throughput |
| Abuabdallah 2026 | Evaluasi Mininet | Protokol pengukuran mapan | Non-DDoS; perbandingan controller |

## 2.7 Research Gap dan Posisi Penelitian

Literatur kaya solusi deteksi dan arsitektur pertahanan, tetapi jarang menjawab: dengan sumber daya tetap, berapa throughput tambahan yang diperoleh bila algoritma berubah dari per-paket menjadi statistik interval + verifikasi selektif, dan berapa harga MTTR/FPR-nya? Penelitian ini mengisi celah tersebut dengan membandingkan baseline per-paket (PoC penulis) melawan S2TD pada hardware, topologi, dan beban yang identik.

---

# BAB 3 PERANCANGAN SISTEM DAN METODOLOGI PENELITIAN

## 3.1 Arsitektur Umum

Sistem terdiri atas: (a) data plane Mininet dengan Open vSwitch, satu attacker zone dan host legitimate; (b) controller os-ken yang menjalankan dua aplikasi — L2 forwarding dan modul DDoS guard S2TD; (c) harness eksperimen (run_experiment.py) yang mengatur skenario, mengukur metrik, dan mencatat CSV; (d) modul analisis (mean ± stddev, grafik). Baseline threshold reaktif (ddos_guard.py PoC) dipertahankan utuh sebagai pembanding dan dipilih via environment variable, sehingga kedua algoritma diuji pada kode dan infrastruktur yang sama.

## 3.2 Algoritma S2TD (Statistik-Switch Two-Tier Detection)

Prinsip: pindahkan titik pengamatan dari per-paket (packet-in) ke per-interval (statistik flow/port switch), dengan baseline adaptif EWMA dan verifikasi selektif dua tahap. Pseudocode:

```
# TAHAP 1 — selalu aktif, sangat ringan (O(1) per switch per interval)
setiap T_poll detik:                       # mis. T_poll = 1 s
    stats = ambil_flow/port_stats(dpid)    # OpenFlow multipart, bukan packet-in
    rate  = (pkt_count - prev_count) / T_poll
    mu    = alpha*rate + (1-alpha)*mu      # EWMA baseline adaptif
    jika rate > k_auto * mu:               # mis. k_auto = 3
        masuk TAHAP 2                      # hanya saat anomali

# TAHAP 2 — hanya saat terpicu, tetap flow-level
    poll per-flow stats; hitung pps per (src_ip, dst_ip)
    suspect = top-N src_ip dengan rate > T_verify
    verifikasi ringan (durasi lonjakan >= T_confirm, konsistensi 2 interval)
    jika terkonfirmasi:
        pasang rule DROP per-src (priority=100, hard_timeout=15 s)
        catat event mitigasi ke CSV

# PEMULIHAN — otomatis
    hard_timeout menghapus rule DROP tanpa intervensi; state EWMA berlanjut
```

Parameter: T_poll (1 s), alpha (0.2–0.5), k_auto (3), T_verify, T_confirm, N. Seluruhnya env-configurable mengikuti pola RATE_THRESHOLD yang sudah ada, tanpa mengubah logika baseline.

## 3.3 Justifikasi Algoritma dari Literatur

| Komponen S2TD | Dasar literatur |
|---|---|
| Observasi via flow/port statistics | Braga 2010; Rajper 2026 |
| Sampling/polling sebagai kontrol beban | FleXam 2013; Abuabdallah 2026 |
| Trigger berbasis rasio muatan controller | CC-Guard 2023 (delta_j = sigma lambda_i / eta_j) |
| Baseline adaptif EWMA | ATS-DTA 2026 |
| Verifikasi dua tahap sebelum aksi | Rajper 2026 (FP −87%); ATS-DTA 2026 |
| Mitigasi terarah per-source + timeout | Rajper 2026 (loss legit 0%); PoC baseline |

Kebaruan penelitian ini bukan komponennya, melainkan komposisi dan bukti empirisnya: S2TD dirakit dari komponen terverifikasi literatur, lalu dievaluasi pada dimensi yang jarang diuji bersamaan — throughput per CPU, MTTR, dan loss legitimate — pada sumber daya tetap dan infrastruktur PoC nyata.

## 3.4 Perancangan Eksperimen

1. Pembekuan baseline: ddos_guard.py threshold reaktif (25 pkt/s, window 1 s, ban 15 s) dijalankan pada skenario baseline/single/mixed; hasil PoC (deteksi 0,64–0,65 s; FPR 0; CPU controller max 31–53% pada flood ±173k pps) menjadi data pendahulang.
2. Profil bottleneck: instrumen waktu parsing packet-in, update state per-IP, instalasi flow, logging — menentukan sumber CPU dominan baseline.
3. Implementasi S2TD sebagai modul controller terpisah di belakang flag; baseline tidak diubah.
4. Load sweep: flood bertingkat (100; 500; 1.000; 1.500; hingga jenuh pps) pada topologi 5 host, diulang 3–5× per titik; guardrail trafik legitimate ping 0,2 s + iperf UDP.
5. Skenario tambahan: multi-attacker (scale50, 51 host) untuk skala; flash_crowd (burst legitimate via iperf3 ~threshold) untuk FPR; threshold_sweep untuk sensitivitas T_verify/k_auto.
6. Metrik per run: throughput maksimum sebelum jenuh (CPU > 80% atau loss legit > 1%), cpu_avg/max, MTTR deteksi (flood→DROP terpasang) dan pemulihan (DROP→kadaluarsa), packet loss legitimate, fp_bans/FPR.
7. Analisis: mean ± stddev per titik; kurva throughput-vs-CPU; tabel S2TD vs baseline; uji signifikansi sederhana (t-test) bila asumsi terpenuhi.

Kriteria keberhasilan: S2TD (a) menaikkan throughput jenuh >= 2× baseline pada CPU setara, atau menurunkan CPU >= 50% pada throughput setara; (b) MTTR deteksi <= 2×T_poll + margin (<= 3 s); (c) packet loss legitimate <= 1%; (d) FPR <= 5% pada flash_crowd.

Diagram metode (Eraser.io):

```
title Gambar 3.1 — Diagram Metode Penelitian (S2TD vs Baseline, Fokus Performa)
direction down
typeface clean

Mulai [shape: circle, color: lightblue, icon: play]
Identifikasi Bottleneck Baseline [color: orange, icon: search, label: "Identifikasi Bottleneck Baseline\n(profiling CPU controller)"]
Studi Literatur Algoritma Ringan [color: purple, icon: book, label: "Studi Literatur Algoritma Ringan\n(flow stats / dua tahap / threshold adaptif)"]
Implementasi S2TD + Flag [color: purple, icon: code, label: "Implementasi S2TD + Flag\n(tanpa merusak baseline)"]
Load Sweep Bertingkat [color: orange, icon: sliders, label: "Load Sweep + Trafik Legitimate\n(flood 100-1500 pps, ping/iperf, ulang 3-5x)"]
Analisis Metrik [color: teal, icon: activity, label: "Analisis Mean ± Stddev\nutama: throughput, CPU/memori\nbatas: MTTR, loss legit, FPR"]
Target Performa Tercapai? [shape: diamond, color: yellow, icon: help-circle, label: "Target tercapai?\n(throughput naik, MTTR & loss dalam batas)"]
Revisi Parameter [color: red, icon: refresh-cw, label: "Revisi Parameter"]
Pilih Konfigurasi Final [color: green, icon: check-circle, label: "Pilih Konfigurasi Final S2TD\n+ simpulan utk skripsi"]
Selesai [shape: circle, color: gray, icon: stop-circle]

Mulai -> Identifikasi Bottleneck Baseline
Identifikasi Bottleneck Baseline -> Studi Literatur Algoritma Ringan
Studi Literatur Algoritma Ringan -> Implementasi S2TD + Flag
Implementasi S2TD + Flag -> Load Sweep Bertingkat
Load Sweep Bertingkat -> Analisis Metrik
Analisis Metrik -> Target Performa Tercapai?
Target Performa Tercapai? -> Revisi Parameter : Tidak
Revisi Parameter -> Load Sweep Bertingkat : uji ulang
Target Performa Tercapai? -> Pilih Konfigurasi Final : Ya
Pilih Konfigurasi Final -> Selesai
```

## 3.5 Alat dan Bahan

Mininet + Open vSwitch, controller os-ken 3.1.1 (Python 3.12) pada WSL2 Ubuntu; scapy (flood generator), iperf3 (trafik legitimate), psutil (sampling CPU/mem 0,5 s); harness run_experiment.py/analyze.py/visualize_results.py dari PoC yang sudah berjalan. Spesifikasi laptop dicatat dan dikunci (turbo/thermal) selama pengujian.

## 3.6 Jadwal Penelitian (16 minggu)

| Minggu | Kegiatan |
|---|---|
| 1–2 | Finalisasi proposal, pembekuan baseline, profiling bottleneck |
| 3–5 | Implementasi S2TD (polling stats, EWMA, verifikasi dua tahap) |
| 6–9 | Load sweep + skenario scale50/flash_crowd/threshold_sweep, 3–5× per titik |
| 10–11 | Analisis mean ± stddev, kurva throughput-CPU, uji signifikansi |
| 12–13 | Penulisan Bab 4–5, grafik final |
| 14–16 | Revisi bimbingan, simulasi, sidang |

## 3.7 Hasil Pendahulang (Kelayakan dari PoC)

PoC yang sudah dibangun membuktikan infrastruktur, harness eksperimen, dan metodologi sudah berjalan; seluruh angka berikut diambil langsung dari hasil eksekusi di repositori:

**Fase 1 (5 host; baseline threshold reaktif; flood ±173k pps):**

| Metrik | baseline | single | mixed |
|---|---|---|---|
| Waktu deteksi | — | 0,64 s | 0,86 s |
| False positive ban | 0 | 0 | 0 |
| Loss host legitimate | 0% | — | 0% |
| CPU controller (avg/max) | 1,0/3,9% | 0,5/27,5% | 1,8/54,9% |

**Fase scale50 (51 host; 5 pengulangan; mean ± stddev):** deteksi tetap di bawah 1 detik (single 0,636±0,005 s; mixed 0,640±0,000 s), FPR dan loss legitimate tetap 0, sementara CPU controller max saat serangan mencapai 35,8–39,8% — lonjakan yang konsisten dengan analisis bahwa desain per-paket menjadi bottleneck ketika skala naik.

**Uji false positive (flash_crowd) dan sweep threshold (fase 1, n=1 per titik):** harness iperf3-burst dan threshold sweep sudah dieksekusi. Pada sweep T = 50–300, TPR 100% di semua titik dan FPR 0%; waktu deteksi tercepat di T = 150–200 (0,88 s) dan melambat di titik ekstrem (2,16 s pada T = 50). Pada run flash_crowd standalone, skenario berhasil memicu satu kejadian false positive (fp_bans = 1, FPR 12,5%, loss ping host terdampak 12,5%) — membuktikan guardrail FPR penelitian ini dapat diukur dan relevan.

Data di atas menegaskan dua hal: (1) baseline layak sebagai pembanding karena deteksinya cepat dan FPR-nya rendah, sehingga klaim perbaikan S2TD harus datang dari efisiensi throughput/CPU, bukan sekadar akurasi; (2) CPU controller baseline sudah menunjukkan tekanan tinggi (hingga 54,9% pada 5 host; sekitar 40% pada 51 host dengan trafik legitimate paralel) — ruang perbaikan yang realistis untuk algoritma berbasis polling statistik.

---

# DAFTAR PUSTAKA

Abuabdallah, A. G. (2026). Performance-based evaluation of SDN controllers: OpenDayLight and RYU. Journal of Electrical Systems and Information Technology, 13, 35. https://doi.org/10.1186/s43067-026-00343-z

Antonakakis, M., April, T., Bailey, M., Bernhard, M., Bursztein, E., Cochran, J., ... Thomas, K. (2017). Understanding the Mirai botnet. In 26th USENIX Security Symposium (USENIX Security 17) (pp. 1093–1110). USENIX Association. https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/antonakakis

Bai, T., Liu, Y., Gao, Y., & Zhou, Y. (2026). ATS-DTA: Adaptive two-stage DDoS detection with dynamic threshold adjustment in SDN networks. Cybersecurity, 9, 12. https://doi.org/10.1186/s42400-025-00414-0

Braga, R., Mota, E., & Passito, A. (2010). Lightweight DDoS flooding attack detection using NOX/OpenFlow. In IEEE Local Computer Networks Conference (pp. 408–415). https://doi.org/10.1109/LCN.2010.5735752

Chen, K., Junuthula, A. R., Siddhrau, I. K., Xu, Y., & Chao, H. J. (2016). SDNShield: Towards more comprehensive defense against DDoS attacks on SDN control plane. In 2016 IEEE Conference on Communications and Network Security (CNS). https://doi.org/10.1109/CNS.2016.7860467

Rajper, A., Paraman, N., Marsono, M. N., Rajper, N. J., Hameed, H., & Usman, M. (2026). An efficient three-tier defense mechanism for mitigation of DDoS attack with port connection analysis in SDN. Scientific Reports, 16, 3510. https://doi.org/10.1038/s41598-025-33463-z

Shirali-Shahreza, S., & Ganjali, Y. (2013). FleXam: Flexible sampling extension for monitoring and security applications in OpenFlow. In Proceedings of the Second ACM SIGCOMM Workshop on Hot Topics in Software Defined Networking (HotSDN '13). https://conferences.sigcomm.org/sigcomm/2013/papers/hotsdn/p167.pdf

Tootoonchian, A., Gorbunov, S., Ganjali, Y., Casado, M., & Sherwood, R. (2012). On controller performance in software-defined networks. In 2nd USENIX Workshop on Hot Topics in Management of Internet, Cloud, and Enterprise Networks and Services (Hot-ICE 12). USENIX Association. https://www.usenix.org/conference/hot-ice12/workshop-program/presentation/tootoonchian

Wang, H., Xu, L., & Gu, G. (2015). FloodGuard: A DoS attack prevention extension in software-defined networks. In 2015 45th Annual IEEE/IFIP International Conference on Dependable Systems and Networks. https://doi.org/10.1109/DSN.2015.27

Wang, J., Wang, L., & Wang, R. (2023). A method of DDoS attack detection and mitigation for the comprehensive coordinated protection of SDN controllers. Entropy, 25(8), 1210. https://doi.org/10.3390/e25081210

Wang, K., Li, Z., Tu, Y., & Wu, J. (2014). OF-GUARD: A DoS attack prevention extension in software-defined networks. In Open Networking Summit (ONS 2014) Research Poster. https://www.usenix.org/sites/default/files/ons2014-poster-wang.pdf
