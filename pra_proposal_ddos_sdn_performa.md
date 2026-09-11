# DOKUMEN PRAPROPOSAL SKRIPSI — SA2-01A

Nama Mahasiswa : [Nama Mahasiswa]
NIM : [NIM]
Jurusan : Teknik Komputer
Program Studi : Teknik Komputer
Keminatan : [Keminatan/nonkeminatan]
Bidang Skripsi : Rekayasa Sistem Komputer
Jenis Penelitian : Implementatif
Tipe Penelitian : Implementatif–Pengembangan (Development)
Asal Judul Skripsi : Usulan Sendiri
Judul : OPTIMASI ALGORITMA DETEKSI DAN MITIGASI DDOS YANG EFISIEN SUMBER DAYA UNTUK MENINGKATKAN THROUGHPUT PADA SOFTWARE-DEFINED NETWORKING DENGAN BATAS MTTR DAN PACKET LOSS

## Latar Belakang (Maksimal 500 kata)

Perangkat IoT memperluas permukaan serangan DDoS karena jumlahnya besar, tersebar, dan sering memiliki pengamanan lemah. Pada skenario kota cerdas, misalnya jaringan kamera/CCTV, banyak sumber dapat menghasilkan trafik besar dan kontinu sehingga gangguan pada server atau jalur utama berdampak luas. Software-Defined Networking (SDN) relevan untuk kasus ini karena kontrol terpusat memudahkan pengaturan kebijakan, tetapi sentralisasi yang sama membuat controller menjadi titik kritis ketika banjir paket terjadi.

Serangan flood terhadap SDN dapat mengeksploitasi mekanisme table-miss: paket yang tidak cocok dengan flow table memicu packet-in ke controller, sehingga CPU, memori, dan kanal controller-switch cepat habis dan layanan kolaps (Wang et al., 2023). Karena itu, penelitian DDoS pada SDN tidak cukup menilai akurasi deteksi; kapasitas controller, latensi, throughput, dan packet loss juga menentukan apakah sistem layak dipakai. Tootoonchian et al. (2012) menunjukkan bahwa performa controller sangat menentukan, sekaligus dapat dioptimasi secara signifikan melalui metodologi pengukuran dan implementasi yang tepat.

Pendekatan statistik umumnya cepat tetapi bergantung pada threshold statis sehingga kurang adaptif terhadap perubahan trafik dan rawan false positive. Sebaliknya, pendekatan machine learning lebih akurat tetapi berat bila dijalankan terus-menerus, terutama pada controller dengan sumber daya terbatas (Rajper et al., 2026; Bai et al., 2026). Penelitian terbaru mengarah ke deteksi dua tahap dan threshold adaptif: tahap ringan untuk anomali, tahap berat hanya untuk verifikasi, serta threshold yang mengikuti karakteristik trafik (Rajper et al., 2026; Bai et al., 2026). Pola event-driven semacam ini penting karena deteksi periodik yang terlalu jarang memperlambat respons, sedangkan deteksi yang terlalu sering memboroskan CPU dan bandwidth controller (Wang et al., 2023).

Celah yang diangkat penelitian ini adalah efisiensi algoritma pada sumber daya yang sama. Banyak studi berfokus menambah kemampuan sistem, tetapi kurang menjawab pertanyaan praktis: dengan laptop/VM yang sama, algoritma mana yang menghasilkan throughput tertinggi per satuan beban CPU? MTTR tetap diukur sebagai batas, bukan fokus utama, bersama packet loss legitimate dan false positive. Studi performa controller di Mininet umumnya memakai metrik throughput, latency/RTT, dan packet loss dengan trafik terkontrol seperti iperf dan ping (Abuabdallah, 2026), sehingga kerangka pengujiannya sudah mapan untuk dipakai sebagai pembanding.

Berdasarkan uraian tersebut, penelitian ini mengoptimasi algoritma deteksi dan mitigasi DDoS yang efisien sumber daya pada SDN. Baseline berupa deteksi threshold reaktif dibandingkan dengan varian ringan seperti statistik switch, deteksi dua tahap suspect-only, dan threshold adaptif. Keberhasilan terutama diukur dari peningkatan throughput dan efisiensi CPU pada resource yang sama; MTTR deteksi-mitigasi, packet loss legitimate, dan false positive dipakai sebagai batas yang tidak boleh dilanggar. CCTV kota dipakai sebagai motivasi dan profil trafik yang sepadan, bukan klaim dataset asli bila datanya tidak terbuka.

## Landasan Kepustakaan (Maksimal 250 kata)

Tootoonchian et al. (2012) meletakkan dasar evaluasi performa controller SDN melalui throughput flow setup, latensi, dan benchmarking cbench, serta membuktikan optimasi implementasi dapat meningkatkan throughput secara besar. Braga et al. (2010) menunjukkan deteksi flooding ringan memakai NOX/OpenFlow sebagai pendekatan awal yang hemat sumber daya. Wang et al. (2023) melalui CC-Guard menegaskan masalah pemicu deteksi periodik, kebutuhan membebaskan controller yang kelebihan beban, serta kesulitan membedakan DDoS dari flash traffic. Rajper et al. (2026) mengusulkan mekanisme tiga tahap yang ringan dan event-driven: CUSUM adaptif untuk deteksi cepat, decision tree hanya saat ada pemicu, lalu mitigasi port-level yang terarah dengan packet loss legitimate nol persen. Bai et al. (2026) melalui ATS-DTA menggabungkan entropi kondisional, penyesuaian threshold EWMA-ARIMA, dan ML dua tahap untuk menyeimbangkan kecepatan, akurasi, dan overhead. Abuabdallah (2026) menyediakan kerangka evaluasi performa controller di Mininet memakai throughput, latency, dan packet loss. Berdasarkan peta tersebut, penelitian ini tidak sekadar memilih algoritma paling akurat, melainkan membandingkan varian ringan pada hardware yang sama berdasarkan throughput per satuan beban CPU; MTTR, packet loss legitimate, dan false positive dipakai sebagai batas. Algoritma final ditetapkan pada proposal Bab 3 dari hasil kajian dan eksperimen awal.

## Rumusan Masalah

1. Seberapa besar throughput flood yang dapat ditangani setiap varian algoritma pada sumber daya yang sama sebelum controller jenuh?
2. Bagaimana efisiensi setiap varian bila throughput per satuan beban CPU/memori dibandingkan dengan baseline?
3. Varian algoritma mana yang paling efisien untuk trafik IoT/CCTV-like bila throughput per satuan beban CPU dimaksimalkan dengan MTTR, packet loss legitimate, dan false positive rate tetap dalam batas?

## Metode yang Digunakan (Maksimal 250 kata dan 1 Gambar Metode)

Penelitian ini memakai metode eksperimental dengan prototyping iteratif pada Mininet dan Open vSwitch memakai controller kompatibel Ryu. Tahap pertama membekukan baseline deteksi threshold reaktif, lalu memprofilkan bottleneck CPU pada parsing packet-in, state per-IP, instalasi flow, dan logging. Tahap berikutnya mengimplementasikan dua sampai tiga varian ringan di belakang flag tanpa merusak baseline: statistik switch, deteksi dua tahap suspect-only, dan threshold adaptif. Pengujian memakai load sweep flood bertingkat pada VM/spesifikasi yang sama, dengan trafik legitimate ping/iperf sebagai guardrail. Setiap titik beban diulang 3–5 kali dan dilaporkan sebagai mean ± stddev untuk throughput dan CPU/memori sebagai metrik utama, sedangkan MTTR, packet loss legitimate, dan FPR dipakai sebagai batas. Apabila target throughput/efisiensi tidak tercapai atau batas MTTR/loss dilanggar, parameter direvisi lalu pengujian diulang. Hasilnya dipakai untuk memilih algoritma final pada proposal Bab 3 beserta justifikasi referensi dan batasannya.

Gambar 1 — Diagram metode rencana:

```text
[Identifikasi bottleneck baseline]
              |
              v
[Studi literatur algoritma ringan]
              |
              v
[Implementasi varian efisien + flag]
              |
              v
[Load sweep + trafik legitimate] -- belum memenuhi target --> [Revisi parameter]
              |
              v
[Analisis throughput/CPU/MTTR/loss/FPR]
              |
              v
[Pilih algoritma untuk proposal Bab 3]
```

## Daftar Pustaka

Abuabdallah, A. G. (2026). Performance-based evaluation of SDN controllers: OpenDayLight and RYU. Journal of Electrical Systems and Information Technology, 13, 35. https://link.springer.com/article/10.1186/s43067-026-00343-z

Bai, T., et al. (2026). ATS-DTA: Adaptive two-stage DDoS detection with dynamic threshold adjustment in SDN networks. Cybersecurity, 9, 12. https://link.springer.com/article/10.1186/s42400-025-00414-0

Braga, R., Mota, E., & Passito, A. (2010). Lightweight DDoS flooding attack detection using NOX/OpenFlow. In IEEE Local Computer Networks Conference (pp. 408–415). https://doi.org/10.1109/LCN.2010.5735752

Rajper, A., et al. (2026). An efficient three-tier defense mechanism for mitigation of DDoS attack with port connection analysis in SDN. Scientific Reports, 16, 3510. https://doi.org/10.1038/s41598-025-33463-z

Tootoonchian, A., Gorbunov, S., Ganjali, Y., Casado, M., & Sherwood, R. (2012). On controller performance in software-defined networks. In 2nd USENIX Workshop on Hot Topics in Management of Internet, Cloud, and Enterprise Networks and Services (Hot-ICE 12). https://www.usenix.org/conference/hot-ice12/workshop-program/presentation/tootoonchian

Wang, J., Wang, L., & Wang, R. (2023). A method of DDoS attack detection and mitigation for the comprehensive coordinated protection of SDN controllers. Entropy, 25(8), 1210. https://doi.org/10.3390/e25081210

Status Usulan: Diteruskan menjadi proposal / Ditolak *)
Keterangan: (apabila ditolak)
Masukan pembimbing untuk penulisan proposal: (diisi oleh calon pembimbing)
