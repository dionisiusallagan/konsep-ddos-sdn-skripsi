# NASKAH KONSULTASI SKRIPSI

## Perbandingan Tiga Algoritme Deteksi DDoS pada Jaringan SDN

**Untuk:** dosen pembimbing baru yang belum mengenal penelitian ini
**Sifat:** naskah siap dibaca; angka dan istilah sudah disesuaikan dengan hasil eksperimen
**Durasi inti:** 10 menit + tanya-jawab

---

## Cara memakai naskah ini

1. **Hafalkan alurnya, bukan kata per kata.** Yang penting urutannya: masalah → yang dibangun → tiga algoritme → desain → hasil → keterbatasan → permintaan arahan.
2. **Jangan mulai dari tools.** Jangan buka dengan "saya pakai Mininet, os-ken, Scapy". Mulai dari masalah. Tools hanya disebut saat menjelaskan sistem.
3. **Bawa empat benda:** naskah ini, satu diagram topologi, satu tabel hasil, satu grafik. Jangan buka kode kecuali diminta.
4. **Sisakan waktu untuk bertanya.** Konsultasi yang baik bukan presentasi 30 menit, tapi 10 menit penjelasan + 20 menit diskusi.
5. **Kalau waktu hanya 5 menit,** pakai Versi 2 Menit lalu langsung ke bagian Hasil dan Keterbatasan.

---

# VERSI 2 MENIT (untuk pembuka atau jika waktu mendesak)

> "Pak/Bu, saya membuat simulasi jaringan SDN: satu switch OpenFlow, satu controller, empat host IoT, dan satu server korban. Serangannya meniru Mirai — satu host membanjiri server dengan paket permintaan koneksi.
>
> Saya membandingkan tiga cara mendeteksi. Pertama, **threshold**: hitung paket per detik per IP, lewat 25 langsung blokir. Kedua, **Shannon entropy**: lihat apakah semua paket datang dari satu sumber. Ketiga, **S2TD** — nama internal saya untuk desain dua tahap: controller membaca rekap statistik flow tiap detik, lalu memverifikasi sumber terbesar selama dua interval berturut-turut sebelum memblokir.
>
> Ketiganya memakai aturan mitigasi yang sama: IP penyerang diblokir 15 detik. Jadi yang berbeda hanya logika deteksinya.
>
> Saya uji pada lima tingkat beban, 100 sampai 3000 paket per detik, masing-masing tiga kali — total 45 run. Hasilnya: baseline paling cepat mendeteksi, entropy paling mahal CPU, S2TD paling hemat CPU tapi terlambat sekitar 2,4 detik. Pada 45 run ini tidak ada false positive dan tidak ada packet loss ke host lain.
>
> Kontribusi saya bukan algoritme baru, tapi perbandingan terkontrol dan pengukuran biayanya. Saya juga menemukan bahwa keunggulan CPU S2TD sebagian karena flow caching — bukan murni algoritmenya. Itu yang ingin saya diskusikan."

---

# VERSI 10 MENIT (naskah inti)

## 0:00–0:45 — Pembukaan dan tujuan

> "Selamat pagi/siang, Pak/Bu. Terima kasih waktunya. Saya Dionisius, mahasiswa Teknik Komputer. Topik saya deteksi dan mitigasi otomatis serangan DDoS pada jaringan Software-Defined Networking.
>
> Saat ini saya sudah sampai tahap data lengkap: 45 eksperimen, tiga algoritme, lima tingkat beban serangan. Yang saya butuhkan hari ini bukan persetujuan, tetapi **koreksi arah sebelum saya menulis bab hasil**. Saya akan pakai sekitar sepuluh menit untuk menjelaskan masalahnya, yang saya bangun, hasilnya, dan tiga keterbatasan yang saya sadari. Setelah itu saya ingin bertanya empat hal."

*[Cue: letakkan diagram topologi di meja, jangan langsung ditunjukkan.]*

---

## 0:45–2:15 — Masalah dan kenapa penting

> "Serangan DDoS adalah upaya membuat sebuah layanan tidak bisa diakses dengan membanjiri jaringan atau server menggunakan trafik dari banyak sumber. Yang saya tiru adalah pola Mirai: botnet perangkat IoT yang membanjiri server dengan permintaan koneksi baru. Karena perangkat IoT jumlahnya sangat banyak dan sering tidak dijaga, serangan jenis ini murah dilakukan dan sulit dihentikan secara manual.
>
> Di jaringan biasa, keputusan filtering tersebar di banyak perangkat, jadi responsnya lambat dan tidak konsisten. SDN memindahkan keputusan itu ke satu **controller** terpusat. Controller bisa melihat seluruh jaringan dan memasang aturan blokir dalam hitungan milidetik. Itu keunggulannya.
>
> Tapi ada konsekuensinya. Controller yang sama juga memproses paket-paket yang belum punya aturan. Kalau serangan membanjiri controller, bukan hanya server yang terganggu — seluruh jaringan bisa ikut lumpuh. Jadi **biaya CPU controller bukan detail teknis**, melainkan bagian inti dari masalah keamanan SDN.
>
> Dari situ pertanyaan penelitian saya: **pada beban serangan yang meningkat, bagaimana trade-off antara kecepatan deteksi, biaya CPU controller, dan dampak ke pengguna sah — antara tiga pendekatan deteksi yang berbeda?**"

*[Cue: berhenti sebentar. Pastikan dosen mengangguk atau bertanya.]*

---

## 2:15–3:15 — Sistem yang dibangun

> "Sistemnya kecil dan sengaja dibuat sederhana supaya variabelnya terkontrol.
>
> Topologinya satu switch OpenFlow, satu controller, empat host yang berperan sebagai perangkat IoT, dan satu server korban. Penyerang adalah salah satu host IoT. Serangan dikirim sebagai paket TCP SYN dengan laju yang bisa diatur, dari 100 sampai 3000 paket per detik.
>
> Tools-nya Mininet untuk topologi, Open vSwitch sebagai switch, os-ken sebagai controller — os-ken adalah fork Ryu yang masih mendukung Python 3.12 — OpenFlow 1.3, dan Scapy untuk merender paket serangan.
>
> Yang penting: **ketiga algoritme memakai aturan mitigasi yang identik**. Kalau terdeteksi, controller memasang flow DROP dengan prioritas 100, mencocokkan IP sumber, dan berlaku 15 detik. Jadi bentuk mitigasinya bukan variabel pembeda. Yang berbeda hanya cara memutuskan kapan dan siapa yang diblokir."

*[Cue: tunjukkan diagram topologi sekarang.]*

---

## 3:15–5:45 — Tiga algoritme

### Baseline — threshold per-IP

> "Algoritme pertama adalah baseline: threshold sederhana. Controller menghitung berapa paket per detik dari setiap IP sumber dalam jendela satu detik. Kalau sebuah IP melewati 25 paket per detik, IP itu langsung diblokir.
>
> Analoginya seperti satpam di pintu yang menghitung: siapa yang lewat lebih dari 25 kali per detik, tangkap. Cepat dan mudah dipahami. Kelemahannya dua: penyerang yang datang pelan-pelan di bawah 25 paket per detik tidak pernah tertangkap, dan satpamnya sibuk kalau semua orang lewat bersamaan.
>
> Baseline ini sengaja **tidak memakai flow caching**: setiap paket dikirim ke controller. Itu membuat rate terlihat langsung dan akurat, tapi mahal secara CPU."

### Entropy — Shannon entropy IP sumber

> "Algoritme kedua memakai Shannon entropy. Controller mengumpulkan paket permintaan koneksi dalam jendela satu detik, lalu menghitung seberapa acak distribusi IP sumbernya.
>
> Kalau trafik normal, paket datang dari beberapa host berbeda, jadi entropinya relatif tinggi. Kalau satu penyerang mendominasi, distribusinya menumpuk di satu IP, dan entropinya turun mendekati nol. Di bawah satu bit, sistem menganggapnya serangan.
>
> Analoginya: satpam tidak menghitung jumlah orang, tapi bertanya 'apakah semua orang datang dari satu arah?' Kalau ya, curiga.
>
> Kelemahannya adalah kebalikan dari kekuatannya: kalau serangannya terdistribusi dari banyak sumber, entropi justru tinggi, sehingga lolos. Dan karena setiap paket harus masuk jendela dan distribusinya dihitung ulang, biaya CPU-nya tumbuh seiring beban."

### S2TD — dua tahap berbasis statistik flow

> "Algoritme ketiga adalah yang saya sebut S2TD. Saya perlu menyampaikan ini terus terang: **S2TD adalah nama internal saya**, bukan nama algoritma dari paper tertentu. Di proposal, desainnya saya tulis sebagai pseudocode. Akronimnya juga tidak dipakai di literatur DDoS/SDN — saya sudah cek, S2TD di literatur justru dipakai di computer vision dan remote sensing. Jadi di skripsi saya akan selalu menuliskannya lengkap saat pertama muncul.
>
> Cara kerjanya dua tahap. **Tahap satu** selalu aktif tapi ringan: controller meminta rekap statistik flow dari switch setiap satu detik, menghitung laju paket agregat, dan membandingkannya dengan ambang adaptif — yaitu kelipatan dari rata-rata bergerak, dengan lantai minimum 50 paket per detik. **Tahap dua** hanya aktif kalau tahap satu terpicu: controller memeringkat sumber teratas, lalu memverifikasi sumber yang melewati 50 paket per detik selama dua interval berturut-turut. Setelah itu baru DROP dipasang.
>
> Analoginya: satpam tidak mengamati setiap orang. Tiap detik ia membaca rekap kunjungan dari mesin. Kalau totalnya melonjak, baru ia memeriksa siapa yang paling banyak, dan butuh dua rekap berturut-turut sebelum menangkap.
>
> Konsekuensinya jelas: lebih hemat tenaga karena mayoritas paket tidak lagi dikirim ke controller — S2TD memakai flow caching — tetapi deteksinya terlambat sekitar dua sampai tiga detik karena bergantung pada interval polling satu detik."

### Posisi S2TD terhadap literatur

> "Pendekatan dua tahap berbasis flow statistics bukan hal baru. Yang paling dekat adalah Yang dkk. 2026 di *International Journal of Computer Applications*: mereka juga memakai flow statistics, menandai kandidat, lalu mengonfirmasi kalau kondisi mencurigakan bertahan. Bedanya, mereka memakai empat indikator simultan termasuk entropi, sedangkan saya memakai ambang agregat adaptif dan konfirmasi berbasis jumlah poll.
>
> Ada juga ATS-DTA 2026 di *Cybersecurity*, yang secara judul juga dua tahap dengan ambang dinamis. Jadi saya tidak mengklaim desain dua tahapnya sebagai kebaruan. Yang saya klaim adalah **perbandingan terkontrol** antara tiga keluarga metode ini pada topologi, serangan, dan aturan mitigasi yang sama."

*[Cue: ini bagian paling rawan. Berhenti, tatap dosen, dan beri kesempatan bertanya.]*

---

## 5:45–7:00 — Desain eksperimen

> "Desainnya tiga algoritme, lima tingkat beban, tiga pengulangan. Total 45 run, sekitar 35 menit.
>
> Skenarionya *mixed*: serangan berjalan bersamaan dengan trafik legitimate dari tiga host lain yang terus mem-ping server. Ini penting supaya saya bisa mengukur apakah mitigasi mengganggu pengguna sah.
>
> Beban yang diuji 100, 500, 1000, 1500, dan 3000 paket per detik. Saya naikkan bertahap, dan urutannya rate dulu, baru algoritme, baru pengulangan — supaya ketiga algoritme mengalami kondisi lingkungan yang berdekatan.
>
> Empat metrik utama. **Waktu deteksi**: dari paket serangan pertama sampai rule DROP pertama terpasang, dihitung dari jam dinding supaya presisinya milidetik. **CPU controller fase serangan**: sengaja hanya fase serangan, bukan rata-rata seluruh run, karena setelah DROP terpasang controller memang idle. **Packet loss host legitimate**. Dan **throughput per CPU**: paket per detik yang benar-benar terkirim dibagi rata-rata CPU fase serangan.
>
> Satu hal yang saya tegaskan: throughput per CPU ini **bukan kapasitas maksimum perangkat**. Ini indeks relatif pada intensitas serangan tertentu."

---

## 7:00–9:00 — Hasil

> "Hasilnya saya ringkas dalam tiga temuan.
>
> **Pertama, waktu deteksi.** Baseline paling cepat, dan makin tinggi beban makin cepat: 0,25 detik pada 100 paket per detik, turun sampai 0,011 detik pada 3000. Itu bukan kebetulan — ambangnya absolut 25 paket per detik, jadi secara matematis waktunya kira-kira 26 dibagi laju serangan. Semua angka terukur cocok dengan prediksi itu.
>
> Entropy berada di tengah: sekitar 0,46 detik pada beban 500 ke atas, tapi 0,97 detik pada 100 paket per detik karena harus menunggu minimal 30 paket terkumpul.
>
> S2TD datar di sekitar 2,4 detik pada semua beban. Itu konsekuensi polling satu detik dikali dua konfirmasi — bukan karena komputasinya lambat.
>
> **Kedua, biaya CPU.** Baseline sekitar 0,8 sampai 1,1 persen. Entropy naik linear terhadap beban: 1,5 persen pada 100 paket per detik, menjadi 4,4 persen pada 3000. S2TD paling rendah, 0,13 sampai 0,20 persen. Tapi saya harus jujur: rendahnya CPU S2TD sebagian besar karena flow caching, bukan murni karena algoritmenya. Ini yang saya sebut confounding — dua variabel tercampur dalam satu angka.
>
> **Ketiga, dampak ke pengguna dan throughput per CPU.** Pada 45 run ini, false positive nol dan packet loss ke host legitimate nol persen. Throughput per CPU meningkat untuk ketiganya, tapi angka S2TD tidak boleh dibaca sebagai kapasitas sustained.
>
> Dan yang penting: **tidak ada saturasi** sampai 3000 paket per detik. CPU rata-rata tertinggi hanya 4,4 persen, loss nol. Jadi kurvanya belum mencapai titik jenuh. Ini bukan kegagalan, tapi batas ruang lingkup yang harus saya nyatakan."

*[Cue: tunjukkan tabel hasil. Tunjuk tiga baris: 100, 1000, 3000. Jangan bacakan 15 baris.]*

---

## 9:00–10:00 — Keterbatasan, kontribusi, dan permintaan arahan

> "Ada tiga keterbatasan yang saya sadari dan akan saya tulis eksplisit.
>
> **Satu, confounding flow caching.** Baseline dan entropy tidak memakai flow caching, S2TD memakai. Jadi selisih CPU mengukur perbedaan pendekatan secara keseluruhan, bukan algoritme murni. Untuk memisahkannya, kedua pembanding harus diberi flow caching setara — itu kandidat eksperimen tambahan.
>
> **Dua, belum ada saturasi.** Pengujian berhenti di 3000 paket per detik karena anggaran waktu. Kurva belum mencapai lutut saturasi.
>
> **Tiga, skala terbatas.** Satu switch, simulasi di WSL2, tiga pengulangan per titik. Angka saya berlaku sebagai tren relatif, bukan kapasitas produksi.
>
> Kontribusi saya bukan algoritme baru. Kontribusinya ada di tiga hal: implementasi tiga keluarga metode pada testbed dan aturan mitigasi yang identik; pengukuran biaya CPU dan throughput per CPU pada lima tingkat beban; dan analisis confounding yang eksplisit, sehingga pembaca tahu apa yang benar-benar diukur.
>
> Dari situ saya ingin bertanya empat hal. **Pertama**, apakah fokus perbandingan seperti ini cukup untuk S1, atau harus ada unsur kebaruan algoritme? **Kedua**, apakah confounding flow caching harus dieliminasi dengan eksperimen tambahan, atau cukup diakui sebagai keterbatasan? **Ketiga**, apakah topologi 51 host perlu masuk ruang lingkup, atau cukup jadi lampiran? **Keempat**, struktur bab seperti apa yang Anda harapkan — metodologi dulu atau hasil dulu?
>
> Terima kasih, Pak/Bu. Saya siap diskusi."

---

# JIKA DOSEN BERTANYA DI TENGAH

## "S2TD itu dari paper mana?"

Jawab dengan urutan ini:

> "Bukan dari paper tertentu, Pak/Bu. S2TD adalah nama internal saya untuk desain dua tahap yang saya tulis sendiri di proposal sebagai pseudocode. Saya sudah cek, akronim S2TD tidak dipakai di literatur DDoS/SDN; yang ada justru di computer vision dan remote sensing. Jadi saya tidak akan mengutipnya sebagai metode yang sudah mapan.
>
> Pendekatan dua tahapnya sendiri sudah ada di literatur. Yang paling dekat Yang dkk. 2026, yang juga memakai flow statistics, menandai kandidat, lalu mengonfirmasi kalau kondisi bertahan. Bedanya, mereka memakai empat indikator termasuk entropi, dan konfirmasinya berbasis durasi. Saya memakai ambang agregat adaptif dan konfirmasi berbasis jumlah poll."

Kalau dosen meminta sumber persisnya:

> "Kalau di proposal saya ada nama penulis atau DOI-nya, saya akan kirimkan setelah konsultasi. Kalau tidak ada, saya akan menulisnya sebagai desain internal, bukan sebagai sitasi."

**Jangan** mengarang sitasi. Lebih baik mengakui nama internal.

## "Apa kebaruannya? Ini kan cuma memakai metode yang sudah ada."

> "Betul, algoritmenya bukan baru. Kebaruan saya ada di perbandingan terkontrol: topologi, pola serangan, dan aturan mitigasi dibuat identik, lalu biaya CPU diukur per tingkat beban. Literatur umumnya mengusulkan satu metode dan mengevaluasinya di testbed masing-masing, sehingga sulit dibandingkan langsung. Saya juga melaporkan confounding flow caching secara eksplisit, sesuatu yang sering tidak dibahas."

## "Kenapa S2TD CPU-nya jauh lebih rendah?"

> "Karena flow caching. Mayoritas paket tidak lagi dikirim ke controller; controller hanya membaca rekap statistik tiap detik. Baseline dan entropy memproses setiap paket. Jadi ini perbedaan arsitektur forwarding, bukan semata perbedaan algoritme. Saya akui itu sebagai keterbatasan."

## "Kenapa S2TD lambat 2,4 detik?"

> "`T_poll` satu detik dan `T_confirm` dua poll berturut-turut. Jadi ada penundaan struktural dua sampai tiga detik. Kalau `T_poll` diperkecil, deteksi bisa lebih cepat, tapi overhead control-channel naik. Ini trade-off yang bisa diuji di eksperimen lanjutan."

## "Kalau baseline paling cepat, kenapa tidak dipakai saja?"

> "Cepat, tapi ada dua masalah. Pertama, ambangnya absolut: penyerang yang menjaga laju di bawah 25 paket per detik tidak pernah terdeteksi. Kedua, karena setiap paket dikirim ke controller, biaya CPU-nya tidak turun saat beban naik. Baseline diuntungkan secara definisi pada serangan deras."

## "Kenapa entropy CPU-nya naik linear?"

> "Karena setiap paket harus masuk sliding window, dan distribusi dihitung ulang secara periodik. Jadi biayanya proporsional terhadap jumlah paket. Regresinya sekitar CPU sama dengan 1,42 ditambah 0,00228 kali paket per detik, dengan R kuadrat 0,95."

## "Kok bisa 0% loss dan 0 false positive? Curiga."

> "Mitigasi mencocokkan IP sumber penyerang secara spesifik, dan IP korban dilindungi eksplisit. Ping legitimate berasal dari host lain, jadi tidak terkena rule. Serangan berlangsung 10 detik dan ban 15 detik, jadi seluruh fase serangan tercakup. Angka ini berlaku untuk 45 run ini, bukan klaim umum."

## "Kenapa tidak sampai saturasi?"

> "Anggaran waktu. 45 run sudah sekitar 35 menit. Pada 3000 paket per detik CPU rata-rata masih 4,4 persen dan loss nol, jadi memang belum jenuh. Untuk mencapai saturasi perlu beban sekitar 10 ribu paket per detik atau lebih; flooder tanpa pacing sebenarnya sanggup sekitar 93 ribu, tapi belum saya sapu."

## "Cukup tiga pengulangan?"

> "Cukup untuk melihat stabilitas — standard deviasi waktu deteksi baseline nol sampai 2 milidetik, entropy 3 sampai 63 milidetik, S2TD 7 sampai 116 milidetik. Tapi belum cukup untuk memetakan distribusi ekor. Kalau diperlukan, saya bisa menambah repeat pada titik-titik kritis."

## "Apa bedanya dengan Yang dkk. 2026?"

> "Mereka mengusulkan satu mekanisme: empat indikator flow statistics, kandidat kalau keempatnya terpenuhi, konfirmasi berbasis durasi, lalu drop per sumber. Saya tidak mengusulkan mekanisme baru; saya membandingkan tiga keluarga metode, dan S2TD adalah salah satunya. Perbedaan teknisnya: saya memakai ambang agregat adaptif berbasis EWMA dengan lantai, konfirmasi berbasis jumlah poll, dan tidak memakai entropi di dalam S2TD."

## "Apakah ini bisa dipakai di produksi?"

> "Belum. Ini proof-of-concept satu switch dengan topologi simulasi. Untuk produksi perlu multi-switch, penanganan source IP spoofed, skala beban yang lebih tinggi, dan pengujian pada trafik nyata."

## "Kenapa os-ken, bukan Ryu?"

> "Ryu asli tidak mendukung Python 3.12 ke atas. os-ken adalah fork aktif dengan API yang kompatibel, jadi kode dan konsepnya tetap sama."

## "Kenapa baseline dan entropy tidak diberi flow caching juga?"

> "Itu keputusan desain awal: tanpa flow caching, controller melihat setiap paket sehingga rate per IP akurat. Kalau diberi caching, flood bisa tidak terlihat controller. Tapi konsekuensinya perbandingan CPU jadi tidak setara. Solusi yang benar adalah membuat varian kedua pembanding dengan caching setara — itu future work yang saya sebut sebagai de-confounding."

## "Apa itu throughput per CPU?"

> "Paket per detik yang benar-benar terkirim dibagi rata-rata CPU controller pada fase serangan. Satuannya paket per detik per satu persen CPU. Ini indeks relatif, bukan kapasitas sustained, karena setelah mitigasi aktif controller berhenti memproses serangan."

## "Kenapa detected rate entropy sekitar setengah dari nominal?"

> "Karena saat evaluasi, window satu detik bisa baru terisi setengah. Jadi rate yang dicatat sekitar 0,46 kali nominal. Karena cara ukurnya berbeda, kolom itu tidak boleh dibandingkan antar algoritme; hanya untuk audit internal."

---

# LAMPIRAN A — Tabel hasil ringkas (bawa satu halaman ini)

| Beban (pps) | Algoritme | Deteksi (s) | CPU serangan (%) | Loss maks (%) | Throughput/CPU |
|---:|---|---:|---:|---:|---:|
| 100 | Baseline | 0,252 | 1,10 | 0 | 90,9 |
| 100 | Entropy | 0,966 | 1,53 | 0 | 65,2 |
| 100 | S2TD | 2,390 | 0,13 | 0 | 750,0 |
| 500 | Baseline | 0,052 | 0,87 | 0 | 576,9 |
| 500 | Entropy | 0,464 | 1,77 | 0 | 283,0 |
| 500 | S2TD | 2,450 | 0,13 | 0 | 3.750,0 |
| 1000 | Baseline | 0,028 | 0,87 | 0 | 1.153,9 |
| 1000 | Entropy | 0,429 | 2,47 | 0 | 405,4 |
| 1000 | S2TD | 2,438 | 0,17 | 0 | 6.000,0 |
| 1500 | Baseline | 0,019 | 0,93 | 0 | 1.607,1 |
| 1500 | Entropy | 0,472 | 3,47 | 0 | 432,7 |
| 1500 | S2TD | 2,463 | 0,13 | 0 | 11.250,0 |
| 3000 | Baseline | 0,011 | 0,80 | 0 | 3.750,0 |
| 3000 | Entropy | 0,464 | 4,40 | 0 | 681,8 |
| 3000 | S2TD | 2,460 | 0,20 | 0 | 15.000,0 |

**Catatan yang harus disebut:** 3 run per titik, 3/3 terdeteksi, 0 false positive, 0% loss. CPU puncak sesaat entropy mencapai 55,1% pada 3000 pps, tetapi rata-rata fase serangannya 4,40%.

---

# LAMPIRAN B — Istilah untuk dosen non-SDN

| Istilah | Arti sederhana |
|---|---|
| **SDN** | Jaringan yang keputusan pengaturannya dipusatkan di satu controller, bukan tersebar di tiap perangkat. |
| **Controller** | "Otak" jaringan; menerima paket yang belum punya aturan dan memutuskan diteruskan atau diblokir. |
| **OpenFlow** | Bahasa komunikasi antara controller dan switch. |
| **Flow** | Aturan di switch: cocokkan ciri paket tertentu, lalu lakukan aksi. |
| **Flow statistics** | Rekap jumlah paket/byte per flow yang bisa diminta controller dari switch. |
| **Packet-in** | Paket yang dikirim switch ke controller karena belum ada aturan yang cocok. |
| **Flow caching** | Switch menyimpan aturan hasil keputusan controller, sehingga paket berikutnya tidak perlu ke controller. |
| **DDoS** | Serangan membanjiri layanan dari banyak sumber agar tidak bisa diakses. |
| **False positive** | Host sah yang salah diblokir. |
| **EWMA** | Rata-rata bergerak yang memberi bobot lebih besar pada sampel terbaru. |
| **Shannon entropy** | Ukuran seberapa acak suatu distribusi; makin menumpuk di satu nilai, makin rendah. |
| **Throughput per CPU** | Berapa paket per detik yang ditangani untuk setiap 1% CPU yang dipakai. |

---

# LAMPIRAN C — Sitasi kunci yang siap dipakai

| Keperluan | Sitasi |
|---|---|
| Dua tahap + flow statistics (paling dekat) | Yang, Y., Jiang, S., Ye, H., She, Y., Liu, M., & Li, Y. (2026). A Lightweight Flow-Statistics-based DDoS Detection and Mitigation Mechanism in SDN. *International Journal of Computer Applications*, 187(146), 47–52. DOI: 10.5120/ijca66aa6399afa5 |
| Dua tahap + ambang dinamis | Bai, T., Liu, Y., Gao, Y., & Zhou, Y. (2026). ATS-DTA: adaptive two-stage DDoS detection with dynamic threshold adjustment in SDN networks. *Cybersecurity*. DOI: 10.1186/s42400-025-00414-0 |
| Deteksi ringan berbasis flow | Jia, K., Liu, C., Liu, Q., et al. (2022). A lightweight DDoS detection scheme under SDN context. *Cybersecurity*, 5(1), 27. |
| Deteksi klasik NOX/OpenFlow | Braga, R., Mota, E., & Passito, A. (2010). Lightweight DDoS flooding attack detection using NOX/OpenFlow. *IEEE LCN*, 408–415. |
| Deteksi dini terhadap controller | Mousavi, S. M., & St-Hilaire, M. (2015). Early detection of DDoS attacks against SDN controllers. *IEEE ICNC*, 77–81. |
| Survei | Eliyan, L. F., & Di Pietro, R. (2021). DoS and DDoS attacks in Software Defined Networks. *Computer Networks*. |
| Survei terbaru | Batool, S., et al. (2025). A Comprehensive Review of DDoS Detection and Mitigation. *Electronics*, 14(21), 4222. |

**Aturan aman:** verifikasi volume, halaman, dan tahun di sumber asli sebelum masuk daftar pustaka. Jangan mengutip detail ATS-DTA di luar judul/abstrak sebelum membaca full-text-nya.

---

# LAMPIRAN D — Checklist sebelum berangkat

- [ ] Naskah ini sudah dibaca dua kali, alurnya hafal.
- [ ] Diagram topologi tercetak.
- [ ] Tabel hasil ringkas (Lampiran A) tercetak.
- [ ] Satu grafik: waktu deteksi vs beban.
- [ ] Daftar empat pertanyaan ditulis di kertas terpisah.
- [ ] README/repo siap ditunjukkan **hanya jika diminta**.
- [ ] Kalimat tentang S2TD sebagai nama internal sudah dilatih.
- [ ] Tidak akan mengklaim "belum ada penelitian" — gunakan "sejauh penelusuran saya".

---

# LAMPIRAN E — Kalimat yang harus dihindari dan penggantinya

| Jangan bilang | Ganti dengan |
|---|---|
| "S2TD adalah algoritma dari paper X" (tanpa sumber) | "S2TD adalah nama internal desain saya; pendekatan dua tahapnya terkait Yang dkk. 2026 dan ATS-DTA 2026." |
| "Belum ada penelitian yang membandingkan ini" | "Sejauh penelusuran saya, belum banyak studi yang membandingkan ketiganya secara terkontrol." |
| "S2TD lebih efisien" | "Pendekatan S2TD lebih hemat CPU pada pengujian ini, sebagian karena flow caching." |
| "Baseline buruk" | "Baseline unggul di waktu deteksi, tetapi ambang absolut dan biaya CPU-nya menjadi keterbatasan." |
| "Hasil ini membuktikan S2TD terbaik" | "Tidak ada pemenang tunggal; hasilnya trade-off yang berbeda-beda menurut metrik." |
| "Tidak ada false positive sama sekali" | "Pada 45 run ini tidak ada false positive." |
| "Throughput per CPU menunjukkan kapasitas" | "Throughput per CPU adalah indeks relatif pada intensitas serangan yang diuji, bukan kapasitas sustained." |

---

# PENUTUP

Kalau dosen hanya mengingat satu hal dari pertemuan ini, pastikan itu:

> **"Saya membandingkan tiga pendekatan deteksi DDoS pada kondisi yang sama, mengukur trade-off waktu deteksi versus biaya CPU, dan saya jujur tentang apa yang belum bisa disimpulkan."**

Itu posisi yang kuat untuk skripsi S1 — lebih kuat daripada klaim "algoritme baru" yang tidak bisa dipertahankan.
