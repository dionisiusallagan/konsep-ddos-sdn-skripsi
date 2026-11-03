# Glosarium Log S2TD

Dokumen pendamping skripsi **"Optimasi Algoritme Deteksi dan Mitigasi DDoS yang Efisien Sumber Daya untuk Meningkatkan Throughput pada SDN"**.

Isi: penjelasan istilah yang muncul di log controller `controller/ddos_guard_s2td.py` dan file `results/mitigation_events_s2td.csv`, disusun mengikuti struktur baris. Berguna saat menulis bab metodologi/hasil dan saat menjawab pertanyaan penguji.

---

## 1. Kerangka umum log

| Istilah | Arti |
|---|---|
| **S2TD** | *Statistik-Switch Two-Tier Detection*. Nama algoritme: deteksi dua tahap berbasis statistik flow switch. |
| **`S2TD ...`** | Prefix log dari controller `ddos_guard_s2td.py`. Semua baris berawalan ini ditulis oleh controller, bukan Mininet atau switch. |
| **`dpid=1`** | *Datapath ID*, nomor identitas switch OpenFlow. Topologi fase 1 hanya punya satu switch (`s1`), jadi selalu 1. Pada topologi multi-switch akan muncul `dpid=2`, dan seterusnya. |
| **`Tahap 2`** | Tahap verifikasi per-IP (lebih berat, hanya berjalan saat terpicu). Tahap 1 (ringan) adalah polling statistik yang selalu aktif. |

---

## 2. Baris `POLL` (Tahap 1, diagnostik)

Contoh:

```
S2TD POLL dpid=1 agg=0.0pps mu=0.0
```

| Istilah | Arti |
|---|---|
| **POLL** | Baris diagnostik yang dicetak tiap poll ke-5 (sekitar 5 detik sekali) agar log tidak banjir. Isinya ringkasan kondisi Tahap 1. |
| **agg** (aggregate) | Total laju paket seluruh flow di switch pada interval tersebut (paket/detik), di luar flow DROP. "Agregat" berarti dijumlah dari semua IP, bukan per-IP. |
| **pps** | *packets per second*, satuan laju. `909.9pps` berarti sekitar 910 paket/detik. |
| **mu** (μ) | **Baseline EWMA**, rata-rata bergerak laju trafik normal yang diperbarui `mu = 0,3·agg + 0,7·mu` tiap poll. Fungsinya menjadi "patokan normal": ambang adaptif = `k × mu`. Saat jaringan idle, `mu` meluruh menuju 0. |
| **EWMA** | *Exponentially Weighted Moving Average*, rata-rata yang memberi bobot lebih besar pada sampel terbaru (α = 0,3). |

---

## 3. Baris `TRIGGER` (Tahap 1 memicu Tahap 2)

Contoh:

```
S2TD TRIGGER dpid=1 agg=909.9pps > thr=50.0 (k*mu=3.0*1.0, floor=50) -> Tahap 2
```

| Istilah | Arti |
|---|---|
| **TRIGGER** | Tahap 1 menyimpulkan ada anomali sehingga memicu Tahap 2 untuk memeriksa per-IP. **Trigger bukan ban**; belum ada tindakan apa pun. |
| **thr** (threshold) | Ambang efektif yang dipakai saat itu, yaitu `max(k*mu, floor)`. Nilai inilah yang dicatat di kolom `threshold` pada CSV. |
| **k\*mu = 3.0\*1.0** | Ambang adaptif: `k_auto` (faktor pengali, default 3) dikali `mu` (baseline). Maknanya "3 kali lebih ramai dari biasanya". |
| **k_auto** | Parameter `S2TD_K_AUTO`, default 3,0. |
| **floor=50** | Lantai absolut ambang (perbaikan Tahap A). Mencegah ambang jatuh mendekati 0 saat `mu` ≈ 0. Default sama dengan `T_verify` (50 pps). Dapat diubah via `S2TD_TRIGGER_FLOOR`. |
| **`>`** | Syarat trigger: `agg` harus lebih besar dari `thr`. Pada contoh, 909,9 > 50 sehingga terpicu. |

---

## 4. Baris `VERIFY` (Tahap 2)

Contoh:

```
S2TD VERIFY dpid=1 src=10.0.0.1 rate=455.5pps > T_verify=50 (konsekutif 1/2)
```

| Istilah | Arti |
|---|---|
| **VERIFY** | Hasil pemeriksaan satu kandidat IP di Tahap 2. |
| **src** | *Source IP*, IP pengirim paket yang sedang dievaluasi. |
| **rate** | Laju paket IP tersebut saja (bukan agregat). Sebagai ilustrasi, 455 (attacker) + 454 (victim) ≈ 909 (agg), bukti bahwa agregat adalah penjumlahan per-IP. |
| **T_verify** | Ambang minimal per-IP agar dianggap suspect, default 50 pps (`S2TD_T_VERIFY`). |
| **konsekutif 1/2** | Penghitung "berturut-turut": IP sudah 1 dari 2 interval berturut melewati `T_verify`. Perlu 2/2 (`T_confirm`) sebelum di-ban. Jika satu poll tidak terpicu, penghitung direset (keputusan desain S3). |
| **T_confirm** | Jumlah interval berturut minimum, default 2 (`S2TD_T_CONFIRM`). Inilah yang membedakan lonjakan sesaat dari serangan. |

---

## 5. Baris `MITIGASI`

Contoh:

```
S2TD MITIGASI: DROP rule terpasang utk 10.0.0.1 (hard_timeout=15s)
```

| Istilah | Arti |
|---|---|
| **MITIGASI** | Aksi memasang aturan pemblokiran di switch. |
| **DROP rule** | Flow entry OpenFlow dengan actions kosong sehingga paket yang match dibuang di switch. Prioritas 100, match `ipv4_src=10.0.0.1` (seluruh trafik IPv4 dari IP tersebut). |
| **hard_timeout=15s** | Rule otomatis terhapus setelah 15 detik (tidak permanen). Berfungsi membatasi dampak salah ban dan memulihkan jaringan secara otomatis. |

---

## 6. Baris `SKIP`

Contoh:

```
S2TD SKIP: 10.0.0.5 memenuhi kriteria namun diproteksi (kemungkinan balasan server) -> tidak di-ban
```

| Istilah | Arti |
|---|---|
| **SKIP** | IP memenuhi semua syarat ban (rate > T_verify, 2/2), tetapi sengaja tidak di-ban. |
| **diproteksi** | IP terdaftar di `PROTECTED_IPS` (keputusan desain S6), default `10.0.0.5` (victim). Alasannya, counter flow buta arah sehingga balasan RST victim bisa setinggi laju serangan. |
| **10.0.0.5** | IP victim/server pada topologi fase 1. Pada scale50 (victim `10.0.0.51`) wajib override `S2TD_PROTECTED_IPS`. |

---

## 7. Kolom CSV (`mitigation_events_s2td.csv`)

| Kolom | Arti |
|---|---|
| **`ts_epoch`** | Unix timestamp (detik sejak 1970, UTC), zona waktu netral dan paling aman untuk analisis. |
| **`ts_iso`** | Waktu format ISO-8601 dalam **UTC** (`+00:00`). Jam WIB = UTC + 7. |
| **`event`** | Jenis kejadian: `S2TD_DETECT_DROP` (pada baseline: `DETECT_DROP`). |
| **`dpid`** | Switch tempat rule dipasang, format heksadesimal (`0x1`). |
| **`src_ip`** | IP yang di-ban. |
| **`rate_pps`** | Laju IP tersebut saat keputusan diambil (mis. 457,5 pps). |
| **`window_sec`** | Panjang jendela pengukuran = `T_poll` (1,0 detik). |
| **`threshold`** | Ambang efektif saat deteksi (nilai `thr` di log). Setelah perbaikan Tahap A bernilai 50.0, sebelumnya 0.0 karena memakai `k*mu` mentah. |
| **`action`** | Tindakan yang diambil: `DROP`. |
| **`ban_sec`** | Lama ban = `hard_timeout` (15 detik). |

---

## 8. Istilah konsep yang tersirat di log

| Istilah | Arti singkat |
|---|---|
| **flow stats** | Counter paket per-flow yang dibaca controller melalui multipart request tiap 1 detik. Sumber data S2TD, bukan packet-in. |
| **flow caching / forwarding flow** | S2TD memasang flow forwarding per pasangan IP (src ke dst) agar paket berikutnya tidak lagi dikirim ke controller, tetapi tetap terhitung di counter. Inilah sumber penghematan CPU sekaligus *confounding factor* yang harus diakui dalam pembahasan skripsi. |
| **in-flight packet** | Paket yang sudah "di jalan" saat rule dipasang. Menjelaskan `mu` transien 5,3 dan `agg=468` setengah interval pada log. |
| **agregat vs per-src** | `agg` adalah total semua IP, `rate` adalah satu IP. Rasio keduanya menjelaskan pembagian attacker dan victim. |
| **ban re-arm / loop deteksi-mitigasi** | Setelah `hard_timeout` habis dan serangan masih berlangsung, sistem mendeteksi ulang dan memasang ban lagi. Terbukti dari 4 event CSV berjarak 17 detik (15 detik ban + sekitar 2 detik deteksi). |
| **false positive (FP)** | Trafik legitimate yang salah di-ban. Pada log contoh nilainya 0 karena hanya `10.0.0.1` yang pernah di-ban. |
| **detection time** | Jeda dari awal flood sampai rule DROP terpasang. Pada S2TD sekitar 2 sampai 3 detik (dua poll konfirmasi), sedangkan baseline di bawah 1 detik. Trade-off ini yang diukur pada Tahap C dan D. |

---

## 9. Contoh membaca satu baris secara utuh

Baris:

```
S2TD TRIGGER dpid=1 agg=909.9pps > thr=50.0 (k*mu=3.0*1.0, floor=50) -> Tahap 2
```

Pembacaan:

> "Di switch 1, laju agregat terukur 909,9 paket per detik. Nilai itu melebihi ambang efektif 50 pps. Ambang adaptif seharusnya 3 kali baseline (3 × 1,0 = 3 pps), tetapi lantai 50 pps yang berlaku. Karena terpicu, sistem lanjut ke Tahap 2 untuk memeriksa IP mana yang dominan."

---

## 10. Ringkasan alur anomali dalam log

1. `POLL`: Tahap 1 mengukur agregat tiap detik dan memperbarui baseline EWMA.
2. `TRIGGER`: agregat melewati ambang efektif, Tahap 2 dijalankan.
3. `VERIFY`: kandidat IP diperiksa; perlu dua interval berturut.
4. `MITIGASI`: IP terkonfirmasi dipasang DROP rule 15 detik.
5. `SKIP`: IP terproteksi (victim) tidak pernah di-ban.
6. Setelah 15 detik, bila serangan masih ada, siklus berulang (ban re-arm).
