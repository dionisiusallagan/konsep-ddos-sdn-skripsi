# Automated DDoS Mitigation pada SDN

Proof-of-concept untuk skripsi S1 Teknik Komputer: deteksi dan mitigasi otomatis serangan DDoS bergaya Mirai pada jaringan Software-Defined Networking.

**Catatan**: Menggunakan **os-ken** (fork aktif Ryu, API kompatibel) karena Ryu asli tidak support Python 3.12+. Import pakai `os_ken`, command pakai `osken-manager`.

## Struktur Project

```
ddos-mitigation-sdn/
├── topology/          # Skrip topologi Mininet
├── controller/        # Aplikasi os-ken (detection + mitigation logic)
├── traffic/           # Skrip generator trafik normal & serangan
├── experiments/       # Skrip untuk menjalankan skenario uji & logging metrik
├── results/           # Output log/CSV dari eksperimen
└── README.md
```

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

## Menjalankan Tahap 1 (Topologi Dasar + L2 Switch)

### Terminal 1: Jalankan os-ken Controller

```bash
source ~/ddos-venv/bin/activate
cd /path/to/ddos-mitigation-sdn/controller
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
cd /path/to/ddos-mitigation-sdn/topology
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

## Tahap 1.5: Deteksi & Mitigasi Otomatis (`controller/ddos_guard.py`)

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

### Keputusan Desain (ringkasan — detail & justifikasi di docstring `ddos_guard.py`)

| Parameter | Nilai | Alasan |
|---|---|---|
| Mode forwarding | Tanpa flow caching (semua paket ke controller) | Flow cache membuat flood tak terlihat controller (packet-in = 0); visibilitas penuh = rate akurat |
| Yang dihitung | Hanya paket inisiasi koneksi (TCP SYN murni, semua UDP, ICMP echo request) | Balasan victim (RST/SYN-ACK/ICMP-error) volumenya menyamai serangan; ikut dihitung akan membanned korban |
| Window | Sliding 1 detik per source IP | Tanpa artefak batas bucket fixed-window |
| Threshold | 25 paket/detik per IP | Baseline ping ≈ 4–8/s; serangan ≥ ratusan/s → margin aman dua arah |
| Masa ban | hard_timeout 15 detik | Pemulihan otomatis (batasi dampak false positive); eksperimen bisa diulang tanpa restart |

### Keterbatasan (untuk bab pembahasan)

- Source IP spoofed acak (`--rand-source`): tiap IP hanya muncul sekali → rate per-IP rendah. Perlu agregasi per subnet/port-switch (future work).
- Baru satu switch; multi-switch butuh registry datapath.
- Mode tanpa flow caching tidak skala untuk produksi (bobot CPU controller).

## Langkah Selanjutnya

1. ~~Topologi dasar + L2 switch~~ ✅
2. ~~Deteksi packet-in rate + auto-DROP + logging CSV~~ ✅
3. **Traffic generator lengkap** (trafik normal terjadwal + skenario UDP flood)
4. **Skrip eksperimen**: baseline / serangan tunggal / serangan campuran → CSV metrik (waktu deteksi, jumlah drop rule, CPU proses controller via psutil)

---

**Catatan**: File di folder ini dikembangkan di Windows (untuk editing), tapi **dijalankan di Ubuntu**. Pastikan path di perintah `cd` di atas disesuaikan dengan lokasi folder project di Ubuntu.