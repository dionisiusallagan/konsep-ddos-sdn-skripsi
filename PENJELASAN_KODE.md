# PENJELASAN KODE PER BARIS — Automated DDoS Mitigation pada SDN

Dokumen pendamping skripsi: menjelaskan **setiap baris fungsional** di seluruh
file kode project, terbagi dua fase:

- **BAGIAN I — Fase 1 (5 host)**: topologi dasar + controller deteksi/mitigasi
  + generator serangan + runner eksperimen (5 file).
- **BAGIAN II — Fase scale50 (51 host)**: topologi 50 IoT + victim dan runner
  adaptasinya. File yang merupakan **salinan identik** dari Fase 1 tidak
  dijelaskan ulang per baris — cukup dirujuk; yang dibedah hanya perbedaannya.

Baris berupa docstring/komentar dikelompokkan menjadi satu entri (isinya sendiri
sudah merupakan dokumentasi).

**Cara konversi ke PDF (pilih salah satu):**
1. VS Code → buka file ini → `Ctrl+Shift+P` → "Markdown: Open Preview to the Side" → print preview ke PDF, atau ekstensi "Markdown PDF" (klik kanan file → Export to PDF).
2. Terminal: `pandoc PENJELASAN_KODE.md -o PENJELASAN_KODE.pdf` (install dulu: `winget install JohnMacFarlane.Pandoc`).

---

# BAGIAN I — FASE 1: TOPOLOGI 5 HOST

## 1. `topology/basic_topo.py` (74 baris) — Definisi jaringan simulasi

| Baris | Kode | Penjelasan |
|---|---|---|
| 1 | `#!/usr/bin/env python3` | Shebang: file ini executable dengan Python 3 (konvensi Unix/WSL). |
| 2–11 | `"""Topologi Mininet dasar..."""` | Docstring: deskripsi file, struktur jaringan (1 controller remote, 1 switch OF1.3, 5 host), identitas penulis. |
| 13 | `from mininet.topo import Topo` | Kelas dasar untuk mendefinisikan topologi custom. |
| 14 | `from mininet.net import Mininet` | Kelas utama yang menyatukan host, switch, link, controller menjadi satu jaringan. |
| 15 | `from mininet.node import RemoteController, OVSSwitch` | `RemoteController` = controller eksternal (os-ken kita); `OVSSwitch` = Open vSwitch (bukan switch Linux legacy). |
| 16 | `from mininet.link import TCLink` | Link dengan parameter trafik (bandwidth, delay, loss). |
| 17 | `from mininet.cli import CLI` | CLI interaktif Mininet (`mininet>`). |
| 18 | `from mininet.log import setLogLevel, info` | Kontrol verbosity log Mininet. |
| 21 | `class DDosTopo(Topo):` | Kelas topologi custom; mewarisi `Topo`. |
| 24 | `def build(self):` | Method yang dipanggil Mininet untuk membangun topologi. |
| 26 | `s1 = self.addSwitch('s1', protocols='OpenFlow13')` | Tambah switch `s1`; **`protocols='OpenFlow13'` wajib** agar OVS bicara OF1.3 ke controller kita (default OVS bisa 1.0). |
| 30–33 | `hosts = []` / `for i in range(1, 6):` / `h = self.addHost(f'h{i}', ip=f'10.0.0.{i}/24')` / `hosts.append(h)` | Buat 5 host h1–h5, masing-masing IP statis `10.0.0.1`–`10.0.0.5` subnet /24. h1–h4 = peran IoT (calon attacker), h5 = victim. |
| 36–37 | `for h in hosts:` / `self.addLink(h, s1, bw=100, delay='1ms', loss=0)` | Sambungkan setiap host ke switch: bandwidth 100 Mbps, delay 1 ms, loss 0% (profil LAN sehat). |
| 40–41 | `def run_topo():` | Fungsi pembungkus eksekusi jaringan (hanya dipakai saat file dijalankan langsung). |
| 42 | `setLogLevel('info')` | Tampilkan log informatif Mininet di konsol. |
| 44 | `info('*** Membuat jaringan...')` | Pesan progres di layar. |
| 46–53 | `net = Mininet(topo=..., controller=lambda name: RemoteController(...), switch=OVSSwitch, link=TCLink, autoSetMacs=True, autoStaticArp=True)` | Inti pembuatan jaringan: pakai topologi kita; controller remote di `127.0.0.1:6633` (port default os-ken/Ryu); switch OVS; link berparameter. `autoSetMacs=True` → MAC unik per host; `autoStaticArp=True` → entri ARP statis (menghilangkan noise ARP broadcast dari pengukuran). |
| 56 | `net.start()` | Nyalakan semuanya (namespace, interface, OVS, koneksi ke controller). |
| 60–61 | `import time` / `time.sleep(3)` | Beri waktu 3 detik agar handshake OpenFlow switch↔controller tuntas sebelum tes. |
| 64 | `net.pingAll()` | Tes konektivitas: semua host saling ping; harapkan 0% loss. |
| 67 | `CLI(net)` | Masuk CLI interaktif (`mininet>`) untuk tes manual. |
| 70 | `net.stop()` | Matikan jaringan & bersihkan (dipanggil setelah `exit` dari CLI). |
| 73–74 | `if __name__ == '__main__':` / `run_topo()` | Idiom Python: hanya eksekusi `run_topo()` jika file dijalankan langsung (bukan saat diimport runner eksperimen). |

---

## 2. `controller/l2_switch.py` (109 baris) — Baseline: L2 learning switch

File ini **tanpa** logika keamanan; fungsinya membuktikan infrastruktur dasar
berfungsi sebelum logika deteksi ditambahkan (tahap validasi awal skripsi).

| Baris | Kode | Penjelasan |
|---|---|---|
| 13–18 | `from os_ken...` | Import framework os-ken: `app_manager` (kelas aplikasi), `ofp_event` (event OpenFlow), handler/decorator, definisi OF1.3, parser paket. |
| 21 | `class L2Switch(app_manager.OSKenApp):` | Aplikasi controller; `OSKenApp` = kelas dasar semua app os-ken (padanan `RyuApp`). |
| 22 | `OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]` | Deklarasi: app ini hanya menerima switch OpenFlow 1.3. |
| 24–27 | `__init__` / `super().__init__` / `self.mac_to_port = {}` | Inisialisasi; `mac_to_port` = tabel learning `{id_switch: {mac: port}}`. |
| 29–30 | `@set_ev_cls(EventOFPSwitchFeatures, CONFIG_DISPATCHER)` | Decorator: daftarkan method berikut sebagai handler event `SwitchFeatures` — dipanggil tepat setelah handshake awal switch↔controller. |
| 32–34 | `datapath = ev.msg.datapath` dst. | `datapath` = representasi switch; `ofproto` = konstanta protokol; `parser` = pembuat pesan OpenFlow. |
| 37 | `match = parser.OFPMatch()` | Match **kosong** = cocok dengan SEMUA paket (table-miss). |
| 38–39 | `actions = [OFPActionOutput(OFPP_CONTROLLER, OFPCML_NO_BUFFER)]` | Aksi: kirim paket ke controller; `NO_BUFFER` = kirim utuh (switch tidak menyimpan salinannya). |
| 40 | `self.add_flow(datapath, 0, match, actions)` | Pasang sebagai flow prioritas 0 (terendah) — hanya dijalankan jika tidak ada rule lain yang cocok. |
| 41 | `self.logger.info(...)` | Bukti di log bahwa switch tersambung. |
| 43–48 | `def add_flow(...)` / `inst = [OFPInstructionActions(APPLY_ACTIONS, actions)]` | Helper pemasangan flow: bungkus daftar aksi menjadi *instruction* APPLY-ACTIONS sesuai format OF1.3. |
| 50–57 | `if buffer_id: ... else: ...` / `datapath.send_msg(mod)` | Jika switch masih menyimpan paket di buffer (ada `buffer_id`), FlowMod ikut merujuknya (paket langsung diproses sesuai rule baru tanpa kirim ulang); jika tidak, FlowMod biasa. `send_msg` = kirim pesan ke switch. |
| 59–66 | `@set_ev_cls(EventOFPPacketIn, MAIN_DISPATCHER)` dst. | Handler paket yang tiba di controller. `in_port` = port masuk paket di switch. |
| 68–69 | `pkt = packet.Packet(msg.data)` / `eth = pkt.get_protocol(ethernet.ethernet)` | Parse bytes mentah menjadi objek berlapis; ambil header Ethernet. |
| 72–76 | `if eth.ethertype == ETH_TYPE_LLDP: return` dst. | Abaikan paket discovery LLDP; IPv6 dibiarkan lewat tanpa diproses khusus. |
| 78–82 | `dpid = datapath.id` / `setdefault` / `self.mac_to_port[dpid][eth.src] = in_port` | **Learning**: catat "MAC sumber berada di port ini". |
| 86–89 | `if eth.dst in ...: out_port = ... else: OFPP_FLOOD` | **Forwarding**: jika MAC tujuan sudah dipelajari → kirim ke portnya; jika belum → flood ke semua port. |
| 91 | `actions = [OFPActionOutput(out_port)]` | Aksi keluar sesuai keputusan di atas. |
| 94–101 | `if out_port != FLOOD:` / `match = OFPMatch(in_port, eth_dst, eth_src)` / `add_flow(priority=1)` | Hanya untuk trafik unicast: pasang rule prioritas 1 (di atas table-miss) agar paket sejenis berikutnya **tidak** perlu ke controller lagi (efisiensi). Dua cabang = dengan/tanpa `buffer_id`. |
| 104–109 | `data = ...` / `out = OFPPacketOut(...)` / `send_msg(out)` | **Packet-out**: kirim paket yang sedang ditangani sesuai aksi, apapun keputusan flow. |

---

## 3. `controller/ddos_guard.py` (341 baris) — INTI: deteksi + mitigasi

### 3a. Docstring & import (baris 1–91)

| Baris | Kode | Penjelasan |
|---|---|---|
| 2–64 | `"""DDoS Guard - ..."""` | Dokumentasi arsitektur + **keputusan desain D1–D5** (dasar bab metodologi): D1 tanpa flow caching; D2 hanya paket inisiasi dihitung; D3 sliding window; D4 alasan threshold 25; D5 hard_timeout 15 s; + keterbatasan. |
| 66–70 | `import csv, os, time; from collections import defaultdict, deque; from datetime import ...` | `csv` = tulis log; `defaultdict/deque` = struktur sliding window; `datetime` = timestamp ISO. |
| 72–79 | `from os_ken...` | Sama seperti l2_switch, plus `hub` (utility green-thread/sleep os-ken) dan parser layer `ipv4, tcp, udp, icmp` untuk deteksi. |
| 82–87 | `WINDOW_SEC=1.0`, `RATE_THRESHOLD=25`, `BAN_DURATION_SEC=15`, `DROP_PRIORITY=100`, `CLEANUP_INTERVAL=30`, `STATS_INTERVAL=5` | **Konstanta tunable** — semua parameter eksperimen di satu tempat, masing-masing merujuk justifikasi D3/D4/D5. |
| 90–91 | `_PROJECT_ROOT = ...` / `MITIGATION_LOG = ...` | Hitung path `results/mitigation_events.csv` relatif terhadap lokasi file (aman dijalankan dari folder mana pun). |

### 3b. Inisialisasi (baris 94–146)

| Baris | Kode | Penjelasan |
|---|---|---|
| 94–97 | `class DDoSGuard(OSKenApp):` / `OFP_VERSIONS = [...]` | Kelas aplikasi controller, versi OF1.3. |
| 100 | `super().__init__(...)` | Inisialisasi framework. |
| 104 | `self.mac_to_port = {}` | Tabel learning MAC (untuk keputusan forwarding). |
| 108 | `self.rate_window = defaultdict(deque)` | Sliding window per IP: otomatis buat `deque` kosong untuk IP baru. |
| 111 | `self.banned_until = {}` | `{ip: timestamp_kadaluarsa_ban}` — mencegah pasang rule ganda saat ban aktif. |
| 113 | `self._last_cleanup = time.monotonic()` | Penanda terakhir kali bersih-bersih memori. (`monotonic` = jam yang tidak melompat, aman untuk selisih waktu.) |
| 120 | `self._pkt_in_count = 0` | Penghitung packet-in untuk log diagnostik berkala. |
| 123–129 | `os.makedirs(...)` / `if not os.path.exists(...)` / `csv.writer(f).writerow([...])` | Pastikan folder `results/` ada; buat file CSV + **header** hanya jika belum ada (data run sebelumnya tidak tertimpa). |
| 131–133 | `self.logger.info('DDoSGuard aktif ...')` | Banner konfigurasi efektif di log — bukti versi parameter yang dipakai. |
| 139 | `hub.spawn(self._stats_loop)` | Jalankan green-thread statistik. Sengaja baris **terakhir** `__init__` (pelajaran bug dead-code). |
| 141–146 | `def _stats_loop(self):` / `while True:` / `hub.sleep(STATS_INTERVAL)` / `self._log_stats()` | Loop tak berujung: tiap 5 detik panggil `_log_stats()`. `hub.sleep` = versi sleep yang ramah eventlet (tidak memblokir event loop). |

### 3c. Setup switch (barus 151–171)

| Baris | Kode | Penjelasan |
|---|---|---|
| 151–152 | `@set_ev_cls(EventOFPSwitchFeatures, CONFIG_DISPATCHER)` / `def switch_features_handler(self, ev):` | Handler saat switch baru terhubung. |
| 159–161 | `dp = ev.msg.datapath` dst. | Ambil objek switch/protokol/parser. |
| 163–167 | `match = OFPMatch()` / `actions = [OFPActionOutput(OFPP_CONTROLLER, OFPCML_NO_BUFFER)]` / `inst = [...]` | **Table-miss**: cocok semua paket → kirim ke controller utuh. INI satu-satunya flow untuk trafik normal (D1) — inilah yang membuat semua paket terlihat controller. |
| 168–171 | `mod = OFPFlowMod(priority=0, ...)` / `dp.send_msg(mod)` / `logger.info(...)` | Pasang rule prioritas 0 + log konfirmasi. |

### 3d. Helper deteksi (baris 176–242)

| Baris | Kode | Penjelasan |
|---|---|---|
| 176–177 | `@staticmethod` / `def _initiation_source(pkt):` | Fungsi murni: dari satu paket, kembalikan IP sumber **hanya jika** ini paket inisiasi koneksi (D2). |
| 182–184 | `ip4 = pkt.get_protocol(ipv4.ipv4)` / `if ip4 is None: return None` | Bukan IPv4 (ARP/LLDP/IPv6) → tidak dihitung. |
| 186–191 | `tcppkt = ...` / `if (bits & (TCP_SYN | TCP_ACK)) == TCP_SYN: return ip4.src` / `return None` | TCP: hitung hanya **SYN murni** (SYN=1, ACK=0) = permintaan koneksi baru. SYN-ACK/RST/ACK/FIN (balasan korban) diabaikan. |
| 193–195 | `udppkt = ...` / `return ip4.src` | UDP: semua datagram dihitung (tidak ada flag; aman karena balasan korban berupa ICMP, bukan UDP). |
| 197–203 | `icmppkt = ...` / `if type == ICMP_ECHO_REQUEST: return src` / `return None` / `return None` | ICMP: hanya echo-request dihitung (bukan reply); protokol lain diabaikan. |
| 205–213 | `def _update_rate(self, src_ip, now):` / `dq = self.rate_window[src_ip]` / `dq.append(now)` / `cutoff = now - WINDOW_SEC` / `while dq and dq[0] < cutoff: dq.popleft()` / `return len(dq)` | **Sliding window (D3)**: catat timestamp, buang semua entri lebih tua dari 1 detik dari ujung depan deque, kembalikan jumlah entri tersisa = rate dalam window. Kompleksitas amortized O(1) per paket. |
| 215–225 | `def _cleanup_state(self, now):` / `if now - self._last_cleanup < CLEANUP_INTERVAL: return` / `stale = [...]` / `del self.rate_window[ip]` / `self.banned_until = {...}` | Hemat memori: tiap 30 detik, buang window IP yang sudah >30 dtk tidak aktif dan ban yang sudah kedaluwarsa. |
| 227–242 | `def _log_stats(self):` / `tops = sorted(...)[:3]` / `self.logger.info('STATS: ...')` / `self._pkt_in_count = 0` | Diagnostik tiap 5 detik: total packet-in per interval, jumlah IP aktif, 3 IP dengan window terbesar. Interpretasinya terdokumentasi di docstring (membedakan "controller kewalahan" vs "controller tidak tersambung"). Counter di-reset tiap log. |

### 3e. Mitigasi (baris 247–286)

| Baris | Kode | Penjelasan |
|---|---|---|
| 247–254 | `def _install_drop(self, datapath, src_ip):` + docstring | Inti mitigasi: pasang rule DROP untuk satu IP. |
| 258–265 | komentar trade-off / `match = parser.OFPMatch(eth_type=ETH_TYPE_IP, ipv4_src=src_ip)` | Match **sengaja luas**: SEMUA trafik IPv4 dari IP tersebut (protokol/port apa pun) → konsisten dengan "isolasi IP attacker". Trade-off (false positive memutus seluruh service IP tsb; spoofing IP korban) dimitigasi oleh hard_timeout. |
| 266–273 | `mod = parser.OFPFlowMod(priority=DROP_PRIORITY, match=match, instructions=[], hard_timeout=int(BAN_DURATION_SEC))` / `datapath.send_msg(mod)` | `instructions=[]` = **tanpa aksi = DROP**; `hard_timeout=15` = switch menghapus rule sendiri setelah 15 dtk (D5); prioritas 100 > table-miss. |
| 274–275 | `self.logger.warning('MITIGASI: ...')` | Log kejadian mitigasi (level warning agar menonjol). |
| 277–286 | `def _log_event(...)` / `now = time.time()` / `with open(MITIGATION_LOG, 'a')` / `csv.writer(f).writerow([...])` | Append satu baris ke CSV: epoch, ISO-UTC, event `DETECT_DROP`, dpid (hex), IP, rate saat deteksi, window, threshold, aksi, durasi ban. Mode `'a'` = histori lintas run terjaga. |

### 3f. Handler utama (baris 291–341) — alur setiap paket

| Baris | Kode | Penjelasan |
|---|---|---|
| 291–294 | `@set_ev_cls(EventOFPPacketIn, MAIN_DISPATCHER)` / `def packet_in_handler(self, ev):` / `self._pkt_in_count += 1` | Handler semua paket dari switch; counter diagnostik bertambah. |
| 295–299 | `msg = ev.msg` dst. | Ekstrak datapath, konstanta protokol, parser, port masuk. |
| 301–304 | `pkt = packet.Packet(msg.data)` / `eth = ...` / `if eth is None or LLDP: return` | Parse header Ethernet; buang paket tak valid/LLDP. |
| 306–307 | `dpid = ...` / `setdefault` | Siapkan tabel learning untuk switch ini. |
| 310–311 | `self.mac_to_port[dpid][eth.src] = in_port` / `out_port = self.mac_to_port[dpid].get(eth.dst, OFPP_FLOOD)` | Learning + keputusan keluar (unicast jika tujuan dikenal, else flood). |
| 313–319 | `actions = [...]` / `data = msg.data if buffer_id == NO_BUFFER else None` / `out = OFPPacketOut(...)` / `send_msg(out)` | **Forward via packet-out** (bukan FlowMod — D1). Jika switch tidak men-buffer, ikutkan isi paket. |
| 322–323 | `now = time.monotonic()` / `self._cleanup_state(now)` | Jam monotonic untuk deteksi; sesekali bersih-bersih memori. |
| 325–327 | `src_ip = self._initiation_source(pkt)` / `if src_ip is None: return` | Deteksi tahap 1: hanya paket inisiasi yang diproses lebih lanjut. |
| 332–333 | `if now < self.banned_until.get(src_ip, 0): return` | IP sedang dibanned → jangan dihitung (paketnya memang sudah dibuang di switch). |
| 335 | `rate = self._update_rate(src_ip, now)` | Deteksi tahap 2: perbarui sliding window, dapatkan rate. |
| 338–341 | `if rate > RATE_THRESHOLD:` / `_install_drop(...)` / `self.banned_until[src_ip] = now + BAN_DURATION_SEC` / `_log_event(...)` | **Mitigasi**: rate melewati ambang → pasang DROP, catat masa ban (cegah rule ganda), tulis CSV. |

---

## 4. `traffic/flood_scapy.py` (86 baris) — Generator serangan

| Baris | Kode | Penjelasan |
|---|---|---|
| 20–25 | `import argparse, random, socket, time` / `from scapy.all import IP, TCP, UDP, conf` | Argumen CLI; random source port; raw socket; pengukuran waktu; Scapy **hanya untuk merender** bytes paket. |
| 28–37 | `def render_packet(proto, target, port):` / `pkt = IP(dst=target) / TCP(sport=random.randint(1024,65535), dport=port, flags='S')` / `... UDP ...` / `return bytes(pkt)` | Rakit paket inisiasi: TCP = SYN murni dengan source port acak; atau UDP. Operator `/` = enkapsulasi Scapy. `bytes()` = render sekali menjadi bytes mentah (agar loop kirim nanti super cepat). |
| 41–49 | `ap = argparse.ArgumentParser(...)` dst. | Argumen: `--target` (wajib), `--proto tcp/udp`, `--port`, `--duration`, `--rate` (0 = maksimal). |
| 51 | `conf.verb = 0` | Matikan output verbose Scapy. |
| 54–55 | `sock = socket.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)` / `sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)` | Raw socket: kita menyediakan header IP sendiri (`IP_HDRINCL`). Butuh root — di host Mininet sudah root. Alasan bukan `send()`: terlalu lambat (~20 pps di WSL2). |
| 57–58 | `payload = render_packet(...)` / `delay = 1.0/args.rate if args.rate > 0 else 0` | Render bytes pertama; hitung jeda antar paket jika rate dibatasi. |
| 60–62 | `sent = 0` / `t_start = time.time()` / `deadline = t_start + args.duration` | Penghitung + batas waktu serangan. |
| 65–68 | `while True:` / `now = time.time()` / `if now >= deadline: break` | Loop utama selama durasi. |
| 70–71 | `if sent % 256 == 0: payload = render_packet(...)` | Tiap 256 paket, render ulang dengan source port baru → tiap batch tampak sebagai "koneksi baru" (pola Mirai) dengan biaya rendah. |
| 72–75 | `sock.sendto(payload, (target, port))` / `sent += 1` / `if delay: time.sleep(delay)` | Kirim bytes (inilah sumber ~170rb pps), hitung, tidur jika mode rate terbatas. |
| 76–77 | `except KeyboardInterrupt: pass` | Bisa dihentikan manual dengan Ctrl+C. |
| 79–82 | `elapsed = ...` / `print(f'[flood] ... terkirim={sent} ... pps')` | Laporan: total paket, durasi, rate aktual — bukti intensitas serangan. |
| 85–86 | `if __name__ == '__main__': main()` | Entry point standar. |

---

## 5. `experiments/run_experiment.py` (423 baris) — Runner eksperimen

### 5a. Import, path, konstanta (baris 44–74)

| Baris | Kode | Penjelasan |
|---|---|---|
| 44–53 | `import argparse, csv, os, re, socket, subprocess, sys, threading, time, datetime` | Argumen CLI; CSV; path; regex (parse ping); cek port; jalankan proses lain; path interpreter; **threading** (sampler & tail berjalan paralel); waktu; timestamp. |
| 55 | `import psutil` | Monitoring CPU/memori proses controller. |
| 58–60 | `EXPERIMENT_DIR/PROJECT_ROOT = ...` / `sys.path.insert(0, .../topology)` | Temukan root project; daftarkan folder topology agar `basic_topo` bisa diimport. |
| 62–67 | `from basic_topo import DDosTopo` dst. | Pakai topologi yang SAMA dengan tes manual; Mininet dll. |
| 69–70 | `RESULTS_DIR = ...` / `MITIGATION_CSV = ...` | Lokasi output. |
| 72–74 | `ATTACKER_IP='10.0.0.1'` / `VICTIM_IP='10.0.0.5'` / `LEGIT_HOSTS=['h2','h3','h4']` | Peran host, konsisten dengan topologi. |

### 5b. Utilitas (baris 80–132)

| Baris | Kode | Penjelasan |
|---|---|---|
| 80–89 | `def wait_port(port, timeout=30):` / `while ...:` / `socket.create_connection(...)` / `return True` / `except OSError: sleep(0.3)` / `return False` | Tunggu sampai controller benar-benar listen (coba koneksi TCP tiap 0,3 s, timeout total 30 s). |
| 92–95 | `_ovs_lock = threading.Lock()` | Lock karena **dua thread** (sampler + loop deteksi) sama-sama memanggil `s1.cmd()`; `Node.cmd()` Mininet tidak thread-safe (assert internal meledak jika bersamaan — bug yang pernah terjadi). |
| 98–102 | `def count_drop_rules(s1):` / `with _ovs_lock:` / `out = s1.cmd('ovs-ofctl -O OpenFlow13 dump-flows s1')` / `return out.count('priority=100')` | Dump flow table switch (dalam lock), hitung berapa rule DROP aktif. Inilah sumber "waktu deteksi" & "jumlah rule". |
| 105–110 | `def parse_ping_loss(popen):` / `out, _ = popen.communicate(timeout=30)` / `re.search(r'([\d.]+)% packet loss', text)` / `return ...` | Ambil output `ping` yang selesai, ekstrak angka % loss via regex → metrik FPR. |
| 113–119 | `def count_mitigation_rows():` / `... return len(rows)-1, rows[1:]` | Baca CSV mitigasi; selisih "sebelum vs sesudah" run = event milik run ini saja. |
| 122–132 | `def proc_jiffies(pid):` / `open(f'/proc/{pid}/stat')` / `rsplit(') ', 1)[1].split()` / `return int(remainder[11]) + int(remainder[12])` / `except ...: return None` | Baca total CPU-time proses **langsung dari kernel** (utime+stime, satuan jiffies) — *ground truth* independen psutil untuk memvalidasi pengukuran. `rsplit(') ')` menangani nama proses ber-spasi. |

### 5c. Persiapan lingkungan (baris 138–218)

| Baris | Kode | Penjelasan |
|---|---|---|
| 138–150 | `def cleanup_stale_environment():` / `subprocess.run(['pkill','-f','osken-manager'],...)` / `subprocess.run(['mn','-c'],...)` / `time.sleep(1)` | **Wajib di awal run**: bunuh controller yatim run yang crash + bersihkan sisa Mininet. Tanpa ini, switch bisa diam-diam dilayani controller lama (state basi) dan semua metrik palsu-normal. |
| 153–163 | `def start_controller(log_path):` / `venv_bin = os.path.dirname(sys.executable)` / `osken_mgr = os.path.join(venv_bin, 'osken-manager')` / `if not isfile: sys.exit(...)` | Cari `osken-manager` **relatif terhadap interpreter venv** (bukan `shutil.which`, karena sudo menimpa PATH). |
| 164–168 | `log = open(log_path,'w')` / `proc = subprocess.Popen([osken_mgr, '--ofp-tcp-listen-port','6633','ddos_guard.py'], cwd=..., stdout=log, stderr=STDOUT)` | Jalankan controller sebagai subprocess; semua outputnya dicatat ke file log per-run (bukti untuk skripsi). |
| 169–172 | `if not wait_port(6633): proc.terminate(); sys.exit(...)` | Gagal listen → hentikan dengan pesan jelas. |
| 178–183 | `time.sleep(0.5)` / `if proc.poll() is not None: sys.exit(...)` | **Validasi anti-zombie**: jika proses baru sudah mati padahal port listen, berarti port dipegang proses lain — berhenti, jangan lanjut dengan metrik palsu. |
| 187–197 | `def build_net():` / `Mininet(topo=DDosTopo(), controller=lambda ...)` / `net.start()` / `net.waitConnected(timeout=30)` / `time.sleep(2)` | Bangun jaringan identik dengan tes manual; tunggu semua switch tersambung + 2 detik agar table-miss stabil. |
| 200–218 | `def tail_controller_log(log_path, stop_event):` / `pattern = re.compile(r'STATS:|MITIGASI|...')` / `f.seek(0, 2)` / `while not stop_event.is_set():` / `line = f.readline()` / `print(f'  [ctrl] ...')` / `time.sleep(0.3)` | Live-view: thread yang membaca log controller dan menampilkan baris penting ke konsol dengan prefix `[ctrl]` — user melihat bukti MITIGASI real-time tanpa menjalankan controller manual. `seek(0,2)` = mulai dari akhir file. |

### 5d. Inti eksperimen `run_scenario` (baris 224–400)

| Baris | Kode | Penjelasan |
|---|---|---|
| 225–226 | `ts = datetime.now().strftime(...)` / `os.makedirs(RESULTS_DIR, exist_ok=True)` | Timestamp unik per run + pastikan folder results ada. |
| 228–231 | `cleanup_stale_environment()` | Panggilan pembersihan (lihat 5c). |
| 233–237 | `ctrl_log_path = ...` / `ts_file = ...` / `ctrl_proc, ctrl_log = start_controller(...)` / `cpu_meter = psutil.Process(ctrl_proc.pid)` | Nama file output; jalankan controller; objek pengukur CPU/mem pada pid controller. |
| 240–245 | `tail_stop = threading.Event()` / `tail_thread = Thread(target=tail_controller_log, ...)` / `tail_thread.start()` | Nyalakan live-view. |
| 247–249 | `net = build_net()` / `s1 = net.get('s1')` / `h1 = net.get('h1')` | Bangun jaringan; pegang referensi switch & host penyerang. |
| 251–252 | `rows_before, _ = count_mitigation_rows()` | Pencacah awal CSV → event run ini = selisih. |
| 259–263 | `tsf = open(ts_file,'w')` / `ts_writer.writerow([...])` / `cpu_meter.cpu_percent(interval=None)` | File timeseries + header (`t, cpu, mem, jiffies, drop_rules`); **priming** psutil (pemanggilan pertama selalu 0 — wajib dibuang). |
| 265–268 | `t_start = time.monotonic()` / `detection_time = None` / `max_rules = 0` / `stop_at = t_start + warmup + flood_dur + post` | Jam eksperimen + variabel hasil + batas waktu total. |
| 270–282 | `def sampler():` / `nonlocal max_rules` / `while time.monotonic() < stop_at:` / `rules = count_drop_rules(s1)` / `max_rules = max(...)` / `ts_writer.writerow([...])` / `time.sleep(0.5)` | **Sampler background**: tiap 0,5 s catat CPU/mem/jiffies/jumlah rule. Sebagai thread, ia mencakup fase serangan (versi lama sinkron → cpu_max 0.0 palsu). |
| 284–285 | `sampler_thread = threading.Thread(..., daemon=True)` / `.start()` | Jalankan sampler sejak t=0. |
| 288–297 | `legit_pings = {}` / `if scenario in ('baseline','mixed'):` / `n_pkts = ...` / `legit_pings[hn] = net.get(hn).popen(['ping','-c',...,'-i',...,'-W','1',VICTIM_IP], ...)` | Trafik legitimate: ping terjadwal dari tiap host normal ke victim selama seluruh durasi; output ditampung untuk hitung % loss. |
| 303–306 | `flood_proc = None` / `t_flood = None` / `if scenario in ('single','mixed'):` / `time.sleep(max(0, t_start + warmup - ...))` | Untuk skenario serangan: tidur persis sampai akhir warmup (fase tenang). |
| 307–316 | `py = sys.executable` / `flooder = os.path.join(...)` / `flood_proc = h1.popen([py, flooder, '--target', VICTIM_IP, ...])` | Luncurkan flooder **di dalam namespace h1** memakai interpreter venv (ada scapy); output dibuang (angka pps sudah dicetak flooder sendiri saat manual). |
| 317 | `t_flood = time.monotonic()` | **t0** pengukuran waktu deteksi. |
| 319–325 | `deadline = t_flood + flood_dur + 10` / `while ...:` / `if count_drop_rules(s1) > 0:` / `detection_time = time.monotonic() - t_flood` / `break` / `time.sleep(0.2)` | Polling tiap 0,2 s: begitu rule DROP pertama terlihat → catat selisihnya sebagai waktu deteksi (pengukuran mesin, bebas bias manusia). |
| 327–330 | komentar / `sampler_thread.join(timeout=... + 5)` | Fase observasi: tunggu sampler menyelesaikan seluruh timeline. |
| 335–336 | `if flood_proc and flood_proc.poll() is None: flood_proc.terminate()` | Flooder pasti sudah selesai (durasinya sama); jaga-jaga terminate. |
| 338–341 | `rows_after, new_rows = count_mitigation_rows()` / `events_this_run = new_rows[rows_before:]` / `fp_bans = sum(1 for r ... if r.split(',')[4] != ATTACKER_IP)` | Event mitigasi milik run ini; **fp_bans** = event yang IP-nya bukan attacker (ban salah sasaran). |
| 343–352 | `for hn, p in legit_pings.items():` / `legit_loss[hn] = parse_ping_loss(p)` / `except: p.terminate(); ... nan` | Kumpulkan % loss tiap host legitimate (tunggu selesai normal; fallback paksa). |
| 354–359 | `tsf.close()` / `tail_stop.set()` / `tail_thread.join(2)` / `net.stop()` / `ctrl_proc.terminate()` / `ctrl_log.close()` | Beres-beres: tutup timeseries, hentikan live-view, matikan jaringan & controller (tidak ada proses yatim dari run sukses). |
| 362–365 | `with open(ts_file) as f: samples = ...` / `cpus = [...]` / `mems = [...]` | Baca kembali timeseries untuk statistik ringkas. |
| 367–382 | `summary = { 'ts_iso': ..., 'detection_time_s': ..., 'drops_max_concurrent': ..., 'fp_bans': ..., **{f'{hn}_loss_pct': ...}, 'cpu_avg_pct': ..., ... }` | Susun satu baris ringkasan: semua metrik kunci (deteksi, rule, FPR, CPU/mem). Kolom loss = `nan` untuk `single` (by design, tak ada trafik legit). |
| 384–391 | `write_header = not os.path.exists(summary_file)` / `csv.DictWriter(...)` / `w.writerow(summary)` | Append ke `exp_summary.csv` (header hanya sekali) → akumulasi lintas run. |
| 393–400 | `print('HASIL SKENARIO ...')` / `for k, v in summary.items(): print(...)` / `return summary` | Tampilkan ringkasan rapi di konsol. |
| 403–419 | `def main():` / `ap.add_argument('--scenario', choices=['baseline','single','mixed'], ...)` dst. / `setLogLevel('warning')` / `run_scenario(...)` | Argumen CLI (skenario wajib; durasi-durasi bisa di-tune); log Mininet diredam agar output terbaca. |
| 422–423 | `if __name__ == '__main__': main()` | Entry point. |

---

## Alur besar FASE 1 (ringkasan 1 paragraf)

`run_experiment.py` membersihkan sisa proses → menyalakan `ddos_guard.py` (controller) → membangun topologi Mininet → memulai sampler CPU/rule sebagai thread + live-view log → (baseline/mixed) menyalakan ping legitimate → (single/mixed) meluncurkan SYN flood dari h1 pada detik ke-`warmup` → mencatat saat rule DROP pertama muncul (waktu deteksi) → menunggu fase pemulihan → mengumpulkan semua metrik ke `exp_summary.csv`. Di sisi lain, `ddos_guard.py` melihat setiap paket (table-miss), meneruskannya via packet-out, menghitung paket inisiasi per IP dalam window 1 detik, dan bila melewati 25 pps memasang DROP rule per-IP yang hangus sendiri setelah 15 detik.

---

# BAGIAN II — FASE scale50: TOPOLOGI 51 HOST (50 IoT + VICTIM)

Prinsip fase ini: **logika deteksi & mitigasi identik Fase 1**, yang berubah
hanya skala topologi dan cakupan trafik — sehingga perbandingan beban CPU
controller antar fase valid (apple-to-apple). Struktur folder: `scale50/`
dengan sub-folder `topology/ controller/ traffic/ experiments/ results/`.

## II.1 `scale50/topology/large_topo.py` (83 baris) — Topologi 50 IoT + victim

| Baris | Kode | Penjelasan |
|---|---|---|
| 1 | `#!/usr/bin/env python3` | Shebang standar. |
| 2–20 | `"""Topologi skala besar..."""` | Docstring: perbedaan dengan `basic_topo.py` (51 host, tetap 1 switch agar perbandingan adil), peran host (h1 attacker, h2–h50 IoT, h51 victim), dan catatan bahwa `pingAll` penuh = 2.550 pasangan (~1 menit). |
| 22–27 | `from mininet...` | Import Mininet — identik Fase 1 (Bagian I §1 baris 13–18). |
| 29–30 | `N_IOT = 50` / `VICTIM_ID = N_IOT + 1` | Konstanta skala: jumlah IoT dan ID victim (h51). Mengubah `N_IOT` otomatis mengubah seluruh topologi. |
| 33–34 | `class IoTTopo50(Topo):` | Kelas topologi 51 host. |
| 36–38 | `def build(self):` / `s1 = self.addSwitch('s1', protocols='OpenFlow13')` | Tetap **satu switch** OF1.3 — keputusan desain agar variabel yang diuji murni jumlah node, bukan perubahan arsitektur data-path. |
| 41–44 | `for i in range(1, VICTIM_ID + 1):` / `h = self.addHost(f'h{i}', ip=f'10.0.0.{i}/24')` / `hosts.append(h)` | Buat 51 host sekaligus dalam satu loop: h1–h50 IoT + h51 victim, IP statis 10.0.0.1–10.0.0.51. |
| 47–48 | `for h in hosts:` / `self.addLink(h, s1, bw=100, delay='1ms', loss=0)` | Topologi bintang: semua host langsung ke s1, parameter link sama dengan Fase 1. |
| 51–53 | `def run_topo(quick=False):` / `setLogLevel('info')` | Mode eksekusi dengan opsi `quick` (verifikasi cepat vs pingAll penuh). |
| 55–63 | `net = Mininet(topo=IoTTopo50(), controller=lambda ... 6633, ...)` | Pembentukan jaringan — parameter identik Fase 1. |
| 64–65 | `net.start()` / `net.waitConnected(timeout=120)` | `timeout` dinaikkan ke 120 dtk — 51 host + 51 link butuh waktu build lebih lama. |
| 67–71 | `if quick:` / `for hn in ('h1','h25','h50'):` / `print(net.get(hn).cmd(f'ping -c 1 -W 2 10.0.0.{VICTIM_ID}'))` | **Mode quick**: 3 host sampel ping victim sekali — verifikasi konektivitas dalam hitungan detik sebagai pengganti pingAll penuh. |
| 72–74 | `else:` / `net.pingAll()` | Mode lengkap: ping semua pasangan (bukti menyeluruh, sekali saja). |
| 76–78 | `CLI(net)` / `net.stop()` | CLI interaktif lalu pembersihan. |
| 81–83 | `if __name__ == '__main__':` / `run_topo(quick='--quick' in sys.argv)` | Flag `--quick` dibaca dari argumen baris perintah. |

## II.2 `scale50/controller/ddos_guard50.py` (346 baris) — Salinan identik

| Baris | Kode | Penjelasan |
|---|---|---|
| 3–7 | `"""DDoS Guard ... [FASE scale50] Salinan identik dari controller/ddos_guard.py ..."""` | Satu-satunya perbedaan dengan Fase 1: penanda fase di docstring. **Logika deteksi & mitigasi sengaja tidak diubah** agar perbandingan CPU antar fase adil. |
| 11 s.d. akhir (≈346) | (identik `ddos_guard.py`) | Seluruh isi — konstanta D1–D5, table-miss, `_initiation_source`, sliding window, `_install_drop`, handler utama — **sama persis** dengan Bagian I §3; rujuk penjelasannya di sana. |
| ≈94–95 | `_PROJECT_ROOT = ...` / `MITIGATION_LOG = ...` | Satu perbedaan *perilaku* (bukan kode): karena file ini berada di `scale50/controller/`, path CSV otomatis menunjuk `scale50/results/mitigation_events.csv` — output kedua fase terpisah tanpa mengubah satu baris logika pun. |

## II.3 `scale50/traffic/flood_scapy.py` (86 baris) — Salinan identik

Tidak ada perbedaan apa pun dengan Fase 1 → penjelasan per baris: **Bagian I §4**.

## II.4 `scale50/experiments/run_scale50.py` (382 baris) — Runner adaptasi

### II.4a Docstring, import, konstanta (baris 1–58)

| Baris | Kode | Penjelasan |
|---|---|---|
| 2–24 | `"""Runner Eksperimen FASE scale50..."""` | Daftar perubahan utama vs Fase 1 (topologi, victim h51, `--legit-count`, output terpisah) + tujuan fase: mengukur CPU controller saat skala naik 5×. |
| 26–37 | `import ...` / `import psutil` | Identik Fase 1 (Bagian I §5a). |
| 40–43 | `EXPERIMENT_DIR/SCALE50_ROOT/PROJECT_ROOT = ...` / `sys.path.insert(0, .../scale50/topology)` | Tiga tingkat path: folder runner → `scale50/` → root project; import topologi dari folder scale50. |
| 45 | `from large_topo import IoTTopo50, VICTIM_ID` | Pakai topologi besar + konstanta victim. |
| 52–54 | `RESULTS_DIR = scale50/results` / `MITIGATION_CSV = ...` / `CONTROLLER_APP = 'ddos_guard50.py'` | Semua output & controller mengarah ke folder fase ini. |
| 56–58 | `ATTACKER_IP='10.0.0.1'` / `VICTIM_IP=f'10.0.0.{VICTIM_ID}'` / `DEFAULT_LEGIT_COUNT=10` | Peran host; jumlah host legitimate kini **bisa diatur** (default 10). |

### II.4b Utilitas (baris 64–191) — mayoritas identik Fase 1

| Baris | Kode | Penjelasan |
|---|---|---|
| 64–113 | `wait_port`, `_ovs_lock`, `count_drop_rules`, `parse_ping_loss`, `count_mitigation_rows`, `proc_jiffies` | **Identik** Fase 1 (Bagian I §5b) — rujuk ke sana. |
| 119–127 | `cleanup_stale_environment()` | Identik Fase 1: pkill controller yatim + `mn -c`. |
| 130–153 | `start_controller(log_path)` | Identik Fase 1 (cari osken-manager via `sys.executable`, anti-zombie check), hanya `CONTROLLER_APP` dan `cwd=scale50/controller` yang berbeda. |
| 156–166 | `build_net()` | Sama, tapi `IoTTopo50()` dan `waitConnected(timeout=120)` (51 host lebih lambat). |
| 169–176 | `def quick_connectivity_check(net):` / `for hn in ('h2','h25','h50'):` / `ok = '1 received' in out` / `return ' | '.join(s)` | **BARU**: ping 3 host sampel ke victim (pengganti pingAll 1 menit); hasilnya string status `OK/GAGAL` per host untuk dicetak ke konsol. |
| 179–191 | `tail_controller_log(...)` | Identik Fase 1: live-view `[ctrl]`. |

### II.4c `run_scenario` (baris 197–360)

| Baris | Kode | Penjelasan |
|---|---|---|
| 197–215 | signature + `legit_count` / cleanup / start controller / tail thread | Alur sama Fase 1; parameter baru `legit_count`. |
| 217–222 | `net = build_net()` / `conn = quick_connectivity_check(net)` / `print(f'  [net] konektivitas: {conn}')` | **BARU**: spot-check konektivitas dicetak ke konsol sebelum eksperimen. |
| 224–225 | `legit_hosts = [f'h{i}' for i in range(2, 2 + legit_count)]` | **BARU**: host legitimate dinamis — h2 s.d. h(1+legit_count); attacker (h1) selalu dikecualikan. |
| 227–255 | CSV diff, sampler background thread, priming psutil | Identik Fase 1 (Bagian I §5d baris 251–285). |
| 257–265 | `legit_pings[hn] = net.get(hn).popen(['ping', ...])` | Ping legitimate untuk subset dinamis (Fase 1: selalu h2–h4). |
| 267–286 | peluncuran flood + polling deteksi | Identik Fase 1, kecuali: flooder dari `scale50/traffic/`, dan `deadline = t_flood + flood_dur + 15` — margin polling diperbesar karena 51 host lebih lambat. |
| 288–315 | join sampler, terminate flood, diff CSV mitigasi, kumpulkan loss legit, stop semuanya | Identik Fase 1. |
| 317–324 | baca timeseries / `loss_vals = [v for v in legit_loss.values() if v == v]` / `loss_avg = ...` | **BARU**: hitung **rata-rata** loss legit (nilai NaN difilter — `v == v` adalah cara idiomatis cek bukan-NaN) → satu kolom ringkas `legit_loss_avg_pct`. |
| 326–342 | `summary = {...}` | Kolom ringkasan + **3 kolom baru**: `n_hosts=51`, `n_legit` (0 untuk single), `legit_loss_avg_pct`. |
| 344–360 | append `exp_summary.csv` + cetak ringkasan | Identik Fase 1, judul cetak `"HASIL SKENARIO scale50"`. |
| 363–378 | `main()` + argparse | Identik + argumen baru `--legit-count` (default 10). |
| 381–382 | `if __name__ == '__main__': main()` | Entry point. |

## Alur besar FASE 2

Sama dengan Fase 1, dengan tiga perbedaan: topologi dibangun dari `IoTTopo50`
(51 host, build ±30–60 detik), trafik legitimate berasal dari `--legit-count`
host IoT pertama (default 10 → ±500 packet-in/5 detik latar), dan konektivitas
diverifikasi cepat via 3 ping sampel. Metrik yang sama direkam ke
`scale50/results/exp_summary.csv`, siap dibandingkan langsung dengan
`results/exp_summary.csv` Fase 1 (tabel perbandingannya ada di
`scale50/README.md`).

---

# BAGIAN III — FASE P1: PERBANDINGAN TIGA ALGORITME + LOAD SWEEP

> **Penting soal nomor baris.** BAGIAN I dan BAGIAN II ditulis untuk versi kode
> **sebelum** Tahap C/D. Dua file yang berubah sejak itu adalah
> `experiments/run_experiment.py` (423 → 1.046 baris) dan
> `traffic/flood_scapy.py` (86 → 108 baris); nomor baris di BAGIAN I §4–§5
> **tidak lagi** menunjuk baris yang sama. Perubahan keduanya didokumentasikan
> ulang di §III.3 dan §III.4 di bawah. `controller/ddos_guard.py`,
> `controller/l2_switch.py`, topologi, dan `scale50/` **tidak diubah**, sehingga
> BAGIAN I §1–§3 dan seluruh BAGIAN II tetap valid.

Bagian ini membedah lima file inti P1:

| § | File | Baris | Peran |
|---|---|---|---|
| III.1 | `controller/ddos_guard_s2td.py` | 497 | Algoritme B: S2TD dua tahap berbasis statistik flow |
| III.2 | `controller/ddos_guard_entropy.py` | 330 | Algoritme C: Shannon entropy IP sumber |
| III.3 | `traffic/flood_scapy.py` | 108 | Flooder + pacing + penanda `t0_epoch` |
| III.4 | `experiments/run_experiment.py` | 1.046 | Runner + mode `--algo` + metrik compare |
| III.5 | `experiments/run_sweep_compare.py` | 426 | Orkestrator load sweep + agregasi |

---

## III.1 `controller/ddos_guard_s2td.py` (497 baris) — S2TD

### III.1a Docstring & import (baris 1–102)

| Baris | Kode | Penjelasan |
|---|---|---|
| 1–88 | Docstring modul | Menjelaskan arsitektur dua tahap, pemetaan ke pseudocode proposal, perbedaan sengaja vs baseline, delapan keputusan desain **S1–S8**, dan keterbatasan yang diakui. Bahan langsung bab metodologi. |
| 90–102 | `import csv, os, time` / `defaultdict` / `datetime, timezone` / `app_manager`, `ofp_event`, dispatcher / `ofproto_v1_3` / `hub` / `packet, ethernet, ethertypes, ipv4` | `hub` = green-thread os-ken untuk loop polling. Tidak ada `math`/`deque` karena deteksi memakai counter switch, bukan window paket. |

**Delapan keputusan desain (S1–S8) yang tertulis di docstring** — ini yang dikutip di skripsi:

- **S1** — satu `FlowStatsRequest` per `T_poll` memberi data agregat (Tahap 1) sekaligus per-`src` (Tahap 2); tidak ada request tambahan saat terpicu → overhead control-channel konstan 1 msg/detik/switch.
- **S2** — EWMA **dibekukan** saat terpicu; `mu` hanya belajar dari sampel normal, agar serangan tidak menaikkan ambangnya sendiri.
- **S3** — verifikasi "berturut-turut" ketat: poll tak-terpicu me-reset semua counter konsekutif.
- **S4** — flow DROP (`priority=100`) dikeluarkan dari agregat, tetapi `prev_count`-nya tetap diingat agar tidak ada lonjakan delta saat rule kedaluwarsa.
- **S5** — counter reset (flow lahir kembali dengan `cur < prev`) ditangani `delta = cur`.
- **S6** — `PROTECTED_IPS` tidak pernah di-ban: flow counter buta arah, sehingga balasan victim bisa memenuhi kriteria.
- **S7** — CSV terpisah, 10 kolom identik baseline; `threshold` = ambang efektif, `window_sec` = `T_poll`.
- **S8** — ambang pemicu = `max(k_auto*mu, TRIGGER_FLOOR)`; lantai absolut mencegah ambang ~0 saat idle.

### III.1b Konfigurasi (baris 104–133)

| Baris | Kode | Penjelasan |
|---|---|---|
| 107 | `T_POLL = float(env S2TD_T_POLL, 1.0)` | Interval polling statistik (detik). Menentukan resolusi waktu deteksi. |
| 108 | `ALPHA = float(env S2TD_ALPHA, 0.3)` | Bobot EWMA baseline (`mu`). |
| 109 | `K_AUTO = float(env S2TD_K_AUTO, 3.0)` | Pengali ambang adaptif `k*mu`. |
| 110 | `T_VERIFY = float(env S2TD_T_VERIFY, 50)` | Ambang per-sumber (pps) di Tahap 2. **Parameter terkunci P1 = 50 pps.** |
| 113 | `TRIGGER_FLOOR = float(env S2TD_TRIGGER_FLOOR, str(T_VERIFY))` | Lantai ambang pemicu (Tahap A). Default mengikuti `T_verify` agar agresivitas Tahap 1 sejalan dengan gerbang Tahap 2. |
| 114 | `T_CONFIRM = int(env S2TD_T_CONFIRM, 2)` | Jumlah poll berturut yang harus lolos `T_verify` sebelum DROP. |
| 115 | `TOP_N = int(env S2TD_TOP_N, 5)` | Kandidat teratas yang diperiksa tiap poll terpicu. |
| 116 | `WARMUP_POLLS = int(env S2TD_WARMUP_POLLS, 3)` | Jumlah poll awal untuk belajar baseline; tidak ada aksi. |
| 117–118 | `BAN_DURATION_SEC=15` / `DROP_PRIORITY=100` | **Sama persis baseline** agar bentuk mitigasi bukan variabel pembeda. |
| 119 | `FWD_PRIORITY = 1` | Prioritas flow forwarding, di atas table-miss (0). |
| 120–121 | `IDLE_TIMEOUT=10` / `CLEANUP_INTERVAL=30` | Flow forwarding kedaluwarsa 10 s; state basi dibuang tiap 30 s. |
| 125–127 | `PROTECTED_IPS = {...env S2TD_PROTECTED_IPS...}` | Daftar IP yang tak boleh di-ban (default `10.0.0.5`; scale50 → `10.0.0.51`). |
| 130–133 | `MITIGATION_LOG = env S2TD_LOG or results/mitigation_events_s2td.csv` | CSV terpisah, bisa di-override runner. |

### III.1c Inisialisasi (baris 136–184)

| Baris | Kode | Penjelasan |
|---|---|---|
| 136–142 | `class DDoSGuardS2TD(OSKenApp)` / `OFP_VERSIONS` / `super().__init__` | Kelas aplikasi os-ken, OpenFlow 1.3. |
| 145 | `self.mac_to_port = {}` | State L2 learning untuk forwarding. |
| 148 | `self.datapaths = {}` | Registry datapath (multi-switch ready) — diisi `_state_change_handler`. |
| 151–153 | `self._mu=None` / `self._eff_threshold=TRIGGER_FLOOR` / `self._poll_count=0` | State Tahap 1. `_eff_threshold` menyimpan ambang poll terakhir untuk CSV/log. |
| 154 | `self._last_poll_ts = None` | Untuk menghitung `dt` **terukur**, bukan mengasumsikan `T_poll`. |
| 158–162 | `_prev_counts`, `_flow_last_seen`, `_src_consec`, `_protect_flag`, `banned_until` | State Tahap 2: counter mentah per flow, waktu terakhir flow terlihat, hitungan konsekutif per sumber, penanda sudah-warning untuk IP terproteksi, dan waktu kedaluwarsa ban. |
| 164 | `self._last_cleanup = time.monotonic()` | Jadwal housekeeping. |
| 166–172 | buat folder + tulis header CSV bila belum ada | Skema 10 kolom identik baseline: `ts_epoch,ts_iso,event,dpid,src_ip,rate_pps,window_sec,threshold,action,ban_sec`. |
| 174–180 | `self.logger.info('S2TD aktif | ...')` | Mencetak **nilai konfigurasi aktual** (bukti eksperimen bahwa env yang dipakai benar). |
| 184 | `hub.spawn(self._poll_loop)` | **Spawn paling akhir**: tidak boleh ada kode `__init__` setelah loop tak berujung (pelajaran dead-code dari baseline). |

### III.1d Tahap 1 paruh 1 — loop polling (baris 186–209)

| Baris | Kode | Penjelasan |
|---|---|---|
| 189–195 | `def _poll_loop(self):` / docstring | Loop manual `while True` + `hub.sleep(T_POLL)`, bukan `spawn_periodic`, agar kompatibel antar versi os-ken. |
| 197–198 | `hub.sleep(T_POLL)` / `for dpid, dp in list(self.datapaths.items())` | Satu request **per switch** tiap interval; salinan list agar aman bila registry berubah. |
| 200–206 | `OFPFlowStatsRequest(dp, 0, OFPTT_ALL, OFPP_ANY, OFPG_ANY)` | `table_id=ALL` **eksplisit**: satu balasan mencakup table-miss + forwarding + drop, sehingga agregat = total switch. |
| 208–209 | `except Exception as e: logger.debug(...)` | Switch mati di tengah poll tidak boleh mematikan loop. |

### III.1e Registry switch & table-miss (baris 211–253)

| Baris | Kode | Penjelasan |
|---|---|---|
| 214–233 | `_state_change_handler` + `EventOFPStateChange` | `MAIN_DISPATCHER` → daftarkan `dp`; `DEAD_DISPATCHER` → hapus. Baseline hanya mengenal satu switch; di sini sudah siap multi-switch. |
| 235–253 | `switch_features_handler` | Pasang table-miss `priority=0` → controller, identik baseline. Bedanya konsekuensi: paket berikutnya dari pasangan IP yang sama akan match flow forwarding (`FWD_PRIORITY`) dan **tidak** packet-in lagi. |

### III.1f Forwarding + flow install (baris 255–310)

| Baris | Kode | Penjelasan |
|---|---|---|
| 258–263 | `packet_in_handler` + docstring | **Sengaja tanpa logika deteksi**: hot-path harus semurah mungkin; deteksi pindah ke reply stats 1/detik. |
| 264–278 | `msg`, `dp`, `in_port`, parse Ethernet, abaikan LLDP, update `mac_to_port`, tentukan `out_port` | Pola L2 learning standar. |
| 281–286 | `ip4 = pkt.get_protocol(ipv4.ipv4)` / `if ip4 and out_port != OFPP_FLOOD:` | Flow **hanya** untuk IPv4 unicast yang port keluarnya sudah diketahui. ARP/broadcast/flood tidak di-cache agar tabel tidak penuh sampah satu-paket. |
| 287–295 | `OFPMatch(eth_type=IP, ipv4_src, ipv4_dst)` / `OFPFlowMod(priority=FWD_PRIORITY, idle_timeout=IDLE_TIMEOUT, buffer_id=...)` | Match per **pasangan IP** — inilah sumber counter yang dipoll Tahap 2. `idle_timeout` mencegah flow abadi. |
| 298–299 | `if msg.buffer_id != OFP_NO_BUFFER: return` | Paket ter-buffer diteruskan switch **melalui flow baru** (masuk counter); tak perlu packet-out terpisah. |
| 301–304 | `OFPPacketOut(...)` | Fallback untuk paket tanpa buffer / non-IPv4. |
| 309–310 | `packet_in_handler = set_ev_cls(EventOFPPacketIn, MAIN_DISPATCHER)(packet_in_handler)` | Pendaftaran handler dipisah dari definisi agar blok Tahap 2 mudah ditemukan saat sidang; fungsional identik decorator. |

### III.1g Tahap 1 paruh 2 + Tahap 2 (baris 312–445)

| Baris | Kode | Penjelasan |
|---|---|---|
| 315–326 | `_match_field(match, field)` | Ambil field `OFPMatch` dengan `try/except` (bukan `.get`) karena perilaku akses berbeda antar versi parser. |
| 328–336 | `flow_stats_reply_handler` + docstring | Satu balasan stats memicu Tahap 1 lalu (bila terpicu) Tahap 2. `dt` diukur monotonic agar rate akurat walau green thread bergeser. |
| 337–345 | `dp/dpid/now_mono` / `dt` / `_last_poll_ts` / `_poll_count += 1` / `_cleanup_state` | Bila `dt <= 0` dipakai `T_poll` sebagai pengaman. Housekeeping dijalankan tiap reply. |
| 347–353 | `agg_delta=0` / `src_delta=defaultdict` / loop `stat in ev.msg.body` / `key=(dpid,priority,src,dst)` / `cur=packet_count` | Menyiapkan agregat dan delta per sumber. |
| 355–361 | `delta = (cur-prev) if (prev is not None and cur >= prev) else cur` / simpan `_prev_counts` & `_flow_last_seen` | **S5**: flow baru / counter reset → `delta=cur`. |
| 362–363 | `if stat.priority == DROP_PRIORITY: continue` | **S4**: trafik yang sudah dimitigasi tidak dihitung, tetapi counter-nya tetap diingat. |
| 364–368 | `agg_delta += delta` / `if src: src_delta[src] += delta` | Flow tanpa `ipv4_src` (table-miss) hanya masuk agregat. |
| 368 | `agg_rate = agg_delta / dt` | Rate agregat switch (pps). |
| 376–378 | `triggered=False` / `if self._mu is None: self._mu = agg_rate` | Poll pertama hanya menginisialisasi baseline; tidak boleh memicu Tahap 2. Inisialisasi dulu mencegah `UnboundLocalError`. |
| 383–387 | `eff_threshold = max(K_AUTO*mu, TRIGGER_FLOOR)` / `self._eff_threshold = ...` / `if poll_count > WARMUP_POLLS and agg_rate > eff_threshold: triggered = True` | **S8**: lantai absolut menutup celah ambang ~0 saat idle. `_eff_threshold` dipakai CSV & log TRIGGER. |
| 390–391 | `if not triggered: self._mu = ALPHA*agg_rate + (1-ALPHA)*(self._mu or 0.0)` | **S2**: `mu` hanya belajar dari sampel normal. |
| 393–394 | `if self._poll_count <= WARMUP_POLLS: return` | Masa belajar: tidak ada aksi. |
| 395–397 | `if poll_count % 5 == 0: logger.info('S2TD POLL ...')` | Log diagnostik berkala. |
| 398–403 | `if not triggered:` reset semua `_src_consec`, `_protect_flag.clear()`, `return` | **S3**: poll tak-terpicu memutus rantai konfirmasi. |
| 405–408 | `logger.info('S2TD TRIGGER ...')` | Bukti pemicu Tahap 2 beserta komponen ambang. |
| 411 | `ranked = sorted(src_delta.items(), key=lambda kv: -kv[1])[:TOP_N]` | Ambil top-N sumber dengan delta terbesar. |
| 412–420 | `active=set()` / loop `src, pkts` / lewati yang sedang diban / `rate = pkts/dt` / `if rate <= T_VERIFY: reset; continue` | Verifikasi ambang per-sumber; sumber di bawah `T_verify` tidak menambah hitungan. |
| 421–427 | `_src_consec[src] += 1` / log VERIFY / `if n < T_CONFIRM: continue` | Konfirmasi **berturut-turut**; log menampilkan `n/T_confirm`. |
| 429–438 | `if src in PROTECTED_IPS:` warning sekali per siklus, reset counter, `continue` | **S6**: korban/server tidak pernah di-ban; upaya ini hanya di log (tidak mengotori CSV). |
| 439–442 | `_install_drop(dp, src)` / `banned_until[...]` / `_log_event(...)` / reset counter | Mitigasi + pencatatan + mulai masa ban. |
| 443–445 | reset sumber yang tidak lagi aktif | Mencegah hitungan "setengah jalan" bertahan saat sumber keluar dari top-N. |

### III.1h Mitigasi, logging, housekeeping (baris 447–497)

| Baris | Kode | Penjelasan |
|---|---|---|
| 450–465 | `_install_drop(dp, src_ip)` | Match `eth_type=IP, ipv4_src`; `instructions=[]` = DROP; `priority=DROP_PRIORITY`; `hard_timeout=BAN_DURATION_SEC`. **Identik baseline** agar bentuk mitigasi bukan variabel pembeda. |
| 467–482 | `_log_event(dpid, src_ip, rate)` | Tulis 10 kolom: `event='S2TD_DETECT_DROP'`, `rate_pps`, `window_sec=T_POLL`, `threshold=_eff_threshold`, `action='DROP'`, `ban_sec`. Beda isi vs baseline hanya identitas algoritme + ambang efektif. |
| 484–497 | `_cleanup_state(now)` | Tiap `CLEANUP_INTERVAL`: buang `_prev_counts`/`_flow_last_seen` yang basi, hapus `_src_consec` bernilai 0, dan buang entri `banned_until` yang sudah kedaluwarsa → memori datar. |

---

## III.2 `controller/ddos_guard_entropy.py` (330 baris) — Shannon Entropy

### III.2a Docstring, import, konfigurasi (baris 1–99)

| Baris | Kode | Penjelasan |
|---|---|---|
| 1–61 | Docstring modul | Posisi algoritme C, arsitektur yang **disamakan** dengan baseline, lima keputusan desain **E1–E5**, dan keterbatasan. |
| 63–76 | `csv, math, os, time` / `defaultdict, deque` / `datetime, timezone` / import os-ken & `packet, ethernet, ether_types, ipv4, tcp, udp, icmp` | `deque` = sliding window; `math.log2` = entropi. |
| 81 | `ENTROPY_WINDOW = float(env, 1.0)` | Panjang window sliding (detik). |
| 82 | `ENTROPY_THRESHOLD = float(env, 1.0)` | Ambang entropi (bit). Di bawah nilai ini → indikasi serangan. |
| 83 | `ENTROPY_MIN_PKTS = int(env, 30)` | **E3**: minimum sampel; mencegah entropi dihitung dari 2–3 paket. |
| 84 | `EVAL_INTERVAL = 0.5` | **E4**: evaluasi entropi maksimal tiap 0,5 s agar biaya tidak dibayar per paket; window tetap sliding per paket. |
| 85–86 | `BAN_DURATION_SEC=15` / `DROP_PRIORITY=100` | **E5**: identik baseline. |
| 87 | `STATS_INTERVAL = 5` | Interval log diagnostik `H=...`. |
| 91–93 | `PROTECTED_IPS = {...env ENTROPY_PROTECTED_IPS...}` | IP yang tak boleh di-ban (victim). |
| 96–99 | `MITIGATION_LOG = env ENTROPY_LOG or results/mitigation_events_entropy.csv` | CSV terpisah, skema 10 kolom identik. |

### III.2b Inisialisasi & switch setup (baris 102–154)

| Baris | Kode | Penjelasan |
|---|---|---|
| 102–108 | `class EntropyGuard(OSKenApp)` / `OFP_VERSIONS` / `super().__init__` | Aplikasi os-ken OpenFlow 1.3. |
| 111 | `self.mac_to_port = {}` | State L2 learning. |
| 114 | `self.window = deque()` | **Sliding window** `[(monotonic_ts, src_ip), ...]`. |
| 115 | `self.counts = defaultdict(int)` | Jumlah paket per source IP di dalam window. |
| 117–120 | `_last_eval`, `_last_stats`, `_last_protect_log`, `banned_until` | Penjadwalan evaluasi/log + masa ban. |
| 122–128 | buat folder + header CSV bila belum ada | Skema 10 kolom. |
| 130–135 | `logger.info('EntropyGuard aktif | ...')` | Mencetak konfigurasi aktual (bukti eksperimen). |
| 140–154 | `switch_features_handler` | Table-miss `priority=0` → controller, identik baseline. |

### III.2c Deteksi: filter, window, entropi (baris 156–252)

| Baris | Kode | Penjelasan |
|---|---|---|
| 159–186 | `_initiation_source(pkt)` | **E2**: filter paket inisiasi disalin persis dari baseline — TCP SYN murni, semua UDP, ICMP echo request. Balasan victim tidak dihitung agar distribusi sumber tidak terdistorsi. |
| 188–198 | `_update_window(src_ip, now)` | Buang entri lebih tua dari `now - WINDOW` (decrement & hapus key bila 0), tambahkan paket baru, kembalikan `N`. |
| 200–207 | `_shannon_entropy(counts, total)` | `H = -Σ p_i log2(p_i)` dalam bit. |
| 209–252 | `_evaluate(datapath, now, total)` | Inti keputusan: (216–218) batasi tiap `EVAL_INTERVAL`; (219–220) `N < MIN_PKTS` → tidak evaluasi; (222) hitung `H`; (223) `top_ip, top_n`; (227–233) log diagnostik tiap 5 s + bersihkan `banned_until`; (235–236) `H >= THRESHOLD` → distribusi wajar; (239–245) **proteksi victim** — bila sumber dominan adalah IP terproteksi, warning berkala dan tidak ban; (246–247) sedang diban → biarkan kedaluwarsa; (249–252) hitung rate, pasang DROP, catat `banned_until`, tulis CSV. |
| 249 | `rate = top_n / ENTROPY_WINDOW` | Rate informatif; pada window yang baru setengah terisi nilainya bisa ≈0,5× nominal — alasan `detected_rate_pps` tidak sebanding antar algoritme. |

### III.2d Mitigasi, logging, packet-in (baris 254–330)

| Baris | Kode | Penjelasan |
|---|---|---|
| 257–268 | `_install_drop(datapath, src_ip)` | **E5**: match `ipv4_src`, `priority=DROP_PRIORITY`, `instructions=[]`, `hard_timeout=BAN_DURATION_SEC` — identik baseline. |
| 270–287 | `_log_event(dpid, src_ip, rate, entropy)` | Tulis 10 kolom: `event='ENTROPY_DETECT_DROP'`, `threshold=ENTROPY_THRESHOLD` (statis, bit), `window_sec=ENTROPY_WINDOW`. Nilai `H` keputusan hanya di log konsol agar skema CSV tetap identik. |
| 292–330 | `packet_in_handler` | (300–303) parse & abaikan LLDP; (305–310) belajar MAC & tentukan `out_port`; (312–316) **packet-out tanpa FlowMod** (D1: tanpa flow caching); (319–320) ambil `src_ip` hanya untuk paket inisiasi; (326–327) sumber yang sedang diban dilewati (jaring pengaman); (329–330) update window lalu evaluasi. |

---

## III.3 `traffic/flood_scapy.py` (108 baris) — Flooder versi Tahap C/D

Bagian yang **tidak berubah** dari BAGIAN I §4: `render_packet` (28–37), argparse dasar (40–49), raw socket (51–55). Perubahan ada di **pacing** dan **penanda t0**.

| Baris | Kode | Penjelasan |
|---|---|---|
| 1–18 | Docstring | Scapy hanya merender bytes; pengiriman lewat raw socket; source port diganti per 256 paket agar tiap batch terlihat sebagai koneksi baru. |
| 28–37 | `render_packet(proto, target, port)` | TCP = SYN murni; UDP = datagram; `bytes(pkt)` dirender sekali agar loop cepat. |
| 41–49 | argparse | `--target`, `--proto`, `--port`, `--duration`, **`--rate`** (0 = secepat mungkin). |
| 51 | `conf.verb = 0` | Matikan output verbose Scapy. |
| 54–55 | raw socket + `IP_HDRINCL` | Menyediakan header IP sendiri; butuh root (di Mininet sudah root). |
| 57–58 | `payload = render_packet(...)` / `delay = 1/rate if rate>0 else 0` | Payload awal + periode antar paket. |
| 60–62 | `sent=0` / `t_start=time.time()` / `deadline=t_start+duration` | **`t_start` adalah t0 absolut** yang dipakai pacing dan penanda. |
| 64–77 | `print(f'[flood] started ... t0_epoch={t_start:.6f}', flush=True)` | **Penanda mulai** dicetak tepat sebelum paket pertama. `flush=True` wajib agar runner bisa membacanya segera. `t0_epoch` = jam dinding, sehingga runner tidak perlu menebak dari waktu baca berkas. |
| 79–88 | loop `while True` / cek `deadline` / ganti source port tiap 256 paket / `sock.sendto(...)` | Loop kirim murni; `sent` menghitung paket. |
| 89–97 | `if delay:` / `ahead = (t_start + sent*delay) - time.time()` / `if ahead > 0: time.sleep(ahead)` | **Pacing jadwal absolut**: target waktu paket ke-`sent+1` dihitung dari `t_start`, bukan `sleep(1/rate)` per paket. Drift tidak menumpuk; tidur hanya bila masih lebih cepat dari jadwal. |
| 98–99 | `except KeyboardInterrupt: pass` | Hentikan rapi. |
| 101–104 | `elapsed` / `print('[flood] ... terkirim=... (~N pps)')` | Baris ringkasan yang diparse runner menjadi `flood_actual_pps`. |
| 107–108 | entry point | — |

**Implikasi metodologi:** `t0_epoch` + pacing absolut membuat `flood_actual_pps` ≈ `--rate` dan `detection_time` tidak lagi tercemar waktu import Scapy (0,5–1 s di WSL) atau jeda baca berkas.

---

## III.4 `experiments/run_experiment.py` (1.046 baris) — Runner + mode compare

BAGIAN I §5 membedah versi 423 baris. Berikut **hanya bagian yang baru/berubah**; fungsi lama yang tidak berubah tetap dirujuk ke sana.

### III.4a Docstring, import, peta algoritme (baris 1–154)

| Baris | Kode | Penjelasan |
|---|---|---|
| 1–92 | Docstring | Daftar skenario, metrik, output, **mode `--algo`**, dan definisi metrik compare (detection_time jam dinding, detected_rate tidak sebanding, throughput_per_cpu memakai CPU fase serangan). |
| 94–118 | import + path | `psutil`, `threading`, `datetime/timezone`, Mininet, topologi. |
| 120–149 | `RESULTS_DIR`, `MITIGATION_CSV`, `ALGO_CONFIG`, `COMPARE_CSV` | **Satu sumber kebenaran**: `ALGO_CONFIG` memetakan `baseline|s2td|entropy` → file controller, CSV event, dan label. `COMPARE_CSV` terpisah agar skema lama tidak tercampur. |
| 151–154 | `ATTACKER_IP='10.0.0.1'` / `THRESHOLD=env RATE_THRESHOLD` | Konstanta peran host & threshold baseline. |

### III.4b Utilitas lama (baris 157–204)

| Baris | Kode | Penjelasan |
|---|---|---|
| 160–204 | `wait_port`, `_ovs_lock`, `count_drop_rules`, `parse_ping_loss`, `count_mitigation_rows` | Sama seperti BAGIAN I §5b, dengan satu perubahan penting: `count_mitigation_rows(csv_path=None)` menerima path agar mode `--algo` membaca CSV algoritme yang benar. |

### III.4c Utilitas baru mode compare (baris 207–391)

| Baris | Kode | Penjelasan |
|---|---|---|
| 213–235 | `COMPARE_FIELDS` (21 kolom) | Skema stabil: `algo`, `repeat`, `flood_rate_pps`, `flood_actual_pps`, `detection_time_s`, `detection_time_poll_s`, `detected_rate_pps`, drop/FP/loss, CPU whole-run & attack-only, memori, `throughput_per_cpu`. Tanpa kolom per-host dinamis agar header tidak berubah antar `--legit-count`. |
| 238–262 | `append_compare_row(row)` | Append aman: bila header file lama berbeda, file **diarsipkan** (`*_skema-lama_<ts>.csv`) lalu header baru ditulis — data lama tidak hilang dan `DictWriter` tidak error. |
| 265–283 | `wait_flood_start(path, timeout=15, poll=0.02)` | Polling penanda `[flood] started`; fallback ke perilaku lama bila flooder versi lama. |
| 286–307 | `flood_start_epoch(path)` | Regex `t0_epoch=([\d.]+)` dari baris penanda → float epoch, atau `None`. |
| 310–322 | `parse_flood_actual(path)` | Regex `~([\d.]+) pps` dari baris akhir flooder → string angka. |
| 325–339 | `first_event_epoch(rows)` | Ambil `ts_iso` (kolom ke-2) baris event pertama → `datetime`. |
| 342–361 | `precise_detection_time(rows, t_flood_wall, max_s=120)` | `(ts_event - t0).total_seconds()`; `None` bila tidak ada event / t0 hilang / negatif / terlalu besar. Alasan: polling `ovs-ofctl` terkuantisasi 0,2 s dan punya lantai 0,01–0,05 s. |
| 364–378 | `first_event_rate(rows)` | Ambil kolom `rate_pps` (indeks 5) dengan validasi numerik; informatif saja. |
| 381–391 | `proc_jiffies(pid)` | Baca `utime+stime` langsung dari `/proc/<pid>/stat` sebagai ground truth independen dari psutil. |

### III.4d Persiapan lingkungan (baris 394–495)

| Baris | Kode | Penjelasan |
|---|---|---|
| 397–409 | `cleanup_stale_environment()` | `pkill -f osken-manager` + `mn -c` + jeda 1 s; mencegah controller yatim/zombie. |
| 412–454 | `start_controller(log_path, threshold=None, algo='baseline', extra_env=None)` | Pilih `ALGO_CONFIG[algo]`; cari `osken-manager` relatif `sys.executable`; gabungkan env + override; spawn; tunggu port 6633; **validasi anti-zombie** (proses baru tidak boleh langsung mati). `extra_env` dipakai runner untuk `S2TD_LOG`/`S2TD_PROTECTED_IPS`/`ENTROPY_LOG`/`ENTROPY_PROTECTED_IPS`. |
| 457–468 | `build_net(n_iot=3)` | Bangun `DDosTopo`; jumlah host legitimate = `n_iot`. |
| 470–495 | `tail_controller_log(...)` | Live-view `[ctrl]` dari log controller. |

### III.4e `run_scenario` (baris 498–882) — jantung runner

| Baris | Kode | Penjelasan |
|---|---|---|
| 498–512 | signature + docstring | Parameter baru `algo=None`, `rate=0.0`, `repeat=1`, `subdir=None`. `algo=None` → **mode lama identik**; `algo=<x>` → mode compare. |
| 513–524 | cek iperf3, hitung `victim_id`/`victim_ip`/`legit_hosts`, `eff_flash_rate` | Konvensi h1 attacker, h2..h(n+1) legit, h(n+2) victim. |
| 526–540 | `compare`, `algo_name`, `algo_cfg`, `mitigation_csv`, `algo_env` | Pilih CSV yang ditulis **dan** dibaca; override IP victim agar proteksi mengikuti `--legit-count`. |
| 542–547 | `ts`, `os.makedirs(RESULTS_DIR)`, `aux_dir` | `--subdir` hanya memindahkan file bukti; CSV event & ringkasan tetap di `results/`. |
| 549–561 | cleanup, `tag`, path log/timeseries/flood, `start_controller`, `cpu_meter` | Nama file diberi tag algoritme + repeat agar tidak saling menimpa. |
| 564–569 | tail thread | Live-view controller. |
| 571–577 | `build_net`, `s1/h1/victim`, `rows_before` | `rows_before` = diff CSV untuk menghitung event milik run ini. |
| 579–618 | timeseries + sampler thread | Sampler background dari t=0; tulis `t_rel_s,cpu_pct,mem_pct,jiffies,drop_rules` tiap 0,5 s; priming `cpu_percent(None)` + `sleep(0.5)` mencegah artefak sampel pertama. |
| 620–631 | ping legitimate | Hanya untuk `baseline/mixed/flash_crowd`; jumlah paket dihitung dari total durasi. |
| 636–686 | fase serangan `single/mixed` | Tunggu `t_start+warmup`; susun `flood_cmd`; **mode compare**: tambah `--rate`, simpan stdout ke file, `wait_flood_start` → `t_flood` monotonic + `t_flood_wall` dari `t0_epoch` (fallback `now`), lalu polling `count_drop_rules` 0,2 s sebagai `detection_time_poll_s`. Mode lama: perilaku persis seperti BAGIAN I §5d. |
| 687–713 | fase `flash_crowd` | Server iperf3 UDP di victim + burst dari semua host legit; deteksi rule DROP = false positive. |
| 715–755 | observasi & pembersihan | Join sampler, terminate flood/burst/iperf, hitung `events_this_run` & `fp_bans`, kumpulkan loss ping, tutup CSV/log, `net.stop()`, terminate controller. |
| 757–787 | ringkasan dari timeseries | `fpr_pct`, `is_legit`, `summary` (detection_time polling, drop max/concurrent, CPU/mem) — skema lama. |
| 789–862 | **cabang compare** | (791) `flood_actual_pps`; (797–800) `cpu_attack_*` hanya sampel `warmup ≤ t_rel ≤ warmup+attack_dur`; (804–807) `load_pps` = actual bila ada, else nominal; (809–811) loss mean/max; (815–817) `det_precise` fallback polling; (819–847) susun 21 kolom; (848) `append_compare_row`; (850–862) cetak hasil + path bukti. |
| 864–882 | mode lama | Tulis `exp_summary.csv` + cetak ringkasan — **tidak berubah**. |

### III.4f Threshold sweep & `main` (baris 885–1046)

| Baris | Kode | Penjelasan |
|---|---|---|
| 885–934 | `run_threshold_sweep(...)` | Untuk tiap `T`: jalankan `mixed` (TPR) + `flash_crowd` (FPR), tulis `threshold_sweep_summary.csv`. Tidak berubah, tetap hanya untuk baseline. |
| 937–982 | `main` + argparse | Argumen lama + **`--algo`**, **`--rate`**, **`--repeats`**, **`--repeat-start`**, **`--subdir`**. |
| 984–997 | validasi | `repeats ≥ 1`, `repeat_start ≥ 1`; `--rate` tanpa `--algo` hanya memberi warning (backward-compat); `rate < 0` error. |
| 999–1009 | cabang `threshold_sweep` | Menolak `--algo` (sweep threshold milik baseline), lalu panggil `run_threshold_sweep`. |
| 1011–1025 | loop repeat | `repeat_no = repeat_start + i - 1`; panggil `run_scenario` dengan algo/rate/repeat/subdir. |
| 1027–1042 | ringkasan multi-repeat | Tabel `rep/detect_s/actual_pps/cpu_avg/cpu_max/loss_max/tput-per-cpu` agar sebaran terlihat tanpa membuka CSV. |
| 1045–1046 | entry point | — |

---

## III.5 `experiments/run_sweep_compare.py` (426 baris) — Orkestrator load sweep

### III.5a Docstring, konstanta, utilitas (baris 1–131)

| Baris | Kode | Penjelasan |
|---|---|---|
| 1–53 | Docstring | Tujuan, cara kerja (tidak menduplikasi logika; memanggil runner), urutan **rate → algo → repeat**, aturan berhenti, definisi metrik, cara pakai, dan output. |
| 55–68 | import + `HERE/PROJECT_ROOT/RESULTS_DIR/RAW_CSV/RUNNER` | Path absolut agar skrip aman dijalankan dari mana pun. |
| 70–74 | `ALGO_LABEL` | Label tampilan untuk tiga algoritme. |
| 76–88 | `STATS_FIELDS` (22 kolom) | Skema `compare_stats.csv`: `n_runs/n_detected/det_miss`, deteksi mean/std/min/max, `flood_actual_mean_pps`, `detected_rate_mean_pps`, CPU attack/run, loss, FP, drops, `throughput_per_cpu`, `saturated`, `stop_reason`. |
| 94–99 | `read_raw_rows()` | Baca seluruh baris `exp_summary_compare.csv`. |
| 102–108 | `num(value)` | Konversi ke float; `None` untuk kosong/NaN (`v == v`). |
| 111–118 | `col(rows, key)` | Ambil semua nilai numerik satu kolom. |
| 121–127 | `mean_std(values)` | Mean + stddev sampel; stddev `None` bila `n < 2`. |
| 130–131 | `fmt(value, nd=2)` | Format angka atau string kosong. |

### III.5b Satu run (baris 134–179)

| Baris | Kode | Penjelasan |
|---|---|---|
| 137–139 | `run_one(args, algo, rate, repeat, index, total)` / `before = len(read_raw_rows())` | Catat jumlah baris sebelum run untuk mengambil baris **baru** setelahnya (tahan terhadap CSV yang sudah berisi riwayat). |
| 140–151 | susun `cmd` runner | `--scenario/--algo/--rate/--repeats 1/--repeat-start/--legit-count/--warmup/--flood-duration/--post` + `--subdir`. |
| 153–162 | print progres, `subprocess.run(..., capture_output=True, timeout)` | Satu run = satu proses terisolasi; timeout mencegah hang. |
| 164–172 | validasi hasil | Bila exit ≠ 0 atau tidak ada baris baru → cetak ekor stdout/stderr dan `SystemExit`. |
| 174–179 | ambil baris terakhir, cetak `ok ... deteksi/cpu/loss`, return `(row, elapsed)` | Progres ringkas per run. |

### III.5c Agregasi & merge (baris 182–283)

| Baris | Kode | Penjelasan |
|---|---|---|
| 185–202 | `aggregate(args, algo, rate, rows)` | Kumpulkan deteksi, CPU attack, CPU peak, CPU run, loss, actual, detected rate, drops. |
| 205–209 | `tput = actual_mean / cpu_mean` | Memakai beban **nyata**, bukan nominal, agar adil saat pacing tidak tercapai. |
| 211–217 | aturan berhenti | `cpu_mean > stop_cpu` dan/atau `loss_worst > stop_loss` → `stop_reason`. |
| 219–243 | return dict 22 kolom | `saturated='ya'/'tidak'`; `n_detected`/`det_miss` dari ketersediaan `detection_time_s`. |
| 246–270 | `merge_levels(existing_path, new_levels)` | Baca CSV lama, gabung berdasarkan kunci `(algo, scenario, float(rate))`; baris baru menang; urutkan `(rate, urutan algo)`. Memungkinkan sweep bertahap tanpa duplikasi. |
| 273–283 | `write_stats(levels, out_path)` | Tulis ulang seluruh CSV tiap titik selesai → hasil parsial tetap aman bila sweep dihentikan. |

### III.5d `main` (baris 286–426)

| Baris | Kode | Penjelasan |
|---|---|---|
| 289–319 | argparse | `--rates` (default `100,500,1000,1500`), `--repeats 3`, `--algos`, `--scenario mixed`, `--legit-count 3`, `--warmup 5`, `--flood-duration 10`, `--post 20`, `--stop-cpu 80`, `--stop-loss 1`, `--timeout 300`, `--subdir tahapD`, `--stats-out`, `--dry-run`. |
| 321–336 | validasi | Wajib root (`geteuid==0`); runner harus ada; `repeats ≥ 1`; rate di-`sorted` & di-*dedup*; algoritme divalidasi terhadap `ALGO_LABEL`. |
| 338–358 | cetak rencana | Total run maksimum, aturan berhenti, path output; `--dry-run` berhenti di sini. |
| 360–367 | siapkan folder + state | `levels`, `saturated` (algo → alasan), `index`. |
| 369–395 | loop utama | `for rate → for algo`: lewati algoritme jenuh; `for rep`: `run_one`; `aggregate`; `write_stats(merge_levels(...))`; cetak ringkas; bila `stop_reason` → tandai jenuh dan lewati rate lebih tinggi. |
| 397–415 | tabel akhir | `merge_levels` sekali lagi agar invokasi bertahap ikut tampil; header `algo/rate/n/detik/cpu%/loss%/tput-cpu/status`. |
| 417–422 | penutup | Total run, durasi menit, path output, timestamp. |
| 425–426 | entry point | — |

---

## Alur besar FASE P1 (ringkasan satu paragraf)

`run_sweep_compare.py` menyusun rencana **rate → algoritme → repeat** dan memanggil
`run_experiment.py --algo <x> --rate <r> --repeats 1` untuk setiap run. Runner
memilih controller dari `ALGO_CONFIG`, membersihkan lingkungan, membangun ulang
topologi, menjalankan ping legitimate, lalu pada `t=warmup` meluncurkan
`flood_scapy.py` dengan pacing. Flooder mencetak `[flood] started ... t0_epoch=...`
sebelum paket pertama; runner memakai epoch itu sebagai t0 dan menghitung
`detection_time_s` dari `ts_iso` event pertama di CSV algoritme (presisi
milidetik). Selama run, sampler 0,5 s merekam CPU/memori/jumlah rule. Setelah
run, runner menulis satu baris 21 kolom ke `exp_summary_compare.csv`; skrip sweep
mengagregasi 3 repeat menjadi mean ± stddev di `compare_stats.csv`, dan berhenti
menaikkan beban untuk algoritme yang sudah jenuh (CPU > 80% atau loss > 1%).
Hasil final P1: 15 titik (5 rate × 3 algoritme), 45 run, 0 false positive, 0%
loss, tanpa saturasi pada ≤3000 pps — dengan catatan metodologi bahwa perbedaan
CPU baseline/entropi vs S2TD **tidak murni** berasal dari algoritme, melainkan
ikut dipengaruhi flow caching (lihat README bagian *Keterbatasan*).
