#!/usr/bin/env python3
"""
DDoS Guard - Deteksi & Mitigasi Otomatis Flooding pada SDN (OpenFlow 1.3)

Skripsi S1 Teknik Komputer - Dionisius

ARSITEKTUR
==========
Aplikasi os-ken (fork Ryu, API identik) yang menggabungkan:
1. FORWARDING   : L2 learning (MAC -> port) tapi TANPA flow caching.
                  Setiap paket data lewat controller (packet-in -> packet-out).
2. DETECTION    : menghitung laju "paket inisiasi koneksi" per source IP
                  dalam sliding window 1 detik.
3. MITIGATION   : jika rate > threshold, pasang flow DROP untuk IP tersebut
                  (OFPFlowMod, actions kosong) selama BAN_DURATION detik,
                  lalu catat kejadian ke CSV.

KEPUTUSAN DESAIN (penting untuk bab metodologi)
===============================================
D1. Mengapa TANPA flow caching (semua paket ke controller)?
    Jika controller memasang flow L2 permanen, paket flood berikutnya akan
    di-forward langsung oleh OVS tanpa packet-in -> controller buta terhadap
    serangan (packet-in rate = 0). Mode reaktif penuh menjamin packet-in rate
    merepresentasikan trafik riil. Konsekuensi: beban controller tinggi saat
    serangan - justru ini yang ingin diukur (efek mitigasi terlihat dari
    turunnya packet-in & CPU setelah drop rule terpasang).
    Keterbatasan (discussed di skripsi): pendekatan ini tidak skala untuk
    produksi; alternatifnya flow dengan hard_timeout pendek atau sampling.

D2. Yang dihitung hanya "paket inisiasi koneksi":
    - TCP : segmen SYN murni (SYN=1, ACK=0)
    - UDP : semua paket (tidak ada flag; korsleting dicegah karena balasan
            victim berupa ICMP, bukan UDP)
    - ICMP: hanya echo request (type 8), bukan reply (type 0)
    Alasan: jika SEMUA paket dihitung, balasan victim (RST/SYN-ACK/ICMP-error)
    yang volumenya menyamai serangan akan memicu false positive dan
    membanned korban. Paket inisiasi mencerminkan perilaku Mirai-style
    (scanning/flooding koneksi baru) sehingga aman bagi korban.

D3. Sliding window 1 detik (bukan bucket tetap):
    timestamp tiap paket disimpan per source IP (deque); entri lebih tua dari
    window dibuang. Sliding window tidak punya artefak batas bucket (serangan
    yang kebagian dua bucket tetap bisa lolos pada fixed window).

D4. Threshold default 25 paket-inisiasi/detik per source IP:
    - Baseline ping antar 5 host di Mininet: ~4-8/detik per host (puncak).
    - Flood scapy/hping3: ratusan hingga ribuan/detik.
    Dipilih 25 agar margin atas baseline >= 3x dan margin bawah serangan
    >= 10x. Nilai ini adalah parameter eksperimen (di-tune per lingkungan;
    di produksi dikalibrasi terhadap profil trafik normal site).

D5. Drop rule memakai hard_timeout (default 15 detik), bukan permanen:
    - Jaringan pulih otomatis jika deteksi salah (batas false positive).
    - Eksperimen bisa diulang tanpa restart controller/switch.
    - Jika flood masih berlanjut setelah ban kedaluwarsa, deteksi terpicu
      lagi dan rule dipasang ulang (loop deteksi-mitigasi teramati di log).

KETERBATASAN YANG DIAKUI
========================
- Source IP spoofed acak (hping3 --rand-source): tiap IP muncul sekali ->
  rate per-IP rendah. Penanganannya (agregasi per subnet/port-switch)
  di luar scope PoC ini; dibahas di bab pembahasan.
- Baru satu switch; multi-switch butuh registry datapath.
"""

import csv
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import (packet, ethernet, ether_types,
                               ipv4, tcp, udp, icmp)

# ========================== KONFIGURASI ==================================
WINDOW_SEC = 1.0        # D3: panjang sliding window (detik)
RATE_THRESHOLD = 25     # D4: max paket inisiasi / window per source IP
BAN_DURATION_SEC = 15   # D5: masa berlaku drop rule (hard_timeout)
DROP_PRIORITY = 100     # prioritas drop rule (> table-miss = 0)
CLEANUP_INTERVAL = 30   # interval buang memori IP yang sudah tidak aktif
STATS_INTERVAL = 5      # interval log statistik packet-in (diagnostik)

# Lokasi CSV hasil mitigasi: <project>/results/mitigation_events.csv
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MITIGATION_LOG = os.path.join(_PROJECT_ROOT, 'results', 'mitigation_events.csv')


class DDoSGuard(app_manager.OSKenApp):
    """Controller deteksi + mitigasi flooding (lihat docstring modul)."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSGuard, self).__init__(*args, **kwargs)

        # ---- forwarding state (sama seperti L2 learning switch) ----
        # {dpid: {mac_src: in_port}}
        self.mac_to_port = {}

        # ---- detection state ----
        # {src_ip: deque[timestamp]} - sliding window per source IP (D3)
        self.rate_window = defaultdict(deque)

        # {src_ip: unix_ts_kadaluarsa_ban} - cegah pasang rule ganda (D5)
        self.banned_until = {}

        self._last_cleanup = time.monotonic()

        # ---- diagnostik ----
        # penghitung packet-in per interval STATS_INTERVAL detik.
        # Fungsi: membedakan "controller tidak tersambung" (counter ~0)
        # vs "controller dibanjiri packet-in" (counter ratusan ribu) saat
        # serangan berlangsung - penting untuk validasi eksperimen.
        self._pkt_in_count = 0
        hub.spawn(self._stats_loop)

    def _stats_loop(self):
        """Loop periodik utk log statistik (hindari API spawn_periodic yang
        berbeda antar versi - loop manual selalu kompatibel)."""
        while True:
            hub.sleep(STATS_INTERVAL)
            self._log_stats()

        # siapkan file CSV + header sekali saja
        os.makedirs(os.path.dirname(MITIGATION_LOG), exist_ok=True)
        if not os.path.exists(MITIGATION_LOG):
            with open(MITIGATION_LOG, 'w', newline='') as f:
                csv.writer(f).writerow(
                    ['ts_epoch', 'ts_iso', 'event', 'dpid', 'src_ip',
                     'rate_pps', 'window_sec', 'threshold',
                     'action', 'ban_sec'])

        self.logger.info('DDoSGuard aktif | window=%.1fs threshold=%d pps '
                         'ban=%ds | log=%s', WINDOW_SEC, RATE_THRESHOLD,
                         BAN_DURATION_SEC, MITIGATION_LOG)

    # ------------------------------------------------------------------
    # SWITCH SETUP
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Pasang table-miss: semua paket tak dikenal dikirim ke controller.

        Satu-satunya flow yang dipasang untuk trafik NORMAL (D1).
        Trafik data tidak pernah di-cache di switch -> controller melihat
        seluruh paket sehingga pengukuran rate akurat.
        """
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=0, match=match,
                                instructions=inst)
        dp.send_msg(mod)
        self.logger.info('Switch %s terhubung, table-miss terpasang', dp.id)

    # ------------------------------------------------------------------
    # DETECTION HELPERS
    # ------------------------------------------------------------------
    @staticmethod
    def _initiation_source(pkt):
        """Kembalikan IP sumber HANYA jika paket adalah inisiasi koneksi (D2).

        Return None untuk paket non-inisiasi (balasan/ack) -> tidak dihitung.
        """
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            return None          # ARP/LLDP/IPv6 dll: di luar scope deteksi

        tcppkt = pkt.get_protocol(tcp.tcp)
        if tcppkt is not None:
            # SYN murni = permintaan koneksi baru; SYN-ACK = balasan server
            if (tcppkt.bits & (tcp.TCP_SYN | tcp.TCP_ACK)) == tcp.TCP_SYN:
                return ip4.src
            return None

        udppkt = pkt.get_protocol(udp.udp)
        if udppkt is not None:
            return ip4.src       # UDP flood: setiap datagram dihitung

        icmppkt = pkt.get_protocol(icmp.icmp)
        if icmppkt is not None:
            if icmppkt.type == icmp.ICMP_ECHO_REQUEST:
                return ip4.src   # ping flood: hanya request, bukan reply
            return None

        return None              # proto lain (mis. TCP ACK/RST/FIN): skip

    def _update_rate(self, src_ip, now):
        """Tambah timestamp ke window source IP, buang entri kadaluarsa,
        kembalikan jumlah paket dalam window (sliding, D3)."""
        dq = self.rate_window[src_ip]
        dq.append(now)
        cutoff = now - WINDOW_SEC
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def _cleanup_state(self, now):
        """Buang state IP lama supaya memori tidak tumbuh tanpa batas."""
        if now - self._last_cleanup < CLEANUP_INTERVAL:
            return
        self._last_cleanup = now
        stale = [ip for ip, dq in self.rate_window.items()
                 if not dq or now - dq[-1] > CLEANUP_INTERVAL]
        for ip in stale:
            del self.rate_window[ip]
        self.banned_until = {ip: t for ip, t in self.banned_until.items()
                             if t > now}

    def _log_stats(self):
        """Log periodik jumlah packet-in & window terbesar (diagnostik).

        Interpretasi saat serangan:
        - counter tinggi + tidak ada MITIGASI -> controller kewalahan
          (channel OpenFlow jenuh; pertimbangkan turunkan rate serangan
          atau optimasi hot-path)
        - counter ~0 -> switch TIDAK tersambung ke controller ini
          (proses lama pegang port 6633 / OVS fail-mode standalone)
        """
        tops = sorted(((ip, len(dq)) for ip, dq in self.rate_window.items()),
                      key=lambda x: -x[1])[:3]
        self.logger.info(
            'STATS: packet_in/%ds=%d | ip_aktif=%d | top=%s',
            STATS_INTERVAL, self._pkt_in_count, len(self.rate_window), tops)
        self._pkt_in_count = 0

    # ------------------------------------------------------------------
    # MITIGATION
    # ------------------------------------------------------------------
    def _install_drop(self, datapath, src_ip):
        """Pasang flow DROP untuk satu source IP (inti mitigasi).

        - match  : eth_type=IPv4 + ipv4_src=<attacker>
        - actions: KOSONG -> paket yang match dibuang (drop) di switch
        - hard_timeout: rule hapus otomatis setelah BAN_DURATION_SEC (D5)
        - priority 100: di atas table-miss (0), tidak ada rule lain.
        """
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser

        # Match SENGAJA dibuat luas: HANYA eth_type + ipv4_src.
        # Artinya SEMUA trafik IPv4 dari IP ini (TCP/UDP/ICMP, port apa pun)
        # di-drop -> konsisten dengan desain "isolasi IP attacker".
        # Trade-off (lihat README): false positive memutus seluruh service
        # di IP tsb, dan spoofing IP korban bisa membanned korban -
        # risikonya dibatasi oleh hard_timeout (ban otomatis kedaluwarsa).
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=src_ip)
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=DROP_PRIORITY,
            match=match,
            instructions=[],                      # tanpa action = DROP
            hard_timeout=int(BAN_DURATION_SEC),
        )
        datapath.send_msg(mod)
        self.logger.warning('MITIGASI: DROP rule terpasang utk %s '
                            '(hard_timeout=%ds)', src_ip, BAN_DURATION_SEC)

    def _log_event(self, dpid, src_ip, rate):
        """Catat kejadian mitigasi ke CSV (timestamp, IP, rate saat itu)."""
        now = time.time()
        with open(MITIGATION_LOG, 'a', newline='') as f:
            csv.writer(f).writerow(
                [f'{now:.3f}',
                 datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
                 'DETECT_DROP', f'{dpid:#x}', src_ip, rate,
                 f'{WINDOW_SEC:.1f}', RATE_THRESHOLD,
                 'DROP', BAN_DURATION_SEC])

    # ------------------------------------------------------------------
    # MAIN PACKET-IN HANDLER
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Jalur utama setiap paket: forward + hitung rate + mitigasi."""
        self._pkt_in_count += 1          # diagnostik (lihat _log_stats)
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # ---------- 1. FORWARDING (packet-out, tanpa FlowMod, D1) ----------
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)

        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions,
                                  data=data)
        datapath.send_msg(out)

        # ---------- 2. DETECTION ----------
        now = time.monotonic()
        self._cleanup_state(now)

        src_ip = self._initiation_source(pkt)
        if src_ip is None:
            return                       # bukan paket inisiasi -> skip

        # IP yang sedang dibanned tidak usah dihitung lagi; paketnya sudah
        # dibuang di switch (tidak akan menghasilkan packet-in) sampai
        # rule kedaluwarsa.
        if now < self.banned_until.get(src_ip, 0):
            return

        rate = self._update_rate(src_ip, now)

        # ---------- 3. MITIGATION ----------
        if rate > RATE_THRESHOLD:
            self._install_drop(datapath, src_ip)
            self.banned_until[src_ip] = now + BAN_DURATION_SEC
            self._log_event(dpid, src_ip, rate)
