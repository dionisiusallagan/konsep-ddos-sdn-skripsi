#!/usr/bin/env python3
"""
Entropy Guard - Deteksi DDoS berbasis Shannon Entropy pada SDN (OpenFlow 1.3).

Skripsi S1 Teknik Komputer - Dionisius (fase P1, algoritme pembanding klasik).

POSISI DALAM PENELITIAN
=======================
Algoritme C (pembanding "generasi lama") terhadap baseline (A = threshold
per-IP) dan S2TD (B = dua tahap berbasis statistik flow). File ini sengaja
dibuat SESEDERHANA dan TIDAK dioptimasi: tujuannya mengukur seberapa baik
pendekatan entropi klasik bertahan pada beban tinggi, bukan untuk mengalahkan
S2TD.

ARSITEKTUR (dibuat sama dengan baseline agar beda hanya di logika deteksi)
==========================================================================
- Forwarding: L2 learning TANPA flow caching (setiap paket -> packet-in ->
  packet-out). Menyalin persis keputusan D1 baseline supaya perbandingan
  "apel ke apel": satu-satunya variabel yang berbeda adalah algoritme deteksi.
- Deteksi: sliding window ENTROPY_WINDOW detik berisi PAKET INISIASI koneksi
  (filter sama dengan baseline D2: TCP SYN murni, semua UDP, ICMP echo
  request). Dari distribusi IP SUMBER dihitung Shannon entropy:
      H = -sum p_i * log2(p_i),   p_i = count_i / N
  Jika N >= ENTROPY_MIN_PKTS dan H < ENTROPY_THRESHOLD -> indikasi serangan.
- Mitigasi: ban sumber dominan (count terbesar) dengan rule IDENTIK baseline:
  priority 100, match ipv4_src saja, hard_timeout 15 detik.

KEPUTUSAN DESAIN (bahan bab metodologi)
=======================================
E1. Entropi IP SUMBER, bukan IP TUJUAN.
    Alasan: topologi PoC hanya punya SATU victim (10.0.0.5). Entropi tujuan
    akan selalu ~0 bit baik saat normal maupun diserang (semua paket menuju
    satu host) sehingga tidak punya daya pisah sama sekali. Entropi sumber
    justru turun drastis saat satu attacker mendominasi (p_attacker ~ 0,99
    -> H ~ 0,1 bit), sementara trafik normal tersebar (H ~ log2(jumlah host)
    ~ 1,6-2,3 bit).
    TRADE-OFF yang diakui: (a) serangan terdistribusi banyak sumber justru
    MENAIKKAN entropi sumber sehingga lolos deteksi (kebalikan serangan
    tunggal); (b) satu host legitimate ber-volume tinggi (mis. server backup)
    membuat entropi sumber rendah -> false positive. Keduanya dibahas di
    bab pembahasan skripsi.
E2. Filter paket inisiasi DISALIN dari baseline (D2). Tanpa filter ini,
    balasan victim (RST/SYN-ACK/ICMP reply) ikut terhitung dan mendistorsi
    distribusi sumber - masalah buta-arah yang di S2TD ditangani
    PROTECTED_IPS (S6).
E3. ENTROPY_MIN_PKTS mencegah evaluasi pada sampel terlalu kecil: dengan
    N=2, entropi maksimum hanya 1 bit walau dua host berbeda -> rawan false
    positive. Default 30 paket.
E4. Evaluasi dibatasi tiap EVAL_INTERVAL (0,5 detik) agar biaya komputasi
    entropi tidak dibayar per paket; window tetap sliding per paket.
E5. Ban memakai rule yang sama persis dengan baseline (priority 100,
    hard_timeout 15 s, match ipv4_src) agar bentuk mitigasi bukan variabel
    pembeda; yang dibandingkan adalah logika deteksinya.

KETERBATASAN
============
- Tidak mendeteksi serangan multi-sumber terdistribusi (entropi tinggi).
- Satu sumber legitimate ber-volume besar dapat memicu false positive.
- Tanpa flow caching: CPU controller tinggi saat beban besar (sama seperti
  baseline). Justru inilah yang diukur pada perbandingan.
"""

import csv
import math
import os
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib.packet import (packet, ethernet, ether_types,
                               ipv4, tcp, udp, icmp)

# ========================== KONFIGURASI ==================================
# Semua via env mengikuti pola RATE_THRESHOLD baseline: replayable tanpa ubah
# kode, dan nilai aktual tercatat di log startup (bukti eksperimen).
ENTROPY_WINDOW = float(os.environ.get('ENTROPY_WINDOW', '1.0'))        # detik
ENTROPY_THRESHOLD = float(os.environ.get('ENTROPY_THRESHOLD', '1.0'))  # bit
ENTROPY_MIN_PKTS = int(os.environ.get('ENTROPY_MIN_PKTS', '30'))
EVAL_INTERVAL = 0.5        # E4: batasi frekuensi evaluasi entropi (detik)
BAN_DURATION_SEC = int(os.environ.get('ENTROPY_BAN_SEC', '15'))  # = baseline
DROP_PRIORITY = int(os.environ.get('ENTROPY_DROP_PRIORITY', '100'))  # = baseline
STATS_INTERVAL = 5         # log diagnostik entropi (detik)

# E2/S6-analog: IP yang tidak boleh di-ban (server/victim). Koma-pisah via env
# agar topologi lain (mis. scale50, victim 10.0.0.51) cukup override.
PROTECTED_IPS = {ip.strip() for ip in
                 os.environ.get('ENTROPY_PROTECTED_IPS', '10.0.0.5').split(',')
                 if ip.strip()}

# CSV TERPISAH dari baseline/S2TD; kolom IDENTIK (10 kolom) agar bisa digabung.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MITIGATION_LOG = os.environ.get(
    'ENTROPY_LOG', os.path.join(_PROJECT_ROOT, 'results',
                                'mitigation_events_entropy.csv'))


class EntropyGuard(app_manager.OSKenApp):
    """Controller entropi klasik: sliding window + Shannon entropy (E1-E5)."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(EntropyGuard, self).__init__(*args, **kwargs)

        # ---- forwarding state (L2 learning, tanpa flow caching: D1) ----
        self.mac_to_port = {}   # {dpid: {mac: port}}

        # ---- state deteksi: sliding window paket inisiasi ----
        self.window = deque()            # [(monotonic_ts, src_ip), ...]
        self.counts = defaultdict(int)   # {src_ip: jumlah paket di window}

        self._last_eval = 0.0            # E4: evaluasi terakhir
        self._last_stats = 0.0           # log diagnostik terakhir
        self._last_protect_log = 0.0     # hindari spam log SKIP
        self.banned_until = {}           # {src_ip: monotonic kedaluwarsa}

        os.makedirs(os.path.dirname(MITIGATION_LOG), exist_ok=True)
        if not os.path.exists(MITIGATION_LOG):
            with open(MITIGATION_LOG, 'w', newline='') as f:
                csv.writer(f).writerow(
                    ['ts_epoch', 'ts_iso', 'event', 'dpid', 'src_ip',
                     'rate_pps', 'window_sec', 'threshold',
                     'action', 'ban_sec'])

        self.logger.info(
            'EntropyGuard aktif | window=%.1fs threshold=%.2f bit '
            'min_pkts=%d eval=%.1fs ban=%ds protected=%s | log=%s',
            ENTROPY_WINDOW, ENTROPY_THRESHOLD, ENTROPY_MIN_PKTS,
            EVAL_INTERVAL, BAN_DURATION_SEC, sorted(PROTECTED_IPS),
            MITIGATION_LOG)

    # ------------------------------------------------------------------
    # SWITCH SETUP (identik baseline)
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Table-miss: semua paket tak dikenal dikirim ke controller."""
        dp = ev.msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                             actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=0, match=match,
                                      instructions=inst))
        self.logger.info('Switch %s terhubung, table-miss terpasang', dp.id)

    # ------------------------------------------------------------------
    # DETEKSI: filter paket + sliding window + Shannon entropy
    # ------------------------------------------------------------------
    @staticmethod
    def _initiation_source(pkt):
        """Filter paket inisiasi: DISALIN PERSIS dari baseline (D2/E2).

        Hanya paket inisiasi koneksi yang membentuk distribusi sumber.
        Balasan victim (RST/SYN-ACK/ICMP reply) sengaja tidak dihitung.
        """
        ip4 = pkt.get_protocol(ipv4.ipv4)
        if ip4 is None:
            return None

        tcppkt = pkt.get_protocol(tcp.tcp)
        if tcppkt is not None:
            if (tcppkt.bits & (tcp.TCP_SYN | tcp.TCP_ACK)) == tcp.TCP_SYN:
                return ip4.src
            return None

        udppkt = pkt.get_protocol(udp.udp)
        if udppkt is not None:
            return ip4.src

        icmppkt = pkt.get_protocol(icmp.icmp)
        if icmppkt is not None:
            if icmppkt.type == icmp.ICMP_ECHO_REQUEST:
                return ip4.src
            return None

        return None

    def _update_window(self, src_ip, now):
        """Masukkan paket ke window, buang yang kedaluwarsa, kembalikan N."""
        cutoff = now - ENTROPY_WINDOW
        while self.window and self.window[0][0] < cutoff:
            _, old_src = self.window.popleft()
            self.counts[old_src] -= 1
            if self.counts[old_src] <= 0:
                del self.counts[old_src]      # jaga memori tetap datar
        self.window.append((now, src_ip))
        self.counts[src_ip] += 1
        return len(self.window)

    @staticmethod
    def _shannon_entropy(counts, total):
        """H = -sum p_i * log2(p_i), dalam bit."""
        h = 0.0
        for c in counts.values():
            p = c / total
            h -= p * math.log2(p)
        return h

    def _evaluate(self, datapath, now, total):
        """Hitung entropi (maks. tiap EVAL_INTERVAL) dan mitigasi bila rendah.

        Sederhana sengaja: satu sumber dominan, satu keputusan ban, tanpa
        ranking top-N maupun konfirmasi berturut (beda dengan S2TD). Perbedaan
        inilah yang nanti dibandingkan pada bab hasil.
        """
        if now - self._last_eval < EVAL_INTERVAL:
            return
        self._last_eval = now
        if total < ENTROPY_MIN_PKTS:          # E3: sampel terlalu kecil
            return

        h = self._shannon_entropy(self.counts, total)
        top_ip, top_n = max(self.counts.items(), key=lambda kv: kv[1])

        # Diagnostik berkala (bukti untuk bab hasil: nilai H saat normal
        # vs saat serangan).
        if now - self._last_stats >= STATS_INTERVAL:
            self._last_stats = now
            self.logger.info('ENTROPY: H=%.2f bit (thr=%.2f) | N=%d | '
                             'top=%s %.1fpps', h, ENTROPY_THRESHOLD, total,
                             top_ip, top_n / ENTROPY_WINDOW)
            self.banned_until = {ip: t for ip, t in self.banned_until.items()
                                 if t > now}

        if h >= ENTROPY_THRESHOLD:
            return                            # distribusi masih wajar

        # Entropi rendah -> sumber dominan dianggap penyerang.
        if top_ip in PROTECTED_IPS:
            if now - self._last_protect_log >= STATS_INTERVAL:
                self._last_protect_log = now
                self.logger.warning(
                    'ENTROPY SKIP: %s dominan (H=%.2f bit) namun diproteksi '
                    '-> tidak di-ban', top_ip, h)
            return
        if now < self.banned_until.get(top_ip, 0):
            return                            # sedang di-ban, biarkan expiry

        rate = top_n / ENTROPY_WINDOW
        self._install_drop(datapath, top_ip)
        self.banned_until[top_ip] = now + BAN_DURATION_SEC
        self._log_event(datapath.id, top_ip, rate, h)

    # ------------------------------------------------------------------
    # MITIGASI (identik baseline: E5)
    # ------------------------------------------------------------------
    def _install_drop(self, datapath, src_ip):
        """Flow DROP per-src: match + timeout SAMA PERSIS dengan baseline."""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=src_ip)
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=DROP_PRIORITY, match=match,
            instructions=[],                       # tanpa action = DROP
            hard_timeout=int(BAN_DURATION_SEC)))
        self.logger.warning('ENTROPY MITIGASI: DROP rule terpasang utk %s '
                            '(hard_timeout=%ds)', src_ip, BAN_DURATION_SEC)

    def _log_event(self, dpid, src_ip, rate, entropy):
        """CSV entropi: 10 kolom SAMA dengan baseline.

        Beda isi: event='ENTROPY_DETECT_DROP' (identitas algoritme),
        threshold = ENTROPY_THRESHOLD (statis, satuan bit), window_sec =
        ENTROPY_WINDOW. Nilai entropi saat keputusan hanya dicatat di log
        konsol (bukan kolom baru) agar skema CSV tetap identik.
        """
        now = time.time()
        with open(MITIGATION_LOG, 'a', newline='') as f:
            csv.writer(f).writerow(
                [f'{now:.3f}',
                 datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
                 'ENTROPY_DETECT_DROP', f'{dpid:#x}', src_ip, f'{rate:.1f}',
                 f'{ENTROPY_WINDOW:.1f}', f'{ENTROPY_THRESHOLD:.1f}',
                 'DROP', BAN_DURATION_SEC])
        self.logger.info('ENTROPY event tercatat: src=%s rate=%.1fpps '
                         'H=%.2f bit', src_ip, rate, entropy)

    # ------------------------------------------------------------------
    # MAIN PACKET-IN HANDLER (forwarding tanpa flow caching: D1)
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
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
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data))

        # ---------- 2. DETEKSI (inelastis: hanya paket inisiasi) ----------
        now = time.monotonic()
        src_ip = self._initiation_source(pkt)
        if src_ip is None:
            return

        # IP yang sedang dibanned sudah di-drop di switch (tak ada packet-in);
        # guard ini hanya jaring pengaman (pola baseline).
        if now < self.banned_until.get(src_ip, 0):
            return

        total = self._update_window(src_ip, now)
        self._evaluate(datapath, now, total)
