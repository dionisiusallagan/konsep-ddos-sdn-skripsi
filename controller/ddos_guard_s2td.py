#!/usr/bin/env python3
"""
S2TD Guard - Deteksi & Mitigasi DDoS Dua-Tahap Berbasis Statistik Flow (OpenFlow 1.3).

Skripsi S1 Teknik Komputer - Dionisius (fase P1, pembanding vs baseline).

ARSITEKTUR
==========
Aplikasi os-ken yang mengimplementasikan S2TD sesuai pseudocode proposal:
  TAHAP 1 (selalu aktif, ringan):
    tiap T_poll detik -> SATU FlowStatsRequest per switch (multipart, BUKAN
    packet-in). Dari balasannya dihitung:
      aggregate_rate = total delta packet_count semua flow / dt
      mu = alpha*aggregate_rate + (1-alpha)*mu   (EWMA baseline trafik normal)
    jika aggregate_rate > k_auto*mu -> TAHAP 2 dievaluasi pada poll itu.
  TAHAP 2 (hanya saat terpicu):
    dari balasan stats yang SAMA, hitung rate per src_ip,
    ambil top-N, yang > T_verify menaikkan penghitung konsekutif;
    yang mencapai T_confirm interval berturut -> DROP per-src
    (priority=100, hard_timeout=15s) + catat CSV.

PEMETAAN KE PSEUDOCODE PROPOSAL: _poll_loop = "setiap T_poll ambil stats";
flow_stats_reply_handler bagian agregat+EWMA = Tahap 1; bagian
ranking+konfirmasi = Tahap 2; _install_drop + _log_event = mitigasi.

PERBEDAAN SENGAJA VS BASELINE (controller/ddos_guard.py, TIDAK DIUBAH)
======================================================================
Baseline memakai forwarding TANPA flow caching (D1): tiap paket -> packet-in,
sehingga rate terlihat langsung. S2TD justru MEMASANG flow forwarding per
pasangan (src_ip, dst_ip) dengan idle_timeout. Alasannya struktural: tanpa
flow di switch, tidak ada counter per-flow yang bisa di-poll - statistik
flow (sumber data S2TD) tidak akan ada. Konsekuensinya sebagian beban pindah
dari controller (packet-in) ke switch (flow table + counter): trade-off inilah
yang diukur pada perbandingan (CPU controller, throughput, waktu deteksi).
CATATAN METODOLOGI: perbandingan baseline-vs-S2TD mencampur dua variabel
(arsitektur forwarding dan algoritma deteksi); lihat draf paragraf
keterbatasan di dokumen perencanaan. Klaim efisiensi dibaca sebagai
efisiensi pendekatan keseluruhan, bukan murni algoritma deteksi.

KEPUTUSAN DESAIN (bahan bab metodologi)
=======================================
S1. Satu request, dua tahap: FlowStatsRequest yang sama memberi data agregat
    (Tahap 1) dan per-src (Tahap 2). Tidak ada request tambahan saat terpicu,
    sehingga overhead control-channel konstan = 1 msg/detik/switch.
S2. EWMA DIBEKUKAN saat terpicu (hanya diupdate dari sampel normal).
    Bukti perlunya: flood 200 pps dengan mu awal 10 -> tanpa pembekuan,
    mu menjadi 67 setelah 1 poll sehingga 200 > 3*67 GAGAL di poll ke-2;
    serangan tier rendah tak pernah mencapai T_confirm=2. Pembekuan adalah
    praktik standar deteksi anomali (baseline tidak terkontaminasi serangan).
S3. Verifikasi "berturut-turut" ditegakkan ketat: poll yang tidak terpicu
    me-reset semua penghitung konsekutif. Spike sesaat tidak lolos.
S4. Flow DROP (priority=100) dikeluarkan dari agregat Tahap 1 tetapi prev
    counter-nya tetap diingat: yang diukur hanya trafik belum tertangani,
    namun tidak ada artefak delta saat rule kedaluwarsa.
S5. Counter-reset (flow kedaluwarsa lalu terpasang ulang, count mulai dari
    kecil) dideteksi via cur < prev -> delta = cur. Aman untuk PoC karena
    flow serangan yang aktif tidak pernah idle-timeout.
S6. PROTECTED_IPS tidak pernah di-ban: flow-counter buta arah, sehingga
    balasan victim (1 RST per SYN, volumenya ~= serangan) membuat victim
    memenuhi kriteria suspect. Baseline kebal via filter paket-inisiasi (D2);
    S2TD butuh proteksi eksplisit. Ke-ban-nya korban adalah FP fatal, maka
    proteksi dilevel "tidak pernah", bukan "threshold khusus". Upaya
    melewati proteksi hanya dicatat di log (bukan CSV) agar tidak mengotori
    hitungan drops_total_events/fp_bans di eksperimen.
S7. CSV terpisah (mitigation_events_s2td.csv), kolom IDENTIK dengan baseline:
    ts_epoch,ts_iso,event,dpid,src_ip,rate_pps,window_sec,threshold,action,
    ban_sec. Kolom 'threshold' diisi ambang EFEKTIF saat deteksi (setelah
    lantai, lihat S8), dan 'window_sec' = T_poll. Parser/analisis yang sama
    dapat dipakai ulang untuk perbandingan.
S8. Ambang trigger = max(k_auto*mu, TRIGGER_FLOOR) dengan default floor =
    T_VERIFY. Lantai absolut ini menutup celah adaptif murni: saat jaringan
    idle, mu meluruh ke 0 (EWMA atas sampel 0) sehingga ambang k*mu ~ 0 dan
    trafik sepele (LLDP/ARP 1-2 pps) memicu Tahap 2 - terlihat di CSV lama
    sebagai threshold=0.0 dan di log sebagai "TRIGGER agg=1.0 > 3.0*0.0".
    Default floor = T_VERIFY dipilih agar agresivitas Tahap 1 sejalan dengan
    gerbang verifikasi Tahap 2: pingAll (~40 pps agregat) tidak lagi memicu,
    sementara flood >= 100 pps tetap terpicu (agg mencakup balasan victim,
    jadi ~2x rate serangan). Floor dapat di-override via S2TD_TRIGGER_FLOOR.

KETERBATASAN YANG DIAKUI
========================
- Spoofed source acak: tiap IP muncul sekali -> tidak mencapai T_confirm
  (sama seperti baseline; agregasi subnet di luar scope).
- Proteksi victim masih eksplisit via env (S6); auto-learn (mis. rasio
  SYN/SYN-ACK) adalah future work. Default 10.0.0.5 = victim topologi fase 1;
  untuk scale50 (victim 10.0.0.51) WAJIB override S2TD_PROTECTED_IPS.
- Registry datapath sudah multi-switch, teruji 1 switch.
"""

import csv
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                        DEAD_DISPATCHER, set_ev_cls)
from os_ken.ofproto import ofproto_v1_3
from os_ken.lib import hub
from os_ken.lib.packet import (packet, ethernet, ether_types, ipv4)

# ========================== KONFIGURASI ==================================
# Semua via env mengikuti pola RATE_THRESHOLD di baseline: replayable tanpa
# ubah kode, dan nilai aktual tercatat di baris log startup (bukti eksperimen).
T_POLL = float(os.environ.get('S2TD_T_POLL', '1.0'))       # interval polling
ALPHA = float(os.environ.get('S2TD_ALPHA', '0.3'))        # bobot EWMA
K_AUTO = float(os.environ.get('S2TD_K_AUTO', '3.0'))      # ambang adaptif
T_VERIFY = float(os.environ.get('S2TD_T_VERIFY', '50'))   # ambang per-src pps
# S8: lantai absolut ambang trigger Tahap 1. Default = T_VERIFY (lihat S8).
# Tanpa lantai, saat idle mu -> 0 membuat ambang -> 0 (CSV lama: threshold=0.0).
TRIGGER_FLOOR = float(os.environ.get('S2TD_TRIGGER_FLOOR', str(T_VERIFY)))
T_CONFIRM = int(os.environ.get('S2TD_T_CONFIRM', '2'))     # interval berturut
TOP_N = int(os.environ.get('S2TD_TOP_N', '5'))             # kandidat per poll
WARMUP_POLLS = int(os.environ.get('S2TD_WARMUP_POLLS', '3'))  # poll belajar
BAN_DURATION_SEC = int(os.environ.get('S2TD_BAN_SEC', '15'))  # = baseline
DROP_PRIORITY = int(os.environ.get('S2TD_DROP_PRIORITY', '100'))  # = baseline
FWD_PRIORITY = 1                          # forwarding: di atas table-miss(0)
IDLE_TIMEOUT = int(float(os.environ.get('S2TD_IDLE_TIMEOUT', '10')))
CLEANUP_INTERVAL = 30     # buang state basi tiap 30 detik (ikuti baseline)

# S6: IP yang tidak boleh di-ban (server/victim). Koma-pisah via env agar
# topologi lain (mis. scale50, victim 10.0.0.51) cukup override tanpa edit kode.
PROTECTED_IPS = {ip.strip() for ip in
                 os.environ.get('S2TD_PROTECTED_IPS', '10.0.0.5').split(',')
                 if ip.strip()}

# S7: file TERPISAH dari mitigation_events.csv milik baseline (kolom sama).
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MITIGATION_LOG = os.environ.get(
    'S2TD_LOG', os.path.join(_PROJECT_ROOT, 'results',
                             'mitigation_events_s2td.csv'))


class DDoSGuardS2TD(app_manager.OSKenApp):
    """Controller S2TD: statistik-polling + verifikasi dua-tahap (lihat modul)."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSGuardS2TD, self).__init__(*args, **kwargs)

        # ---- forwarding state (L2 learning, seperti l2_switch.py) ----
        self.mac_to_port = {}   # {dpid: {mac: port}}

        # ---- registry switch (multi-switch ready; baseline single-switch) --
        self.datapaths = {}     # {dpid: datapath}, via EventOFPStateChange

        # ---- Tahap 1 state ----
        self._mu = None         # EWMA baseline; None = belum ada sampel
        self._eff_threshold = TRIGGER_FLOOR  # ambang efektif poll terakhir (S8)
        self._poll_count = 0
        self._last_poll_ts = None

        # ---- Tahap 2 state ----
        # counter mentah poll sebelumnya: {(dpid,prio,src,dst): packet_count}
        self._prev_counts = {}
        self._flow_last_seen = {}   # kunci yang sama -> monotonic terakhir
        self._src_consec = defaultdict(int)  # {src_ip: poll berturut > T_VERIFY}
        self._protect_flag = set()  # src proteksi yang sudah diperingatkan
        self.banned_until = {}      # {src_ip: monotonic kedaluwarsa}

        self._last_cleanup = time.monotonic()

        os.makedirs(os.path.dirname(MITIGATION_LOG), exist_ok=True)
        if not os.path.exists(MITIGATION_LOG):
            with open(MITIGATION_LOG, 'w', newline='') as f:
                csv.writer(f).writerow(
                    ['ts_epoch', 'ts_iso', 'event', 'dpid', 'src_ip',
                     'rate_pps', 'window_sec', 'threshold',
                     'action', 'ban_sec'])

        self.logger.info(
            'S2TD aktif | T_poll=%.1fs alpha=%.2f k_auto=%.1f floor=%.0fpps '
            'T_verify=%.0fpps T_confirm=%d top-N=%d warmup=%d ban=%ds '
            'protected=%s | log=%s',
            T_POLL, ALPHA, K_AUTO, TRIGGER_FLOOR, T_VERIFY, T_CONFIRM, TOP_N,
            WARMUP_POLLS, BAN_DURATION_SEC, sorted(PROTECTED_IPS),
            MITIGATION_LOG)

        # Spawn PALING AKHIR (pelajaran dead-code dari baseline: tak ada kode
        # __init__ yang boleh tertinggal setelah spawn loop tak berujung).
        hub.spawn(self._poll_loop)

    # ------------------------------------------------------------------
    # TAHAP 1 (paruh 1): pemicu polling periodik
    # ------------------------------------------------------------------
    def _poll_loop(self):
        """Kirim SATU FlowStatsRequest per switch tiap T_poll (S1).

        Sengaja manual loop + hub.sleep (bukan spawn_periodic): pola yang sama
        dengan _stats_loop baseline, kompatibel antar versi os-ken.
        send_msg dari green thread aman: datapath antre ke socket hub yang sama.
        """
        while True:
            hub.sleep(T_POLL)
            for dpid, dp in list(self.datapaths.items()):
                try:
                    parser = dp.ofproto_parser
                    ofp = dp.ofproto
                    # table_id=ALL eksplisit (default arg bisa berarti tabel 0
                    # saja di sebagian versi): satu balasan mencakup table-miss
                    # + forwarding + drop rule sehingga agregat = total switch.
                    req = parser.OFPFlowStatsRequest(
                        dp, 0, ofp.OFPTT_ALL, ofp.OFPP_ANY, ofp.OFPG_ANY)
                    dp.send_msg(req)
                except Exception as e:  # switch mati di tengah poll
                    self.logger.debug('poll dpid=%s gagal: %s', dpid, e)

    # ------------------------------------------------------------------
    # SWITCH SETUP + REGISTRY
    # ------------------------------------------------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Registry datapath: TAHAN untuk multi-switch (baseline: 1 switch).

        Tanpa ini controller hanya kenal switch terakhir (keterbatasan yang
        diakui baseline); di sini setiap switch yang handshake didaftar dan
        yang mati dikeluarkan agar poll tidak bocor ke koneksi basi.
        """
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.datapaths[dp.id] = dp
                self.logger.info('Switch %s terdaftar untuk polling S2TD',
                                 dp.id)
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                del self.datapaths[dp.id]
                self.logger.info('Switch %s keluar, dihapus dari polling',
                                 dp.id)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Table-miss identik baseline: semua paket tak dikenal -> controller.

        Bedanya: paket berikutnya dari pasangan IP yang sama akan match flow
        forwarding (FWD_PRIORITY) sehingga TIDAK lagi packet-in - inilah
        sumber penghematan CPU S2TD (keputusan arsitektur di docstring modul).
        """
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
    # FORWARDING + FLOW INSTALL (bukan deteksi: deteksi murni dari stats)
    # ------------------------------------------------------------------
    def packet_in_handler(self, ev):
        """HANYA forwarding + pasang flow (sengaja tanpa logika deteksi).

        Alasan (inti klaim efisiensi): hot-path packet-in harus semurah
        mungkin; seluruh keputusan deteksi pindah ke reply stats 1/detik.
        """
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip4 = pkt.get_protocol(ipv4.ipv4)
        # Pasang flow HANYA untuk IPv4 unicast yang port keluarnya sudah
        # diketahui: match (src_ip, dst_ip) memberi counter per pasangan IP
        # yang dibutuhkan Tahap 2. Flood/broadcast/ARP tetap packet-out saja
        # (tidak di-cache) agar flow table tidak dipenuhi sampah satu-paket.
        if ip4 is not None and out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ipv4_src=ip4.src, ipv4_dst=ip4.dst)
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                 actions)]
            mod = parser.OFPFlowMod(
                datapath=dp, priority=FWD_PRIORITY, match=match,
                instructions=inst, idle_timeout=IDLE_TIMEOUT,
                buffer_id=msg.buffer_id)
            dp.send_msg(mod)
            # Paket ter-buffer diteruskan switch MELALUI flow baru (masuk
            # counter): tidak perlu packet-out terpisah (pola l2_switch.py).
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                return

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data))

    # Tanpa decorator @ di sini agar jelas: pendaftaran handler di bawah
    # (dipisah supaya blok Tahap 2 mudah ditemukan saat sidang). Fungsional
    # identik dengan @set_ev_cls di atas definisi (pola baseline).
    packet_in_handler = set_ev_cls(ofp_event.EventOFPPacketIn,
                                   MAIN_DISPATCHER)(packet_in_handler)

    # ------------------------------------------------------------------
    # TAHAP 1 (paruh 2) + TAHAP 2: reply stats -> EWMA -> verifikasi
    # ------------------------------------------------------------------
    @staticmethod
    def _match_field(match, field):
        """Ambil satu field OFPMatch, None bila tidak ada.

        try/except (bukan .get) karena perilaku akses field berbeda antar
        versi parser; yang pasti ada hanyalah match['in_port'] pada packet-in
        (terbukti di baseline) - sisanya diperlakukan opsional.
        """
        try:
            return match[field]
        except Exception:
            return None

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Satu balasan stats -> Tahap 1 (agregat+EWMA) -> Tahap 2 (suspect).

        Dijalankan di event loop controller; komputasi O(jumlah flow) yang
        kecil (topologi PoC: belasan flow) sehingga tidak memblokir hub.
        dt DIUKUR (monotonic), bukan diasumsikan = T_poll, agar rate akurat
        walau scheduling green thread bergeser saat controller sibuk.
        """
        dp = ev.msg.datapath
        dpid = dp.id
        now_mono = time.monotonic()
        dt = (now_mono - self._last_poll_ts) if self._last_poll_ts else T_POLL
        if dt <= 0:
            dt = T_POLL
        self._last_poll_ts = now_mono
        self._poll_count += 1
        self._cleanup_state(now_mono)

        agg_delta = 0
        src_delta = defaultdict(int)   # paket interval ini per src_ip
        for stat in ev.msg.body:
            src = self._match_field(stat.match, 'ipv4_src')
            dst = self._match_field(stat.match, 'ipv4_dst')
            key = (dpid, stat.priority, src or '', dst or '')
            cur = stat.packet_count
            prev = self._prev_counts.get(key)
            # S5: flow baru / counter reset (cur < prev) -> delta = cur.
            # Untuk flow serangan yang aktif terus, kasus ini jarang (tidak
            # pernah idle-timeout); untuk flow legit yang baru lahir, cur
            # kecil sehingga tidak bisa memicu T_verify sendirian.
            delta = (cur - prev) if (prev is not None and cur >= prev) else cur
            self._prev_counts[key] = cur
            self._flow_last_seen[key] = now_mono
            if stat.priority == DROP_PRIORITY:
                continue               # S4: trafik termitigasi tak dihitung
            agg_delta += delta
            if src:
                src_delta[src] += delta  # table-miss (src None) -> agregat saja

        agg_rate = agg_delta / dt

        # ---- Tahap 1: EWMA ----
        # PERBAIKAN (hasil review): triggered diinisialisasi False DULU.
        # Poll pertama (mu masih None) hanya menginisialisasi baseline, tidak
        # boleh memicu Tahap 2. Tanpa baris ini -> UnboundLocalError di reply
        # stats pertama karena cabang `if self._mu is None` tidak menyentuh
        # variabel triggered yang dipakai di bawah.
        triggered = False
        if self._mu is None:
            self._mu = agg_rate        # sampel pertama = baseline awal
        # TAHAP A (P1) / S8: ambang EFEKTIF = max(k_auto*mu, TRIGGER_FLOOR).
        # Lantai absolut mencegah ambang mendekati 0 saat idle (mu meluruh ke
        # 0 karena EWMA atas sampel 0). Guard lama "mu==0 dan agg==0" menjadi
        # redundan: dengan lantai, agg=0 tidak pernah > floor (floor >= 0).
        eff_threshold = max(K_AUTO * self._mu, TRIGGER_FLOOR)
        self._eff_threshold = eff_threshold   # dipakai CSV (S7) & log TRIGGER
        if (self._poll_count > WARMUP_POLLS
                and agg_rate > eff_threshold):
            triggered = True
        # S2: mu HANYA belajar dari sampel normal (tak-terpicu). Sampel
        # serangan tidak boleh mencemari baseline.
        if not triggered:
            self._mu = ALPHA * agg_rate + (1 - ALPHA) * (self._mu or 0.0)

        if self._poll_count <= WARMUP_POLLS:
            return                     # masa belajar: tidak ada aksi
        if self._poll_count % 5 == 0:
            self.logger.info('S2TD POLL dpid=%s agg=%.1fpps mu=%.1f',
                             dpid, agg_rate, self._mu)
        if not triggered:
            # S3 (ketat): poll tak-terpicu me-reset rantai konsekutif.
            for s in list(self._src_consec):
                self._src_consec[s] = 0
            self._protect_flag.clear()
            return

        self.logger.info('S2TD TRIGGER dpid=%s agg=%.1fpps > thr=%.1f '
                         '(k*mu=%.1f*%.1f, floor=%.0f) -> Tahap 2',
                         dpid, agg_rate, self._eff_threshold, K_AUTO,
                         self._mu, TRIGGER_FLOOR)

        # ---- Tahap 2: ranking top-N + konfirmasi konsekutif ----
        ranked = sorted(src_delta.items(), key=lambda kv: -kv[1])[:TOP_N]
        active = set()
        for src, pkts in ranked:
            if now_mono < self.banned_until.get(src, 0):
                continue               # sedang di-ban: biarkan kedaluwarsa
            active.add(src)
            rate = pkts / dt
            if rate <= T_VERIFY:
                self._src_consec[src] = 0
                continue
            self._src_consec[src] += 1
            n = self._src_consec[src]
            self.logger.info('S2TD VERIFY dpid=%s src=%s rate=%.1fpps > '
                             'T_verify=%.0f (konsekutif %d/%d)',
                             dpid, src, rate, T_VERIFY, min(n, T_CONFIRM),
                             T_CONFIRM)
            if n < T_CONFIRM:
                continue
            if src in PROTECTED_IPS:
                # S6: penuhi kriteria tapi korban/server -> JANGAN ban; catat
                # sekali per siklus agar log tidak banjir tiap poll.
                if src not in self._protect_flag:
                    self._protect_flag.add(src)
                    self.logger.warning(
                        'S2TD SKIP: %s memenuhi kriteria namun diproteksi '
                        '(kemungkinan balasan server) -> tidak di-ban', src)
                self._src_consec[src] = 0
                continue
            self._install_drop(dp, src)
            self.banned_until[src] = now_mono + BAN_DURATION_SEC
            self._log_event(dpid, src, rate)
            self._src_consec[src] = 0
        for s in list(self._src_consec):
            if s not in active and self._src_consec[s] != 0:
                self._src_consec[s] = 0

    # ------------------------------------------------------------------
    # MITIGASI (identik baseline agar perbandingan adil) + housekeeping
    # ------------------------------------------------------------------
    def _install_drop(self, datapath, src_ip):
        """Flow DROP per-src: match + timeout SAMA PERSIS dengan baseline.

        Disamakan sengaja: yang dibandingkan adalah ALGORITME DETEKSI
        (kapan & siapa yang di-ban), bukan bentuk rule mitigasinya.
        """
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_src=src_ip)
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=DROP_PRIORITY, match=match,
            instructions=[],                       # tanpa action = DROP
            hard_timeout=int(BAN_DURATION_SEC)))
        self.logger.warning('S2TD MITIGASI: DROP rule terpasang utk %s '
                            '(hard_timeout=%ds)', src_ip, BAN_DURATION_SEC)

    def _log_event(self, dpid, src_ip, rate):
        """CSV S2TD: 10 kolom SAMA dengan baseline (S7).

        Beda isi: event='S2TD_DETECT_DROP' (identitas algoritme untuk analisis
        gabungan), threshold = ambang EFEKTIF max(k_auto*mu, floor) saat
        deteksi (baseline: threshold statis; TAHAP A: bukan lagi 0.0 saat
        mu jenuh nol), window_sec = T_poll.
        """
        now = time.time()
        with open(MITIGATION_LOG, 'a', newline='') as f:
            csv.writer(f).writerow(
                [f'{now:.3f}',
                 datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
                 'S2TD_DETECT_DROP', f'{dpid:#x}', src_ip, f'{rate:.1f}',
                 f'{T_POLL:.1f}', f'{self._eff_threshold:.1f}',
                 'DROP', BAN_DURATION_SEC])

    def _cleanup_state(self, now):
        """Buang state basi agar memori datar (pola baseline _cleanup_state)."""
        if now - self._last_cleanup < CLEANUP_INTERVAL:
            return
        self._last_cleanup = now
        stale = [k for k, t in self._flow_last_seen.items()
                 if now - t > CLEANUP_INTERVAL]
        for k in stale:
            self._prev_counts.pop(k, None)
            del self._flow_last_seen[k]
        for s in [s for s, c in self._src_consec.items() if c == 0]:
            del self._src_consec[s]
        self.banned_until = {ip: t for ip, t in self.banned_until.items()
                             if t > now}
