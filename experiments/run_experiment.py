#!/usr/bin/env python3
"""
Runner Eksperimen - Skenario Uji Deteksi & Mitigasi DDoS pada SDN

Skripsi S1 Teknik Komputer - Dionisius

SKENARIO (dijalankan TERPISAH, satu proses per skenario)
========================================================
  baseline : hanya trafik legitimate (ping h2..h{n_iot+1} -> victim). Tanpa
              serangan. Tujuan: garis dasar CPU & bukti tidak ada false positive.
  single   : flooding murni dari h1 (attacker) -> victim, tanpa trafik legit.
              Tujuan: ukur waktu deteksi & efektivitas mitigasi murni.
  mixed    : flooding h1 -> victim BERSAMAAN dengan trafik legitimate.
              Tujuan: ukur false positive rate (host legit ke-block / loss).
  flash_crowd : trafik legitimate BERLEBIH (burst iperf3 UDP dari host legit,
              rate ~RATE_THRESHOLD) menyerupai DDoS namun BUKAN serangan.
              Tujuan: uji apakah detector salah mengklasifikasikan trafik
              wajar sebagai serangan (false positive / FPR).
  threshold_sweep : sweep nilai RATE_THRESHOLD (--thresholds) untuk memetakan
              TPR (dari 'mixed') vs FPR (dari 'flash_crowd') -> data ROC.

METRIK YANG DICATAT
===================
1. Waktu deteksi   : jeda antara flood/burst pertama dikirim sampai flow
                      DROP (priority=100) terlihat pertama kali di switch.
                      Diukur dengan polling `ovs-ofctl dump-flows` tiap 0.2s.
2. Jumlah drop rule: maksimum rule DROP simultan + total event mitigasi.
3. CPU & memori controller : disampling tiap 0.5s via psutil.
4. False positive  : (a) % loss ping host legitimate selama eksperimen,
                      (b) jumlah ban yg mengenai IP selain attacker (fp_bans),
                      dilaporkan sbg fpr_pct di terminal & CSV.

OUTPUT (folder results/)
========================
- exp_summary.csv                  : satu baris per run (append), + kolom
                                      is_legitimate & fpr_pct.
- threshold_sweep_summary.csv      : hasil sweep (threshold_value,tpr,fpr,avg_detection_time).
- exp_timeseries_<scenario>_<ts>.csv : sampel waktu (t, cpu, mem, n_rules).
- controller_<scenario>_<ts>.log   : log controller utk run ini (bukti).

CATATAN: logika DETEKSI di controller/ddos_guard.py TIDAK diubah; threshold
hanya diteruskan via env RATE_THRESHOLD agar bisa di-sweep. flash_crowd BUTUH
iperf3 (sudo apt install iperf3).

CARA PAKAI (di dalam venv, sebagai root via sudo)
=================================================
  sudo ~/ddos-venv/bin/python experiments/run_experiment.py --scenario baseline
  sudo ~/ddos-venv/bin/python experiments/run_experiment.py --scenario single
  sudo ~/ddos-venv/bin/python experiments/run_experiment.py --scenario mixed
  sudo ~/ddos-venv/bin/python experiments/run_experiment.py --scenario flash_crowd --legit-count 8
  sudo ~/ddos-venv/bin/python experiments/run_experiment.py --scenario threshold_sweep --legit-count 8 --thresholds 50,100,150,200,250,300

MODE PERBANDINGAN ALGORITME (Tahap C, --algo)
============================================
Menambahkan --algo memilih controller yang dijalankan dan file CSV-nya:
  baseline -> controller/ddos_guard.py         results/mitigation_events.csv
  s2td     -> controller/ddos_guard_s2td.py    results/mitigation_events_s2td.csv
  entropy  -> controller/ddos_guard_entropy.py results/mitigation_events_entropy.csv

Hasil mode ini ditulis ke file TERPISAH `results/exp_summary_compare.csv`
(kolom diawali `algo` dan `flood_rate_pps`) sehingga `exp_summary.csv` lama
tidak pernah tercampur skema baru. Tanpa --algo, perilaku runner PERSIS
seperti sebelumnya (controller baseline, exp_summary.csv).

  sudo ~/ddos-venv/bin/python experiments/run_experiment.py \
       --scenario mixed --algo baseline --rate 500 --repeats 3
  sudo ~/ddos-venv/bin/python experiments/run_experiment.py \
       --scenario mixed --algo s2td     --rate 500 --repeats 3
  sudo ~/ddos-venv/bin/python experiments/run_experiment.py \
       --scenario mixed --algo entropy  --rate 500 --repeats 3

DEFINISI METRIK (SAMA untuk ketiga algoritme)
=============================================
- detection_time_s : jeda dari paket flood PERTAMA dikirim (penanda
  '[flood] started' dari flood_scapy.py) sampai rule DROP priority=100
  PERTAMA dipasang. Mode compare memakai selisih JAM DINDING antara t0
  (saat penanda terlihat) dan ts_iso baris event pertama di CSV algoritme,
  sehingga resolusinya milidetik dan identik untuk ketiga algoritme.
  Kolom detection_time_poll_s menyimpan hasil polling `ovs-ofctl` 0,2 s
  sebagai pembanding/audit (angka inilah yang dipakai versi Tahap C).
- detected_rate_pps : laju yang dicatat algoritme pada event pertama
  (kolom rate_pps di CSV masing-masing). TIDAK boleh dibandingkan langsung
  antar algoritme karena cara pengukurannya berbeda (S2TD: counter switch
  satu interval penuh; entropi: isi window saat evaluasi, bisa setengah).
- throughput_per_cpu : paket/detik yang BENAR-BENAR terkirim
  (flood_actual_pps, dari baris akhir flooder) dibagi CPU rata-rata pada
  FASE SERANGAN (cpu_attack_avg_pct), bukan rata-rata seluruh run. Alasannya:
  setelah rule DROP aktif controller sengaja idle, sehingga rata-rata
  seluruh run mengencerkan beban dan membuat algoritme yang cepat mem-ban
  tampak lebih "hemat CPU" daripada yang sebenarnya. Satuan: pps per 1% CPU.
  Bila flood_actual_pps tidak tersedia, dipakai flood_rate_pps (nominal).
"""

import argparse
import csv
import os
import re
import socket
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

import psutil

# ---- path project -------------------------------------------------------
EXPERIMENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(EXPERIMENT_DIR)
sys.path.insert(0, os.path.join(PROJECT_ROOT, 'topology'))

from basic_topo import DDosTopo                      # noqa: E402

from mininet.net import Mininet                      # noqa: E402
from mininet.node import RemoteController, OVSSwitch # noqa: E402
from mininet.link import TCLink                      # noqa: E402
from mininet.log import setLogLevel                  # noqa: E402

RESULTS_DIR = os.path.join(PROJECT_ROOT, 'results')
MITIGATION_CSV = os.path.join(RESULTS_DIR, 'mitigation_events.csv')

# -------------------------------------------------------------------------
# TAHAP C: peta algoritme -> (file controller, file CSV event, label).
# Satu sumber kebenaran: mengganti nama file hanya perlu di sini. CSV tiap
# algoritme SUDAH ada (dan berisi riwayat Tahap A/B); runner tidak menimpa,
# hanya menghitung selisih baris sebelum vs sesudah run.
# -------------------------------------------------------------------------
ALGO_CONFIG = {
    'baseline': {
        'controller': 'ddos_guard.py',
        'csv': os.path.join(RESULTS_DIR, 'mitigation_events.csv'),
        'label': 'Baseline (threshold per-IP)',
    },
    's2td': {
        'controller': 'ddos_guard_s2td.py',
        'csv': os.path.join(RESULTS_DIR, 'mitigation_events_s2td.csv'),
        'label': 'S2TD (dua tahap, flow caching)',
    },
    'entropy': {
        'controller': 'ddos_guard_entropy.py',
        'csv': os.path.join(RESULTS_DIR, 'mitigation_events_entropy.csv'),
        'label': 'Entropy (Shannon, tanpa flow caching)',
    },
}

# CSV KHUSUS mode --algo. Terpisah dari exp_summary.csv supaya skema lama
# (tanpa kolom algo/flood_rate_pps) tidak pernah tercampur.
COMPARE_CSV = os.path.join(RESULTS_DIR, 'exp_summary_compare.csv')

ATTACKER_IP = '10.0.0.1'      # h1 = attacker (konsisten dgn topologi)
# Threshold deteksi dibaca dari env (SAMA yg dipakai ddos_guard.py) agar
# flash_crowd / threshold_sweep tidak me-hardcode ulang nilainya.
THRESHOLD = int(os.environ.get('RATE_THRESHOLD', '25'))


# =========================================================================
# UTILITAS
# =========================================================================
def wait_port(port, timeout=30):
    """Tunggu sampai controller listen di port tertentu."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


# Lock utk akses ke shell node Mininet: Node.cmd() TIDAK thread-safe
# (ada assert internal yang meledak jika dua thread memanggil bersamaan).
# Dipakai oleh sampler-thread DAN loop deteksi di main thread.
_ovs_lock = threading.Lock()


def count_drop_rules(s1):
    """Hitung flow DROP (priority=100) yang aktif di switch saat ini."""
    with _ovs_lock:
        out = s1.cmd('ovs-ofctl -O OpenFlow13 dump-flows s1')
    return out.count('priority=100')


def parse_ping_loss(popen):
    """Ambil % loss dari output `ping` yang sudah selesai."""
    out, _ = popen.communicate(timeout=30)
    text = out.decode(errors='replace') if isinstance(out, bytes) else out
    m = re.search(r'([\d.]+)% packet loss', text)
    return float(m.group(1)) if m else float('nan')


def count_mitigation_rows(csv_path=None):
    """Baca jumlah baris event (kolom rate_pps) pada CSV algoritme aktif.

    Parameter csv_path wajib diberikan di mode --algo: tanpa itu fungsi
    membaca CSV baseline dan event S2TD/entropi tidak akan pernah terhitung.
    """
    path = csv_path or MITIGATION_CSV
    if not os.path.exists(path):
        return 0, []
    with open(path) as f:
        rows = [line for line in f if line.strip()]
    return len(rows) - 1, rows[1:]   # -1: header


# =========================================================================
# TAHAP C: UTILITAS MODE PERBANDINGAN ALGORITME
# =========================================================================
# Kolom file compare. Sengaja STABIL (tidak ada kolom per-host dinamis) agar
# header tidak berubah ketika --legit-count berbeda antar run. Nilai loss
# per-host tetap tersedia di exp_summary.csv mode lama bila diperlukan.
COMPARE_FIELDS = [
    'ts_iso',                 # waktu run (UTC)
    'algo',                   # baseline | s2td | entropy
    'scenario',               # baseline | single | mixed | flash_crowd
    'repeat',                 # indeks pengulangan (1..N)
    'flood_rate_pps',         # rate NOMINAL yang diminta (--rate), 0 = unpaced
    'flood_actual_pps',       # rate yang BENAR-BENAR terkirim (baris akhir flooder)
    'detection_time_s',       # definisi sama utk ketiga algoritme (lihat docstring)
    'detection_time_poll_s',  # nilai polling ovs-ofctl (cadangan/audit, kasar)
    'detected_rate_pps',      # laju yang dicatat algoritme saat event pertama
    'drops_max_concurrent',   # maksimum rule DROP simultan
    'drops_total_events',     # jumlah event mitigasi milik run ini
    'fp_bans',                # ban yang mengenai IP selain attacker
    'fpr_pct',                # fp_bans / jumlah host legitimate * 100
    'legit_loss_mean_pct',    # rata-rata packet loss host legitimate
    'legit_loss_max_pct',     # loss terburuk (dipakai sbg ambang 1% di Tahap D)
    'cpu_avg_pct',            # CPU controller rata-rata SELURUH run (warmup..post)
    'cpu_max_pct',            # CPU controller puncak seluruh run
    'cpu_attack_avg_pct',     # CPU rata-rata HANYA fase serangan
    'cpu_attack_max_pct',     # CPU puncak HANYA fase serangan
    'mem_avg_pct',            # memori controller rata-rata
    'throughput_per_cpu',     # flood_actual_pps / cpu_attack_avg_pct
]


def append_compare_row(row):
    """Append satu baris ke exp_summary_compare.csv dengan aman.

    Jika file sudah ada tetapi header-nya berbeda (mis. skema berubah saat
    pengembangan), file lama diarsipkan lebih dulu alih-alih mencampur dua
    skema dalam satu CSV - data lama tidak hilang, dan penulisan tidak error
    karena DictWriter menolak field yang tidak dikenal.
    """
    has_file = os.path.exists(COMPARE_CSV) and os.path.getsize(COMPARE_CSV) > 0
    if has_file:
        with open(COMPARE_CSV, newline='') as f:
            header = next(csv.reader(f), [])
        if header != COMPARE_FIELDS:
            stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup = COMPARE_CSV.replace(
                '.csv', f'_skema-lama_{stamp}.csv')
            os.replace(COMPARE_CSV, backup)
            print(f'[compare] header lama diarsipkan -> {backup}')
            has_file = False
    with open(COMPARE_CSV, 'a', newline='') as f:
        w = csv.DictWriter(f, fieldnames=COMPARE_FIELDS,
                           extrasaction='ignore')
        if not has_file:
            w.writeheader()
        w.writerow(row)


def wait_flood_start(flood_log_path, timeout=15.0, poll=0.02):
    """Tunggu penanda '[flood] started' dari flood_scapy.py.

    Return True bila penanda terlihat. Menetapkan t0 pengukuran detection_time
    TEPAT saat paket pertama siap dikirim: waktu import scapy (~0,5-1 s di
    WSL) dan pembuatan raw socket tidak lagi ikut terhitung, untuk SEMUA
    algoritme. Tanpa penanda (mis. flooder versi lama), runner jatuh kembali
    ke perilaku lama (t0 = saat proses diluncurkan).
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with open(flood_log_path) as f:
                if '[flood] started' in f.read():
                    return True
        except OSError:
            pass
        time.sleep(poll)
    return False


def flood_start_epoch(flood_log_path):
    """Ambil t0_epoch (jam dinding) dari baris penanda flooder.

    Flooder mencetak `t0_epoch=<epoch>` tepat sebelum paket pertama. Nilai ini
    adalah acuan t0 yang benar: tanpa itu, t0 runner akan bergeser sebesar
    jeda pembacaan berkas (polling 20 ms + latensi drvfs), yang cukup besar
    untuk mengaburkan algoritme cepat (baseline bisa < 50 ms).

    Return float epoch, atau None bila penanda versi lama / berkas tak ada.
    """
    try:
        with open(flood_log_path) as f:
            text = f.read()
    except OSError:
        return None
    m = re.search(r'\[flood\] started[^\n]*?t0_epoch=([\d.]+)', text)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None


def parse_flood_actual(flood_log_path):
    """Ambil achieved rate dari baris akhir flooder: 'terkirim=.. (~402 pps)'.

    Return string angka pps (mis. '402') atau '' bila run dihentikan sebelum
    flooder sempat mencetak ringkasan.
    """
    try:
        with open(flood_log_path) as f:
            text = f.read()
    except OSError:
        return ''
    m = re.search(r'\[flood\].*?~([\d.]+)\s*pps', text, re.S)
    return m.group(1) if m else ''


def first_event_epoch(rows):
    """Ambil timestamp ISO (kolom 2) dari baris event mitigasi pertama.

    Skema 10 kolom ketiga algoritme sama: ts_epoch, ts_iso, event, dpid, ...
    Nilai ini ditulis controller TEPAT setelah rule DROP dipasang, sehingga
    bisa dipakai sebagai penanda "mitigasi aktif" berpresisi milidetik -
    jauh lebih halus daripada polling ovs-ofctl 0,2 s.
    """
    if not rows:
        return None
    try:
        parts = next(csv.reader([rows[0]]))
        return datetime.fromisoformat(parts[1])
    except (IndexError, ValueError, StopIteration):
        return None


def precise_detection_time(rows, t_flood_wall, max_s=120.0):
    """detection_time presisi = ts event controller - t0 flood (jam dinding).

    Return None bila tidak bisa dihitung (tidak ada event, t0 hilang, atau
    selisih negatif/terlalu besar karena jam tidak sinkron). Pemanggil
    kemudian memakai hasil polling sebagai cadangan.

    Kenapa ini lebih baik daripada polling: polling `dump-flows` hanya bisa
    menyatakan "rule sudah ada saat saya memeriksa", sehingga hasilnya
    terkuantisasi ~0,2 s DAN punya lantai ~0,01-0,05 s (durasi satu
    pemanggilan ovs-ofctl). Dua artefak itu sempat membuat baseline tercatat
    0,01 s pada satu run dan 0,22 s pada run lain padahal perilakunya sama.
    """
    event_ts = first_event_epoch(rows)
    if event_ts is None or t_flood_wall is None:
        return None
    delta = (event_ts - t_flood_wall).total_seconds()
    if not (0.0 <= delta <= max_s):
        return None
    return delta


def first_event_rate(rows):
    """Ambil kolom rate_pps (indeks 5) dari baris event mitigasi pertama.

    CSV ketiga algoritme memakai skema 10 kolom yang sama, jadi indeks kolom
    ini valid untuk semuanya. Nilainya informatif saja - cara pengukurannya
    berbeda antar algoritme (lihat docstring modul).
    """
    if not rows:
        return ''
    try:
        parts = next(csv.reader([rows[0]]))
        float(parts[5])                  # validasi numerik
        return parts[5]
    except (IndexError, ValueError, StopIteration):
        return ''


def proc_jiffies(pid):
    """Baca total CPU-time proses (utime+stime) satuan jiffies LANGSUNG dari
    /proc - ground truth independen dari psutil. Return None jika proses
    sudah tidak ada."""
    try:
        with open(f'/proc/{pid}/stat') as f:
            # buang bagian "(comm)" yang bisa mengandung spasi
            remainder = f.read().rsplit(') ', 1)[1].split()
        return int(remainder[11]) + int(remainder[12])   # utime + stime
    except (OSError, IndexError, ValueError):
        return None


# =========================================================================
# PERSIAPAN LINGKUNGAN
# =========================================================================
def cleanup_stale_environment():
    """Bunuh sisa proses controller/topologi dari run sebelumnya.

    Run yang crash (exception) meninggalkan osken-manager 'yatim' yang masih
    memegang port 6633. Akibatnya: controller baru gagal bind, atau LEBIH
    BURUK - switch diam-diam tersambung ke controller lama dengan state basi
    (deteksi tampak jalan padahal kode barunya tidak aktif). Karena setiap
    eksperimen selalu menjalankan controllernya sendiri, membersihkan saat
    start adalah perilaku paling aman.
    """
    subprocess.run(['pkill', '-f', 'osken-manager'], capture_output=True)
    subprocess.run(['mn', '-c'], capture_output=True)
    time.sleep(1)


def start_controller(log_path, threshold=None, algo='baseline', extra_env=None):
    """Jalankan osken-manager sebagai subprocess, kembalikan (proc, logfile).

    threshold: bila tidak None, diteruskan ke controller via env
    RATE_THRESHOLD (memungkinkan threshold_sweep tanpa ubah kode detector).
    algo: memilih file controller dari ALGO_CONFIG (Tahap C). Default
    'baseline' -> perilaku lama tetap utuh.
    extra_env: override env tambahan (mis. S2TD_LOG, ENTROPY_PROTECTED_IPS).
    """
    cfg = ALGO_CONFIG[algo]
    # Cari osken-manager RELATIF terhadap interpreter yang menjalankan script.
    venv_bin = os.path.dirname(sys.executable)
    osken_mgr = os.path.join(venv_bin, 'osken-manager')
    if not os.path.isfile(osken_mgr):
        sys.exit(f'ERROR: osken-manager tidak ditemukan di {venv_bin} - '
                  'jalankan dengan python dari venv project!')
    # teruskan environment saat ini + override RATE_THRESHOLD bila diminta
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    if threshold is not None:
        env['RATE_THRESHOLD'] = str(threshold)
    log = open(log_path, 'w')
    proc = subprocess.Popen(
        [osken_mgr, '--ofp-tcp-listen-port', '6633', cfg['controller']],
        cwd=os.path.join(PROJECT_ROOT, 'controller'),
        stdout=log, stderr=subprocess.STDOUT, env=env)
    if not wait_port(6633):
        proc.terminate()
        sys.exit(f'ERROR: controller gagal listen di port 6633 '
                 f'(cek {log_path})')
    # Validasi KRITIS: pastikan yang listen di 6633 benar-benar proses BARU
    # ini, bukan controller yatim dari run sebelumnya. Gejalanya: proses baru
    # mati segera (gagal bind 'address already in use') sementara port tetap
    # listen milik proses lain. Jika terjadi, metrik CPU kita akan mengukur
    # mayat proses (zombie) dan switch dilayani kode/state lama.
    time.sleep(0.5)
    if proc.poll() is not None:
        sys.exit('ERROR: proses controller baru mati segera setelah start '
                 f'(exit code={proc.returncode}). Kemungkinan besar port 6633 '
                 'masih dipegang controller lama. Jalankan manual: '
                 'pkill -f osken-manager && sudo mn -c')
    return proc, log


def build_net(n_iot=3):
    """Bangun topologi (jumlah host legitimate = n_iot)."""
    net = Mininet(topo=DDosTopo(n_iot=n_iot),
                  controller=lambda name: RemoteController(
                      name, ip='127.0.0.1', port=6633),
                  switch=OVSSwitch, link=TCLink,
                  autoSetMacs=True, autoStaticArp=True)
    net.start()
    net.waitConnected(timeout=30)
    time.sleep(2)          # beri waktu table-miss stabil
    return net


def tail_controller_log(log_path, stop_event):
    """Tampilkan baris penting dari log controller secara LIVE ke konsol.

    Tujuan UX: saat eksperimen berjalan, user tetap bisa melihat bukti
    aktivitas controller (STATS / MITIGASI / switch terhubung) tanpa harus
    menjalankan osken-manager manual di terminal terpisah - karena controller
    eksperimen memang dikelola runner dan lognya ditulis ke file.
    """
    import re
    # Tahap C: pola diperluas agar log S2TD (TRIGGER/VERIFY/SKIP) dan
    # entropi (ENTROPY:) juga tampil live. Tidak ada efek pada baseline.
    pattern = re.compile(r'STATS:|MITIGASI|DDoSGuard aktif|terhubung|'
                         r'TRIGGER|VERIFY|SKIP|ENTROPY|S2TD aktif|'
                         r'EntropyGuard aktif')
    with open(log_path) as f:
        f.seek(0, 2)                       # mulai dari akhir file
        while not stop_event.is_set():
            line = f.readline()
            if line:
                if pattern.search(line):
                    print(f'  [ctrl] {line.strip()}')
            else:
                time.sleep(0.3)


# =========================================================================
# EKSPERIMEN UTAMA
# =========================================================================
def run_scenario(scenario, warmup, flood_dur, post, ping_interval,
                 legit_count=3, flash_rate=None, burst_dur=4, threshold=None,
                 algo=None, rate=0.0, repeat=1, subdir=None):
    """Jalankan satu skenario. Return dict ringkasan (legacy) atau baris compare.

    algo=None  -> MODE LAMA: controller baseline, output exp_summary.csv,
                  flood tanpa --rate (secepat mungkin). Perilaku identik
                  dengan sebelum Tahap C.
    algo=<x>   -> MODE PERBANDINGAN: controller sesuai ALGO_CONFIG, output
                  exp_summary_compare.csv, flood diberi --rate (bila > 0),
                  dan detection_time diukur dari penanda '[flood] started'.
    subdir     -> subfolder results/ untuk file bukti (log controller,
                  timeseries, log flood). CSV event & CSV ringkasan tetap di
                  results/ langsung. Default None = perilaku lama.
    """
    # iperf3 wajib untuk flash_crowd; cek sejak awal (sebelum bangun net)
    if scenario == 'flash_crowd' and shutil.which('iperf3') is None:
        sys.exit('ERROR: iperf3 tidak ditemukan. Instal dulu '
                 '(sudo apt install iperf3) di environment WSL.')
    # ---- turunan topologi & threshold ------------------------------------
    # Konvensi (lihat basic_topo.py): h1 attacker, h2..h{n_iot+1} legit,
    # h{n_iot+2} victim.
    victim_id = legit_count + 2
    victim_ip = f'10.0.0.{victim_id}'
    legit_hosts = [f'h{i}' for i in range(2, 2 + legit_count)]
    # flash_crowd: rate burst "setara RATE_THRESHOLD" bila tak di-override
    eff_flash_rate = flash_rate if flash_rate is not None else THRESHOLD

    # ---- Tahap C: algoritme aktif ----------------------------------------
    compare = algo is not None
    algo_name = algo or 'baseline'
    algo_cfg = ALGO_CONFIG[algo_name]
    mitigation_csv = algo_cfg['csv']
    # Env per-algoritme: pastikan CSV yang ditulis = CSV yang dibaca runner,
    # dan IP victim selalu masuk daftar terlindungi (default controller hanya
    # 10.0.0.5; dengan --legit-count lain, victim berpindah alamat).
    algo_env = {}
    if algo_name == 's2td':
        algo_env['S2TD_LOG'] = mitigation_csv
        algo_env['S2TD_PROTECTED_IPS'] = victim_ip
    elif algo_name == 'entropy':
        algo_env['ENTROPY_LOG'] = mitigation_csv
        algo_env['ENTROPY_PROTECTED_IPS'] = victim_ip

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs(RESULTS_DIR, exist_ok=True)
    # Folder bukti terpisah untuk sweep (Tahap D) agar results/ tetap rapi.
    # CSV event & CSV ringkasan TIDAK ikut dipindah.
    aux_dir = os.path.join(RESULTS_DIR, subdir) if subdir else RESULTS_DIR
    os.makedirs(aux_dir, exist_ok=True)

    # WAJIB: bersihkan controller yatim dari run sebelumnya SEBELUM apa pun.
    cleanup_stale_environment()

    # Nama file bukti diberi tag algoritme di mode compare agar run ketiga
    # algoritme (dan repeat) tidak saling menimpa.
    tag = f'{algo_name}_{scenario}' if compare else scenario
    ctrl_log_path = os.path.join(aux_dir, f'controller_{tag}_{ts}.log')
    ts_file = os.path.join(aux_dir, f'exp_timeseries_{tag}_{ts}.csv')
    flood_log_path = os.path.join(aux_dir, f'flood_{tag}_{ts}_r{repeat}.log')

    ctrl_proc, ctrl_log = start_controller(ctrl_log_path, threshold=threshold,
                                           algo=algo_name,
                                           extra_env=algo_env)
    cpu_meter = psutil.Process(ctrl_proc.pid)

    # live-view: ceritakan aktivitas controller ke konsol (STATS/MITIGASI)
    tail_stop = threading.Event()
    tail_thread = threading.Thread(target=tail_controller_log,
                                   args=(ctrl_log_path, tail_stop),
                                   daemon=True)
    tail_thread.start()

    net = build_net(n_iot=legit_count)
    s1 = net.get('s1')
    h1 = net.get('h1')
    victim = net.get(f'h{victim_id}')

    # ---- diff CSV mitigasi (utk hitung event milik run ini saja) ----
    rows_before, _ = count_mitigation_rows(mitigation_csv)

    # ---- mulai sampling CPU/mem + jumlah rule ke timeseries ----
    # Sampler berjalan sebagai BACKGROUND THREAD dari t=0 sehingga mencakup
    # SELURUH fase (warmup + serangan + pemulihan). Versi lama memanggil
    # sampler secara sinkron SETELAH fase serangan selesai -> jendela CPU
    # tinggi saat deteksi tidak sempat terukur (hasil cpu_max 0.0 palsu).
    tsf = open(ts_file, 'w', newline='')
    ts_writer = csv.writer(tsf)
    ts_writer.writerow(['t_rel_s', 'cpu_pct', 'mem_pct', 'jiffies',
                        'drop_rules'])
    cpu_meter.cpu_percent(interval=None)          # priming sample

    t_start = time.monotonic()
    detection_time = None                          # deteksi flood / FP (detik)
    max_rules = 0
    # durasi "serangan": flood (single/mixed) atau burst (flash_crowd)
    attack_dur = (flood_dur if scenario in ('single', 'mixed')
                  else (burst_dur if scenario == 'flash_crowd' else 0))
    stop_at = t_start + warmup + attack_dur + post

    def sampler():
        """Sampling CPU/mem/jiffies/rule tiap 0.5s sampai stop_at."""
        nonlocal max_rules
        # Beri satu interval sebelum sampel pertama. cpu_percent(interval=None)
        # mengukur CPU SEJAK pemanggilan sebelumnya; tanpa jeda ini sampel
        # t=0 menghitung CPU sejak proses lahir (artefak, pernah terbaca 75%)
        # dan mencemari cpu_max.
        time.sleep(0.5)
        while time.monotonic() < stop_at:
            t_rel = time.monotonic() - t_start
            rules = count_drop_rules(s1)
            max_rules = max(max_rules, rules)
            ts_writer.writerow([f'{t_rel:.2f}',
                                f'{cpu_meter.cpu_percent(interval=None):.1f}',
                                f'{cpu_meter.memory_percent():.1f}',
                                proc_jiffies(ctrl_proc.pid),
                                rules])
            time.sleep(0.5)

    sampler_thread = threading.Thread(target=sampler, daemon=True)
    sampler_thread.start()

    # ---- 1. TRAFIK LEGITIMATE (baseline, mixed, flash_crowd) ------------
    # ping terus-menerus dr host legitimate ke victim -> bahan % loss (FPR).
    # Di flash_crowd ini juga yang akan menunjukkan dampak bila detector
    # salah mem-ban trafik legitimate.
    legit_pings = {}
    if scenario in ('baseline', 'mixed', 'flash_crowd'):
        n_pkts = int((warmup + attack_dur + post) / ping_interval)
        for hn in legit_hosts:
            legit_pings[hn] = net.get(hn).popen(
                ['ping', '-c', str(n_pkts), '-i', str(ping_interval),
                 '-W', '1', victim_ip],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # ---- 2. FASE WARMUP -------------------------------------------------
    # (single: idle; baseline/mixed: ping legitimate sudah jalan sejak t=0)

    # ---- 3. FASE SERANGAN / BURST (dimulai tepat di t=warmup) -----------
    flood_proc = None
    flood_out = None
    burst_procs = []
    iperf_srv = None
    t_flood = None
    t_flood_wall = None      # t0 versi jam dinding (mode compare)
    if scenario in ('single', 'mixed'):
        time.sleep(max(0, t_start + warmup - time.monotonic()))
        # Interpreter yg sama dgn runner ini (venv, ada scapy).
        py = sys.executable
        flooder = os.path.join(PROJECT_ROOT, 'traffic', 'flood_scapy.py')
        flood_cmd = [py, flooder, '--target', victim_ip,
                     '--proto', 'tcp', '--port', '80', '--duration',
                     str(flood_dur)]
        if compare:
            # Mode compare: rate eksplisit + stdout flooder DISIMPAN ke file.
            # Dua-duanya dibutuhkan: --rate untuk load sweep (Tahap D) dan
            # output untuk kolom flood_actual_pps (bukti beban nyata).
            if rate > 0:
                flood_cmd += ['--rate', f'{rate:g}']
            flood_out = open(flood_log_path, 'w')
            flood_proc = h1.popen(flood_cmd, stdout=flood_out,
                                  stderr=subprocess.STDOUT)
            # t0 = paket pertama siap dikirim (bukan saat proses diluncurkan),
            # supaya waktu import scapy tidak ikut terhitung.
            if wait_flood_start(flood_log_path):
                t_flood = time.monotonic()
                # t0 versi JAM DINDING: utamakan t0_epoch dari flooder sendiri
                # (bebas bias jeda pembacaan berkas); cadangan: jam sekarang.
                epoch = flood_start_epoch(flood_log_path)
                t_flood_wall = (datetime.fromtimestamp(epoch, timezone.utc)
                                if epoch is not None
                                else datetime.now(timezone.utc))
            else:
                print('  [warn] penanda "[flood] started" tidak terlihat; '
                      'jatuh kembali ke t0 = waktu peluncuran proses')
                t_flood = time.monotonic()
                t_flood_wall = datetime.now(timezone.utc)
        else:
            # Mode lama: perilaku PERSIS seperti sebelumnya.
            flood_proc = h1.popen(flood_cmd,
                                  stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
            t_flood = time.monotonic()            # t0 pengukuran deteksi
        deadline = t_flood + flood_dur + 10
        while time.monotonic() < deadline:
            if count_drop_rules(s1) > 0:
                detection_time = time.monotonic() - t_flood
                break
            time.sleep(0.2)
    elif scenario == 'flash_crowd':
        # Skenario ini MENSIMULASIKAN lonjakan trafik LEGITIMATE (bukan
        # serangan): semua host legit mengirim burst iperf3 UDP bersamaan
        # dgn rate ~RATE_THRESHOLD. Tujuannya: uji apakah detector salah
        # mengklasifikasikan trafik wajar sebagai serangan (false positive).
        time.sleep(max(0, t_start + warmup - time.monotonic()))
        # Server UDP di victim menerima burst dari semua host legit.
        iperf_srv = victim.popen(['iperf3', '-s', '-p', '5201'],
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        time.sleep(1)  # beri server waktu listen sebelum client menembak
        # Burst UDP bersamaan dr semua host legit, rate ~eff_flash_rate pps.
        bps = eff_flash_rate * 1470 * 8  # bit/s (datagram 1470 byte)
        for hn in legit_hosts:
            burst_procs.append(net.get(hn).popen(
                ['iperf3', '-c', victim_ip, '-u', '-p', '5201', '-l', '1470',
                 '-b', f'{int(bps)}', '-t', str(burst_dur)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        t_flood = time.monotonic()
        # Di sini deteksi = waktu pertama rule DROP muncul; artinya ada host
        # legitimate yang salah ke-block -> false positive.
        deadline = t_flood + burst_dur + 10
        while time.monotonic() < deadline:
            if count_drop_rules(s1) > 0:
                detection_time = time.monotonic() - t_flood
                break
            time.sleep(0.2)

    # ---- 4. FASE OBSERVASI AKHIR ----------------------------------------
    # sampler thread berhenti sendiri di stop_at; tunggu sampai tuntas agar
    # seluruh sampel sudah tertulis sebelum ringkasan dihitung.
    sampler_thread.join(timeout=max(0, stop_at - time.monotonic()) + 5)

    # ---- 5. BERESKAN & KUMPULKAN HASIL ----------------------------------
    # ping legitimate dibiarkan selesai sendiri (durasi = durasi eksperimen)
    # supaya ringkasan statistiknya sempat dicetak oleh `ping`.
    if flood_proc and flood_proc.poll() is None:
        flood_proc.terminate()
    if flood_out is not None:
        flood_out.close()
    # flash_crowd: hentikan client burst & server iperf3 (jika masih hidup)
    for bp in burst_procs:
        if bp.poll() is None:
            bp.terminate()
    if iperf_srv and iperf_srv.poll() is None:
        iperf_srv.terminate()

    rows_after, new_rows = count_mitigation_rows(mitigation_csv)
    events_this_run = new_rows[rows_before:]
    fp_bans = sum(1 for r in events_this_run
                  if len(r.split(',')) > 4 and r.split(',')[4] != ATTACKER_IP)

    legit_loss = {}
    for hn, p in legit_pings.items():
        try:
            legit_loss[hn] = parse_ping_loss(p)      # tunggu selesai normal
        except Exception:
            p.terminate()                            # darurat: paksa berhenti
            try:
                legit_loss[hn] = parse_ping_loss(p)
            except Exception:
                legit_loss[hn] = float('nan')

    tsf.close()
    tail_stop.set()                # hentikan live-view controller
    tail_thread.join(timeout=2)
    net.stop()
    ctrl_proc.terminate()
    ctrl_log.close()

    # ---- ringkasan metrik dari timeseries --------------------------------
    with open(ts_file) as f:
        samples = list(csv.DictReader(f))
    cpus = [float(r['cpu_pct']) for r in samples]
    mems = [float(r['mem_pct']) for r in samples]

    # FPR = proporsi host legitimate yang salah di-ban (hanya relevan sbg
    # ukuran false positive; di single/mixed fp_bans normalnya 0).
    n_legit = len(legit_hosts)
    fpr_pct = (fp_bans / n_legit * 100.0) if n_legit else 0.0
    # flash_crowd = trafik legitimate berlebih (label "is_legitimate=True")
    is_legit = (scenario == 'flash_crowd')
    summary = {
        'ts_iso': datetime.now(timezone.utc).isoformat(),
        'scenario': scenario,
        'is_legitimate': f'{is_legit}',
        'warmup_s': warmup,
        'flood_duration_s': (burst_dur if scenario == 'flash_crowd'
                             else (0 if scenario == 'baseline' else flood_dur)),
        'post_s': post,
        'detection_time_s': f'{detection_time:.2f}' if detection_time else '',
        'drops_max_concurrent': max_rules,
        'drops_total_events': len(events_this_run),
        'fp_bans': fp_bans,
        'fpr_pct': f'{fpr_pct:.1f}',
        **{f'{hn}_loss_pct': f'{legit_loss.get(hn, float("nan")):.1f}'
           for hn in legit_hosts},
        'cpu_avg_pct': f'{sum(cpus) / len(cpus):.1f}' if cpus else '',
        'cpu_max_pct': f'{max(cpus):.1f}' if cpus else '',
        'mem_avg_pct': f'{sum(mems) / len(mems):.1f}' if mems else '',
    }

    # ---- TAHAP C: tulis ke CSV compare (skema lama TIDAK disentuh) -------
    if compare:
        actual_pps = parse_flood_actual(flood_log_path) if flood_log_path else ''
        # CPU fase serangan: seluruh sampel dinormalisasi per run akan
        # mengencerkan beban (controller sengaja idle setelah rule DROP
        # terpasang), sehingga angka "throughput per CPU" jadi bias ke
        # algoritme yang cepat mem-ban. Rata-rata fase serangan lebih jujur:
        # ia mengukur biaya memproses trafik serangan sampai mitigasi aktif.
        atk_cpus = [float(r['cpu_pct']) for r in samples
                    if warmup <= float(r['t_rel_s']) <= warmup + attack_dur]
        cpu_attack_avg = (sum(atk_cpus) / len(atk_cpus)) if atk_cpus else 0.0
        cpu_attack_max = max(atk_cpus) if atk_cpus else ''
        # throughput_per_cpu memakai beban NYATA bila tersedia; kalau flooder
        # tidak sempat mencetak ringkasan, pakai rate nominal (dan kolom
        # flood_actual_pps dibiarkan kosong sebagai penanda).
        try:
            load_pps = float(actual_pps) if actual_pps else float(rate or 0)
        except ValueError:
            load_pps = float(rate or 0)

        loss_vals = [v for v in legit_loss.values() if v == v]   # buang NaN
        loss_mean = sum(loss_vals) / len(loss_vals) if loss_vals else None
        loss_max = max(loss_vals) if loss_vals else None

        # detection_time presisi (jam dinding). Bila gagal dihitung, pakai
        # hasil polling agar kolom tidak kosong.
        det_precise = precise_detection_time(events_this_run, t_flood_wall)
        det_value = (f'{det_precise:.3f}' if det_precise is not None
                     else summary['detection_time_s'])

        compare_row = {
            'ts_iso': summary['ts_iso'],
            'algo': algo_name,
            'scenario': scenario,
            'repeat': repeat,
            'flood_rate_pps': f'{rate:g}',
            'flood_actual_pps': actual_pps,
            'detection_time_s': det_value,
            'detection_time_poll_s': summary['detection_time_s'],
            'detected_rate_pps': first_event_rate(events_this_run),
            'drops_max_concurrent': max_rules,
            'drops_total_events': len(events_this_run),
            'fp_bans': fp_bans,
            'fpr_pct': f'{fpr_pct:.1f}',
            'legit_loss_mean_pct': (f'{loss_mean:.1f}'
                                    if loss_mean is not None else ''),
            'legit_loss_max_pct': (f'{loss_max:.1f}'
                                   if loss_max is not None else ''),
            'cpu_avg_pct': summary['cpu_avg_pct'],
            'cpu_max_pct': summary['cpu_max_pct'],
            'cpu_attack_avg_pct': (f'{cpu_attack_avg:.1f}'
                                   if atk_cpus else ''),
            'cpu_attack_max_pct': (f'{cpu_attack_max:.1f}'
                                   if atk_cpus else ''),
            'mem_avg_pct': summary['mem_avg_pct'],
            'throughput_per_cpu': (f'{load_pps / cpu_attack_avg:.2f}'
                                   if cpu_attack_avg > 0 and load_pps > 0
                                   else ''),
        }
        append_compare_row(compare_row)

        print('\n' + '=' * 68)
        print(f'HASIL [{algo_cfg["label"]}] skenario={scenario} '
              f'repeat={repeat} rate={rate:g}pps')
        print('=' * 68)
        for k in COMPARE_FIELDS:
            print(f'  {k:22s}: {compare_row[k]}')
        print(f'\nFalse positives   : {fp_bans} ban dari {n_legit} host '
              f'legitimate -> FPR {fpr_pct:.1f}%')
        print(f'\nDetail timeseries : {ts_file}')
        print(f'Log controller    : {ctrl_log_path}')
        print(f'Log flood         : {flood_log_path}')
        print(f'Ringkasan compare : {COMPARE_CSV}')
        return compare_row

    summary_file = os.path.join(RESULTS_DIR, 'exp_summary.csv')
    header = list(summary.keys())
    write_header = not os.path.exists(summary_file)
    with open(summary_file, 'a', newline='') as f:
        w = csv.DictWriter(f, fieldnames=header)
        if write_header:
            w.writeheader()
        w.writerow(summary)

    print('\n' + '=' * 60)
    print(f'HASIL SKENARIO: {scenario}')
    print('=' * 60)
    for k, v in summary.items():
        print(f'  {k:24s}: {v}')
    print(f'\nFalse positives   : {fp_bans} ban dari {n_legit} host legitimate '
          f'-> FPR {fpr_pct:.1f}%')
    print(f'\nDetail timeseries : {ts_file}')
    print(f'Log controller    : {ctrl_log_path}')
    return summary


def run_threshold_sweep(thresholds, legit_count=8, warmup=5.0, burst_dur=4.0,
                        flood_dur=10.0, post=20.0, ping_interval=0.2,
                        flash_rate=200):
    """Mode tambahan: sweep RATE_THRESHOLD untuk mengukur TPR & FPR.

    Untuk tiap nilai threshold T:
      - jalankan skenario 'mixed' (serangan asli) -> TPR = deteksi benar
        (dihitung 100% bila detection_time terukur, 0 bila missed).
      - jalankan skenario 'flash_crowd' (burst legit) -> FPR = proporsi
        host legitimate yang salah di-ban pada threshold T.

    Hasil ditulis ke results/threshold_sweep_summary.csv dengan kolom:
      threshold_value, tpr, fpr, avg_detection_time

    Setiap iterasi memanggil run_scenario() yang sudah membersihkan env
    (controller yatim + flow) antar-run, sehingga tiap titik sweep independen.
    """
    out = os.path.join(RESULTS_DIR, 'threshold_sweep_summary.csv')
    header = ['threshold_value', 'tpr', 'fpr', 'avg_detection_time']
    write_header = not os.path.exists(out)
    with open(out, 'a', newline='') as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(header)
        for T in thresholds:
            # --- TPR: mixed (harus terdeteksi) -----------------------------
            mixed = run_scenario('mixed', warmup, flood_dur, post,
                                 ping_interval, legit_count=legit_count,
                                 threshold=T)
            tpr = 1.0 if mixed.get('detection_time_s') else 0.0
            try:
                det_t = float(mixed.get('detection_time_s') or 'nan')
            except ValueError:
                det_t = float('nan')
            # --- FPR: flash_crowd (harus TIDAK terdeteksi) -----------------
            fc = run_scenario('flash_crowd', warmup, flood_dur, post,
                              ping_interval, legit_count=legit_count,
                              flash_rate=flash_rate, burst_dur=burst_dur,
                              threshold=T)
            try:
                fpr = float(fc.get('fpr_pct') or '0') / 100.0
            except ValueError:
                fpr = float('nan')
            w.writerow([T, f'{tpr:.2f}', f'{fpr:.2f}',
                        f'{det_t:.2f}' if det_t == det_t else ''])
            f.flush()
            print(f'[sweep] T={T}: TPR={tpr:.2f} FPR={fpr:.2f} '
                  f'det={det_t:.2f}s')
    print(f'\nSelesai threshold sweep -> {out}')
    return out


def main():
    ap = argparse.ArgumentParser(
        description='Runner eksperimen PoC DDoS-SDN (fase 1, 5+ host).')
    ap.add_argument('--scenario', required=True,
                    choices=['baseline', 'single', 'mixed',
                             'flash_crowd', 'threshold_sweep'],
                    help="'flash_crowd'=burst trafik legit (uji false "
                         "positive); 'threshold_sweep'=sweep RATE_THRESHOLD "
                         "(hasilkan data ROC TPR vs FPR).")
    ap.add_argument('--warmup', type=float, default=5.0,
                    help='durasi fase awal sebelum serangan/burst (detik)')
    ap.add_argument('--flood-duration', type=float, default=10.0,
                    help='lama serangan (detik, untuk single/mixed)')
    ap.add_argument('--burst-dur', type=float, default=4.0,
                    help='lama burst flash_crowd (detik)')
    ap.add_argument('--post', type=float, default=20.0,
                    help='observasi setelah serangan/burst (>= ban 15s)')
    ap.add_argument('--ping-interval', type=float, default=0.2,
                    help='interval ping trafik legitimate (detik)')
    ap.add_argument('--legit-count', type=int, default=3,
                    help='jumlah host legitimate (h2..h{n+1}); victim=h{n+2}')
    ap.add_argument('--flash-rate', type=int, default=None,
                    help='rate per-host flash_crowd (pps); default=RATE_THRESHOLD')
    ap.add_argument('--thresholds', type=str, default='50,100,150,200,250,300',
                    help='daftar threshold utk threshold_sweep (koma-pisah)')
    # ---- Tahap C: mode perbandingan algoritme ---------------------------
    ap.add_argument('--algo', choices=list(ALGO_CONFIG.keys()), default=None,
                    help='jalankan controller algoritme ini dan tulis ke '
                         'results/exp_summary_compare.csv. Tanpa argumen ini: '
                         'perilaku lama (baseline, exp_summary.csv).')
    ap.add_argument('--rate', type=float, default=0.0,
                    help='batas laju flood (paket/detik) yg diteruskan ke '
                         'flood_scapy.py; 0 = secepat mungkin (perilaku lama). '
                         'Hanya dipakai bila --algo diberikan.')
    ap.add_argument('--repeats', type=int, default=1,
                    help='jumlah pengulangan run (independen: controller + '
                         'topologi dibangun ulang tiap repeat).')
    ap.add_argument('--repeat-start', type=int, default=1,
                    help='indeks awal penomoran repeat (dipakai skrip sweep '
                         'yang memanggil runner sekali per repeat, agar kolom '
                         'repeat di CSV tetap 1..N).')
    ap.add_argument('--subdir', default=None,
                    help='simpan log controller/timeseries/log flood ke '
                         'results/<subdir>/ (untuk sweep Tahap D). CSV event '
                         'dan CSV ringkasan tetap di results/.')
    args = ap.parse_args()

    if args.repeats < 1:
        ap.error('--repeats minimal 1')
    if args.repeat_start < 1:
        ap.error('--repeat-start minimal 1')

    setLogLevel('warning')     # log mininet minim supaya hasil terbaca

    if args.rate and not args.algo:
        # Backward-compat: mode lama sengaja tetap mengirim flood secepat
        # mungkin agar hasil historis tidak berubah diam-diam.
        print('[warn] --rate diabaikan tanpa --algo (mode lama mempertahankan '
              'flood tanpa batas laju). Pakai --algo baseline|s2td|entropy.')
    if args.rate < 0:
        ap.error('--rate tidak boleh negatif (0 = secepat mungkin)')

    if args.scenario == 'threshold_sweep':
        if args.algo:
            ap.error('threshold_sweep hanya untuk baseline; jangan gabung '
                     'dengan --algo (sweep RATE_THRESHOLD milik baseline).')
        thr = [int(x) for x in args.thresholds.split(',') if x.strip()]
        run_threshold_sweep(thr, legit_count=args.legit_count,
                            warmup=args.warmup, burst_dur=args.burst_dur,
                            flood_dur=args.flood_duration, post=args.post,
                            ping_interval=args.ping_interval,
                            flash_rate=args.flash_rate)
        return

    results = []
    for i in range(1, args.repeats + 1):
        repeat_no = args.repeat_start + i - 1
        if args.repeats > 1:
            print(f'\n### REPEAT {repeat_no}/{args.repeat_start + args.repeats - 1} '
                  f'| algo={args.algo or "baseline"} '
                  f'| scenario={args.scenario} | rate={args.rate:g}pps')
        results.append(
            run_scenario(args.scenario, args.warmup, args.flood_duration,
                         args.post, args.ping_interval,
                         legit_count=args.legit_count,
                         flash_rate=args.flash_rate,
                         burst_dur=args.burst_dur,
                         algo=args.algo, rate=args.rate, repeat=repeat_no,
                         subdir=args.subdir))

    # Ringkasan singkat di akhir: berguna saat --repeats > 1 supaya user
    # langsung melihat sebaran tanpa membuka CSV.
    if args.algo and len(results) > 1:
        print('\n' + '=' * 68)
        print(f'RINGKASAN {len(results)} REPEAT | algo={args.algo} '
              f'scenario={args.scenario} rate={args.rate:g}pps')
        print('=' * 68)
        print(f'  {"rep":>3} {"detect_s":>9} {"actual_pps":>11} '
              f'{"cpu_avg":>8} {"cpu_max":>8} {"loss_max":>9} {"tput/cpu":>9}')
        for r in results:
            print(f'  {r["repeat"]:>3} {r["detection_time_s"] or "-":>9} '
                  f'{r["flood_actual_pps"] or "-":>11} '
                  f'{r["cpu_avg_pct"]:>8} {r["cpu_max_pct"]:>8} '
                  f'{r["legit_loss_max_pct"] or "-":>9} '
                  f'{r["throughput_per_cpu"] or "-":>9}')
        print(f'\nCSV compare: {COMPARE_CSV}')


if __name__ == '__main__':
    main()
