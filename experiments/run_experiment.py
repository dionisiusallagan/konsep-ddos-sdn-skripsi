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


def count_mitigation_rows():
    """Baca jumlah baris event mitigasi saat ini (utk diff sebelum/sesudah)."""
    if not os.path.exists(MITIGATION_CSV):
        return 0, []
    with open(MITIGATION_CSV) as f:
        rows = [line for line in f if line.strip()]
    return len(rows) - 1, rows[1:]   # -1: header


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


def start_controller(log_path, threshold=None):
    """Jalankan osken-manager sebagai subprocess, kembalikan (proc, logfile).

    threshold: bila tidak None, diteruskan ke controller via env
    RATE_THRESHOLD (memungkinkan threshold_sweep tanpa ubah kode detector).
    """
    # Cari osken-manager RELATIF terhadap interpreter yang menjalankan script.
    venv_bin = os.path.dirname(sys.executable)
    osken_mgr = os.path.join(venv_bin, 'osken-manager')
    if not os.path.isfile(osken_mgr):
        sys.exit(f'ERROR: osken-manager tidak ditemukan di {venv_bin} - '
                  'jalankan dengan python dari venv project!')
    # teruskan environment saat ini + override RATE_THRESHOLD bila diminta
    env = dict(os.environ)
    if threshold is not None:
        env['RATE_THRESHOLD'] = str(threshold)
    log = open(log_path, 'w')
    proc = subprocess.Popen(
        [osken_mgr, '--ofp-tcp-listen-port', '6633', 'ddos_guard.py'],
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
    pattern = re.compile(r'STATS:|MITIGASI|DDoSGuard aktif|terhubung')
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
                 legit_count=3, flash_rate=None, burst_dur=4, threshold=None):
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

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # WAJIB: bersihkan controller yatim dari run sebelumnya SEBELUM apa pun.
    cleanup_stale_environment()

    ctrl_log_path = os.path.join(RESULTS_DIR, f'controller_{scenario}_{ts}.log')
    ts_file = os.path.join(RESULTS_DIR,
                           f'exp_timeseries_{scenario}_{ts}.csv')

    ctrl_proc, ctrl_log = start_controller(ctrl_log_path, threshold=threshold)
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
    rows_before, _ = count_mitigation_rows()

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
    burst_procs = []
    iperf_srv = None
    t_flood = None
    if scenario in ('single', 'mixed'):
        time.sleep(max(0, t_start + warmup - time.monotonic()))
        # Interpreter yg sama dgn runner ini (venv, ada scapy).
        py = sys.executable
        flooder = os.path.join(PROJECT_ROOT, 'traffic', 'flood_scapy.py')
        flood_proc = h1.popen(
            [py, flooder, '--target', victim_ip,
             '--proto', 'tcp', '--port', '80', '--duration',
             str(flood_dur)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t_flood = time.monotonic()                # t0 pengukuran deteksi
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
    # flash_crowd: hentikan client burst & server iperf3 (jika masih hidup)
    for bp in burst_procs:
        if bp.poll() is None:
            bp.terminate()
    if iperf_srv and iperf_srv.poll() is None:
        iperf_srv.terminate()

    rows_after, new_rows = count_mitigation_rows()
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
    args = ap.parse_args()

    setLogLevel('warning')     # log mininet minim supaya hasil terbaca

    if args.scenario == 'threshold_sweep':
        thr = [int(x) for x in args.thresholds.split(',') if x.strip()]
        run_threshold_sweep(thr, legit_count=args.legit_count,
                            warmup=args.warmup, burst_dur=args.burst_dur,
                            flood_dur=args.flood_duration, post=args.post,
                            ping_interval=args.ping_interval,
                            flash_rate=args.flash_rate)
        return

    run_scenario(args.scenario, args.warmup, args.flood_duration,
                 args.post, args.ping_interval,
                 legit_count=args.legit_count, flash_rate=args.flash_rate,
                 burst_dur=args.burst_dur)


if __name__ == '__main__':
    main()
