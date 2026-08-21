#!/usr/bin/env python3
"""
Runner Eksperimen - Skenario Uji Deteksi & Mitigasi DDoS pada SDN

Skripsi S1 Teknik Komputer - Dionisius

SKENARIO (dijalankan TERPISAH, satu proses per skenario)
========================================================
  baseline : hanya trafik legitimate (ping h2,h3,h4 -> h5). Tanpa serangan.
             Tujuan: membuktikan deteksi TIDAK memicu false positive saat
             trafik normal, dan memberi garis dasar CPU controller.
  single   : flooding murni dari h1 -> h5, tanpa trafik legitimate.
             Tujuan: mengukur waktu deteksi & efektivitas mitigasi murni.
  mixed    : flooding h1 -> h5 BERSAMAAN dengan trafik legitimate h2-h4.
             Tujuan: mengukur false positive rate (loss host legitimate
             dan/atau IP legitimate yang tak sengaja dibanned).

METRIK YANG DICATAT
===================
1. Waktu deteksi   : jeda antara paket flood pertama dikirim sampai flow
                     DROP (priority=100) terlihat pertama kali di switch.
                     Diukur dengan polling `ovs-ofctl dump-flows` tiap 0.2s.
2. Jumlah drop rule: maksimum rule DROP simultan + total event mitigasi
                     (baris baru di results/mitigation_events.csv).
3. CPU & memori controller : disampling tiap 0.5s via psutil
                     (cpu_percent non-blocking; sampel pertama dipakai priming).
4. False positive  : (a) % loss ping host legitimate selama eksperimen,
                     (b) jumlah ban yang mengenai IP selain attacker.

OUTPUT (folder results/)
========================
- exp_summary.csv                  : satu baris per run (append).
- exp_timeseries_<scenario>_<ts>.csv : sampel waktu (t, cpu, mem, n_rules).
- controller_<scenario>_<ts>.log   : log controller utk run ini (bukti).
- mitigation_events.csv            (milik ddos_guard.py, dibaca ulang).

CARA PAKAI (di dalam venv, sebagai root via sudo -E)
====================================================
  sudo -E python experiments/run_experiment.py --scenario baseline
  sudo -E python experiments/run_experiment.py --scenario single
  sudo -E python experiments/run_experiment.py --scenario mixed
"""

import argparse
import csv
import os
import re
import shutil
import socket
import subprocess
import sys
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
VICTIM_IP = '10.0.0.5'        # h5 = victim/server
LEGIT_HOSTS = ['h2', 'h3', 'h4']   # host legitimate utk skenario baseline/mixed


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


def count_drop_rules(s1):
    """Hitung flow DROP (priority=100) yang aktif di switch saat ini."""
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


# =========================================================================
# PERSIAPAN LINGKUNGAN
# =========================================================================
def start_controller(log_path):
    """Jalankan osken-manager sebagai subprocess, kembalikan (proc, logfile)."""
    osken_mgr = shutil.which('osken-manager')
    if not osken_mgr:
        sys.exit('ERROR: osken-manager tidak ditemukan - aktifkan venv!')
    log = open(log_path, 'w')
    proc = subprocess.Popen(
        [osken_mgr, '--ofp-tcp-listen-port', '6633', 'ddos_guard.py'],
        cwd=os.path.join(PROJECT_ROOT, 'controller'),
        stdout=log, stderr=subprocess.STDOUT)
    if not wait_port(6633):
        proc.terminate()
        sys.exit('ERROR: controller gagal listen di port 6633 '
                 f'(cek {log_path})')
    return proc, log


def build_net():
    """Bangun topologi yang sama dengan basic_topo.py."""
    net = Mininet(topo=DDosTopo(),
                  controller=lambda name: RemoteController(
                      name, ip='127.0.0.1', port=6633),
                  switch=OVSSwitch, link=TCLink,
                  autoSetMacs=True, autoStaticArp=True)
    net.start()
    net.waitConnected(timeout=30)
    time.sleep(2)          # beri waktu table-miss stabil
    return net


# =========================================================================
# EKSPERIMEN UTAMA
# =========================================================================
def run_scenario(scenario, warmup, flood_dur, post, ping_interval):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs(RESULTS_DIR, exist_ok=True)

    ctrl_log_path = os.path.join(RESULTS_DIR, f'controller_{scenario}_{ts}.log')
    ts_file = os.path.join(RESULTS_DIR,
                           f'exp_timeseries_{scenario}_{ts}.csv')

    ctrl_proc, ctrl_log = start_controller(ctrl_log_path)
    cpu_meter = psutil.Process(ctrl_proc.pid)

    net = build_net()
    s1 = net.get('s1')
    h1 = net.get('h1')

    # ---- diff CSV mitigasi (utk hitung event milik run ini saja) ----
    rows_before, _ = count_mitigation_rows()

    # ---- mulai sampling CPU/mem + jumlah rule ke timeseries ----
    tsf = open(ts_file, 'w', newline='')
    ts_writer = csv.writer(tsf)
    ts_writer.writerow(['t_rel_s', 'cpu_pct', 'mem_pct', 'drop_rules'])
    cpu_meter.cpu_percent(interval=None)          # priming sample

    t_start = time.monotonic()
    detection_time = None                          # deteksi flood (detik)
    max_rules = 0

    # ---- 1. TRAFIK LEGITIMATE (baseline & mixed; tidak ada di single) --
    legit_pings = {}
    if scenario in ('baseline', 'mixed'):
        n_pkts = int((warmup + flood_dur + post) / ping_interval)
        for hn in LEGIT_HOSTS:
            # ping terus-menerus dr host legitimate ke victim.
            # output lengkapnya jadi bahan hitung % loss (FPR).
            legit_pings[hn] = net.get(hn).popen(
                ['ping', '-c', str(n_pkts), '-i', str(ping_interval),
                 '-W', '1', VICTIM_IP],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def sampler(stop_at):
        """Sampling CPU/mem/rule tiap 0.5s sampai stop_at (monotonic)."""
        nonlocal max_rules
        while time.monotonic() < stop_at:
            t_rel = time.monotonic() - t_start
            rules = count_drop_rules(s1)
            max_rules = max(max_rules, rules)
            ts_writer.writerow([f'{t_rel:.2f}',
                                f'{cpu_meter.cpu_percent(interval=None):.1f}',
                                f'{cpu_meter.memory_percent():.1f}',
                                rules])
            time.sleep(0.5)

    # ---- 2. FASE WARMUP -------------------------------------------------
    warm_end = t_start + warmup

    if scenario == 'single':
        # tanpa trafik legitimate; cukup sampling pasif
        pass
    # baseline/mixed: ping sudah jalan sejak t=0

    # polling deteksi: mulai cek rule beberapa saat setelah flood diluncurkan
    detect_stop = None

    # ---- 3. LUNCURKAN SERANGAN (single & mixed) -------------------------
    flood_proc = None
    t_flood = None
    if scenario in ('single', 'mixed'):
        time.sleep(max(0, warm_end - time.monotonic()))
        py = shutil.which('python')               # python venv (ada scapy)
        flooder = os.path.join(PROJECT_ROOT, 'traffic', 'flood_scapy.py')
        flood_proc = h1.popen(
            [py, flooder, '--target', VICTIM_IP,
             '--proto', 'tcp', '--port', '80', '--duration',
             str(flood_dur)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t_flood = time.monotonic()                # t0 pengukuran deteksi

        # poll rule DROP tiap 0.2s sampai muncul (maks. flood_dur+10 dtk)
        deadline = t_flood + flood_dur + 10
        while time.monotonic() < deadline:
            if count_drop_rules(s1) > 0:
                detection_time = time.monotonic() - t_flood
                break
            time.sleep(0.2)

    # ---- 4. FASE OBSERVASI AKHIR ----------------------------------------
    stop_at = t_start + warmup + flood_dur + post
    sampler(stop_at)

    # ---- 5. BERESKAN & KUMPULKAN HASIL ----------------------------------
    # ping legitimate dibiarkan selesai sendiri (durasi = durasi eksperimen)
    # supaya ringkasan statistiknya sempat dicetak oleh `ping`.
    if flood_proc and flood_proc.poll() is None:
        flood_proc.terminate()

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
    net.stop()
    ctrl_proc.terminate()
    ctrl_log.close()

    # ---- ringkasan metrik dari timeseries --------------------------------
    with open(ts_file) as f:
        samples = list(csv.DictReader(f))
    cpus = [float(r['cpu_pct']) for r in samples]
    mems = [float(r['mem_pct']) for r in samples]

    summary = {
        'ts_iso': datetime.now(timezone.utc).isoformat(),
        'scenario': scenario,
        'warmup_s': warmup,
        'flood_duration_s': flood_dur if scenario != 'baseline' else 0,
        'post_s': post,
        'detection_time_s': f'{detection_time:.2f}' if detection_time else '',
        'drops_max_concurrent': max_rules,
        'drops_total_events': len(events_this_run),
        'fp_bans': fp_bans,
        **{f'{hn}_loss_pct': f'{legit_loss.get(hn, float("nan")):.1f}'
           for hn in LEGIT_HOSTS},
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
    print(f'\nDetail timeseries : {ts_file}')
    print(f'Log controller    : {ctrl_log_path}')
    return summary


def main():
    ap = argparse.ArgumentParser(description='Runner eksperimen PoC DDoS-SDN')
    ap.add_argument('--scenario', required=True,
                    choices=['baseline', 'single', 'mixed'])
    ap.add_argument('--warmup', type=float, default=5.0,
                    help='durasi fase awal sebelum serangan (detik)')
    ap.add_argument('--flood-duration', type=float, default=10.0,
                    help='lama serangan (detik)')
    ap.add_argument('--post', type=float, default=20.0,
                    help='observasi setelah serangan (>= ban 15s + margin)')
    ap.add_argument('--ping-interval', type=float, default=0.2,
                    help='interval ping trafik legitimate (detik)')
    args = ap.parse_args()

    setLogLevel('warning')     # log mininet minim supaya hasil terbaca
    run_scenario(args.scenario, args.warmup, args.flood_duration,
                 args.post, args.ping_interval)


if __name__ == '__main__':
    main()
