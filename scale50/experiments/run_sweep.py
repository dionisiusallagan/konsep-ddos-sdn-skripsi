#!/usr/bin/env python3
"""
Threshold-sensitivity sweep untuk ddos_guard_tune.py (fase scale50).

Mengukur performa detector terhadap DUA variabel:
  - RATE_THRESHOLD (T) : batas rate per-source-IP (diubah via env RATE_THRESHOLD)
  - attack rate (R)    : --rate flooder (paket/detik; 0 = secepat mungkin)

Untuk tiap pasangan (T, R) dijalankan skenario MIXED (legit + flood):
  - detected  : 1 bila rule DROP terpasang (attacker keban) -> proxy TPR
  - fp_bans   : jumlah IP legit terban                -> proxy FPR
  - cpu_max   : beban puncak controller

Hasil per run ditulis ke scale50/results/sweep.csv dan dicetak sebagai
pivot threshold x rate (format sel "detected/fp_bans").

CATATAN METODOLOGI: karena deteksi/FPR bersifat biner per run, ini adalah
"matriks sensitivitas threshold", bukan kurva ROC halus. Tetap valid untuk
menunjukkan: threshold terlalu rendah -> false positive pada trafik legit
(legit ~5 pps/IP); threshold terlalu tinggi -> serangan lemah lolos.

Penggunaan:
  ~/ddos-venv/bin/python scale50/experiments/run_sweep.py \
      --thresholds 3,5,10,15,20,25,40 --rates 0,30,60,120 --repeats 1
"""

import argparse
import csv
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

import psutil

EXPERIMENT_DIR = os.path.dirname(os.path.abspath(__file__))
SCALE50_ROOT = os.path.dirname(EXPERIMENT_DIR)
sys.path.insert(0, os.path.join(SCALE50_ROOT, 'topology'))

# helper dari runner utama (modulnya tidak menjalankan main() saat di-import)
from run_scale50 import (                                 # noqa: E402
    cleanup_stale_environment, start_controller, build_net,
    quick_connectivity_check, count_drop_rules, proc_jiffies,
    parse_ping_loss, count_mitigation_rows,
    ATTACKER_IP, VICTIM_IP, DEFAULT_LEGIT_COUNT, RESULTS_DIR, setLogLevel,
)

SWEEP_CSV = os.path.join(RESULTS_DIR, 'sweep.csv')
CONTROLLER_APP = 'ddos_guard_tune.py'   # controller dgn RATE_THRESHOLD via env


def run_cell(threshold, rate, warmup, flood_dur, post, ping_interval,
             legit_count):
    """Jalankan satu sel (threshold, rate). Return dict hasil."""
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.environ['RATE_THRESHOLD'] = str(threshold)
    os.environ['CONTROLLER_APP'] = CONTROLLER_APP

    cleanup_stale_environment()
    ctrl_log_path = os.path.join(RESULTS_DIR,
                                 f'sweep_ctrl_T{threshold}_R{rate}_{ts}.log')
    ctrl_proc, ctrl_log = start_controller(ctrl_log_path)
    cpu_meter = psutil.Process(ctrl_proc.pid)

    # live-view log controller (sama seperti runner utama)
    tail_stop = threading.Event()

    def _tail():
        pat = re.compile(r'STATS:|MITIGASI|DDoSGuard aktif|terhubung')
        with open(ctrl_log_path) as f:
            f.seek(0, 2)
            while not tail_stop.is_set():
                line = f.readline()
                if line:
                    if pat.search(line):
                        print(f'  [ctrl] {line.strip()}')
                else:
                    time.sleep(0.3)

    threading.Thread(target=_tail, daemon=True).start()

    net = build_net()
    s1 = net.get('s1')
    h1 = net.get('h1')
    print(f'  [net] konektivitas: {quick_connectivity_check(net)}')

    legit_hosts = [f'h{i}' for i in range(2, 2 + legit_count)]
    rows_before, _ = count_mitigation_rows()

    # sampler CPU/mem/jiffies/rule
    ts_path = os.path.join(RESULTS_DIR,
                           f'sweep_ts_T{threshold}_R{rate}_{ts}.csv')
    tsf = open(ts_path, 'w', newline='')
    ts_writer = csv.writer(tsf)
    ts_writer.writerow(['t_rel_s', 'cpu_pct', 'jiffies', 'drop_rules'])
    cpu_meter.cpu_percent(interval=None)
    t_start = time.monotonic()
    max_rules = 0
    stop_at = t_start + warmup + flood_dur + post

    def sampler():
        nonlocal max_rules
        while time.monotonic() < stop_at:
            t_rel = time.monotonic() - t_start
            rules = count_drop_rules(s1)
            max_rules = max(max_rules, rules)
            ts_writer.writerow([f'{t_rel:.2f}',
                                f'{cpu_meter.cpu_percent(interval=None):.1f}',
                                proc_jiffies(ctrl_proc.pid), rules])
            time.sleep(0.5)

    threading.Thread(target=sampler, daemon=True).start()

    # trafik legitimate (ping tiap ~1/ping_interval detik)
    legit_pings = {}
    n_pkts = int((warmup + flood_dur + post) / ping_interval)
    for hn in legit_hosts:
        legit_pings[hn] = net.get(hn).popen(
            ['ping', '-c', str(n_pkts), '-i', str(ping_interval), '-W', '1',
             VICTIM_IP], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # serangan dengan rate terkontrol
    time.sleep(max(0, t_start + warmup - time.monotonic()))
    py = sys.executable
    flooder = os.path.join(SCALE50_ROOT, 'traffic', 'flood_scapy.py')
    h1.popen([py, flooder, '--target', VICTIM_IP, '--proto', 'tcp',
              '--port', '80', '--duration', str(flood_dur),
              '--rate', str(rate)],
             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t_flood = time.monotonic()
    detection_time = None
    deadline = t_flood + flood_dur + 15
    while time.monotonic() < deadline:
        if count_drop_rules(s1) > 0:
            detection_time = time.monotonic() - t_flood
            break
        time.sleep(0.2)

    # kumpulkan hasil
    rows_after, new_rows = count_mitigation_rows()
    events = new_rows[rows_before:]
    fp_bans = sum(1 for r in events
                  if len(r.split(',')) > 4 and r.split(',')[4] != ATTACKER_IP)

    legit_loss = {}
    for hn, p in legit_pings.items():
        try:
            legit_loss[hn] = parse_ping_loss(p)
        except Exception:
            p.terminate()
            try:
                legit_loss[hn] = parse_ping_loss(p)
            except Exception:
                legit_loss[hn] = float('nan')

    tsf.close()
    tail_stop.set()
    net.stop()
    ctrl_proc.terminate()
    ctrl_log.close()

    # cpu_max dari timeseries yg direkam
    cpu_max = 0.0
    with open(ts_path) as f:
        for row in csv.DictReader(f):
            try:
                cpu_max = max(cpu_max, float(row['cpu_pct']))
            except (ValueError, KeyError):
                pass

    loss_vals = [v for v in legit_loss.values() if v == v]
    loss_avg = (sum(loss_vals) / len(loss_vals)) if loss_vals else float('nan')

    detected = 1 if len(events) > 0 else 0
    return {
        'threshold': threshold,
        'attack_rate': rate,
        'detected': detected,
        'detection_time_s': f'{detection_time:.2f}' if detection_time else '',
        'fp_bans': fp_bans,
        'legit_loss_avg_pct': f'{loss_avg:.1f}' if loss_vals else 'nan',
        'cpu_max_pct': f'{cpu_max:.1f}',
    }


def main():
    ap = argparse.ArgumentParser(description='Threshold-sensitivity sweep')
    ap.add_argument('--thresholds', default='3,5,10,15,20,25,40',
                    help='daftar RATE_THRESHOLD, dipisah koma')
    ap.add_argument('--rates', default='0,30,60,120',
                    help='daftar --rate flooder, dipisah koma (0 = max)')
    ap.add_argument('--repeats', type=int, default=1,
                    help='ulang tiap sel (untuk stabilitas)')
    ap.add_argument('--warmup', type=float, default=5.0)
    ap.add_argument('--flood-duration', type=float, default=10.0)
    ap.add_argument('--post', type=float, default=20.0)
    ap.add_argument('--ping-interval', type=float, default=0.2)
    ap.add_argument('--legit-count', type=int, default=DEFAULT_LEGIT_COUNT)
    args = ap.parse_args()
    setLogLevel('warning')

    thresholds = [int(x) for x in args.thresholds.split(',') if x != '']
    rates = [int(x) for x in args.rates.split(',') if x != '']

    header = ['threshold', 'attack_rate', 'detected', 'detection_time_s',
              'fp_bans', 'legit_loss_avg_pct', 'cpu_max_pct']
    write_header = not os.path.exists(SWEEP_CSV)
    with open(SWEEP_CSV, 'a', newline='') as f:
        w = csv.DictWriter(f, fieldnames=header)
        if write_header:
            w.writeheader()
        for T in thresholds:
            for R in rates:
                for rep in range(max(1, args.repeats)):
                    print(f'\n=== SWEEP T={T} R={R} rep={rep + 1} ===')
                    row = run_cell(T, R, args.warmup, args.flood_duration,
                                   args.post, args.ping_interval,
                                   args.legit_count)
                    w.writerow(row)
                    f.flush()
                    print('  ->', row)

    # pivot sederhana: sel = "detected/fp_bans" per (T x R)
    print('\n' + '=' * 66)
    print('PIVOT  detected / fp_bans   per  threshold (baris) x rate (kolom)')
    print('=' * 66)
    rows = list(csv.DictReader(open(SWEEP_CSV)))
    print('T \\ R'.rjust(14) + ''.join(str(R).rjust(10) for R in rates))
    for T in thresholds:
        cells = []
        for R in rates:
            cell = [r for r in rows
                    if int(r['threshold']) == T and int(r['attack_rate']) == R]
            if not cell:
                cells.append('-')
                continue
            d = sum(int(c['detected']) for c in cell)
            fp = sum(int(c['fp_bans']) for c in cell)
            cells.append(f'{d}/{fp}')
        print(str(T).rjust(14) + ''.join(c.rjust(10) for c in cells))
    print(f'\nTersimpan: {SWEEP_CSV}')


if __name__ == '__main__':
    main()
