#!/usr/bin/env python3
"""
Runner Eksperimen FASE scale50 - 50 IoT edge nodes + 1 victim.

Adaptasi dari experiments/run_experiment.py (fase 5-host). Perubahan utama:
- Topologi : IoTTopo50 (51 host) dari scale50/topology/large_topo.py
- Victim   : 10.0.0.51 (h51); attacker tetap 10.0.0.1 (h1)
- Legit    : subset host IoT yang bisa diatur (--legit-count, default 10)
- Controller: scale50/controller/ddos_guard50.py (logika identik fase lama)
- Output   : scale50/results/* (terpisah dari fase 5-host utk perbandingan)

Tujuan fase ini: mengukur BEBAN CPU CONTROLLER saat skala jaringan naik
5x, dengan logika deteksi yang identik.

Skenario (sama seperti fase lama, agar tabel perbandingan sejajar):
  baseline : trafik legitimate saja  -> garis dasar CPU pada skala 50 node
  single   : flooding murni h1->h51  -> deteksi + CPU saat serangan
  mixed    : flooding + trafik legit -> FPR pada skala besar

Contoh:
  sudo ~/ddos-venv/bin/python run_scale50.py --scenario baseline
  sudo ~/ddos-venv/bin/python run_scale50.py --scenario single
  sudo ~/ddos-venv/bin/python run_scale50.py --scenario mixed
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
from datetime import datetime, timezone

import psutil

# ---- path project -------------------------------------------------------
EXPERIMENT_DIR = os.path.dirname(os.path.abspath(__file__))
SCALE50_ROOT = os.path.dirname(EXPERIMENT_DIR)
PROJECT_ROOT = os.path.dirname(SCALE50_ROOT)
sys.path.insert(0, os.path.join(SCALE50_ROOT, 'topology'))

from large_topo import IoTTopo50, VICTIM_ID            # noqa: E402

from mininet.net import Mininet                      # noqa: E402
from mininet.node import RemoteController, OVSSwitch # noqa: E402
from mininet.link import TCLink                      # noqa: E402
from mininet.log import setLogLevel                  # noqa: E402

RESULTS_DIR = os.path.join(SCALE50_ROOT, 'results')
MITIGATION_CSV = os.path.join(RESULTS_DIR, 'mitigation_events.csv')
CONTROLLER_APP = 'ddos_guard50.py'

ATTACKER_IP = '10.0.0.1'          # h1 = attacker
VICTIM_IP = f'10.0.0.{VICTIM_ID}'  # h51 = victim
DEFAULT_LEGIT_COUNT = 10          # jumlah host IoT utk trafik legitimate


# =========================================================================
# UTILITAS (identik fase lama)
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


# Node.cmd() Mininet TIDAK thread-safe -> semua akses s1.cmd lewat lock ini
# (dipakai sampler-thread DAN loop deteksi di main thread).
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
    """CPU-time proses (utime+stime) langsung dari /proc - ground truth
    independen psutil. Return None jika proses sudah tidak ada."""
    try:
        with open(f'/proc/{pid}/stat') as f:
            remainder = f.read().rsplit(') ', 1)[1].split()
        return int(remainder[11]) + int(remainder[12])
    except (OSError, IndexError, ValueError):
        return None


# =========================================================================
# PERSIAPAN LINGKUNGAN
# =========================================================================
def cleanup_stale_environment():
    """Bunuh sisa controller/topologi dari run sebelumnya.

    Orphan osken-manager yg memegang port 6633 membuat switch diam-diam
    dilayani controller lama (state basi) -> metrik tidak valid.
    """
    subprocess.run(['pkill', '-f', 'osken-manager'], capture_output=True)
    subprocess.run(['mn', '-c'], capture_output=True)
    time.sleep(1)


def start_controller(log_path):
    """Jalankan ddos_guard50.py sebagai subprocess (anti-zombie check)."""
    venv_bin = os.path.dirname(sys.executable)
    osken_mgr = os.path.join(venv_bin, 'osken-manager')
    if not os.path.isfile(osken_mgr):
        sys.exit(f'ERROR: osken-manager tidak ditemukan di {venv_bin} - '
                 'jalankan dengan python dari venv project!')
    log = open(log_path, 'w')
    # App controller bisa diganti via env (untuk threshold-sweep).
    app = os.environ.get('CONTROLLER_APP', CONTROLLER_APP)
    proc = subprocess.Popen(
        [osken_mgr, '--ofp-tcp-listen-port', '6633', app],
        cwd=os.path.join(SCALE50_ROOT, 'controller'),
        stdout=log, stderr=subprocess.STDOUT)
    if not wait_port(6633):
        proc.terminate()
        sys.exit(f'ERROR: controller gagal listen di port 6633 '
                 f'(cek {log_path})')
    # anti-zombie: proses baru harus MASIH hidup setelah port listen;
    # jika mati segera = port dipegang proses lain -> metrik palsu.
    time.sleep(0.5)
    if proc.poll() is not None:
        sys.exit('ERROR: proses controller baru mati segera setelah start '
                 f'(exit code={proc.returncode}). Kemungkinan port 6633 '
                 'dipegang proses lama. Jalankan: pkill -f osken-manager')
    return proc, log


def build_net():
    """Bangun topologi 51 host (lebih lambat dari 5-host, harap sabar)."""
    net = Mininet(topo=IoTTopo50(),
                  controller=lambda name: RemoteController(
                      name, ip='127.0.0.1', port=6633),
                  switch=OVSSwitch, link=TCLink,
                  autoSetMacs=True, autoStaticArp=True)
    net.start()
    net.waitConnected(timeout=120)
    time.sleep(3)          # beri waktu table-miss stabil
    return net


def quick_connectivity_check(net):
    """Ping subset host -> victim (pengganti pingAll yang butuh ~1 menit)."""
    s = []
    for hn in ('h2', 'h25', 'h50'):
        out = net.get(hn).cmd(f'ping -c 1 -W 2 {VICTIM_IP}')
        ok = '1 received' in out
        s.append(f'{hn}->victim:{"OK" if ok else "GAGAL"}')
    return ' | '.join(s)


def tail_controller_log(log_path, stop_event):
    """Live-view baris penting log controller ke konsol ([ctrl] prefix)."""
    import re
    pattern = re.compile(r'STATS:|MITIGASI|DDoSGuard aktif|terhubung')
    with open(log_path) as f:
        f.seek(0, 2)
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
                 legit_count):
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    os.makedirs(RESULTS_DIR, exist_ok=True)

    cleanup_stale_environment()

    ctrl_log_path = os.path.join(RESULTS_DIR, f'controller_{scenario}_{ts}.log')
    ts_file = os.path.join(RESULTS_DIR,
                           f'exp_timeseries_{scenario}_{ts}.csv')

    ctrl_proc, ctrl_log = start_controller(ctrl_log_path)
    cpu_meter = psutil.Process(ctrl_proc.pid)

    tail_stop = threading.Event()
    tail_thread = threading.Thread(target=tail_controller_log,
                                   args=(ctrl_log_path, tail_stop),
                                   daemon=True)
    tail_thread.start()

    net = build_net()
    s1 = net.get('s1')
    h1 = net.get('h1')

    conn = quick_connectivity_check(net)
    print(f'  [net] konektivitas: {conn}')

    # host legitimate: h2 .. h(1+legit_count) - subset IoT, tidak termasuk h1
    legit_hosts = [f'h{i}' for i in range(2, 2 + legit_count)]

    rows_before, _ = count_mitigation_rows()

    # sampler background: CPU/mem/jiffies/rule sepanjang eksperimen
    tsf = open(ts_file, 'w', newline='')
    ts_writer = csv.writer(tsf)
    ts_writer.writerow(['t_rel_s', 'cpu_pct', 'mem_pct', 'jiffies',
                        'drop_rules'])
    cpu_meter.cpu_percent(interval=None)          # priming

    t_start = time.monotonic()
    detection_time = None
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
                                f'{cpu_meter.memory_percent():.1f}',
                                proc_jiffies(ctrl_proc.pid),
                                rules])
            time.sleep(0.5)

    sampler_thread = threading.Thread(target=sampler, daemon=True)
    sampler_thread.start()

    # ---- trafik legitimate (baseline & mixed) --------------------------
    legit_pings = {}
    if scenario in ('baseline', 'mixed'):
        n_pkts = int((warmup + flood_dur + post) / ping_interval)
        for hn in legit_hosts:
            legit_pings[hn] = net.get(hn).popen(
                ['ping', '-c', str(n_pkts), '-i', str(ping_interval),
                 '-W', '1', VICTIM_IP],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # ---- serangan (single & mixed) -------------------------------------
    flood_proc = None
    t_flood = None
    if scenario in ('single', 'mixed'):
        time.sleep(max(0, t_start + warmup - time.monotonic()))
        py = sys.executable
        flooder = os.path.join(SCALE50_ROOT, 'traffic', 'flood_scapy.py')
        flood_proc = h1.popen(
            [py, flooder, '--target', VICTIM_IP,
             '--proto', 'tcp', '--port', '80', '--duration',
             str(flood_dur)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        t_flood = time.monotonic()

        deadline = t_flood + flood_dur + 15   # +margin: 51 host lebih lambat
        while time.monotonic() < deadline:
            if count_drop_rules(s1) > 0:
                detection_time = time.monotonic() - t_flood
                break
            time.sleep(0.2)

    sampler_thread.join(timeout=max(0, stop_at - time.monotonic()) + 5)

    # ---- beres-beres & kumpulkan hasil ---------------------------------
    if flood_proc and flood_proc.poll() is None:
        flood_proc.terminate()

    rows_after, new_rows = count_mitigation_rows()
    events_this_run = new_rows[rows_before:]
    fp_bans = sum(1 for r in events_this_run
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
    tail_thread.join(timeout=2)
    net.stop()
    ctrl_proc.terminate()
    ctrl_log.close()

    with open(ts_file) as f:
        samples = list(csv.DictReader(f))
    cpus = [float(r['cpu_pct']) for r in samples]
    mems = [float(r['mem_pct']) for r in samples]

    # rata2 loss legit (nan di-skip agar kolom tetap informatif)
    loss_vals = [v for v in legit_loss.values() if v == v]  # filter NaN
    loss_avg = f'{sum(loss_vals) / len(loss_vals):.1f}' if loss_vals else 'nan'

    summary = {
        'ts_iso': datetime.now(timezone.utc).isoformat(),
        'scenario': scenario,
        'n_hosts': 51,
        'n_legit': legit_count if scenario != 'single' else 0,
        'warmup_s': warmup,
        'flood_duration_s': flood_dur if scenario != 'baseline' else 0,
        'post_s': post,
        'detection_time_s': f'{detection_time:.2f}' if detection_time else '',
        'drops_max_concurrent': max_rules,
        'drops_total_events': len(events_this_run),
        'fp_bans': fp_bans,
        'legit_loss_avg_pct': loss_avg,
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
    print(f'HASIL SKENARIO scale50: {scenario}')
    print('=' * 60)
    for k, v in summary.items():
        print(f'  {k:24s}: {v}')
    print(f'\nDetail timeseries : {ts_file}')
    print(f'Log controller    : {ctrl_log_path}')
    return summary


def main():
    ap = argparse.ArgumentParser(
        description='Runner eksperimen scale50 (50 IoT + victim)')
    ap.add_argument('--scenario', required=True,
                    choices=['baseline', 'single', 'mixed'])
    ap.add_argument('--warmup', type=float, default=5.0)
    ap.add_argument('--flood-duration', type=float, default=10.0)
    ap.add_argument('--post', type=float, default=20.0)
    ap.add_argument('--ping-interval', type=float, default=0.2)
    ap.add_argument('--legit-count', type=int, default=DEFAULT_LEGIT_COUNT,
                    help='jumlah host IoT utk trafik legitimate (default 10)')
    ap.add_argument('--repeats', type=int, default=1,
                    help='ulangi eksperimen N kali (untuk mean +/- stddev)')
    args = ap.parse_args()

    setLogLevel('warning')
    for _i in range(max(1, args.repeats)):
        run_scenario(args.scenario, args.warmup, args.flood_duration,
                     args.post, args.ping_interval, args.legit_count)


if __name__ == '__main__':
    main()
