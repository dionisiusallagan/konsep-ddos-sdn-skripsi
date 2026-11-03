#!/usr/bin/env python3
"""
Tahap D - Load Sweep Perbandingan Algoritme (baseline vs S2TD vs entropi).

Tujuan
======
Memetakan bagaimana waktu deteksi, CPU controller, packet loss legitimate,
dan throughput-per-CPU berubah ketika beban serangan dinaikkan bertahap.
Setiap titik beban diulang N kali agar bisa dilaporkan sebagai mean +/- stddev.

CARA KERJA
==========
Skrip ini TIDAK menduplikasi logika eksperimen. Ia memanggil
`experiments/run_experiment.py --algo ... --rate ... --repeats 1` satu kali
per run, lalu membaca baris yang baru ditambahkan ke
`results/exp_summary_compare.csv`.

Urutan eksekusi (penting untuk validitas):
  rate terluar (naik)  ->  algoritme  ->  repeat
Artinya ketiga algoritme diuji pada beban yang sama secara berdekatan,
sehingga efek drift lingkungan (suhu/CPU host) tidak pilih kasih.

ATURAN BERHENTI
===============
Setelah semua repeat pada satu titik (algo, rate) selesai:
  jenuh jika  cpu_attack_mean > --stop-cpu  ATAU  loss_legit_max > --stop-loss
Algoritme yang jenuh dilewati pada rate yang lebih tinggi (tidak ada gunanya
menekan beban lebih jauh; hasilnya hanya mengulang kondisi saturasi).
Algoritme lain tetap lanjut. Alasan berhenti dicatat di kolom stop_reason.

METRIK (lihat CATATAN_TAHAP_C.md untuk definisi lengkap)
========================================================
- detection_time_s : jeda dari paket flood pertama sampai rule DROP terpasang,
  dihitung dari jam dinding (ts_iso event controller - t0 penanda flooder).
  Resolusi milidetik; kolom detection_time_poll_s menyimpan versi polling
  ovs-ofctl 0,2 s sebagai pembanding.
- detected_rate_pps : informatif, TIDAK sebanding antar algoritme.
- cpu_attack_*     : CPU pada fase serangan (bukan rata-rata seluruh run).
- throughput_per_cpu = flood_actual_mean_pps / cpu_attack_mean_pct
  (paket/detik nyata per 1% CPU controller).

CARA PAKAI (root, dari venv project)
====================================
  sudo ~/ddos-venv/bin/python experiments/run_sweep_compare.py
  sudo ~/ddos-venv/bin/python experiments/run_sweep_compare.py \
       --rates 100,500,1000,1500 --repeats 3
  sudo ~/ddos-venv/bin/python experiments/run_sweep_compare.py --dry-run

Output:
  results/exp_summary_compare.csv   (raw, satu baris per run; append)
  results/compare_stats.csv         (ringkasan mean+/-stddev per titik)
  results/tahapD/                   (log controller, timeseries, log flood)
"""

import argparse
import csv
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(HERE)
RESULTS_DIR = os.path.join(PROJECT_ROOT, 'results')
RAW_CSV = os.path.join(RESULTS_DIR, 'exp_summary_compare.csv')
RUNNER = os.path.join(HERE, 'run_experiment.py')

ALGO_LABEL = {
    'baseline': 'Baseline (threshold per-IP)',
    's2td': 'S2TD (dua tahap, flow caching)',
    'entropy': 'Entropy (Shannon, tanpa caching)',
}

STATS_FIELDS = [
    'algo', 'scenario', 'flood_rate_pps',
    'n_runs', 'n_detected', 'det_miss',
    'detection_time_mean_s', 'detection_time_std_s',
    'detection_time_min_s', 'detection_time_max_s',
    'flood_actual_mean_pps', 'detected_rate_mean_pps',
    'cpu_attack_mean_pct', 'cpu_attack_std_pct', 'cpu_attack_max_pct',
    'cpu_run_mean_pct',
    'loss_mean_pct', 'loss_max_pct',
    'fp_bans_total', 'drops_mean',
    'throughput_per_cpu',
    'saturated', 'stop_reason',
]


# -------------------------------------------------------------------------
# UTILITAS
# -------------------------------------------------------------------------
def read_raw_rows():
    """Baca semua baris data exp_summary_compare.csv (tanpa header)."""
    if not os.path.exists(RAW_CSV):
        return []
    with open(RAW_CSV, newline='') as f:
        return list(csv.DictReader(f))


def num(value):
    """Konversi ke float; kembalikan None untuk sel kosong/nan."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return None
    return v if v == v else None          # buang NaN


def col(rows, key):
    """Ambil semua nilai numerik dari satu kolom."""
    out = []
    for r in rows:
        v = num(r.get(key))
        if v is not None:
            out.append(v)
    return out


def mean_std(values):
    """Return (mean, stddev). stddev kosong bila n < 2."""
    if not values:
        return None, None
    m = sum(values) / len(values)
    s = statistics.stdev(values) if len(values) > 1 else None
    return m, s


def fmt(value, nd=2):
    return '' if value is None else f'{value:.{nd}f}'


# -------------------------------------------------------------------------
# SATU RUN
# -------------------------------------------------------------------------
def run_one(args, algo, rate, repeat, index, total):
    """Jalankan satu eksperimen lengkap lewat runner. Return (baris, detik)."""
    before = len(read_raw_rows())
    cmd = [sys.executable, RUNNER,
           '--scenario', args.scenario,
           '--algo', algo,
           '--rate', f'{rate:g}',
           '--repeats', '1',
           '--repeat-start', str(repeat),
           '--legit-count', str(args.legit_count),
           '--warmup', str(args.warmup),
           '--flood-duration', str(args.flood_duration),
           '--post', str(args.post)]
    if args.subdir:
        cmd += ['--subdir', args.subdir]

    label = f'[{index}/{total}] rate={rate:g}pps algo={algo} rep={repeat}'
    print(f'{label} ...', end='', flush=True)
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True,
                              text=True, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        raise SystemExit(f'\nERROR: run melewati batas waktu {args.timeout}s '
                         f'({label}). Jalankan manual untuk memeriksa.')
    elapsed = time.time() - t0

    new_rows = read_raw_rows()[before:]
    if proc.returncode != 0 or not new_rows:
        print(' GAGAL')
        print('--- stdout (ekor) ---')
        print('\n'.join(proc.stdout.strip().splitlines()[-25:]))
        print('--- stderr (ekor) ---')
        print('\n'.join(proc.stderr.strip().splitlines()[-25:]))
        raise SystemExit(f'ERROR: run gagal (algo={algo} rate={rate} '
                         f'rep={repeat}, exit={proc.returncode})')

    row = new_rows[-1]
    det = row.get('detection_time_s') or '-'
    print(f' ok {elapsed:.0f}s | deteksi={det}s '
          f'cpu_serang={row.get("cpu_attack_avg_pct") or "-"}% '
          f'loss={row.get("legit_loss_max_pct") or "-"}%')
    return row, elapsed


# -------------------------------------------------------------------------
# AGREGASI SATU TITIK (algo, rate)
# -------------------------------------------------------------------------
def aggregate(args, algo, rate, rows):
    det = col(rows, 'detection_time_s')
    det_mean, det_std = mean_std(det)
    cpu_attack = col(rows, 'cpu_attack_avg_pct')
    cpu_mean, cpu_std = mean_std(cpu_attack)
    peak_vals = col(rows, 'cpu_attack_max_pct')
    cpu_peak = max(peak_vals) if peak_vals else None
    cpu_run = col(rows, 'cpu_avg_pct')
    cpu_run_mean, _ = mean_std(cpu_run)
    loss_max_runs = col(rows, 'legit_loss_max_pct')
    loss_mean_runs = col(rows, 'legit_loss_mean_pct')
    actual = col(rows, 'flood_actual_pps')
    det_rate = col(rows, 'detected_rate_pps')

    loss_mean, _ = mean_std(loss_mean_runs)
    loss_worst = max(loss_max_runs) if loss_max_runs else None
    actual_mean, _ = mean_std(actual)
    det_rate_mean, _ = mean_std(det_rate)
    drops_mean, _ = mean_std(col(rows, 'drops_total_events'))

    # throughput per CPU memakai beban NYATA (bukan nominal) agar adil ketika
    # pacing tidak sepenuhnya tercapai pada beban tinggi.
    tput = None
    if actual_mean is not None and cpu_mean:
        tput = actual_mean / cpu_mean

    # ---- aturan berhenti ------------------------------------------------
    reasons = []
    if cpu_mean is not None and cpu_mean > args.stop_cpu:
        reasons.append(f'cpu>{args.stop_cpu:g}')
    if loss_worst is not None and loss_worst > args.stop_loss:
        reasons.append(f'loss>{args.stop_loss:g}')
    reason = ';'.join(reasons)

    return {
        'algo': algo,
        'scenario': args.scenario,
        'flood_rate_pps': f'{rate:g}',
        'n_runs': len(rows),
        'n_detected': len(det),
        'det_miss': len(rows) - len(det),
        'detection_time_mean_s': fmt(det_mean, 3),
        'detection_time_std_s': fmt(det_std, 3),
        'detection_time_min_s': fmt(min(det) if det else None, 3),
        'detection_time_max_s': fmt(max(det) if det else None, 3),
        'flood_actual_mean_pps': fmt(actual_mean, 1),
        'detected_rate_mean_pps': fmt(det_rate_mean, 1),
        'cpu_attack_mean_pct': fmt(cpu_mean),
        'cpu_attack_std_pct': fmt(cpu_std),
        'cpu_attack_max_pct': fmt(cpu_peak),
        'cpu_run_mean_pct': fmt(cpu_run_mean),
        'loss_mean_pct': fmt(loss_mean),
        'loss_max_pct': fmt(loss_worst),
        'fp_bans_total': int(sum(col(rows, 'fp_bans'))),
        'drops_mean': fmt(drops_mean, 1),
        'throughput_per_cpu': fmt(tput, 2),
        'saturated': 'ya' if reason else 'tidak',
        'stop_reason': reason,
    }


def merge_levels(existing_path, new_levels):
    """Gabungkan baris baru dengan isi compare_stats.csv yang sudah ada.

    Baris dengan (algo, scenario, flood_rate_pps) sama diganti versi baru;
    baris lain dipertahankan. Gunanya: sweep bisa dijalankan BERTAHAP
    (mis. 100-1500 pps dulu, lalu 3000/6000 pps) tanpa menghapus hasil
    sebelumnya, dan pengulangan satu titik aman (tidak menduplikasi baris).
    """
    merged = {}
    if os.path.exists(existing_path):
        with open(existing_path, newline='') as f:
            for row in csv.DictReader(f):
                try:
                    key = (row['algo'], row['scenario'],
                           float(row['flood_rate_pps']))
                except (KeyError, ValueError, TypeError):
                    continue
                merged[key] = row
    for row in new_levels:
        key = (row['algo'], row['scenario'], float(row['flood_rate_pps']))
        merged[key] = row
    order = {a: i for i, a in enumerate(ALGO_LABEL)}
    return sorted(merged.values(),
                  key=lambda r: (float(r['flood_rate_pps']),
                                 order.get(r['algo'], 99)))


def write_stats(levels, out_path):
    """Tulis ulang compare_stats.csv dari seluruh titik yang sudah selesai.

    Ditulis ulang tiap titik (bukan di akhir) supaya hasil parsial tetap ada
    bila sweep dihentikan di tengah jalan.
    """
    with open(out_path, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=STATS_FIELDS)
        w.writeheader()
        for row in levels:
            w.writerow(row)


# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description='Tahap D: load sweep perbandingan algoritme DDoS-SDN.')
    ap.add_argument('--rates', default='100,500,1000,1500',
                    help='daftar beban (pps), koma-pisah, naik (default: '
                         '100,500,1000,1500)')
    ap.add_argument('--repeats', type=int, default=3,
                    help='pengulangan per titik (default 3)')
    ap.add_argument('--algos', default='baseline,s2td,entropy',
                    help='algoritme yang diuji, koma-pisah')
    ap.add_argument('--scenario', default='mixed',
                    help='skenario runner (default mixed: flood + trafik legit)')
    ap.add_argument('--legit-count', type=int, default=3,
                    help='jumlah host legitimate (default 3 -> victim 10.0.0.5)')
    ap.add_argument('--warmup', type=float, default=5.0)
    ap.add_argument('--flood-duration', type=float, default=10.0)
    ap.add_argument('--post', type=float, default=20.0)
    ap.add_argument('--stop-cpu', type=float, default=80.0,
                    help='CPU fase serangan (%% ) yang dianggap jenuh')
    ap.add_argument('--stop-loss', type=float, default=1.0,
                    help='loss legitimate (%%) yang dianggap jenuh')
    ap.add_argument('--timeout', type=float, default=300.0,
                    help='batas waktu satu run (detik)')
    ap.add_argument('--subdir', default='tahapD',
                    help='subfolder results/ untuk log bukti (default tahapD)')
    ap.add_argument('--stats-out', default=os.path.join(RESULTS_DIR,
                                                        'compare_stats.csv'),
                    help='path ringkasan (default results/compare_stats.csv)')
    ap.add_argument('--dry-run', action='store_true',
                    help='tampilkan rencana tanpa menjalankan apa pun')
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit('ERROR: jalankan sebagai root (sudo), karena Mininet/OVS '
                 'butuh akses jaringan. Contoh:\n'
                 '  sudo ~/ddos-venv/bin/python '
                 'experiments/run_sweep_compare.py')
    if not os.path.isfile(RUNNER):
        sys.exit(f'ERROR: runner tidak ditemukan: {RUNNER}')
    if args.repeats < 1:
        ap.error('--repeats minimal 1')

    rates = sorted({float(x) for x in args.rates.split(',') if x.strip()})
    algos = [a.strip() for a in args.algos.split(',') if a.strip()]
    bad = [a for a in algos if a not in ALGO_LABEL]
    if bad:
        sys.exit(f'ERROR: algoritme tidak dikenal: {bad}. '
                 f'Pilihan: {list(ALGO_LABEL)}')

    planned = len(rates) * len(algos) * args.repeats
    print('=' * 70)
    print('TAHAP D - LOAD SWEEP PERBANDINGAN ALGORITME')
    print('=' * 70)
    print(f'  skenario      : {args.scenario} '
          f'({args.legit_count} host legit -> victim '
          f'10.0.0.{args.legit_count + 2})')
    print(f'  rate (pps)    : {", ".join(f"{r:g}" for r in rates)}')
    print(f'  algoritme     : {", ".join(algos)}')
    print(f'  repeat/titik  : {args.repeats}')
    print(f'  total run     : {planned} (maks, sebelum aturan berhenti)')
    print(f'  berhenti bila : cpu > {args.stop_cpu:g}% '
          f'atau loss legit > {args.stop_loss:g}%')
    print(f'  raw CSV       : {RAW_CSV}')
    print(f'  stats CSV     : {args.stats_out}')
    print(f'  log bukti     : {os.path.join(RESULTS_DIR, args.subdir)}')
    print('=' * 70)

    if args.dry_run:
        print('\n(--dry-run: tidak ada run yang dijalankan)')
        return

    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(os.path.join(RESULTS_DIR, args.subdir), exist_ok=True)
    os.makedirs(os.path.dirname(args.stats_out), exist_ok=True)

    t_start = time.time()
    levels = []                  # baris compare_stats.csv
    saturated = {}               # algo -> alasan
    index = 0

    for rate in rates:
        for algo in algos:
            if algo in saturated:
                print(f'[lewati] rate={rate:g}pps algo={algo}: '
                      f'jenuh ({saturated[algo]})')
                continue
            level_rows = []
            for rep in range(1, args.repeats + 1):
                index += 1
                row, _ = run_one(args, algo, rate, rep, index, planned)
                level_rows.append(row)

            agg = aggregate(args, algo, rate, level_rows)
            levels.append(agg)
            write_stats(merge_levels(args.stats_out, levels), args.stats_out)

            print(f'  -> {algo} @ {rate:g}pps: '
                  f'deteksi {agg["detection_time_mean_s"] or "-"}'
                  f'±{agg["detection_time_std_s"] or "-"}s | '
                  f'cpu {agg["cpu_attack_mean_pct"] or "-"}% | '
                  f'loss {agg["loss_max_pct"] or "-"}% | '
                  f'tput/cpu {agg["throughput_per_cpu"] or "-"}')

            if agg['stop_reason']:
                saturated[algo] = agg['stop_reason']
                print(f'  -> STOP {algo} di {rate:g}pps '
                      f'({agg["stop_reason"]}); rate lebih tinggi dilewati')

    # ---- tabel ringkasan akhir ------------------------------------------
    # Pakai hasil GABUNGAN: bila sweep dijalankan bertahap, tabel ini juga
    # menampilkan titik-titik dari invokasi sebelumnya.
    all_levels = merge_levels(args.stats_out, levels)
    print('\n' + '=' * 70)
    print(f'RINGKASAN compare_stats.csv ({len(all_levels)} titik)')
    print('=' * 70)
    hdr = (f'{"algo":9s} {"rate":>6s} {"n":>2s} {"detik":>15s} '
           f'{"cpu%":>6s} {"loss%":>6s} {"tput/cpu":>9s} {"status":>7s}')
    print(hdr)
    for r in all_levels:
        det = r['detection_time_mean_s'] or '-'
        std = r['detection_time_std_s']
        det_s = f'{det}±{std}' if std else det
        print(f'{r["algo"]:9s} {r["flood_rate_pps"]:>6s} {r["n_runs"]:>2d} '
              f'{det_s:>15s} {r["cpu_attack_mean_pct"] or "-":>6s} '
              f'{r["loss_max_pct"] or "-":>6s} '
              f'{r["throughput_per_cpu"] or "-":>9s} '
              f'{r["saturated"]:>7s}')

    elapsed = time.time() - t_start
    print(f'\nSelesai {index} run dalam {elapsed / 60:.1f} menit')
    print(f'Ringkasan : {args.stats_out}')
    print(f'Raw       : {RAW_CSV}')
    print(f'Log bukti : {os.path.join(RESULTS_DIR, args.subdir)}')
    print(f'Waktu     : {datetime.now().isoformat(timespec="seconds")}')


if __name__ == '__main__':
    main()
