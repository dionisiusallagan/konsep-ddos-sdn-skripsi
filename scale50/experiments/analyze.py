#!/usr/bin/env python3
"""
Analisis hasil eksperimen scale50: hitung mean +/- stddev per skenario.

Membaca scale50/results/exp_summary.csv (dihadirkan oleh run_scale50.py
dengan --repeats) lalu untuk tiap skenario menghitung rata-rata & simpangan
baku (sample, n-1) untuk metrik numerik. Hasil ditulis ke
scale50/results/summary_stats.csv dan dicetak sebagai tabel (siap untuk
bab hasil skripsi).

Penggunaan:
    ~/ddos-venv/bin/python scale50/experiments/analyze.py
"""

import csv
import math
import os
import sys
from collections import defaultdict

EXPERIMENT_DIR = os.path.dirname(os.path.abspath(__file__))
SCALE50_ROOT = os.path.dirname(EXPERIMENT_DIR)
SUMMARY_CSV = os.path.join(SCALE50_ROOT, 'results', 'exp_summary.csv')
OUT_CSV = os.path.join(SCALE50_ROOT, 'results', 'summary_stats.csv')

# metrik numerik yg dianalisis (sesuai kolom exp_summary.csv)
METRICS = [
    'detection_time_s', 'cpu_avg_pct', 'cpu_max_pct', 'mem_avg_pct',
    'drops_max_concurrent', 'drops_total_events', 'fp_bans',
    'legit_loss_avg_pct',
]
# metrik berbasis hitungan -> formatting integer (bukan desimal)
INT_METRICS = {'fp_bans', 'drops_max_concurrent', 'drops_total_events'}


def _to_float(v):
    v = (v or '').strip()
    if v == '':
        return None
    try:
        f = float(v)
    except ValueError:
        return None
    if not math.isfinite(f):      # abaikan "nan" / "inf" dari CSV
        return None
    return f


def _mean(vals):
    return sum(vals) / len(vals)


def _stdev(vals):
    """Sample stddev (n-1), dihitung manual (hindari bug statistics.stdev
    di Python 3.12 yg mengembalikan float utk sum-of-squares eksak)."""
    n = len(vals)
    if n < 2:
        return 0.0
    m = _mean(vals)
    return math.sqrt(sum((x - m) ** 2 for x in vals) / (n - 1))


def main():
    if not os.path.exists(SUMMARY_CSV):
        sys.exit(f'ERROR: {SUMMARY_CSV} tidak ditemukan. Jalankan dulu '
                 'run_scale50.py --scenario <x> --repeats N.')
    rows = list(csv.DictReader(open(SUMMARY_CSV)))
    if not rows:
        sys.exit('ERROR: exp_summary.csv kosong.')

    by_scenario = defaultdict(list)
    for r in rows:
        by_scenario[r['scenario']].append(r)

    stats = []
    for scen, scen_rows in by_scenario.items():
        for m in METRICS:
            vals = [_to_float(r.get(m)) for r in scen_rows]
            vals = [v for v in vals if v is not None]
            n = len(vals)
            if n == 0:
                mean = std = None
            else:
                mean = _mean(vals)
                std = _stdev(vals)                    # sample stddev (n-1)
            fmt = (lambda x: f'{x:.0f}') if m in INT_METRICS \
                else (lambda x: f'{x:.3f}')
            stats.append({
                'scenario': scen, 'metric': m, 'n': n,
                'mean': fmt(mean) if mean is not None else '',
                'stddev': fmt(std) if std is not None else '',
            })

    with open(OUT_CSV, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['scenario', 'metric', 'n',
                                          'mean', 'stddev'])
        w.writeheader()
        w.writerows(stats)

    print('=' * 66)
    print('RINGKASAN  mean +/- stddev  per SKENARIO (fase scale50)')
    print('=' * 66)
    for scen in by_scenario:
        print(f'\n## Skenario: {scen}   (n = {len(by_scenario[scen])} run)')
        print(f'{"metrik":<24}{"mean":>14}{"stddev":>14}')
        print('-' * 52)
        for s in stats:
            if s['scenario'] == scen:
                print(f'{s["metric"]:<24}{s["mean"]:>14}{s["stddev"]:>14}')
    print(f'\nTersimpan: {OUT_CSV}')


if __name__ == '__main__':
    main()
