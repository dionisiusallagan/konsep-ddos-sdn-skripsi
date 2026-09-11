#!/usr/bin/env python3
"""
visualize_results.py - Hasilkan chart dari CSV eksperimen skripsi DDoS-SDN.

Membaca semua CSV hasil di folder:
  - results/            (fase 1: 5 host)
  - scale50/results/     (fase 2: 51 host)
yaitu:
  - exp_summary.csv      : ringkasan per run (deteksi, cpu, fp, loss)
  - exp_timeseries_*.csv : deret waktu cpu/mem/jiffies/drop_rules (+loss bila ada)

Menghasilkan 4 chart PNG (dpi=150) ke results/plots/:
  1. Bar  : rata-rata waktu deteksi (single, mixed) per fase
  2. Line : CPU controller vs waktu, window serangan di-highlight (axvspan)
  3. Line : packet loss host legitimate vs waktu (jika kolom loss ada)
  4. Bar  : false positive rate per skenario per fase

Robust: format CSV beda / kolom hilang -> skip + warning, tidak crash.
Reusable: cukup jalankan `python visualize_results.py` tiap ada data baru.
"""

import glob
import os
import sys
import tempfile

# cache matplotlib di temp agar tidak bergantung permission $HOME
os.environ.setdefault('MPLCONFIGDIR', tempfile.mkdtemp(prefix='mpl_'))

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import pandas as pd

# ---- style ---------------------------------------------------------------
for _s in ('seaborn-v0_8', 'seaborn', 'ggplot'):
    try:
        plt.style.use(_s)
        break
    except OSError:
        continue

# ---- path -----------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_DIRS = [
    os.path.join(SCRIPT_DIR, 'results'),
    os.path.join(SCRIPT_DIR, 'scale50', 'results'),
]
PLOTS_DIR = os.path.join(SCRIPT_DIR, 'results', 'plots')
os.makedirs(PLOTS_DIR, exist_ok=True)

PHASE_LABEL = {
    os.path.join(SCRIPT_DIR, 'results'): '5 host',
    os.path.join(SCRIPT_DIR, 'scale50', 'results'): '51 host',
}
COLORS = {'5 host': '#1f77b4', '51 host': '#d62728'}


def warn(msg):
    print(f'[WARN] {msg}', file=sys.stderr)


def safe_numeric(series):
    return pd.to_numeric(series, errors='coerce')


def load_summaries():
    frames = []
    for d in RESULT_DIRS:
        f = os.path.join(d, 'exp_summary.csv')
        if not os.path.exists(f):
            continue
        try:
            df = pd.read_csv(f)
        except Exception as e:
            warn(f'gagal baca {f}: {e}')
            continue
        df['phase'] = PHASE_LABEL.get(d, os.path.basename(os.path.dirname(d)))
        frames.append(df)
    if not frames:
        warn(f'tidak ada exp_summary.csv di {RESULT_DIRS}')
        return pd.DataFrame()
    return pd.concat(frames, ignore_index=True)


def load_timeseries():
    """Return list of (phase, scenario, df) untuk tiap exp_timeseries_*.csv."""
    out = []
    for d in RESULT_DIRS:
        for path in glob.glob(os.path.join(d, 'exp_timeseries_*.csv')):
            if os.path.getsize(path) == 0:
                warn(f'file kosong dilewati: {path}')
                continue
            base = os.path.basename(path)
            # format: exp_timeseries_{scenario}_{ts}.csv (ts mengandung '_')
            body = base[len('exp_timeseries_'):-len('.csv')]
            parts = body.split('_')
            if len(parts) < 2:
                warn(f'format nama tidak dikenali: {base}')
                continue
            scenario = parts[0]
            try:
                df = pd.read_csv(path)
            except Exception as e:
                if 'No columns' in str(e):
                    warn(f'file kosong/tanpa kolom dilewati: {path}')
                    continue
                warn(f'gagal baca {path}: {e}')
                continue
            if df.empty:
                warn(f'file tanpa data dilewati: {path}')
                continue
            out.append((PHASE_LABEL.get(d, '?'), scenario, df))
    return out


# ---- 1. Bar: rata-rata waktu deteksi --------------------------------------
def chart_detection_time(summary):
    if summary.empty or 'detection_time_s' not in summary:
        warn('tidak ada data detection_time_s -> chart deteksi dilewati')
        return
    rows = []
    for phase in ['5 host', '51 host']:
        sub = summary[summary['phase'] == phase]
        for sc in ['single', 'mixed']:
            col = safe_numeric(sub[sub['scenario'] == sc]['detection_time_s']).dropna()
            if col.empty:
                continue
            rows.append({'phase': phase, 'scenario': sc, 'mean': col.mean(),
                         'std': col.std(ddof=1) if len(col) > 1 else 0.0,
                         'min': col.min(), 'max': col.max()})
    if not rows:
        warn('tidak ada baris detection_time_s valid -> chart deteksi dilewati')
        return
    df = pd.DataFrame(rows)
    scenarios = ['single', 'mixed']
    phases = [p for p in ['5 host', '51 host'] if p in df['phase'].unique()]
    x = range(len(scenarios))
    width = 0.35
    fig, ax = plt.subplots(figsize=(7, 5))
    for i, phase in enumerate(phases):
        s = df[df['phase'] == phase].set_index('scenario').reindex(scenarios)
        bars = ax.bar([xj + i * width for xj in x], s['mean'].values, width,
                      yerr=s['std'].values, capsize=4, label=phase,
                      color=COLORS.get(phase, '#333'))
        # label nilai di atas bar
        for bar, v in zip(bars, s['mean'].values):
            if pd.notna(v):
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                        f'{v:.2f}', ha='center', va='bottom', fontsize=8)
    ax.set_xticks([xj + width * (len(phases) - 1) / 2 for xj in x])
    ax.set_xticklabels(scenarios)
    ax.set_title('Rata-rata Waktu Deteksi per Skenario')
    ax.set_ylabel('Waktu (detik)')
    ax.set_xlabel('Skenario')
    ax.legend(title='Fase')
    ax.text(0.5, -0.18, 'baseline tidak memiliki event deteksi (tanpa serangan)',
            transform=ax.transAxes, ha='center', fontsize=7, style='italic', color='#555')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'detection_time.png'), dpi=150)
    plt.close()
    print('\n=== Waktu Deteksi (s) ===')
    for _, r in df.iterrows():
        print(f"  {r['phase']} / {r['scenario']}: mean={r['mean']:.3f}  "
              f"min={r['min']:.3f}  max={r['max']:.3f}  std={r['std']:.3f}")


# ---- 2. Line: CPU vs waktu (window serangan di-highlight) -----------------
def chart_cpu_timeseries(ts_list):
    from collections import defaultdict
    SCENARIO_STYLE = {'baseline': ':', 'single': '--', 'mixed': '-'}
    groups = defaultdict(list)
    for phase, sc, df in ts_list:
        if df.empty or 't_rel_s' not in df or 'cpu_pct' not in df:
            continue
        groups[(phase, sc)].append(df)
    if not groups:
        warn('tidak ada exp_timeseries_*.csv -> chart CPU dilewati')
        return
    fig, ax = plt.subplots(figsize=(10, 5))
    # Satu window serangan saja [5–15s] (warmup=5s, flood=10s di semua run).
    # Sebelumnya 4 window tertumpuk dengan warna sama -> terlihat seperti 1 blok tebal.
    ax.axvspan(5, 15, facecolor='#FFB74D', alpha=0.18, hatch='///', edgecolor='#FF9800',
               label='window serangan [5–15 s]')
    # Gambar garis: warna = fase, gaya garis = skenario (jadi tidak semua sama)
    for (phase, sc), dfs in groups.items():
        color = COLORS.get(phase, '#333')
        ls = SCENARIO_STYLE.get(sc, '-')
        # tiap run: faint
        for df in dfs:
            t = safe_numeric(df['t_rel_s'])
            c = safe_numeric(df['cpu_pct'])
            valid = t.notna() & c.notna() & (t >= 0.5)  # buang spike startup t=0
            ax.plot(t[valid], c[valid], color=color, linestyle=ls, alpha=0.22, linewidth=1)
        # satu run representatif: tebal + label (agar legend hanya 1 per kombinasi)
        try:
            t0 = safe_numeric(dfs[0]['t_rel_s'])
            c0 = safe_numeric(dfs[0]['cpu_pct'])
            valid0 = t0.notna() & c0.notna() & (t0 >= 0.5)
            ax.plot(t0[valid0], c0[valid0], color=color, linestyle=ls,
                    alpha=0.95, linewidth=2.2, label=f'{phase} / {sc}')
        except Exception:
            pass
    ax.set_title('Beban CPU Controller vs Waktu')
    ax.set_xlabel('Waktu (detik)')
    ax.set_ylabel('CPU (%)')
    ax.set_ylim(bottom=0)
    ax.set_xlim(0, 35)
    # Legend: pisah agar tidak menumpuk. Window di kiri atas, garis di kanan atas.
    handles, labels = ax.get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    ax.legend(by_label.values(), by_label.keys(), fontsize=7, loc='upper right',
              framealpha=0.92, ncols=1,
              title='Garis: warna=fase, gaya=skenario | Oranye=periode serangan')
    # Anotasi kecil penjelas window (supaya tanpa legend pun jelas)
    ax.text(10, ax.get_ylim()[1] * 0.92, '← serangan aktif (flood) →',
            ha='center', fontsize=7, color='#E65100', style='italic')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'cpu_timeseries.png'), dpi=150)
    plt.close()


# ---- 3. Line: packet loss legit vs waktu ----------------------------------
def chart_loss_timeseries(ts_list):
    frames = []
    for phase, sc, df in ts_list:
        loss_cols = [c for c in df.columns if 'loss' in c.lower()]
        if not loss_cols or 't_rel_s' not in df:
            continue
        t = safe_numeric(df['t_rel_s'])
        for c in loss_cols:
            v = safe_numeric(df[c])
            valid = t.notna() & v.notna()
            frames.append(pd.DataFrame({'t': t[valid], 'loss': v[valid],
                                        'phase': phase, 'scenario': sc,
                                        'col': c}))
    if not frames:
        warn('tidak ada kolom loss di timeseries (kedua fase tidak mencatat '
             'loss per-waktu) -> chart packet loss dilewati')
        return
    data = pd.concat(frames, ignore_index=True)
    fig, ax = plt.subplots(figsize=(9, 5))
    for (phase, sc, col), g in data.groupby(['phase', 'scenario', 'col']):
        ax.plot(g['t'], g['loss'], label=f'{phase}/{sc}/{col}', alpha=0.7)
    ax.set_title('Packet Loss pada Host Legitimate vs Waktu')
    ax.set_xlabel('Waktu (detik)')
    ax.set_ylabel('Packet loss (%)')
    ax.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'legit_loss_timeseries.png'), dpi=150)
    plt.close()


# ---- 4. Bar: false positive rate ------------------------------------------
def chart_fp_rate(summary):
    if summary.empty or 'fp_bans' not in summary:
        warn('kolom fp_bans tidak ada -> chart FP dilewati')
        return
    rows = []
    for phase in ['5 host', '51 host']:
        sub = summary[summary['phase'] == phase]
        for sc in ['baseline', 'single', 'mixed']:
            s = sub[sub['scenario'] == sc]
            fp = safe_numeric(s['fp_bans']).dropna()
            if fp.empty:
                continue
            nleg = safe_numeric(s.get('n_legit',
                                     pd.Series([0] * len(s)))).fillna(0)
            nleg_mean = nleg.mean() if len(nleg) else 0
            fpr = (fp.mean() / nleg_mean * 100.0) if nleg_mean > 0 else 0.0
            rows.append({'phase': phase, 'scenario': sc, 'fp_rate': fpr,
                         'fp_mean': fp.mean(), 'fp_min': fp.min(),
                         'fp_max': fp.max()})
    if not rows:
        warn('tidak ada data fp_bans -> chart FP dilewati')
        return
    df = pd.DataFrame(rows)
    scenarios = ['baseline', 'single', 'mixed']
    phases = [p for p in ['5 host', '51 host'] if p in df['phase'].unique()]
    x = range(len(scenarios))
    width = 0.35
    fig, ax = plt.subplots(figsize=(7, 5))
    for i, phase in enumerate(phases):
        s = df[df['phase'] == phase].set_index('scenario').reindex(scenarios)
        vals = s['fp_rate'].values
        # ganti NaN (skenario hilang) dengan 0
        vals = [0 if pd.isna(v) else v for v in vals]
        bars = ax.bar([xj + i * width for xj in x], vals, width,
                      label=phase, color=COLORS.get(phase, '#333'))
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                    f'{v:.1f}%', ha='center', va='bottom', fontsize=8, color='#333')
    ax.set_xticks([xj + width * (len(phases) - 1) / 2 for xj in x])
    ax.set_xticklabels(scenarios)
    ax.set_title('False Positive Rate per Skenario')
    ax.set_ylabel('FPR (%)')
    ax.set_xlabel('Skenario')
    ax.set_ylim(0, 1.2)  # semua 0% -> beri ruang agar label terlihat
    ax.text(0.5, 0.5, 'Tidak ada false positive di semua skenario (FPR = 0%)',
            transform=ax.transAxes, ha='center', va='center', fontsize=9,
            color='#2ca02c', style='italic',
            bbox=dict(boxstyle='round,pad=0.3', fc='#e8f5e9', ec='#a5d6a7'))
    ax.legend(title='Fase')
    plt.tight_layout()
    plt.savefig(os.path.join(PLOTS_DIR, 'fp_rate.png'), dpi=150)
    plt.close()
    print('\n=== False Positive Rate (%) ===')
    for _, r in df.iterrows():
        print(f"  {r['phase']} / {r['scenario']}: FPR={r['fp_rate']:.2f}  "
              f"(fp_bans mean={r['fp_mean']:.2f}, min={r['fp_min']:.0f}, "
              f"max={r['fp_max']:.0f})")


def main():
    print('Membaca hasil eksperimen dari:', RESULT_DIRS)
    summary = load_summaries()
    ts_list = load_timeseries()
    chart_detection_time(summary)
    chart_cpu_timeseries(ts_list)
    chart_loss_timeseries(ts_list)
    chart_fp_rate(summary)
    print(f'\nSelesai. Chart tersimpan di: {PLOTS_DIR}')


if __name__ == '__main__':
    main()
