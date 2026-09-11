# FASE scale50 — 50 IoT Edge Nodes

Fase kedua skripsi: **menaikkan skala topologi 5x** (5 host → 51 host) dengan
logika deteksi yang **identik**, untuk mengukur dampaknya pada beban CPU
controller. Kode fase lama (folder `topology/`, `controller/`, dst.) tidak
disentuh — hasil kedua fase dapat dibandingkan langsung.

## Struktur

```
scale50/
├── topology/large_topo.py       # IoTTopo50: h1..h50 IoT + h51 victim, 1 switch OF1.3
├── controller/ddos_guard50.py   # salinan identik ddos_guard.py (logika sama)
├── traffic/flood_scapy.py       # generator serangan (salinan)
├── experiments/run_scale50.py   # runner 3 skenario
└── results/                     # output fase ini (terpisah dari fase lama)
```

**Kenapa logika controller tidak diubah?** Agar perbandingan *apple-to-apple*:
yang berubah hanya skala topologi & jumlah trafik, bukan algoritmanya.
Output CSV otomatis mengarah ke `scale50/results/` karena path dihitung
relatif terhadap lokasi file controller.

**Kenapa tetap 1 switch?** Agar variabel yang diuji murni "jumlah node",
bukan berubahnya arsitektur data-path.

## Peran host

| Host | Peran |
|---|---|
| h1 | attacker |
| h2..h50 | IoT edge nodes (default 10 pertama dipakai sebagai trafik legitimate, bisa diatur `--legit-count`) |
| h51 | victim/server (10.0.0.51) |

## Menjalankan

```bash
# Terminal 1 (opsional, verifikasi manual topologi):
cd scale50/topology
sudo -E python3 large_topo.py --quick     # ping 3 host saja (cepat)
# tanpa --quick = pingAll penuh 2550 pasangan (~1 menit)

# Eksperimen (masing-masing membangun jaringannya sendiri, setup ~30-60 dtk):
cd scale50/experiments
sudo ~/ddos-venv/bin/python run_scale50.py --scenario baseline
sudo ~/ddos-venv/bin/python run_scale50.py --scenario single
sudo ~/ddos-venv/bin/python run_scale50.py --scenario mixed
```

## Output

`scale50/results/`:
- `exp_summary.csv` — ringkasan per run (kolom tambahan vs fase lama: `n_hosts`, `n_legit`, `legit_loss_avg_pct`)
- `exp_timeseries_*.csv` — CPU/mem/jiffies/rule per 0,5 s
- `controller_*.log` — log controller per run
- `mitigation_events.csv` — histori kejadian blokir fase ini

## Hasil perbandingan 5 host vs 51 host (data: run di mesin penulis, 2026-08-26)

| Metrik | 5 host (fase 1) | 51 host (fase 2) | Tren |
|---|---|---|---|
| CPU baseline (avg/max) | 1,0 / 3,9% | 4,7 / 31,5% | ↑ ~4× (10 host legit ping terus-menerus ≈ 500 packet-in/5s) |
| Waktu deteksi (single) | 0,64 s | 1,35 s | ↑ tetap orde ~1 detik |
| CPU max saat serangan (single) | 27,5% | 49,9% | ↑ ~1,8× |
| Waktu deteksi (mixed) | 0,86 s | 0,85 s | ≈ sama |
| CPU max saat serangan (mixed) | 31,4% | 66,0% | ↑ ~2× |
| FPR (mixed): fp_bans / loss legit | 0 / 0% | **0 / 0%** | tetap sempurna |

**Interpretasi cepat (bahan bab hasil):**
- Beban dasar controller naik seiring skala (lebih banyak state & trafik latar),
  tetapi tetap rendah secara absolut (< 5% rata-rata).
- Puncak CPU saat serangan naik ~2×, namun **waktu deteksi tidak terdegradasi
  signifikan** (tetap 0,85–1,35 s) dan **false positive tetap nol** — bukti
  pendekatan per-source-IP + threshold absolut tetap valid pada skala 10×.
- Pola `STATS` saat mixed: trafik legitimate terus mengalir (~500/5s) sementara
  attacker disunyikan oleh DROP rule → mitigasi presisi tanpa collateral damage.
