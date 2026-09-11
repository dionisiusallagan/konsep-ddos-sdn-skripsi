#!/usr/bin/env python3
"""
Topologi skala besar: 50 IoT edge nodes + 1 victim/server (fase scale50).

Perbedaan dengan topology/basic_topo.py (fase 5 host):
- 50 host IoT (h1..h50), h51 = victim/server -> total 51 host.
- Tetap SATU switch (s1, OpenFlow 1.3) agar perbandingan CPU controller
  dengan fase 5-host adil (jumlah switch/data path sama, yang berubah
  hanya jumlah node & trafik).
- Controller tetap remote (os-ken di 127.0.0.1:6633).

Peran host:
- h1          : attacker (konsisten dengan fase sebelumnya)
- h2..h50     : IoT edge nodes (subset dipakai sebagai trafik legitimate)
- h51         : victim/server tujuan

CATATAN KINERJA:
- net.pingAll() pada 51 host = 2550 pasangan ping (butuh ~1 menit).
  Untuk verifikasi cepat gunakan ping subset (lihat --quick).
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info

N_IOT = 50                 # jumlah IoT edge nodes
VICTIM_ID = N_IOT + 1      # h51 = victim


class IoTTopo50(Topo):
    """Topologi 50 IoT + 1 victim pada satu switch OpenFlow 1.3."""

    def build(self):
        # Switch tunggal - alasan: perbandingan adil dgn fase 5-host
        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        # 50 host IoT + 1 victim, IP statis 10.0.0.1 .. 10.0.0.51
        hosts = []
        for i in range(1, VICTIM_ID + 1):
            h = self.addHost(f'h{i}', ip=f'10.0.0.{i}/24')
            hosts.append(h)

        # Semua host tersambung langsung ke s1 (bintang/star)
        for h in hosts:
            self.addLink(h, s1, bw=100, delay='1ms', loss=0)


def run_topo(quick=False):
    """Jalankan jaringan + tes konektivitas + CLI interaktif."""
    setLogLevel('info')

    net = Mininet(
        topo=IoTTopo50(),
        controller=lambda name: RemoteController(name, ip='127.0.0.1',
                                                 port=6633),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )
    net.start()
    net.waitConnected(timeout=120)

    if quick:
        # verifikasi cepat: 3 host acak ping victim
        info('*** Quick connectivity check\n')
        for hn in ('h1', 'h25', 'h50'):
            print(net.get(hn).cmd(f'ping -c 1 -W 2 10.0.0.{VICTIM_ID}'))
    else:
        info('*** pingAll penuh (2550 pasangan, ~1 menit)...\n')
        net.pingAll()

    info('*** CLI Mininet (exit untuk keluar)\n')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    import sys
    run_topo(quick='--quick' in sys.argv)
