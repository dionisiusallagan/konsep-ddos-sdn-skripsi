#!/usr/bin/env python3
"""
Topologi Mininet dasar untuk proof-of-concept DDoS mitigation pada SDN.

Struktur:
- 1 controller remote (Ryu)
- 1 switch OpenFlow 1.3 (OVSSwitch)
- 5 host: h1-h4 sebagai IoT edge nodes, h5 sebagai victim/server

Author: Dionisius - Skripsi S1 Teknik Komputer
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class DDosTopo(Topo):
    """Topologi sederhana: 1 switch, 5 host, 1 controller remote."""

    def build(self):
        # Switch OpenFlow 1.3
        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        # Host h1-h4: IoT edge nodes (potensi attacker)
        # Host h5: victim/server tujuan
        hosts = []
        for i in range(1, 6):
            h = self.addHost(f'h{i}', ip=f'10.0.0.{i}/24')
            hosts.append(h)

        # Koneksi semua host ke switch dengan bandwidth limit (opsional, untuk realisme)
        for h in hosts:
            self.addLink(h, s1, bw=100, delay='1ms', loss=0)


def run_topo():
    """Jalankan topologi Mininet dengan controller remote Ryu."""
    setLogLevel('info')

    info('*** Membuat jaringan dengan controller remote (Ryu)\n')
    # Controller remote: Ryu berjalan di localhost:6633 (default)
    net = Mininet(
        topo=DDosTopo(),
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6633),
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True,
        autoStaticArp=True
    )

    info('*** Memulai jaringan\n')
    net.start()

    info('*** Menunggu koneksi switch ke controller...\n')
    # Tunggu switch terhubung ke controller
    import time
    time.sleep(3)

    info('*** Testing konektivitas dasar (pingAll)\n')
    net.pingAll()

    info('*** Masuk ke CLI Mininet (ketik exit untuk keluar)\n')
    CLI(net)

    info('*** Menghentikan jaringan\n')
    net.stop()


if __name__ == '__main__':
    run_topo()