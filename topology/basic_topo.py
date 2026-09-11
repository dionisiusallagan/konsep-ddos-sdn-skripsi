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
    """Topologi dasar: 1 switch, 1 controller remote, N host legitimate.

    Konvensi penomoran (penting, dipakai runner):
      h1                 = attacker (konsisten di semua skenario)
      h2 .. h{n_iot+1}   = host legitimate (IoT edge nodes)
      h{n_iot+2}         = victim / server tujuan
    Default n_iot=3 -> topologi 5 host (h1..h5), identik desain awal.
    Naikkan n_iot untuk skenario flash_crowd (5-10 host legitimate).
    """

    def build(self, n_iot=3):
        # Switch OpenFlow 1.3
        s1 = self.addSwitch('s1', protocols='OpenFlow13')

        # Total host = attacker(1) + legitimate(n_iot) + victim(1) = n_iot+2
        # h1 = attacker, h2..h{n_iot+1} = legit, h{n_iot+2} = victim
        hosts = []
        for i in range(1, n_iot + 3):
            h = self.addHost(f'h{i}', ip=f'10.0.0.{i}/24')
            hosts.append(h)

        # Koneksi semua host ke switch dengan bandwidth limit (opsional)
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