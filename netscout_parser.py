#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
netscout_parser.py — Parser Laporan NetScout
============================================

Modul Python untuk mem-parsing output XML Nmap dan menghasilkan laporan
yang mudah dibaca manusia dalam format .txt dan .csv.

Penggunaan:
    python3 netscout_parser.py --xml scan.xml --output ./hasil/ \\
                               --target 192.168.1.0/24 \\
                               --profile standard \\
                               --operator admin \\
                               --timestamp 20240101_120000

Penulis  : NetScout Team
Lisensi  : Untuk penggunaan yang sah dan terotorisasi
"""

import argparse
import csv
import os
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict


# ─── Konstanta Warna ANSI ────────────────────────────────────────────────────
class Warna:
    """Konstanta kode warna ANSI untuk output terminal berwarna."""
    MERAH    = '\033[0;31m'
    HIJAU    = '\033[0;32m'
    KUNING   = '\033[1;33m'
    BIRU     = '\033[0;34m'
    CYAN     = '\033[0;36m'
    MAGENTA  = '\033[0;35m'
    PUTIH    = '\033[1;37m'
    BOLD     = '\033[1m'
    RESET    = '\033[0m'
    DIM      = '\033[2m'


# ─── Model Data ──────────────────────────────────────────────────────────────

@dataclass
class InfoPort:
    """Merepresentasikan satu port dengan detail layanannya."""
    nomor: str
    protokol: str
    state: str
    layanan: str
    versi: str
    catatan: str = ""

    @property
    def adalah_menarik(self) -> bool:
        """Cek apakah port ini merupakan layanan yang menarik/berisiko tinggi."""
        layanan_menarik = {
            'ftp', 'ssh', 'telnet', 'smtp', 'dns', 'http', 'pop3',
            'imap', 'https', 'smb', 'mssql', 'mysql', 'rdp', 'vnc',
            'ldap', 'snmp', 'nfs', 'rpc', 'oracle', 'mongodb',
            'redis', 'elasticsearch', 'memcached', 'postgresql'
        }
        return self.layanan.lower() in layanan_menarik


@dataclass
class InfoHost:
    """Merepresentasikan satu host dengan semua informasi terkait."""
    alamat_ip: str
    hostname: str = ""
    status: str = ""
    tebakan_os: str = "Tidak terdeteksi"
    akurasi_os: str = ""
    daftar_port: List[InfoPort] = field(default_factory=list)

    @property
    def jumlah_port_terbuka(self) -> int:
        """Hitung jumlah port dengan state 'open'."""
        return sum(1 for p in self.daftar_port if p.state == 'open')

    @property
    def port_menarik(self) -> List[InfoPort]:
        """Kembalikan daftar port yang menarik/berisiko tinggi."""
        return [p for p in self.daftar_port if p.adalah_menarik and p.state == 'open']


@dataclass
class MetadataScan:
    """Metadata keseluruhan sesi scan."""
    target: str
    profil: str
    operator: str
    timestamp: str
    waktu_mulai: str = ""
    waktu_selesai: str = ""
    versi_nmap: str = ""
    argumen_nmap: str = ""


# ─── Kelas Parser XML ────────────────────────────────────────────────────────

class ParserNmapXML:
    """
    Mem-parsing file XML output Nmap menjadi struktur data Python.

    Mendukung parsing:
    - Informasi host (IP, hostname, status)
    - Detail port (nomor, state, layanan, versi)
    - OS fingerprinting
    - Metadata scan
    """

    def __init__(self, path_xml: str):
        """
        Inisialisasi parser dengan path file XML.

        Args:
            path_xml: Path absolut atau relatif ke file XML Nmap
        """
        self.path_xml = path_xml
        self.tree: Optional[ET.ElementTree] = None
        self.root: Optional[ET.Element] = None

    def muat(self) -> bool:
        """
        Muat dan parse file XML.

        Returns:
            True jika berhasil, False jika gagal
        """
        try:
            self.tree = ET.parse(self.path_xml)
            self.root = self.tree.getroot()
            return True
        except ET.ParseError as e:
            print(f"{Warna.MERAH}[ERROR]{Warna.RESET} XML tidak valid: {e}")
            return False
        except FileNotFoundError:
            print(f"{Warna.MERAH}[ERROR]{Warna.RESET} File tidak ditemukan: {self.path_xml}")
            return False

    def ambil_metadata(self, meta: MetadataScan) -> MetadataScan:
        """
        Ekstrak metadata scan dari elemen root XML.

        Args:
            meta: Objek MetadataScan yang akan diisi

        Returns:
            Objek MetadataScan yang sudah terisi
        """
        if self.root is None:
            return meta

        # Ambil versi dan argumen Nmap
        meta.versi_nmap = self.root.get('version', 'Tidak diketahui')
        meta.argumen_nmap = self.root.get('args', '')

        # Ambil waktu scan
        elem_runstats = self.root.find('runstats')
        if elem_runstats is not None:
            elem_finished = elem_runstats.find('finished')
            if elem_finished is not None:
                timestamp_unix = elem_finished.get('time', '0')
                try:
                    waktu = datetime.fromtimestamp(int(timestamp_unix))
                    meta.waktu_selesai = waktu.strftime('%Y-%m-%d %H:%M:%S')
                except (ValueError, OSError):
                    meta.waktu_selesai = 'Tidak diketahui'

        return meta

    def ambil_semua_host(self) -> List[InfoHost]:
        """
        Ekstrak semua informasi host dari XML.

        Returns:
            List objek InfoHost
        """
        daftar_host = []

        if self.root is None:
            return daftar_host

        for elem_host in self.root.findall('host'):
            host = self._parse_satu_host(elem_host)
            if host:
                daftar_host.append(host)

        return daftar_host

    def _parse_satu_host(self, elem_host: ET.Element) -> Optional[InfoHost]:
        """
        Parse satu elemen host XML menjadi objek InfoHost.

        Args:
            elem_host: Elemen XML <host>

        Returns:
            Objek InfoHost atau None jika tidak valid
        """
        # Ambil alamat IP
        alamat_ip = ""
        for elem_addr in elem_host.findall('address'):
            if elem_addr.get('addrtype') == 'ipv4':
                alamat_ip = elem_addr.get('addr', '')
                break
            elif elem_addr.get('addrtype') == 'ipv6' and not alamat_ip:
                alamat_ip = elem_addr.get('addr', '')

        if not alamat_ip:
            return None

        # Ambil status host
        elem_status = elem_host.find('status')
        status = elem_status.get('state', 'unknown') if elem_status is not None else 'unknown'

        # Ambil hostname
        hostname = ""
        elem_hostnames = elem_host.find('hostnames')
        if elem_hostnames is not None:
            elem_hn = elem_hostnames.find('hostname')
            if elem_hn is not None:
                hostname = elem_hn.get('name', '')

        # Buat objek host
        host = InfoHost(
            alamat_ip=alamat_ip,
            hostname=hostname,
            status=status
        )

        # Parse OS fingerprint
        host = self._parse_os(elem_host, host)

        # Parse port
        host.daftar_port = self._parse_port(elem_host)

        return host

    def _parse_os(self, elem_host: ET.Element, host: InfoHost) -> InfoHost:
        """
        Parse informasi OS fingerprint dari elemen host.

        Args:
            elem_host: Elemen XML <host>
            host: Objek InfoHost yang akan diisi

        Returns:
            Objek InfoHost dengan informasi OS
        """
        elem_os = elem_host.find('os')
        if elem_os is None:
            return host

        # Cari osmatch dengan akurasi tertinggi
        osmatch_terbaik = None
        akurasi_tertinggi = 0

        for elem_match in elem_os.findall('osmatch'):
            akurasi = int(elem_match.get('accuracy', '0'))
            if akurasi > akurasi_tertinggi:
                akurasi_tertinggi = akurasi
                osmatch_terbaik = elem_match

        if osmatch_terbaik is not None:
            host.tebakan_os = osmatch_terbaik.get('name', 'Tidak terdeteksi')
            host.akurasi_os = f"{akurasi_tertinggi}%"

        return host

    def _parse_port(self, elem_host: ET.Element) -> List[InfoPort]:
        """
        Parse semua port dari elemen host.

        Args:
            elem_host: Elemen XML <host>

        Returns:
            List objek InfoPort
        """
        daftar_port = []

        elem_ports = elem_host.find('ports')
        if elem_ports is None:
            return daftar_port

        for elem_port in elem_ports.findall('port'):
            port = self._parse_satu_port(elem_port)
            if port:
                daftar_port.append(port)

        # Urutkan berdasarkan nomor port
        daftar_port.sort(key=lambda p: int(p.nomor))

        return daftar_port

    def _parse_satu_port(self, elem_port: ET.Element) -> Optional[InfoPort]:
        """
        Parse satu elemen port XML menjadi objek InfoPort.

        Args:
            elem_port: Elemen XML <port>

        Returns:
            Objek InfoPort atau None jika tidak valid
        """
        nomor = elem_port.get('portid', '')
        protokol = elem_port.get('protocol', '')

        # State
        elem_state = elem_port.find('state')
        state = elem_state.get('state', 'unknown') if elem_state is not None else 'unknown'

        # Layanan
        layanan = ""
        versi = ""
        catatan = ""
        elem_service = elem_port.find('service')
        if elem_service is not None:
            layanan = elem_service.get('name', '')
            produk = elem_service.get('product', '')
            ver = elem_service.get('version', '')
            extra = elem_service.get('extrainfo', '')

            # Gabungkan informasi versi
            bagian_versi = [x for x in [produk, ver] if x]
            versi = ' '.join(bagian_versi)
            catatan = extra

        # Cek apakah ada script output yang menarik
        for elem_script in elem_port.findall('script'):
            script_id = elem_script.get('id', '')
            # Tandai port yang memiliki temuan vulnerability
            if 'vuln' in script_id.lower() or 'exploit' in script_id.lower():
                catatan = f"⚠ VULN: {catatan}" if catatan else "⚠ Potensi Vulnerability"

        return InfoPort(
            nomor=nomor,
            protokol=protokol,
            state=state,
            layanan=layanan,
            versi=versi,
            catatan=catatan
        )


# ─── Kelas Generator Laporan ─────────────────────────────────────────────────

class GeneratorLaporan:
    """
    Menghasilkan laporan dalam format yang mudah dibaca dari data host hasil scan.

    Mendukung output:
    - Terminal (berwarna)
    - File teks (.txt)
    - File CSV (.csv)
    """

    def __init__(self, daftar_host: List[InfoHost], metadata: MetadataScan,
                 direktori_output: str):
        """
        Inisialisasi generator laporan.

        Args:
            daftar_host: List hasil parsing host
            metadata: Metadata sesi scan
            direktori_output: Direktori untuk menyimpan file output
        """
        self.daftar_host = daftar_host
        self.metadata = metadata
        self.direktori_output = direktori_output

    def _header_ascii(self) -> str:
        """Buat header ASCII dengan metadata scan."""
        baris = "=" * 72
        return f"""
{baris}
  NETSCOUT — LAPORAN PEMINDAIAN JARINGAN
{baris}
  Tanggal     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Target      : {self.metadata.target}
  Profil      : {self.metadata.profil.upper()}
  Operator    : {self.metadata.operator}
  Versi Nmap  : {self.metadata.versi_nmap}
  Timestamp   : {self.metadata.timestamp}
{baris}
"""

    def _warna_state(self, state: str) -> str:
        """
        Kembalikan teks state dengan kode warna ANSI.

        Args:
            state: State port ('open', 'closed', 'filtered', dll)

        Returns:
            Teks state dengan warna
        """
        peta_warna = {
            'open':     f"{Warna.HIJAU}open{Warna.RESET}",
            'closed':   f"{Warna.MERAH}closed{Warna.RESET}",
            'filtered': f"{Warna.KUNING}filtered{Warna.RESET}",
            'unknown':  f"{Warna.DIM}unknown{Warna.RESET}",
        }
        return peta_warna.get(state, state)

    def _tabel_port_terminal(self, daftar_port: List[InfoPort]) -> str:
        """
        Buat tabel port untuk output terminal (dengan warna).

        Args:
            daftar_port: List port yang akan ditampilkan

        Returns:
            String tabel yang diformat
        """
        if not daftar_port:
            return f"  {Warna.DIM}(Tidak ada port yang terdeteksi){Warna.RESET}\n"

        lebar = {
            'port':    8,
            'state':   12,
            'service': 15,
            'versi':   30,
            'catatan': 20,
        }

        # Header tabel
        header = (
            f"  {'PORT':<{lebar['port']}} "
            f"{'STATE':<{lebar['state']}} "
            f"{'SERVICE':<{lebar['service']}} "
            f"{'VERSION':<{lebar['versi']}} "
            f"{'NOTES':<{lebar['catatan']}}"
        )
        garis = "  " + "─" * 90

        baris_list = [f"{Warna.BOLD}{header}{Warna.RESET}", garis]

        for port in daftar_port:
            port_str = f"{port.nomor}/{port.protokol}"
            state_warna = self._warna_state(port.state)
            # Tambah padding manual karena state_warna mengandung escape codes
            state_pad = port.state.ljust(lebar['state'])
            layanan = port.layanan[:lebar['service']].ljust(lebar['service'])
            versi = port.versi[:lebar['versi']].ljust(lebar['versi'])
            catatan = port.catatan[:lebar['catatan']]

            # Warnai port menarik
            if port.adalah_menarik and port.state == 'open':
                prefix = f"{Warna.CYAN}"
            else:
                prefix = ""

            baris = (
                f"  {prefix}{port_str:<{lebar['port']}} "
                f"{self._warna_state(port.state)}"
                f"{' ' * (lebar['state'] - len(port.state))} "
                f"{layanan} "
                f"{versi} "
                f"{catatan}{Warna.RESET}"
            )
            baris_list.append(baris)

        return "\n".join(baris_list) + "\n"

    def _tabel_port_teks(self, daftar_port: List[InfoPort]) -> str:
        """
        Buat tabel port untuk output file teks (tanpa warna).

        Args:
            daftar_port: List port yang akan ditampilkan

        Returns:
            String tabel yang diformat (tanpa escape codes)
        """
        if not daftar_port:
            return "  (Tidak ada port yang terdeteksi)\n"

        lebar = {'port': 10, 'state': 10, 'service': 15, 'versi': 30, 'catatan': 25}
        header = (
            f"  {'PORT':<{lebar['port']}} "
            f"{'STATE':<{lebar['state']}} "
            f"{'SERVICE':<{lebar['service']}} "
            f"{'VERSION':<{lebar['versi']}} "
            f"{'NOTES'}"
        )
        garis = "  " + "-" * 95

        baris_list = [header, garis]

        for port in daftar_port:
            port_str = f"{port.nomor}/{port.protokol}"
            baris = (
                f"  {port_str:<{lebar['port']}} "
                f"{port.state:<{lebar['state']}} "
                f"{port.layanan[:lebar['service']]:<{lebar['service']}} "
                f"{port.versi[:lebar['versi']]:<{lebar['versi']}} "
                f"{port.catatan[:lebar['catatan']]}"
            )
            baris_list.append(baris)

        return "\n".join(baris_list) + "\n"

    def _bagian_host_terminal(self, host: InfoHost, nomor: int) -> str:
        """
        Format bagian satu host untuk output terminal.

        Args:
            host: Objek InfoHost
            nomor: Nomor urut host

        Returns:
            String terformat dengan warna
        """
        garis_tebal = f"{Warna.BIRU}{'═' * 72}{Warna.RESET}"
        garis_tipis = f"{Warna.DIM}{'─' * 72}{Warna.RESET}"

        bagian = [
            "",
            garis_tebal,
            f"  {Warna.PUTIH}{Warna.BOLD}HOST #{nomor}: {host.alamat_ip}{Warna.RESET}",
            garis_tipis,
        ]

        if host.hostname:
            bagian.append(f"  {Warna.CYAN}Hostname  :{Warna.RESET} {host.hostname}")

        bagian.append(f"  {Warna.CYAN}Status    :{Warna.RESET} "
                      f"{Warna.HIJAU if host.status == 'up' else Warna.MERAH}"
                      f"{host.status.upper()}{Warna.RESET}")

        if host.tebakan_os != "Tidak terdeteksi":
            bagian.append(f"  {Warna.CYAN}OS Tebakan:{Warna.RESET} "
                          f"{host.tebakan_os} "
                          f"{Warna.DIM}(Akurasi: {host.akurasi_os}){Warna.RESET}")

        bagian.append(f"  {Warna.CYAN}Port Terbuka:{Warna.RESET} "
                      f"{Warna.HIJAU}{host.jumlah_port_terbuka}{Warna.RESET}")

        bagian.append("")
        bagian.append(f"  {Warna.PUTIH}DETAIL PORT:{Warna.RESET}")
        bagian.append(self._tabel_port_terminal(host.daftar_port))

        # Tampilkan layanan menarik
        if host.port_menarik:
            bagian.append(f"  {Warna.KUNING}⚠ Layanan Menarik:{Warna.RESET}")
            for port in host.port_menarik:
                bagian.append(
                    f"    {Warna.CYAN}→{Warna.RESET} "
                    f"{port.nomor}/{port.protokol} "
                    f"({port.layanan}) "
                    f"{Warna.DIM}{port.versi}{Warna.RESET}"
                )
            bagian.append("")

        return "\n".join(bagian)

    def _bagian_host_teks(self, host: InfoHost, nomor: int) -> str:
        """
        Format bagian satu host untuk file teks (tanpa warna).

        Args:
            host: Objek InfoHost
            nomor: Nomor urut host

        Returns:
            String terformat tanpa escape codes
        """
        garis = "=" * 72
        garis_tipis = "-" * 72

        bagian = [
            "",
            garis,
            f"HOST #{nomor}: {host.alamat_ip}",
            garis_tipis,
        ]

        if host.hostname:
            bagian.append(f"Hostname   : {host.hostname}")

        bagian.append(f"Status     : {host.status.upper()}")

        if host.tebakan_os != "Tidak terdeteksi":
            bagian.append(f"OS Tebakan : {host.tebakan_os} (Akurasi: {host.akurasi_os})")

        bagian.append(f"Port Terbuka: {host.jumlah_port_terbuka}")
        bagian.append("")
        bagian.append("DETAIL PORT:")
        bagian.append(self._tabel_port_teks(host.daftar_port))

        if host.port_menarik:
            bagian.append("Layanan Menarik:")
            for port in host.port_menarik:
                bagian.append(f"  → {port.nomor}/{port.protokol} ({port.layanan}) {port.versi}")
            bagian.append("")

        return "\n".join(bagian)

    def _bagian_ringkasan_terminal(self) -> str:
        """
        Buat bagian ringkasan keseluruhan scan untuk terminal.

        Returns:
            String ringkasan dengan warna
        """
        host_aktif = [h for h in self.daftar_host if h.status == 'up']
        total_port_terbuka = sum(h.jumlah_port_terbuka for h in host_aktif)

        # Kumpulkan semua layanan unik
        layanan_ditemukan: Dict[str, int] = {}
        for host in host_aktif:
            for port in host.daftar_port:
                if port.state == 'open' and port.layanan:
                    layanan_ditemukan[port.layanan] = \
                        layanan_ditemukan.get(port.layanan, 0) + 1

        # Urutkan berdasarkan frekuensi
        layanan_terurut = sorted(
            layanan_ditemukan.items(),
            key=lambda x: x[1],
            reverse=True
        )

        garis = f"{Warna.MAGENTA}{'═' * 72}{Warna.RESET}"
        bagian = [
            "",
            garis,
            f"  {Warna.PUTIH}{Warna.BOLD}RINGKASAN SCAN{Warna.RESET}",
            garis,
            f"  {Warna.CYAN}Total Host Dipindai  :{Warna.RESET} {len(self.daftar_host)}",
            f"  {Warna.CYAN}Host Aktif (Up)      :{Warna.RESET} "
            f"{Warna.HIJAU}{len(host_aktif)}{Warna.RESET}",
            f"  {Warna.CYAN}Total Port Terbuka   :{Warna.RESET} "
            f"{Warna.HIJAU}{total_port_terbuka}{Warna.RESET}",
            "",
        ]

        if layanan_terurut:
            bagian.append(f"  {Warna.PUTIH}Layanan yang Ditemukan:{Warna.RESET}")
            for layanan, jumlah in layanan_terurut[:15]:
                tanda = "⚠" if layanan in {'telnet', 'ftp', 'snmp', 'rdp', 'vnc'} else "•"
                warna = Warna.KUNING if tanda == "⚠" else Warna.CYAN
                bagian.append(
                    f"    {warna}{tanda}{Warna.RESET} "
                    f"{layanan:<20} "
                    f"{Warna.DIM}({jumlah} instance){Warna.RESET}"
                )

        bagian.append("")
        bagian.append(garis)

        return "\n".join(bagian)

    def _bagian_ringkasan_teks(self) -> str:
        """
        Buat bagian ringkasan keseluruhan scan untuk file teks.

        Returns:
            String ringkasan tanpa escape codes
        """
        host_aktif = [h for h in self.daftar_host if h.status == 'up']
        total_port_terbuka = sum(h.jumlah_port_terbuka for h in host_aktif)

        layanan_ditemukan: Dict[str, int] = {}
        for host in host_aktif:
            for port in host.daftar_port:
                if port.state == 'open' and port.layanan:
                    layanan_ditemukan[port.layanan] = \
                        layanan_ditemukan.get(port.layanan, 0) + 1

        layanan_terurut = sorted(
            layanan_ditemukan.items(),
            key=lambda x: x[1],
            reverse=True
        )

        garis = "=" * 72
        bagian = [
            "",
            garis,
            "RINGKASAN SCAN",
            garis,
            f"Total Host Dipindai  : {len(self.daftar_host)}",
            f"Host Aktif (Up)      : {len(host_aktif)}",
            f"Total Port Terbuka   : {total_port_terbuka}",
            "",
        ]

        if layanan_terurut:
            bagian.append("Layanan yang Ditemukan:")
            for layanan, jumlah in layanan_terurut[:15]:
                bagian.append(f"  • {layanan:<20} ({jumlah} instance)")

        bagian.append("")
        bagian.append(garis)

        return "\n".join(bagian)

    def tampilkan_terminal(self):
        """Tampilkan laporan lengkap ke terminal dengan warna."""
        print(self._header_ascii())

        for i, host in enumerate(self.daftar_host, start=1):
            print(self._bagian_host_terminal(host, i))

        print(self._bagian_ringkasan_terminal())

    def simpan_teks(self, path_output: str):
        """
        Simpan laporan ke file teks.

        Args:
            path_output: Path file output .txt
        """
        konten = []
        konten.append(self._header_ascii())

        for i, host in enumerate(self.daftar_host, start=1):
            konten.append(self._bagian_host_teks(host, i))

        konten.append(self._bagian_ringkasan_teks())

        with open(path_output, 'w', encoding='utf-8') as f:
            f.write("\n".join(konten))

        print(f"{Warna.HIJAU}[✓]{Warna.RESET} Laporan teks disimpan: {path_output}")

    def simpan_csv(self, path_output: str):
        """
        Simpan data port semua host ke file CSV.

        Args:
            path_output: Path file output .csv
        """
        kolom = [
            'IP', 'Hostname', 'Status', 'OS', 'Akurasi OS',
            'Port', 'Protokol', 'State', 'Layanan', 'Versi', 'Catatan'
        ]

        with open(path_output, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=kolom)
            writer.writeheader()

            for host in self.daftar_host:
                if not host.daftar_port:
                    # Host tanpa port tetap dicatat
                    writer.writerow({
                        'IP': host.alamat_ip,
                        'Hostname': host.hostname,
                        'Status': host.status,
                        'OS': host.tebakan_os,
                        'Akurasi OS': host.akurasi_os,
                        'Port': '', 'Protokol': '', 'State': '',
                        'Layanan': '', 'Versi': '', 'Catatan': ''
                    })
                else:
                    for port in host.daftar_port:
                        writer.writerow({
                            'IP': host.alamat_ip,
                            'Hostname': host.hostname,
                            'Status': host.status,
                            'OS': host.tebakan_os,
                            'Akurasi OS': host.akurasi_os,
                            'Port': port.nomor,
                            'Protokol': port.protokol,
                            'State': port.state,
                            'Layanan': port.layanan,
                            'Versi': port.versi,
                            'Catatan': port.catatan,
                        })

        print(f"{Warna.HIJAU}[✓]{Warna.RESET} Laporan CSV disimpan: {path_output}")


# ─── Fungsi Utama ─────────────────────────────────────────────────────────────

def parse_argumen() -> argparse.Namespace:
    """
    Parse argumen command-line.

    Returns:
        Namespace dengan semua argumen yang diparsing
    """
    parser = argparse.ArgumentParser(
        description='NetScout Parser — Menghasilkan laporan dari output XML Nmap',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--xml',       required=True,  help='Path ke file XML Nmap')
    parser.add_argument('--output',    required=True,  help='Direktori output untuk laporan')
    parser.add_argument('--target',    default='N/A',  help='Target scan (untuk metadata)')
    parser.add_argument('--profile',   default='standard', help='Profil scan yang digunakan')
    parser.add_argument('--operator',  default='unknown', help='Nama operator')
    parser.add_argument('--timestamp', default='', help='Timestamp scan')

    return parser.parse_args()


def main():
    """Fungsi entry point utama parser."""
    args = parse_argumen()

    # Pastikan direktori output ada
    os.makedirs(args.output, exist_ok=True)

    # Inisialisasi metadata
    metadata = MetadataScan(
        target=args.target,
        profil=args.profile,
        operator=args.operator,
        timestamp=args.timestamp or datetime.now().strftime('%Y%m%d_%H%M%S')
    )

    # Parse XML
    print(f"\n{Warna.BIRU}[INFO]{Warna.RESET} Mem-parsing file XML: {args.xml}")
    parser = ParserNmapXML(args.xml)

    if not parser.muat():
        sys.exit(1)

    # Ambil metadata dari XML
    metadata = parser.ambil_metadata(metadata)

    # Ambil data host
    daftar_host = parser.ambil_semua_host()
    print(f"{Warna.HIJAU}[✓]{Warna.RESET} Berhasil memparse {len(daftar_host)} host")

    if not daftar_host:
        print(f"{Warna.KUNING}[PERINGATAN]{Warna.RESET} Tidak ada host yang ditemukan dalam XML")
        # Tetap lanjut untuk membuat laporan kosong
    
    # Buat generator laporan
    generator = GeneratorLaporan(daftar_host, metadata, args.output)

    # Tampilkan ke terminal
    generator.tampilkan_terminal()

    # Simpan ke file
    path_laporan_txt = os.path.join(args.output, 'laporan.txt')
    path_laporan_csv = os.path.join(args.output, 'laporan.csv')

    generator.simpan_teks(path_laporan_txt)
    generator.simpan_csv(path_laporan_csv)

    print(f"\n{Warna.HIJAU}{Warna.BOLD}[✓] Semua laporan berhasil dibuat!{Warna.RESET}")


if __name__ == '__main__':
    main()