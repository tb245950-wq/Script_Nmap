#!/usr/bin/env bash
# =============================================================================
# NETSCOUT - Alat Otomasi Pemindaian Jaringan & Enumerasi Layanan
# =============================================================================
#
# README / PANDUAN INSTALASI DAN PENGGUNAAN
# =========================================
#
# PRASYARAT:
#   - Linux/macOS dengan Bash 4.0+
#   - Nmap (versi 7.0+)
#   - Python 3.6+
#   - Akses root/sudo (diperlukan untuk SYN scan)
#
# INSTALASI:
#   1. Unduh kedua file: netscout.sh dan netscout_parser.py
#   2. Tempatkan keduanya di direktori yang sama
#   3. Beri izin eksekusi:
#        chmod +x netscout.sh
#   4. (Opsional) Salin ke /usr/local/bin untuk akses global:
#        sudo cp netscout.sh /usr/local/bin/netscout
#        sudo cp netscout_parser.py /usr/local/bin/netscout_parser.py
#
# PENGGUNAAN DASAR:
#   sudo ./netscout.sh --target 192.168.1.1 --accept-tos
#   sudo ./netscout.sh --target 192.168.1.0/24 --profile full --accept-tos
#   sudo ./netscout.sh --target hosts.txt --profile stealth --accept-tos
#   sudo ./netscout.sh --target 10.0.0.1 --dry-run --accept-tos
#   sudo ./netscout.sh --target 192.168.1.0/24 --report-only --output ./hasil_scan/ --accept-tos
#
# CONTOH LENGKAP:
#   sudo ./netscout.sh -t 192.168.1.0/24 -p full -o ./hasil/ -r 1000 --accept-tos
#   sudo ./netscout.sh -t 10.10.10.5 -p stealth --no-ping --accept-tos
#
# =============================================================================

# ─── Opsi Ketat Bash ─────────────────────────────────────────────────────────
set -euo pipefail
IFS=$'\n\t'

# ─── Konstanta Warna Terminal ─────────────────────────────────────────────────
MERAH='\033[0;31m'
HIJAU='\033[0;32m'
KUNING='\033[1;33m'
BIRU='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
PUTIH='\033[1;37m'
RESET='\033[0m'
BOLD='\033[1m'

# ─── Nilai Default Variabel Global ────────────────────────────────────────────
TARGET=""
OUTPUT_DIR=""
PROFIL="standard"
MAX_RATE=""
SKIP_PING=false
REPORT_ONLY=false
DRY_RUN=false
ACCEPT_TOS=false
FULL_PORTS=false
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARSER_SCRIPT="${SCRIPT_DIR}/netscout_parser.py"

# ─── Fungsi: Tampilkan Banner ─────────────────────────────────────────────────
tampilkan_banner() {
    echo -e "${CYAN}"
    cat << 'EOF'
  ███╗   ██╗███████╗████████╗███████╗ ██████╗ ██████╗ ██╗   ██╗████████╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝
  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ██║   ██║██║   ██║   ██║   
  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██║   ██║██║   ██║   ██║   
  ██║ ╚████║███████╗   ██║   ███████║╚██████╗╚██████╔╝╚██████╔╝   ██║   
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝  ╚═════╝    ╚═╝   
EOF
    echo -e "${RESET}"
    echo -e "${PUTIH}  Alat Otomasi Pemindaian Jaringan & Enumerasi Layanan${RESET}"
    echo -e "${KUNING}  Versi 1.0 | Untuk Penggunaan yang Sah dan Terotorisasi${RESET}"
    echo -e "  ${BIRU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

# ─── Fungsi: Tampilkan Peringatan Etika ──────────────────────────────────────
tampilkan_peringatan_etika() {
    echo -e "${MERAH}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║           ⚠  PERINGATAN PENTING - BACA DULU  ⚠          ║"
    echo "  ╠══════════════════════════════════════════════════════════╣"
    echo "  ║  Alat ini HANYA boleh digunakan pada sistem/jaringan    ║"
    echo "  ║  yang Anda MILIKI atau yang telah memberikan IZIN        ║"
    echo "  ║  TERTULIS kepada Anda untuk melakukan pengujian.         ║"
    echo "  ║                                                          ║"
    echo "  ║  Pemindaian tanpa izin adalah ILEGAL dan dapat           ║"
    echo "  ║  mengakibatkan tuntutan hukum pidana maupun perdata.     ║"
    echo "  ║                                                          ║"
    echo "  ║  Gunakan flag --accept-tos untuk mengkonfirmasi bahwa    ║"
    echo "  ║  Anda telah mendapat otorisasi yang sah.                 ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# ─── Fungsi: Tampilkan Bantuan ───────────────────────────────────────────────
tampilkan_bantuan() {
    tampilkan_banner
    echo -e "${PUTIH}${BOLD}PENGGUNAAN:${RESET}"
    echo -e "  sudo $0 [OPSI]"
    echo ""
    echo -e "${PUTIH}${BOLD}OPSI WAJIB:${RESET}"
    echo -e "  ${HIJAU}-t, --target${RESET}      Target pemindaian: IP tunggal, range CIDR, atau file host"
    echo -e "  ${HIJAU}--accept-tos${RESET}      Konfirmasi bahwa Anda memiliki otorisasi (WAJIB)"
    echo ""
    echo -e "${PUTIH}${BOLD}OPSI OPSIONAL:${RESET}"
    echo -e "  ${CYAN}-o, --output${RESET}      Direktori output (default: ./scan_results/TIMESTAMP/)"
    echo -e "  ${CYAN}-p, --profile${RESET}     Profil pemindaian: quick | standard | full | stealth"
    echo -e "  ${CYAN}-r, --rate${RESET}        Batas maksimum paket per detik"
    echo -e "  ${CYAN}--no-ping${RESET}         Lewati fase host discovery (ping sweep)"
    echo -e "  ${CYAN}--report-only${RESET}     Hanya parsing XML yang sudah ada, skip scanning"
    echo -e "  ${CYAN}--dry-run${RESET}         Tampilkan perintah yang akan dijalankan tanpa mengeksekusi"
    echo -e "  ${CYAN}-h, --help${RESET}        Tampilkan bantuan ini"
    echo ""
    echo -e "${PUTIH}${BOLD}PROFIL PEMINDAIAN:${RESET}"
    echo -e "  ${KUNING}quick${RESET}     → Top 100 port, tanpa deteksi versi"
    echo -e "  ${KUNING}standard${RESET}  → Top 1000 port, deteksi versi, script default (DEFAULT)"
    echo -e "  ${KUNING}full${RESET}      → Semua 65535 port, deteksi agresif, skrip vuln"
    echo -e "  ${KUNING}stealth${RESET}   → SYN scan, timing lambat (T2), tanpa ping, urutan acak"
    echo ""
    echo -e "${PUTIH}${BOLD}CONTOH PENGGUNAAN:${RESET}"
    echo -e "  ${BIRU}# Scan standar IP tunggal:${RESET}"
    echo -e "  sudo $0 -t 192.168.1.1 --accept-tos"
    echo ""
    echo -e "  ${BIRU}# Scan penuh range CIDR:${RESET}"
    echo -e "  sudo $0 -t 192.168.1.0/24 -p full --accept-tos"
    echo ""
    echo -e "  ${BIRU}# Scan stealth dengan output kustom:${RESET}"
    echo -e "  sudo $0 -t 10.0.0.0/8 -p stealth -o /tmp/hasil_scan --accept-tos"
    echo ""
    echo -e "  ${BIRU}# Scan dari file daftar host dengan rate limit:${RESET}"
    echo -e "  sudo $0 -t hosts.txt -r 500 --accept-tos"
    echo ""
    echo -e "  ${BIRU}# Dry run - lihat perintah tanpa eksekusi:${RESET}"
    echo -e "  sudo $0 -t 192.168.1.0/24 -p full --dry-run --accept-tos"
    echo ""
    echo -e "  ${BIRU}# Hanya buat laporan dari hasil scan sebelumnya:${RESET}"
    echo -e "  sudo $0 --report-only -o ./scan_results/20240101_120000/ --accept-tos"
    echo ""
}

# ─── Fungsi: Log Pesan ke File dan Terminal ──────────────────────────────────
# Argumen: $1=level (INFO|WARN|ERROR|SUCCESS), $2=pesan
log() {
    local level="$1"
    local pesan="$2"
    local waktu
    waktu=$(date +"%Y-%m-%d %H:%M:%S")
    local log_file="${OUTPUT_DIR}/scan.log"

    # Tentukan warna berdasarkan level
    case "$level" in
        "INFO")    echo -e "${BIRU}[INFO]${RESET} ${pesan}" ;;
        "SUCCESS") echo -e "${HIJAU}[✓]${RESET} ${pesan}" ;;
        "WARN")    echo -e "${KUNING}[PERINGATAN]${RESET} ${pesan}" ;;
        "ERROR")   echo -e "${MERAH}[ERROR]${RESET} ${pesan}" ;;
        "CMD")     echo -e "${MAGENTA}[PERINTAH]${RESET} ${pesan}" ;;
        *)         echo -e "${pesan}" ;;
    esac

    # Tulis ke log file jika direktori output sudah ada
    if [[ -n "${OUTPUT_DIR}" && -d "${OUTPUT_DIR}" ]]; then
        echo "[${waktu}] [${level}] ${pesan}" >> "${log_file}"
    fi
}

# ─── Fungsi: Indikator Progress ──────────────────────────────────────────────
# Argumen: $1=PID proses, $2=pesan progress
tampilkan_progress() {
    local pid="$1"
    local pesan="$2"
    local spinner=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0

    while kill -0 "$pid" 2>/dev/null; do
        printf "\r${CYAN}%s${RESET} %s..." "${spinner[$i]}" "$pesan"
        i=$(( (i + 1) % ${#spinner[@]} ))
        sleep 0.1
    done
    printf "\r${HIJAU}✓${RESET} %s... Selesai!    \n" "$pesan"
}

# ─── Fungsi: Periksa Prasyarat ───────────────────────────────────────────────
periksa_prasyarat() {
    log "INFO" "Memeriksa prasyarat sistem..."

    # Periksa apakah dijalankan sebagai root
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "Script ini memerlukan akses root/sudo untuk SYN scan"
        echo -e "${KUNING}  Jalankan dengan: sudo $0 ${*}${RESET}"
        exit 1
    fi

    # Periksa ketersediaan Nmap
    if ! command -v nmap &>/dev/null; then
        log "ERROR" "Nmap tidak ditemukan!"
        echo -e "${KUNING}  Instalasi Nmap:${RESET}"
        echo -e "    Ubuntu/Debian: sudo apt-get install nmap"
        echo -e "    CentOS/RHEL:   sudo yum install nmap"
        echo -e "    macOS:         brew install nmap"
        exit 1
    fi

    # Periksa versi Nmap
    local nmap_ver
    nmap_ver=$(nmap --version | head -1 | grep -oP '\d+\.\d+' | head -1)
    log "SUCCESS" "Nmap ditemukan: versi ${nmap_ver}"

    # Periksa ketersediaan Python 3
    if ! command -v python3 &>/dev/null; then
        log "ERROR" "Python 3 tidak ditemukan!"
        echo -e "${KUNING}  Instalasi Python 3:${RESET}"
        echo -e "    Ubuntu/Debian: sudo apt-get install python3"
        echo -e "    CentOS/RHEL:   sudo yum install python3"
        echo -e "    macOS:         brew install python3"
        exit 1
    fi

    local py_ver
    py_ver=$(python3 --version 2>&1 | grep -oP '\d+\.\d+\.\d+')
    log "SUCCESS" "Python 3 ditemukan: versi ${py_ver}"

    # Periksa apakah parser script tersedia
    if [[ ! -f "${PARSER_SCRIPT}" ]]; then
        log "ERROR" "File parser tidak ditemukan: ${PARSER_SCRIPT}"
        echo -e "${KUNING}  Pastikan file 'netscout_parser.py' berada di direktori yang sama${RESET}"
        exit 1
    fi

    log "SUCCESS" "Semua prasyarat terpenuhi"
}

# ─── Fungsi: Validasi Target ─────────────────────────────────────────────────
validasi_target() {
    local target="$1"

    # Cek apakah target adalah file
    if [[ -f "${target}" ]]; then
        log "INFO" "Target adalah file daftar host: ${target}"
        local jumlah_host
        jumlah_host=$(grep -cE '^[^#]' "${target}" || echo "0")
        log "INFO" "Ditemukan ${jumlah_host} host dalam file"
        return 0
    fi

    # Cek format IP tunggal (IPv4)
    if [[ "${target}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        log "INFO" "Target: IP tunggal ${target}"
        return 0
    fi

    # Cek format CIDR
    if [[ "${target}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        log "INFO" "Target: Range CIDR ${target}"
        return 0
    fi

    # Cek format range IP (misal: 192.168.1.1-254)
    if [[ "${target}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}-[0-9]{1,3}$ ]]; then
        log "INFO" "Target: Range IP ${target}"
        return 0
    fi

    # Cek hostname
    if [[ "${target}" =~ ^[a-zA-Z0-9][a-zA-Z0-9\-\.]+[a-zA-Z0-9]$ ]]; then
        log "INFO" "Target: Hostname ${target}"
        return 0
    fi

    log "ERROR" "Format target tidak valid: ${target}"
    echo -e "${KUNING}  Format yang didukung:${RESET}"
    echo -e "    IP tunggal : 192.168.1.1"
    echo -e "    CIDR range : 192.168.1.0/24"
    echo -e "    IP range   : 192.168.1.1-254"
    echo -e "    Hostname   : server.example.com"
    echo -e "    File host  : /path/ke/hosts.txt"
    exit 1
}

# ─── Fungsi: Buat Direktori Output ───────────────────────────────────────────
buat_direktori_output() {
    if [[ -z "${OUTPUT_DIR}" ]]; then
        OUTPUT_DIR="./scan_results/${TIMESTAMP}"
    fi

    if [[ "${DRY_RUN}" == false ]]; then
        mkdir -p "${OUTPUT_DIR}"
        log "SUCCESS" "Direktori output dibuat: ${OUTPUT_DIR}"

        # Inisialisasi file log
        echo "# NetScout Scan Log - $(date)" > "${OUTPUT_DIR}/scan.log"
        echo "# Target: ${TARGET}" >> "${OUTPUT_DIR}/scan.log"
        echo "# Profil: ${PROFIL}" >> "${OUTPUT_DIR}/scan.log"
        echo "# Operator: $(whoami)" >> "${OUTPUT_DIR}/scan.log"
        echo "---" >> "${OUTPUT_DIR}/scan.log"
    else
        log "INFO" "[DRY-RUN] Direktori output akan dibuat: ${OUTPUT_DIR}"
    fi
}

# ─── Fungsi: Eksekusi Perintah (dengan dukungan dry-run) ─────────────────────
# Argumen: $@=perintah yang akan dijalankan
jalankan_perintah() {
    local perintah="$*"
    log "CMD" "${perintah}"

    if [[ "${DRY_RUN}" == true ]]; then
        echo -e "${KUNING}  [DRY-RUN] Akan dijalankan: ${perintah}${RESET}"
        return 0
    fi

    # Catat perintah ke log
    echo "[CMD] ${perintah}" >> "${OUTPUT_DIR}/scan.log"

    # Jalankan perintah
    eval "${perintah}"
}

# ─── Fungsi: Bangun Argumen Nmap Berdasarkan Profil ─────────────────────────
bangun_argumen_nmap() {
    local fase="$1"
    local args=""
    local prefix_output="${OUTPUT_DIR}/scan"

    case "${PROFIL}" in
        "quick")
            case "$fase" in
                "discovery") args="-sn -T4" ;;
                "portscan")  args="-sS --top-ports 100 -T4" ;;
                "service")   args="-sS --top-ports 100 -T4" ;; # quick skip service detect
                "script")    args="" ;; # quick skip scripts
            esac
            ;;
        "standard")
            case "$fase" in
                "discovery") args="-sn -T4" ;;
                "portscan")  args="-sS --top-ports 1000 -T4" ;;
                "service")   args="-sV -O --top-ports 1000 -T4" ;;
                "script")    args="-sC --top-ports 1000 -T4" ;;
            esac
            ;;
        "full")
            case "$fase" in
                "discovery") args="-sn -T4" ;;
                "portscan")  args="-sS -p- -T4" ;;
                "service")   args="-sV -O -p- -T4 --version-intensity 9" ;;
                "script")    args="-sC --script=vuln -p- -T4" ;;
            esac
            ;;
        "stealth")
            case "$fase" in
                "discovery") args="-sn -T2 --randomize-hosts" ;;
                "portscan")  args="-sS --top-ports 1000 -T2 --randomize-hosts" ;;
                "service")   args="-sV -O --top-ports 1000 -T2" ;;
                "script")    args="-sC --top-ports 1000 -T2" ;;
            esac
            ;;
    esac

    # Tambahkan rate limit jika ditentukan
    if [[ -n "${MAX_RATE}" ]]; then
        args="${args} --max-rate ${MAX_RATE}"
    fi

    # Tambahkan flag no-ping jika diperlukan (kecuali fase discovery)
    if [[ "${SKIP_PING}" == true && "${fase}" != "discovery" ]]; then
        args="${args} -Pn"
    fi

    echo "${args}"
}

# ─── FASE 1: Host Discovery (Ping Sweep) ─────────────────────────────────────
fase_host_discovery() {
    local live_hosts_file="${OUTPUT_DIR}/live_hosts.txt"

    if [[ "${SKIP_PING}" == true ]]; then
        log "WARN" "Fase host discovery dilewati (--no-ping aktif)"
        # Gunakan target langsung sebagai live hosts
        echo "${TARGET}" > "${live_hosts_file}"
        return 0
    fi

    log "INFO" "═══ FASE 1: Host Discovery (Ping Sweep) ═══"
    local nmap_args
    nmap_args=$(bangun_argumen_nmap "discovery")

    local perintah="nmap ${nmap_args} ${TARGET} -oG ${OUTPUT_DIR}/discovery.gnmap"
    
    if [[ "${DRY_RUN}" == true ]]; then
        log "CMD" "${perintah}"
        echo -e "${KUNING}  [DRY-RUN] ${perintah}${RESET}"
        return 0
    fi

    # Jalankan dengan indikator progress
    eval "${perintah}" > /dev/null 2>&1 &
    local pid=$!
    echo "[CMD] ${perintah}" >> "${OUTPUT_DIR}/scan.log"
    tampilkan_progress $pid "Menjalankan ping sweep pada ${TARGET}"
    wait $pid

    # Ekstrak host yang aktif dari hasil Nmap grepable
    if [[ -f "${OUTPUT_DIR}/discovery.gnmap" ]]; then
        grep "Up" "${OUTPUT_DIR}/discovery.gnmap" | \
            grep -oP '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' | \
            sort -u > "${live_hosts_file}"
        
        local jumlah_live
        jumlah_live=$(wc -l < "${live_hosts_file}" | tr -d ' ')
        log "SUCCESS" "Ditemukan ${jumlah_live} host aktif"
        
        if [[ "${jumlah_live}" -eq 0 ]]; then
            log "WARN" "Tidak ada host aktif yang ditemukan. Pastikan target dapat dijangkau."
            exit 0
        fi
    else
        log "ERROR" "Gagal membuat file discovery output"
        exit 1
    fi
}

# ─── FASE 2: Port Scan pada Host Aktif ───────────────────────────────────────
fase_port_scan() {
    local live_hosts_file="${OUTPUT_DIR}/live_hosts.txt"

    log "INFO" "═══ FASE 2: Port Scan pada Host Aktif ═══"
    
    local nmap_args
    nmap_args=$(bangun_argumen_nmap "portscan")

    local target_arg
    if [[ -f "${live_hosts_file}" && "${SKIP_PING}" == false ]]; then
        target_arg="-iL ${live_hosts_file}"
    else
        target_arg="${TARGET}"
    fi

    local perintah="nmap ${nmap_args} ${target_arg} -oG ${OUTPUT_DIR}/portscan.gnmap"

    if [[ "${DRY_RUN}" == true ]]; then
        log "CMD" "${perintah}"
        echo -e "${KUNING}  [DRY-RUN] ${perintah}${RESET}"
        return 0
    fi

    eval "${perintah}" > /dev/null 2>&1 &
    local pid=$!
    echo "[CMD] ${perintah}" >> "${OUTPUT_DIR}/scan.log"
    tampilkan_progress $pid "Memindai port pada host aktif"
    wait $pid

    log "SUCCESS" "Fase port scan selesai"
}

# ─── FASE 3: Deteksi Layanan & Versi + OS Fingerprint ───────────────────────
fase_service_detection() {
    local live_hosts_file="${OUTPUT_DIR}/live_hosts.txt"

    # Lewati untuk profil quick
    if [[ "${PROFIL}" == "quick" ]]; then
        log "WARN" "Deteksi layanan dilewati (profil: quick)"
        return 0
    fi

    log "INFO" "═══ FASE 3: Deteksi Layanan & Versi + OS Fingerprint ═══"

    local nmap_args
    nmap_args=$(bangun_argumen_nmap "service")

    local target_arg
    if [[ -f "${live_hosts_file}" && "${SKIP_PING}" == false ]]; then
        target_arg="-iL ${live_hosts_file}"
    else
        target_arg="${TARGET}"
    fi

    local prefix="${OUTPUT_DIR}/scan"
    local perintah="nmap ${nmap_args} ${target_arg} -oA ${prefix}"

    if [[ "${DRY_RUN}" == true ]]; then
        log "CMD" "${perintah}"
        echo -e "${KUNING}  [DRY-RUN] ${perintah}${RESET}"
        return 0
    fi

    eval "${perintah}" > /dev/null 2>&1 &
    local pid=$!
    echo "[CMD] ${perintah}" >> "${OUTPUT_DIR}/scan.log"
    tampilkan_progress $pid "Mendeteksi layanan, versi, dan OS fingerprint"
    wait $pid

    log "SUCCESS" "Fase deteksi layanan selesai"
    log "SUCCESS" "Output disimpan: ${prefix}.nmap, ${prefix}.xml, ${prefix}.gnmap"
}

# ─── FASE 4: NSE Script Scan ─────────────────────────────────────────────────
fase_nse_scan() {
    local live_hosts_file="${OUTPUT_DIR}/live_hosts.txt"

    # Lewati untuk profil quick
    if [[ "${PROFIL}" == "quick" ]]; then
        log "WARN" "NSE scan dilewati (profil: quick)"
        return 0
    fi

    log "INFO" "═══ FASE 4: NSE Script Scan ═══"

    local nmap_args
    nmap_args=$(bangun_argumen_nmap "script")

    local target_arg
    if [[ -f "${live_hosts_file}" && "${SKIP_PING}" == false ]]; then
        target_arg="-iL ${live_hosts_file}"
    else
        target_arg="${TARGET}"
    fi

    local perintah="nmap ${nmap_args} ${target_arg} -oA ${OUTPUT_DIR}/nse_scan"

    if [[ "${DRY_RUN}" == true ]]; then
        log "CMD" "${perintah}"
        echo -e "${KUNING}  [DRY-RUN] ${perintah}${RESET}"
        return 0
    fi

    eval "${perintah}" > /dev/null 2>&1 &
    local pid=$!
    echo "[CMD] ${perintah}" >> "${OUTPUT_DIR}/scan.log"
    tampilkan_progress $pid "Menjalankan NSE scripts (default + vuln)"
    wait $pid

    log "SUCCESS" "Fase NSE scan selesai"
}

# ─── Fungsi: Generate Laporan ────────────────────────────────────────────────
generate_laporan() {
    log "INFO" "═══ GENERATING LAPORAN ═══"

    local xml_file="${OUTPUT_DIR}/scan.xml"

    # Jika tidak ada XML dari scan utama, coba dari NSE scan
    if [[ ! -f "${xml_file}" ]]; then
        xml_file="${OUTPUT_DIR}/nse_scan.xml"
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        log "CMD" "python3 ${PARSER_SCRIPT} --xml [scan.xml] --output ${OUTPUT_DIR} --target '${TARGET}' --profile ${PROFIL}"
        echo -e "${KUNING}  [DRY-RUN] Akan menjalankan parser Python untuk membuat laporan${RESET}"
        return 0
    fi

    if [[ ! -f "${xml_file}" ]]; then
        log "ERROR" "File XML tidak ditemukan: ${xml_file}"
        log "WARN" "Pastikan scan sudah dijalankan terlebih dahulu"
        return 1
    fi

    # Jalankan parser Python
    python3 "${PARSER_SCRIPT}" \
        --xml "${xml_file}" \
        --output "${OUTPUT_DIR}" \
        --target "${TARGET}" \
        --profile "${PROFIL}" \
        --operator "$(whoami)" \
        --timestamp "${TIMESTAMP}"

    log "SUCCESS" "Laporan berhasil dibuat di: ${OUTPUT_DIR}"
    echo ""
    echo -e "${PUTIH}${BOLD}  File output:${RESET}"
    echo -e "  ${HIJAU}→${RESET} ${OUTPUT_DIR}/laporan.txt"
    echo -e "  ${HIJAU}→${RESET} ${OUTPUT_DIR}/laporan.csv"
    echo -e "  ${HIJAU}→${RESET} ${OUTPUT_DIR}/scan.log"
    [[ -f "${OUTPUT_DIR}/scan.nmap" ]] && echo -e "  ${HIJAU}→${RESET} ${OUTPUT_DIR}/scan.nmap"
    [[ -f "${OUTPUT_DIR}/scan.xml"  ]] && echo -e "  ${HIJAU}→${RESET} ${OUTPUT_DIR}/scan.xml"
    [[ -f "${OUTPUT_DIR}/scan.gnmap" ]] && echo -e "  ${HIJAU}→${RESET} ${OUTPUT_DIR}/scan.gnmap"
}

# ─── Fungsi: Parse Argumen CLI ───────────────────────────────────────────────
parse_argumen() {
    if [[ $# -eq 0 ]]; then
        tampilkan_bantuan
        exit 0
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)
                TARGET="$2"
                shift 2
                ;;
            -o|--output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            -p|--profile)
                PROFIL="$2"
                # Validasi profil
                if [[ ! "${PROFIL}" =~ ^(quick|standard|full|stealth)$ ]]; then
                    echo -e "${MERAH}[ERROR]${RESET} Profil tidak valid: ${PROFIL}"
                    echo -e "  Profil yang tersedia: quick, standard, full, stealth"
                    exit 1
                fi
                shift 2
                ;;
            -r|--rate)
                MAX_RATE="$2"
                shift 2
                ;;
            --no-ping)
                SKIP_PING=true
                shift
                ;;
            --report-only)
                REPORT_ONLY=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --accept-tos)
                ACCEPT_TOS=true
                shift
                ;;
            -h|--help)
                tampilkan_bantuan
                exit 0
                ;;
            *)
                echo -e "${MERAH}[ERROR]${RESET} Opsi tidak dikenal: $1"
                echo -e "  Gunakan --help untuk melihat daftar opsi"
                exit 1
                ;;
        esac
    done
}

# ─── Fungsi: Validasi Input ───────────────────────────────────────────────────
validasi_input() {
    # Cek apakah --accept-tos sudah diberikan
    if [[ "${ACCEPT_TOS}" == false ]]; then
        tampilkan_peringatan_etika
        echo -e "${MERAH}${BOLD}  ERROR: Anda harus menambahkan flag --accept-tos untuk melanjutkan.${RESET}"
        echo -e "${KUNING}  Dengan menambahkan flag tersebut, Anda menyatakan bahwa:${RESET}"
        echo -e "  1. Anda memiliki otorisasi tertulis untuk melakukan scan"
        echo -e "  2. Anda bertanggung jawab penuh atas penggunaan alat ini"
        echo ""
        exit 1
    fi

    # Cek apakah target diberikan (kecuali mode report-only)
    if [[ -z "${TARGET}" && "${REPORT_ONLY}" == false ]]; then
        log "ERROR" "Target tidak ditentukan. Gunakan -t atau --target"
        echo -e "  Contoh: sudo $0 -t 192.168.1.1 --accept-tos"
        exit 1
    fi

    # Validasi target jika bukan mode report-only
    if [[ "${REPORT_ONLY}" == false ]]; then
        validasi_target "${TARGET}"
    fi

    # Cek output dir untuk mode report-only
    if [[ "${REPORT_ONLY}" == true && -z "${OUTPUT_DIR}" ]]; then
        log "ERROR" "Mode --report-only memerlukan --output yang menunjuk ke hasil scan sebelumnya"
        exit 1
    fi
}

# ─── Fungsi: Log Penerimaan ToS ──────────────────────────────────────────────
log_penerimaan_tos() {
    if [[ "${DRY_RUN}" == false && -d "${OUTPUT_DIR}" ]]; then
        {
            echo "# === KONFIRMASI OTORISASI ==="
            echo "# Operator  : $(whoami)"
            echo "# Hostname  : $(hostname)"
            echo "# Waktu     : $(date)"
            echo "# Target    : ${TARGET}"
            echo "# IP Mesin  : $(hostname -I | awk '{print $1}' 2>/dev/null || echo 'N/A')"
            echo "# Status    : Operator mengkonfirmasi bahwa scan ini telah diotorisasi"
            echo "# =========================="
        } >> "${OUTPUT_DIR}/scan.log"
    fi
}

# ─── Fungsi: Tampilkan Ringkasan Konfigurasi ─────────────────────────────────
tampilkan_konfigurasi() {
    echo ""
    echo -e "${PUTIH}${BOLD}  Konfigurasi Scan:${RESET}"
    echo -e "  ${BIRU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "  ${CYAN}Target    :${RESET} ${TARGET:-'(dari output dir)'}"
    echo -e "  ${CYAN}Profil    :${RESET} ${PROFIL}"
    echo -e "  ${CYAN}Output    :${RESET} ${OUTPUT_DIR}"
    echo -e "  ${CYAN}Tanpa Ping:${RESET} ${SKIP_PING}"
    echo -e "  ${CYAN}Rate Limit:${RESET} ${MAX_RATE:-'tidak dibatasi'}"
    echo -e "  ${CYAN}Dry Run   :${RESET} ${DRY_RUN}"
    [[ "${PROFIL}" == "full" ]] && echo -e "  ${KUNING}PERINGATAN: Profil 'full' dapat memakan waktu lama!${RESET}"
    echo -e "  ${BIRU}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

# ─── MAIN: Fungsi Utama ───────────────────────────────────────────────────────
main() {
    # Tampilkan banner
    tampilkan_banner

    # Parse argumen
    parse_argumen "$@"

    # Validasi input
    validasi_input

    # Periksa prasyarat sistem
    periksa_prasyarat

    # Buat direktori output
    buat_direktori_output

    # Log penerimaan ToS
    log_penerimaan_tos

    # Tampilkan konfigurasi
    tampilkan_konfigurasi

    # ─── Mode Report Only ──────────────────────────────────────────────────
    if [[ "${REPORT_ONLY}" == true ]]; then
        log "INFO" "Mode report-only: melewati semua fase scan"
        generate_laporan
        exit 0
    fi

    # ─── Jalankan Fase Scan ────────────────────────────────────────────────
    local waktu_mulai
    waktu_mulai=$(date +%s)

    # Fase 1: Host Discovery
    fase_host_discovery

    # Fase 2: Port Scan
    fase_port_scan

    # Fase 3: Service Detection
    fase_service_detection

    # Fase 4: NSE Scripts
    fase_nse_scan

    # Generate Laporan
    generate_laporan

    # Hitung durasi
    local waktu_selesai
    waktu_selesai=$(date +%s)
    local durasi=$((waktu_selesai - waktu_mulai))
    local menit=$((durasi / 60))
    local detik=$((durasi % 60))

    echo ""
    echo -e "${HIJAU}${BOLD}  ✓ Scan selesai dalam ${menit} menit ${detik} detik${RESET}"
    echo -e "  ${BIRU}Semua hasil tersimpan di: ${OUTPUT_DIR}${RESET}"
    echo ""
    log "SUCCESS" "Scan selesai. Durasi: ${menit}m ${detik}s"
}

# ─── Entry Point ──────────────────────────────────────────────────────────────
main "$@"
