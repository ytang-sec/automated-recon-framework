#!/usr/bin/env bash
# =============================================================================
#  LOCAL NETWORK RECON SCRIPT — Interactive Mode
#  Tools: nmap, nikto, arp-scan, enum4linux, smbclient,
#         snmpwalk, curl, whatweb, dnsrecon, masscan (optional)
#  Output: HTML + plain-text report
#  Usage:  sudo ./wifi_recon.sh [CIDR]
# =============================================================================

set -uo pipefail

# ── Colour codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
MAGENTA='\033[0;35m'; WHITE='\033[1;37m'; DIM='\033[2m'

banner(){
  clear
  echo -e "${CYAN}${BOLD}"
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║         LOCAL NETWORK RECON & VULN SCANNER v2                ║"
  echo "║    nmap · nikto · arp-scan · enum4linux · snmpwalk           ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && { echo -e "${RED}[!] Run as root / sudo${RESET}"; exit 1; }

banner

# ── Output paths ──────────────────────────────────────────────────────────────
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="recon_${TIMESTAMP}"
mkdir -p "$OUTDIR"/{raw,web,smb,snmp}
TXT_REPORT="$OUTDIR/report_${TIMESTAMP}.txt"
HTML_REPORT="$OUTDIR/report_${TIMESTAMP}.html"

log(){ echo -e "${GREEN}[+]${RESET} $*" | tee -a "$TXT_REPORT"; }
warn(){ echo -e "${YELLOW}[!]${RESET} $*" | tee -a "$TXT_REPORT"; }
info(){ echo -e "${CYAN}[i]${RESET} $*" | tee -a "$TXT_REPORT"; }
section(){ echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}\n" | tee -a "$TXT_REPORT"; }

# ══════════════════════════════════════════════════════════════════════════════
#  INTERACTIVE MENU
# ══════════════════════════════════════════════════════════════════════════════

echo -e "${BOLD}${WHITE}┌─ SCAN MODE ────────────────────────────────────────────────┐${RESET}"
echo -e "${WHITE}│${RESET}  ${BOLD}1)${RESET} ${GREEN}Quick${RESET}      – Top 100 ports, no vuln scripts    ${DIM}(~1 min)${RESET}"
echo -e "${WHITE}│${RESET}  ${BOLD}2)${RESET} ${YELLOW}Standard${RESET}   – Top 1000 ports + version detect   ${DIM}(~3 min)${RESET}"
echo -e "${WHITE}│${RESET}  ${BOLD}3)${RESET} ${MAGENTA}Vuln Scan${RESET}  – Top 1000 ports + NSE vuln scripts ${DIM}(~8 min)${RESET}"
echo -e "${WHITE}│${RESET}  ${BOLD}4)${RESET} ${RED}Full${RESET}       – All 65535 ports + full vuln scan  ${DIM}(~30 min)${RESET}"
echo -e "${WHITE}│${RESET}  ${BOLD}5)${RESET} ${CYAN}Custom${RESET}     – You choose exact ports & options"
echo -e "${BOLD}${WHITE}└────────────────────────────────────────────────────────────┘${RESET}"
echo
echo -ne "${BOLD}Select scan mode [1-5]: ${RESET}"
read -r SCAN_MODE

echo
echo -e "${BOLD}${WHITE}┌─ EXTRA MODULES ────────────────────────────────────────────┐${RESET}"
echo -e "${WHITE}│${RESET}  Run these after port scan? (y/n for each)"
echo -e "${WHITE}│${RESET}"
echo -ne "${WHITE}│${RESET}  ${BOLD}Nikto web scan${RESET} (scans HTTP/HTTPS hosts)? [y/n]: "
read -r DO_NIKTO
echo -ne "${WHITE}│${RESET}  ${BOLD}SMB enumeration${RESET} (enum4linux on Windows hosts)? [y/n]: "
read -r DO_SMB
echo -ne "${WHITE}│${RESET}  ${BOLD}SNMP enumeration${RESET} (snmpwalk with default communities)? [y/n]: "
read -r DO_SNMP
echo -ne "${WHITE}│${RESET}  ${BOLD}DNS recon${RESET} (reverse lookup + zone transfer attempt)? [y/n]: "
read -r DO_DNS
SKIP_NETDISCOVER="y" # removed
echo -e "${BOLD}${WHITE}└────────────────────────────────────────────────────────────┘${RESET}"

# Build nmap flags based on mode
case "$SCAN_MODE" in
  1)
    SCAN_LABEL="Quick (Top 100)"
    NMAP_FLAGS="-sS -sV --top-ports 100 --open --min-rate 2000"
    DO_VULN_SCRIPTS="n"
    DO_TARGETED="n"
    DO_UDP="n"
    ;;
  2)
    SCAN_LABEL="Standard (Top 1000)"
    NMAP_FLAGS="-sS -sV -sC -O --top-ports 1000 --open --min-rate 1500"
    DO_VULN_SCRIPTS="n"
    DO_TARGETED="n"
    DO_UDP="y"
    ;;
  3)
    SCAN_LABEL="Vuln Scan (Top 1000 + NSE)"
    NMAP_FLAGS="-sS -sV -sC -O --top-ports 1000 --open --min-rate 1000"
    DO_VULN_SCRIPTS="y"
    DO_TARGETED="y"
    DO_UDP="y"
    ;;
  4)
    SCAN_LABEL="Full (All Ports + Full Vuln)"
    NMAP_FLAGS="-sS -sV -sC -O -p- --open --min-rate 1000"
    DO_VULN_SCRIPTS="y"
    DO_TARGETED="y"
    DO_UDP="y"
    ;;
  5)
    echo
    echo -e "${CYAN}Custom mode — enter your options:${RESET}"
    echo -ne "  Ports (e.g. 22,80,443  or  1-1024  or  --top-ports 500): "
    read -r CUSTOM_PORTS
    echo -ne "  Extra nmap flags (e.g. -sV -O  or just press Enter): "
    read -r CUSTOM_FLAGS
    echo -ne "  Run NSE vuln scripts? [y/n]: "
    read -r DO_VULN_SCRIPTS
    echo -ne "  Run targeted CVE scripts? [y/n]: "
    read -r DO_TARGETED
    echo -ne "  Run UDP top-20 scan? [y/n]: "
    read -r DO_UDP
    # Handle port format
    if echo "$CUSTOM_PORTS" | grep -q '\-\-top-ports'; then
      NMAP_FLAGS="-sS $CUSTOM_PORTS --open --min-rate 1000 $CUSTOM_FLAGS"
    else
      NMAP_FLAGS="-sS -p $CUSTOM_PORTS --open --min-rate 1000 $CUSTOM_FLAGS"
    fi
    SCAN_LABEL="Custom ($CUSTOM_PORTS)"
    ;;
  *)
    echo -e "${YELLOW}Invalid choice, defaulting to Standard mode.${RESET}"
    SCAN_LABEL="Standard (Top 1000)"
    NMAP_FLAGS="-sS -sV -sC -O --top-ports 1000 --open --min-rate 1500"
    DO_VULN_SCRIPTS="n"
    DO_TARGETED="n"
    DO_UDP="y"
    ;;
esac

echo
echo -e "${BOLD}${GREEN}✔ Scan configured:${RESET} $SCAN_LABEL"
echo -e "${DIM}  nmap flags: $NMAP_FLAGS${RESET}"
echo
echo -ne "Press ${BOLD}Enter${RESET} to start scan..."
read -r

# ── Dependency check ──────────────────────────────────────────────────────────
section "Dependency Check"
REQUIRED=(nmap arp-scan curl)
[[ "$DO_NIKTO" =~ ^[Yy] ]] && REQUIRED+=(nikto)
OPTIONAL=(enum4linux smbclient snmpwalk masscan whatweb dnsrecon)
for t in "${REQUIRED[@]}"; do
  command -v "$t" &>/dev/null \
    && log "$t found" \
    || warn "$t NOT FOUND – install it: sudo apt install $t"
done
for t in "${OPTIONAL[@]}"; do
  command -v "$t" &>/dev/null \
    && log "$t found (optional)" \
    || warn "$t not found (optional – will be skipped)"
done

# ── Target subnet detection ───────────────────────────────────────────────────
section "Target Detection"
if [[ -n "${1:-}" ]]; then
  SUBNET="$1"
  log "Using supplied target: $SUBNET"
else
  IFACE=$(ip route | awk '/default/{print $5; exit}')
  SUBNET=$(ip -o -f inet addr show "$IFACE" | awk '{print $4}')
  log "Auto-detected subnet: $SUBNET  (interface: $IFACE)"
fi
GATEWAY=$(ip route | awk '/default/{print $3; exit}')
MY_IP=$(hostname -I | awk '{print $1}')
log "Gateway  : $GATEWAY"
log "This host: $MY_IP"
log "Scan mode: $SCAN_LABEL"

# ── Phase 1 – Host Discovery ──────────────────────────────────────────────────
section "Phase 1 – Host Discovery"
HOSTS_FILE="$OUTDIR/raw/hosts.txt"
touch "$HOSTS_FILE"

log "Running arp-scan …"
arp-scan --localnet 2>/dev/null | tee "$OUTDIR/raw/arp_scan.txt" \
  | grep -E '^[0-9]' | awk '{print $1}' >> "$HOSTS_FILE" || true

log "Running nmap ping sweep …"
nmap -sn "$SUBNET" -oN "$OUTDIR/raw/nmap_ping.txt" 2>/dev/null || true
grep 'Nmap scan report' "$OUTDIR/raw/nmap_ping.txt" 2>/dev/null \
  | awk '{print $NF}' | tr -d '()' >> "$HOSTS_FILE" || true

sort -u "$HOSTS_FILE" -o "$HOSTS_FILE"
HOST_COUNT=$(wc -l < "$HOSTS_FILE")
log "Discovered $HOST_COUNT unique hosts"
cat "$HOSTS_FILE" | tee -a "$TXT_REPORT"

# netdiscover removed — unreliable on most networks, hangs indefinitely

# ── Phase 2 – Port & Service Scan ────────────────────────────────────────────
section "Phase 2 – Port & Service Scan  [$SCAN_LABEL]"
NMAP_OUT="$OUTDIR/raw/nmap_full"
log "nmap $NMAP_FLAGS …"
# shellcheck disable=SC2086
nmap $NMAP_FLAGS \
  -oA "$NMAP_OUT" \
  -iL "$HOSTS_FILE" \
  2>/dev/null | tee -a "$TXT_REPORT" || true

if [[ "$DO_UDP" =~ ^[Yy] ]]; then
  log "UDP top-20 ports …"
  nmap -sU --top-ports 20 -sV --open \
    -oN "$OUTDIR/raw/nmap_udp.txt" \
    -iL "$HOSTS_FILE" \
    2>/dev/null | tee -a "$TXT_REPORT" || true
else
  info "Skipping UDP scan."
fi

# ── Phase 3 – Vulnerability Scripts ──────────────────────────────────────────
if [[ "$DO_VULN_SCRIPTS" =~ ^[Yy] ]]; then
  section "Phase 3 – Vulnerability & Exploit Detection (nmap NSE)"
  VULN_OUT="$OUTDIR/raw/nmap_vuln"
  log "Running vuln + exploit NSE scripts …"
  nmap -sV \
    --script="vuln,exploit,auth,brute,default,safe" \
    --script-timeout 60s \
    -oA "$VULN_OUT" \
    -iL "$HOSTS_FILE" \
    2>/dev/null | tee -a "$TXT_REPORT" || true
else
  info "Skipping NSE vuln scripts (not selected for this mode)."
  touch "$OUTDIR/raw/nmap_vuln.nmap" 2>/dev/null || true
fi

if [[ "$DO_TARGETED" =~ ^[Yy] ]]; then
  log "Targeted CVE/protocol scripts …"
  nmap -sV \
    --script="smb-vuln-ms17-010,smb-vuln-ms08-067,smb-vuln-cve2009-3103,\
ms-sql-empty-password,mysql-empty-password,ftp-anon,ftp-bounce,\
http-shellshock,http-slowloris-check,ssl-heartbleed,ssl-poodle,\
rdp-enum-encryption,vnc-info,telnet-ntlm-info,\
snmp-sysdescr,dns-recursion,ntp-monlist" \
    -oN "$OUTDIR/raw/nmap_targeted.txt" \
    -iL "$HOSTS_FILE" \
    2>/dev/null | tee -a "$TXT_REPORT" || true
else
  info "Skipping targeted CVE scripts."
  touch "$OUTDIR/raw/nmap_targeted.txt" 2>/dev/null || true
fi

# ── Phase 4 – Web Scanning ────────────────────────────────────────────────────
WEB_HOSTS="$OUTDIR/raw/web_hosts.txt"
touch "$WEB_HOSTS"

# Extract web hosts from nmap XML if it exists
if [[ -f "$NMAP_OUT.xml" ]]; then
  python3 - "$NMAP_OUT.xml" "$WEB_HOSTS" 2>/dev/null <<'PYEOF' || true
import sys, xml.etree.ElementTree as ET
try:
    tree = ET.parse(sys.argv[1])
    out  = open(sys.argv[2], 'w')
    for host in tree.findall('host'):
        addr = host.find('address').get('addr','')
        for p in host.findall('ports/port'):
            if p.find('state').get('state') != 'open': continue
            port = p.get('portid')
            if port in ('80','443','8080','8443','8000','8888','8181'):
                svc = 'https' if port in ('443','8443') else 'http'
                out.write(f"{svc}://{addr}:{port}\n")
    out.close()
except Exception as e:
    print(f"XML parse error: {e}", file=sys.stderr)
PYEOF
fi

if [[ "$DO_NIKTO" =~ ^[Yy] ]]; then
  section "Phase 4 – Web Service Scanning"
  if [[ -s "$WEB_HOSTS" ]]; then
    log "Found $(wc -l < "$WEB_HOSTS") web endpoints – running Nikto …"
    while IFS= read -r url; do
      SAFE=$(echo "$url" | tr '/:' '_')
      log "  Nikto → $url"
      nikto -h "$url" -output "$OUTDIR/web/nikto_${SAFE}.txt" \
        -Format txt -Tuning x6789abc 2>/dev/null || true
    done < "$WEB_HOSTS"
    if command -v whatweb &>/dev/null; then
      log "Running WhatWeb …"
      whatweb --input-file="$WEB_HOSTS" \
        --log-verbose="$OUTDIR/web/whatweb.txt" 2>/dev/null || true
    fi
  else
    warn "No web hosts detected on common ports."
  fi
else
  info "Skipping Nikto web scan."
fi

# ── Phase 5 – SMB Enumeration ─────────────────────────────────────────────────
if [[ "$DO_SMB" =~ ^[Yy] ]]; then
  section "Phase 5 – SMB / Windows Enumeration"
  SMB_HOSTS="$OUTDIR/raw/smb_hosts.txt"
  touch "$SMB_HOSTS"
  if [[ -f "$NMAP_OUT.xml" ]]; then
    python3 - "$NMAP_OUT.xml" "$SMB_HOSTS" 2>/dev/null <<'PYEOF' || true
import sys, xml.etree.ElementTree as ET
try:
    tree = ET.parse(sys.argv[1])
    out  = open(sys.argv[2], 'w')
    for host in tree.findall('host'):
        addr = host.find('address').get('addr','')
        for p in host.findall('ports/port'):
            if p.find('state').get('state') != 'open': continue
            if p.get('portid') in ('139','445'):
                out.write(addr + '\n'); break
    out.close()
except: pass
PYEOF
  fi
  if [[ -s "$SMB_HOSTS" ]]; then
    while IFS= read -r ip; do
      log "  SMB enum → $ip"
      command -v enum4linux &>/dev/null && \
        enum4linux -a "$ip" > "$OUTDIR/smb/enum4linux_${ip}.txt" 2>/dev/null || true
      command -v smbclient &>/dev/null && \
        smbclient -L "$ip" -N > "$OUTDIR/smb/smbclient_${ip}.txt" 2>/dev/null || true
    done < "$SMB_HOSTS"
  else
    log "No SMB hosts found."
  fi
else
  info "Skipping SMB enumeration."
fi

# ── Phase 6 – SNMP Enumeration ────────────────────────────────────────────────
if [[ "$DO_SNMP" =~ ^[Yy] ]]; then
  section "Phase 6 – SNMP Enumeration"
  SNMP_HOSTS="$OUTDIR/raw/snmp_hosts.txt"
  grep -h 'open' "$OUTDIR/raw/nmap_udp.txt" 2>/dev/null \
    | grep '161/udp' | awk '{print $1}' > "$SNMP_HOSTS" || touch "$SNMP_HOSTS"
  if [[ -s "$SNMP_HOSTS" ]] && command -v snmpwalk &>/dev/null; then
    while IFS= read -r ip; do
      for comm in public private community manager; do
        log "  snmpwalk $ip community=$comm"
        snmpwalk -c "$comm" -v2c "$ip" \
          > "$OUTDIR/snmp/snmp_${ip}_${comm}.txt" 2>/dev/null || true
      done
    done < "$SNMP_HOSTS"
  else
    log "No SNMP hosts found or snmpwalk not installed."
  fi
else
  info "Skipping SNMP enumeration."
fi

# ── Phase 7 – DNS Recon ───────────────────────────────────────────────────────
if [[ "$DO_DNS" =~ ^[Yy] ]]; then
  section "Phase 7 – DNS Recon"
  log "DNS reverse lookup sweep …"
  nmap -sn -R "$SUBNET" --dns-servers "$GATEWAY" \
    -oN "$OUTDIR/raw/dns_reverse.txt" 2>/dev/null || true
  if command -v dnsrecon &>/dev/null; then
    log "dnsrecon against gateway …"
    dnsrecon -r "$SUBNET" -n "$GATEWAY" \
      -c "$OUTDIR/raw/dnsrecon.csv" 2>/dev/null || true
  fi
else
  info "Skipping DNS recon."
fi

# ── Phase 8 – Parse & Classify Findings ──────────────────────────────────────
section "Phase 8 – Parse & Classify Findings"
VULN_SUMMARY="$OUTDIR/raw/vuln_summary.txt"
> "$VULN_SUMMARY"

if [[ -f "$NMAP_OUT.xml" ]]; then
python3 - "$NMAP_OUT.xml" >> "$VULN_SUMMARY" 2>/dev/null <<'PYEOF' || true
import sys, xml.etree.ElementTree as ET

DANGEROUS = {
  "21":"FTP – anonymous login / plaintext creds",
  "22":"SSH – brute-force / weak ciphers",
  "23":"Telnet – plaintext protocol",
  "25":"SMTP – open relay / user enum",
  "53":"DNS – zone transfer / cache poison",
  "80":"HTTP – web vulns (XSS/SQLi/etc)",
  "110":"POP3 – plaintext mail",
  "111":"RPC portmapper – CVEs",
  "135":"MSRPC – MS03-026",
  "139":"NetBIOS/SMB – EternalBlue",
  "143":"IMAP – plaintext",
  "161":"SNMP – info disclosure",
  "443":"HTTPS – SSL vulns (Heartbleed/POODLE)",
  "445":"SMB – EternalBlue / PrintNightmare",
  "512":"rexec – unauthenticated exec",
  "513":"rlogin – no encryption",
  "514":"rsh – command exec no auth",
  "1433":"MSSQL – default creds / xp_cmdshell",
  "1521":"Oracle – default creds",
  "2049":"NFS – world-readable exports",
  "3306":"MySQL – empty root password",
  "3389":"RDP – BlueKeep CVE-2019-0708",
  "4444":"Backdoor/Metasploit listener",
  "5432":"PostgreSQL – default creds",
  "5900":"VNC – weak/no auth",
  "6379":"Redis – unauthenticated RCE",
  "8080":"HTTP-alt – web vulns",
  "8443":"HTTPS-alt – SSL/web vulns",
  "27017":"MongoDB – no auth default",
}

try:
    tree = ET.parse(sys.argv[1])
except Exception as e:
    print(f"Could not parse XML: {e}")
    sys.exit(0)

results = []
for host in tree.findall('host'):
    ip  = host.find('address').get('addr','?')
    hostname = ''
    hn = host.find('hostnames/hostname')
    if hn is not None: hostname = hn.get('name','')
    os_el = host.find('os/osmatch')
    os_str = os_el.get('name','Unknown') if os_el is not None else 'Unknown'
    ports = []
    for p in host.findall('ports/port'):
        st = p.find('state')
        if st is None or st.get('state') != 'open': continue
        pid   = p.get('portid')
        proto = p.get('protocol','tcp')
        svc   = p.find('service')
        name  = svc.get('name','') if svc is not None else ''
        prod  = svc.get('product','') if svc is not None else ''
        ver   = svc.get('version','') if svc is not None else ''
        risk  = DANGEROUS.get(pid, '')
        ports.append({'port':pid,'proto':proto,'service':name,
                      'product':prod,'version':ver,'risk':risk})
    results.append({'ip':ip,'hostname':hostname,'os':os_str,'ports':ports})

for r in results:
    print(f"\n{'='*60}")
    print(f"HOST : {r['ip']}  {r['hostname']}")
    print(f"OS   : {r['os']}")
    if not r['ports']:
        print("  No open ports found in this scan range.")
    for p in r['ports']:
        flag = '  [RISKY]' if p['risk'] else ''
        print(f"  {p['port']}/{p['proto']:<4} {p['service']:<12} {p['product']} {p['version']}{flag}")
        if p['risk']:
            print(f"         └─ {p['risk']}")
PYEOF
fi

cat "$VULN_SUMMARY" | tee -a "$TXT_REPORT"

# ── Phase 9 – HTML Report ─────────────────────────────────────────────────────
section "Phase 9 – Generating HTML Report"

cat > "$HTML_REPORT" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Recon Report</title>
<style>
  :root{--bg:#0d1117;--card:#161b22;--border:#30363d;--green:#3fb950;
    --yellow:#d29922;--red:#f85149;--blue:#58a6ff;--text:#c9d1d9;--dim:#8b949e}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',monospace;padding:24px}
  h1{color:var(--blue);font-size:1.8rem;margin-bottom:4px}
  h2{color:var(--green);font-size:1.1rem;margin:24px 0 8px;
     border-bottom:1px solid var(--border);padding-bottom:4px}
  .meta{color:var(--dim);font-size:.85rem;margin-bottom:24px}
  .card{background:var(--card);border:1px solid var(--border);
        border-radius:8px;padding:16px;margin-bottom:16px}
  table{width:100%;border-collapse:collapse;font-size:.82rem}
  th{text-align:left;padding:6px 10px;background:#21262d;
     color:var(--dim);border-bottom:1px solid var(--border)}
  td{padding:5px 10px;border-bottom:1px solid #21262d;vertical-align:top}
  .badge-crit{background:#3d0a0a;color:var(--red);border:1px solid var(--red);
    border-radius:4px;padding:1px 6px;font-size:.75rem}
  .badge-high{background:#3d2a00;color:var(--yellow);border:1px solid var(--yellow);
    border-radius:4px;padding:1px 6px;font-size:.75rem}
  .badge-mode{background:#0d2137;color:var(--blue);border:1px solid var(--blue);
    border-radius:4px;padding:2px 8px;font-size:.8rem;margin-left:8px}
  pre{white-space:pre-wrap;word-break:break-all;font-size:.78rem;
    background:#0d1117;padding:12px;border-radius:6px;overflow-x:auto}
  details{margin-bottom:8px}
  summary{cursor:pointer;color:var(--blue);padding:6px;
    background:#21262d;border-radius:4px;margin-bottom:4px}
  .stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));
    gap:12px;margin-bottom:24px}
  .stat{background:var(--card);border:1px solid var(--border);
    border-radius:8px;padding:12px;text-align:center}
  .stat-num{font-size:2rem;font-weight:bold;color:var(--blue)}
  .stat-lbl{font-size:.72rem;color:var(--dim);margin-top:2px}
  .skipped{color:var(--dim);font-style:italic;font-size:.85rem;padding:8px}
</style>
</head>
<body>
HTMLEOF

# Dynamic content injection
{
  echo "<h1>🛰 Local Network Recon Report <span class='badge-mode'>$SCAN_LABEL</span></h1>"
  echo "<p class='meta'>Generated: $(date) &nbsp;|&nbsp; Target: $SUBNET &nbsp;|&nbsp; Scanner: $MY_IP</p>"

  OPEN_PORTS=$(grep -c 'open' "$OUTDIR/raw/nmap_full.nmap" 2>/dev/null || echo 0)
  RISKY=$(grep -c '\[RISKY\]' "$VULN_SUMMARY" 2>/dev/null || echo 0)
  WEB_COUNT=$(wc -l < "$WEB_HOSTS" 2>/dev/null || echo 0)

  echo "<div class='stat-grid'>"
  echo "  <div class='stat'><div class='stat-num'>$HOST_COUNT</div><div class='stat-lbl'>Hosts Found</div></div>"
  echo "  <div class='stat'><div class='stat-num'>$OPEN_PORTS</div><div class='stat-lbl'>Open Ports</div></div>"
  echo "  <div class='stat'><div class='stat-num' style='color:var(--red)'>$RISKY</div><div class='stat-lbl'>Risky Ports</div></div>"
  echo "  <div class='stat'><div class='stat-num'>$WEB_COUNT</div><div class='stat-lbl'>Web Endpoints</div></div>"
  echo "</div>"

  echo "<h2>Scan Configuration</h2><div class='card'><table>"
  echo "<tr><th>Setting</th><th>Value</th></tr>"
  echo "<tr><td>Scan Mode</td><td>$SCAN_LABEL</td></tr>"
  echo "<tr><td>nmap Flags</td><td><code>$NMAP_FLAGS</code></td></tr>"
  echo "<tr><td>Nikto Web Scan</td><td>$DO_NIKTO</td></tr>"
  echo "<tr><td>SMB Enum</td><td>$DO_SMB</td></tr>"
  echo "<tr><td>SNMP Enum</td><td>$DO_SNMP</td></tr>"
  echo "<tr><td>DNS Recon</td><td>$DO_DNS</td></tr>"
  echo "</table></div>"

  echo "<h2>Discovered Hosts</h2><div class='card'><table>"
  echo "<tr><th>IP</th><th>MAC / Vendor</th><th>Hostname</th></tr>"
  grep -E '^[0-9]' "$OUTDIR/raw/arp_scan.txt" 2>/dev/null \
    | awk '{printf "<tr><td>%s</td><td>%s %s</td><td>—</td></tr>\n",$1,$2,$3}' || true
  echo "</table></div>"

  echo "<h2>Port &amp; Vulnerability Summary</h2><div class='card'><pre>"
  cat "$VULN_SUMMARY" 2>/dev/null | sed 's/</\&lt;/g;s/>/\&gt;/g' || echo "No data."
  echo "</pre></div>"

  if ls "$OUTDIR"/web/nikto_*.txt &>/dev/null 2>&1; then
    echo "<h2>Web Scan (Nikto)</h2>"
    for f in "$OUTDIR"/web/nikto_*.txt; do
      echo "<details><summary>$(basename "$f")</summary>"
      echo "<pre>$(sed 's/</\&lt;/g;s/>/\&gt;/g' "$f")</pre></details>"
    done
  fi

  if ls "$OUTDIR"/smb/*.txt &>/dev/null 2>&1; then
    echo "<h2>SMB Enumeration</h2>"
    for f in "$OUTDIR"/smb/*.txt; do
      echo "<details><summary>$(basename "$f")</summary>"
      echo "<pre>$(sed 's/</\&lt;/g;s/>/\&gt;/g' "$f")</pre></details>"
    done
  fi

  if [[ -s "$OUTDIR/raw/nmap_vuln.nmap" ]]; then
    echo "<h2>NSE Vulnerability Scripts</h2>"
    echo "<details><summary>nmap vuln script output</summary>"
    echo "<pre>$(sed 's/</\&lt;/g;s/>/\&gt;/g' "$OUTDIR/raw/nmap_vuln.nmap")</pre></details>"
  fi

  if [[ -s "$OUTDIR/raw/nmap_targeted.txt" ]]; then
    echo "<details><summary>Targeted CVE scripts output</summary>"
    echo "<pre>$(sed 's/</\&lt;/g;s/>/\&gt;/g' "$OUTDIR/raw/nmap_targeted.txt")</pre></details>"
  fi

  cat << 'REFTABLE'
<h2>Common Exploit Reference</h2>
<div class='card'><table>
<tr><th>Port</th><th>Service</th><th>CVE / Exploit</th><th>Severity</th><th>Notes</th></tr>
<tr><td>445</td><td>SMB</td><td>MS17-010 / EternalBlue</td><td><span class='badge-crit'>CRITICAL</span></td><td>RCE – used by WannaCry/NotPetya</td></tr>
<tr><td>445</td><td>SMB</td><td>MS08-067</td><td><span class='badge-crit'>CRITICAL</span></td><td>RCE on XP/2003</td></tr>
<tr><td>445</td><td>SMB</td><td>CVE-2021-34527 PrintNightmare</td><td><span class='badge-crit'>CRITICAL</span></td><td>Windows Print Spooler RCE/LPE</td></tr>
<tr><td>3389</td><td>RDP</td><td>CVE-2019-0708 BlueKeep</td><td><span class='badge-crit'>CRITICAL</span></td><td>Pre-auth RCE Windows 7/2008</td></tr>
<tr><td>443</td><td>HTTPS</td><td>CVE-2014-0160 Heartbleed</td><td><span class='badge-crit'>CRITICAL</span></td><td>OpenSSL memory disclosure</td></tr>
<tr><td>80/443</td><td>HTTP</td><td>CVE-2014-6271 Shellshock</td><td><span class='badge-crit'>CRITICAL</span></td><td>Bash env var RCE via CGI</td></tr>
<tr><td>6379</td><td>Redis</td><td>Unauthenticated RCE</td><td><span class='badge-crit'>CRITICAL</span></td><td>Write SSH keys / cron jobs</td></tr>
<tr><td>27017</td><td>MongoDB</td><td>No auth default</td><td><span class='badge-crit'>CRITICAL</span></td><td>Full DB read/write without creds</td></tr>
<tr><td>21</td><td>FTP</td><td>Anonymous login</td><td><span class='badge-high'>HIGH</span></td><td>Unauthenticated file access</td></tr>
<tr><td>161</td><td>SNMP</td><td>Default community strings</td><td><span class='badge-high'>HIGH</span></td><td>public/private exposes full MIB</td></tr>
<tr><td>2049</td><td>NFS</td><td>World-readable exports</td><td><span class='badge-high'>HIGH</span></td><td>Mount and read filesystem remotely</td></tr>
<tr><td>5900</td><td>VNC</td><td>No-auth / weak password</td><td><span class='badge-high'>HIGH</span></td><td>Full desktop access</td></tr>
<tr><td>23</td><td>Telnet</td><td>Plaintext protocol</td><td><span class='badge-high'>HIGH</span></td><td>Credentials visible on wire</td></tr>
<tr><td>1433</td><td>MSSQL</td><td>xp_cmdshell / default SA</td><td><span class='badge-high'>HIGH</span></td><td>OS command exec via SQL</td></tr>
<tr><td>3306</td><td>MySQL</td><td>Empty root password</td><td><span class='badge-high'>HIGH</span></td><td>Full DB access without password</td></tr>
</table></div>
REFTABLE

  echo "<p class='meta' style='margin-top:24px'>Report complete. Raw files in: <strong>$OUTDIR/</strong></p>"
  echo "</body></html>"

} >> "$HTML_REPORT"

# ── Done ──────────────────────────────────────────────────────────────────────
section "Scan Complete"
log "Mode             : $SCAN_LABEL"
log "Output directory : $OUTDIR/"
log "Text report      : $TXT_REPORT"
log "HTML report      : $HTML_REPORT"
echo
echo -e "${BOLD}${GREEN}Open the HTML report:${RESET}  firefox $HTML_REPORT"
echo
