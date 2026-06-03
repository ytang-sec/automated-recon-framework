#!/usr/bin/env bash
# =============================================================================
#  LOCAL NETWORK RECON SCRIPT
#  Tools: nmap, nikto, arp-scan, netdiscover, enum4linux, smbclient,
#         snmpwalk, curl, whois, dig, masscan (optional)
#  Output: HTML + plain-text report
#  Usage:  sudo ./wifi_recon.sh [CIDR]   e.g. sudo ./wifi_recon.sh 192.168.1.0/24
#          If no CIDR supplied, the script auto-detects your local subnet.
# =============================================================================

set -euo pipefail

# ── Colour codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

banner(){
  echo -e "${CYAN}${BOLD}"
  echo "╔══════════════════════════════════════════════════════════╗"
  echo "║          LOCAL NETWORK RECON & VULN SCANNER              ║"
  echo "║     nmap · nikto · arp-scan · enum4linux · snmpwalk      ║"
  echo "╚══════════════════════════════════════════════════════════╝"
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
section(){ echo -e "\n${BOLD}${CYAN}══ $* ══${RESET}\n" | tee -a "$TXT_REPORT"; }

# ── Dependency check ──────────────────────────────────────────────────────────
REQUIRED=(nmap nikto arp-scan curl)
OPTIONAL=(netdiscover enum4linux smbclient snmpwalk masscan whatweb dnsrecon)
section "Dependency Check"
for t in "${REQUIRED[@]}"; do
  command -v "$t" &>/dev/null \
    && log "$t found" \
    || warn "$t NOT FOUND – install it (apt/brew/pacman)"
done
for t in "${OPTIONAL[@]}"; do
  command -v "$t" &>/dev/null \
    && log "$t found (optional)" \
    || warn "$t not found (optional – skipped if missing)"
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
log "Gateway : $GATEWAY"
log "This host: $MY_IP"

# ── Phase 1 – Host Discovery ──────────────────────────────────────────────────
section "Phase 1 – Host Discovery"
HOSTS_FILE="$OUTDIR/raw/hosts.txt"

log "Running arp-scan …"
arp-scan --localnet 2>/dev/null | tee "$OUTDIR/raw/arp_scan.txt" \
  | grep -E '^[0-9]' | awk '{print $1}' >> "$HOSTS_FILE" || true

log "Running nmap ping sweep …"
nmap -sn "$SUBNET" -oN "$OUTDIR/raw/nmap_ping.txt" 2>/dev/null
grep 'Nmap scan report' "$OUTDIR/raw/nmap_ping.txt" \
  | awk '{print $NF}' | tr -d '()' >> "$HOSTS_FILE" || true

# Deduplicate
sort -u "$HOSTS_FILE" -o "$HOSTS_FILE"
HOST_COUNT=$(wc -l < "$HOSTS_FILE")
log "Discovered $HOST_COUNT unique hosts"
cat "$HOSTS_FILE" | tee -a "$TXT_REPORT"

if command -v netdiscover &>/dev/null; then
  log "Running netdiscover (passive 15 s) …"
  timeout 15 netdiscover -p -r "$SUBNET" 2>/dev/null \
    > "$OUTDIR/raw/netdiscover.txt" || true
fi

# ── Phase 2 – Port & Service Scan ────────────────────────────────────────────
section "Phase 2 – Port & Service Scan"
NMAP_OUT="$OUTDIR/raw/nmap_full"
log "Full TCP SYN scan + version + default scripts (this may take a while) …"
nmap -sS -sV -sC -O \
  -p- \
  --min-rate 1000 \
  --open \
  -oA "$NMAP_OUT" \
  -iL "$HOSTS_FILE" \
  2>/dev/null | tee -a "$TXT_REPORT" || true

# UDP top-20
log "UDP top-20 ports …"
nmap -sU --top-ports 20 -sV \
  --open \
  -oN "$OUTDIR/raw/nmap_udp.txt" \
  -iL "$HOSTS_FILE" \
  2>/dev/null | tee -a "$TXT_REPORT" || true

# ── Phase 3 – Vulnerability Scripts ──────────────────────────────────────────
section "Phase 3 – Vulnerability & Exploit Detection (nmap NSE)"
VULN_OUT="$OUTDIR/raw/nmap_vuln"
log "Running vuln + exploit NSE scripts …"
nmap -sV \
  --script="vuln,exploit,auth,brute,default,safe" \
  --script-timeout 60s \
  -oA "$VULN_OUT" \
  -iL "$HOSTS_FILE" \
  2>/dev/null | tee -a "$TXT_REPORT" || true

# Specific high-value NSE scripts
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

# ── Phase 4 – Web Scanning ────────────────────────────────────────────────────
section "Phase 4 – Web Service Scanning"
# Extract hosts with open 80/443/8080/8443 from nmap XML
WEB_HOSTS="$OUTDIR/raw/web_hosts.txt"
python3 - <<'PYEOF' "$NMAP_OUT.xml" "$WEB_HOSTS" 2>/dev/null || true
import sys, xml.etree.ElementTree as ET
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
PYEOF

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

# ── Phase 5 – SMB / Windows Enumeration ──────────────────────────────────────
section "Phase 5 – SMB / Windows Enumeration"
SMB_HOSTS="$OUTDIR/raw/smb_hosts.txt"
python3 - <<'PYEOF' "$NMAP_OUT.xml" "$SMB_HOSTS" 2>/dev/null || true
import sys, xml.etree.ElementTree as ET
tree = ET.parse(sys.argv[1])
out  = open(sys.argv[2], 'w')
for host in tree.findall('host'):
    addr = host.find('address').get('addr','')
    for p in host.findall('ports/port'):
        if p.find('state').get('state') != 'open': continue
        if p.get('portid') in ('139','445'):
            out.write(addr + '\n'); break
out.close()
PYEOF

if [[ -s "$SMB_HOSTS" ]]; then
  while IFS= read -r ip; do
    log "  SMB enum → $ip"
    if command -v enum4linux &>/dev/null; then
      enum4linux -a "$ip" > "$OUTDIR/smb/enum4linux_${ip}.txt" 2>/dev/null || true
    fi
    if command -v smbclient &>/dev/null; then
      smbclient -L "$ip" -N > "$OUTDIR/smb/smbclient_${ip}.txt" 2>/dev/null || true
    fi
  done < "$SMB_HOSTS"
else
  log "No SMB hosts found."
fi

# ── Phase 6 – SNMP Enumeration ────────────────────────────────────────────────
section "Phase 6 – SNMP Enumeration"
SNMP_HOSTS="$OUTDIR/raw/snmp_hosts.txt"
grep -h 'open' "$OUTDIR/raw/nmap_udp.txt" 2>/dev/null \
  | grep '161/udp' | awk '{print $1}' > "$SNMP_HOSTS" || true

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

# ── Phase 7 – DNS Recon ───────────────────────────────────────────────────────
section "Phase 7 – DNS Recon"
log "DNS reverse lookup sweep …"
nmap -sn -R "$SUBNET" --dns-servers "$GATEWAY" \
  -oN "$OUTDIR/raw/dns_reverse.txt" 2>/dev/null || true

if command -v dnsrecon &>/dev/null; then
  log "dnsrecon against gateway …"
  dnsrecon -r "$SUBNET" -n "$GATEWAY" \
    -c "$OUTDIR/raw/dnsrecon.csv" 2>/dev/null || true
fi

# ── Phase 8 – Parse & Classify Findings ──────────────────────────────────────
section "Phase 8 – Parse & Classify Findings"

# Known dangerous ports and what they mean
declare -A PORT_INFO=(
  ["21"]="FTP – often allows anonymous login; plaintext credentials"
  ["22"]="SSH – brute-force target; check for old versions"
  ["23"]="Telnet – plaintext protocol; should not be open"
  ["25"]="SMTP – open relay or user enumeration possible"
  ["53"]="DNS – zone transfer, cache poisoning"
  ["80"]="HTTP – web app vulnerabilities (XSS, SQLi, etc.)"
  ["110"]="POP3 – plaintext mail"
  ["111"]="RPC – portmapper; multiple known CVEs"
  ["135"]="MSRPC – Windows RPC; MS03-026 and others"
  ["139"]="NetBIOS – SMB; EternalBlue (MS17-010)"
  ["143"]="IMAP – plaintext mail"
  ["161"]="SNMP – information disclosure; default communities"
  ["443"]="HTTPS – SSL/TLS vulns (Heartbleed, POODLE, BEAST)"
  ["445"]="SMB – EternalBlue MS17-010, MS08-067, PrintNightmare"
  ["512"]="rexec – remote execution, no auth"
  ["513"]="rlogin – legacy; no encryption"
  ["514"]="rsh/syslog – command execution without password"
  ["1433"]="MSSQL – empty/default passwords, xp_cmdshell"
  ["1521"]="Oracle DB – default credentials"
  ["2049"]="NFS – world-readable exports"
  ["3306"]="MySQL – empty root password, remote access"
  ["3389"]="RDP – BlueKeep CVE-2019-0708, brute force"
  ["4444"]="Metasploit default listener / backdoor"
  ["5432"]="PostgreSQL – default credentials"
  ["5900"]="VNC – no auth / weak password"
  ["6379"]="Redis – unauthenticated access, RCE"
  ["8080"]="HTTP-alt – same risks as port 80"
  ["8443"]="HTTPS-alt – same risks as port 443"
  ["27017"]="MongoDB – no auth by default"
)

VULN_SUMMARY="$OUTDIR/raw/vuln_summary.txt"
> "$VULN_SUMMARY"

log "Extracting open ports from nmap XML …"
python3 - <<'PYEOF' >> "$VULN_SUMMARY" 2>/dev/null || true
import sys, xml.etree.ElementTree as ET, json

DANGEROUS = {
  "21":"FTP – anonymous login / plaintext creds",
  "22":"SSH – brute-force / weak ciphers",
  "23":"Telnet – plaintext protocol",
  "25":"SMTP – open relay / user enum",
  "53":"DNS – zone transfer / cache poison",
  "80":"HTTP – web vulns",
  "110":"POP3 – plaintext mail",
  "111":"RPC portmapper – CVEs",
  "135":"MSRPC – MS03-026",
  "139":"NetBIOS/SMB – EternalBlue",
  "143":"IMAP – plaintext",
  "161":"SNMP – info disclosure",
  "443":"HTTPS – SSL vulns",
  "445":"SMB – EternalBlue / PrintNightmare",
  "512":"rexec – unauthenticated",
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
    tree = ET.parse("$(ls recon_*/raw/nmap_full.xml 2>/dev/null | head -1 || echo /dev/null)")
except:
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
        pid  = p.get('portid')
        proto= p.get('protocol','tcp')
        svc  = p.find('service')
        name = svc.get('name','') if svc is not None else ''
        prod = svc.get('product','') if svc is not None else ''
        ver  = svc.get('version','') if svc is not None else ''
        risk = DANGEROUS.get(pid, '')
        ports.append({'port':pid,'proto':proto,'service':name,
                      'product':prod,'version':ver,'risk':risk})
    results.append({'ip':ip,'hostname':hostname,'os':os_str,'ports':ports})

for r in results:
    print(f"\n{'='*60}")
    print(f"HOST : {r['ip']}  {r['hostname']}")
    print(f"OS   : {r['os']}")
    for p in r['ports']:
        flag = '  [RISKY]' if p['risk'] else ''
        print(f"  {p['port']}/{p['proto']:<4} {p['service']:<12} {p['product']} {p['version']}{flag}")
        if p['risk']:
            print(f"         └─ {p['risk']}")
PYEOF

cat "$VULN_SUMMARY" | tee -a "$TXT_REPORT"

# ── Phase 9 – HTML Report Generation ─────────────────────────────────────────
section "Phase 9 – Generating HTML Report"

cat > "$HTML_REPORT" <<'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Network Recon Report</title>
<style>
  :root{--bg:#0d1117;--card:#161b22;--border:#30363d;--green:#3fb950;
    --yellow:#d29922;--red:#f85149;--blue:#58a6ff;--text:#c9d1d9;}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--text);font-family:'Segoe UI',monospace;padding:24px}
  h1{color:var(--blue);font-size:1.8rem;margin-bottom:4px}
  h2{color:var(--green);font-size:1.1rem;margin:24px 0 8px;border-bottom:1px solid var(--border);padding-bottom:4px}
  .meta{color:#8b949e;font-size:.85rem;margin-bottom:24px}
  .card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px;margin-bottom:16px}
  .host-title{color:var(--blue);font-size:1rem;font-weight:bold}
  .os{color:#8b949e;font-size:.8rem;margin:4px 0 10px}
  table{width:100%;border-collapse:collapse;font-size:.82rem}
  th{text-align:left;padding:6px 10px;background:#21262d;color:#8b949e;border-bottom:1px solid var(--border)}
  td{padding:5px 10px;border-bottom:1px solid #21262d;vertical-align:top}
  .risky{color:var(--red);font-weight:bold}
  .warn{color:var(--yellow)}
  .ok{color:var(--green)}
  .badge-crit{background:#3d0a0a;color:var(--red);border:1px solid var(--red);
    border-radius:4px;padding:1px 6px;font-size:.75rem;white-space:nowrap}
  .badge-med{background:#3d2a00;color:var(--yellow);border:1px solid var(--yellow);
    border-radius:4px;padding:1px 6px;font-size:.75rem;white-space:nowrap}
  pre{white-space:pre-wrap;word-break:break-all;font-size:.78rem;
    background:#0d1117;padding:12px;border-radius:6px;overflow-x:auto}
  .section-raw{display:none}
  .toggle{cursor:pointer;color:var(--blue);font-size:.8rem;
    background:none;border:1px solid var(--border);border-radius:4px;padding:2px 8px;margin-top:6px}
  summary{cursor:pointer;color:var(--blue);margin-bottom:8px}
  .stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:24px}
  .stat{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:12px;text-align:center}
  .stat-num{font-size:2rem;font-weight:bold;color:var(--blue)}
  .stat-lbl{font-size:.75rem;color:#8b949e;margin-top:2px}
  @media(max-width:600px){.stat-num{font-size:1.4rem}}
</style>
</head>
<body>
HTMLEOF

# Inject dynamic content via bash
{
  echo "<h1>🛰 Local Network Recon Report</h1>"
  echo "<p class='meta'>Generated: $(date)  &nbsp;|&nbsp;  Target: $SUBNET  &nbsp;|&nbsp;  Scanner: $MY_IP</p>"

  # Stats
  OPEN_PORTS=$(grep -c 'open' "$OUTDIR/raw/nmap_full.nmap" 2>/dev/null || echo 0)
  RISKY=$(grep -c 'RISKY' "$VULN_SUMMARY" 2>/dev/null || echo 0)
  WEB_COUNT=$(wc -l < "$WEB_HOSTS" 2>/dev/null || echo 0)
  echo "<div class='stat-grid'>"
  echo "  <div class='stat'><div class='stat-num'>$HOST_COUNT</div><div class='stat-lbl'>Hosts Found</div></div>"
  echo "  <div class='stat'><div class='stat-num'>$OPEN_PORTS</div><div class='stat-lbl'>Open Ports</div></div>"
  echo "  <div class='stat'><div class='stat-num' style='color:var(--red)'>$RISKY</div><div class='stat-lbl'>Risky Ports</div></div>"
  echo "  <div class='stat'><div class='stat-num'>$WEB_COUNT</div><div class='stat-lbl'>Web Endpoints</div></div>"
  echo "</div>"

  # Host table
  echo "<h2>Discovered Hosts</h2>"
  echo "<div class='card'><table><tr><th>IP</th><th>MAC / Vendor</th><th>Hostname</th></tr>"
  grep -E '^[0-9]' "$OUTDIR/raw/arp_scan.txt" 2>/dev/null \
    | awk '{printf "<tr><td>%s</td><td>%s %s</td><td>—</td></tr>\n",$1,$2,$3}' || true
  echo "</table></div>"

  # Vuln summary per host (embed pre block)
  echo "<h2>Port & Vulnerability Summary</h2>"
  echo "<div class='card'><pre>"
  cat "$VULN_SUMMARY" 2>/dev/null | sed 's/</\&lt;/g;s/>/\&gt;/g' || echo "No data."
  echo "</pre></div>"

  # Nikto findings
  if ls "$OUTDIR"/web/nikto_*.txt &>/dev/null; then
    echo "<h2>Web Scan (Nikto)</h2>"
    for f in "$OUTDIR"/web/nikto_*.txt; do
      echo "<details><summary>$(basename "$f")</summary>"
      echo "<pre>$(cat "$f" | sed 's/</\&lt;/g;s/>/\&gt;/g')</pre></details>"
    done
  fi

  # SMB findings
  if ls "$OUTDIR"/smb/*.txt &>/dev/null; then
    echo "<h2>SMB Enumeration</h2>"
    for f in "$OUTDIR"/smb/*.txt; do
      echo "<details><summary>$(basename "$f")</summary>"
      echo "<pre>$(cat "$f" | sed 's/</\&lt;/g;s/>/\&gt;/g')</pre></details>"
    done
  fi

  # NSE vuln output
  echo "<h2>NSE Vulnerability Scripts Output</h2>"
  echo "<details><summary>nmap_vuln full output</summary>"
  echo "<pre>$(cat "$OUTDIR/raw/nmap_vuln.nmap" 2>/dev/null | sed 's/</\&lt;/g;s/>/\&gt;/g' || echo 'No data.')</pre></details>"

  echo "<details><summary>Targeted CVE scripts output</summary>"
  echo "<pre>$(cat "$OUTDIR/raw/nmap_targeted.txt" 2>/dev/null | sed 's/</\&lt;/g;s/>/\&gt;/g' || echo 'No data.')</pre></details>"

  # Reference: common exploits table
  cat <<'REFTABLE'
<h2>Common Exploit Reference</h2>
<div class='card'><table>
<tr><th>Port</th><th>Service</th><th>CVE / Exploit</th><th>Severity</th><th>Notes</th></tr>
<tr><td>445</td><td>SMB</td><td>MS17-010 / EternalBlue</td><td><span class='badge-crit'>CRITICAL</span></td><td>Remote code execution, used by WannaCry/NotPetya</td></tr>
<tr><td>445</td><td>SMB</td><td>MS08-067</td><td><span class='badge-crit'>CRITICAL</span></td><td>Remote code execution on XP/2003</td></tr>
<tr><td>445</td><td>SMB</td><td>CVE-2021-34527 PrintNightmare</td><td><span class='badge-crit'>CRITICAL</span></td><td>Windows Print Spooler RCE/LPE</td></tr>
<tr><td>3389</td><td>RDP</td><td>CVE-2019-0708 BlueKeep</td><td><span class='badge-crit'>CRITICAL</span></td><td>Pre-auth RCE on Windows 7/2008</td></tr>
<tr><td>443</td><td>HTTPS</td><td>CVE-2014-0160 Heartbleed</td><td><span class='badge-crit'>CRITICAL</span></td><td>OpenSSL memory disclosure</td></tr>
<tr><td>80/443</td><td>HTTP</td><td>CVE-2014-6271 Shellshock</td><td><span class='badge-crit'>CRITICAL</span></td><td>Bash env variable RCE via CGI</td></tr>
<tr><td>6379</td><td>Redis</td><td>Unauthenticated RCE</td><td><span class='badge-crit'>CRITICAL</span></td><td>Write SSH keys / cron jobs</td></tr>
<tr><td>27017</td><td>MongoDB</td><td>No auth default</td><td><span class='badge-crit'>CRITICAL</span></td><td>Full DB read/write without creds</td></tr>
<tr><td>21</td><td>FTP</td><td>Anonymous login</td><td><span class='badge-med'>HIGH</span></td><td>Unauthenticated file access</td></tr>
<tr><td>161</td><td>SNMP</td><td>Default community strings</td><td><span class='badge-med'>HIGH</span></td><td>'public'/'private' exposes full MIB</td></tr>
<tr><td>2049</td><td>NFS</td><td>World-readable exports</td><td><span class='badge-med'>HIGH</span></td><td>Mount and read filesystem remotely</td></tr>
<tr><td>5900</td><td>VNC</td><td>No-auth / weak password</td><td><span class='badge-med'>HIGH</span></td><td>Full desktop access</td></tr>
<tr><td>23</td><td>Telnet</td><td>Plaintext protocol</td><td><span class='badge-med'>HIGH</span></td><td>Credentials visible on wire</td></tr>
<tr><td>443</td><td>HTTPS</td><td>CVE-2014-3566 POODLE</td><td><span class='badge-med'>MEDIUM</span></td><td>SSLv3 downgrade attack</td></tr>
<tr><td>1433</td><td>MSSQL</td><td>xp_cmdshell / default SA</td><td><span class='badge-med'>HIGH</span></td><td>OS command execution via SQL</td></tr>
<tr><td>3306</td><td>MySQL</td><td>Empty root password</td><td><span class='badge-med'>HIGH</span></td><td>Full DB access without password</td></tr>
</table></div>
REFTABLE

  echo "<p class='meta' style='margin-top:24px'>Report complete. Raw files saved in: <strong>$OUTDIR/</strong></p>"
  echo "</body></html>"

} >> "$HTML_REPORT"

# ── Done ──────────────────────────────────────────────────────────────────────
section "Scan Complete"
log "Output directory : $OUTDIR/"
log "Text report      : $TXT_REPORT"
log "HTML report      : $HTML_REPORT"
echo
echo -e "${BOLD}${GREEN}Open the HTML report in a browser for the full formatted output.${RESET}"
echo
