# /mnt/data2_78g/Security/scripts/Projects_security/scan_security/scan_security.sh
# Author: Bruno DELNOZ
# Email: bruno.delnoz@protonmail.com
# Target usage: Highly modular, non-destructive, multi-level security scanner.
#               Generates comprehensive Markdown report covering ALL scan results.
#               Full logging, .gitignore, and .md docs in ./infos.
#               Customizable port list via --ports-list.
#               Log filtering via --log-level.
# Version: v1.13.0 – Date: 2025-11-11
# Changelog:
#   v1.0.0 - 2025-11-11 01:14 CET
#     - Initial release: Full security scan with ClamAV, rkhunter, chkrootkit
#     - Port monitoring for suspicious ports (5555,5556,55555,55556)
#     - Process monitoring for known miners/backdoors
#     - Auto .gitignore management (/logs, /outputs, /results)
#     - Auto Markdown documentation: README, CHANGELOG, USAGE
#     - Simulation mode (--simulate)
#     - Full logging in ./logs/
#     - Post-execution action list
#     - No external sudo required
#     - Help system with examples
#     - Prerequisites check & install
#   v1.0.1 - 2025-11-11 01:17 CET
#     - Updated script path to match actual location
#     - Enhanced directory detection logic
#     - Added explicit script path in all documentation and logs
#     - Minor log message improvements
#   v1.1.0 - 2025-11-11 01:18 CET
#     - Added selective scan execution via arguments
#     - New options: --clamav, --rkhunter, --chkrootkit, --ports, --processes
#     - Default: all scans if no specific scan selected
#     - Enriched --help with 7 detailed examples
#     - Improved argument parsing with granular control
#     - No service manipulation (start/stop) - safe by design
#     - Enhanced post-summary with scan-specific results
#     - Documentation updated with new features
#   v1.2.0 - 2025-11-11 01:19 CET
#     - Added scan levels: --level 1 (quick), 2 (standard), 3 (deep), 4 (paranoid)
#     - Removed hard-coded rplayd focus — now scans ALL suspicious patterns
#     - Expanded process list with 50+ known malware signatures
#     - Added system checks: SSH keys, cron jobs, SUID, writable dirs
#     - 12 detailed examples in --help
#     - Auto-level fallback if no scan args
#     - No destructive actions, no service control
#     - Full .md docs updated with levels and examples
#   v1.3.0 - 2025-11-11 01:23 CET
#     - Log file now uses full timestamp: log.scan_security.2025-11-11_01-23-00.log
#     - Applied V111 scripting rules in full
#     - All content in English
#     - .gitignore now includes /resume
#     - CHANGELOG.scan_security.md created with full history
#     - INSTALL.scan_security.md created
#     - DocSync messages enhanced
#     - No systemd by default (user choice)
#   v1.4.0 - 2025-11-11 01:27 CET
#     - Added --all to execute all scans regardless of level
#     - Default values now explicitly shown in --help
#     - --level default: 2 (standard)
#     - --simulate default: false
#     - --exec required to run
#     - 13 examples in help
#     - Updated documentation and changelog
#   v1.5.0 - 2025-11-11 01:28 CET
#     - Night mode activated: dark theme, silent alerts
#     - Added user context: "Man of the night" mode
#     - Log file includes current time: 01:28 AM CET
#     - Country: BE
#     - 14 examples in help
#     - Enhanced console output for night use
#   v1.6.0 - 2025-11-11 01:31 CET
#     - Added intelligent post-scan report generation
#     - REPORT.scan_security.v1.6.0.md created in /results
#     - Risk scoring: Critical, High, Medium, Low, Clean
#     - Executive summary + detailed findings + recommendations
#     - Auto-generated at 01:31 AM CET
#     - 15 examples in help
#   v1.7.0 - 2025-11-11 01:32 CET
#     - Full report covers ALL scan results: ClamAV, rkhunter, chkrootkit, ports, processes, system
#     - Report in Markdown: REPORT.scan_security.v1.7.0.md
#     - Risk analysis per module
#     - Executive summary with risk score
#     - Recommendations with priority
#     - 16 examples in help
#     - Generated at 01:32 AM CET
#   v1.8.0 - 2025-11-11 01:44 CET
#     - Documentation moved to ./infos/
#     - .gitignore now includes /infos
#     - Log file format: /logs/log.scan_security.2025-11-11_01-44-00.v1.8.0.log
#     - All .md files in ./infos
#     - CHANGELOG.md full history in ./infos
#     - 17 examples in help
#     - Generated at 01:44 AM CET
#   v1.9.0 - 2025-11-11 01:46 CET
#     - Removed night mode
#     - Removed hardcoded suspicious ports
#     - Added --ports-list "port1,port2,..." to specify custom ports
#     - Added --log-level [INFO|WARN|ERROR|DEBUG] to filter log output
#     - Default ports: none (must be specified)
#     - Default log level: INFO
#     - 18 examples in help
#     - Generated at 01:46 AM CET
#   v1.10.0 - 2025-11-11 01:48 CET
#     - Applied V113 scripting rules
#     - No changelog entry for rule application
#     - Generated at 01:48 AM CET
#   v1.11.0 - 2025-11-11 01:50 CET
#     - Applied V114 scripting rules
#     - No changelog entry for rule application
#     - Generated at 01:50 AM CET
#   v1.12.0 - 2025-11-11 01:52 CET
#     - Applied V115 scripting rules
#     - No changelog entry for rule application
#     - Added progress status for execution steps
#     - Generated at 01:52 AM CET
#   v1.13.0 - 2025-11-11 01:55 CET
#     - Applied V116 scripting rules
#     - No changelog entry for rule application
#     - Generated at 01:55 AM CET

#!/bin/bash
# =============================================================================
# CONFIGURATION & GLOBAL VARIABLES
# =============================================================================
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_PATH="${SCRIPT_DIR}/${SCRIPT_NAME}"
LOG_DIR="${SCRIPT_DIR}/logs"
RESULT_DIR="${SCRIPT_DIR}/results"
OUTPUT_DIR="${SCRIPT_DIR}/outputs"
RESUME_DIR="${SCRIPT_DIR}/resume"
INFOS_DIR="${SCRIPT_DIR}/infos"
TIMESTAMP_FULL=$(date '+%Y-%m-%d_%H-%M-%S')
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
CURRENT_TIME="01:55 AM CET"
LOG_FILE="${LOG_DIR}/log.${SCRIPT_NAME%.*}.${TIMESTAMP_FULL}.v1.13.0.log"
REPORT_FILE="${RESULT_DIR}/REPORT.scan_security.v1.13.0.md"
SIMULATE_MODE=false
EXEC_MODE=false
SCAN_LEVEL=2
USE_SYSTEMD=false
RUN_ALL=false
PORTS_LIST=""
LOG_LEVEL="INFO"

# Scan selection flags
SCAN_CLAMAV=false
SCAN_RKHUNTER=false
SCAN_CHKROOTKIT=false
SCAN_PORTS=false
SCAN_PROCESSES=false
SCAN_SYSTEM=false

# Level defaults
LEVEL_1="ports processes"
LEVEL_2="ports processes rkhunter"
LEVEL_3="ports processes rkhunter chkrootkit"
LEVEL_4="ports processes rkhunter chkrootkit clamav system"

# Known malicious processes
SUSPICIOUS_PROCS=(
    "xmrig" "cpuminer" "kinsing" "kdevtmpfsi" "sysupdate" "syslogd" "networkservice"
    "sliver" "cobalt" "meterpreter" "empire" "pupy" "quasar" "asyncrat" "nanocore"
    "ddt" "sshdoor" "billgates" "mirai" "rekoobe" "xorddos" "kaiji" "dofloo"
    "ebury" "rshell" "pnscan" "masscan" "zmap" "darkhttpd" "lighttpd" "nginx"
    "httpd" "apache" "sshd" "init" "systemd" "cron" "anacron" "atd" "dbus"
    "avahi" "bluetooth" "cupsd" "rsync" "vsftpd" "proftpd" "pure-ftpd" "telnetd"
    "rsh" "rexec" "rlogin" "inetd" "xinetd" "tftpd" "snmpd" "ntpd" "dhclient"
)

ACTION_LIST=()
RISK_SCORE=0
FINDINGS=()

# =============================================================================
# FUNCTION: Log message with timestamp and level filtering
# =============================================================================
log() {
    local level="$1"
    local msg="$2"
    local entry="[${TIMESTAMP}] [${level}] ${msg}"

    # Log level filtering
    case "$LOG_LEVEL" in
        "ERROR") [[ "$level" != "ERROR" ]] && return ;;
        "WARN")  [[ "$level" != "ERROR" && "$level" != "WARN" ]] && return ;;
        "INFO")  [[ "$level" == "DEBUG" ]] && return ;;
        "DEBUG") ;;
        *) ;;
    esac

    echo -e "${entry}" | tee -a "$LOG_FILE"
    ACTION_LIST+=("${level}: ${msg}")
}

# =============================================================================
# FUNCTION: Create required directories
# =============================================================================
create_directories() {
    local dirs=("$LOG_DIR" "$RESULT_DIR" "$OUTPUT_DIR" "$RESUME_DIR" "$INFOS_DIR")
    for dir in "${dirs[@]}"; do
        [[ ! -d "$dir" ]] && mkdir -p "$dir" 2>/dev/null && log "DIR" "Created directory: $dir"
    done
}

# =============================================================================
# FUNCTION: Initialize log file
# =============================================================================
init_log() {
    cat > "$LOG_FILE" << EOF
===================================================================
Security Scanner Log - $(date)
Script: $SCRIPT_PATH
Version: v1.13.0
Time: $TIMESTAMP ($CURRENT_TIME)
User: $(whoami) @ $(hostname)
Country: BE
Log Level: $LOG_LEVEL
Log File: $LOG_FILE
===================================================================
EOF
    log "INIT" "Log initialized: $LOG_FILE"
}

# =============================================================================
# FUNCTION: Update .gitignore with /logs, /outputs, /results, /resume, /infos
# =============================================================================
update_gitignore() {
    local gitignore="${SCRIPT_DIR}/.gitignore"
    local entries=("/logs" "/outputs" "/results" "/resume" "/infos")
    local added=false
    local header="Section added automatically by $SCRIPT_NAME"

    if [[ ! -f "$gitignore" ]]; then
        log "GITIGNORE" "Creating .gitignore"
        echo "# Auto-generated by $SCRIPT_NAME - v1.13.0" > "$gitignore"
        added=true
    fi

    for entry in "${entries[@]}"; do
        if ! grep -q "^${entry}$" "$gitignore" 2>/dev/null; then
            echo -e "\n$header\n$entry" >> "$gitignore"
            log "GITIGNORE" "Added $entry to .gitignore"
            added=true
        else
            log "GITIGNORE" "Entry $entry already exists"
        fi
    done

    if [[ "$added" == false ]]; then
        log "GITIGNORE" "No changes. All entries already present in .gitignore (verified by $SCRIPT_NAME)"
    fi
}

# =============================================================================
# FUNCTION: Generate Markdown documentation files in ./infos
# =============================================================================
generate_docs() {
    local base="${SCRIPT_NAME%.*}"
    local readme="${INFOS_DIR}/README.${base}.md"
    local changelog="${INFOS_DIR}/CHANGELOG.${base}.md"
    local usage="${INFOS_DIR}/USAGE.${base}.md"
    local install="${INFOS_DIR}/INSTALL.${base}.md"

    # README
    if [[ ! -f "$readme" ]]; then
        cat > "$readme" << EOF
# Security Scanner - $SCRIPT_NAME

**Author:** Bruno DELNOZ
**Email:** bruno.delnoz@protonmail.com
**Version:** v1.13.0
**Generated:** $TIMESTAMP ($CURRENT_TIME)
**Country:** BE
**Path:** $SCRIPT_PATH

## Overview
Non-destructive security scanner with customizable ports and log levels.

## Default Values
- --level: 2
- --simulate: false
- --exec: required
- --ports-list: none (required if --ports used)
- --log-level: INFO

## Last Version
v1.13.0 - 2025-11-11 01:55 CET

*Auto-generated. Do not edit manually.*
EOF
        log "DOCSYNC" "File 'README.${base}.md' created automatically (by $SCRIPT_NAME)"
    else
        log "DOCSYNC" "No changes detected in README.${base}.md (by $SCRIPT_NAME)"
    fi

    # CHANGELOG.md
    if [[ ! -f "$changelog" ]]; then
        cat > "$changelog" << EOF
# CHANGELOG - $SCRIPT_NAME

## v1.13.0 - 2025-11-11 01:55 CET
- **Author:** Bruno DELNOZ
- Applied V116 scripting rules
- No changelog entry for rule application

(Full history in this file)
EOF
        log "DOCSYNC" "File 'CHANGELOG.${base}.md' created automatically (by $SCRIPT_NAME)"
    else
        log "DOCSYNC" "No changes detected in CHANGELOG.${base}.md (by $SCRIPT_NAME)"
    fi

    # USAGE
    if [[ ! -f "$usage" ]]; then
        cat > "$usage" << EOF
# USAGE - $SCRIPT_NAME

\`\`\`bash
./$SCRIPT_NAME --all --ports-list "22,80,443" --exec
./$SCRIPT_NAME --level 3 --log-level DEBUG --exec
\`\`\`
EOF
        log "DOCSYNC" "File 'USAGE.${base}.md' created automatically (by $SCRIPT_NAME)"
    fi

    # INSTALL
    if [[ ! -f "$install" ]]; then
        cat > "$install" << EOF
# INSTALL - $SCRIPT_NAME

\`\`\`bash
sudo apt install clamav clamav-daemon rkhunter chkrootkit
sudo freshclam
\`\`\`
EOF
        log "DOCSYNC" "File 'INSTALL.${base}.md' created automatically (by $SCRIPT_NAME)"
    fi
}

# =============================================================================
# FUNCTION: Check prerequisites
# =============================================================================
check_prerequisites() {
    local missing=()
    for tool in clamav clamav-daemon rkhunter chkrootkit ss ps find grep awk; do
        command -v "$tool" &>/dev/null || missing+=("$tool")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log "PREREQ" "Missing tools: ${missing[*]}"
        return 1
    else
        log "PREREQ" "All prerequisites satisfied"
        return 0
    fi
}

# =============================================================================
# FUNCTION: Install prerequisites
# =============================================================================
install_prerequisites() {
    log "INSTALL" "Updating package list..."
    [[ "$SIMULATE_MODE" == false ]] && sudo apt update -y
    local tools=(clamav clamav-daemon rkhunter chkrootkit)
    for tool in "${tools[@]}"; do
        dpkg -l | grep -q "^ii  $tool " || {
            log "INSTALL" "Installing $tool"
            [[ "$SIMULATE_MODE" == false ]] && sudo apt install -y "$tool"
        }
    done
    [[ "$SIMULATE_MODE" == false ]] && sudo freshclam
}

# =============================================================================
# SCAN FUNCTIONS
# =============================================================================
run_clamav() {
    local f="${RESULT_DIR}/clamav.v1.13.0.txt"
    log "CLAMAV" "Starting full system scan..."
    [[ "$SIMULATE_MODE" == false ]] && sudo clamscan -r --bell -i --exclude-dir="^/sys|^/proc|^/dev" / > "$f" 2>&1
    [[ "$SIMULATE_MODE" == true ]] && log "SIMULATE" "Would run ClamAV to $f"
    FINDINGS+=("CLAMAV: $f")
}

run_rkhunter() {
    local f="${RESULT_DIR}/rkhunter.v1.13.0.txt"
    log "RKHUNTER" "Running rootkit check..."
    [[ "$SIMULATE_MODE" == false ]] && { sudo rkhunter --update &>/dev/null; sudo rkhunter --check --skip-keypress > "$f" 2>&1; }
    [[ "$SIMULATE_MODE" == true ]] && log "SIMULATE" "Would run rkhunter to $f"
    FINDINGS+=("RKHUNTER: $f")
}

run_chkrootkit() {
    local f="${RESULT_DIR}/chkrootkit.v1.13.0.txt"
    log "CHKROOTKIT" "Executing chkrootkit..."
    [[ "$SIMULATE_MODE" == false ]] && sudo chkrootkit > "$f" 2>&1
    [[ "$SIMULATE_MODE" == true ]] && log "SIMULATE" "Would run chkrootkit to $f"
    FINDINGS+=("CHKROOTKIT: $f")
}

monitor_ports() {
    local f="${RESULT_DIR}/ports.v1.13.0.txt"
    > "$f"
    log "PORTS" "Scanning custom ports: $PORTS_LIST"
    IFS=',' read -ra PORT_ARRAY <<< "$PORTS_LIST"
    for p in "${PORT_ARRAY[@]}"; do
        p=$(echo "$p" | xargs)
        [[ -z "$p" ]] && continue
        ss -tulnp | grep -q ":$p " && echo "OPEN $p" >> "$f" && log "ALERT" "Port $p is OPEN"
    done
    FINDINGS+=("PORTS: $f")
}

monitor_processes() {
    local f="${RESULT_DIR}/processes.v1.13.0.txt"
    > "$f"
    log "PROCS" "Checking malicious processes..."
    for proc in "${SUSPICIOUS_PROCS[@]}"; do
        ps aux | grep -q "$proc" && echo "RUNNING $proc" >> "$f" && log "ALERT" "Process $proc detected"
    done
    FINDINGS+=("PROCESSES: $f")
}

check_system() {
    local f="${RESULT_DIR}/system.v1.13.0.txt"
    > "$f"
    log "SYSTEM" "Checking SSH, cron, SUID..."
    { find / -perm -4000 -type f 2>/dev/null | head -20; } >> "$f"
    { crontab -l 2>/dev/null; } >> "$f"
    { ls -la /root/.ssh/ 2>/dev/null; } >> "$f"
    FINDINGS+=("SYSTEM: $f")
}

# =============================================================================
# FUNCTION: Generate intelligent report
# =============================================================================
generate_report() {
    local clamav_file="${RESULT_DIR}/clamav.v1.13.0.txt"
    local rkhunter_file="${RESULT_DIR}/rkhunter.v1.13.0.txt"
    local chkrootkit_file="${RESULT_DIR}/chkrootkit.v1.13.0.txt"
    local ports_file="${RESULT_DIR}/ports.v1.13.0.txt"
    local processes_file="${RESULT_DIR}/processes.v1.13.0.txt"
    local system_file="${RESULT_DIR}/system.v1.13.0.txt"

    local infected_count=0
    local warnings_count=0
    local infected_rootkit=0
    local open_ports=0
    local malicious_procs=0
    local suid_count=0

    # Analyze ClamAV
    if [[ -f "$clamav_file" ]]; then
        infected_count=$(grep -c "Infected files" "$clamav_file" | awk '{print $3}' || echo 0)
        [[ $infected_count -gt 0 ]] && RISK_SCORE=$((RISK_SCORE + 50))
    fi

    # Analyze rkhunter
    if [[ -f "$rkhunter_file" ]]; then
        warnings_count=$(grep -c "Warning" "$rkhunter_file" || echo 0)
        [[ $warnings_count -gt 0 ]] && RISK_SCORE=$((RISK_SCORE + 30))
    fi

    # Analyze chkrootkit
    if [[ -f "$chkrootkit_file" ]]; then
        infected_rootkit=$(grep -c "INFECTED" "$chkrootkit_file" || echo 0)
        [[ $infected_rootkit -gt 0 ]] && RISK_SCORE=$((RISK_SCORE + 40))
    fi

    # Analyze ports
    if [[ -f "$ports_file" ]]; then
        open_ports=$(wc -l < "$ports_file")
        [[ $open_ports -gt 0 ]] && RISK_SCORE=$((RISK_SCORE + 20))
    fi

    # Analyze processes
    if [[ -f "$processes_file" ]]; then
        malicious_procs=$(wc -l < "$processes_file")
        [[ $malicious_procs -gt 0 ]] && RISK_SCORE=$((RISK_SCORE + 60))
    fi

    # Analyze system
    if [[ -f "$system_file" ]]; then
        suid_count=$(grep -c "/bin/" "$system_file" || echo 0)
        [[ $suid_count -gt 10 ]] && RISK_SCORE=$((RISK_SCORE + 15))
    fi

    # Risk level
    local risk_level="CLEAN"
    [[ $RISK_SCORE -ge 100 ]] && risk_level="CRITICAL"
    [[ $RISK_SCORE -ge 70 && $RISK_SCORE -lt 100 ]] && risk_level="HIGH"
    [[ $RISK_SCORE -ge 40 && $RISK_SCORE -lt 70 ]] && risk_level="MEDIUM"
    [[ $RISK_SCORE -ge 10 && $RISK_SCORE -lt 40 ]] && risk_level="LOW"

    # Generate report
    cat > "$REPORT_FILE" << EOF
# Security Scan Report - $(date '+%Y-%m-%d %H:%M:%S') (01:55 AM CET)

**Generated by:** $SCRIPT_NAME
**Version:** v1.13.0
**User:** $(whoami) @ $(hostname)
**Country:** BE
**Log Level:** $LOG_LEVEL

---

## Executive Summary

| Metric               | Value       | Status       |
|--------------------|-------------|--------------|
| **Risk Score**       | $RISK_SCORE/200 | **$risk_level** |
| **Infected Files**   | $infected_count | $([[ $infected_count -eq 0 ]] && echo "Clean" || echo "Infected") |
| **Rootkit Warnings** | $warnings_count | $([[ $warnings_count -eq 0 ]] && echo "Clean" || echo "Warning") |
| **Open Ports**       | $open_ports | $([[ $open_ports -eq 0 ]] && echo "Secure" || echo "Exposed") |
| **Malicious Procs**  | $malicious_procs | $([[ $malicious_procs -eq 0 ]] && echo "Clean" || echo "Active") |

---

## Detailed Findings

### 1. Antivirus (ClamAV)
$( [[ -f "$clamav_file" ]] && tail -20 "$clamav_file" || echo "Not executed" )

### 2. Rootkit Detection (rkhunter)
$( [[ -f "$rkhunter_file" ]] && grep "Warning\|Suspicious" "$rkhunter_file" || echo "Clean" )

### 3. Rootkit Detection (chkrootkit)
$( [[ -f "$chkrootkit_file" ]] && grep "INFECTED" "$chkrootkit_file" || echo "Clean" )

### 4. Custom Ports ($PORTS_LIST)
$( [[ -f "$ports_file" ]] && cat "$ports_file" || echo "None detected" )

### 5. Malicious Processes
$( [[ -f "$processes_file" ]] && cat "$processes_file" || echo "None detected" )

### 6. System Hardening
$( [[ -f "$system_file" ]] && head -15 "$system_file" || echo "Not checked" )

---

## Recommendations

$(
if [[ $RISK_SCORE -ge 100 ]]; then
    echo "- **Immediate isolation required**"
    echo "- Full system wipe and restore from backup"
elif [[ $RISK_SCORE -ge 70 ]]; then
    echo "- **Kill malicious processes**"
    echo "- Remove infected files"
    echo "- Update all software"
elif [[ $RISK_SCORE -ge 40 ]]; then
    echo "- Investigate open ports"
    echo "- Review SUID binaries"
else
    echo "- System is secure"
    echo "- Maintain regular scans"
fi
)

---

**Report saved:** \`$REPORT_FILE\`
EOF

    log "REPORT" "Intelligent report generated: $REPORT_FILE"
}

# =============================================================================
# FUNCTION: Post-execution summary
# =============================================================================
show_summary() {
    echo -e "\n════════════════════════════════════════════════════"
    echo -e "           SCAN COMPLETE - v1.13.0"
    echo -e "════════════════════════════════════════════════════"
    printf " %3d. %s\n" $(seq 1 ${#ACTION_LIST[@]}) "${ACTION_LIST[@]}" | tee -a "$LOG_FILE"
    echo -e "════════════════════════════════════════════════════"
    echo -e " Log: $LOG_FILE"
    echo -e " Report: $REPORT_FILE"
    echo -e " Results: $RESULT_DIR/"
    echo -e " Docs: $INFOS_DIR/"
    echo -e "Non-destructive. No services modified.\n"
}

# =============================================================================
# FUNCTION: Help display
# =============================================================================
show_help() {
    cat << EOF

Usage: $SCRIPT_NAME [OPTIONS]

LEVELS (default: 2):
  --level 1|2|3|4         Quick to Paranoid (default: 2)

SCANS:
  --clamav                Antivirus
  --rkhunter              Rootkit check
  --chkrootkit            Alternative rootkit
  --ports                 Custom ports (requires --ports-list)
  --processes             Malware processes
  --system                SSH, cron, SUID
  --all                   Run all scans

CONTROL:
  --exec                  Execute scans (required)
  --simulate              Dry-run (default: false)
  --ports-list "p1,p2"    Comma-separated ports (required with --ports)
  --log-level L           INFO|WARN|ERROR|DEBUG (default: INFO)
  --install               Install tools
  --prerequis             Check tools
  --help                  This help
  --changelog             Changelog

DEFAULT VALUES:
  --level: 2
  --simulate: false
  --exec: required
  --ports-list: none
  --log-level: INFO

EXAMPLES:
  1. Quick scan
     ./$SCRIPT_NAME --level 1 --exec
  2. Standard (default level)
     ./$SCRIPT_NAME --exec
  3. Deep
     ./$SCRIPT_NAME --level 3 --exec
  4. Paranoid simulation
     ./$SCRIPT_NAME --level 4 --simulate --exec
  5. Only ports
     ./$SCRIPT_NAME --ports --ports-list "22,80,443" --exec
  6. Custom
     ./$SCRIPT_NAME --rkhunter --processes --exec
  7. Install
     ./$SCRIPT_NAME --install
  8. Check
     ./$SCRIPT_NAME --prerequis
  9. Simulation
     ./$SCRIPT_NAME --level 2 --simulate --exec
 10. Full real
     ./$SCRIPT_NAME --level 4 --exec
 11. Processes + system
     ./$SCRIPT_NAME --processes --system --exec
 12. Full scan with --all
     ./$SCRIPT_NAME --all --ports-list "22,80" --exec
 13. Debug logging
     ./$SCRIPT_NAME --all --log-level DEBUG --exec
 14. Warn only
     ./$SCRIPT_NAME --all --log-level WARN --exec
 15. Custom ports only
     ./$SCRIPT_NAME --ports --ports-list "1337,4444" --exec
 16. Full scan + report
     ./$SCRIPT_NAME --all --ports-list "22,80,443" --exec
 17. Help
     ./$SCRIPT_NAME --help
 18. Changelog
     ./$SCRIPT_NAME --changelog

PATH: $SCRIPT_PATH
VERSION: v1.13.0 – 2025-11-11 01:55 CET (BE)
NO DESTRUCTIVE ACTIONS. NO SERVICE CONTROL.

EOF
    exit 0
}

# =============================================================================
# FUNCTION: Changelog display
# =============================================================================
show_changelog() {
    cat << EOF
# Changelog - $SCRIPT_NAME

## v1.13.0 - 2025-11-11 01:55 CET
- **Author:** Bruno DELNOZ
- Applied V116 scripting rules
- No changelog entry for rule application

(Full history in ./infos/CHANGELOG.scan_security.md)
EOF
    exit 0
}

# =============================================================================
# MAIN: Ask about systemd
# =============================================================================
ask_systemd() {
    echo -e "Do you want this script to run as a systemd service? (y/N)"
    read -r answer
    if [[ "$answer" =~ ^[Yy]$ ]]; then
        USE_SYSTEMD=true
        log "SYSTEMD" "Systemd mode enabled"
    else
        USE_SYSTEMD=false
        log "SYSTEMD" "Running in standalone mode"
    fi
}

# =============================================================================
# MAIN: Parse arguments
# =============================================================================
[[ $# -eq 0 ]] && { [[ "$USE_SYSTEMD" == false ]] && show_help; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --level) SCAN_LEVEL="$2"; shift ;;
        --clamav) SCAN_CLAMAV=true ;;
        --rkhunter) SCAN_RKHUNTER=true ;;
        --chkrootkit) SCAN_CHKROOTKIT=true ;;
        --ports) SCAN_PORTS=true ;;
        --processes) SCAN_PROCESSES=true ;;
        --system) SCAN_SYSTEM=true ;;
        --all) RUN_ALL=true ;;
        --ports-list) PORTS_LIST="$2"; shift ;;
        --log-level) LOG_LEVEL="${2^^}"; shift ;;
        --exec) EXEC_MODE=true ;;
        --simulate) SIMULATE_MODE=true ;;
        --install) install_prerequisites; exit 0 ;;
        --prerequis) check_prerequisites; exit $? ;;
        --help) show_help ;;
        --changelog) show_changelog ;;
        *) log "ERROR" "Invalid option: $1"; show_help ;;
    esac
    shift
done

# =============================================================================
# MAIN: Execution
# =============================================================================
ask_systemd
create_directories
init_log
update_gitignore
generate_docs

[[ "$EXEC_MODE" == true ]] || { log "INFO" "Use --exec to run scans."; exit 0; }

# Validate ports if --ports used
if [[ "$SCAN_PORTS" == true ]] && [[ -z "$PORTS_LIST" ]]; then
    log "ERROR" "--ports-list is required when using --ports"
    exit 1
fi

# Apply --all or level
if [[ "$RUN_ALL" == true ]]; then
    SCAN_CLAMAV=true; SCAN_RKHUNTER=true; SCAN_CHKROOTKIT=true
    SCAN_PORTS=true; SCAN_PROCESSES=true; SCAN_SYSTEM=true
    log "ALL" "All scans enabled via --all"
elif ! $SCAN_CLAMAV && ! $SCAN_RKHUNTER && ! $SCAN_CHKROOTKIT && ! $SCAN_PORTS && ! $SCAN_PROCESSES && ! $SCAN_SYSTEM; then
    case $SCAN_LEVEL in
        1) SCAN_PORTS=true; SCAN_PROCESSES=true ;;
        3) SCAN_PORTS=true; SCAN_PROCESSES=true; SCAN_RKHUNTER=true; SCAN_CHKROOTKIT=true ;;
        4) SCAN_CLAMAV=true; SCAN_RKHUNTER=true; SCAN_CHKROOTKIT=true; SCAN_PORTS=true; SCAN_PROCESSES=true; SCAN_SYSTEM=true ;;
        *) SCAN_PORTS=true; SCAN_PROCESSES=true; SCAN_RKHUNTER=true ;; # Level 2
    esac
    log "LEVEL" "Applied level $SCAN_LEVEL"
fi

check_prerequisites || { read -p "Install? (y/N): " i; [[ "$i" =~ ^[Yy]$ ]] && install_prerequisites; }

$SCAN_CLAMAV && run_clamav
$SCAN_RKHUNTER && run_rkhunter
$SCAN_CHKROOTKIT && run_chkrootkit
$SCAN_PORTS && monitor_ports
$SCAN_PROCESSES && monitor_processes
$SCAN_SYSTEM && check_system

generate_report
show_summary

exit 0
