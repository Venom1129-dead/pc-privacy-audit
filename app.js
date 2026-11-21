// PC Hardening & Privacy Audit Engine
(function () {
  const CHECKS = [
    // 1. OS Telemetry & Privacy
    {
      id: "diag_telemetry",
      cat: "telemetry",
      catName: "OS Telemetry",
      title: "Disable Windows Diagnostic Data Telemetry",
      desc: "Prevent Windows from sending diagnostic telemetry and keystroke logs to external servers.",
      points: 8,
      cmd: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection' -Name 'AllowTelemetry' -Value 0 -Type DWord"
    },
    {
      id: "ad_tracking_id",
      cat: "telemetry",
      catName: "OS Telemetry",
      title: "Disable Advertising ID Tracking",
      desc: "Stop cross-app profile tracking and targeted telemetry via personalized advertising identifiers.",
      points: 6,
      cmd: "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo' -Name 'Enabled' -Value 0"
    },
    {
      id: "activity_history",
      cat: "telemetry",
      catName: "OS Telemetry",
      title: "Disable Activity History & Timeline Uploads",
      desc: "Prevent local application usage and file browsing timeline sync to Microsoft cloud accounts.",
      points: 6,
      cmd: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System' -Name 'PublishUserActivities' -Value 0"
    },
    {
      id: "location_services",
      cat: "telemetry",
      catName: "OS Telemetry",
      title: "Restrict Geolocation Sensor Access",
      desc: "Turn off background sensor tracking and global positioning access for background desktop apps.",
      points: 5,
      cmd: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors' -Name 'DisableLocation' -Value 1"
    },

    // 2. Network & DNS Security
    {
      id: "doh_dns_encryption",
      cat: "network",
      catName: "Network & DNS",
      title: "Enforce DNS-over-HTTPS (DoH) / DNS-over-TLS",
      desc: "Encrypt all plaintext port 53 DNS lookups to prevent ISP snooping, man-in-the-middle attacks, and router hijacking.",
      points: 9,
      cmd: "netsh dns add encryption server=1.1.1.1 dohtemplate=https://cloudflare-dns.com/dns-query autoupgrade=yes"
    },
    {
      id: "webrtc_leak_shield",
      cat: "network",
      catName: "Network & DNS",
      title: "Block Browser WebRTC Local IP Leaks",
      desc: "Configure browser policies to block STUN queries that reveal true local and public IP addresses behind VPNs.",
      points: 7,
      cmd: "# In Chrome/Edge: Go to chrome://flags and set WebRTC IP handling to Disable non-proxied UDP"
    },
    {
      id: "rdp_exposure_check",
      cat: "network",
      catName: "Network & DNS",
      title: "Disable Unauthenticated Remote Desktop (Port 3389)",
      desc: "Close default RDP ports exposed to brute-force network scans when remote access is not needed.",
      points: 8,
      cmd: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1"
    },
    {
      id: "smbv1_protocol_disable",
      cat: "network",
      catName: "Network & DNS",
      title: "Disable Legacy SMBv1 Protocol (EternalBlue Vector)",
      desc: "Disable the legacy SMBv1 file-sharing protocol vulnerable to lateral network ransomware worms.",
      points: 8,
      cmd: "Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol -NoRestart"
    },

    // 3. Malware & System Defense
    {
      id: "core_isolation_hvci",
      cat: "malware",
      catName: "Malware Defense",
      title: "Enable Core Isolation & Memory Integrity (HVCI)",
      desc: "Uses hardware virtualization to isolate critical OS kernel memory processes from malicious driver injection.",
      points: 10,
      cmd: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1"
    },
    {
      id: "tamper_protection",
      cat: "malware",
      catName: "Malware Defense",
      title: "Verify Windows Defender Tamper Protection",
      desc: "Locks real-time antivirus shields so unauthorized background scripts or malware cannot disable them.",
      points: 8,
      cmd: "# Verify in Windows Security -> Virus & threat protection settings -> Tamper Protection: ON"
    },
    {
      id: "pua_protection",
      cat: "malware",
      catName: "Malware Defense",
      title: "Enable Potentially Unwanted App (PUA) Blocking",
      desc: "Blocks bundled adware, crypto miners, and browser hijackers during third-party software installation.",
      points: 6,
      cmd: "Set-MpPreference -PUAProtection 1"
    },
    {
      id: "controlled_folder_access",
      cat: "malware",
      catName: "Malware Defense",
      title: "Enable Controlled Folder Access (Anti-Ransomware)",
      desc: "Restricts untrusted applications from modifying or encrypting documents, photos, and system directories.",
      points: 7,
      cmd: "Set-MpPreference -EnableControlledFolderAccess Enabled"
    },

    // 4. Backup & Disaster Recovery
    {
      id: "vss_shadow_copies",
      cat: "backup",
      catName: "Backup & Recovery",
      title: "Enable Volume Shadow Copy & Restore Points",
      desc: "Guarantees system snapshot restore capability before OS updates or software changes.",
      points: 5,
      cmd: "Enable-ComputerRestore -Drive 'C:\\'; Checkpoint-Computer -Description 'Hardened_Baseline' -RestorePointType 'MODIFY_SETTINGS'"
    },
    {
      id: "encrypted_offsite_backup",
      cat: "backup",
      catName: "Backup & Recovery",
      title: "Establish 3-2-1 Encrypted Backup Strategy",
      desc: "Keep 3 copies of vital data on 2 different media types, with 1 copy encrypted offsite.",
      points: 4,
      cmd: "# Schedule weekly local backup or encrypted sync with Veeam or Duplicati"
    },
    {
      id: "bitlocker_device_encryption",
      cat: "backup",
      catName: "Backup & Recovery",
      title: "Verify Full-Disk Encryption (BitLocker / VeraCrypt)",
      desc: "Encrypt physical SSD/NVMe drives so stolen laptops or unmounted disks cannot be read without authentication.",
      points: 3,
      cmd: "manage-bde -status C:"
    }
  ];

  // Elements
  const checklistEl = document.getElementById('auditChecklist');
  const scoreNumberEl = document.getElementById('scoreNumber');
  const riskBadgeEl = document.getElementById('riskBadge');
  const scoreHintEl = document.getElementById('scoreHint');
  const filterBtns = document.querySelectorAll('.filter-btn');
  const copyRemediationBtn = document.getElementById('copyRemediationBtn');
  const exportReportBtn = document.getElementById('exportReportBtn');

  // Load state from localStorage
  let savedState = JSON.parse(localStorage.getItem('pc_audit_state') || '{}');
  let currentFilter = 'all';

  function renderChecklist() {
    checklistEl.innerHTML = '';
    
    const filtered = CHECKS.filter(c => currentFilter === 'all' || c.cat === currentFilter);

    filtered.forEach(item => {
      const isChecked = !!savedState[item.id];
      const div = document.createElement('div');
      div.className = `check-item ${isChecked ? 'passed' : ''}`;
      div.dataset.id = item.id;
      div.dataset.cat = item.cat;

      div.innerHTML = `
        <div class="check-info">
          <div class="check-header-row">
            <span class="check-cat">${item.catName}</span>
            <h3 class="check-title">${item.title}</h3>
            <span class="check-points">+${item.points} pts</span>
          </div>
          <p class="check-desc">${item.desc}</p>
          <code class="check-cmd">${item.cmd}</code>
        </div>
        <label class="switch">
          <input type="checkbox" ${isChecked ? 'checked' : ''} data-id="${item.id}">
          <span class="slider"></span>
        </label>
      `;
      checklistEl.appendChild(div);
    });
  }

  function updateScore() {
    let currentScore = 0;
    CHECKS.forEach(c => {
      if (savedState[c.id]) {
        currentScore += c.points;
      }
    });

    scoreNumberEl.textContent = currentScore;

    if (currentScore >= 80) {
      riskBadgeEl.textContent = 'HARDENED & SECURE';
      riskBadgeEl.className = 'risk-badge risk-hardened';
      scoreNumberEl.style.color = '#00ff88';
      scoreHintEl.textContent = 'Excellent posture! Your PC exceeds baseline corporate hardening standards.';
    } else if (currentScore >= 45) {
      riskBadgeEl.textContent = 'MODERATE EXPOSURE';
      riskBadgeEl.className = 'risk-badge risk-med';
      scoreNumberEl.style.color = '#ffaa00';
      scoreHintEl.textContent = 'Moderate security. Several high-impact telemetry and network vectors are still open.';
    } else {
      riskBadgeEl.textContent = 'CRITICAL EXPOSURE';
      riskBadgeEl.className = 'risk-badge risk-high';
      scoreNumberEl.style.color = '#ff3366';
      scoreHintEl.textContent = 'Critical exposure. Complete the remaining checks to prevent tracking and exploits.';
    }

    localStorage.setItem('pc_audit_state', JSON.stringify(savedState));
  }

  // Handle toggle switch clicks
  checklistEl.addEventListener('change', (e) => {
    if (e.target.type === 'checkbox') {
      const id = e.target.dataset.id;
      savedState[id] = e.target.checked;
      const card = e.target.closest('.check-item');
      if (card) {
        if (e.target.checked) card.classList.add('passed');
        else card.classList.remove('passed');
      }
      updateScore();
    }
  });

  // Filter Buttons
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFilter = btn.dataset.filter;
      renderChecklist();
    });
  });

  // Copy Remediation Script
  copyRemediationBtn.addEventListener('click', () => {
    const unapplied = CHECKS.filter(c => !savedState[c.id]);
    if (unapplied.length === 0) {
      copyRemediationBtn.textContent = '✓ All Applied!';
      setTimeout(() => copyRemediationBtn.textContent = '📋 Copy Fix Script', 1800);
      return;
    }

    let script = "# PC HARDENING REMEDIATION SCRIPT\n";
    script += "# Run in an elevated PowerShell terminal (Run as Administrator)\n\n";
    unapplied.forEach(c => {
      script += `# Fix: ${c.title} (+${c.points} pts)\n`;
      script += `${c.cmd}\n\n`;
    });

    navigator.clipboard.writeText(script).then(() => {
      copyRemediationBtn.textContent = '✓ Script Copied!';
      setTimeout(() => copyRemediationBtn.textContent = '📋 Copy Fix Script', 1800);
    });
  });

  // Export Audit Report
  exportReportBtn.addEventListener('click', () => {
    let currentScore = 0;
    CHECKS.forEach(c => { if (savedState[c.id]) currentScore += c.points; });

    let report = `# PC HARDENING & PRIVACY AUDIT REPORT\n`;
    report += `Generated: ${new Date().toISOString()}\n`;
    report += `Defense Score: ${currentScore} / 100\n`;
    report += `Status: ${currentScore >= 80 ? 'HARDENED' : (currentScore >= 45 ? 'MODERATE' : 'CRITICAL')}\n\n`;

    report += `## Detailed Assessment Checklist\n`;
    CHECKS.forEach(c => {
      const status = savedState[c.id] ? '[x] PASSED' : '[ ] FAILED / OPEN';
      report += `- ${status} | ${c.catName} | ${c.title} (${c.points} pts)\n`;
      if (!savedState[c.id]) {
        report += `  Remediation: ${c.cmd}\n`;
      }
    });

    const blob = new Blob([report], { type: 'text/markdown;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `PC_Security_Audit_Report_${new Date().toISOString().slice(0, 10)}.md`;
    link.click();
  });

  // Initial render
  renderChecklist();
  updateScore();
})();
