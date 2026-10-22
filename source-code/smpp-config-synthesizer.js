/**
 * SMPPForge Pro - Gateway Rules & Threat Signature Synthesizer (smpp-config-synthesizer.js)
 * 
 * Generates:
 * - Linux nftables stateful firewall rules for SMSC / SMPP gateways (TCP 2775 / 3550)
 * - Suricata / Snort Layer 7 Deep Packet Inspection (DPI) telecom threat signatures
 * - Hardened Linux systemd service unit for high-throughput SMPP daemon
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SMPPConfigSynthesizer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  function generateNftables(options) {
    options = options || {};
    var authorizedIps = options.authorizedIps || "198.51.100.0/24, 203.0.113.50";
    var smppPort = options.smppPort || 2775;
    var smppsPort = options.smppsPort || 3550;
    var maxSynRate = options.maxSynRate || "50/second";

    return [
      "#!/usr/sbin/nft -f",
      "# SMPPForge Pro - Hardened SMSC Gateway Firewall Rules",
      "# Standard: NIST SP 800-82r3 / GSMA FS.19",
      "",
      "table inet smpp_gateway {",
      "  set allowed_aggregators {",
      "    type ipv4_addr",
      "    flags interval",
      "    elements = { " + authorizedIps + " }",
      "  }",
      "",
      "  chain inbound_filter {",
      "    type filter hook input priority filter; policy drop;",
      "",
      "    # Allow established and related connections",
      "    ct state established,related accept",
      "",
      "    # Allow loopback interface",
      "    iif lo accept",
      "",
      "    # Drop invalid TCP state packets",
      "    ct state invalid drop",
      "",
      "    # Mitigate SYN Flood on SMPP Ports",
      "    tcp dport { " + smppPort + ", " + smppsPort + " } tcp flags syn limit rate " + maxSynRate + " burst 100 packets accept",
      "    tcp dport { " + smppPort + ", " + smppsPort + " } tcp flags syn drop",
      "",
      "    # Restrict SMPP access strictly to authorized aggregator IP subnets",
      "    ip saddr @allowed_aggregators tcp dport { " + smppPort + ", " + smppsPort + " } ct state new accept",
      "",
      "    # Log and drop unauthorized bind attempts",
      "    tcp dport { " + smppPort + ", " + smppsPort + " } log prefix \"[SMPP-UNAUTH-BIND]: \" group 0 drop",
      "  }",
      "}"
    ].join("\n");
  }

  function generateSuricata(options) {
    options = options || {};
    var sidBase = options.sidBase || 3001000;

    return [
      "# ====================================================================",
      "# SMPPForge Pro - Suricata Layer 7 Telecom Threat Signatures",
      "# Protocol: SMPP v3.4 / v5.0 (Short Message Peer-to-Peer)",
      "# Ports: TCP 2775 (Plaintext), TCP 3550 (SMPPS / Cleartext Tap)",
      "# ====================================================================",
      "",
      "# 1. Alert on Unauthenticated / Weak Default System ID Bind Attempt",
      'alert tcp any any -> any [2775,3550] (msg:"SMPP-THREAT: Weak Default System ID (admin/test) Bind Attempt"; flow:to_server,established; content:"|00 00 00 02|"; offset:4; depth:4; content:"admin|00|"; nocase; distance:8; classtype:bad-unknown; sid:' + (sidBase + 1) + '; rev:1;)',
      "",
      "# 2. Detect SMPP Throttling Storm (ESME_RTHROTTLED 0x00000058 Spikes)",
      'alert tcp any [2775,3550] -> any any (msg:"SMPP-THREAT: ESME_RTHROTTLED Status Storm (TPS Rate Exceeded)"; flow:to_client,established; content:"|80 00 00 04|"; offset:4; depth:4; content:"|00 00 00 58|"; offset:8; depth:4; threshold:type both, track by_dst, count 50, seconds 5; classtype:attempted-dos; sid:' + (sidBase + 2) + '; rev:1;)',
      "",
      "# 3. Rogue Alphanumeric Sender ID Spoofing (Banking Brand Impersonation)",
      'alert tcp any any -> any [2775,3550] (msg:"SMPP-FRAUD: Rogue Alphanumeric Sender ID Impersonating Bank"; flow:to_server,established; content:"|00 00 00 04|"; offset:4; depth:4; pcre:"/\\x05[\\x00-\\x01](CHASE|BARCLAYS|EMIRATES_NBD|FAB|ADCB)\\x00/i"; classtype:policy-violation; sid:' + (sidBase + 3) + '; rev:1;)',
      "",
      "# 4. High-Risk Smishing URL Pattern in Short Message Payload",
      'alert tcp any any -> any [2775,3550] (msg:"SMPP-FRAUD: Smishing Keyword with Public URL Shortener in Payload"; flow:to_server,established; content:"|00 00 00 04|"; offset:4; depth:4; pcre:"/(urgent|verify|suspended|account|login).*?(bit\\.ly|tinyurl\\.com|t\\.co|is\\.gd)/i"; classtype:successful-recon-largescale; sid:' + (sidBase + 4) + '; rev:1;)',
      "",
      "# 5. Malformed PDU Header Length Overflow Attack (Buffer Overflow Attempt)",
      'alert tcp any any -> any [2775,3550] (msg:"SMPP-ANOMALY: Malformed PDU Command Length Exceeds Safe Buffer"; flow:to_server,established; byte_test:4,>,4096,0,relative; classtype:misc-activity; sid:' + (sidBase + 5) + '; rev:1;)'
    ].join("\n");
  }

  function generateSystemdService(options) {
    options = options || {};
    var binPath = options.binPath || "/opt/smppforge/bin/smpp-gateway";

    return [
      "[Unit]",
      "Description=SMPPForge Pro - High-Throughput Edge SMSC Gateway Daemon",
      "Documentation=https://github.com/smppforge/smppforge-pro",
      "After=network.target network-online.target",
      "Wants=network-online.target",
      "",
      "[Service]",
      "Type=simple",
      "User=smpp",
      "Group=smpp",
      "WorkingDirectory=/opt/smppforge",
      "ExecStart=" + binPath + " --port 3550 --tls --tps 250 --log /var/log/smpp-gateway.log",
      "Restart=always",
      "RestartSec=5s",
      "LimitNOFILE=65536",
      "LimitNPROC=32768",
      "",
      "# Systemd Hardening Sandboxing",
      "ProtectSystem=strict",
      "ProtectHome=true",
      "PrivateTmp=true",
      "PrivateDevices=true",
      "ProtectKernelTunables=true",
      "ProtectControlGroups=true",
      "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
      "AmbientCapabilities=CAP_NET_BIND_SERVICE",
      "NoNewPrivileges=true",
      "",
      "[Install]",
      "WantedBy=multi-user.target"
    ].join("\n");
  }

  return {
    generateNftables: generateNftables,
    generateSuricata: generateSuricata,
    generateSystemdService: generateSystemdService
  };
}));
