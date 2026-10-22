# SMPPForge Pro: Comprehensive Operations Manual & CLI Reference

## 1\. Quick Start

### Web Studio (Zero-Dependency Single-Page App)

Open `source-code/index.html` in any web browser. Runs 100% locally with zero external network requests or server dependencies.

### Standalone Python CLI (`smppforge-cli.py`)

Ensure Python 3.8+ is installed.

\# Make executable

chmod \+x build/smppforge-cli.py

\# Display global options

python3 build/smppforge-cli.py \--help

---

## 2\. CLI Command Inventory

### `build-packet` — Synthesize SMPP v3.4 Binary PDU

\# Build an outbound OTP submit\_sm PDU

python3 build/smppforge-cli.py build-packet \--cmd submit\_sm \--src ALERT\_OTP \--src-ton 5 \--dst 971501234567 \--msg "Your code is 849201\. Reply STOP to opt out."

\# Build an Arabic UCS-2 submit\_sm PDU

python3 build/smppforge-cli.py build-packet \--cmd submit\_sm \--src DUBAI\_POLICE \--dst 971501234567 \--msg "شرطة دبي: تم تجديد التصريح بنجاح" \--ucs2

\# Build a bind\_transceiver PDU

python3 build/smppforge-cli.py build-packet \--cmd bind\_transceiver \--seq 1

### `dissect` — Dissect Raw Hex PDU Stream

python3 build/smppforge-cli.py dissect \--hex "00000045000000040000000000000001000501414C4552545F4F5450000101393731353031323334353637000000000000010000000F54657374204F545020313233343536"

### `encode-gsm7` — GSM 03.38 7-Bit Septet Packer

python3 build/smppforge-cli.py encode-gsm7 \--text "Hello World"

### `split-sms` — Concatenated SMS Multi-Part Splitter

python3 build/smppforge-cli.py split-sms \--text "Long message exceeding 160 characters..." \--ref 42

### `audit` — 10-Point Telecom Cybersecurity Compliance Auditor

\# Run baseline audit

python3 build/smppforge-cli.py audit

\# Run strict CI/CD pipeline gate (exit code 1 on non-compliance)

python3 build/smppforge-cli.py audit \--strict \--profile site\_profile.json

### `export-pcap` — Wireshark Libpcap 2.4 Generator

python3 build/smppforge-cli.py export-pcap \--out smpp-traffic.pcap

### `synth-config` — Firewall Rules & Suricata Signatures

\# Generate Linux nftables rules

python3 build/smppforge-cli.py synth-config \--type nftables

\# Generate Suricata Layer 7 telecom DPI signatures

python3 build/smppforge-cli.py synth-config \--type suricata

\# Generate hardened systemd service

python3 build/smppforge-cli.py synth-config \--type systemd