# SMPPForge Pro: Technical Architecture & Protocol Specification

## Executive Overview

**SMPPForge Pro** is an enterprise-grade DevSecOps telecommunications protocol engineering workbench, PDU synthesizer, cryptographic validator, and regulatory compliance auditing platform for the Short Message Peer-to-Peer (SMPP v3.4 / v5.0) protocol.

SMPP is the backbone protocol powering global enterprise Application-to-Person (A2P) messaging, Two-Factor Authentication (2FA/OTP) delivery, Communication Platform-as-a-Service (CPaaS) vendors (Twilio, Sinch, Infobip), and Mobile Network Operators (MNOs/MVNOs) across the US, UK, UAE, and international markets.

---

## 1\. Network Topology & SMPP Communication Flow

\+-----------------------------------------------------------------------------------+

|                         Global Telecommunications Messaging                       |

\+-----------------------------------------------------------------------------------+

|  External Short Message Entity (ESME)                 Short Message Service Center |

|  (Fintech / Bank / CPaaS Aggregator)                  (SMSC / Telco Carrier Core)  |

|  \+------------------------+                          \+--------------------------+ |

|  | SMPP Client / Gateway  |   TCP Port 2775 (Plain)  | SMSC Interconnect Gateway| |

|  | \- PDU Serializer       | \<======================\> | \- GSM 03.38 Transcoder   | |

|  | \- GSM 7-bit / UCS2     |   TCP Port 3550 (SMPPS)  | \- SS7 / MAP Core Bridge  | |

|  | \- UDH Splitter Engine  |   Sliding Window Pacing  | \- A2P 10DLC Vetting Hub  | |

|  \+------------------------+                          \+--------------------------+ |

\+-----------------------------------------------------------------------------------+

### Supported Standards

- **SMPP v3.4 / v5.0 (SMS Forum)**: Complete 16-byte header packing, binary PDU streams, and asynchronous session states (`OPEN`, `BOUND_TX`, `BOUND_RX`, `BOUND_TRX`, `UNBOUND`).  
- **3GPP TS 23.038 / GSM 03.38**: 7-bit default alphabet septet packing/unpacking (160 characters compressed into 140 bytes), escape table character translation (`€`, `[`, `]`, `\`, `~`, `^`, `{`, `}`, `|`).  
- **UCS-2 (ISO/IEC 10646 / UTF-16BE)**: 16-bit Big-Endian character representation for Arabic (UAE regulatory mandate), Cyrillic, CJK, and Emojis (70 characters per SMS segment).  
- **User Data Header (UDH) Concatenation (3GPP TS 23.040)**: 8-bit reference (`05 00 03 ref total seq`) and 16-bit reference (`06 08 04 ref total seq`) splitting.  
- **SAR TLVs (Segmentation and Reassembly)**: Tag `0x020C` (`sar_msg_ref_num`), `0x020E` (`sar_total_segments`), `0x020F` (`sar_segment_seqnum`).  
- **Regulatory Frameworks**: US FCC / CTIA A2P 10DLC, UAE TDRA SMS Sender ID Regulations, UK Ofcom SMS Spoofing Code of Practice, and GSMA FS.11 / FS.19 Messaging Security.

---

## 2\. SMPP v3.4 Binary PDU Architecture

Every SMPP PDU consists of a mandatory 16-byte header followed by an optional command body and optional TLV parameters:

\+-----------------------------------------------------------------------------+

|                               SMPP Header (16 Bytes)                        |

\+----------------------+----------------------+-------------------------------+

| command\_length (4B)  |   command\_id (4B)    | command\_status | seq\_num (4B) |

| (uint32 Big-Endian)  | (uint32 Big-Endian)  | (4B, uint32)   | (uint32 BE)  |

\+----------------------+----------------------+----------------+--------------+

|                               SMPP Mandatory Body                           |

| service\_type (C-Str) | source\_addr (TON/NPI)| dest\_addr (TON/NPI)           |

| esm\_class (1B)       | data\_coding (1B)     | sm\_length (1B) | message bytes|

\+-----------------------------------------------------------------------------+

|                               Optional TLV Fields                           |

| Tag (2 Bytes, BE)    | Length (2 Bytes, BE) | Value (Variable Bytes)        |

\+-----------------------------------------------------------------------------+

### Core Commands & Identifiers

1. **`bind_transmitter` (`0x00000002`)**: Binds an ESME to submit outbound messages.  
2. **`bind_receiver` (`0x00000001`)**: Binds an ESME to receive inbound messages and DLRs.  
3. **`bind_transceiver` (`0x00000009`)**: Bidirectional bind combining transmission and reception.  
4. **`submit_sm` (`0x00000004`)**: Dispatches a short message to the SMSC.  
5. **`submit_sm_resp` (`0x80000004`)**: Returns message acknowledgment and SMSC assigned message ID.  
6. **`deliver_sm` (`0x00000005`)**: Forwards inbound mobile-originated SMS or Delivery Receipts (DLR).  
7. **`enquire_link` (`0x00000015`)**: Ping/keep-alive request validating active socket state.  
8. **`unbind` (`0x00000006`)**: Clean termination of the bound session.

---

## 3\. Character Encoding & Concatenation Mathematics

### GSM 03.38 7-Bit Septet Compression

In standard GSM networks, characters are represented as 7-bit integers (septets). To transmit over 8-bit octet channels, septets are packed sequentially:

- First octet holds 7 bits of septet 0 \+ 1 lowest bit of septet 1\.  
- Second octet holds remaining 6 bits of septet 1 \+ 2 lowest bits of septet 2\.  
- Every 7 octets encompass 8 characters (12.5% bandwidth compression).  
- A standard 140-byte SMS payload yields \$\\lfloor rac{140 	imes 8}{7} floor \= 160\$ characters.

### UCS-2 Encoding for Multilingual & Arabic Messaging

For Arabic, Chinese, and Emoji content, `data_coding = 0x08` (UCS-2) is required. Each character occupies 2 full octets (16 bits):

- Maximum characters in single SMS \= \$rac{140}{2} \= 70\$ characters.

### UDH Concatenation Splitting

When message lengths exceed single-segment thresholds, User Data Header (UDH) is injected:

- UDH byte length: 6 bytes (`0x05, 0x00, 0x03, [ref], [total], [part]`).  
- Available payload per GSM 7-bit segment: \$140 \- 6 \= 134\$ bytes \$ ightarrow\$ **153 characters**.  
- Available payload per UCS-2 segment: \$140 \- 6 \= 134\$ bytes \$ ightarrow\$ **67 characters**.

---

## 4\. 10-Point GSMA / 10DLC Cybersecurity Audit Matrix

| ID | Vector | Criticality | Reference | Description |
| :---- | :---- | :---- | :---- | :---- |
| **V1** | Transport Layer Encryption | CRITICAL | GSMA FS.19 | Enforce TLS 1.3 / SMPPS (TCP 3550); reject plaintext TCP 2775\. |
| **V2** | Bind Authentication & Secrets | CRITICAL | CIS Telecom | Prohibit default `system_id` ('admin'/'test') and weak passwords (\<12 chars). |
| **V3** | Alphanumeric Sender ID Protection | HIGH | US 10DLC / UAE TDRA | Require verified pre-registration for TON=5 alphanumeric sender IDs. |
| **V4** | Opt-Out Keyword Gating | HIGH | TCPA / CTIA | Validate mandatory STOP / UNSUBSCRIBE keywords on marketing messages. |
| **V5** | Throughput Pacing & Rate Limiting | HIGH | SMPP v3.4 Sec 5 | Token-bucket pacing to prevent `ESME_RTHROTTLED` (0x58) and buffer drops. |
| **V6** | Character Encoding Hygiene | MEDIUM | 3GPP TS 23.038 | Enforce septet boundary padding and reject truncated UCS-2 payloads. |
| **V7** | UDH Reassembly Exhaustion Defense | HIGH | GSMA Core | Enforce 60s reassembly timer on multi-part concatenation buffers. |
| **V8** | Keep-Alive Heartbeat Supervision | MEDIUM | SMPP v3.4 Sec 2.11 | Supervise `enquire_link` frequency (every 30s) to prevent zombie binds. |
| **V9** | Smishing & Malicious URL Screening | HIGH | M3AAWG | Quarantine generic public URL shorteners (bit.ly/tinyurl) lacking branded subdomains. |
| **V10** | SMSC Gateway Firewall & Isolation | HIGH | NIST SP 800-82 | Restrict ports 2775/3550 to authorized aggregator IP subnets via nftables. |

