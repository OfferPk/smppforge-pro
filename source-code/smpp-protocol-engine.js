/**
 * SMPPForge Pro - Protocol Engine (smpp-protocol-engine.js)
 * 
 * Implements:
 * - SMPP v3.4 / v5.0 Binary PDU Serialization & Dissection
 * - 16-Byte Header: command_length, command_id, command_status, sequence_number
 * - Core PDUs: bind_transmitter, bind_receiver, bind_transceiver, submit_sm,
 *   submit_sm_resp, deliver_sm, deliver_sm_resp, enquire_link, enquire_link_resp, unbind
 * - GSM 03.38 7-Bit Default Alphabet Septet Packing & Unpacking (160 chars / 140 bytes)
 * - UCS-2 (UTF-16BE) Character Encoding for Arabic, Multilingual & Emoji Messaging
 * - Multi-Part SMS Concatenation via User Data Header (UDH 05 00 03 ref total seq) & SAR TLVs
 * - Optional Tag-Length-Value (TLV) Parameter Engine
 * - Wireshark-Compatible Libpcap 2.4 Binary PCAP Exporter (TCP Port 2775)
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.SMPPProtocolEngine = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // --- SMPP Constants ---
  var CMD_ID = {
    GENERIC_NACK: 0x80000000,
    BIND_RECEIVER: 0x00000001,
    BIND_RECEIVER_RESP: 0x80000001,
    BIND_TRANSMITTER: 0x00000002,
    BIND_TRANSMITTER_RESP: 0x80000002,
    QUERY_SM: 0x00000003,
    QUERY_SM_RESP: 0x80000003,
    SUBMIT_SM: 0x00000004,
    SUBMIT_SM_RESP: 0x80000004,
    DELIVER_SM: 0x00000005,
    DELIVER_SM_RESP: 0x80000005,
    UNBIND: 0x00000006,
    UNBIND_RESP: 0x80000006,
    REPLACE_SM: 0x00000007,
    REPLACE_SM_RESP: 0x80000007,
    CANCEL_SM: 0x00000008,
    CANCEL_SM_RESP: 0x80000008,
    BIND_TRANSCEIVER: 0x00000009,
    BIND_TRANSCEIVER_RESP: 0x80000009,
    ENQUIRE_LINK: 0x00000015,
    ENQUIRE_LINK_RESP: 0x80000015,
    SUBMIT_MULTI: 0x00000021,
    SUBMIT_MULTI_RESP: 0x80000021,
    DATA_SM: 0x00000103,
    DATA_SM_RESP: 0x80000103
  };

  var CMD_NAMES = {};
  for (var k in CMD_ID) {
    CMD_NAMES[CMD_ID[k]] = k.toLowerCase();
  }

  var STATUS_CODES = {
    0x00000000: "ESME_ROK (No Error)",
    0x00000001: "ESME_RINVMSGLEN (Message Length Invalid)",
    0x00000002: "ESME_RINVCMDLEN (Command Length Invalid)",
    0x00000003: "ESME_RINVCMDID (Invalid Command ID)",
    0x00000004: "ESME_RINVBNDSTS (Incorrect Bind Status for Command)",
    0x00000005: "ESME_RALYBND (Already in Bound State)",
    0x00000006: "ESME_RINVPRM (Invalid Priority Flag)",
    0x0000000A: "ESME_RINVSRCADR (Invalid Source Address)",
    0x0000000B: "ESME_RINVDSTADR (Invalid Destination Address)",
    0x0000000C: "ESME_RINVMSGID (Invalid Message ID)",
    0x0000000D: "ESME_RBINDFAIL (Bind Failed / Bad Auth)",
    0x0000000E: "ESME_RINVPASWD (Invalid Password)",
    0x0000000F: "ESME_RINVSYSID (Invalid System ID)",
    0x00000045: "ESME_RSUBMITFAIL (Submit SM Failed)",
    0x00000058: "ESME_RTHROTTLED (Throttling Error: Exceeded TPS Limit)"
  };

  var DATA_CODING = {
    DEFAULT: 0x00, // GSM 7-bit default alphabet
    IA5_ASCII: 0x01,
    BINARY_8BIT: 0x04,
    LATIN1_ISO8859_1: 0x03,
    UCS2_UTF16BE: 0x08
  };

  // GSM 03.38 Basic Character Set Table (Unicode -> 7-bit index)
  var GSM_7BIT_CHARS = "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà";
  var GSM_EXT_CHARS = {
    10: 0x0A, // Form Feed \f
    94: 0x14, // ^
    123: 0x28, // {
    125: 0x29, // }
    92: 0x2F, // \
    91: 0x3C, // [
    126: 0x3D, // ~
    93: 0x3E, // ]
    124: 0x40, // |
    8364: 0x65 // €
  };

  // --- GSM 7-Bit Septet Packing Engine ---
  function encodeGSM7(text) {
    var septets = [];
    for (var i = 0; i < text.length; i++) {
      var c = text.charCodeAt(i);
      if (GSM_EXT_CHARS[c] !== undefined) {
        septets.push(0x1B); // Escape byte
        septets.push(GSM_EXT_CHARS[c]);
      } else {
        var idx = GSM_7BIT_CHARS.indexOf(text[i]);
        if (idx >= 0) {
          septets.push(idx);
        } else {
          septets.push(0x3F); // '?' substitution
        }
      }
    }
    return septets;
  }

  function packSeptetsToOctets(septets) {
    var octets = [];
    var cur = 0;
    var curBits = 0;

    for (var i = 0; i < septets.length; i++) {
      var s = septets[i] & 0x7F;
      cur |= (s << curBits);
      curBits += 7;

      if (curBits >= 8) {
        octets.push(cur & 0xFF);
        cur >>= 8;
        curBits -= 8;
      }
    }
    if (curBits > 0) {
      octets.push(cur & 0xFF);
    }
    return new Uint8Array(octets);
  }

  function unpackOctetsToSeptets(octets, septetCount) {
    var septets = [];
    var cur = 0;
    var curBits = 0;
    var byteIdx = 0;

    for (var i = 0; i < septetCount; i++) {
      while (curBits < 7 && byteIdx < octets.length) {
        cur |= (octets[byteIdx++] << curBits);
        curBits += 8;
      }
      septets.push(cur & 0x7F);
      cur >>= 7;
      curBits -= 7;
    }
    return septets;
  }

  function decodeGSM7(septets) {
    var out = "";
    var isExt = false;
    for (var i = 0; i < septets.length; i++) {
      var s = septets[i];
      if (s === 0x1B) {
        isExt = true;
        continue;
      }
      if (isExt) {
        isExt = false;
        var found = false;
        for (var code in GSM_EXT_CHARS) {
          if (GSM_EXT_CHARS[code] === s) {
            out += String.fromCharCode(parseInt(code, 10));
            found = true;
            break;
          }
        }
        if (!found) out += "?";
      } else {
        if (s < GSM_7BIT_CHARS.length) {
          out += GSM_7BIT_CHARS[s];
        } else {
          out += "?";
        }
      }
    }
    return out;
  }

  // --- UCS-2 (UTF-16BE) Encoding ---
  function encodeUCS2(text) {
    var bytes = [];
    for (var i = 0; i < text.length; i++) {
      var code = text.charCodeAt(i);
      bytes.push((code >> 8) & 0xFF);
      bytes.push(code & 0xFF);
    }
    return new Uint8Array(bytes);
  }

  function decodeUCS2(bytes) {
    var out = "";
    for (var i = 0; i < bytes.length; i += 2) {
      if (i + 1 < bytes.length) {
        var code = (bytes[i] << 8) | bytes[i + 1];
        out += String.fromCharCode(code);
      }
    }
    return out;
  }

  // --- Multi-part Concatenation Splitter ---
  function splitMultipartMessage(text, options) {
    options = options || {};
    var refNum = options.refNum !== undefined ? (options.refNum & 0xFF) : Math.floor(Math.random() * 255);
    var forceEncoding = options.forceEncoding || null;

    // Detect if UCS-2 is required (contains non-GSM characters or Arabic/Emojis)
    var isUcs2 = false;
    if (forceEncoding === "ucs2") {
      isUcs2 = true;
    } else if (forceEncoding === "gsm7") {
      isUcs2 = false;
    } else {
      for (var i = 0; i < text.length; i++) {
        var c = text.charCodeAt(i);
        if (GSM_7BIT_CHARS.indexOf(text[i]) === -1 && GSM_EXT_CHARS[c] === undefined) {
          isUcs2 = true;
          break;
        }
      }
    }

    var segments = [];
    if (!isUcs2) {
      // GSM 7-bit: 160 characters in single SMS, 153 characters per part if concatenated (7 chars reserved for 6-byte UDH)
      if (text.length <= 160 && !options.forceMultipart) {
        segments.push({
          part: 1,
          total: 1,
          encoding: "gsm7",
          dataCoding: DATA_CODING.DEFAULT,
          text: text,
          udh: null,
          payloadBytes: packSeptetsToOctets(encodeGSM7(text))
        });
      } else {
        var chunkSize = 153;
        var totalParts = Math.ceil(text.length / chunkSize);
        for (var p = 0; p < totalParts; p++) {
          var partText = text.substr(p * chunkSize, chunkSize);
          // UDH: 05 (length) 00 (IEI Concatenated 8-bit) 03 (IEDL) refNum totalParts partNum
          var udh = new Uint8Array([0x05, 0x00, 0x03, refNum, totalParts, p + 1]);
          var septets = encodeGSM7(partText);
          // In standard SMPP submit_sm, short_message can contain binary UDH prepended to octet-packed or uncompressed septets
          var bodyBytes = new Uint8Array(udh.length + partText.length);
          bodyBytes.set(udh, 0);
          for (var b = 0; b < partText.length; b++) {
            bodyBytes[udh.length + b] = partText.charCodeAt(b) & 0x7F;
          }
          segments.push({
            part: p + 1,
            total: totalParts,
            encoding: "gsm7",
            dataCoding: DATA_CODING.DEFAULT,
            esmClass: 0x40, // UDHI set
            text: partText,
            udh: udh,
            payloadBytes: bodyBytes
          });
        }
      }
    } else {
      // UCS-2: 70 characters in single SMS, 67 characters per part if concatenated
      if (text.length <= 70 && !options.forceMultipart) {
        segments.push({
          part: 1,
          total: 1,
          encoding: "ucs2",
          dataCoding: DATA_CODING.UCS2_UTF16BE,
          text: text,
          udh: null,
          payloadBytes: encodeUCS2(text)
        });
      } else {
        var ucsChunkSize = 67;
        var ucsTotalParts = Math.ceil(text.length / ucsChunkSize);
        for (var up = 0; up < ucsTotalParts; up++) {
          var ucsPartText = text.substr(up * ucsChunkSize, ucsChunkSize);
          var ucsUdh = new Uint8Array([0x05, 0x00, 0x03, refNum, ucsTotalParts, up + 1]);
          var rawUcsBytes = encodeUCS2(ucsPartText);
          var ucsBody = new Uint8Array(ucsUdh.length + rawUcsBytes.length);
          ucsBody.set(ucsUdh, 0);
          ucsBody.set(rawUcsBytes, ucsUdh.length);

          segments.push({
            part: up + 1,
            total: ucsTotalParts,
            encoding: "ucs2",
            dataCoding: DATA_CODING.UCS2_UTF16BE,
            esmClass: 0x40, // UDHI set
            text: ucsPartText,
            udh: ucsUdh,
            payloadBytes: ucsBody
          });
        }
      }
    }

    return segments;
  }

  // --- Helper: Null-terminated C-String buffer pack/unpack ---
  function packCString(str) {
    str = str || "";
    var arr = [];
    for (var i = 0; i < str.length; i++) {
      arr.push(str.charCodeAt(i) & 0xFF);
    }
    arr.push(0x00);
    return new Uint8Array(arr);
  }

  function unpackCString(bytes, offset) {
    var str = "";
    var idx = offset;
    while (idx < bytes.length && bytes[idx] !== 0x00) {
      str += String.fromCharCode(bytes[idx]);
      idx++;
    }
    return { string: str, nextOffset: idx + 1 };
  }

  // --- PDU Frame Packer ---
  function packPDU(cmdId, seqNum, status, bodyBytes) {
    bodyBytes = bodyBytes || new Uint8Array(0);
    var totalLen = 16 + bodyBytes.length;
    var pdu = new Uint8Array(totalLen);
    var view = new DataView(pdu.buffer);

    view.setUint32(0, totalLen, false); // Big Endian
    view.setUint32(4, cmdId, false);
    view.setUint32(8, status || 0, false);
    view.setUint32(12, seqNum || 1, false);

    pdu.set(bodyBytes, 16);
    return pdu;
  }

  // --- High-Level PDU Builders ---
  function buildBindTransmitter(params) {
    params = params || {};
    var systemId = packCString(params.systemId || "SMPP_CLIENT");
    var password = packCString(params.password || "password123");
    var systemType = packCString(params.systemType || "");
    var ifVersion = new Uint8Array([params.interfaceVersion || 0x34]); // v3.4
    var addrTon = new Uint8Array([params.addrTon !== undefined ? params.addrTon : 0x00]);
    var addrNpi = new Uint8Array([params.addrNpi !== undefined ? params.addrNpi : 0x00]);
    var addressRange = packCString(params.addressRange || "");

    var bodyLen = systemId.length + password.length + systemType.length + 3 + addressRange.length;
    var body = new Uint8Array(bodyLen);
    var offset = 0;

    body.set(systemId, offset); offset += systemId.length;
    body.set(password, offset); offset += password.length;
    body.set(systemType, offset); offset += systemType.length;
    body.set(ifVersion, offset); offset += 1;
    body.set(addrTon, offset); offset += 1;
    body.set(addrNpi, offset); offset += 1;
    body.set(addressRange, offset);

    return packPDU(CMD_ID.BIND_TRANSMITTER, params.seqNum || 1, 0, body);
  }

  function buildBindTransceiver(params) {
    params = params || {};
    var pdu = buildBindTransmitter(params);
    // Replace command ID with BIND_TRANSCEIVER
    var view = new DataView(pdu.buffer);
    view.setUint32(4, CMD_ID.BIND_TRANSCEIVER, false);
    return pdu;
  }

  function buildSubmitSM(params) {
    params = params || {};
    var serviceType = packCString(params.serviceType || "");
    var srcTon = params.srcTon !== undefined ? params.srcTon : 0x01; // International
    var srcNpi = params.srcNpi !== undefined ? params.srcNpi : 0x01; // ISDN
    var srcAddr = packCString(params.srcAddr || "14155550100");

    var dstTon = params.dstTon !== undefined ? params.dstTon : 0x01; // International
    var dstNpi = params.dstNpi !== undefined ? params.dstNpi : 0x01; // ISDN
    var dstAddr = packCString(params.dstAddr || "971501234567");

    var esmClass = params.esmClass !== undefined ? params.esmClass : 0x00;
    var protocolId = params.protocolId !== undefined ? params.protocolId : 0x00;
    var priority = params.priority !== undefined ? params.priority : 0x00;
    var schedDelivery = packCString(params.scheduleDeliveryTime || "");
    var validityPeriod = packCString(params.validityPeriod || "");
    var regDelivery = params.registeredDelivery !== undefined ? params.registeredDelivery : 0x01; // Request receipt
    var replaceIfPresent = params.replaceIfPresent !== undefined ? params.replaceIfPresent : 0x00;
    var dataCoding = params.dataCoding !== undefined ? params.dataCoding : DATA_CODING.DEFAULT;
    var smDefMsgId = params.smDefaultMsgId !== undefined ? params.smDefaultMsgId : 0x00;

    // Payload processing
    var shortMessage = params.shortMessage;
    if (typeof shortMessage === "string") {
      if (dataCoding === DATA_CODING.UCS2_UTF16BE) {
        shortMessage = encodeUCS2(shortMessage);
      } else {
        shortMessage = packCString(shortMessage).subarray(0, -1); // Raw bytes
      }
    } else if (!shortMessage) {
      shortMessage = new Uint8Array(0);
    }

    var smLength = Math.min(shortMessage.length, 255);

    // Optional TLVs
    var tlvBytes = params.tlvBytes || new Uint8Array(0);

    var bodyLen = serviceType.length + 2 + srcAddr.length + 2 + dstAddr.length + 3 +
                  schedDelivery.length + validityPeriod.length + 4 + 1 + smLength + tlvBytes.length;
    var body = new Uint8Array(bodyLen);
    var off = 0;

    body.set(serviceType, off); off += serviceType.length;
    body[off++] = srcTon;
    body[off++] = srcNpi;
    body.set(srcAddr, off); off += srcAddr.length;

    body[off++] = dstTon;
    body[off++] = dstNpi;
    body.set(dstAddr, off); off += dstAddr.length;

    body[off++] = esmClass;
    body[off++] = protocolId;
    body[off++] = priority;
    body.set(schedDelivery, off); off += schedDelivery.length;
    body.set(validityPeriod, off); off += validityPeriod.length;
    body[off++] = regDelivery;
    body[off++] = replaceIfPresent;
    body[off++] = dataCoding;
    body[off++] = smDefMsgId;
    body[off++] = smLength;
    body.set(shortMessage.subarray(0, smLength), off); off += smLength;

    if (tlvBytes.length > 0) {
      body.set(tlvBytes, off);
    }

    return packPDU(CMD_ID.SUBMIT_SM, params.seqNum || 1, 0, body);
  }

  function buildSubmitSMResp(params) {
    params = params || {};
    var msgId = packCString(params.messageId || "MSG_987654321");
    return packPDU(CMD_ID.SUBMIT_SM_RESP, params.seqNum || 1, params.status || 0, msgId);
  }

  function buildEnquireLink(seqNum) {
    return packPDU(CMD_ID.ENQUIRE_LINK, seqNum || 1, 0, new Uint8Array(0));
  }

  function buildEnquireLinkResp(seqNum) {
    return packPDU(CMD_ID.ENQUIRE_LINK_RESP, seqNum || 1, 0, new Uint8Array(0));
  }

  function buildUnbind(seqNum) {
    return packPDU(CMD_ID.UNBIND, seqNum || 1, 0, new Uint8Array(0));
  }

  function buildUnbindResp(seqNum, status) {
    return packPDU(CMD_ID.UNBIND_RESP, seqNum || 1, status || 0, new Uint8Array(0));
  }

  // --- PDU Dissector & Parser ---
  function dissectPDU(bytes) {
    if (typeof bytes === "string") {
      var clean = bytes.replace(/[\s:,\-]/g, "");
      var arr = [];
      for (var i = 0; i < clean.length; i += 2) {
        arr.push(parseInt(clean.substr(i, 2), 16));
      }
      bytes = new Uint8Array(arr);
    }

    if (bytes.length < 16) {
      return { valid: false, error: "PDU too short (min 16 bytes for SMPP header)" };
    }

    var view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    var commandLength = view.getUint32(0, false);
    var commandId = view.getUint32(4, false);
    var commandStatus = view.getUint32(8, false);
    var sequenceNumber = view.getUint32(12, false);

    var result = {
      valid: true,
      commandLength: commandLength,
      commandId: "0x" + commandId.toString(16).toUpperCase().padStart(8, "0"),
      commandName: CMD_NAMES[commandId] || "unknown_command",
      commandStatus: "0x" + commandStatus.toString(16).toUpperCase().padStart(8, "0"),
      statusDescription: STATUS_CODES[commandStatus] || "Unknown Status",
      sequenceNumber: sequenceNumber,
      declaredLengthMatch: commandLength === bytes.length,
      body: {}
    };

    var off = 16;
    if (commandId === CMD_ID.SUBMIT_SM || commandId === CMD_ID.DELIVER_SM) {
      var sType = unpackCString(bytes, off);
      result.body.serviceType = sType.string;
      off = sType.nextOffset;

      result.body.sourceAddrTon = bytes[off++];
      result.body.sourceAddrNpi = bytes[off++];
      var sAddr = unpackCString(bytes, off);
      result.body.sourceAddr = sAddr.string;
      off = sAddr.nextOffset;

      result.body.destAddrTon = bytes[off++];
      result.body.destAddrNpi = bytes[off++];
      var dAddr = unpackCString(bytes, off);
      result.body.destAddr = dAddr.string;
      off = dAddr.nextOffset;

      result.body.esmClass = bytes[off++];
      result.body.protocolId = bytes[off++];
      result.body.priority = bytes[off++];

      var schedDel = unpackCString(bytes, off);
      result.body.scheduleDeliveryTime = schedDel.string;
      off = schedDel.nextOffset;

      var valPer = unpackCString(bytes, off);
      result.body.validityPeriod = valPer.string;
      off = valPer.nextOffset;

      result.body.registeredDelivery = bytes[off++];
      result.body.replaceIfPresent = bytes[off++];
      result.body.dataCoding = bytes[off++];
      result.body.smDefaultMsgId = bytes[off++];

      var smLen = bytes[off++];
      result.body.smLength = smLen;

      var smBytes = bytes.subarray(off, off + smLen);
      result.body.rawShortMessage = Array.from(smBytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("").toUpperCase();
      off += smLen;

      // Decode Message Content
      var isUdhi = (result.body.esmClass & 0x40) !== 0;
      result.body.isUdhi = isUdhi;
      var textBytes = smBytes;
      if (isUdhi && smBytes.length >= 6) {
        var udhLen = smBytes[0];
        result.body.udh = {
          length: udhLen,
          iei: smBytes[1],
          iedl: smBytes[2],
          refNum: smBytes[3],
          totalParts: smBytes[4],
          partNum: smBytes[5]
        };
        textBytes = smBytes.subarray(udhLen + 1);
      }

      if (result.body.dataCoding === DATA_CODING.UCS2_UTF16BE) {
        result.body.decodedMessage = decodeUCS2(textBytes);
      } else {
        var ascii = "";
        for (var t = 0; t < textBytes.length; t++) {
          ascii += String.fromCharCode(textBytes[t]);
        }
        result.body.decodedMessage = ascii;
      }

      // Check for Optional TLVs
      result.body.tlvs = [];
      while (off + 4 <= bytes.length) {
        var tag = view.getUint16(off, false);
        var tLen = view.getUint16(off + 2, false);
        off += 4;
        if (off + tLen <= bytes.length) {
          var valBytes = bytes.subarray(off, off + tLen);
          result.body.tlvs.push({
            tag: "0x" + tag.toString(16).toUpperCase().padStart(4, "0"),
            length: tLen,
            valueHex: Array.from(valBytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("").toUpperCase()
          });
          off += tLen;
        } else {
          break;
        }
      }
    } else if (commandId === CMD_ID.SUBMIT_SM_RESP || commandId === CMD_ID.DELIVER_SM_RESP) {
      if (off < bytes.length) {
        var mId = unpackCString(bytes, off);
        result.body.messageId = mId.string;
      }
    } else if (commandId === CMD_ID.BIND_TRANSMITTER || commandId === CMD_ID.BIND_RECEIVER || commandId === CMD_ID.BIND_TRANSCEIVER) {
      var bSysId = unpackCString(bytes, off);
      result.body.systemId = bSysId.string;
      off = bSysId.nextOffset;
      var bPass = unpackCString(bytes, off);
      result.body.password = "******";
      off = bPass.nextOffset;
      var bSysType = unpackCString(bytes, off);
      result.body.systemType = bSysType.string;
      off = bSysType.nextOffset;
      if (off < bytes.length) {
        result.body.interfaceVersion = "0x" + bytes[off++].toString(16).padStart(2, "0");
      }
    }

    return result;
  }

  // --- Libpcap 2.4 Binary Generator (TCP Port 2775) ---
  function exportLibpcap(pduPackets, options) {
    options = options || {};
    var srcIp = options.srcIp || [192, 168, 1, 100];
    var dstIp = options.dstIp || [10, 0, 0, 50]; // SMSC Gateway
    var clientPort = options.clientPort || 54321;
    var smscPort = 2775; // Standard SMPP Port

    var pcapRecords = [];
    var totalLen = 24; // Libpcap Global Header

    // Libpcap Global Header (24 Bytes)
    var globalHeader = new Uint8Array(24);
    var gView = new DataView(globalHeader.buffer);
    gView.setUint32(0, 0xa1b2c3d4, false); // Magic number (Big Endian)
    gView.setUint16(4, 2, false);          // Version Major 2
    gView.setUint16(6, 4, false);          // Version Minor 4
    gView.setInt32(8, 0, false);           // Timezone GMT
    gView.setUint32(12, 0, false);         // Sigfigs
    gView.setUint32(16, 65535, false);     // Snaplen
    gView.setUint32(20, 1, false);         // Linktype: Ethernet (1)

    var baseTime = Math.floor(Date.now() / 1000) - 30;

    for (var i = 0; i < pduPackets.length; i++) {
      var pdu = pduPackets[i];
      var isClientToSmsc = (i % 2 === 0);
      var sPort = isClientToSmsc ? clientPort : smscPort;
      var dPort = isClientToSmsc ? smscPort : clientPort;
      var sIp = isClientToSmsc ? srcIp : dstIp;
      var dIp = isClientToSmsc ? dstIp : srcIp;

      // Ethernet Header (14 Bytes)
      var eth = new Uint8Array(14);
      eth.set([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E], 0); // Dest MAC
      eth.set([0x52, 0x54, 0x00, 0x12, 0x34, 0x56], 6); // Src MAC
      eth[12] = 0x08; eth[13] = 0x00;                   // IPv4 (0x0800)

      // IPv4 Header (20 Bytes)
      var ipTotalLen = 20 + 20 + pdu.length;
      var ip = new Uint8Array(20);
      var ipView = new DataView(ip.buffer);
      ip[0] = 0x45; // Version 4, IHL 5
      ip[1] = 0x00; // DSCP
      ipView.setUint16(2, ipTotalLen, false);
      ipView.setUint16(4, 1000 + i, false); // Ident
      ipView.setUint16(6, 0x4000, false);   // Don't Fragment
      ip[8] = 64;   // TTL
      ip[9] = 6;    // TCP protocol
      ip.set(sIp, 12);
      ip.set(dIp, 16);

      // IP Checksum
      var ipCks = 0;
      for (var c = 0; c < 20; c += 2) {
        if (c !== 10) ipCks += ipView.getUint16(c, false);
      }
      while (ipCks > 0xFFFF) ipCks = (ipCks & 0xFFFF) + (ipCks >> 16);
      ipView.setUint16(10, (~ipCks) & 0xFFFF, false);

      // TCP Header (20 Bytes)
      var tcp = new Uint8Array(20);
      var tcpView = new DataView(tcp.buffer);
      tcpView.setUint16(0, sPort, false);
      tcpView.setUint16(2, dPort, false);
      tcpView.setUint32(4, 100000 + (i * 500), false); // Seq
      tcpView.setUint32(8, 200000 + (i * 500), false); // Ack
      tcp[12] = 0x50; // Data offset 5 (20 bytes)
      tcp[13] = 0x18; // PSH, ACK
      tcpView.setUint16(14, 64240, false); // Window
      tcpView.setUint16(16, 0, false);     // Checksum (placeholder)
      tcpView.setUint16(18, 0, false);     // Urgent ptr

      var frameLen = eth.length + ip.length + tcp.length + pdu.length;

      // Packet Record Header (16 Bytes)
      var recHeader = new Uint8Array(16);
      var rView = new DataView(recHeader.buffer);
      rView.setUint32(0, baseTime + i, false); // ts_sec
      rView.setUint32(4, i * 150000, false);   // ts_usec
      rView.setUint32(8, frameLen, false);     // incl_len
      rView.setUint32(12, frameLen, false);    // orig_len

      var packetData = new Uint8Array(16 + frameLen);
      packetData.set(recHeader, 0);
      packetData.set(eth, 16);
      packetData.set(ip, 30);
      packetData.set(tcp, 50);
      packetData.set(pdu, 70);

      pcapRecords.push(packetData);
      totalLen += packetData.length;
    }

    var finalPcap = new Uint8Array(totalLen);
    finalPcap.set(globalHeader, 0);
    var pOffset = 24;
    for (var r = 0; r < pcapRecords.length; r++) {
      finalPcap.set(pcapRecords[r], pOffset);
      pOffset += pcapRecords[r].length;
    }
    return finalPcap;
  }

  return {
    CMD_ID: CMD_ID,
    CMD_NAMES: CMD_NAMES,
    STATUS_CODES: STATUS_CODES,
    DATA_CODING: DATA_CODING,
    encodeGSM7: encodeGSM7,
    packSeptetsToOctets: packSeptetsToOctets,
    unpackOctetsToSeptets: unpackOctetsToSeptets,
    decodeGSM7: decodeGSM7,
    encodeUCS2: encodeUCS2,
    decodeUCS2: decodeUCS2,
    splitMultipartMessage: splitMultipartMessage,
    packPDU: packPDU,
    buildBindTransmitter: buildBindTransmitter,
    buildBindTransceiver: buildBindTransceiver,
    buildSubmitSM: buildSubmitSM,
    buildSubmitSMResp: buildSubmitSMResp,
    buildEnquireLink: buildEnquireLink,
    buildEnquireLinkResp: buildEnquireLinkResp,
    buildUnbind: buildUnbind,
    buildUnbindResp: buildUnbindResp,
    dissectPDU: dissectPDU,
    exportLibpcap: exportLibpcap
  };
}));
