/**
 * SMPPForge Pro - Application Controller (app.js)
 */

document.addEventListener("DOMContentLoaded", function () {
  'use strict';

  // --- Tab Navigation ---
  var tabButtons = document.querySelectorAll(".tab-btn");
  var tabPanes = document.querySelectorAll(".tab-pane");

  tabButtons.forEach(function (btn) {
    btn.addEventListener("click", function () {
      tabButtons.forEach(function (b) { b.classList.remove("active"); });
      tabPanes.forEach(function (p) { p.classList.remove("active"); });

      btn.classList.add("active");
      var targetId = btn.getAttribute("data-tab");
      var targetPane = document.getElementById(targetId);
      if (targetPane) targetPane.classList.add("active");
    });
  });

  // --- Elements: Tab 1 Builder ---
  var cmdTypeSelect = document.getElementById("pdu-cmd-type");
  var submitFields = document.getElementById("submit-sm-fields");
  var bindFields = document.getElementById("bind-fields");
  var srcAddrInput = document.getElementById("src-addr");
  var srcTonSelect = document.getElementById("src-ton");
  var dstAddrInput = document.getElementById("dst-addr");
  var dstTonSelect = document.getElementById("dst-ton");
  var dataCodingSelect = document.getElementById("data-coding");
  var regDeliverySelect = document.getElementById("reg-delivery");
  var shortMsgInput = document.getElementById("short-message");
  var seqInput = document.getElementById("pdu-seq");

  var btnSynthesize = document.getElementById("btn-synthesize");
  var btnExportPcap = document.getElementById("btn-export-pcap");
  var btnLoadOtp = document.getElementById("btn-load-otp");
  var btnLoadArabic = document.getElementById("btn-load-arabic");

  var hexOutput = document.getElementById("pdu-hex-output");
  var byteBadge = document.getElementById("pdu-byte-badge");
  var sumLen = document.getElementById("sum-len");
  var sumId = document.getElementById("sum-id");
  var sumStatus = document.getElementById("sum-status");
  var sumSeq = document.getElementById("sum-seq");
  var sumSrc = document.getElementById("sum-src");
  var sumDst = document.getElementById("sum-dst");
  var sumEnc = document.getElementById("sum-enc");

  cmdTypeSelect.addEventListener("change", function () {
    var val = cmdTypeSelect.value;
    if (val === "submit_sm") {
      submitFields.style.display = "block";
      bindFields.style.display = "none";
    } else if (val.indexOf("bind_") !== -1) {
      submitFields.style.display = "none";
      bindFields.style.display = "block";
    } else {
      submitFields.style.display = "none";
      bindFields.style.display = "none";
    }
    updateSynthesizedPDU();
  });

  function formatHex(uint8arr) {
    var parts = [];
    for (var i = 0; i < uint8arr.length; i++) {
      parts.push(uint8arr[i].toString(16).padStart(2, "0").toUpperCase());
    }
    return parts.join(" ");
  }

  var currentPduBytes = null;

  function updateSynthesizedPDU() {
    var cmd = cmdTypeSelect.value;
    var seq = parseInt(seqInput.value, 10) || 1;
    var pdu;

    if (cmd === "submit_sm") {
      pdu = SMPPProtocolEngine.buildSubmitSM({
        seqNum: seq,
        srcAddr: srcAddrInput.value,
        srcTon: parseInt(srcTonSelect.value, 10),
        dstAddr: dstAddrInput.value,
        dstTon: parseInt(dstTonSelect.value, 10),
        dataCoding: parseInt(dataCodingSelect.value, 10),
        registeredDelivery: parseInt(regDeliverySelect.value, 10),
        shortMessage: shortMsgInput.value
      });
    } else if (cmd === "bind_transceiver") {
      pdu = SMPPProtocolEngine.buildBindTransceiver({
        seqNum: seq,
        systemId: document.getElementById("bind-sys-id").value,
        password: document.getElementById("bind-password").value,
        systemType: document.getElementById("bind-sys-type").value
      });
    } else if (cmd === "bind_transmitter") {
      pdu = SMPPProtocolEngine.buildBindTransmitter({
        seqNum: seq,
        systemId: document.getElementById("bind-sys-id").value,
        password: document.getElementById("bind-password").value,
        systemType: document.getElementById("bind-sys-type").value
      });
    } else if (cmd === "enquire_link") {
      pdu = SMPPProtocolEngine.buildEnquireLink(seq);
    } else if (cmd === "unbind") {
      pdu = SMPPProtocolEngine.buildUnbind(seq);
    }

    currentPduBytes = pdu;
    hexOutput.textContent = formatHex(pdu);
    byteBadge.textContent = pdu.length + " Bytes";

    // Dissect summary
    var dissected = SMPPProtocolEngine.dissectPDU(pdu);
    if (dissected.valid) {
      sumLen.textContent = dissected.commandLength + " Bytes";
      sumId.textContent = dissected.commandId + " (" + dissected.commandName + ")";
      sumStatus.textContent = dissected.commandStatus + " (" + dissected.statusDescription + ")";
      sumSeq.textContent = dissected.sequenceNumber;
      if (cmd === "submit_sm") {
        sumSrc.textContent = (dissected.body.sourceAddr || "-") + " (TON " + dissected.body.sourceAddrTon + ")";
        sumDst.textContent = (dissected.body.destAddr || "-") + " (TON " + dissected.body.destAddrTon + ")";
        sumEnc.textContent = dissected.body.dataCoding === 8 ? "UCS-2 (UTF-16BE)" : "GSM 7-Bit Default";
      } else {
        sumSrc.textContent = "-";
        sumDst.textContent = "-";
        sumEnc.textContent = "-";
      }
    }
  }

  btnSynthesize.addEventListener("click", updateSynthesizedPDU);

  btnLoadOtp.addEventListener("click", function () {
    cmdTypeSelect.value = "submit_sm";
    submitFields.style.display = "block";
    bindFields.style.display = "none";
    srcAddrInput.value = "CHASE_ALERT";
    srcTonSelect.value = "5"; // Alphanumeric
    dstAddrInput.value = "14155550199";
    dstTonSelect.value = "1";
    dataCodingSelect.value = "0";
    shortMsgInput.value = "Chase Alert: $249.50 approved at Apple Store. If not you, reply NO. To stop texts reply STOP.";
    updateSynthesizedPDU();
  });

  btnLoadArabic.addEventListener("click", function () {
    cmdTypeSelect.value = "submit_sm";
    submitFields.style.display = "block";
    bindFields.style.display = "none";
    srcAddrInput.value = "DUBAI_POLICE";
    srcTonSelect.value = "5";
    dstAddrInput.value = "971501234567";
    dstTonSelect.value = "1";
    dataCodingSelect.value = "8"; // UCS2
    shortMsgInput.value = "شرطة دبي: تم تجديد تصريح المرور بنجاح. شكرا لتعاونكم.";
    updateSynthesizedPDU();
  });

  btnExportPcap.addEventListener("click", function () {
    if (!currentPduBytes) updateSynthesizedPDU();
    var pcapBytes = SMPPProtocolEngine.exportLibpcap([currentPduBytes]);
    var blob = new Blob([pcapBytes], { type: "application/vnd.tcpdump.pcap" });
    var url = URL.createObjectURL(blob);
    var a = document.createElement("a");
    a.href = url;
    a.download = "smpp-pdu-trace.pcap";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // --- TAB 2: Dissector ---
  var rawHexInput = document.getElementById("raw-hex-input");
  var btnDissect = document.getElementById("btn-dissect-hex");
  var dissectTree = document.getElementById("dissector-result-tree");
  var btnSampleSubmit = document.getElementById("btn-load-sample-submit");
  var btnSampleDlr = document.getElementById("btn-load-sample-dlr");

  function renderDissection(d) {
    if (!d.valid) {
      dissectTree.innerHTML = '<div style="color:var(--accent-rose); font-weight:bold;">Error: ' + d.error + '</div>';
      return;
    }
    var html = '';
    html += '<div class="dissect-row"><span class="dissect-key">PDU Length:</span><span class="dissect-val">' + d.commandLength + ' Bytes (' + (d.declaredLengthMatch ? 'Matches Wire' : 'MISMATCH') + ')</span></div>';
    html += '<div class="dissect-row"><span class="dissect-key">Command:</span><span class="dissect-val highlight">' + d.commandName + ' (' + d.commandId + ')</span></div>';
    html += '<div class="dissect-row"><span class="dissect-key">Command Status:</span><span class="dissect-val">' + d.statusDescription + ' (' + d.commandStatus + ')</span></div>';
    html += '<div class="dissect-row"><span class="dissect-key">Sequence Number:</span><span class="dissect-val">' + d.sequenceNumber + '</span></div>';

    if (d.body.sourceAddr !== undefined) {
      html += '<div class="dissect-row"><span class="dissect-key">Source Address:</span><span class="dissect-val">' + (d.body.sourceAddr || '[Empty]') + ' (TON=' + d.body.sourceAddrTon + ', NPI=' + d.body.sourceAddrNpi + ')</span></div>';
      html += '<div class="dissect-row"><span class="dissect-key">Dest Address:</span><span class="dissect-val">' + (d.body.destAddr || '[Empty]') + ' (TON=' + d.body.destAddrTon + ', NPI=' + d.body.destAddrNpi + ')</span></div>';
      html += '<div class="dissect-row"><span class="dissect-key">Data Coding:</span><span class="dissect-val">0x' + d.body.dataCoding.toString(16).padStart(2, '0') + ' (' + (d.body.dataCoding === 8 ? 'UCS-2' : 'GSM 7-bit') + ')</span></div>';
      html += '<div class="dissect-row"><span class="dissect-key">ESM Class:</span><span class="dissect-val">0x' + d.body.esmClass.toString(16).padStart(2, '0') + ' ' + (d.body.isUdhi ? '[UDHI Active]' : '') + '</span></div>';
      html += '<div class="dissect-row"><span class="dissect-key">Payload Length:</span><span class="dissect-val">' + d.body.smLength + ' Bytes</span></div>';
      if (d.body.udh) {
        html += '<div class="dissect-row"><span class="dissect-key">UDH Concatenation:</span><span class="dissect-val" style="color:var(--accent-amber);">Part ' + d.body.udh.partNum + ' of ' + d.body.udh.totalParts + ' (Ref ' + d.body.udh.refNum + ')</span></div>';
      }
      html += '<div class="dissect-row"><span class="dissect-key">Decoded Message:</span><span class="dissect-val" style="color:var(--accent-cyan); word-break:break-word;">' + (d.body.decodedMessage || '') + '</span></div>';
    } else if (d.body.messageId !== undefined) {
      html += '<div class="dissect-row"><span class="dissect-key">Assigned Message ID:</span><span class="dissect-val highlight">' + d.body.messageId + '</span></div>';
    } else if (d.body.systemId !== undefined) {
      html += '<div class="dissect-row"><span class="dissect-key">Client System ID:</span><span class="dissect-val highlight">' + d.body.systemId + '</span></div>';
    }

    if (d.body.tlvs && d.body.tlvs.length > 0) {
      html += '<div style="margin-top:0.5rem; font-weight:bold; color:var(--accent-purple);">Optional TLVs (' + d.body.tlvs.length + '):</div>';
      d.body.tlvs.forEach(function (t) {
        html += '<div class="dissect-row"><span class="dissect-key">Tag ' + t.tag + ':</span><span class="dissect-val">' + t.length + ' Bytes (Hex: ' + t.valueHex + ')</span></div>';
      });
    }

    dissectTree.innerHTML = html;
  }

  btnDissect.addEventListener("click", function () {
    var raw = rawHexInput.value.trim();
    if (!raw) return;
    var d = SMPPProtocolEngine.dissectPDU(raw);
    renderDissection(d);
  });

  btnSampleSubmit.addEventListener("click", function () {
    var sample = SMPPProtocolEngine.buildSubmitSM({
      seqNum: 42,
      srcAddr: "VERIFY_AUTH",
      srcTon: 5,
      dstAddr: "447700900123",
      shortMessage: "Your single-use passcode is 912834. Reply STOP to cancel."
    });
    rawHexInput.value = formatHex(sample);
    btnDissect.click();
  });

  btnSampleDlr.addEventListener("click", function () {
    var sample = SMPPProtocolEngine.buildSubmitSMResp({
      seqNum: 42,
      status: 0,
      messageId: "SMSC_REF_9918231"
    });
    rawHexInput.value = formatHex(sample);
    btnDissect.click();
  });

  // --- TAB 3: GSM 7-bit vs UCS-2 Encoder ---
  var encTextInput = document.getElementById("enc-text-input");
  var encCharCount = document.getElementById("enc-char-count");
  var encRec = document.getElementById("enc-rec");
  var encOctetsHex = document.getElementById("enc-octets-hex");
  var telStd = document.getElementById("tel-std");
  var telBytes = document.getElementById("tel-bytes");
  var telEff = document.getElementById("tel-eff");
  var telExt = document.getElementById("tel-ext");

  function analyzeEncoding() {
    var text = encTextInput.value;
    encCharCount.value = text.length;

    var segments = SMPPProtocolEngine.splitMultipartMessage(text);
    if (segments.length > 0) {
      var s = segments[0];
      if (s.encoding === "gsm7") {
        encRec.value = "GSM 7-Bit (" + segments.length + " SMS part" + (segments.length > 1 ? "s" : "") + ")";
        telStd.textContent = "GSM 03.38 (7-Bit Septets)";
        telEff.textContent = "12.5% Compression Active";
      } else {
        encRec.value = "UCS-2 (" + segments.length + " SMS part" + (segments.length > 1 ? "s" : "") + ")";
        telStd.textContent = "UCS-2 (UTF-16BE Multilingual)";
        telEff.textContent = "No Compression (16 bits/char)";
      }
      telBytes.textContent = s.payloadBytes.length + " Bytes";
      encOctetsHex.textContent = formatHex(s.payloadBytes);
    }
  }

  document.getElementById("btn-calc-encoding").addEventListener("click", analyzeEncoding);
  encTextInput.addEventListener("input", analyzeEncoding);

  document.getElementById("btn-test-arabic").addEventListener("click", function () {
    encTextInput.value = "مرحبا بك في دبي! استمتع بأسرع شبكة إنترنت الجيل الخامس.";
    analyzeEncoding();
  });

  document.getElementById("btn-test-escaped").addEventListener("click", function () {
    encTextInput.value = "Total invoice charge: €150.00 EUR. Please review your balance at portal [online].";
    analyzeEncoding();
  });

  // --- TAB 4: Multi-part Concatenation ---
  var longMsgInput = document.getElementById("long-msg-input");
  var udhRefInput = document.getElementById("udh-ref");
  var btnSplitSms = document.getElementById("btn-split-sms");
  var multipartBox = document.getElementById("multipart-segments-box");

  btnSplitSms.addEventListener("click", function () {
    var text = longMsgInput.value;
    var ref = parseInt(udhRefInput.value, 10) || 42;
    var segments = SMPPProtocolEngine.splitMultipartMessage(text, { refNum: ref });

    var html = '';
    html += '<div style="margin-bottom:1rem; font-weight:bold; color:var(--accent-cyan);">Total Segments: ' + segments.length + ' (' + segments[0].encoding.toUpperCase() + ')</div>';

    segments.forEach(function (seg) {
      html += '<div style="background:var(--bg-primary); padding:0.85rem; border-radius:6px; margin-bottom:0.75rem; border:1px solid var(--border-color);">';
      html += '<div style="display:flex; justify-content:space-between; margin-bottom:0.4rem; font-weight:bold;">';
      html += '<span style="color:var(--accent-emerald);">Part ' + seg.part + ' of ' + seg.total + '</span>';
      html += '<span class="brand-badge">' + seg.payloadBytes.length + ' Bytes</span>';
      html += '</div>';
      if (seg.udh) {
        html += '<div style="font-size:0.8rem; color:var(--accent-amber); margin-bottom:0.3rem;">UDH (Hex): ' + formatHex(seg.udh) + '</div>';
      }
      html += '<div style="font-size:0.85rem; color:var(--text-main);">' + seg.text + '</div>';
      html += '</div>';
    });

    multipartBox.innerHTML = html;
  });

  // --- TAB 5: Auditor ---
  var btnRunAudit = document.getElementById("btn-run-audit");
  var btnLoadVuln = document.getElementById("btn-load-vulnerable-audit");
  var auditScoreNum = document.getElementById("audit-score-num");
  var auditGradeBadge = document.getElementById("audit-grade-badge");
  var auditStatusText = document.getElementById("audit-status-text");
  var auditSubText = document.getElementById("audit-sub-text");
  var auditTableBody = document.querySelector("#audit-results-table tbody");

  function executeAudit(profile) {
    var report = SMPPSecurityAuditor.runAudit(profile);
    auditScoreNum.textContent = report.score + "%";
    auditScoreNum.className = "score-badge " + (report.score >= 85 ? "grade-A" : "grade-F");
    auditGradeBadge.textContent = "GRADE: " + report.grade;

    if (report.score >= 85) {
      auditStatusText.textContent = "Fully Compliant Carrier Gateway";
      auditSubText.textContent = "GSMA FS.19 & A2P 10DLC Standards Satisfied (0 Critical Issues)";
    } else {
      auditStatusText.textContent = "High Risk: Non-Compliant SMS Gateway";
      auditSubText.textContent = report.criticalVulnerabilities + " Critical Vulnerabilities Detected. High Spoofing/Fine Risk.";
    }

    var tbodyHtml = '';
    report.results.forEach(function (r) {
      tbodyHtml += '<tr>';
      tbodyHtml += '<td style="font-family:var(--font-mono);">' + r.id + '</td>';
      tbodyHtml += '<td><strong>' + r.name + '</strong><br><span style="font-size:0.75rem; color:var(--text-muted);">' + r.detail + '</span></td>';
      tbodyHtml += '<td><span class="status-tag ' + (r.passed ? 'pass' : 'fail') + '">' + (r.passed ? 'PASSED' : 'FAILED') + '</span></td>';
      tbodyHtml += '</tr>';
    });
    auditTableBody.innerHTML = tbodyHtml;
  }

  btnRunAudit.addEventListener("click", function () {
    var profile = {
      transport: document.getElementById("aud-transport").value,
      systemId: document.getElementById("aud-creds").value === "strong" ? "ACME_CORP_SMPP" : "admin",
      password: document.getElementById("aud-creds").value === "strong" ? "S3cur3P@ssw0rd99" : "admin",
      sourceTon: 5,
      registeredSenderId: document.getElementById("aud-sender").value === "registered" ? "BRAND_OTP" : "",
      messageType: "marketing",
      sampleMessage: document.getElementById("aud-optout").value === "enforced" ? "Spring deals 50% off! Reply STOP to opt out." : "Spring deals 50% off! Buy now.",
      rateLimitTps: 100,
      isMultipart: false,
      characterCount: 65,
      dataCoding: 0,
      enquireLinkInterval: 30,
      ipWhitelistEnforced: document.getElementById("aud-firewall").value === "whitelist"
    };
    executeAudit(profile);
  });

  btnLoadVuln.addEventListener("click", function () {
    document.getElementById("aud-transport").value = "plaintext";
    document.getElementById("aud-creds").value = "weak";
    document.getElementById("aud-sender").value = "unregistered";
    document.getElementById("aud-optout").value = "missing";
    document.getElementById("aud-firewall").value = "open";
    btnRunAudit.click();
  });

  // --- TAB 6: Gateway Configs ---
  var nftablesBox = document.getElementById("nftables-box");
  var suricataBox = document.getElementById("suricata-box");

  nftablesBox.value = SMPPConfigSynthesizer.generateNftables();
  suricataBox.value = SMPPConfigSynthesizer.generateSuricata();

  document.getElementById("btn-copy-nftables").addEventListener("click", function () {
    navigator.clipboard.writeText(nftablesBox.value);
    alert("nftables rules copied to clipboard!");
  });

  document.getElementById("btn-copy-suricata").addEventListener("click", function () {
    navigator.clipboard.writeText(suricataBox.value);
    alert("Suricata signatures copied to clipboard!");
  });

  // --- TAB 7: Simulator ---
  var simLog = document.getElementById("sim-log-box");

  function logSim(msg, color) {
    var now = new Date();
    var timeStr = now.toTimeString().split(" ")[0] + "." + now.getMilliseconds().toString().padStart(3, "0");
    var row = document.createElement("div");
    row.className = "dissect-row";
    row.innerHTML = '<span class="dissect-key">' + timeStr + '</span><span class="dissect-val" style="color:' + (color || 'var(--text-main)') + ';">' + msg + '</span>';
    simLog.prepend(row);
  }

  document.getElementById("btn-sim-send-otp").addEventListener("click", function () {
    logSim("-> [OUT] submit_sm (Seq 101, Dest 14155550199, Content: Passcode 849201)", "var(--accent-cyan)");
    setTimeout(function () {
      logSim("<- [IN] submit_sm_resp (Seq 101, Status: ESME_ROK, MsgID: SMSC_20261005_9182)", "var(--accent-emerald)");
    }, 120);
    setTimeout(function () {
      logSim("<- [IN] deliver_sm (DLR: id:SMSC_20261005_9182 stat:DELIVRD err:000 submit_date:2610050408 done_date:2610050408)", "var(--accent-purple)");
    }, 450);
  });

  document.getElementById("btn-sim-burst").addEventListener("click", function () {
    logSim("=== Starting 50 TPS High-Load Transmission Burst ===", "var(--accent-amber)");
    for (var i = 1; i <= 5; i++) {
      (function(idx) {
        setTimeout(function() {
          logSim("-> [OUT] Burst submit_sm batch " + idx + " (10 messages dispatched, window: " + (idx * 2) + "/16)", "var(--accent-cyan)");
          logSim("<- [IN] submit_sm_resp batch " + idx + " acknowledged (ESME_ROK)", "var(--accent-emerald)");
        }, idx * 150);
      })(i);
    }
  });

  document.getElementById("btn-sim-throttle").addEventListener("click", function () {
    logSim("-> [OUT] submit_sm burst rate exceeded upstream aggregator threshold (550 TPS)", "var(--accent-amber)");
    setTimeout(function () {
      logSim("<- [IN] submit_sm_resp Status 0x00000058 (ESME_RTHROTTLED: Queue Full - Pacing Backoff Activated)", "var(--accent-rose)");
      logSim("[FLOW-CONTROL] Exponential backoff triggered: Pausing transmitter queue for 1200ms...", "var(--accent-amber)");
    }, 100);
  });

  document.getElementById("btn-clear-sim").addEventListener("click", function () {
    simLog.innerHTML = '';
  });

  // Initial render
  updateSynthesizedPDU();
  analyzeEncoding();
  btnRunAudit.click();
});
