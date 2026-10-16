/* verify.behavry.ai client.
   Deliberately dependency-free and small enough to read in full. A page whose
   job is to establish trust should not ask you to trust a bundle. */

(function () {
  "use strict";

  var form = document.getElementById("form");
  var packageInput = document.getElementById("package");
  var anchorInput = document.getElementById("anchor");
  var drop = document.getElementById("drop");
  var dropLabel = document.getElementById("drop-label");
  var submit = document.getElementById("submit");
  var status = document.getElementById("status");
  var result = document.getElementById("result");

  var GLYPH = { pass: "✓", fail: "✗", warn: "⚠", skipped: "–", info: "i" };

  // -- file selection -------------------------------------------------------

  function describeSelection() {
    var file = packageInput.files && packageInput.files[0];
    if (!file) {
      dropLabel.textContent = "Drop the .zip here, or choose a file";
      drop.classList.remove("filled");
      return;
    }
    dropLabel.textContent = file.name + "  (" + formatBytes(file.size) + ")";
    drop.classList.add("filled");
  }

  function formatBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / (1024 * 1024)).toFixed(1) + " MB";
  }

  packageInput.addEventListener("change", describeSelection);

  ["dragenter", "dragover"].forEach(function (evt) {
    drop.addEventListener(evt, function (e) {
      e.preventDefault();
      drop.classList.add("over");
    });
  });
  ["dragleave", "drop"].forEach(function (evt) {
    drop.addEventListener(evt, function (e) {
      e.preventDefault();
      drop.classList.remove("over");
    });
  });
  drop.addEventListener("drop", function (e) {
    if (e.dataTransfer && e.dataTransfer.files.length) {
      packageInput.files = e.dataTransfer.files;
      describeSelection();
    }
  });

  // -- submit ---------------------------------------------------------------

  var observersInput = document.getElementById("observers");
  var tsaRootsInput = document.getElementById("tsa-roots");
  var anchorForm = document.getElementById("anchor-form");
  var auditAnchorInput = document.getElementById("audit-anchor");
  var anchorTrustInput = document.getElementById("anchor-trust");
  var anchorTsaRootsInput = document.getElementById("anchor-tsa-roots");
  var anchorSubmit = document.getElementById("anchor-submit");
  var anchorStatus = document.getElementById("anchor-status");

  // Small JSON and PEM files are read client-side so the server receives them
  // as text and never has to guess at an encoding. Resolves "" for no file.
  function readText(input) {
    var file = input.files && input.files[0];
    return new Promise(function (resolve, reject) {
      if (!file) { resolve(""); return; }
      var reader = new FileReader();
      reader.onload = function () { resolve(String(reader.result)); };
      reader.onerror = function () { reject(new Error("Could not read " + file.name + ".")); };
      reader.readAsText(file);
    });
  }

  function post(url, body, button, statusNode) {
    button.disabled = true;
    setStatus(statusNode, "Verifying…", false);
    return fetch(url, { method: "POST", body: body })
      .then(function (response) {
        return response.json().then(function (payload) {
          return { ok: response.ok, payload: payload };
        });
      })
      .then(function (outcome) {
        button.disabled = false;
        if (!outcome.ok) {
          setStatus(statusNode, outcome.payload.detail || "The request could not be processed.", true);
          result.hidden = true;
          return;
        }
        setStatus(statusNode, "", false);
        render(outcome.payload);
      })
      .catch(function () {
        button.disabled = false;
        setStatus(statusNode, "Could not reach the verification service.", true);
      });
  }

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var file = packageInput.files && packageInput.files[0];
    if (!file) {
      setStatus(status, "Choose an evidence package first.", true);
      return;
    }
    var body = new FormData();
    body.append("package", file);
    // Observer key files go up as files, one observer_anchor field each.
    Array.prototype.forEach.call(observersInput.files || [], function (observer) {
      body.append("observer_anchor", observer);
    });
    Promise.all([readText(anchorInput), readText(tsaRootsInput)])
      .then(function (texts) {
        if (texts[0]) body.append("trust_anchor", texts[0]);
        if (texts[1]) body.append("tsa_roots", texts[1]);
        return post("/api/v1/verify", body, submit, status);
      })
      .catch(function (err) { setStatus(status, err.message, true); });
  });

  anchorForm.addEventListener("submit", function (e) {
    e.preventDefault();
    var file = auditAnchorInput.files && auditAnchorInput.files[0];
    if (!file) {
      setStatus(anchorStatus, "Choose an audit anchor first.", true);
      return;
    }
    var body = new FormData();
    body.append("audit_anchor", file);
    Promise.all([readText(anchorTrustInput), readText(anchorTsaRootsInput)])
      .then(function (texts) {
        if (texts[0]) body.append("trust_anchor", texts[0]);
        if (texts[1]) body.append("tsa_roots", texts[1]);
        return post("/api/v1/verify-anchor", body, anchorSubmit, anchorStatus);
      })
      .catch(function (err) { setStatus(anchorStatus, err.message, true); });
  });

  function setStatus(node, text, isError) {
    node.textContent = text;
    node.classList.toggle("error", Boolean(isError));
  }

  // -- rendering ------------------------------------------------------------

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function render(report) {
    result.textContent = "";
    result.hidden = false;

    var verdict = el("div", "verdict " + (report.verified ? "pass" : "fail"));
    verdict.appendChild(
      el("h2", null, report.verified ? "Verified" : "Not verified")
    );
    verdict.appendChild(el("p", "summary", summarize(report)));

    var list = el("ul", "checks");
    (report.checks || []).forEach(function (check) {
      var item = el("li", check.status);
      item.appendChild(el("span", "glyph", GLYPH[check.status] || "?"));
      var body = el("div");
      body.appendChild(el("div", "label", check.label));
      if (check.detail) body.appendChild(el("div", "detail", check.detail));
      item.appendChild(body);
      list.appendChild(item);
    });
    verdict.appendChild(list);

    var meta = el("dl", "meta");
    var anchorSummary = report.anchor_summary || {};
    var anchoring = report.provenance_anchoring;
    var isAnchor = report.kind === "audit_anchor";
    [
      ["APR identifier", report.apr_identifier],
      ["Signer", signerLine(report)],
      ["Events", report.event_count],
      ["Root hash", report.root_hash],
      [isAnchor ? "Anchor sealed" : "Package created", report.created_at],
      ["Tenant", anchorSummary.tenant_id],
      ["Period", anchorSummary.period_start
        ? anchorSummary.period_start + " to " + anchorSummary.period_end : null],
      ["Provenance entries", anchorSummary.provenance_count],
      ["Provenance root", anchorSummary.provenance_root],
      ["TSA genTime", anchorSummary.tsa_gen_time],
      ["Provenance anchoring", anchoring
        ? anchoring.anchored + " anchored, " + anchoring.not_yet_anchored +
          " not yet anchored, " + anchoring.missing + " missing" +
          (anchoring.unanchored ? ", " + anchoring.unanchored + " unanchored" : "") +
          " (" + anchoring.anchor_count + " anchor" + (anchoring.anchor_count === 1 ? "" : "s") + ")"
        : null],
      ["Verified at", report.verified_at],
    ].forEach(function (pair) {
      if (pair[1] === null || pair[1] === undefined || pair[1] === "") return;
      var row = el("div");
      row.appendChild(el("dt", null, pair[0]));
      row.appendChild(el("dd", null, pair[1]));
      meta.appendChild(row);
    });
    if (meta.children.length) verdict.appendChild(meta);

    if (report.caveat) verdict.appendChild(el("p", "caveat", report.caveat));
    if (report.error) verdict.appendChild(el("p", "caveat", report.error));

    result.appendChild(verdict);
    result.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function summarize(report) {
    var checks = report.checks || [];
    var failed = checks.filter(function (c) { return c.status === "fail"; });
    if (report.verified && report.kind === "audit_anchor") {
      return (
        "Every check passed. This anchor is exactly what was sealed, and its " +
        (report.event_count || 0) + " events and " +
        ((report.anchor_summary || {}).provenance_count || 0) +
        " provenance entries reproduce its roots."
      );
    }
    if (report.verified) {
      return (
        "Every check passed. This package is exactly what was signed, and its " +
        (report.event_count || 0) + " events are intact and in order."
      );
    }
    if (!failed.length) {
      return "Verification could not be completed. See the checks below.";
    }
    return failed.length === 1
      ? "One check failed: " + failed[0].label.toLowerCase() + "."
      : failed.length + " checks failed. See below.";
  }

  function signerLine(report) {
    if (!report.signer_kid) return null;
    var parts = [report.signer_kid];
    if (report.signature_algorithm) parts.push("(" + report.signature_algorithm + ")");
    if (report.signing_backend) parts.push("via " + report.signing_backend);
    return parts.join(" ");
  }
})();
