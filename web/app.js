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

  var GLYPH = { pass: "✓", fail: "✗", warn: "⚠", skipped: "–" };

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

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var file = packageInput.files && packageInput.files[0];
    if (!file) {
      setStatus("Choose an evidence package first.", true);
      return;
    }

    var body = new FormData();
    body.append("package", file);

    var anchorFile = anchorInput.files && anchorInput.files[0];
    var send = function () {
      submit.disabled = true;
      setStatus("Verifying…", false);
      fetch("/api/v1/verify", { method: "POST", body: body })
        .then(function (response) {
          return response.json().then(function (payload) {
            return { ok: response.ok, payload: payload };
          });
        })
        .then(function (outcome) {
          submit.disabled = false;
          if (!outcome.ok) {
            setStatus(outcome.payload.detail || "The request could not be processed.", true);
            result.hidden = true;
            return;
          }
          setStatus("", false);
          render(outcome.payload);
        })
        .catch(function () {
          submit.disabled = false;
          setStatus("Could not reach the verification service.", true);
        });
    };

    if (anchorFile) {
      // Read the anchor client-side so the server receives it as text and
      // never has to guess at an encoding.
      var reader = new FileReader();
      reader.onload = function () {
        body.append("trust_anchor", String(reader.result));
        send();
      };
      reader.onerror = function () {
        setStatus("Could not read the trust anchor file.", true);
      };
      reader.readAsText(anchorFile);
    } else {
      send();
    }
  });

  function setStatus(text, isError) {
    status.textContent = text;
    status.classList.toggle("error", Boolean(isError));
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
    [
      ["APR identifier", report.apr_identifier],
      ["Signer", signerLine(report)],
      ["Events", report.event_count],
      ["Root hash", report.root_hash],
      ["Package created", report.created_at],
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
