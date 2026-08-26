(function () {
  "use strict";

  var netHistory = [];
  var MAX_POINTS = 24;

  function setRing(id, pct) {
    var el = document.getElementById(id);
    if (!el) return;
    var clamped = Math.max(0, Math.min(100, pct || 0));
    el.style.setProperty("--pct", clamped);
  }

  function setText(id, text) {
    var el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function fmt1(n) {
    return (Math.round((n || 0) * 10) / 10).toFixed(1);
  }

  function updateNetChart(downKBs) {
    netHistory.push(downKBs || 0);
    if (netHistory.length > MAX_POINTS) netHistory.shift();

    var w = 220, h = 40;
    var max = 1;
    for (var i = 0; i < netHistory.length; i++) {
      if (netHistory[i] > max) max = netHistory[i];
    }
    var step = w / Math.max(1, MAX_POINTS - 1);
    var offset = (MAX_POINTS - netHistory.length) * step;

    var pts = netHistory.map(function (v, i) {
      var x = offset + i * step;
      var y = h - (v / max) * (h - 4) - 2;
      return x.toFixed(1) + "," + y.toFixed(1);
    });

    var line = document.getElementById("net-line");
    var fill = document.getElementById("net-fill");
    if (line) {
      line.setAttribute("points", pts.join(" "));
      line.setAttribute("stroke", "var(--accent)");
    }
    if (fill && pts.length) {
      var firstX = pts[0].split(",")[0];
      var lastX = pts[pts.length - 1].split(",")[0];
      fill.setAttribute("points", firstX + "," + h + " " + pts.join(" ") + " " + lastX + "," + h);
    }
  }

  function onSample(s) {
    setRing("ring-cpu", s.cpuPercent);
    setText("val-cpu", Math.round(s.cpuPercent || 0) + "%");
    if (s.cpuCores) setText("detail-cpu", s.cpuCores + " cores");

    setRing("ring-mem", s.memPercent);
    setText("val-mem", Math.round(s.memPercent || 0) + "%");
    setText("detail-mem", fmt1(s.memUsedGB) + " / " + fmt1(s.memTotalGB) + " GB");

    setRing("ring-disk", s.diskPercent);
    setText("val-disk", Math.round(s.diskPercent || 0) + "%");
    setText("detail-disk", fmt1(s.diskUsedGB) + " / " + fmt1(s.diskTotalGB) + " GB");

    var downMBs = (s.netDownKBs || 0) / 1024;
    var upMBs = (s.netUpKBs || 0) / 1024;
    setText("val-net-down", "↓ " + fmt1(downMBs) + " MB/s");
    setText("val-net-up", "↑ " + fmt1(upMBs) + " MB/s");
    updateNetChart(s.netDownKBs);
  }

  if (window.EventSource) {
    var es = new EventSource("/monitor/stream");
    es.onmessage = function (ev) {
      try {
        onSample(JSON.parse(ev.data));
      } catch (e) {
        /* ignore malformed event */
      }
    };
    es.onerror = function () {
      /* EventSource auto-reconnects; nothing to do here for the MVP */
    };
  }
})();
