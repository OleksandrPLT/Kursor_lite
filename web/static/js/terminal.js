(function () {
  "use strict";

  var container = document.getElementById("terminal");
  if (!container || !window.Terminal) return;

  var term = new Terminal({
    cursorBlink: true,
    fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
    fontSize: 13,
    theme: {
      background: "#161b26",
      foreground: "#f5f1e6",
      cursor: "#ffd500",
      selectionBackground: "rgba(255,213,0,0.25)",
    },
  });

  var fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open(container);
  fitAddon.fit();

  var statusEl = document.getElementById("terminal-status");
  function setStatus(text, connected) {
    if (!statusEl) return;
    statusEl.textContent = text;
    statusEl.style.color = connected ? "var(--good)" : "var(--muted)";
  }

  var proto = location.protocol === "https:" ? "wss:" : "ws:";
  var ws = new WebSocket(proto + "//" + location.host + "/server/terminal/ws");
  ws.binaryType = "arraybuffer";

  function sendResize() {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ resize: { cols: term.cols, rows: term.rows } }));
    }
  }

  ws.onopen = function () {
    setStatus("●", true);
    sendResize();
    term.focus();
  };
  ws.onmessage = function (ev) {
    if (ev.data instanceof ArrayBuffer) {
      term.write(new Uint8Array(ev.data));
    } else {
      term.write(ev.data);
    }
  };
  ws.onclose = function () {
    setStatus("○", false);
    term.write("\r\n\x1b[90m[disconnected]\x1b[0m\r\n");
  };
  ws.onerror = function () {
    setStatus("○", false);
  };

  term.onData(function (data) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(data);
    }
  });

  var resizeTimer = null;
  window.addEventListener("resize", function () {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(function () {
      fitAddon.fit();
      sendResize();
    }, 100);
  });
})();
