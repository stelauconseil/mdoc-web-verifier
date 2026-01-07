/*
  Copyright (c) 2026 Stelau
  Author: Nicolas Chalanset

  Activity Log module
  Provides a global log() function used across the app
*/

(function () {
  function log(msg) {
    const el = document.getElementById("log");
    if (!el) return;
    const t = new Date().toLocaleTimeString();
    el.innerHTML += `[${t}] ${msg}<br>`;
    el.scrollTop = el.scrollHeight;
  }
  // Expose globally
  window.log = log;
})();
