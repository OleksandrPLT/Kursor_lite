// Real package installs (apt-get/yum/brew) block the request for as
// long as the actual install takes — often 10-30+ seconds. Without any
// feedback, a plain form submit just leaves the browser on a blank
// "loading" tab, which reads as hung, not busy. This adds an immediate,
// unmistakable "installing..." overlay the instant the form submits —
// purely a perceived-wait fix; the request itself is exactly as
// synchronous as before, real real output/errors still land in the
// normal error-banner once the page reloads.
(function () {
  "use strict";

  document.querySelectorAll("form.js-install-form").forEach(function (form) {
    form.addEventListener("submit", function () {
      var btn = form.querySelector('button[type="submit"]');
      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> ' + (form.dataset.loadingText || "…");
      }

      var overlay = document.createElement("div");
      overlay.className = "install-overlay";
      var box = document.createElement("div");
      box.className = "install-overlay-box";
      box.innerHTML =
        '<span class="spinner spinner-lg"></span><p>' +
        (form.dataset.installingMessage || "Виконується встановлення… це може зайняти хвилину.") +
        "</p>";
      overlay.appendChild(box);
      document.body.appendChild(overlay);
    });
  });
})();
