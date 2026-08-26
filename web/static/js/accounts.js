(function () {
  "use strict";

  // Ukrainian Cyrillic -> Latin transliteration, close to the official
  // national rules — good enough for a login suggestion (not a legal
  // document), always lowercase, ASCII-only output.
  var MAP = {
    а: "a", б: "b", в: "v", г: "h", ґ: "g", д: "d", е: "e", є: "ie",
    ж: "zh", з: "z", и: "y", і: "i", ї: "i", й: "i", к: "k", л: "l",
    м: "m", н: "n", о: "o", п: "p", р: "r", с: "s", т: "t", у: "u",
    ф: "f", х: "kh", ц: "ts", ч: "ch", ш: "sh", щ: "shch", ь: "",
    ю: "iu", я: "ia", "'": "", "’": "", "ʼ": "",
    // common Latin diacritics just fall back to their base letter
  };

  function translit(s) {
    var out = "";
    s = (s || "").toLowerCase();
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      out += MAP.hasOwnProperty(c) ? MAP[c] : c;
    }
    return out.replace(/[^a-z0-9]/g, "");
  }

  function wireUsernameSuggestion(form) {
    var first = form.querySelector('[name="first_name"]');
    var last = form.querySelector('[name="last_name"]');
    var username = form.querySelector('[name="username"]');
    if (!first || !last || !username) return;

    var touched = false;
    username.addEventListener("input", function () {
      touched = true;
    });

    function suggest() {
      if (touched) return;
      var f = translit(first.value);
      var l = translit(last.value);
      if (!f || !l) return;
      username.value = f.charAt(0) + "." + l;
    }
    first.addEventListener("input", suggest);
    last.addEventListener("input", suggest);
  }

  document.querySelectorAll("form").forEach(function (form) {
    if (form.querySelector('[name="last_name"]') && form.querySelector('[name="username"]')) {
      wireUsernameSuggestion(form);
    }
  });
})();
