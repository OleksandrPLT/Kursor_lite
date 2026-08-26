(function () {
  "use strict";

  // Quick-pick reasons per topic — deliberately plain client-side data
  // (not part of the Go i18n dictionary): descriptive suggestions, not
  // UI chrome. "Reason" is stored as free text on the ticket either way,
  // so this list is just a head start, not a closed enum.
  var REASONS = {
    uk: {
      sites: ["Сайт не відкривається", "Помилка 502/504", "Потрібен новий сайт", "SSL не працює"],
      files: ["Не можу завантажити файл", "Не вистачає прав доступу", "Файл видалено помилково", "Потрібне відновлення з бекапу"],
      databases: ["Не можу підключитись до бази", "Потрібна нова база даних", "Забув пароль від бази", "Повільні запити"],
      ssl: ["Сертифікат прострочився", "Потрібен сертифікат для нового домену", "Помилка HTTPS у браузері"],
      cron: ["Завдання не виконується", "Потрібне нове завдання", "Помилка у виконанні завдання"],
      backups: ["Потрібне відновлення з бекапу", "Бекап не створюється", "Потрібен позаплановий бекап"],
      terminal: ["Потрібен доступ до терміналу", "Не можу підключитись"],
      network_dns: ["Потрібен новий DNS-запис", "DNS не резолвиться", "Потрібно змінити існуючий запис"],
      network_ports: ["Потрібно відкрити порт", "Порт заблоковано помилково"],
      network_vpn: ["Потрібен доступ до VPN", "VPN не підключається", "Втрачено конфіг/ключ"],
      network_ssh: ["Потрібен SSH-доступ", "Втрачено SSH-ключ"],
      accounts: ["Забув пароль", "Потрібен новий акаунт", "Потрібно змінити права доступу", "Акаунт заблоковано"],
      departments: ["Перехід в інший підрозділ", "Потрібен новий підрозділ/посада"],
      mail: ["Не можу увійти в пошту", "Потрібна нова поштова скринька", "Лист не надходить/не надсилається"],
      sso: ["Не можу авторизуватись у проєкті", "Потрібно підключити новий проєкт"],
      other: ["Інше питання"],
    },
    en: {
      sites: ["Site is down", "502/504 error", "Need a new site", "SSL isn't working"],
      files: ["Can't upload a file", "Missing permissions", "A file was deleted by mistake", "Need a restore from backup"],
      databases: ["Can't connect to the database", "Need a new database", "Forgot the database password", "Slow queries"],
      ssl: ["Certificate expired", "Need a certificate for a new domain", "Browser HTTPS error"],
      cron: ["A job isn't running", "Need a new scheduled job", "A job is failing"],
      backups: ["Need to restore from a backup", "Backups aren't being created", "Need an ad-hoc backup"],
      terminal: ["Need terminal access", "Can't connect"],
      network_dns: ["Need a new DNS record", "DNS isn't resolving", "Need to change an existing record"],
      network_ports: ["Need a port opened", "A port was blocked by mistake"],
      network_vpn: ["Need VPN access", "VPN won't connect", "Lost my config/key"],
      network_ssh: ["Need SSH access", "Lost my SSH key"],
      accounts: ["Forgot my password", "Need a new account", "Need my access changed", "My account is locked"],
      departments: ["Moving to a different department", "Need a new department/position added"],
      mail: ["Can't log into mail", "Need a new mailbox", "Mail isn't arriving/sending"],
      sso: ["Can't sign in to a project", "Need a new project connected"],
      other: ["Something else"],
    },
  };

  var OTHER_LABEL = { uk: "Інша причина...", en: "Other reason…" };

  // Which module permission a topic is "about" — lets a grant_access
  // request on e.g. network_vpn pre-check the "network" checkbox
  // instead of making the requester guess which of the six it means.
  // Topics with no entry here (departments/mail/sso/other) don't map
  // to a grantable module at all, so they get no request-kind scenario.
  var TOPIC_PERMISSION = {
    sites: "sites", ssl: "sites",
    files: "files",
    databases: "databases",
    cron: "server", backups: "server", terminal: "server",
    network_dns: "network", network_ports: "network", network_vpn: "network", network_ssh: "network",
  };

  document.querySelectorAll("form[data-lang]").forEach(function (form) {
    var lang = REASONS[form.dataset.lang] ? form.dataset.lang : "en";
    var topicSelect = form.querySelector('[name="topic"]');
    var reasonSelect = form.querySelector('[name="reason"]');
    if (!topicSelect || !reasonSelect) return;

    function repopulate() {
      var list = REASONS[lang][topicSelect.value] || REASONS[lang].other;
      reasonSelect.innerHTML = "";
      list.forEach(function (text) {
        var opt = document.createElement("option");
        opt.value = text;
        opt.textContent = text;
        reasonSelect.appendChild(opt);
      });
      var otherOpt = document.createElement("option");
      otherOpt.value = "";
      otherOpt.textContent = OTHER_LABEL[lang];
      reasonSelect.appendChild(otherOpt);
    }

    topicSelect.addEventListener("change", repopulate);
    repopulate();

    // Request-kind workflow: every topic that maps to a module (or is
    // "accounts" itself) can offer a scenario — which scenarios depends
    // on the topic. "accounts" gets the full set (grant/new/terminate);
    // a module topic (sites, network_vpn, ...) only gets "grant access",
    // pre-checking the permission that topic is about; everything else
    // (departments/mail/sso/other) gets no request-kind block at all,
    // same as before this generalization.
    var kindBlock = form.querySelector("#request-kind-block");
    var kindSelect = form.querySelector("#request-kind-select");
    var targetBlock = form.querySelector("#target-user-block");
    var permissionsBlock = form.querySelector("#permissions-block");
    var newAccountBlock = form.querySelector("#new-account-block");
    if (!kindBlock || !kindSelect) return;

    function updateKindBlocks() {
      var kind = kindSelect.value;
      targetBlock.style.display = (kind === "grant_access" || kind === "terminate") ? "block" : "none";
      permissionsBlock.style.display = kind === "grant_access" ? "block" : "none";
      newAccountBlock.style.display = kind === "new_account" ? "block" : "none";
    }

    function updateTopicVisibility() {
      var topic = topicSelect.value;
      var isAccounts = topic === "accounts";
      var modulePermission = TOPIC_PERMISSION[topic] || null;
      var hasScenario = isAccounts || !!modulePermission;

      kindBlock.style.display = hasScenario ? "block" : "none";

      // Account-only scenarios (new hire, termination) only make sense
      // on the "accounts" topic itself — hide them for a module topic.
      kindSelect.querySelectorAll("option[data-only-accounts]").forEach(function (opt) {
        var accountsOnly = opt.dataset.onlyAccounts === "1";
        opt.hidden = accountsOnly && !isAccounts;
      });

      if (!hasScenario) {
        kindSelect.value = "";
      } else if (!isAccounts && kindSelect.value !== "" && kindSelect.value !== "grant_access") {
        // Was showing new_account/terminate for "accounts", topic just
        // changed to a module topic — fall back to the one scenario
        // that's still valid rather than leaving a hidden option selected.
        kindSelect.value = "grant_access";
      }

      // Pre-check (don't force) the permission this topic is about —
      // a convenience, not a restriction: the requester can still tick
      // any other box too.
      if (modulePermission) {
        var box = permissionsBlock.querySelector('input[value="' + modulePermission + '"]');
        if (box) box.checked = true;
      }

      updateKindBlocks();
    }

    topicSelect.addEventListener("change", updateTopicVisibility);
    kindSelect.addEventListener("change", updateKindBlocks);
    updateTopicVisibility();
  });
})();
