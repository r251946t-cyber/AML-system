(function () {
  const adminRoot = document.getElementById("admin-react-root");
  const complianceRoot = document.getElementById("compliance-react-root");
  const customerRoot = document.getElementById("customer-react-root");

  if (!adminRoot && !complianceRoot && !customerRoot) return;

  if (!window.React || !window.ReactDOM) {
    const root = adminRoot || complianceRoot || customerRoot;
    root.innerHTML = '<section class="card"><h3>Dashboard unavailable</h3><p class="muted-line">React could not be loaded. Check your network connection and reload this page.</p></section>';
    return;
  }

  const { createElement: h, useEffect, useMemo, useState } = window.React;
  const suspiciousLevels = ["suspicious", "super_suspicious", "high_risk", "critical"];

  function readJson(id) {
    const node = document.getElementById(id);
    if (!node) return {};
    try {
      return JSON.parse(node.textContent || "{}");
    } catch (_error) {
      return {};
    }
  }

  function money(value) {
    return `$${Number(value || 0).toFixed(2)}`;
  }

  function score(value) {
    return Number(value || 0).toFixed(0);
  }

  function confidence(value) {
    if (value === null || value === undefined || value === "") return "unavailable";
    return `${Math.round(Number(value || 0) * 100)}%`;
  }

  function riskClass(level) {
    return level && level !== "normal" ? "status-pill alert" : "status-pill";
  }

  function trim(list, count) {
    return list.slice(0, count);
  }

  function StatGrid({ items }) {
    return h("section", { className: "react-metrics" },
      items.map((item) => h("div", { className: "metric-tile", key: item.label },
        h("span", { className: "metric-label" }, item.label),
        h("strong", null, item.value)
      ))
    );
  }

  function EmptyState({ children }) {
    return h("p", { className: "muted-line empty-state" }, children);
  }

  function useRealtime(handlers) {
    useEffect(() => {
      if (window.io) {
        const socket = window.io({ transports: ["websocket", "polling"] });
        Object.keys(handlers).forEach((eventName) => socket.on(eventName, handlers[eventName]));
        return () => socket.disconnect();
      }

      if (window.EventSource) {
        const source = new EventSource("/stream");
        Object.keys(handlers).forEach((eventName) => {
          source.addEventListener(eventName, (event) => {
            const payload = eventName === "reset" ? {} : JSON.parse(event.data);
            handlers[eventName](payload);
          });
        });
        return () => source.close();
      }

      return undefined;
    }, []);
  }

  function ownsTransaction(txn, accountNumber) {
    return txn.sender_account === accountNumber || txn.receiver_account === accountNumber;
  }

  function CustomerDashboard({ initialData }) {
    const user = initialData.user || {};
    const accountNumber = user.account_number || "";
    const [balance, setBalance] = useState(Number(user.balance || 0));
    const [transactions, setTransactions] = useState(initialData.transactions || []);
    const [alerts, setAlerts] = useState(initialData.alerts || []);
    const [stats, setStats] = useState(initialData.stats || {});
    const [feed, setFeed] = useState([]);
    const [status, setStatus] = useState("Connected | live monitoring active");

    const addFeed = (text) => setFeed((current) => trim([{ text, timestamp: new Date().toLocaleTimeString() }, ...current], 25));
    const adjustBalanceFromTransaction = (txn) => {
      if (!ownsTransaction(txn, accountNumber)) return;
      const amount = Number(txn.amount || 0);
      const txType = txn.transaction_type || txn.type;
      setBalance((current) => {
        if (txType === "deposit" && txn.sender_account === accountNumber) return current + amount;
        if (txType === "withdraw" && txn.sender_account === accountNumber) return current - amount;
        if (txType === "transfer" && txn.sender_account === accountNumber) return current - amount;
        if (txType === "transfer" && txn.receiver_account === accountNumber) return current + amount;
        return current;
      });
    };

    useRealtime({
      connect: () => setStatus("Connected | WebSocket live stream active"),
      transaction: (txn) => {
        if (!ownsTransaction(txn, accountNumber)) return;
        setTransactions((current) => trim([txn, ...current], 25));
        setStats((current) => ({
          ...current,
          total_tx: Number(current.total_tx || 0) + 1,
          flagged: txn.risk_level && txn.risk_level !== "normal"
            ? Number(current.flagged || 0) + 1
            : Number(current.flagged || 0),
        }));
        adjustBalanceFromTransaction(txn);
        addFeed(`Transaction | ${txn.transaction_type || txn.type || ""} | ${money(txn.amount)} | ${txn.risk_level || "normal"}`);
      },
      alert: (alert) => {
        if (alert.account_number !== accountNumber) return;
        setAlerts((current) => trim([alert, ...current], 10));
        setStats((current) => ({ ...current, open_alerts: Number(current.open_alerts || 0) + 1 }));
        setStatus("Live alert received | stream active");
        addFeed(`Alert | Tx #${alert.transaction_id || ""} | ${alert.risk_level || ""} | Score ${score(alert.risk_score)} | ${alert.reason || ""}`);
      },
      alert_update: (alert) => {
        if (alert.account_number !== accountNumber) return;
        setAlerts((current) => {
          if (alert.status !== "open") return current.filter((item) => String(item.id) !== String(alert.id));
          const exists = current.some((item) => String(item.id) === String(alert.id));
          return exists
            ? current.map((item) => String(item.id) === String(alert.id) ? alert : item)
            : trim([alert, ...current], 10);
        });
        if (alert.status !== "open") {
          setStats((current) => ({ ...current, open_alerts: Math.max(0, Number(current.open_alerts || 0) - 1) }));
        }
        addFeed(`Alert status | #${alert.id || ""} | ${alert.status || ""}`);
      },
      ai_model: (model) => addFeed(`AI model | ${model.trained ? "trained" : "waiting for more labels"} | ${model.training_rows} rows`),
      balance: (event) => {
        if (event.account_number !== accountNumber) return;
        setBalance(Number(event.balance || 0));
      },
      reset: () => {
        setTransactions([]);
        setAlerts([]);
        setFeed([]);
        setStatus("Live reset received | stream active");
        setStats((current) => ({ ...current, total_tx: 0, flagged: 0, open_alerts: 0 }));
      },
    });

    const metricItems = [
      { label: "Available balance", value: money(balance) },
      { label: "Transactions", value: stats.total_tx || transactions.length },
      { label: "Flagged", value: stats.flagged || 0 },
      { label: "Open alerts", value: stats.open_alerts || alerts.filter((alert) => alert.status === "open").length },
    ];

    return h(window.React.Fragment, null,
      h(StatGrid, { items: metricItems }),
      h("section", { className: "grid" },
        h("div", { className: "card" },
          h("p", { className: "status-pill" }, "Primary Account"),
          h("h3", null, accountNumber),
          h("p", { className: "metric" }, money(balance)),
          h("p", null, "Available balance")
        ),
        h("div", { className: "card" },
          h("h3", null, "Initiate Transaction"),
          h("form", { method: "post", action: "/customer/transaction" },
            h("label", null, "Type"),
            h("select", { name: "type", defaultValue: "deposit" },
              h("option", { value: "deposit" }, "Deposit"),
              h("option", { value: "withdraw" }, "Withdrawal"),
              h("option", { value: "transfer" }, "Transfer")
            ),
            h("label", null, "Amount"),
            h("input", { type: "number", step: "0.01", name: "amount", required: true }),
            h("label", null, "Recipient Account Number"),
            h("input", { name: "recipient", placeholder: "ACC1002" }),
            h("button", { type: "submit" }, "Process Transaction")
          )
        )
      ),
      h("section", { className: "react-dashboard-grid" },
        h(CustomerTransactionsPanel, { transactions }),
        h(CustomerAlertsPanel, { alerts })
      ),
      h("section", { className: "card table-card live-feed-card" },
        h("div", { className: "panel-heading-row" },
          h("h3", null, "Live AML Feed"),
          h("span", { className: "status-pill" }, status)
        ),
        feed.length ? h("ul", null, feed.map((event, index) => (
          h("li", { key: `${event.timestamp}-${index}` }, `${event.timestamp} - ${event.text}`)
        ))) : h(EmptyState, null, "Waiting for live events.")
      )
    );
  }

  function CustomerTransactionsPanel({ transactions }) {
    return h("div", { className: "card table-card" },
      h("h3", null, "Recent Transactions"),
      transactions.length ? h("ul", null, transactions.map((txn, index) => (
        h("li", { key: txn.id || index },
          h("strong", null, `Tx #${txn.id || ""}`),
          ` | ${txn.timestamp || ""} | ${txn.transaction_type || txn.type || ""} | ${money(txn.amount)}`,
          h("br"),
          "Final risk ",
          h("span", { className: riskClass(txn.risk_level) }, txn.risk_level || "normal"),
          ` | Score ${score(txn.risk_score)}`,
          h("br"),
          h("span", { className: "muted-line" },
            `Rules risk: ${txn.rule_level || "normal"} / ${score(txn.rule_score)} | AI behavior risk: ${txn.ai_risk_level || "unavailable"} / ${confidence(txn.ai_confidence)}`
          )
        )
      ))) : h(EmptyState, null, "No transactions to show.")
    );
  }

  function CustomerAlertsPanel({ alerts }) {
    return h("div", { className: "card table-card" },
      h("h3", null, "AML Alerts"),
      alerts.length ? h("ul", null, alerts.map((alert, index) => (
        h("li", { key: alert.id || index },
          h("strong", null, `Alert #${alert.id || ""}`),
          ` | Tx #${alert.transaction_id || ""} | ${alert.timestamp || ""} | `,
          h("span", { className: "status-pill alert" }, alert.risk_level || "risk"),
          ` | ${alert.reason || ""}`
        )
      ))) : h(EmptyState, null, "No alerts for this account.")
    );
  }

  function AdminDashboard({ initialData }) {
    const [users, setUsers] = useState(initialData.users || []);
    const [activity, setActivity] = useState(initialData.activity || []);
    const [transactions, setTransactions] = useState(initialData.transactions || []);
    const [watchlist, setWatchlist] = useState(initialData.watchlist || []);
    const [stats, setStats] = useState(initialData.system_stats || {});

    const updateBalances = (txn) => {
      const amount = Number(txn.amount || 0);
      const txType = txn.transaction_type || txn.type;
      setUsers((current) => current.map((user) => {
        let balance = Number(user.balance || 0);
        if (txType === "deposit" && user.account_number === txn.sender_account) balance += amount;
        if (txType === "withdraw" && user.account_number === txn.sender_account) balance -= amount;
        if (txType === "transfer" && user.account_number === txn.sender_account) balance -= amount;
        if (txType === "transfer" && user.account_number === txn.receiver_account) balance += amount;
        return { ...user, balance };
      }));
    };

    useRealtime({
      transaction: (txn) => {
        setTransactions((current) => trim([txn, ...current], 20));
        updateBalances(txn);
      },
      balance: (event) => {
        setUsers((current) => current.map((user) => (
          user.account_number === event.account_number
            ? { ...user, balance: event.balance, kyc_status: event.kyc_status || user.kyc_status }
            : user
        )));
      },
      user: (event) => {
        setUsers((current) => current.map((user) => (
          user.id === event.user_id
            ? { ...user, balance: event.balance, kyc_status: event.kyc_status || user.kyc_status }
            : user
        )));
      },
      activity: (event) => setActivity((current) => trim([event, ...current], 25)),
      ai_model: (model) => setActivity((current) => trim([{
        timestamp: model.timestamp,
        action: "ai_model",
        detail: `${model.trained ? "trained" : "waiting for more labels"} on ${model.training_rows} rows`,
      }, ...current], 25)),
      transaction_batch: (batch) => setActivity((current) => trim([{
        timestamp: batch.timestamp,
        action: "transaction_batch",
        detail: `generated ${batch.count} transactions`,
      }, ...current], 25)),
      watchlist: (entry) => setWatchlist((current) => trim([entry, ...current], 20)),
      stats: setStats,
      reset: () => {
        setTransactions([]);
        setActivity((current) => trim([{
          timestamp: new Date().toISOString(),
          action: "reset",
          detail: "transactions, alerts, reports, and AI model cleared",
        }, ...current], 25));
      },
    });

    const metricItems = [
      { label: "Users", value: stats.total_users || users.length },
      { label: "Transactions", value: stats.total_transactions || 0 },
      { label: "Open alerts", value: stats.open_alerts || 0 },
      { label: "Draft SARs", value: stats.pending_sars || 0 },
      { label: "Pending CTRs", value: stats.pending_ctrs || 0 },
    ];

    return h(window.React.Fragment, null,
      h(StatGrid, { items: metricItems }),
      h("section", { className: "react-dashboard-grid" },
        h("div", { className: "card" },
          h("h3", null, "Transaction Simulator"),
          h("form", { method: "post", action: "/admin/generate-transactions" },
            h("label", null, "Number of Transactions"),
            h("select", { name: "count", defaultValue: "100" },
              h("option", { value: "100" }, "100"),
              h("option", { value: "1000" }, "1,000"),
              h("option", { value: "5000" }, "5,000")
            ),
            h("button", { type: "submit" }, "Generate Transactions")
          )
        ),
        h("div", { className: "card" },
          h("h3", null, "Manage Users"),
          h("form", { method: "post", action: "/admin" },
            h("input", { type: "hidden", name: "action", value: "update_role" }),
            h("label", null, "User"),
            h("select", { name: "user_id" },
              users.map((user) => h("option", { value: user.id, key: user.id }, `${user.username} (${user.role})`))
            ),
            h("label", null, "KYC Status"),
            h("select", { name: "kyc_status", defaultValue: "pending" },
              h("option", { value: "pending" }, "Pending"),
              h("option", { value: "verified" }, "Verified"),
              h("option", { value: "rejected" }, "Rejected")
            ),
            h("button", { type: "submit" }, "Update User")
          )
        ),
        h("div", { className: "card" },
          h("h3", null, "Watchlist Entry"),
          h("form", { method: "post", action: "/admin" },
            h("input", { type: "hidden", name: "action", value: "add_watchlist" }),
            h("label", null, "Name"),
            h("input", { name: "wl_name", required: true }),
            h("label", null, "ID Number"),
            h("input", { name: "wl_id_number" }),
            h("label", null, "List Type"),
            h("select", { name: "wl_type", defaultValue: "internal" },
              h("option", { value: "internal" }, "Internal"),
              h("option", { value: "pep" }, "PEP"),
              h("option", { value: "sanctions" }, "Sanctions")
            ),
            h("label", null, "Reason"),
            h("input", { name: "wl_reason" }),
            h("button", { type: "submit" }, "Add to Watchlist")
          )
        )
      ),
      h("section", { className: "react-dashboard-grid" },
        h(ActivityPanel, { activity }),
        h(AdminTransactionsPanel, { transactions }),
        h(WatchlistPanel, { watchlist })
      ),
      h(UsersTable, { users }),
      h("section", { className: "admin-danger-zone" },
        h("form", { method: "post", action: "/admin/clear-transactions" },
          h("button", { type: "submit", className: "danger-button" }, "Clear All Transactions")
        )
      )
    );
  }

  function ActivityPanel({ activity }) {
    return h("div", { className: "card table-card" },
      h("h3", null, "Recent Activity"),
      activity.length ? h("ul", null, activity.map((event, index) => (
        h("li", { key: `${event.timestamp || ""}-${index}` },
          `${event.timestamp || ""} - ${event.action || ""} - ${event.detail || ""}`
        )
      ))) : h(EmptyState, null, "No activity recorded yet.")
    );
  }

  function AdminTransactionsPanel({ transactions }) {
    return h("div", { className: "card table-card" },
      h("h3", null, "Recent Transactions"),
      transactions.length ? h("ul", null, transactions.map((txn, index) => (
        h("li", { key: txn.id || index },
          `${txn.timestamp || ""} - ${txn.sender_account || ""} -> ${txn.receiver_account || ""} - ${money(txn.amount)} - `,
          h("span", { className: riskClass(txn.risk_level) }, txn.risk_level || "normal")
        )
      ))) : h(EmptyState, null, "No transactions to show.")
    );
  }

  function WatchlistPanel({ watchlist }) {
    return h("div", { className: "card table-card" },
      h("h3", null, "Watchlist"),
      watchlist.length ? h("ul", null, watchlist.map((entry, index) => (
        h("li", { key: entry.id || index },
          `${entry.name || ""} - ${entry.list_type || "internal"} - ${entry.reason || "No reason recorded"}`
        )
      ))) : h(EmptyState, null, "No watchlist entries.")
    );
  }

  function UsersTable({ users }) {
    return h("section", { className: "card table-card" },
      h("h3", null, "Registered Users"),
      h("table", null,
        h("thead", null,
          h("tr", null,
            ["ID", "Username", "Email", "Account Number", "Role", "Balance", "KYC", "Created"].map((head) => h("th", { key: head }, head))
          )
        ),
        h("tbody", null,
          users.map((user) => h("tr", { key: user.id },
            h("td", null, user.id),
            h("td", null, user.username),
            h("td", null, user.email),
            h("td", null, user.account_number),
            h("td", null, user.role),
            h("td", null, money(user.balance)),
            h("td", null, h("span", { className: user.kyc_status === "verified" ? "status-pill" : "status-pill alert" }, user.kyc_status || "pending")),
            h("td", null, user.created_at)
          ))
        )
      )
    );
  }

  function ComplianceDashboard({ initialData }) {
    const [transactions, setTransactions] = useState(initialData.transactions || []);
    const [alerts, setAlerts] = useState(initialData.open_alerts || []);
    const [stats, setStats] = useState(initialData.stats || {});
    const [feed, setFeed] = useState([]);
    const [status, setStatus] = useState("Connected | live alert monitoring active");
    const filterValue = initialData.filter_value || "all";

    const addFeed = (text) => setFeed((current) => trim([{ text, timestamp: new Date().toLocaleTimeString() }, ...current], 30));
    const passesFilter = (txn) => {
      if (filterValue === "flagged") return txn.risk_level !== "normal";
      if (filterValue === "suspicious") return suspiciousLevels.includes(txn.risk_level);
      return true;
    };

    useRealtime({
      transaction: (txn) => {
        if (passesFilter(txn)) setTransactions((current) => trim([txn, ...current], 25));
        addFeed(`Transaction | Tx #${txn.id || ""} | ${txn.risk_level || "normal"} | Score ${score(txn.risk_score)}`);
      },
      alert: (alert) => {
        setAlerts((current) => trim([alert, ...current], 30));
        setStatus("New alert received | stream active");
        addFeed(`Alert | Tx #${alert.transaction_id || ""} | ${alert.risk_level || ""} | ${alert.reason || ""}`);
      },
      alert_update: (alert) => {
        setAlerts((current) => {
          if (alert.status !== "open") return current.filter((item) => String(item.id) !== String(alert.id));
          const exists = current.some((item) => String(item.id) === String(alert.id));
          return exists
            ? current.map((item) => String(item.id) === String(alert.id) ? alert : item)
            : trim([alert, ...current], 30);
        });
        addFeed(`Alert status | #${alert.id || ""} | ${alert.status || ""}`);
      },
      ai_model: (model) => addFeed(`AI model | ${model.trained ? "trained" : "waiting for more labels"} | ${model.training_rows} rows`),
      sar_report: (report) => addFeed(`SAR report | #${report.id || ""} | ${report.status || "created"}`),
      ctr_report: (report) => addFeed(`CTR report | #${report.id || ""} | ${report.status || "created"}`),
      transaction_batch: (batch) => addFeed(`Batch | generated ${batch.count || 0} transactions`),
      stats: setStats,
      reset: () => {
        setTransactions([]);
        setAlerts([]);
        setFeed([]);
        setStatus("Reset received | stream active");
      },
    });

    const pageCount = useMemo(() => {
      return Math.max(1, Math.ceil(Number(initialData.total_count || 0) / Number(initialData.page_size || 25)));
    }, [initialData.total_count, initialData.page_size]);

    const metricItems = [
      { label: "Open alerts", value: stats.open_alerts || alerts.length },
      { label: "High risk today", value: stats.high_risk_today || 0 },
      { label: "Draft SARs", value: stats.pending_sars || 0 },
      { label: "Pending CTRs", value: stats.pending_ctrs || 0 },
    ];

    return h(window.React.Fragment, null,
      h(StatGrid, { items: metricItems }),
      h("section", { className: "card react-filter-card" },
        h("form", { method: "get" },
          h("label", null, "Show"),
          h("select", { name: "filter", defaultValue: filterValue },
            h("option", { value: "all" }, "All"),
            h("option", { value: "flagged" }, "Flagged"),
            h("option", { value: "suspicious" }, "Suspicious"),
            h("option", { value: "ctr" }, "CTR required"),
            h("option", { value: "sar" }, "SAR required")
          ),
          h("button", { type: "submit" }, "Apply Filter")
        ),
        h("p", { className: "muted-line" }, `Page ${initialData.page || 1} of ${pageCount} | ${initialData.total_count || 0} matching transactions`)
      ),
      h("section", { className: "react-dashboard-grid" },
        h(ComplianceTransactionsPanel, { transactions }),
        h(AlertsPanel, { alerts })
      ),
      h("section", { className: "card table-card" },
        h("div", { className: "panel-heading-row" },
          h("h3", null, "Live Compliance Feed"),
          h("span", { className: "status-pill" }, status)
        ),
        feed.length ? h("ul", null, feed.map((event, index) => (
          h("li", { key: `${event.timestamp}-${index}` }, `${event.timestamp} - ${event.text}`)
        ))) : h(EmptyState, null, "Waiting for live events.")
      )
    );
  }

  function ComplianceTransactionsPanel({ transactions }) {
    return h("div", { className: "card table-card" },
      h("h3", null, "Transactions"),
      transactions.length ? h("ul", null, transactions.map((txn, index) => (
        h("li", { key: txn.id || index },
          h("strong", null, `Tx #${txn.id || ""}`),
          ` | ${txn.timestamp || ""} | ${txn.transaction_type || txn.type || ""} | ${money(txn.amount)}`,
          h("br"),
          "Final risk ",
          h("span", { className: riskClass(txn.risk_level) }, txn.risk_level || "normal"),
          ` | Score ${score(txn.risk_score)}`,
          h("br"),
          h("span", { className: "muted-line" },
            `Rules risk: ${txn.rule_level || "normal"} / ${score(txn.rule_score)} | AI behavior risk: ${txn.ai_risk_level || "unavailable"} / ${confidence(txn.ai_confidence)}`
          )
        )
      ))) : h(EmptyState, null, "No transactions match this filter.")
    );
  }

  function AlertsPanel({ alerts }) {
    return h("div", { className: "card table-card" },
      h("h3", null, "Alerts"),
      alerts.length ? h("ul", null, alerts.map((alert, index) => (
        h("li", { key: alert.id || index },
          h("strong", null, `Alert #${alert.id || ""}`),
          ` | Tx #${alert.transaction_id || ""} | ${alert.timestamp || ""} | ${alert.account_number || ""} | `,
          h("span", { className: "status-pill alert" }, alert.risk_level || "risk"),
          ` | ${alert.reason || ""}`
        )
      ))) : h(EmptyState, null, "No open alerts.")
    );
  }

  if (adminRoot) {
    window.ReactDOM.createRoot(adminRoot).render(
      h(AdminDashboard, { initialData: readJson("admin-dashboard-data") })
    );
  }

  if (complianceRoot) {
    window.ReactDOM.createRoot(complianceRoot).render(
      h(ComplianceDashboard, { initialData: readJson("compliance-dashboard-data") })
    );
  }

  if (customerRoot) {
    window.ReactDOM.createRoot(customerRoot).render(
      h(CustomerDashboard, { initialData: readJson("customer-dashboard-data") })
    );
  }
})();
