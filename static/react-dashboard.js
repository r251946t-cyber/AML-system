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

  function normalizeLevel(level) {
    return String(level || "normal").toLowerCase().replace(/[^a-z0-9]+/g, "-");
  }

  function labelize(value) {
    return String(value || "normal").replace(/_/g, " ");
  }

  function shortTime(value) {
    if (!value) return "";
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString([], {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  function riskClass(level) {
    return `status-pill risk-pill risk-${normalizeLevel(level)}`;
  }

  function trim(list, count) {
    return list.slice(0, count);
  }

  function StatGrid({ items }) {
    return h("section", { className: "react-metrics" },
      items.map((item) => h("div", { className: "metric-tile", key: item.label },
        h("span", { className: "metric-label" }, item.label),
        h("strong", null, item.value),
        item.caption ? h("small", null, item.caption) : null
      ))
    );
  }

  function EmptyState({ children }) {
    return h("div", { className: "empty-state" },
      h("span", { className: "empty-state-icon", "aria-hidden": "true" }, "i"),
      h("p", null, children)
    );
  }

  function PanelHeading({ title, meta }) {
    return h("div", { className: "panel-heading-row" },
      h("h3", null, title),
      meta || null
    );
  }

  function LiveStatus({ children, tone = "live" }) {
    return h("span", { className: `live-status ${tone}` },
      h("span", { className: "live-dot", "aria-hidden": "true" }),
      children
    );
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
      { label: "Available balance", value: money(balance), caption: accountNumber },
      { label: "Transactions", value: stats.total_tx || transactions.length, caption: "account history" },
      { label: "Flagged", value: stats.flagged || 0, caption: "requires attention" },
      { label: "Open alerts", value: stats.open_alerts || alerts.filter((alert) => alert.status === "open").length, caption: "live cases" },
    ];

    return h(window.React.Fragment, null,
      h(StatGrid, { items: metricItems }),
      h("section", { className: "grid" },
        h("div", { className: "card account-card" },
          h("p", { className: "status-pill" }, "Primary Account"),
          h("h3", null, accountNumber),
          h("p", { className: "metric" }, money(balance)),
          h("p", { className: "muted-line" }, "Available balance updates automatically after every live transaction.")
        ),
        h("div", { className: "card action-card" },
          h(PanelHeading, { title: "Initiate Transaction" }),
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
            h("input", { name: "recipient", placeholder: "ACC1004" }),
            h("p", { className: "form-hint" }, "Recipient is required for transfers only."),
            h("button", { type: "submit" }, "Process Transaction")
          )
        )
      ),
      h("section", { className: "react-dashboard-grid" },
        h(CustomerTransactionsPanel, { transactions }),
        h(CustomerAlertsPanel, { alerts })
      ),
      h("section", { className: "card table-card live-feed-card" },
        h(PanelHeading, { title: "Live AML Feed", meta: h(LiveStatus, null, status) }),
        feed.length ? h("ul", null, feed.map((event, index) => (
          h("li", { key: `${event.timestamp}-${index}` }, `${event.timestamp} - ${event.text}`)
        ))) : h(EmptyState, null, "Waiting for live events.")
      )
    );
  }

  function CustomerTransactionsPanel({ transactions }) {
    return h("div", { className: "card table-card" },
      h(PanelHeading, { title: "Recent Transactions" }),
      transactions.length ? h("table", { className: "data-table" },
        h("thead", null,
          h("tr", null, ["Transaction", "Type", "Amount", "Risk", "AI"].map((head) => h("th", { key: head }, head)))
        ),
        h("tbody", null,
          transactions.map((txn, index) => h("tr", { key: txn.id || index },
            h("td", null,
              h("strong", null, `#${txn.id || ""}`),
              h("span", { className: "muted-line block-line" }, shortTime(txn.timestamp))
            ),
            h("td", null, labelize(txn.transaction_type || txn.type)),
            h("td", null, money(txn.amount)),
            h("td", null,
              h("span", { className: riskClass(txn.risk_level) }, labelize(txn.risk_level)),
              h("span", { className: "muted-line block-line" }, `Score ${score(txn.risk_score)}`)
            ),
            h("td", null,
              h("span", null, labelize(txn.ai_risk_level || "unavailable")),
              h("span", { className: "muted-line block-line" }, confidence(txn.ai_confidence))
            )
          ))
        )
      ) : h(EmptyState, null, "No transactions to show.")
    );
  }

  function CustomerAlertsPanel({ alerts }) {
    return h("div", { className: "card table-card" },
      h(PanelHeading, { title: "AML Alerts" }),
      alerts.length ? h("table", { className: "data-table" },
        h("thead", null,
          h("tr", null, ["Alert", "Transaction", "Risk", "Reason"].map((head) => h("th", { key: head }, head)))
        ),
        h("tbody", null,
          alerts.map((alert, index) => h("tr", { key: alert.id || index },
            h("td", null,
              h("strong", null, `#${alert.id || ""}`),
              h("span", { className: "muted-line block-line" }, shortTime(alert.timestamp))
            ),
            h("td", null, `#${alert.transaction_id || ""}`),
            h("td", null, h("span", { className: riskClass(alert.risk_level) }, labelize(alert.risk_level || "risk"))),
            h("td", null, alert.reason || "")
          )
        )
      )) : h(EmptyState, null, "No alerts for this account.")
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
        setActivity([]);
      },
    });

    const metricItems = [
      { label: "Users", value: stats.total_users || users.length, caption: "registered accounts" },
      { label: "Transactions", value: stats.total_transactions || 0, caption: "monitored ledger" },
      { label: "Open alerts", value: stats.open_alerts || 0, caption: "active cases" },
      { label: "Draft SARs", value: stats.pending_sars || 0, caption: "pending review" },
      { label: "Pending CTRs", value: stats.pending_ctrs || 0, caption: "currency reports" },
    ];

    return h(window.React.Fragment, null,
      h(StatGrid, { items: metricItems }),
      h("section", { className: "react-dashboard-grid" },
        h("div", { className: "card action-card" },
          h(PanelHeading, { title: "Transaction Simulator", meta: h("span", { className: "status-pill" }, "Customers only") }),
          h("p", { className: "muted-line" }, "Generate realistic deposits, withdrawals, and transfers using registered customer accounts."),
          h("form", { method: "post", action: "/admin/generate-transactions" },
            h("label", null, "Number of Transactions"),
            h("select", { name: "count", defaultValue: "100" },
              h("option", { value: "50" }, "50"),
              h("option", { value: "100" }, "100"),
              h("option", { value: "250" }, "250"),
              h("option", { value: "500" }, "500")
            ),
            h("button", { type: "submit" }, "Generate Transactions")
          )
        ),
        h("div", { className: "card action-card" },
          h(PanelHeading, { title: "Manage Users" }),
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
        h("div", { className: "card action-card" },
          h(PanelHeading, { title: "Watchlist Entry" }),
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
        h("form", {
          method: "post",
          action: "/admin/clear-transactions",
          onSubmit: (event) => {
            if (!window.confirm("Clear all transactions, alerts, reports, recent activity, and the AI model?")) {
              event.preventDefault();
            }
          },
        },
          h("button", { type: "submit", className: "danger-button" }, "Clear All Transactions")
        ),
        h("form", {
          method: "post",
          action: "/admin/clear-watchlist",
          onSubmit: (event) => {
            if (!window.confirm("Clear all watchlist entries?")) {
              event.preventDefault();
            }
          },
        },
          h("button", { type: "submit", className: "danger-button" }, "Clear Watchlist")
        ),
        h("form", {
          method: "post",
          action: "/admin/migrate-database",
          onSubmit: (event) => {
            if (!window.confirm("Run database migration to add missing columns?")) {
              event.preventDefault();
            }
          },
        },
          h("button", { type: "submit", className: "danger-button" }, "Migrate Database")
        )
      )
    );
  }

  function ActivityPanel({ activity }) {
    return h("div", { className: "card table-card" },
      h(PanelHeading, { title: "Recent Activity" }),
      activity.length ? h("ul", null, activity.map((event, index) => (
        h("li", { className: "activity-item", key: `${event.timestamp || ""}-${index}` },
          h("strong", null, labelize(event.action || "")),
          h("span", { className: "muted-line block-line" }, shortTime(event.timestamp)),
          h("p", null, event.detail || "")
        )
      ))) : h(EmptyState, null, "No activity recorded yet.")
    );
  }

  function AdminTransactionsPanel({ transactions }) {
    return h("div", { className: "card table-card" },
      h(PanelHeading, { title: "Recent Transactions" }),
      transactions.length ? h("table", { className: "data-table admin-transactions-table" },
        h("thead", null,
          h("tr", null, ["Time", "Route", "Amount", "Risk"].map((head) => h("th", { key: head }, head)))
        ),
        h("tbody", null,
          transactions.map((txn, index) => h("tr", { key: txn.id || index },
            h("td", null, shortTime(txn.timestamp)),
            h("td", null, `${txn.sender_account || ""} -> ${txn.receiver_account || ""}`),
            h("td", null, money(txn.amount)),
            h("td", null, h("span", { className: riskClass(txn.risk_level) }, labelize(txn.risk_level)))
          ))
        )
      ) : h(EmptyState, null, "No transactions to show.")
    );
  }

  function WatchlistPanel({ watchlist }) {
    return h("div", { className: "card table-card" },
      h(PanelHeading, { title: "Watchlist" }),
      watchlist.length ? h("ul", null, watchlist.map((entry, index) => (
        h("li", { className: "activity-item", key: entry.id || index },
          h("strong", null, entry.name || ""),
          h("span", { className: "status-pill block-fit" }, entry.list_type || "internal"),
          h("p", null, entry.reason || "No reason recorded")
        )
      ))) : h(EmptyState, null, "No watchlist entries.")
    );
  }

  function UsersTable({ users }) {
    return h("section", { className: "card table-card" },
      h(PanelHeading, { title: "Registered Users" }),
      h("table", { className: "data-table" },
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
      if (filterValue === "ctr") return Boolean(txn.ctr_required);
      if (filterValue === "sar") return Boolean(txn.sar_required);
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
      { label: "Open alerts", value: stats.open_alerts || alerts.length, caption: "needs review" },
      { label: "High risk today", value: stats.high_risk_today || 0, caption: "new severe activity" },
      { label: "Draft SARs", value: stats.pending_sars || 0, caption: "case narratives" },
      { label: "Pending CTRs", value: stats.pending_ctrs || 0, caption: "currency reports" },
    ];

    return h(window.React.Fragment, null,
      h(StatGrid, { items: metricItems }),
      h("section", { className: "card react-filter-card action-card" },
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
      h("section", { className: "react-dashboard-grid compliance-dashboard-grid" },
        h(ComplianceTransactionsPanel, { transactions }),
        h(AlertsPanel, { alerts })
      ),
      h("section", { className: "card table-card" },
        h(PanelHeading, { title: "Live Compliance Feed", meta: h(LiveStatus, null, status) }),
        feed.length ? h("ul", null, feed.map((event, index) => (
          h("li", { className: "activity-item", key: `${event.timestamp}-${index}` },
            h("strong", null, event.timestamp),
            h("p", null, event.text)
          )
        ))) : h(EmptyState, null, "Waiting for live events.")
      )
    );
  }

  function ComplianceTransactionsPanel({ transactions }) {
    return h("div", { className: "card table-card" },
      h(PanelHeading, { title: "Transactions" }),
      transactions.length ? h("table", { className: "data-table" },
        h("thead", null,
          h("tr", null, ["Transaction", "Type", "Amount", "Risk", "Rules / AI"].map((head) => h("th", { key: head }, head)))
        ),
        h("tbody", null,
          transactions.map((txn, index) => h("tr", { key: txn.id || index },
            h("td", null,
              h("strong", null, `#${txn.id || ""}`),
              h("span", { className: "muted-line block-line" }, shortTime(txn.timestamp))
            ),
            h("td", null, labelize(txn.transaction_type || txn.type)),
            h("td", null, money(txn.amount)),
            h("td", null,
              h("span", { className: riskClass(txn.risk_level) }, labelize(txn.risk_level)),
              h("span", { className: "muted-line block-line" }, `Score ${score(txn.risk_score)}`)
            ),
            h("td", null,
              h("span", null, `${labelize(txn.rule_level || "normal")} / ${score(txn.rule_score)}`),
              h("span", { className: "muted-line block-line" }, `${labelize(txn.ai_risk_level || "unavailable")} / ${confidence(txn.ai_confidence)}`)
            )
          ))
        )
      ) : h(EmptyState, null, "No transactions match this filter.")
    );
  }

  function AlertsPanel({ alerts }) {
    return h("div", { className: "card table-card" },
      h(PanelHeading, { title: "Alerts" }),
      alerts.length ? h("table", { className: "data-table" },
        h("thead", null,
          h("tr", null, ["Alert", "Account", "Risk", "Reason", "Action"].map((head) => h("th", { key: head }, head)))
        ),
        h("tbody", null,
          alerts.map((alert, index) => h("tr", { key: alert.id || index },
            h("td", null,
              h("strong", null, `#${alert.id || ""}`),
              h("span", { className: "muted-line block-line" }, `Tx #${alert.transaction_id || ""}`)
            ),
            h("td", null, alert.account_number || ""),
            h("td", null, h("span", { className: riskClass(alert.risk_level) }, labelize(alert.risk_level || "risk"))),
            h("td", null, alert.reason || ""),
            h("td", null, alert.id
              ? h("a", { className: "action-link", href: `/compliance/alert/${alert.id}` }, "Review")
              : h("span", { className: "muted-line" }, "Pending")
            )
          )
        )
      )) : h(EmptyState, null, "No open alerts.")
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
