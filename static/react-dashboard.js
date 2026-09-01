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

  window.__amlSidebarController = window.__amlSidebarController || {
    listeners: new Set(),
    register(handler) {
      this.listeners.add(handler);
      return () => this.listeners.delete(handler);
    },
    toggle() {
      this.listeners.forEach((handler) => handler());
    },
    close() {
      this.listeners.forEach((handler) => handler(false));
    }
  };

  function Icon({ name }) {
    const icons = {
      home: h("svg", { viewBox: "0 0 24 24" },
        h("path", { d: "M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("polyline", { points: "9 22 9 12 15 12 15 22", fill: "none", stroke: "currentColor", strokeWidth: 2 })
      ),
      users: h("svg", { viewBox: "0 0 24 24" },
        h("path", { d: "M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("circle", { cx: "9", cy: "7", r: "4", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("path", { d: "M23 21v-2a4 4 0 0 0-3-3.87", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("path", { d: "M16 3.13a4 4 0 0 1 0 7.75", fill: "none", stroke: "currentColor", strokeWidth: 2 })
      ),
      list: h("svg", { viewBox: "0 0 24 24" },
        h("line", { x1: "8", y1: "6", x2: "21", y2: "6", stroke: "currentColor", strokeWidth: 2 }),
        h("line", { x1: "8", y1: "12", x2: "21", y2: "12", stroke: "currentColor", strokeWidth: 2 }),
        h("line", { x1: "8", y1: "18", x2: "21", y2: "18", stroke: "currentColor", strokeWidth: 2 }),
        h("line", { x1: "3", y1: "6", x2: "3.01", y2: "6", stroke: "currentColor", strokeWidth: 2 }),
        h("line", { x1: "3", y1: "12", x2: "3.01", y2: "12", stroke: "currentColor", strokeWidth: 2 }),
        h("line", { x1: "3", y1: "18", x2: "3.01", y2: "18", stroke: "currentColor", strokeWidth: 2 })
      ),
      shield: h("svg", { viewBox: "0 0 24 24" },
        h("path", { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z", fill: "none", stroke: "currentColor", strokeWidth: 2 })
      ),
      activity: h("svg", { viewBox: "0 0 24 24" },
        h("polyline", { points: "22 12 18 12 15 21 9 3 6 12 2 12", fill: "none", stroke: "currentColor", strokeWidth: 2 })
      ),
      settings: h("svg", { viewBox: "0 0 24 24" },
        h("circle", { cx: "12", cy: "12", r: "3", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("path", { d: "M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z", fill: "none", stroke: "currentColor", strokeWidth: 2 })
      ),
      file: h("svg", { viewBox: "0 0 24 24" },
        h("path", { d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("polyline", { points: "14 2 14 8 20 8", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("line", { x1: "16", y1: "13", x2: "8", y2: "13", stroke: "currentColor", strokeWidth: 2 }),
        h("line", { x1: "16", y1: "17", x2: "8", y2: "17", stroke: "currentColor", strokeWidth: 2 }),
        h("polyline", { points: "10 9 9 9 8 9", stroke: "currentColor", strokeWidth: 2 })
      ),
      logout: h("svg", { viewBox: "0 0 24 24" },
        h("path", { d: "M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("polyline", { points: "16 17 21 12 16 7", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("line", { x1: "21", y1: "12", x2: "9", y2: "12", stroke: "currentColor", strokeWidth: 2 })
      ),
      alert: h("svg", { viewBox: "0 0 24 24" },
        h("path", { d: "M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("line", { x1: "12", y1: "9", x2: "12", y2: "13", stroke: "currentColor", strokeWidth: 2 }),
        h("line", { x1: "12", y1: "17", x2: "12.01", y2: "17", stroke: "currentColor", strokeWidth: 2 })
      ),
      message: h("svg", { viewBox: "0 0 24 24" },
        h("path", { d: "M21 15a2 2 0 0 1-2 2H8l-5 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z", fill: "none", stroke: "currentColor", strokeWidth: 2 }),
        h("path", { d: "M8 9h8M8 13h5", fill: "none", stroke: "currentColor", strokeWidth: 2 })
      )
    };
    return icons[name] || null;
  }

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

  // Singleton SocketIO connection to prevent multiple connections
  let globalSocket = null;
  let globalHeartbeatInterval = null;

  function getSocket() {
    if (!globalSocket && window.io) {
      globalSocket = window.io({ 
        transports: ["websocket", "polling"],
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 500,
        reconnectionDelayMax: 2000,
        pingTimeout: 30000,
        pingInterval: 5000
      });
      
      globalSocket.on('connect', () => {
        console.log('SocketIO connected', { socketId: globalSocket.id });
      });
      
      globalSocket.on('disconnect', (reason) => {
        console.log('SocketIO disconnected', { reason });
      });
      
      globalSocket.on('connect_error', (error) => {
        console.error('SocketIO connection error:', error);
      });
      
      globalSocket.on('reconnect', (attemptNumber) => {
        console.log('SocketIO reconnected', { attemptNumber });
      });
      
      globalSocket.on('reconnect_attempt', (attemptNumber) => {
        console.log('SocketIO reconnection attempt', { attemptNumber });
      });
      
      globalSocket.on('reconnect_error', (error) => {
        console.error('SocketIO reconnection error:', error);
      });
      
      // Socket.IO maintains transport-level ping/pong. This heartbeat only
      // refreshes the server-side presence record.
      globalHeartbeatInterval = setInterval(() => {
        if (globalSocket && globalSocket.connected) {
          globalSocket.emit('heartbeat');
        }
      }, 30000);
    }
    return globalSocket;
  }

  function useRealtime(handlers) {
    useEffect(() => {
      const socket = getSocket();
      if (!socket) {
        console.warn('SocketIO not available');
        return;
      }
      
      // Store event handlers for cleanup
      const eventHandlers = {};
      Object.keys(handlers).forEach((eventName) => {
        const handler = handlers[eventName];
        socket.on(eventName, handler);
        eventHandlers[eventName] = handler;
      });
      
      return () => {
        // Remove event handlers on cleanup
        Object.keys(eventHandlers).forEach((eventName) => {
          socket.off(eventName, eventHandlers[eventName]);
        });
      };
    }, [JSON.stringify(handlers)]); // Re-register if handlers change
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
    const [activeSection, setActiveSection] = useState("overview");
    const [sidebarOpen, setSidebarOpen] = useState(false);

    const sidebarItems = [
      { id: "overview", label: "Overview", icon: "home" },
      { id: "transactions", label: "Transactions", icon: "list" },
      { id: "alerts", label: "Alerts", icon: "alert" },
      { id: "activity", label: "Activity Feed", icon: "activity" },
      { id: "signout", label: "Sign Out", href: "/logout", icon: "logout" }
    ];

    const toggleTheme = () => {
      const currentTheme = document.documentElement.dataset.theme || "dark";
      const newTheme = currentTheme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = newTheme;
      localStorage.setItem("StanPro-theme", newTheme);
      document.cookie = `StanPro-theme=${encodeURIComponent(newTheme)}; Max-Age=31536000; Path=/; SameSite=Lax`;
    };

    // Listen for sidebar toggle click from header
    useEffect(() => {
      const handleToggleClick = (nextValue) => {
        if (typeof nextValue === 'boolean') {
          setSidebarOpen(nextValue);
          return;
        }
        setSidebarOpen((prev) => !prev);
      };
      const unregister = window.__amlSidebarController.register(handleToggleClick);
      const fallback = () => handleToggleClick();
      window.addEventListener('sidebar-toggle-click', fallback);
      return () => {
        unregister();
        window.removeEventListener('sidebar-toggle-click', fallback);
      };
    }, []);

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

    const renderSection = () => {
      switch (activeSection) {
        case "overview":
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
              ),
            )
          );
        case "transactions":
          return h(CustomerTransactionsPanel, { transactions });
        case "alerts":
          return h(CustomerAlertsPanel, { alerts });
        case "activity":
          return h("section", { className: "card table-card live-feed-card" },
            h(PanelHeading, { title: "Live AML Feed", meta: h(LiveStatus, null, status) }),
            feed.length ? h("ul", null, feed.map((event, index) => (
              h("li", { key: `${event.timestamp}-${index}` }, `${event.timestamp} - ${event.text}`)
            ))) : h(EmptyState, null, "Waiting for live events.")
          );
        default:
          return null;
      }
    };

    return h("div", { className: "admin-layout" },
      sidebarOpen && h("div", {
        className: "sidebar-overlay active",
        onClick: () => setSidebarOpen(false)
      }),
      h("aside", { className: `admin-sidebar ${sidebarOpen ? "open" : ""}` },
        h("nav", null,
          sidebarItems.map((item) => item.href ? 
            h("a", {
              key: item.id,
              href: item.href,
              className: "sidebar-item"
            }, h(Icon, { name: item.icon }), item.label) :
            h("button", {
              key: item.id,
              className: activeSection === item.id ? "sidebar-item active" : "sidebar-item",
              onClick: () => {
                setActiveSection(item.id);
                setSidebarOpen(false);
              },
              type: "button"
            }, h(Icon, { name: item.icon }), item.label))
        ),
        h("div", { className: "sidebar-footer" },
          h("button", {
            className: "theme-toggle-sidebar",
            onClick: toggleTheme,
            type: "button",
            "aria-label": "Toggle theme"
          }, 
            h("span", { className: "theme-toggle__track" },
              h("span", { className: "theme-toggle__thumb" })
            ),
            h("span", { className: "theme-toggle__text" }, document.documentElement.dataset.theme === "dark" ? "Dark" : "Light")
          )
        )
      ),
      h("main", { className: "admin-content" }, renderSection())
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
    const [activeSection, setActiveSection] = useState("overview");
    const [sidebarOpen, setSidebarOpen] = useState(false);

    const sidebarItems = [
      { id: "overview", label: "Overview", icon: "home" },
      { id: "users", label: "User Management", icon: "users" },
      { id: "transactions", label: "Transactions", icon: "list" },
      { id: "watchlist", label: "Watchlist", icon: "shield" },
      { id: "activity", label: "Activity Feed", icon: "activity" },
      { id: "settings", label: "Settings", icon: "settings" },
      { id: "reports", label: "Reports", href: "/reports", icon: "file" },
      { id: "signout", label: "Sign Out", href: "/logout", icon: "logout" }
    ];

    const toggleTheme = () => {
      const currentTheme = document.documentElement.dataset.theme || "dark";
      const newTheme = currentTheme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = newTheme;
      localStorage.setItem("StanPro-theme", newTheme);
      document.cookie = `StanPro-theme=${encodeURIComponent(newTheme)}; Max-Age=31536000; Path=/; SameSite=Lax`;
    };

    // Listen for sidebar toggle click from header
    useEffect(() => {
      const handleToggleClick = (nextValue) => {
        if (typeof nextValue === 'boolean') {
          setSidebarOpen(nextValue);
          return;
        }
        setSidebarOpen((prev) => !prev);
      };
      const unregister = window.__amlSidebarController.register(handleToggleClick);
      const fallback = () => handleToggleClick();
      window.addEventListener('sidebar-toggle-click', fallback);
      return () => {
        unregister();
        window.removeEventListener('sidebar-toggle-click', fallback);
      };
    }, []);

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

    const renderSection = () => {
      switch (activeSection) {
        case "overview":
          return h(window.React.Fragment, null,
            h(StatGrid, { items: metricItems }),
            h("section", { className: "react-dashboard-grid" },
              h("div", { className: "card action-card" },
                h(PanelHeading, { title: "Transaction Simulator", meta: h("span", { className: "status-pill" }, "Customers only") }),
                h("p", { className: "muted-line" }, "Generate realistic deposits, withdrawals, and transfers using registered customer accounts."),
                h("form", { method: "post", action: "/admin/generate-transactions" },
                  h("label", null, "Number of Transactions"),
                  h("select", { name: "count", defaultValue: "100" },
                    h("option", { value: "100" }, "100"),
                    h("option", { value: "500" }, "500"),
                    h("option", { value: "1000" }, "1000"),
                    h("option", { value: "2000" }, "2000"),
                    h("option", { value: "5000" }, "5000")
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
              ),
              h(MessagingSummaryCard, { audience: "Coordinate with compliance officers and customer support without leaving the AML control workflow." })
            )
          );
        case "users":
          return h(UsersTable, { users });
        case "transactions":
          return h(AdminTransactionsPanel, { transactions });
        case "watchlist":
          return h(WatchlistPanel, { watchlist });
        case "activity":
          return h(ActivityPanel, { activity });
        case "settings":
          return h("section", { className: "admin-danger-zone" },
            h("div", { className: "card action-card" },
              h(PanelHeading, { title: "System Maintenance" }),
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
        default:
          return null;
      }
    };

    return h("div", { className: "admin-layout" },
      sidebarOpen && h("div", {
        className: "sidebar-overlay active",
        onClick: () => setSidebarOpen(false)
      }),
      h("aside", { className: `admin-sidebar ${sidebarOpen ? "open" : ""}` },
        h("nav", null,
          sidebarItems.map((item) => item.href ? 
            h("a", {
              key: item.id,
              href: item.href,
              className: "sidebar-item"
            }, h(Icon, { name: item.icon }), item.label) :
            h("button", {
              key: item.id,
              className: activeSection === item.id ? "sidebar-item active" : "sidebar-item",
              onClick: () => {
                setActiveSection(item.id);
                setSidebarOpen(false);
              },
              type: "button"
            }, h(Icon, { name: item.icon }), item.label))
        ),
        h("div", { className: "sidebar-footer" },
          h("button", {
            className: "theme-toggle-sidebar",
            onClick: toggleTheme,
            type: "button",
            "aria-label": "Toggle theme"
          }, 
            h("span", { className: "theme-toggle__track" },
              h("span", { className: "theme-toggle__thumb" })
            ),
            h("span", { className: "theme-toggle__text" }, document.documentElement.dataset.theme === "dark" ? "Dark" : "Light")
          )
        )
      ),
      h("main", { className: "admin-content" }, renderSection())
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
    const [activeSection, setActiveSection] = useState("overview");
    const [sidebarOpen, setSidebarOpen] = useState(false);
    const filterValue = initialData.filter_value || "all";

    const sidebarItems = [
      { id: "overview", label: "Overview", icon: "home" },
      { id: "alerts", label: "Alerts", icon: "alert" },
      { id: "activity", label: "Activity Feed", icon: "activity" },
      { id: "reports", label: "Reports", href: "/reports", icon: "file" },
      { id: "signout", label: "Sign Out", href: "/logout", icon: "logout" }
    ];

    const toggleTheme = () => {
      const currentTheme = document.documentElement.dataset.theme || "dark";
      const newTheme = currentTheme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = newTheme;
      localStorage.setItem("StanPro-theme", newTheme);
      document.cookie = `StanPro-theme=${encodeURIComponent(newTheme)}; Max-Age=31536000; Path=/; SameSite=Lax`;
    };

    // Listen for sidebar toggle click from header
    useEffect(() => {
      const handleToggleClick = (nextValue) => {
        if (typeof nextValue === 'boolean') {
          setSidebarOpen(nextValue);
          return;
        }
        setSidebarOpen((prev) => !prev);
      };
      const unregister = window.__amlSidebarController.register(handleToggleClick);
      const fallback = () => handleToggleClick();
      window.addEventListener('sidebar-toggle-click', fallback);
      return () => {
        unregister();
        window.removeEventListener('sidebar-toggle-click', fallback);
      };
    }, []);

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

    const alertPageCount = useMemo(() => {
      return Math.max(1, Math.ceil(Number(initialData.open_alert_count || 0) / Number(initialData.page_size || 25)));
    }, [initialData.open_alert_count, initialData.page_size]);

    const metricItems = [
      { label: "Open alerts", value: stats.open_alerts || alerts.length, caption: "needs review" },
      { label: "High risk today", value: stats.high_risk_today || 0, caption: "new severe activity" },
      { label: "Draft SARs", value: stats.pending_sars || 0, caption: "case narratives" },
      { label: "Pending CTRs", value: stats.pending_ctrs || 0, caption: "currency reports" },
    ];

    const renderSection = () => {
      switch (activeSection) {
        case "overview":
          return h(window.React.Fragment, null,
            h(StatGrid, { items: metricItems }),
            h("section", { className: "compliance-dashboard-grid grid" },
              h(AlertsPanel, { alerts, page: initialData.alert_page, pageCount: alertPageCount }),
            )
          );
        case "alerts":
          return h(AlertsPanel, { alerts, page: initialData.alert_page, pageCount: alertPageCount });
        case "activity":
          return h("section", { className: "card table-card" },
            h(PanelHeading, { title: "Live Compliance Feed", meta: h(LiveStatus, null, status) }),
            feed.length ? h("ul", null, feed.map((event, index) => (
              h("li", { className: "activity-item", key: `${event.timestamp}-${index}` },
                h("strong", null, event.timestamp),
                h("p", null, event.text)
              )
            ))) : h(EmptyState, null, "Waiting for live events.")
          );
        default:
          return null;
      }
    };

    return h("div", { className: "admin-layout" },
      sidebarOpen && h("div", {
        className: "sidebar-overlay active",
        onClick: () => setSidebarOpen(false)
      }),
      h("aside", { className: `admin-sidebar ${sidebarOpen ? "open" : ""}` },
        h("nav", null,
          sidebarItems.map((item) => item.href ? 
            h("a", {
              key: item.id,
              href: item.href,
              className: "sidebar-item"
            }, h(Icon, { name: item.icon }), item.label) :
            h("button", {
              key: item.id,
              className: activeSection === item.id ? "sidebar-item active" : "sidebar-item",
              onClick: () => {
                setActiveSection(item.id);
                setSidebarOpen(false);
              },
              type: "button"
            }, h(Icon, { name: item.icon }), item.label))
        ),
        h("div", { className: "sidebar-footer" },
          h("button", {
            className: "theme-toggle-sidebar",
            onClick: toggleTheme,
            type: "button",
            "aria-label": "Toggle theme"
          }, 
            h("span", { className: "theme-toggle__track" },
              h("span", { className: "theme-toggle__thumb" })
            ),
            h("span", { className: "theme-toggle__text" }, document.documentElement.dataset.theme === "dark" ? "Dark" : "Light")
          )
        )
      ),
      h("main", { className: "admin-content" }, renderSection())
    );
  }

  function ComplianceTransactionsPanel({ transactions }) {
    const [filter, setFilter] = useState("all");
    
    const filteredTransactions = filter === "all" 
      ? transactions 
      : transactions.filter(txn => txn.risk_level === filter);
    
    return h("div", { className: "card table-card" },
      h(PanelHeading, { title: "Transactions" }),
      h("div", { className: "filter-bar" },
        h("label", null, "Filter by Risk:"),
        h("select", { 
          value: filter, 
          onChange: (e) => setFilter(e.target.value),
          className: "filter-select"
        },
          h("option", { value: "all" }, "All"),
          h("option", { value: "critical" }, "Critical"),
          h("option", { value: "high_risk" }, "High Risk"),
          h("option", { value: "suspicious" }, "Suspicious"),
          h("option", { value: "normal" }, "Normal")
        )
      ),
      filteredTransactions.length ? h("table", { className: "data-table" },
        h("thead", null,
          h("tr", null, ["Transaction", "Type", "Amount", "AI Assessment"].map((head) => h("th", { key: head }, head)))
        ),
        h("tbody", null,
          filteredTransactions.map((txn, index) => h("tr", { key: txn.id || index },
            h("td", null,
              h("strong", null, `#${txn.id || ""}`),
              h("span", { className: "muted-line block-line" }, shortTime(txn.timestamp))
            ),
            h("td", null, labelize(txn.transaction_type || txn.type)),
            h("td", null, money(txn.amount)),
            h("td", null,
              h("span", { className: riskClass(txn.ai_risk_level || txn.risk_level) }, labelize(txn.ai_risk_level || txn.risk_level || "unavailable")),
              h("span", { className: "muted-line block-line" }, `Score ${score(txn.risk_score)}`)
            )
          ))
        )
      ) : h(EmptyState, null, "No transactions match this filter.")
    );
  }

  function AlertsPanel({ alerts, page = 1, pageCount = 1 }) {
    return h("div", { className: "card table-card" },
      h(PanelHeading, { title: "Open Alerts" }),
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
      )) : h(EmptyState, null, "No open alerts."),
      pageCount > 1 ? h("nav", { className: "queue-pagination", "aria-label": "Open alert pages" },
        h("a", {
          className: page <= 1 ? "action-link pagination-disabled" : "action-link",
          href: page <= 1 ? undefined : `/compliance?alert_page=${page - 1}`,
          "aria-disabled": page <= 1
        }, "Previous"),
        h("span", { className: "muted-line" }, `Page ${page} of ${pageCount}`),
        h("a", {
          className: page >= pageCount ? "action-link pagination-disabled" : "action-link",
          href: page >= pageCount ? undefined : `/compliance?alert_page=${page + 1}`,
          "aria-disabled": page >= pageCount
        }, "Next")
      ) : null
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
