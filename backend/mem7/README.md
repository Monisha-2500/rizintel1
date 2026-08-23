# MEMBER 7 — Remediation, Ticketing & SLA Automation Engine

A **terminal-based** Python application, split into separate `.py` files
by operation instead of one big script. No website, no dashboard, no
REST API, no database, no external integrations.

---

## 1. Folder Structure

```
member7_project/
│
├── run_member7.py                    # ENTRY POINT - run this file
├── m7_input_explained_findings.json  # Input dataset (from Member 6)
├── member7_output.json               # Auto-created after you generate tickets
├── README.md                         # This file
│
└── member7_app/                      # All the operations, one per file
    ├── __init__.py
    ├── config.py          # File names + SLA warning threshold
    ├── state.py           # Shared in-memory storage (findings, tickets)
    ├── time_utils.py      # Timestamp parsing + duration formatting
    ├── data_loader.py     # OPERATION: Load Findings
    ├── sla_engine.py       # OPERATION: SLA assignment, deadline, breach detection
    ├── ticket_manager.py  # OPERATION: Ticket creation + generation + lookup
    ├── storage.py          # OPERATION: Save tickets to member7_output.json
    ├── views.py            # OPERATION: All "View ..." + "Show ticket" screens
    ├── actions.py          # OPERATION: Assign / Update Status / Resolve
    └── menu.py             # OPERATION: Terminal menu (ties everything together)
```

**Important:** keep the whole `member7_project` folder together — the
`member7_app` folder must sit next to `run_member7.py`, and
`m7_input_explained_findings.json` must sit next to `run_member7.py` too.

---

## 2. Requirements / Installation

None. Every module only uses Python's built-in `json`, `os`, and
`datetime` — no `pip install` needed.

Check your Python version:
```bash
python3 --version
```

---

## 3. How to Run It

1. Unzip the project and open a terminal in the `member7_project` folder.
2. Run:
   ```bash
   python run_member7.py
   ```
   (use `python3 run_member7.py` if `python` points to Python 2 on your system)
3. The terminal menu appears. Type a number and press Enter.

---

## 4. Step-by-Step Usage (recommended order)

| Step | Menu Option | Handled by |
|------|-------------|------------|
| 1 | **1. Load Findings** | `data_loader.loadfindings()` |
| 2 | **2. Generate Remediation Tickets** | `ticket_manager.generatetickets()` |
| 3 | **3. View All Tickets** | `views.viewtickets()` |
| 4 | **4. View Critical Tickets** | `views.viewcritical()` |
| 5 | **5. View High Priority Tickets** | `views.viewhigh()` |
| 6 | **6. View SLA Warnings** | `views.checkwarnings()` |
| 7 | **7. View SLA Breached Tickets** | `views.view_breached()` |
| 8 | **8. Update Ticket Status** | `actions.updatestatus()` |
| 9 | **9. Assign Ticket** | `actions.assignticket()` |
| 10 | **10. Resolve Ticket** | `actions.resolveticket()` |
| 11 | **11. Show Ticket Details** | `views.showticket()` |
| 12 | **12. Exit** | `menu.main()` |

Run **option 1** then **option 2** before anything else — that's what
loads the JSON and creates the tickets in memory.

---

## 5. Why It's Split Into Separate Files

Each file owns exactly one job, so it's easy to find and change any
single operation without touching the rest:

- **`config.py`** — the only place to change file names or the warning window.
- **`state.py`** — the single shared "in-memory database" (a Python list of
  findings and a list of tickets). No real database is used, as required.
- **`time_utils.py`** — pure helper functions for parsing timestamps and
  formatting durations, reused by both `sla_engine.py` and `ticket_manager.py`.
- **`data_loader.py`** — reads the input JSON. Never modifies it.
- **`sla_engine.py`** — the SLA rule table, SLA deadline math, and the
  live remaining-time / breach / warning calculation (`checksla`).
- **`ticket_manager.py`** — turns one finding into one ticket
  (`createticket`), and loops over all findings to build every ticket
  (`generatetickets`), plus ticket lookup by ID.
- **`storage.py`** — the one optional line of "persistence": saving the
  ticket list to `member7_output.json`.
- **`views.py`** — every terminal screen for *looking at* tickets: all
  tickets, critical-only, high-only, warnings, breaches, and single
  ticket details, plus the shared print formats (ticket / warning /
  breach banners).
- **`actions.py`** — every terminal action for *changing* a ticket:
  assign, update status, resolve (with the SLA MET / BREACHED check).
- **`menu.py`** — the terminal menu loop. It just imports functions from
  the other files and calls the right one based on the user's choice.
- **`run_member7.py`** — the one file you actually run. It's intentionally
  tiny; all logic lives inside `member7_app/`.

---

## 6. How the Input JSON Connects to the Program

`m7_input_explained_findings.json` is Member 6's output — a list of
findings, each already containing a computed `risk_score`. Member 7
does **not** recompute risk. `data_loader.loadfindings()` reads the
whole file into `state.findings`. `ticket_manager.generatetickets()`
then loops through that list once per finding and calls
`ticket_manager.createticket()`, which reads:

- `finding_id`, `cve_id`, `vulnerability_name`, `asset_id`
- `risk_score`, `risk_level`
- `asset_context.asset_name`
- `remediation.recommended_action`
- `discovered_at` (used as the SLA start time)

The original input file is never written to. All output lives in
`state.tickets` (in memory) and, optionally, in `member7_output.json`.

---

## 7. How Member 7 Works — Step by Step

1. **Load Findings** (`data_loader.py`) — reads the JSON dataset into memory.
2. **Priority & SLA Assignment** (`sla_engine.createsla`) — applies the
   fixed rule table:

   | Risk Score | Priority | SLA |
   |---|---|---|
   | 90–100 | CRITICAL | 4 hours |
   | 70–89 | HIGH | 24 hours |
   | 40–69 | MEDIUM | 7 days |
   | < 40 | LOW | 30 days |

3. **Ticket Creation** (`ticket_manager.createticket`) — builds a ticket
   with a unique `TKT-XXXX` ID, sets `sla_start_time` to the finding's
   `discovered_at`, and calculates `sla_deadline`.
4. **SLA Calculation** (`sla_engine.checksla`) — every time a ticket is
   displayed, remaining time is calculated **live** as
   `sla_deadline - current_time`, never hardcoded. This sets:
   - `ON_TRACK` — plenty of time left
   - `WARNING` — 2 hours or less remaining, unresolved
   - `SLA_BREACHED` — deadline passed, unresolved
   - `RESOLVED` — ticket was closed
5. **Ticket Management** (`actions.py`) — assign a ticket to someone,
   move it through OPEN → ASSIGNED → IN_PROGRESS → RESOLVED, or let it
   fall into `SLA_BREACHED` automatically if the deadline passes first.
6. **Resolution Check** (`actions.resolveticket`) — compares the resolve
   time against the SLA deadline and reports `✓ SLA MET` or
   `✗ SLA BREACHED`.
7. **Terminal Output** (`views.py`) — every action prints directly to
   the terminal in the exact ticket / warning / breach formats
   specified for Member 7.
8. **Optional Save** (`storage.py`) — after ticket generation or any
   status change, the full ticket list is saved to
   `member7_output.json`. The terminal remains the primary output.

---

## 8. Notes

- The dataset used contains **150 findings**, covering all four risk
  levels (CRITICAL, HIGH, MEDIUM, LOW).
- SLA status is always recalculated against the current system clock.
- Re-running **option 2** regenerates all tickets from scratch (resets
  any manual assignments/resolutions from the current run, since ticket
  data lives in memory only, aside from the optional
  `member7_output.json` snapshot).
