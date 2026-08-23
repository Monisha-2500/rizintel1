# RizIntel — M8 Security Decision Intelligence Command Center

RizIntel sits above existing vulnerability scanners (ZAP, Nuclei, OpenVAS) to consolidate, prioritize, and translate security intelligence into actionable remediation decisions. Module 8 (M8) transforms the upstream outputs of Modules M1–M7 into an interactive Operations Console for cybersecurity analysts.

This repository implements the **RizIntel Command Center** against the Schema v1.0 data contract, integrating mock capabilities with a full service layer, a FastAPI backend, and an interactive React frontend.

---

## Technical Stack & Architecture

### Backend: Python & FastAPI
* **FastAPI**: Chosen for its high performance, automatic OpenAPI documentation, and native async support.
* **Pydantic**: Validates incoming pipeline payloads directly against the Schema v1.0 structure, rejecting malformed JSON gracefully rather than crashing.
* **Uvicorn**: Lightweight ASGI server hosting the service layer.

### Frontend: React, Vite & Recharts
* **Vite**: Used for rapid hot-module reloading and efficient project building.
* **React Flow**: Renders the dynamic, hierarchical **Risk DNA** provenance graph.
* **Recharts**: Standard declarative charting library used to build the operational distribution charts.
* **CSS Variables**: Power the clean, Navy/Blue/Teal security SaaS design system.

---

## How to Run the Application

### 1. Run the FastAPI Backend
Ensure you have Python 3.8+ installed. Navigate to the backend folder and start the server:

```bash
# Install dependencies
pip install -r backend/requirements.txt

# Start uvicorn server on http://localhost:8000
python backend/main.py
```
To verify the API health, navigate to `http://localhost:8000/health`.

### 2. Run the React Frontend
Open another terminal pane, install node packages, and run Vite:

```bash
# Navigate to the frontend directory
cd frontend

# Install package dependencies
npm install

# Start Vite dev server on http://localhost:5173
npm run dev
```

Open `http://localhost:5173` in your browser. The Vite server handles proxy requests to the backend.

---

## Core Algorithms & Traceability

### 1. Priority Queue Ordering (Algorithm 1)
* **Design**: Isolated inside [priorityQueue.js](file:///Users/Harshita/Desktop/cts_frontend/frontend/src/utils/priorityQueue.js). Sorts findings descending by priority.
* **Heap Complexity**:
  * **Insertion**: $O(\log n)$
  * **Peak (Highest Priority)**: $O(1)$
  * **Removal**: $O(\log n)$
* **Tie-Breaking Rule**: Risk Score $\rightarrow$ SLA Urgency (Breached first) $\rightarrow$ Finding Confidence Score $\rightarrow$ EPSS Score.

### 2. Provenance Adjacency Graph (Algorithm 2)
* **Design**: Located in [provenanceGraph.js](file:///Users/Harshita/Desktop/cts_frontend/frontend/src/utils/provenanceGraph.js). Converts vulnerability records into an adjacency-list directed graph representing relationships from scanner alerts up to remediation.
* **Complexity**: BFS/DFS operations run in $O(V + E)$ where $V$ is vertices and $E$ is edges.
* **Significance**: Allows analysts to trace any priority score back to original scanner logs, verifying consensus and mitigating false positives.

---

## Key Features

1. **Risk DNA**: Visual decision graph centered on the M5 risk score showing threat intelligence, scanner consensus, asset context, and remediation.
2. **Why Now?**: Deterministic, evidence-backed urgency check (looks at EPSS, CISA KEV, exploit availability, asset exposure, and SLA deadlines).
3. **Finding Journey**: Visual timeline showing step-by-step progress from detection to correlation, prioritization, and assignment.
4. **Risk Delta**: Track risk change history over time.
5. **Analyst Feedback (Human-in-the-Loop)**: Submit priority approvals, escalations, or downgrades with full audit trailing.
6. **Integration Health**: Visual dashboard strip representing upstream processing engines.

---

## Security Considerations
* Input payload validation using Pydantic.
* Separation of analyst feedback logic from M5 raw risk scores.
* Sanitization of text parameters to prevent script injection.
