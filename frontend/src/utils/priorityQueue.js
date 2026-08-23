/**
 * priorityQueue.js — Priority Queue for RizIntel Finding Ordering
 *
 * PRODUCTION DESIGN (documented):
 * ─────────────────────────────────────────────────────────────
 * A binary max-heap keeps the highest-priority finding at root.
 *
 * Operations:
 *   insert(finding)  — O(log n)   sift-up after adding to tail
 *   peek()           — O(1)       root is always the max priority
 *   poll()           — O(log n)   remove root, sift-down replacement
 *   size()           — O(1)
 *
 * Priority comparator (descending priority):
 *   1. risk_score (primary)             — higher wins
 *   2. SLA urgency                      — BREACHED > AT_RISK > ON_TRACK > MET
 *   3. finding_confidence score         — higher wins
 *   4. EPSS score                       — higher wins
 *
 * NOTE: For the current mock dataset (10 findings) a JavaScript Array.sort()
 *       is used directly (O(n log n) one-time sort). The PriorityQueue class
 *       below is the production-ready implementation that a backend priority
 *       queue service would replace.
 *
 * BFS/DFS for provenance traversal lives in provenanceGraph.js.
 * ─────────────────────────────────────────────────────────────
 */

// ── SLA urgency ordering ──────────────────────────────────────
const SLA_URGENCY = { BREACHED: 3, AT_RISK: 2, ON_TRACK: 1, MET: 0 };

/**
 * comparePriority — returns positive if a > b in priority.
 * Used both by the heap and the sort wrapper.
 */
export function comparePriority(a, b) {
  // 1. Risk score
  const scoreDiff = (b.risk_score ?? 0) - (a.risk_score ?? 0);
  if (scoreDiff !== 0) return scoreDiff;

  // 2. SLA urgency
  const slaA = SLA_URGENCY[(a.workflow?.sla_status ?? '').toUpperCase()] ?? 0;
  const slaB = SLA_URGENCY[(b.workflow?.sla_status ?? '').toUpperCase()] ?? 0;
  const slaDiff = slaB - slaA;
  if (slaDiff !== 0) return slaDiff;

  // 3. Confidence score
  const confA = a.detail?.finding_confidence?.score ?? 0;
  const confB = b.detail?.finding_confidence?.score ?? 0;
  const confDiff = confB - confA;
  if (confDiff !== 0) return confDiff;

  // 4. EPSS
  const epssA = a.detail?.threat_intelligence?.epss_score ?? 0;
  const epssB = b.detail?.threat_intelligence?.epss_score ?? 0;
  return epssB - epssA;
}

/**
 * sortFindings — wraps Array.sort with the priority comparator.
 * Returns a new sorted array (does not mutate input).
 * This is the function React components should call.
 */
export function sortFindings(findings) {
  if (!Array.isArray(findings)) return [];
  return [...findings].sort(comparePriority);
}

// ── Production Priority Queue Implementation ──────────────────

/**
 * MaxFindingHeap — binary max-heap ordered by finding priority.
 *
 * Usage (production backend integration):
 *   const heap = new MaxFindingHeap();
 *   findings.forEach(f => heap.insert(f));
 *   while (!heap.isEmpty()) console.log(heap.poll());
 */
export class MaxFindingHeap {
  constructor() {
    this._heap = [];
  }

  size()    { return this._heap.length; }
  isEmpty() { return this._heap.length === 0; }

  /** O(1) — highest-priority finding without removal */
  peek() {
    return this._heap[0] ?? null;
  }

  /** O(log n) — insert a finding */
  insert(finding) {
    this._heap.push(finding);
    this._siftUp(this._heap.length - 1);
  }

  /** O(log n) — remove and return highest-priority finding */
  poll() {
    if (this.isEmpty()) return null;
    const top = this._heap[0];
    const last = this._heap.pop();
    if (!this.isEmpty()) {
      this._heap[0] = last;
      this._siftDown(0);
    }
    return top;
  }

  /** Build heap from array — O(n) */
  static fromArray(findings) {
    const heap = new MaxFindingHeap();
    findings.forEach(f => heap.insert(f));
    return heap;
  }

  /** Drain all findings in priority order — O(n log n) */
  drainSorted() {
    const result = [];
    while (!this.isEmpty()) result.push(this.poll());
    return result;
  }

  _siftUp(i) {
    while (i > 0) {
      const parent = Math.floor((i - 1) / 2);
      if (comparePriority(this._heap[i], this._heap[parent]) < 0) {
        [this._heap[i], this._heap[parent]] = [this._heap[parent], this._heap[i]];
        i = parent;
      } else break;
    }
  }

  _siftDown(i) {
    const n = this._heap.length;
    while (true) {
      let largest = i;
      const l = 2 * i + 1;
      const r = 2 * i + 2;
      if (l < n && comparePriority(this._heap[l], this._heap[largest]) < 0) largest = l;
      if (r < n && comparePriority(this._heap[r], this._heap[largest]) < 0) largest = r;
      if (largest !== i) {
        [this._heap[i], this._heap[largest]] = [this._heap[largest], this._heap[i]];
        i = largest;
      } else break;
    }
  }
}

export const PriorityQueue = MaxFindingHeap;
export const triageFindings = sortFindings;

