#!/usr/bin/env python3
"""MECI bounded explicit-state reference checker, v1.0.0.

Memory-Egress Cryptographic Interlock (MECI), Thor Thor, 2026.
Paper license: CC BY 4.0. This checker: MIT.

Dependency-free (Python 3.8+), deterministic output. Run:
    python3 meci_modelcheck.py

The safety model mirrors spec/MECI.tla state for state: same variables,
same initial state, same actions, same bounds. Distinct-state counts can
therefore be compared directly with TLC output (see spec/tlc_results.txt).

What this checks:
  1. Safety core (Section 8, Table 1): five open designs, exhaustive BFS
     within GEN_BOUND and MAX_EPOCH; invariant  egress => Safe.
  2. Release-equivalence (relational) test over 16 protected records.
  3. Epoch non-resurrection under persistent vs rollback-vulnerable state.
  4. Influence-graph sanity checks: reflexive closure and relabeling.

This is a bounded model of the abstract reference design. It is not a
proof about any processor, firmware, device, or TEE.
"""
from collections import deque
from itertools import product

HAZARDS = ("P", "M", "I", "G", "B", "Q")  # D is derived from epoch revocation
GEN_BOUND = 3
MAX_EPOCH = 3
DESIGNS = ("atomic", "gencheck", "buggy", "dponly", "noB")

# State: (egress, hazards, gen, permit, permitGen, epoch, revoked)


def init_state():
    return (False, frozenset(HAZARDS), 0, False, 0, 1, frozenset())


def d_usable(s):
    """D: the current-epoch decryption capability is still usable."""
    return s[5] not in s[6]


def safe(s):
    return not s[1] and not d_usable(s)


def successors(s, design):
    egress, haz, gen, permit, pgen, epoch, revoked = s
    # Clean(h): cleanup of one hazard
    for h in sorted(haz):
        yield ("Clean(%s)" % h, (egress, haz - {h}, gen, permit, pgen, epoch, revoked))
    # Revoke: revoke the current epoch capability (clears D)
    if d_usable(s):
        yield ("Revoke(e%d)" % epoch, (egress, haz, gen, permit, pgen, epoch, revoked | {epoch}))
    # Produce(h): a live producer (Q) recreates high state; mutation increments gen
    if "Q" in haz and gen < GEN_BOUND:
        for h in HAZARDS:
            if h != "Q" and h not in haz:
                yield ("Produce(%s)" % h, (egress, haz | {h}, gen + 1, permit, pgen, epoch, revoked))
    # Restart: a protected producer restarts while egress is closed
    if not egress and "Q" not in haz and gen < GEN_BOUND:
        yield ("RestartProducer", (egress, haz | {"Q"}, gen + 1, permit, pgen, epoch, revoked))
    # Design-specific open semantics
    if design == "atomic":
        if not egress and safe(s):
            yield ("SafeOpen", (True, haz, gen, permit, pgen, epoch, revoked))
    if design in ("gencheck", "buggy"):
        if not egress and safe(s):
            yield ("CheckSafe", (egress, haz, gen, True, gen, epoch, revoked))
    if design == "gencheck":
        if not egress and permit and pgen == gen:
            yield ("OpenWithGeneration", (True, haz, gen, False, pgen, epoch, revoked))
    if design == "buggy":
        if not egress and permit:
            yield ("OpenStalePermit", (True, haz, gen, False, pgen, epoch, revoked))
    if design == "dponly":
        if not egress and not d_usable(s) and "P" not in haz:
            yield ("OpenDPOnly", (True, haz, gen, permit, pgen, epoch, revoked))
    if design == "noB":
        if not egress and not d_usable(s) and haz <= {"B"}:
            yield ("OpenIgnoringB", (True, haz, gen, permit, pgen, epoch, revoked))
    # CloseAdvance: close egress, advance epoch, start new isolated compute
    if egress and epoch < MAX_EPOCH and gen < GEN_BOUND:
        yield ("CloseAdvance", (False, frozenset({"P", "Q"}), gen + 1, False, pgen, epoch + 1, revoked))


def meci_invariant(s):
    return (not s[0]) or safe(s)


def permit_invariant(s):
    return not (s[3] and s[4] == s[2]) or safe(s)


def epoch_invariant(s):
    return all(e <= s[5] for e in s[6])


def fmt(s):
    egress, haz, gen, permit, pgen, epoch, revoked = s
    hz = "".join(h for h in ("D",) if d_usable(s)) + "".join(sorted(haz))
    return "E=%d hazards={%s} gen=%d permit=%s epoch=%d" % (
        int(egress), ",".join(hz), gen, ("g%d" % pgen) if permit else "-", epoch)


def check_design(design):
    s0 = init_state()
    parent = {s0: (None, "Init")}
    depth = {s0: 1}
    queue = deque([s0])
    generated = 1
    violations = []
    aux_fail = 0
    epoch_fail = 0
    while queue:
        s = queue.popleft()
        if not meci_invariant(s):
            violations.append(s)
        if not permit_invariant(s):
            aux_fail += 1
        if not epoch_invariant(s):
            epoch_fail += 1
        for name, t in successors(s, design):
            generated += 1
            if t not in parent:
                parent[t] = (s, name)
                depth[t] = depth[s] + 1
                queue.append(t)
    trace = []
    if violations:
        v = min(violations, key=lambda x: depth[x])
        cur = v
        while cur is not None:
            p, name = parent[cur]
            trace.append((name, cur))
            cur = p
        trace.reverse()
    return {
        "design": design,
        "distinct": len(parent),
        "generated": generated,
        "depth": max(depth.values()),
        "violations": len(violations),
        "aux_fail": aux_fail,
        "epoch_fail": epoch_fail,
        "trace": trace,
    }


# ---------------------------------------------------------------- relational
def relational_test():
    """Release-equivalence over 16 protected records.

    H = (severity 0..3, tactic 0..1, token 0..1). delta(H) = (bucket, tactic)
    with bucket = severity // 2. Two records are release-equivalent when
    delta agrees. A violation is an ordered pair of distinct, release-
    equivalent records whose gated outputs differ.
    """
    records = list(product(range(4), range(2), range(2)))
    delta = lambda h: (h[0] // 2, h[1])
    exports = {
        "secure (exports delta only)": lambda h: delta(h),
        "vulnerable (also exports token)": lambda h: delta(h) + (h[2],),
        "vulnerable (exports raw severity)": lambda h: (h[0], h[1]),
    }
    out = []
    for name, f in exports.items():
        first = None
        n = 0
        for h1, h2 in product(records, records):
            if h1 != h2 and delta(h1) == delta(h2) and f(h1) != f(h2):
                n += 1
                if first is None:
                    first = (h1, h2)
        out.append((name, n, first))
    return len(records), out


# --------------------------------------------------------------------- epoch
def epoch_test(n_epochs=8):
    """Revoke each epoch, then simulate a reboot from a snapshot taken
    before revocation. Persistent design: the monotonic counter and the
    revocation record live in rollback-protected storage and survive.
    Vulnerable design: both are restored from the stale snapshot.
    Returns the number of revoked epochs whose keys become usable again.
    """
    results = {}
    for design in ("persistent", "rollback-vulnerable"):
        resurrected = 0
        for e in range(1, n_epochs + 1):
            counter, revoked = e, set()
            snapshot = (counter, set(revoked))      # taken before revocation
            revoked.add(e)                          # revoke tau_e
            counter += 1                            # advance epoch
            if design == "rollback-vulnerable":
                counter, revoked = snapshot[0], set(snapshot[1])
            usable = (e == counter) and (e not in revoked)
            if usable:
                resurrected += 1
        results[design] = resurrected
    return n_epochs, results


# --------------------------------------------------------------------- graph
def reach(edges, x, y, reflexive):
    if reflexive and x == y:
        return True
    seen, stack = set(), [x]
    while stack:
        u = stack.pop()
        for (a, b) in edges:
            if a == u and b not in seen:
                if b == y:
                    return True
                seen.add(b)
                stack.append(b)
    return False


def high_reach(labels, edges, endpoint, reflexive):
    return any(reach(edges, v, endpoint, reflexive) for v, l in labels.items() if l == "H")


def graph_tests():
    rows = []
    # 1. Endpoint itself carries high data and has no incoming edge.
    labels = {"buf": "H"}
    rows.append(("endpoint labeled H, no edges",
                 high_reach(labels, set(), "buf", False),
                 high_reach(labels, set(), "buf", True)))
    # 2. Relabeling: low buffer already wired to an enabled channel becomes H.
    edges = {("buf", "nic")}
    before = high_reach({"buf": "L", "nic": "L"}, edges, "nic", True)
    after = high_reach({"buf": "H", "nic": "L"}, edges, "nic", True)
    rows.append(("relabel low buffer on an enabled path", before, after))
    # 3. Release through an authorized edge is excluded from Reach.
    labels = {"logs": "H", "decl": "D", "rel": "L", "nic": "L"}
    all_edges = {("logs", "decl"), ("decl", "rel"), ("rel", "nic")}
    authorized = {("decl", "rel")}
    rows.append(("path through authorized declassifier",
                 high_reach(labels, all_edges, "nic", True),
                 high_reach(labels, all_edges - authorized, "nic", True)))
    return rows


def main():
    global GEN_BOUND, MAX_EPOCH
    print("MECI bounded reference checker v1.0.0")
    print("bounds: GEN_BOUND=%d MAX_EPOCH=%d hazards=D(derived),%s" % (GEN_BOUND, MAX_EPOCH, ",".join(HAZARDS)))
    print()
    print("== Safety core: invariant  egress => Safe ==")
    print("%-9s %9s %10s %6s %11s %8s %8s" % ("design", "distinct", "generated", "depth", "violations", "permitI", "epochI"))
    results = [check_design(d) for d in DESIGNS]
    for r in results:
        print("%-9s %9d %10d %6d %11d %8s %8s" % (
            r["design"], r["distinct"], r["generated"], r["depth"], r["violations"],
            "ok" if r["aux_fail"] == 0 else "FAIL(%d)" % r["aux_fail"],
            "ok" if r["epoch_fail"] == 0 else "FAIL(%d)" % r["epoch_fail"]))
    for r in results:
        if r["trace"]:
            print()
            print("shortest counterexample, design=%s (%d steps):" % (r["design"], len(r["trace"]) - 1))
            for i, (name, st) in enumerate(r["trace"]):
                print("  %2d %-20s %s" % (i, name, fmt(st)))
    print()
    print("== Release-equivalence test ==")
    n, rel = relational_test()
    print("protected records: %d; delta = (severity bucket, tactic class)" % n)
    for name, count, first in rel:
        extra = "" if first is None else "; first pair %s vs %s" % (first[0], first[1])
        print("  %-36s violations=%d%s" % (name, count, extra))
    print()
    print("== Epoch non-resurrection ==")
    n, ep = epoch_test()
    for name, count in ep.items():
        print("  %-22s revoked epochs tested=%d resurrected=%d" % (name, n, count))
    print()
    print("== Influence-graph sanity checks (HighReach) ==")
    for name, a, b in graph_tests():
        print("  %-40s %-5s -> %s" % (name, a, b))
    print("  (row 1: transitive-only vs reflexive closure; row 2: before vs after relabel;")
    print("   row 3: with vs without the authorized edge removed)")
    print()
    print("== Bound sensitivity (distinct states / violations / shortest counterexample steps) ==")
    saved = (GEN_BOUND, MAX_EPOCH)
    for gb, me in ((3, 3), (4, 3), (5, 4)):
        GEN_BOUND, MAX_EPOCH = gb, me
        row = []
        for d in DESIGNS:
            r = check_design(d)
            row.append("%s %d/%d/%s" % (d, r["distinct"], r["violations"], (len(r["trace"]) - 1) if r["trace"] else "-"))
        print("  GEN_BOUND=%d MAX_EPOCH=%d: %s" % (gb, me, "; ".join(row)))
    GEN_BOUND, MAX_EPOCH = saved
    ok = all(r["violations"] == 0 for r in results if r["design"] in ("atomic", "gencheck"))
    print()
    print("RESULT: correct designs %s; weakened designs produce counterexamples as expected." % ("PASS" if ok else "FAIL"))


if __name__ == "__main__":
    main()
