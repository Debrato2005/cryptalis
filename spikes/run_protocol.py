"""S2: bounded state exploration; no AWS or production package imports."""
from collections import deque
from dataclasses import dataclass, replace
import json
from pathlib import Path


@dataclass(frozen=True)
class State:
    # 0=not registered, 1=registered, 2=fenced, 3=admitted,
    # 4=commit sent, 5=backend terminal, 6=outcome reconciled/ownership closed.
    phases: tuple = (0, 0)
    alive: tuple = (True, True)
    locks: tuple = (False, False)
    registered: tuple = (False, False)
    markers: tuple = (False, False)
    data_commits: tuple = (False, False)
    known: tuple = (None, None)
    publications: tuple = (False, False)
    denied: bool = False
    complete: bool = False
    db_token: int = 0


def assign(values, i, value):
    return values[:i] + (value,) + values[i + 1:]


def successors(s):
    if not s.denied:
        yield "deny", replace(s, denied=True)
    if s.denied and not s.complete and not any(s.registered) and not any(s.locks):
        yield "complete-denial", replace(s, complete=True, db_token=1)
    for i, p in enumerate(s.phases):
        if s.alive[i] and 0 < p < 6:
            yield f"crash-{i}", replace(s, alive=assign(s.alive, i, False))
        if p == 0 and not s.denied and s.alive[i]:
            yield f"register-{i}", replace(s, phases=assign(s.phases, i, 1),
                                          registered=assign(s.registered, i, True))
        if p == 1:
            if s.alive[i] and not s.denied:
                yield f"fence-{i}", replace(s, phases=assign(s.phases, i, 2),
                                            locks=assign(s.locks, i, True))
            if s.denied or not s.alive[i]:
                yield f"reject-before-admission-{i}", replace(s, phases=assign(s.phases, i, 6),
                                                               registered=assign(s.registered, i, False))
        if p == 2:
            if s.alive[i] and not s.denied and s.locks[i]:
                yield f"observe-authority-{i}", replace(s, phases=assign(s.phases, i, 3))
            if s.denied or not s.alive[i] or not s.locks[i]:
                yield f"close-unadmitted-{i}", replace(s, phases=assign(s.phases, i, 6),
                                                        locks=assign(s.locks, i, False),
                                                        registered=assign(s.registered, i, False))
        if p == 3:
            if s.alive[i] and s.locks[i]:
                # Existing registered admission may finish while denial is PENDING.
                assert s.db_token == 0 and not s.complete
                yield f"send-commit-{i}", replace(s, phases=assign(s.phases, i, 4))
                yield f"publish-read-{i}", replace(s, phases=assign(s.phases, i, 6),
                                                    publications=assign(s.publications, i, True),
                                                    locks=assign(s.locks, i, False),
                                                    registered=assign(s.registered, i, False))
            else:
                yield f"abort-before-send-{i}", replace(s, phases=assign(s.phases, i, 6),
                                                       locks=assign(s.locks, i, False),
                                                       registered=assign(s.registered, i, False))
        if p == 4:
            # An absent marker while this backend can still commit means UNKNOWN.
            assert s.known[i] is None
            for committed in (False, True):
                yield f"backend-terminal-{i}-{committed}", replace(
                    s, phases=assign(s.phases, i, 5), locks=assign(s.locks, i, False),
                    markers=assign(s.markers, i, committed),
                    data_commits=assign(s.data_commits, i, committed))
        if p == 5:
            yield f"reconcile-{i}", replace(s, phases=assign(s.phases, i, 6),
                                            known=assign(s.known, i, s.markers[i]),
                                            registered=assign(s.registered, i, False))
        if p in (2, 3) and s.locks[i]:
            # Backend lock loss does not clear registered worker ownership.
            yield f"lock-loss-{i}", replace(s, locks=assign(s.locks, i, False))


def invariant(s):
    assert s.markers == s.data_commits, "Data and durable outcome split"
    if s.complete:
        assert not any(s.registered) and not any(s.locks), "Premature denial completion"
    for i, known in enumerate(s.known):
        if known is not None:
            assert known == s.data_commits[i], "False commit classification"


def explore():
    start = State()
    queue = deque([start]); seen = {start}; transitions = 0
    counterexample_to_lock_only_drain = None
    while queue:
        s = queue.popleft(); invariant(s)
        if s.denied and not any(s.locks) and any(s.registered):
            counterexample_to_lock_only_drain = repr(s)
        for action, n in successors(s):
            transitions += 1; invariant(n)
            if action.startswith("publish-read"):
                assert not s.complete and any(s.locks), "Publication after completed denial"
            if n not in seen:
                seen.add(n); queue.append(n)
    assert counterexample_to_lock_only_drain is not None
    assert any(s.complete for s in seen)
    assert any(s.known == (True, False) for s in seen)
    return len(seen), transitions, counterexample_to_lock_only_drain


def effect_ownership_checks():
    # Fake authority validates a monotonic owner token. Expiry is not transfer.
    current = {"token": 1, "owner": "A", "alive": True, "action": "RESERVED", "effects": 0}
    def dispatch(owner, token):
        if owner != current["owner"] or token != current["token"]:
            return "DENIED"
        if current["action"] != "RESERVED":
            return "RECONCILE"
        current["action"] = "IN_FLIGHT"; current["effects"] += 1
        return "DISPATCHED"
    assert dispatch("B", 1) == "DENIED"
    assert dispatch("A", 0) == "DENIED"
    assert dispatch("A", 1) == "DISPATCHED"
    assert dispatch("A", 1) == "RECONCILE"
    # No token takeover while the old worker or external action remains live.
    takeover_allowed = not current["alive"] and current["action"] == "TERMINAL"
    assert not takeover_allowed
    current.update(alive=False, action="TERMINAL", owner="B", token=2)
    assert dispatch("A", 1) == "DENIED"
    assert current["effects"] == 1
    return {"stale_owner": "DENIED", "expiry_takeover": "DENIED", "repeat_dispatch": "RECONCILE"}


def capacity_checks():
    def preflight(live_calls, live_bytes, target_calls, target_bytes, retry_calls,
                  mirror_calls, observed_window_writes):
        if live_calls + retry_calls > target_calls or live_bytes > target_bytes:
            return "DENIED_CAPACITY"
        if observed_window_writes > mirror_calls:
            return "FINALIZE_BEFORE_WRITERS"
        return "ADMITTED"
    assert preflight(9, 9, 8, 16, 0, 8, 1) == "DENIED_CAPACITY"
    assert preflight(7, 3, 8, 16, 2, 8, 1) == "DENIED_CAPACITY"
    assert preflight(3, 3, 8, 16, 1, 0, 1) == "FINALIZE_BEFORE_WRITERS"
    assert preflight(3, 3, 8, 16, 1, 3, 2) == "ADMITTED"
    return ["oversized_live_set", "burned_retry_headroom", "exhausted_rollback_mirror"]


def recovery_checks():
    # Small fake command engine, not the production CLI or AWS behavior.
    state = {"target": "owned-fixture", "digest": "frozen", "phase": "PREPARED",
             "steps": set(), "denied": True, "owner_terminal": False}
    def command(action, target="owned-fixture", digest="frozen"):
        if target != state["target"] or digest != state["digest"]: return "DENIED_IDENTITY"
        if action == "reconcile": return "UNKNOWN" if not state["owner_terminal"] else state["phase"]
        if not state["owner_terminal"]: return "PENDING"
        if action == "abort":
            if state["phase"] == "SWITCHED": return "IrreversibleState"
            state["phase"] = "ABORTED"; return "ABORTED"
        if action == "resume":
            if state["phase"] == "ABORTED": return "DENIED_ABORTED"
            state["steps"].add("original-owned-chunk"); state["phase"] = "SWITCHED"
            return "SWITCHED"
        if action == "recover": return "DENIED_UNPROVABLE_HISTORY"
        raise AssertionError("Unknown fake command")
    assert command("reconcile") == "UNKNOWN"
    assert command("resume") == "PENDING"
    state["owner_terminal"] = True
    assert command("resume", target="wrong") == "DENIED_IDENTITY"
    assert command("resume", digest="edited") == "DENIED_IDENTITY"
    assert command("resume") == command("resume") == "SWITCHED"
    assert len(state["steps"]) == 1
    assert command("abort") == "IrreversibleState"
    assert command("recover") == "DENIED_UNPROVABLE_HISTORY" and state["denied"]
    state["phase"] = "PREPARED"
    assert command("abort") == command("abort") == "ABORTED" and state["denied"]
    return ["repeat_resume_one_effect", "repeat_abort_retains_denial", "unknown_owner_pending",
            "wrong_target_digest_denied", "post_switch_abort_denied", "unprovable_recovery_denied"]


if __name__ == "__main__":
    states, edges, mutant = explore()
    result = {"spike": "S2", "status": "PASS_LOCAL_MODEL", "states": states,
              "transitions": edges, "lock_only_drain_counterexample": mutant,
              "effect_checks": effect_ownership_checks(), "capacity_checks": capacity_checks(),
              "recovery_checks": recovery_checks(),
              "limits": ["two operations", "atomic fake authority", "no AWS semantics or IAM",
                         "no proof of worker termination", "not Cryptalis runtime verification"]}
    out = Path(__file__).parent / "results"; out.mkdir(exist_ok=True)
    (out / "S2.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
