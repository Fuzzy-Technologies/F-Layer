"""Validate and dispatch closed protocol guest operations without accepting paths, commands or caller-selected dependencies."""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path
from typing import Any

MAX_OPERATION_BYTES = 1024 * 1024
MAX_RESULT_BYTES = 65536
READ_ACTIONS = frozenset({"authority-status", "cache-status", "input-status", "native-status", "services"})
WRITE_ACTIONS = frozenset({"reserve", "expose", "cancel", "input-prepare", "input-apply", "input-rollback", "native-apply", "native-rollback", "complete"})
_COMPOSITE = frozenset({"cache-status", "input-status", "input-prepare", "input-apply", "input-rollback", "native-status", "native-apply", "native-rollback"})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9-]{0,62}\Z")
_NATIVE_PHASES = {
    "enable": frozenset({"ready", "publishing", "starting", "active", "removing-candidate", "stopping-candidate", "rolled-back", "restarting-active", "recovery-required"}),
    "disable": frozenset({"ready", "removing-original", "stopping-original", "inactive", "unchanged", "restored", "publishing", "starting",
                          "removing-candidate", "stopping-candidate", "restarting-restored", "recovery-required"}),
}


class RpcError(ValueError):
    """A fixed operation/response diagnostic without private input or native output."""


def Json(value: object) -> bytes:
    """Keep the transport's public control records canonical across controller and standalone receiver."""

    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def Decode(content: bytes, *, limit: int) -> dict[str, Any]:
    """Reject oversized, ambiguous and nonstandard JSON before interpreting control fields."""

    def Unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Require one field interpretation at every nesting level."""

        result: dict[str, object] = {}

        for key, value in pairs:
            if key in result:
                raise ValueError

            result[key] = value

        return result

    def Nonfinite(value: str) -> None:
        """Refuse NaN and Infinity without retaining parser input in an exception."""

        raise ValueError

    parsed = None

    try:
        if type(content) is not bytes or not 1 <= len(content) <= limit:
            raise ValueError

        value = json.loads(content, object_pairs_hook=Unique, parse_constant=Nonfinite)

        if type(value) is not dict:
            raise ValueError

        parsed = value

    except (ValueError, TypeError, UnicodeError, RecursionError):
        pass

    if parsed is None:
        raise RpcError("Protocol RPC JSON is invalid, ambiguous or exceeds its bound")

    return parsed


def Identity(value: object) -> dict[str, str]:
    """Bind one full stack identity before deriving a guest namespace or accepting mutation consent."""

    if (type(value) is not dict or set(value) != {"project", "stack", "provider", "scope_id", "owner_id"}
            or any(type(item) is not str for item in value.values())
            or any(_NAME.fullmatch(value[key]) is None for key in ("project", "stack", "provider", "owner_id"))
            or not 1 <= len(value["scope_id"]) <= 256 or any(not 33 <= ord(item) <= 126 for item in value["scope_id"])):
        raise RpcError("Protocol RPC requires one complete bounded stack identity")

    return dict(value)


def _Bundles(value: object) -> list[dict[str, Any]]:
    """Decode only retained server-role bytes; supplied installers remain data and can never select receiver code."""

    if type(value) is not list or len(value) > 2:
        raise RpcError("Protocol RPC requires bounded unrelated server sources")

    result = []

    for bundle in value:
        if (type(bundle) is not dict or set(bundle) != {"protocol", "name", "files"} or type(bundle["protocol"]) is not str
                or bundle["protocol"] not in {"amneziawg", "vless-reality"} or type(bundle["name"]) is not str
                or type(bundle["files"]) is not dict or not 1 <= len(bundle["files"]) <= 5
                or any(type(name) is not str or type(content) is not str for name, content in bundle["files"].items())):
            raise RpcError("Protocol RPC server source envelope is malformed")

        files = {}

        failed = False

        try:
            for name, content in bundle["files"].items():
                data = base64.b64decode(content, validate=True)

                if not 1 <= len(data) <= 1048576 or base64.b64encode(data).decode("ascii") != content:
                    raise ValueError

                files[name] = data

        except (ValueError, UnicodeError):
            failed = True

        if failed:
            raise RpcError("Protocol RPC server source encoding is invalid")

        result.append({"protocol": bundle["protocol"], "name": bundle["name"], "files": files})

    return result


def Request(modules: Any, value: object) -> dict[str, Any]:
    """Validate the complete operation before guest I/O, including exact scope, owner, plan and closed backend models."""

    fields = {"schema_version", "identity", "action", "allow_mutation", "scope_confirm", "intent", "body",
              "expected_reservation_sha256", "sources", "bundles"}

    if (type(value) is not dict or set(value) != fields or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["action"]) is not str or value["action"] not in READ_ACTIONS | WRITE_ACTIONS
            or type(value["allow_mutation"]) is not bool or type(value["scope_confirm"]) is not str
            or type(value["expected_reservation_sha256"]) is not str or type(value["sources"]) is not list
            or len(Json(value)) > MAX_OPERATION_BYTES):
        raise RpcError("Protocol RPC operation is malformed or unsupported")

    identity = Identity(value["identity"])
    action = value["action"]

    if (action in WRITE_ACTIONS and (value["allow_mutation"] is not True or value["scope_confirm"] != identity["scope_id"])
            or action in READ_ACTIONS and (value["allow_mutation"] or value["scope_confirm"])
            or action == "expose" and _HASH.fullmatch(value["expected_reservation_sha256"]) is None
            or action != "expose" and value["expected_reservation_sha256"]):
        raise RpcError("Protocol RPC requires exact action-specific consent, scope and reservation preconditions")

    intent = None

    if action != "services":
        intent = modules.authority.Intent(value["intent"])
        owner = modules.guest._Digest(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode())

        if intent["owner"] != owner:
            raise RpcError("Protocol RPC intent belongs to another complete owner")

    elif value["intent"] is not None:
        raise RpcError("Unrelated service observation accepts no protocol mutation intent")

    if action in _COMPOSITE:
        if action.startswith("input-"):
            request, policies = modules.inputs.Request(modules.guest, modules.policy, value["body"], intent)

        else:
            request = modules.cache.Request(modules.guest, modules.policy, value["body"], intent)
            policies = modules.policy.Transition(request["input"])

        if Json(policies[0]["identity"]) != Json(identity):
            raise RpcError("Protocol RPC composite belongs to another stack identity")

        if action.startswith("native-") and request["generation"]["schema_version"] != 3:
            raise RpcError("Native protocol RPC requires the sealed generation contract")

    elif action == "complete":
        candidate = modules.completion.Candidate(modules.guest, modules.authority, modules.policy, modules.cache, value["body"], intent)

        if Json(candidate["metadata"]["identity"]) != Json(identity) or Json(candidate["metadata"]["sources"]) != Json(value["sources"]):
            raise RpcError("Protocol RPC completion has a different source selection or identity")

    elif value["body"] is not None:
        raise RpcError("Protocol RPC action accepts no composite or command body")

    bundles = _Bundles(value["bundles"])

    if action in {"complete", "services"}:
        modules.services.ServiceObserver(modules.guest, modules.authority, modules.completion, modules.runtime, modules.vless,
                                         identity, value["sources"], bundles)

    elif value["sources"] or bundles:
        raise RpcError("Protocol RPC action accepts no private service sources")

    return {**value, "identity": identity, "intent": intent, "decoded_bundles": bundles}


def _Hashes(value: dict[str, Any], fields: set[str], *, empty: set[str] | None = None) -> bool:
    """Accept only public hex digests, never free-form native output or encoded private keys."""

    return all(type(value[key]) is str and (value[key] == "" and key in (empty or set()) or _HASH.fullmatch(value[key]) is not None) for key in fields)


def _InputResult(modules: Any, operation: dict[str, Any], value: dict[str, Any]) -> bool:
    """Reconstruct the exact input journal and terminal boot proof from its bounded public compiler witnesses."""

    if (set(value) != {"status", "phase", "journal_sha256", "boot_sha256", "native_sha256", "fingerprints"} or value["status"] != "host-input"
            or type(value["phase"]) is not str or value["phase"] not in {"prepared", "applying", "applied", "rolling-back", "rolled-back"}
            or type(value["fingerprints"]) is not list or len(value["fingerprints"]) != 3
            or any(type(item) is not str or _HASH.fullmatch(item) is None for item in value["fingerprints"])
            or not _Hashes(value, {"journal_sha256", "boot_sha256", "native_sha256"}, empty={"boot_sha256", "native_sha256"})):
        return False

    phase = value["phase"]

    if operation["action"] in {"input-apply", "input-rollback"} and phase != ("applied" if operation["action"] == "input-apply" else "rolled-back"):
        return False

    policy, inputs = modules.policy, modules.inputs
    request, values = inputs.Request(modules.guest, policy, operation["body"], operation["intent"])
    record = {**inputs._Expected(policy, operation["intent"], request, value["fingerprints"]), "phase": phase}
    index = {"prepared": 0, "applied": 1, "rolled-back": 2}.get(phase)
    boot = policy.Digest(policy.Boot(values[index])) if index is not None else ""
    native = value["fingerprints"][index] if index is not None else ""

    return bool(value["journal_sha256"] == policy.Digest(policy.Json(record)) and value["boot_sha256"] == boot and value["native_sha256"] == native)


def _NativeResult(modules: Any, operation: dict[str, Any], value: dict[str, Any]) -> bool:
    """Bind histories and terminal journal hashes to the exact reserved native plan and action-specific state machine."""

    action, request, intent = operation["action"], operation["body"], operation["intent"]
    change = request["generation"]["change"]
    fields = {"history_sha256"} if action == "native-status" else {"history_sha256", "journal_sha256"}
    phases = _NATIVE_PHASES[change] if action == "native-status" else {"active"} if change == "enable" else {"inactive"}

    if action == "native-rollback":
        phases = {"rolled-back"} if change == "enable" else {"restored", "unchanged"}

    if (set(value) != {"status", "phase", *fields} or value["status"] != "native-generation" or type(value["phase"]) is not str
            or value["phase"] not in phases or not _Hashes(value, fields)):
        return False

    guest = modules.guest
    original = guest._ProtocolHistory(intent, request)
    fresh = guest._Digest(guest._Encode(guest._GenerationAudit(intent, request)))
    phase = value["phase"]
    histories = ({original} if phase in {"ready", "unchanged", "removing-original", "stopping-original", "inactive"}
                 else {original, fresh} if phase in {"publishing", "removing-candidate", "recovery-required"} else {fresh})

    if value["history_sha256"] not in histories:
        return False

    record = {"schema_version": 1, "intent": intent, "request": request, "history_sha256": original,
              "admitted_program_sha256": request["generation"]["candidate_receipt"]["files"]["lifecycle.py"], "phase": phase,
              "rollback": action == "native-rollback"}

    return bool(action == "native-status" or value["journal_sha256"] == guest._Digest(guest._Encode(record)))


def _InputWitness(modules: Any, operation: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
    """Re-read only the fixed locked journal; a concurrent advance refuses instead of inventing a witness for an earlier reply."""

    guest, authority, inputs, policy = modules.guest, modules.authority, modules.inputs, modules.policy

    with authority._Locks(guest, readOnly=True):
        value = authority._Decode(guest, authority._Root(guest) / "input.json")
        fingerprints = value.get("fingerprints")

        if type(fingerprints) is not list or len(fingerprints) != 3 or any(type(item) is not str or _HASH.fullmatch(item) is None for item in fingerprints):
            raise RpcError("Protocol RPC input witness is incomplete")

        record = inputs._Load(guest, authority, inputs._Expected(policy, operation["intent"], operation["body"], fingerprints))
        values = policy.Transition(operation["body"]["input"])

        if record != value or inputs._Result(policy, values, record) != result:
            raise RpcError("Protocol RPC input journal advanced before its exact witness could be returned")

    return {**result, "fingerprints": fingerprints}


def Result(modules: Any, operation: dict[str, Any], value: object) -> dict[str, Any]:
    """Close each response shape and bind completion/services to their exact request before any bytes can leave the guest."""

    if type(value) is not dict or len(Json(value)) > MAX_RESULT_BYTES:
        raise RpcError("Protocol RPC result is malformed or exceeds its bound")

    action = operation["action"]
    valid = False

    if action == "complete":
        expected = modules.completion.Candidate(modules.guest, modules.authority, modules.policy, modules.cache, operation["body"], operation["intent"])["record"]
        valid = Json(value) == Json(expected)

    elif action == "services":
        sources = [source for source in operation["sources"] if source["pin"]["protocol"] != "wireguard"]
        valid = set(value) == {"status", "services"} and value["status"] == "services" and type(value["services"]) is list and len(value["services"]) == len(sources)

        if valid:
            for proof, source in zip(value["services"], sources):
                if (type(proof) is not dict or set(proof) != {"protocol", "source_sha256", "state", "receipt_sha256", "absence_sha256"}
                        or proof["protocol"] != source["pin"]["protocol"] or proof["source_sha256"] != source["pin"]["server_digest"]
                        or type(proof["state"]) is not str or proof["state"] not in {"active", "absent"}
                        or not _Hashes(proof, {"source_sha256", "receipt_sha256", "absence_sha256"}, empty={"receipt_sha256", "absence_sha256"})
                        or bool(proof["receipt_sha256"]) != (proof["state"] == "active") or bool(proof["absence_sha256"]) != (proof["state"] == "absent")):
                    valid = False

    elif action == "authority-status":
        valid = (set(value) == {"status", "authority_sha256", "history_sha256", "phase", "reservation_sha256", "completion_count"}
                 and value["status"] == "protocol-authority" and type(value["phase"]) is str
                 and value["phase"] in {"initial", "preparing", "reserved", "exposed", "cancelling", "cancelled", "completed"}
                 and type(value["completion_count"]) is int and 0 <= value["completion_count"] <= modules.authority.MAX_COMPLETIONS
                 and _Hashes(value, {"authority_sha256", "history_sha256", "reservation_sha256"}, empty={"reservation_sha256"})
                 and bool(value["reservation_sha256"]) == (value["phase"] in {"preparing", "reserved", "exposed", "cancelling"}))

    elif action in {"reserve", "expose", "cancel"}:
        fields = ({"reservation_sha256", "history_sha256", "authority_sha256"} if action == "reserve"
                  else {"reservation_sha256", "history_sha256"} if action == "expose" else {"authority_sha256", "history_sha256"})
        valid = set(value) == {"status", *fields} and value["status"] == {"reserve": "reserved", "expose": "exposed", "cancel": "cancelled"}[action] and _Hashes(value, fields)

    elif action == "cache-status":
        valid = (set(value) == {"status", "phase", "journal_sha256", "history_sha256"} and value["status"] == "generation-cache"
                 and type(value["phase"]) is str and value["phase"] in {"preparing", "prepared"} and _Hashes(value, {"journal_sha256", "history_sha256"}))

        if valid:
            history = modules.guest._ProtocolHistory(operation["intent"], operation["body"])
            record = {**modules.cache._Expected(modules.guest, operation["intent"], operation["body"], history), "phase": value["phase"]}
            valid = value["history_sha256"] == history and value["journal_sha256"] == modules.guest._Digest(modules.guest._Encode(record))

    elif action.startswith("input-"):
        valid = _InputResult(modules, operation, value)

    elif action.startswith("native-"):
        valid = _NativeResult(modules, operation, value)

    if not valid:
        raise RpcError("Protocol RPC returned an unknown, rebound or private-bearing response")

    return value


def Dispatch(modules: Any, value: object) -> dict[str, Any]:
    """Route only validated fixed actions to package-selected dependencies; transport supplies no ordering or cloud mutation authority."""

    operation = Request(modules, value)
    guest, peer, authority, policy = modules.guest, modules.peer, modules.authority, modules.policy
    inputs, cache, runtime = modules.inputs, modules.cache, modules.runtime
    action, intent, body = operation["action"], operation["intent"], operation["body"]

    if action == "authority-status":
        result = authority.Status(guest, peer, intent)

    elif action == "reserve":
        result = authority.Reserve(guest, peer, intent, allowMutation=True)

    elif action == "expose":
        result = authority.Expose(guest, peer, intent, operation["expected_reservation_sha256"], allowMutation=True)

    elif action == "cancel":
        result = authority.Cancel(guest, peer, intent, allowMutation=True)

    elif action == "cache-status":
        result = cache.Status(guest, peer, authority, policy, body, intent, runtimeBackend=runtime)

    elif action.startswith("input-"):
        arguments = {"generationCache": cache if body["schema_version"] == 2 else None, "runtimeBackend": runtime if body["schema_version"] == 2 else None}

        if action == "input-status":
            result = inputs.Status(guest, peer, authority, policy, body, intent, **arguments)

        elif action == "input-prepare":
            result = inputs.Prepare(guest, peer, authority, policy, body, intent, allowMutation=True, **arguments)

        else:
            result = inputs.Apply(guest, peer, authority, policy, body, intent, allowMutation=True, rollback=action == "input-rollback", **arguments)

        result = _InputWitness(modules, operation, result)

    elif action == "native-status":
        result = runtime.Status(guest, peer, authority, policy, cache, body, intent)

    elif action in {"native-apply", "native-rollback"}:
        program = guest._Read(Path(guest.__file__), limit=1048576)
        result = runtime.Execute(guest, peer, authority, policy, inputs, cache, body, intent, expectedProgramSha256=guest._Digest(program),
                                 allowMutation=True, rollback=action == "native-rollback")

    else:
        observer = modules.services.ServiceObserver(guest, authority, modules.completion, runtime, modules.vless,
                                                     operation["identity"], operation["sources"], operation["decoded_bundles"])

        if action == "services":
            with authority._Locks(guest, readOnly=True):
                with observer.Pinned():
                    result = {"status": "services", "services": observer.Observe(guest, operation["sources"])}

        else:
            result = modules.completion.Complete(guest, peer, authority, policy, inputs, cache, runtime, body, intent, allowMutation=True, serviceObserver=observer)

    return Result(modules, operation, result)
