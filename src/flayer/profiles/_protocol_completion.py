"""Bind verified native/input/service facts to an immutable common completion before retiring its reservation."""

from __future__ import annotations

import os
import re
import stat
from contextlib import ExitStack, nullcontext
from typing import Any

_PROTOCOLS = ("amneziawg", "vless-reality", "wireguard")
_METADATA = {"schema_version", "identity", "creation_sha256", "parent", "closed_peer_head", "closed_peer_head_sha256", "closed_peer_count",
             "previous_state_sha256", "sources", "configured_listeners", "active_protocols", "static_fingerprint", "wireguard_receipt_sha256",
             "wireguard_history_sha256", "generation_receipt_sha256", "reservation", "authority_parent", "ingress_intents", "cloud_sha256",
             "input_sha256", "services_sha256", "generation", "native_sha256"}


class CompletionError(ValueError):
    """A bounded completion diagnostic without private runtime/configuration bytes or native output."""


def _Pointer(authority: Any, value: object, pattern: str) -> dict[str, str] | None:
    """Validate public graph locators without interpreting any locator as a guest filesystem path."""

    if value is None:
        return None

    if (type(value) is not dict or set(value) != {"name", "sha256"} or type(value["name"]) is not str
            or re.fullmatch(pattern, value["name"]) is None or not authority._Hash(value["sha256"])):
        raise ValueError

    return dict(value)


def _Sources(guest: Any, authority: Any, identity: dict[str, str], values: object) -> list[dict[str, Any]]:
    """Retain complete source identity and confined role references, independently of any private projection bodies."""

    if type(values) is not list or not 1 <= len(values) <= 3:
        raise ValueError

    result = []

    for source in values:
        if (type(source) is not dict or set(source) != {"schema_version", "identity", "pin", "kind", "request_name", "request_sha256"}
                or type(source["schema_version"]) is not int or source["schema_version"] != 1
                or guest._Encode(source["identity"]) != guest._Encode(identity) or type(source["pin"]) is not dict
                or set(source["pin"]) != {"protocol", "intent_fingerprint", "material_digest", "server_digest"}
                or type(source["pin"]["protocol"]) is not str or source["pin"]["protocol"] not in _PROTOCOLS
                or any(not authority._Hash(source["pin"][key]) for key in ("intent_fingerprint", "material_digest", "server_digest"))
                or type(source["kind"]) is not str or source["kind"] not in {"initial", "peer", "protocol"}
                or type(source["request_name"]) is not str or type(source["request_sha256"]) is not str):
            raise ValueError

        if source["kind"] == "initial":
            if source["request_name"] or source["request_sha256"]:
                raise ValueError

        else:
            prefix = "wp" if source["kind"] == "peer" else "tp"

            if (source["kind"] == "peer" and source["pin"]["protocol"] != "wireguard"
                    or len(source["request_name"]) > 63 or not authority._Hash(source["request_sha256"])
                    or re.fullmatch(re.escape(identity["stack"]) + "-" + prefix + r"-[0-9a-f]{16}", source["request_name"]) is None):
                raise ValueError

        result.append(source)

    names = [source["pin"]["protocol"] for source in result]

    if names != [name for name in _PROTOCOLS if name in names]:
        raise ValueError

    return result


def Candidate(guest: Any, authority: Any, policy: Any, cache: Any, value: object, rawIntent: object) -> dict[str, Any]:
    """Cross-bind a closed native intent and terminal witness envelope before any guest I/O; provider attestation belongs to the controller."""

    result = None

    try:
        intent = authority.Intent(rawIntent)

        if (type(value) is not dict or set(value) != {"schema_version", "metadata", "request", "input", "services", "outcome"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or type(value["outcome"]) is not str or value["outcome"] not in {"committed", "not-applied"}
                or len(guest._Encode(value)) > 131072):
            raise ValueError

        request = cache.Request(guest, policy, value["request"], intent)
        values = policy.Transition(request["input"])
        metadata, inputProof, serviceProof = value["metadata"], value["input"], value["services"]

        if (type(metadata) is not dict or set(metadata) != _METADATA or type(metadata["schema_version"]) is not int or metadata["schema_version"] != 2
                or len(guest._Encode(metadata)) > 32768 or request["generation"]["schema_version"] != 3
                or guest._Encode(metadata["reservation"]) != guest._Encode(intent) or guest._Encode(metadata["generation"]) != guest._Encode(request["generation"])
                or guest._Encode(metadata["identity"]) != guest._Encode(values[0]["identity"])
                or metadata["creation_sha256"] != intent["creation_sha256"] or metadata["previous_state_sha256"] != intent["previous_state_sha256"]
                or any(not authority._Hash(metadata[key]) for key in ("creation_sha256", "closed_peer_head_sha256", "previous_state_sha256", "static_fingerprint",
                                                                      "wireguard_history_sha256", "cloud_sha256", "input_sha256", "services_sha256", "native_sha256"))
                or any(type(metadata[key]) is not str or metadata[key] != "" and not authority._Hash(metadata[key])
                       for key in ("wireguard_receipt_sha256", "generation_receipt_sha256"))
                or type(metadata["closed_peer_count"]) is not int or not 0 <= metadata["closed_peer_count"] <= 4096):
            raise ValueError

        stack = re.escape(values[0]["identity"]["stack"])
        parent = _Pointer(authority, metadata["parent"], stack + r"-ep-[0-9a-f]{16}")
        peer = _Pointer(authority, metadata["closed_peer_head"], stack + r"-wc-[0-9a-f]{16}")
        authority._Pointer(metadata["authority_parent"])

        if (bool(peer) != bool(metadata["closed_peer_count"])
                or metadata["closed_peer_head_sha256"] != (guest._Digest(guest._Encode(peer)) if peer is not None
                                                          else parent["sha256"] if parent is not None else metadata["creation_sha256"])
                or type(metadata["ingress_intents"]) is not list or len(metadata["ingress_intents"]) > 2):
            raise ValueError

        roles = []

        for reference in metadata["ingress_intents"]:
            if type(reference) is not dict or set(reference) != {"role", "name", "sha256"} or reference["role"] not in {"change", "restoration"}:
                raise ValueError

            _Pointer(authority, {key: reference[key] for key in ("name", "sha256")}, stack + r"-ip-[0-9a-f]{16}")
            roles.append(reference["role"])

        if len(set(roles)) != len(roles):
            raise ValueError

        sources = _Sources(guest, authority, values[0]["identity"], metadata["sources"])
        names = [source["pin"]["protocol"] for source in sources]

        if (type(metadata["configured_listeners"]) is not list or [policy.Listener(item)["transport"] for item in metadata["configured_listeners"]] != names
                or type(metadata["active_protocols"]) is not list or any(type(item) is not str for item in metadata["active_protocols"])
                or metadata["active_protocols"] != [name for name in names if name in metadata["active_protocols"]]
                or type(serviceProof) is not dict or set(serviceProof) != {"schema_version", "services"}
                or type(serviceProof["schema_version"]) is not int or serviceProof["schema_version"] != 1
                or type(serviceProof["services"]) is not list or len(serviceProof["services"]) != len(sources)):
            raise ValueError

        active = metadata["active_protocols"]
        committed = value["outcome"] == "committed"
        targetPolicy = values[1 if committed else 2]
        configured = {item["transport"]: item for item in metadata["configured_listeners"]}

        if guest._Encode({item["transport"]: item for item in targetPolicy["listeners"]}) != guest._Encode({name: configured[name] for name in active}):
            raise ValueError

        for proof, source in zip(serviceProof["services"], sources):
            if (type(proof) is not dict or set(proof) != {"protocol", "source_sha256", "state", "receipt_sha256", "absence_sha256"}
                    or proof["protocol"] != source["pin"]["protocol"] or proof["source_sha256"] != source["pin"]["server_digest"]
                    or proof["state"] != ("active" if proof["protocol"] in active else "absent")
                    or type(proof["receipt_sha256"]) is not str or type(proof["absence_sha256"]) is not str
                    or proof["state"] == "active" and (not authority._Hash(proof["receipt_sha256"]) or proof["absence_sha256"] != "")
                    or proof["state"] == "absent" and (proof["receipt_sha256"] != "" or not authority._Hash(proof["absence_sha256"]))):
                raise ValueError

        if (type(inputProof) is not dict or set(inputProof) != {"schema_version", "transition", "outcome", "native_sha256", "journal_sha256", "boot_sha256"}
                or type(inputProof["schema_version"]) is not int or inputProof["schema_version"] != 1
                or guest._Encode(inputProof["transition"]) != guest._Encode(request["input"])
                or inputProof["outcome"] != ("applied" if committed else "rolled-back")
                or any(not authority._Hash(inputProof[key]) for key in ("native_sha256", "journal_sha256", "boot_sha256"))
                or inputProof["boot_sha256"] != policy.Digest(policy.Boot(targetPolicy))
                or metadata["input_sha256"] != guest._Digest(guest._Encode(inputProof))
                or metadata["services_sha256"] != guest._Digest(guest._Encode(serviceProof))):
            raise ValueError

        generation = request["generation"]
        source = next(item for item in sources if item["pin"]["protocol"] == "wireguard")
        fresh = guest._Digest(guest._Encode({**generation["candidate_receipt"], "status": "installed"}))
        original = guest._ProtocolHistory(intent, request)
        change = generation["change"]
        phase = (("active" if change == "enable" else "inactive") if committed
                 else "rolled-back" if change == "enable" else "restored" if metadata["generation_receipt_sha256"] else "unchanged")
        generated = phase in {"active", "restored", "rolled-back"}
        receipt = fresh if phase in {"active", "restored"} else intent["wireguard_receipt_sha256"] if phase == "unchanged" else ""
        history = guest._Digest(guest._Encode(guest._GenerationAudit(intent, request))) if generated else original
        native = {"schema_version": 1, "intent": intent, "request": request, "history_sha256": original,
                  "admitted_program_sha256": generation["candidate_receipt"]["files"]["lifecycle.py"], "phase": phase, "rollback": not committed}
        guest._RuntimeRecord(native, intent)
        wg = next(item for item in serviceProof["services"] if item["protocol"] == "wireguard")

        if (generation["source_sha256"] != guest._Digest(guest._Encode(source))
                or metadata["wireguard_receipt_sha256"] != receipt or metadata["generation_receipt_sha256"] != (fresh if generated else "")
                or metadata["wireguard_history_sha256"] != history or metadata["native_sha256"] != guest._Digest(guest._Encode(native))
                or wg["receipt_sha256"] != receipt or (wg["state"] == "active") != bool(receipt)
                or wg["absence_sha256"] != ("" if receipt else guest._AbsenceDigest(intent["owner"]))):
            raise ValueError

        record = authority.Completion({"schema_version": 2, "owner": intent["owner"], "creation_sha256": intent["creation_sha256"],
            "operation_id": intent["operation_id"], "intent_sha256": guest._Digest(guest._Encode(metadata)), "parent": metadata["authority_parent"],
            "previous_authority_sha256": intent["previous_authority_sha256"], "history_sha256": history, "outcome": value["outcome"]}, intent)
        result = {"intent": intent, "request": request, "metadata": metadata, "input": inputProof, "services": serviceProof,
                  "record": record, "native": native, "values": values}

    except (ValueError, TypeError, KeyError, StopIteration, RecursionError):
        pass

    if result is None:
        raise CompletionError("Native completion candidate is malformed or differs from its exact reserved terminal witnesses")

    return result


def _Files(guest: Any, authority: Any, cache: Any, candidate: dict[str, Any], *, complete: bool) -> dict[str, bytes]:
    """Validate every remaining exact sidecar before cleanup; absent sidecars are permitted only after immutable completion exists."""

    root = authority._Root(guest)
    request, intent = candidate["request"], candidate["intent"]
    generation = {**cache._Expected(guest, intent, request, guest._ProtocolHistory(intent, request)), "phase": "prepared"}
    result = {}

    for filename in ("input.json", "generation.json", "runtime.json"):
        if (root / ("." + filename + ".new")).exists() or (root / ("." + filename + ".new")).is_symlink():
            raise CompletionError("Native completion requires canonical terminal sidecars before publication or cleanup")

        path = root / filename

        if not path.exists() and not path.is_symlink():
            if not complete:
                raise CompletionError("Native completion is missing its exact terminal sidecars")

            continue

        record = authority._Decode(guest, path)
        content = guest._Encode(record)

        if (filename == "input.json" and guest._Digest(content) != candidate["input"]["journal_sha256"]
                or filename == "generation.json" and content != guest._Encode(generation)
                or filename == "runtime.json" and content != guest._Encode(candidate["native"])):
            raise CompletionError("Native completion sidecar differs from its exact verified terminal candidate")

        result[filename] = content

    return result


def _WriteCompletion(guest: Any, authority: Any, record: dict[str, Any]) -> None:
    """Append only an exact incomplete prefix; a complete immutable completion may only be verified and resynchronized."""

    root = authority._DurableRoot(guest)
    path = root / ("done-" + record["operation_id"] + ".json")
    expected = guest._Encode(record)
    created = False

    try:
        descriptor = os.open(path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True

    except FileExistsError:
        descriptor = os.open(path, os.O_RDWR | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)

    try:
        if created:
            os.fchmod(descriptor, 0o600)

        initial = os.fstat(descriptor)
        prefix = authority._CompletionPrefix(guest, record)
        linked, current = path.lstat(), os.fstat(descriptor)

        if ((initial.st_dev, initial.st_ino) != (linked.st_dev, linked.st_ino)
                or (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns)
                or os.pread(descriptor, len(expected) + 1, 0) != prefix):
            raise CompletionError("Native completion inode changed before its exact append")

        offset = len(prefix)

        while offset < len(expected):
            written = os.write(descriptor, expected[offset:])

            if written <= 0:
                raise CompletionError("Native completion prefix could not be durably finished")

            offset += written

        os.fsync(descriptor)

        if (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) != (path.lstat().st_dev, path.lstat().st_ino):
            raise CompletionError("Native completion inode changed before acknowledgment")

        authority._SyncFile(guest, path, expected)
        guest._SyncDirectory(root)

    finally:
        os.close(descriptor)


def _Retire(guest: Any, authority: Any, filename: str, expected: bytes) -> None:
    """Remove only a fixed exact owned sidecar through pinned file/directory identities; never enumerate private runtime payloads."""

    if filename not in {"input.json", "generation.json", "runtime.json", "pending.json"}:
        raise CompletionError("Unsupported native completion cleanup path")

    root = authority._Root(guest)
    path = root / filename
    with ExitStack() as cleanup:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        cleanup.callback(os.close, directory)
        descriptor = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        cleanup.callback(os.close, descriptor)
        info = os.fstat(descriptor)
        parent = os.fstat(directory)

        def Verify() -> None:
            """Reject replacement, hardlinks and namespace rebinding before unlinking the exact known sidecar."""

            current, linked, linkedParent = os.fstat(descriptor), path.lstat(), root.lstat()

            if (not stat.S_ISREG(current.st_mode) or current.st_uid != guest._ROOT_UID or current.st_nlink != 1 or stat.S_IMODE(current.st_mode) != 0o600
                    or (info.st_dev, info.st_ino) != (linked.st_dev, linked.st_ino)
                    or (info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (current.st_size, current.st_mtime_ns, current.st_ctime_ns)
                    or not stat.S_ISDIR(linkedParent.st_mode) or linkedParent.st_uid != guest._ROOT_UID or stat.S_IMODE(linkedParent.st_mode) != 0o700
                    or (parent.st_dev, parent.st_ino) != (linkedParent.st_dev, linkedParent.st_ino)
                    or os.pread(descriptor, len(expected) + 1, 0) != expected):
                raise CompletionError("Native completion cleanup found a replaced or unexplained sidecar")

        Verify()
        os.fsync(descriptor)
        Verify()
        os.unlink(filename, dir_fd=directory)
        os.fsync(directory)

        if (parent.st_dev, parent.st_ino) != (root.lstat().st_dev, root.lstat().st_ino) or path.exists() or path.is_symlink():
            raise CompletionError("Native completion namespace changed during cleanup")


def Complete(
    guest: Any, peer: Any, authority: Any, policy: Any, inputs: Any, cache: Any, runtime: Any,
    value: object, rawIntent: object, *, allowMutation: bool = False, serviceObserver: Any = None,
) -> dict[str, Any]:
    """Commit verified terminal guest witnesses once; recorded completion replay is historical metadata recovery, never a health claim."""

    candidate = Candidate(guest, authority, policy, cache, value, rawIntent)

    if allowMutation is not True:
        raise CompletionError("Native completion requires explicit mutation consent")

    intent, record, request = candidate["intent"], candidate["record"], candidate["request"]
    pointer = {"name": "done-" + intent["operation_id"] + ".json", "sha256": guest._Digest(guest._Encode(record))}

    with authority._Locks(guest, readOnly=False):
        pending = authority._Pending(guest, intent)
        head, digest, latest, count = authority._Authority(guest, intent, pending, expectedCompletion=record)
        path = authority._Root(guest) / pointer["name"]
        recorded = (path.exists() or path.is_symlink()) and authority._CompletionPrefix(guest, record) == guest._Encode(record)

        if pending is None:
            if head != pointer or latest != record or not recorded:
                raise CompletionError("No exact latest native completion exists for this reservation")

            _WriteCompletion(guest, authority, record)
            authority._Publish(guest, "head.json", pointer)

            return dict(record)

        expected = {"schema_version": 1, "intent": intent, "parent": record["parent"],
                    "deployment_sha256": request["generation"]["cached_receipt"]["deployment_sha256"] if intent["wireguard_state"] == "active" else "",
                    "phase": "exposed", "fenced": intent["wireguard_state"] == "active"}

        if (guest._Encode(pending) != guest._Encode(expected) or head not in (record["parent"], pointer)
                or head == record["parent"] and (digest != intent["previous_authority_sha256"] or count >= authority.MAX_COMPLETIONS)
                or (authority._Root(guest) / ".pending.json.new").exists() or (authority._Root(guest) / ".pending.json.new").is_symlink()
                or not recorded and ((authority._Root(guest) / ".head.json.new").exists() or (authority._Root(guest) / ".head.json.new").is_symlink())):
            raise CompletionError("Native completion does not continue its exact exposed authority or canonical prefix")

        files = _Files(guest, authority, cache, candidate, complete=recorded)

        if not recorded:
            with cache.Ready(guest, authority, policy, request, intent, guest._ProtocolHistory(intent, request)) as verify:
                native = candidate["native"]
                root, unit, _ = guest._Paths(intent["owner"], nonce=request["generation"]["candidate_receipt"]["nonce"])
                installed = {**request["generation"]["candidate_receipt"], "status": "installed"}
                active = native["phase"] in {"active", "restored", "unchanged"}

                if native["phase"] == "unchanged":
                    root, unit, _ = guest._ActivePaths(intent["owner"])
                    installed = request["generation"]["cached_receipt"]

                with runtime._Published(guest, root, unit, installed) if active else nullcontext():
                    if native["phase"] == "unchanged":
                        _, history = authority._Observe(guest, peer, intent)
                        runtime._Active(guest, guest._ActivePaths(intent["owner"])[1])

                    else:
                        history = runtime._Observe(guest, peer, authority, cache, request, intent, native)

                    if history != record["history_sha256"]:
                        raise CompletionError("Native completion has stale actual consumed history")

                    fingerprints = inputs._Compiled(guest, policy, candidate["values"])
                    inputRecord = inputs._Load(guest, authority, inputs._Expected(policy, intent, request, fingerprints))
                    phase = candidate["input"]["outcome"]

                    if inputRecord is None or inputRecord["phase"] != phase:
                        raise CompletionError("Native completion requires its exact terminal host-input transaction")

                    inputs._State(guest, policy, candidate["values"], fingerprints, phase)
                    observed = inputs._Result(policy, candidate["values"], inputRecord)

                    if any(observed[key] != candidate["input"][key] for key in ("journal_sha256", "boot_sha256", "native_sha256")):
                        raise CompletionError("Native completion host-input witnesses differ from the actual verified policy")

                    unrelated = [proof for proof in candidate["services"]["services"] if proof["protocol"] != "wireguard"]

                    if unrelated and (serviceObserver is None or guest._Encode(serviceObserver.Observe(guest, candidate["metadata"]["sources"])) != guest._Encode(unrelated)):
                        raise CompletionError("Native completion requires trusted exact live witnesses for every unrelated service")

                    verify()

                    if _Files(guest, authority, cache, candidate, complete=False) != files:
                        raise CompletionError("Native completion witnesses changed before immutable publication")

                    _WriteCompletion(guest, authority, record)
                    verify()

        else:
            _WriteCompletion(guest, authority, record)

        if peer._History(guest, intent["owner"]) != record["history_sha256"]:
            raise CompletionError("Native completion cannot retire protection with changed or lost peer history")

        authority._Publish(guest, "head.json", pointer)

        for filename, content in files.items():
            if peer._History(guest, intent["owner"]) != record["history_sha256"]:
                raise CompletionError("Native completion history changed during sidecar retirement")

            _Retire(guest, authority, filename, content)

        observedHead, _, observedLatest, _ = authority._Authority(guest, intent, pending, expectedCompletion=record)

        if (observedHead != pointer or observedLatest != record or authority._Pending(guest, intent) != pending
                or any(path.name.startswith(".") for path in authority._Root(guest).iterdir())
                or any((authority._Root(guest) / filename).exists() or (authority._Root(guest) / filename).is_symlink()
                       for filename in ("input.json", "generation.json", "runtime.json"))
                or peer._History(guest, intent["owner"]) != record["history_sha256"]):
            raise CompletionError("Native completion reservation/history changed before retirement")

        _Retire(guest, authority, "pending.json", guest._Encode(pending))

        return dict(record)
