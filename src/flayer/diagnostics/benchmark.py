"""Bounded HTTP measurements against an explicitly authorized endpoint."""

from __future__ import annotations

import http.client
import math
import multiprocessing
import time
from dataclasses import dataclass
from multiprocessing.connection import Connection
from typing import Protocol
from urllib.parse import SplitResult, urlsplit

from .contracts import CheckResult, DiagnosticStatus

MAX_TIMEOUT_SECONDS = 30.0
MAX_REQUEST_COUNT = 10
MAX_BYTE_LIMIT = 1024 * 1024


@dataclass(frozen=True)
class BenchmarkLimits:
    """Hard per-request deadline, request count, and response payload limits."""

    timeoutSeconds: float = 3.0
    count: int = 3
    byteLimit: int = 64 * 1024

    def __post_init__(self) -> None:
        """Reject invalid or unbounded work before starting a transport."""

        if (
            isinstance(self.timeoutSeconds, bool)
            or not math.isfinite(self.timeoutSeconds)
            or not 0 < self.timeoutSeconds <= MAX_TIMEOUT_SECONDS
            or isinstance(self.count, bool)
            or not isinstance(self.count, int)
            or not 1 <= self.count <= MAX_REQUEST_COUNT
            or isinstance(self.byteLimit, bool)
            or not isinstance(self.byteLimit, int)
            or not 1 <= self.byteLimit <= MAX_BYTE_LIMIT
        ):
            raise ValueError("Benchmark limits exceed the supported bounds")


@dataclass(frozen=True)
class EndpointMeasurement:
    """Safe metrics exclude response content, credentials, and target identifiers."""

    status: DiagnosticStatus
    durationSeconds: float
    receivedBytes: int = 0
    httpStatus: int | None = None


class EndpointTransport(Protocol):
    """A measurement implementation enforces supplied limits without emitting raw data."""

    def __call__(
        self, endpoint: str, timeoutSeconds: float, byteLimit: int
    ) -> EndpointMeasurement:
        """Return one bounded HTTP measurement without exposing response payloads."""

        ...


def ValidateEndpoint(endpoint: str) -> SplitResult:
    """Allow explicit HTTP(S) URLs without credentials, query strings, or fragments."""

    try:
        parsed = urlsplit(endpoint)
        port = parsed.port

        if (
            parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(character.isspace() or ord(character) < 32 for character in endpoint)
            or (port is not None and port < 1)
        ):
            raise ValueError("Invalid endpoint")

    except ValueError:
        raise ValueError("Endpoint must be an HTTP(S) URL without credentials, query or fragment") \
            from None

    return parsed


def HttpMeasurement(endpoint: str, timeoutSeconds: float, byteLimit: int) -> EndpointMeasurement:
    """Read a limited payload with TLS verification and no redirects or proxy discovery."""

    parsed = ValidateEndpoint(endpoint)
    connectionType = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    connection = connectionType(str(parsed.hostname), port=parsed.port, timeout=timeoutSeconds)
    started = time.monotonic()

    try:
        connection.request(
            "GET", parsed.path or "/",
            headers={"Range": f"bytes=0-{byteLimit - 1}", "Connection": "close"},
        )
        response = connection.getresponse()
        receivedBytes = len(response.read(byteLimit))
        status = DiagnosticStatus.OK if 200 <= response.status < 300 else DiagnosticStatus.FAILED

        return EndpointMeasurement(status, time.monotonic() - started, receivedBytes, response.status)

    finally:
        connection.close()


def EndpointWorker(
    sender: Connection, endpoint: str, timeoutSeconds: float, byteLimit: int
) -> None:
    """Isolate network work so DNS, TLS, connect, and response reads share a hard deadline."""

    try:
        measurement = HttpMeasurement(endpoint, timeoutSeconds, byteLimit)

    except Exception:
        measurement = EndpointMeasurement(DiagnosticStatus.FAILED, 0.0)

    try:
        sender.send(measurement)

    finally:
        sender.close()


def MeasureEndpoint(endpoint: str, timeoutSeconds: float, byteLimit: int) -> EndpointMeasurement:
    """Terminate isolated network work at the deadline, including a stalled DNS resolver."""

    ValidateEndpoint(endpoint)
    BenchmarkLimits(timeoutSeconds=timeoutSeconds, count=1, byteLimit=byteLimit)
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=EndpointWorker, args=(sender, endpoint, timeoutSeconds, byteLimit), daemon=True
    )
    started = time.monotonic()
    launched = False

    try:
        process.start()
        launched = True
        sender.close()
        remaining = max(0.0, timeoutSeconds - (time.monotonic() - started))

        if receiver.poll(remaining):
            measurement: EndpointMeasurement = receiver.recv()

            return measurement

        return EndpointMeasurement(DiagnosticStatus.FAILED, timeoutSeconds)

    except (OSError, EOFError, RuntimeError):
        return EndpointMeasurement(DiagnosticStatus.FAILED, time.monotonic() - started)

    finally:
        sender.close()
        receiver.close()

        if launched:
            if process.is_alive():
                process.terminate()

            process.join(timeout=1.0)

            if process.is_alive():
                process.kill()
                process.join(timeout=1.0)

        process.close()


def SafeMeasurement(
    endpoint: str, limits: BenchmarkLimits, transport: EndpointTransport
) -> EndpointMeasurement:
    """Reject invalid adapter metrics and suppress all unstructured exception output."""

    try:
        measurement = transport(endpoint, limits.timeoutSeconds, limits.byteLimit)

        if (
            not isinstance(measurement, EndpointMeasurement)
            or not isinstance(measurement.status, DiagnosticStatus)
            or isinstance(measurement.durationSeconds, bool)
            or not math.isfinite(measurement.durationSeconds)
            or not 0 <= measurement.durationSeconds <= limits.timeoutSeconds
            or isinstance(measurement.receivedBytes, bool)
            or not isinstance(measurement.receivedBytes, int)
            or not 0 <= measurement.receivedBytes <= limits.byteLimit
            or (
                measurement.httpStatus is not None
                and (
                    isinstance(measurement.httpStatus, bool)
                    or not isinstance(measurement.httpStatus, int)
                    or not 100 <= measurement.httpStatus <= 599
                )
            )
            or (
                measurement.status is DiagnosticStatus.OK
                and (measurement.httpStatus is None or not 200 <= measurement.httpStatus < 300)
            )
        ):
            raise ValueError("Adapter returned invalid metrics")

        return measurement

    except Exception:
        return EndpointMeasurement(DiagnosticStatus.FAILED, 0.0)


def ProbeEndpoint(
    endpoint: str, timeoutSeconds: float = 3.0,
    transport: EndpointTransport = MeasureEndpoint,
) -> CheckResult:
    """Check explicit HTTP reachability without pretending it validates guest hardening."""

    ValidateEndpoint(endpoint)
    limits = BenchmarkLimits(timeoutSeconds=timeoutSeconds, count=1, byteLimit=1)
    measurement = SafeMeasurement(endpoint, limits, transport)

    return CheckResult(
        "endpoint", measurement.status,
        "Endpoint answered successfully" if measurement.status is DiagnosticStatus.OK
        else "Endpoint probe did not succeed",
        {"duration_seconds": measurement.durationSeconds, "http_status": measurement.httpStatus},
    )


def RunBenchmark(
    endpoint: str, limits: BenchmarkLimits | None = None,
    transport: EndpointTransport = MeasureEndpoint,
) -> tuple[CheckResult, ...]:
    """Measure a fixed count of bounded downloads without inferring upload or tunnel speed."""

    ValidateEndpoint(endpoint)
    resolvedLimits = limits or BenchmarkLimits()
    checks: list[CheckResult] = []

    for index in range(resolvedLimits.count):
        measurement = SafeMeasurement(endpoint, resolvedLimits, transport)
        status = measurement.status

        if status is DiagnosticStatus.OK and measurement.receivedBytes == 0:
            status = DiagnosticStatus.FAILED

        throughput = (
            measurement.receivedBytes * 8 / measurement.durationSeconds / 1_000_000
            if measurement.durationSeconds > 0 else None
        )
        checks.append(CheckResult(
            f"http-download-{index + 1}", status,
            "Bounded HTTP download measured" if status is DiagnosticStatus.OK
            else "Bounded HTTP download did not succeed",
            {
                "received_bytes": measurement.receivedBytes,
                "duration_seconds": measurement.durationSeconds,
                "throughput_mbps": throughput,
                "http_status": measurement.httpStatus,
                "byte_limit": resolvedLimits.byteLimit,
            },
        ))

    return tuple(checks)
