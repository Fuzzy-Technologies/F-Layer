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

    timeout_seconds: float = 3.0
    count: int = 3
    byte_limit: int = 64 * 1024

    def __post_init__(self) -> None:
        """Reject invalid or unbounded work before starting a transport."""

        if (
            isinstance(self.timeout_seconds, bool)
            or not math.isfinite(self.timeout_seconds)
            or not 0 < self.timeout_seconds <= MAX_TIMEOUT_SECONDS
            or isinstance(self.count, bool)
            or not isinstance(self.count, int)
            or not 1 <= self.count <= MAX_REQUEST_COUNT
            or isinstance(self.byte_limit, bool)
            or not isinstance(self.byte_limit, int)
            or not 1 <= self.byte_limit <= MAX_BYTE_LIMIT
        ):
            raise ValueError("Benchmark limits exceed the supported bounds")


@dataclass(frozen=True)
class EndpointMeasurement:
    """Safe metrics exclude response content, credentials, and target identifiers."""

    status: DiagnosticStatus
    duration_seconds: float
    received_bytes: int = 0
    http_status: int | None = None


class EndpointTransport(Protocol):
    """A measurement implementation enforces supplied limits without emitting raw data."""

    def __call__(
        self, endpoint: str, timeout_seconds: float, byte_limit: int
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


def HttpMeasurement(endpoint: str, timeout_seconds: float, byte_limit: int) -> EndpointMeasurement:
    """Read a limited payload with TLS verification and no redirects or proxy discovery."""

    parsed = ValidateEndpoint(endpoint)
    connection_type = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    connection = connection_type(str(parsed.hostname), port=parsed.port, timeout=timeout_seconds)
    started = time.monotonic()

    try:
        connection.request(
            "GET", parsed.path or "/",
            headers={"Range": f"bytes=0-{byte_limit - 1}", "Connection": "close"},
        )
        response = connection.getresponse()
        received_bytes = len(response.read(byte_limit))
        status = DiagnosticStatus.OK if 200 <= response.status < 300 else DiagnosticStatus.FAILED

        return EndpointMeasurement(status, time.monotonic() - started, received_bytes, response.status)

    finally:
        connection.close()


def EndpointWorker(
    sender: Connection, endpoint: str, timeout_seconds: float, byte_limit: int
) -> None:
    """Isolate network work so DNS, TLS, connect, and response reads share a hard deadline."""

    try:
        measurement = HttpMeasurement(endpoint, timeout_seconds, byte_limit)

    except Exception:
        measurement = EndpointMeasurement(DiagnosticStatus.FAILED, 0.0)

    try:
        sender.send(measurement)

    finally:
        sender.close()


def MeasureEndpoint(endpoint: str, timeout_seconds: float, byte_limit: int) -> EndpointMeasurement:
    """Terminate isolated network work at the deadline, including a stalled DNS resolver."""

    ValidateEndpoint(endpoint)
    BenchmarkLimits(timeout_seconds=timeout_seconds, count=1, byte_limit=byte_limit)
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=EndpointWorker, args=(sender, endpoint, timeout_seconds, byte_limit), daemon=True
    )
    started = time.monotonic()
    launched = False

    try:
        process.start()
        launched = True
        sender.close()
        remaining = max(0.0, timeout_seconds - (time.monotonic() - started))

        if receiver.poll(remaining):
            measurement: EndpointMeasurement = receiver.recv()

            return measurement

        return EndpointMeasurement(DiagnosticStatus.FAILED, timeout_seconds)

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
        measurement = transport(endpoint, limits.timeout_seconds, limits.byte_limit)

        if (
            not isinstance(measurement, EndpointMeasurement)
            or not isinstance(measurement.status, DiagnosticStatus)
            or isinstance(measurement.duration_seconds, bool)
            or not math.isfinite(measurement.duration_seconds)
            or not 0 <= measurement.duration_seconds <= limits.timeout_seconds
            or isinstance(measurement.received_bytes, bool)
            or not isinstance(measurement.received_bytes, int)
            or not 0 <= measurement.received_bytes <= limits.byte_limit
            or (
                measurement.http_status is not None
                and (
                    isinstance(measurement.http_status, bool)
                    or not isinstance(measurement.http_status, int)
                    or not 100 <= measurement.http_status <= 599
                )
            )
            or (
                measurement.status is DiagnosticStatus.OK
                and (measurement.http_status is None or not 200 <= measurement.http_status < 300)
            )
        ):
            raise ValueError("Adapter returned invalid metrics")

        return measurement

    except Exception:
        return EndpointMeasurement(DiagnosticStatus.FAILED, 0.0)


def ProbeEndpoint(
    endpoint: str, timeout_seconds: float = 3.0,
    transport: EndpointTransport = MeasureEndpoint,
) -> CheckResult:
    """Check explicit HTTP reachability without pretending it validates guest hardening."""

    ValidateEndpoint(endpoint)
    limits = BenchmarkLimits(timeout_seconds=timeout_seconds, count=1, byte_limit=1)
    measurement = SafeMeasurement(endpoint, limits, transport)

    return CheckResult(
        "endpoint", measurement.status,
        "Endpoint answered successfully" if measurement.status is DiagnosticStatus.OK
        else "Endpoint probe did not succeed",
        {"duration_seconds": measurement.duration_seconds, "http_status": measurement.http_status},
    )


def RunBenchmark(
    endpoint: str, limits: BenchmarkLimits | None = None,
    transport: EndpointTransport = MeasureEndpoint,
) -> tuple[CheckResult, ...]:
    """Measure a fixed count of bounded downloads without inferring upload or tunnel speed."""

    ValidateEndpoint(endpoint)
    resolved_limits = limits or BenchmarkLimits()
    checks: list[CheckResult] = []

    for index in range(resolved_limits.count):
        measurement = SafeMeasurement(endpoint, resolved_limits, transport)
        status = measurement.status

        if status is DiagnosticStatus.OK and measurement.received_bytes == 0:
            status = DiagnosticStatus.FAILED

        throughput = (
            measurement.received_bytes * 8 / measurement.duration_seconds / 1_000_000
            if measurement.duration_seconds > 0 else None
        )
        checks.append(CheckResult(
            f"http-download-{index + 1}", status,
            "Bounded HTTP download measured" if status is DiagnosticStatus.OK
            else "Bounded HTTP download did not succeed",
            {
                "received_bytes": measurement.received_bytes,
                "duration_seconds": measurement.duration_seconds,
                "throughput_mbps": throughput,
                "http_status": measurement.http_status,
                "byte_limit": resolved_limits.byte_limit,
            },
        ))

    return tuple(checks)
