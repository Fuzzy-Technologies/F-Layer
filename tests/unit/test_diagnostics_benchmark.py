"""Offline benchmark safety tests with injected network and process boundaries."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest

from flayer.__main__ import Main
from flayer.diagnostics import (
    BenchmarkLimits,
    DiagnosticReport,
    DiagnosticStatus,
    EndpointMeasurement,
    ProbeEndpoint,
    RenderJson,
    RunBenchmark,
)
from flayer.diagnostics.benchmark import (
    EndpointWorker,
    HttpMeasurement,
    MeasureEndpoint,
    ValidateEndpoint,
)


@pytest.mark.parametrize("endpoint", [
    "fixture.invalid", "file:///fixture", "https://user:fixture-secret@fixture.invalid",
    "https://fixture.invalid/?token=fixture-secret", "https://fixture.invalid/#secret",
    "https://fixture.invalid:0", "https://fixture.invalid:99999", "https://fixture.invalid/\n",
])
def test_EndpointRejectsAmbiguousOrSensitiveInput(endpoint: str) -> None:
    """Validation errors never include raw URLs, credentials, or sensitive fragments."""

    with pytest.raises(ValueError) as error:
        ValidateEndpoint(endpoint)

    assert "fixture-secret" not in str(error.value), "Validation echoed sensitive input"


@pytest.mark.parametrize("timeout, count, byte_limit", [
    (0, 1, 1), (31, 1, 1), (float("nan"), 1, 1), (True, 1, 1),
    (1, 0, 1), (1, 11, 1), (1, True, 1), (1, 1.5, 1),
    (1, 1, 0), (1, 1, 1024 * 1024 + 1), (1, 1, True),
])
def test_BenchmarkRejectsUnboundedWork(timeout: float, count: int, byte_limit: int) -> None:
    """Limits reject runaway time, request count, and payload before invoking a transport."""

    with pytest.raises(ValueError):
        BenchmarkLimits(timeout, count, byte_limit)


def test_BenchmarkBoundsAndMetrics() -> None:
    """Each sample receives precise bounds and throughput reflects only measured HTTP data."""

    calls: list[tuple[str, float, int]] = []

    def Transport(endpoint: str, timeout_seconds: float, byte_limit: int) -> EndpointMeasurement:
        """Record explicit bounds without making any request."""

        calls.append((endpoint, timeout_seconds, byte_limit))

        return EndpointMeasurement(DiagnosticStatus.OK, 0.5, byte_limit, 206)

    checks = RunBenchmark("https://fixture.invalid", BenchmarkLimits(1, 2, 64), Transport)

    assert calls == [("https://fixture.invalid", 1, 64)] * 2, "Transport bounds changed"
    assert [check.name for check in checks] == ["http-download-1", "http-download-2"], \
        "Sample ordering changed"
    assert checks[0].details["throughput_mbps"] == 0.001024, "Throughput units are incorrect"
    assert "fixture.invalid" not in RenderJson(DiagnosticReport("benchmark", checks)), \
        "Private endpoint was exposed"


@pytest.mark.parametrize("measurement, expected", [
    (EndpointMeasurement(DiagnosticStatus.OK, 0.0, 1, 200), DiagnosticStatus.OK),
    (EndpointMeasurement(DiagnosticStatus.OK, 0.1, 0, 204), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.FAILED, 0.1), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.OK, -1, 1), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.OK, float("inf"), 1), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.OK, 2, 1, 200), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.OK, False, 1, 200), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.OK, 0.1, 1), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.OK, 0.1, 1, 500), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.OK, 0.1, 999999), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.OK, 0.1, True), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.OK, 0.1, 1, 999), DiagnosticStatus.FAILED),
    (EndpointMeasurement(DiagnosticStatus.OK, 0.1, 1, True), DiagnosticStatus.FAILED),
])
def test_BenchmarkValidatesAdapterMetrics(measurement: EndpointMeasurement,
                                         expected: DiagnosticStatus) -> None:
    """Missing payload and invalid metrics cannot create a misleading successful benchmark."""

    def Transport(endpoint: str, timeout_seconds: float, byte_limit: int) -> EndpointMeasurement:
        """Return the adversarial fixture metrics without network access."""

        return measurement

    checks = RunBenchmark("https://fixture.invalid", BenchmarkLimits(1, 1, 8), Transport)

    assert checks[0].status is expected, "Invalid benchmark metrics implied success"


def test_ProbeDistinguishesEndpointHealthFromDownloadAndSuppressesErrors() -> None:
    """An empty 204 response can be healthy; transport exceptions never expose private data."""

    def HealthyTransport(endpoint: str, timeout_seconds: float,
                         byte_limit: int) -> EndpointMeasurement:
        """Supply an empty successful health response."""

        assert byte_limit == 1, "Health probe downloaded unnecessary data"

        return EndpointMeasurement(DiagnosticStatus.OK, 0.01, 0, 204)

    def FailedTransport(endpoint: str, timeout_seconds: float,
                        byte_limit: int) -> EndpointMeasurement:
        """Raise an exception that must not reach rendered output."""

        raise OSError("fixture-secret")

    healthy = ProbeEndpoint("https://fixture.invalid", transport=HealthyTransport)
    failed = ProbeEndpoint("https://fixture.invalid", transport=FailedTransport)

    assert healthy.status is DiagnosticStatus.OK, "Health response was confused with throughput"
    assert failed.status is DiagnosticStatus.FAILED, "Transport error was hidden"
    assert "fixture-secret" not in str(failed.AsDict()), "Transport exception escaped suppression"


class FakeHttpConnection:
    """An HTTP implementation fixture exposes request bounds and simulates failures."""

    instances: list[FakeHttpConnection] = []
    response_status = 206
    raise_request = False

    def __init__(self, host: str, port: int | None, timeout: float) -> None:
        """Record transport construction without opening sockets."""

        self.host = host
        self.port = port
        self.timeout = timeout
        self.status = self.response_status
        self.request_args: tuple[str, str, dict[str, str]] | None = None
        self.read_limit = 0
        self.closed = False
        self.instances.append(self)

    def request(self, method: str, path: str, headers: dict[str, str]) -> None:
        """Preserve the standard library callback names in this transport fixture."""

        self.request_args = (method, path, headers)

        if self.raise_request:
            raise OSError("fixture-private-error")

    def getresponse(self) -> FakeHttpConnection:
        """Act as the bounded response fixture."""

        return self

    def read(self, amount: int) -> bytes:
        """Return exactly the requested payload without exposing its body in metrics."""

        self.read_limit = amount

        return b"x" * amount

    def close(self) -> None:
        """Record cleanup using the standard transport interface."""

        self.closed = True


@pytest.mark.parametrize("scheme, status, expected", [
    ("https", 206, DiagnosticStatus.OK), ("http", 200, DiagnosticStatus.OK),
    ("https", 302, DiagnosticStatus.FAILED), ("https", 500, DiagnosticStatus.FAILED),
])
def test_HttpDoesNotFollowRedirectsAndCapsResponseReads(
    monkeypatch: pytest.MonkeyPatch, scheme: str, status: int, expected: DiagnosticStatus
) -> None:
    """TLS and HTTP share explicit bounds; redirects cannot silently expand target scope."""

    monkeypatch.setattr("flayer.diagnostics.benchmark.http.client.HTTPConnection", FakeHttpConnection)
    monkeypatch.setattr("flayer.diagnostics.benchmark.http.client.HTTPSConnection", FakeHttpConnection)
    monkeypatch.setattr(FakeHttpConnection, "response_status", status)
    result = HttpMeasurement(f"{scheme}://fixture.invalid:8080/path", 1, 16)
    connection = FakeHttpConnection.instances[-1]

    assert connection.read_limit == 16, "Ignored Range headers must not cause unbounded reads"
    assert connection.timeout == 1 and connection.port == 8080, "Transport options were lost"
    assert connection.request_args == (
        "GET", "/path", {"Range": "bytes=0-15", "Connection": "close"}
    ), "HTTP request expanded its scope"
    assert connection.closed, "Connection leaked after measurement"
    assert result.status is expected and result.http_status == status, "HTTP outcome was masked"


def test_HttpClosesOnFailureAndDefaultsToRoot(monkeypatch: pytest.MonkeyPatch) -> None:
    """Connection cleanup remains guaranteed on failure; root paths are deterministic."""

    monkeypatch.setattr("flayer.diagnostics.benchmark.http.client.HTTPConnection", FakeHttpConnection)
    monkeypatch.setattr(FakeHttpConnection, "raise_request", True)

    with pytest.raises(OSError):
        HttpMeasurement("http://fixture.invalid", 1, 8)

    connection = FakeHttpConnection.instances[-1]

    assert connection.closed, "Failure leaked its connection"
    assert connection.request_args is not None and connection.request_args[1] == "/", \
        "Missing URL path must select the root"


class FakePipe:
    """An isolated result channel fixture avoids subprocess and network side effects."""

    def __init__(self, ready: bool = True, eof: bool = False) -> None:
        """Initialize controlled result availability."""

        self.ready = ready
        self.eof = eof
        self.closed = False
        self.measurement = EndpointMeasurement(DiagnosticStatus.OK, 0.01, 1, 200)

    def poll(self, timeout: float) -> bool:
        """Observe the bounded parent wait without blocking."""

        assert 0 <= timeout <= 1, "Parent wait exceeded the request deadline"

        return self.ready

    def recv(self) -> EndpointMeasurement:
        """Return a safe result or simulate a terminated worker channel."""

        if self.eof:
            raise EOFError("fixture-secret")

        return self.measurement

    def send(self, measurement: EndpointMeasurement) -> None:
        """Record a worker result using the multiprocessing channel contract."""

        self.measurement = measurement

    def close(self) -> None:
        """Record channel cleanup."""

        self.closed = True


class FakeProcess:
    """A process lifecycle fixture simulates timeout cancellation and cleanup."""

    def __init__(self, fail_start: bool = False, resist_terminate: bool = False) -> None:
        """Initialize lifecycle failure conditions."""

        self.fail_start = fail_start
        self.resist_terminate = resist_terminate
        self.alive = True
        self.terminated = False
        self.killed = False
        self.closed = False

    def start(self) -> None:
        """Simulate launching a measurement worker."""

        if self.fail_start:
            raise OSError("fixture-secret")

    def is_alive(self) -> bool:
        """Expose worker liveness to the cancellation owner."""

        return self.alive

    def terminate(self) -> None:
        """Simulate graceful termination or an unresponsive worker."""

        self.terminated = True
        self.alive = self.resist_terminate

    def join(self, timeout: float) -> None:
        """Verify cleanup wait remains bounded."""

        assert timeout == 1, "Cleanup wait is unbounded"

    def kill(self) -> None:
        """Simulate final cancellation of an unresponsive worker."""

        self.killed = True
        self.alive = False

    def close(self) -> None:
        """Record worker handle cleanup."""

        self.closed = True


class FakeContext:
    """A multiprocessing context fixture supplies lifecycle instrumentation."""

    def __init__(self, receiver: FakePipe, sender: FakePipe, process: FakeProcess) -> None:
        """Store the controlled channels and process."""

        self.receiver = receiver
        self.sender = sender
        self.process = process

    def Pipe(self, duplex: bool) -> tuple[FakePipe, FakePipe]:
        """Match the external pipe factory without introducing an outbound channel."""

        assert not duplex, "Worker only needs a one-way result channel"

        return self.receiver, self.sender

    def Process(self, target: Callable[..., None], args: tuple[Any, ...],
                daemon: bool) -> FakeProcess:
        """Verify explicit endpoint bounds reach the isolated worker."""

        assert target is EndpointWorker, "Unexpected worker implementation"
        assert args[1:] == ("https://fixture.invalid", 1, 1), "Worker bounds changed"
        assert daemon, "Measurement worker must not outlive its owner"

        return self.process


@pytest.mark.parametrize("ready, eof, fail_start, resist, expected", [
    (True, False, False, False, DiagnosticStatus.OK),
    (False, False, False, False, DiagnosticStatus.FAILED),
    (False, False, False, True, DiagnosticStatus.FAILED),
    (True, True, False, False, DiagnosticStatus.FAILED),
    (True, False, True, False, DiagnosticStatus.FAILED),
])
def test_WorkerDeadlineAndCleanup(monkeypatch: pytest.MonkeyPatch, ready: bool, eof: bool,
                                 fail_start: bool, resist: bool,
                                 expected: DiagnosticStatus) -> None:
    """Every worker failure cleans handles and deadline expiry terminates network work."""

    receiver = FakePipe(ready, eof)
    sender = FakePipe()
    process = FakeProcess(fail_start, resist)
    context = FakeContext(receiver, sender, process)
    monkeypatch.setattr("flayer.diagnostics.benchmark.multiprocessing.get_context",
                        lambda mode: context)
    result = MeasureEndpoint("https://fixture.invalid", 1, 1)

    assert result.status is expected, "Worker outcome did not reach the caller"
    assert receiver.closed and sender.closed and process.closed, "Worker handles leaked"
    assert process.terminated is not fail_start, "Launched worker was not terminated"
    assert process.killed is resist, "Unresponsive worker survived cancellation"


@pytest.mark.parametrize("fail", [False, True])
def test_WorkerNeverSendsRawErrors(monkeypatch: pytest.MonkeyPatch, fail: bool) -> None:
    """Only structured metrics cross the worker result boundary."""

    def Measurement(endpoint: str, timeout_seconds: float, byte_limit: int) -> EndpointMeasurement:
        """Supply a successful or failed bounded worker fixture."""

        if fail:
            raise OSError("fixture-secret")

        return EndpointMeasurement(DiagnosticStatus.OK, 0.1, 1, 200)

    sender = FakePipe()
    monkeypatch.setattr("flayer.diagnostics.benchmark.HttpMeasurement", Measurement)
    EndpointWorker(sender, "https://fixture.invalid", 1, 1)  # type: ignore[arg-type]

    assert sender.closed, "Worker must close its channel"
    assert sender.measurement.status is (DiagnosticStatus.FAILED if fail else DiagnosticStatus.OK), \
        "Worker outcome was lost"
    assert "fixture-secret" not in str(sender.measurement), "Worker leaked private error text"


def test_CliEndpointPathsUseInjectedProbes(monkeypatch: pytest.MonkeyPatch,
                                         capsys: pytest.CaptureFixture[str]) -> None:
    """Successful CLI routes are tested with safe injected observations."""

    def Probe(endpoint: str, timeout_seconds: float) -> object:
        """Supply CLI health output without any endpoint traffic."""

        return ProbeEndpoint(endpoint, timeout_seconds, lambda url, seconds, size:
                             EndpointMeasurement(DiagnosticStatus.OK, 0.1, 0, 204))

    def Benchmark(endpoint: str, limits: BenchmarkLimits) -> object:
        """Supply CLI measurements without any endpoint traffic."""

        return RunBenchmark(endpoint, limits, lambda url, seconds, size:
                            EndpointMeasurement(DiagnosticStatus.OK, 0.1, size, 200))

    monkeypatch.setattr("flayer.__main__.ProbeEndpoint", Probe)
    monkeypatch.setattr("flayer.__main__.RunBenchmark", Benchmark)

    for command in ("health", "benchmark"):
        assert Main([command, "--endpoint", "https://fixture.invalid", "--format", "json"]) == 0, \
            "Successful CLI route returned failure"
        assert json.loads(capsys.readouterr().out)["status"] == "ok", "CLI discarded probe output"
