import json
from pathlib import Path

from src.palworld_watchdog import Watchdog, WatchdogConfig, atomic_write_json


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakePalworld:
    def __init__(self):
        self.players = 0
        self.raises = False

    def player_count(self) -> int:
        if self.raises:
            raise RuntimeError("api down")
        return self.players

    def server_running(self) -> bool:
        return True


class FakeUnsloth:
    def __init__(self):
        self.status_body = {"model_identifier": "unsloth/Qwen3.6-35B-A3B-MTP-GGUF"}
        self.loaded = True
        self.contract = (True, "ok")
        self.calls: list[str] = []

    def status(self):
        self.calls.append("status")
        return self.status_body

    def model_loaded(self) -> bool:
        return self.loaded

    def load(self) -> None:
        self.calls.append("load")

    def unload_force(self) -> None:
        self.calls.append("unload_force")

    def chat_contract_ok(self):
        self.calls.append("contract")
        return self.contract

    def start_server(self) -> None:
        self.calls.append("start_server")


class FakeDriver:
    def __init__(self):
        self.alive = False
        self.reap_result = (None, None)
        self.calls: list[str] = []
        self.process = None

    def any_driver_alive(self) -> bool:
        return self.alive

    def reap(self):
        result = self.reap_result
        self.reap_result = (None, None)
        return result

    def launch(self) -> int:
        self.calls.append("launch")
        self.alive = True
        return 4242

    def kill_all(self) -> None:
        self.calls.append("kill_all")
        self.alive = False


def make_watchdog(tmp_path: Path) -> tuple[Watchdog, FakePalworld, FakeUnsloth, FakeDriver, FakeClock]:
    config = WatchdogConfig(
        repo_root=tmp_path / "repo",
        oghidra_root=tmp_path / "oghidra",
        empty_grace_seconds=60,
        stop_grace_seconds=0,
    )
    config.run_root.mkdir(parents=True)
    palworld, unsloth, driver, clock = FakePalworld(), FakeUnsloth(), FakeDriver(), FakeClock()
    watchdog = Watchdog(
        config,
        palworld=palworld,  # type: ignore[arg-type]
        unsloth=unsloth,  # type: ignore[arg-type]
        driver=driver,  # type: ignore[arg-type]
        embeddings_sync=lambda: None,
        sleep=lambda _: clock.advance(max(_, 0.25)),
        clock=clock,
    )
    return watchdog, palworld, unsloth, driver, clock


def run_until_heavy(watchdog: Watchdog, clock: FakeClock) -> None:
    watchdog.iterate()  # starts the empty grace window
    clock.advance(61)
    watchdog.iterate()


def test_player_join_unloads_kills_and_protects(tmp_path: Path):
    watchdog, palworld, unsloth, driver, _ = make_watchdog(tmp_path)
    driver.alive = True
    palworld.players = 2

    watchdog.iterate()

    assert watchdog.mode == "protected"
    assert "unload_force" in unsloth.calls
    assert "kill_all" in driver.calls
    control = json.loads(watchdog.config.control_path.read_text(encoding="utf-8"))
    assert control["command"] == "stop_after_stage"


def test_protection_kills_even_when_control_write_fails(tmp_path: Path, monkeypatch):
    watchdog, palworld, _, driver, _ = make_watchdog(tmp_path)
    driver.alive = True
    palworld.players = 1
    monkeypatch.setattr(
        watchdog, "write_control", lambda command: (_ for _ in ()).throw(OSError("locked"))
    )

    watchdog.protect("player joined", 1)

    assert "kill_all" in driver.calls


def test_empty_grace_defers_then_launches(tmp_path: Path):
    watchdog, _, _, driver, clock = make_watchdog(tmp_path)

    watchdog.iterate()
    assert driver.calls == []  # still inside the grace window

    clock.advance(61)
    watchdog.iterate()
    assert driver.calls == ["launch"]
    assert watchdog.mode == "running"


def test_completed_latch_blocks_relaunch_until_ledger_moves(tmp_path: Path):
    watchdog, _, _, driver, clock = make_watchdog(tmp_path)
    atomic_write_json(watchdog.config.ledger_path, {"chunks": {}})
    atomic_write_json(
        watchdog.config.run_state_path, {"status": "completed", "run_mode": "driver"}
    )

    run_until_heavy(watchdog, clock)
    assert driver.calls == []

    # Ledger reset/extension outdates run-state: latch must open.
    atomic_write_json(watchdog.config.ledger_path, {"chunks": {"chunk_0009": {}}})
    watchdog.iterate()
    assert driver.calls == ["launch"]


def test_crash_guard_blocks_after_three_unhealthy_short_exits(tmp_path: Path):
    watchdog, _, _, driver, clock = make_watchdog(tmp_path)
    run_until_heavy(watchdog, clock)
    assert driver.calls == ["launch"]

    for _ in range(3):
        driver.alive = False
        driver.reap_result = (1, 5.0)  # unexpected code, died young
        watchdog.iterate()
    assert watchdog.mode == "blocked"
    assert "crashed in under" in (watchdog.blocked_reason or "")
    assert driver.calls == ["launch", "launch", "launch"]  # third exit blocks, no 4th


def test_healthy_fast_exit_codes_do_not_feed_crash_guard(tmp_path: Path):
    watchdog, _, _, driver, clock = make_watchdog(tmp_path)
    run_until_heavy(watchdog, clock)

    for _ in range(4):
        driver.alive = False
        driver.reap_result = (2, 3.0)  # stopped via control.json: healthy
        watchdog.iterate()
    assert watchdog.mode == "running"
    assert watchdog.blocked_reason is None


def test_lock_held_exits_block_after_three(tmp_path: Path):
    watchdog, _, _, driver, clock = make_watchdog(tmp_path)
    run_until_heavy(watchdog, clock)

    for _ in range(3):
        driver.alive = False
        driver.reap_result = (5, 2.0)
        watchdog.iterate()
    assert watchdog.mode == "blocked"
    assert "driver.lock" in (watchdog.blocked_reason or "")


def test_contract_failure_blocks_and_recheck_retries(tmp_path: Path):
    watchdog, _, unsloth, driver, clock = make_watchdog(tmp_path)
    unsloth.contract = (False, "Invalid tool_choice type")

    run_until_heavy(watchdog, clock)
    assert watchdog.mode == "blocked"
    assert driver.calls == []

    # Before the recheck window: still blocked, no probing.
    watchdog.iterate()
    assert driver.calls == []

    # After the window the condition is re-tested; now healthy.
    unsloth.contract = (True, "ok")
    clock.advance(watchdog.config.block_recheck_minutes * 60 + 1)
    watchdog.iterate()
    assert driver.calls == ["launch"]
    assert watchdog.mode == "running"


def test_provider_pause_holds_until_status_answers(tmp_path: Path):
    watchdog, _, unsloth, driver, clock = make_watchdog(tmp_path)
    atomic_write_json(
        watchdog.config.run_state_path, {"status": "paused_provider_unavailable"}
    )
    unsloth.status_body = None

    run_until_heavy(watchdog, clock)
    assert driver.calls == []

    unsloth.status_body = {"model_identifier": "unsloth/Qwen3.6-35B-A3B-MTP-GGUF"}
    watchdog.iterate()
    assert driver.calls == ["launch"]
