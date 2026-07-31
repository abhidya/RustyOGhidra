"""Progress window for OGhidra's autonomous GotYaForce port run."""

from __future__ import annotations

import logging
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from typing import Callable

from ..port_run_controller import PortRunController, PortRunSnapshot, RunMode, format_duration
from .ui_thread import run_on_ui, ui_safe


logger = logging.getLogger("ollama-ghidra-bridge.port-run")


class PortRunPanel:
    """Non-modal durable-run dashboard opened from Analysis > Finish Game Port."""

    MODE_LABELS: dict[str, RunMode] = {
        "Fresh whole-program run": "fresh",
        "Resume whole-program run": "resume",
        "Recheck verified artifacts": "replay",
    }

    def __init__(
        self,
        root: tk.Misc,
        controller: PortRunController | None = None,
        active_session_path: Callable[[], Path | None] | None = None,
        host: tk.Misc | None = None,
        on_show: Callable[[], None] | None = None,
    ):
        self.root = root
        self.controller = controller or PortRunController()
        self.active_session_path = active_session_path or (lambda: None)
        self.host = host
        self.on_show = on_show
        self.window: tk.Misc | None = None
        self._poll_token: str | None = None
        self._last_terminal_status: str | None = None
        self._stream_kind: str | None = None
        self._stream_address: str | None = None
        self._activity_chars = 0
        self._reset_running = False

    def mount(self) -> None:
        """Build an embedded panel without selecting or starting the run."""
        if self.window is None or not self.window.winfo_exists():
            self._build()
        self._poll()

    def show(self, *, auto_start: bool = False) -> None:
        if self.window is None or not self.window.winfo_exists():
            self._build()
        assert self.window is not None
        if self.on_show:
            self.on_show()
        if isinstance(self.window, tk.Toplevel):
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()
        if auto_start and not self.controller.is_running():
            self._start(self.controller.recommended_mode())
        self._poll()

    def _build(self) -> None:
        window = self.host if self.host is not None else tk.Toplevel(self.root)
        self.window = window
        if isinstance(window, tk.Toplevel):
            window.title("Finish Game Port")
            window.geometry("1100x800")
            window.minsize(820, 600)
            window.protocol("WM_DELETE_WINDOW", window.withdraw)

        container = ttk.Frame(window, padding=12)
        container.pack(fill="both", expand=True)

        heading = ttk.Frame(container)
        heading.pack(fill="x")
        ttk.Label(heading, text="Finish Game Port", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(
            heading,
            text="Qwen proposes mechanics; Ghidra corroborates; deterministic gates compile, test, promote, and launch.",
            foreground="#a9b1bd",
        ).pack(anchor="w", pady=(3, 12))

        status_card = ttk.LabelFrame(container, text="Autonomous run", padding=12)
        status_card.pack(fill="x")
        status_grid = ttk.Frame(status_card)
        status_grid.pack(fill="x")

        self.status_var = tk.StringVar(value="Not started")
        self.stage_var = tk.StringVar(value="Waiting")
        self.progress_var = tk.DoubleVar(value=0.0)
        ttk.Label(status_grid, text="Status", width=16).grid(row=0, column=0, sticky="w")
        ttk.Label(status_grid, textvariable=self.status_var, font=("Segoe UI", 10, "bold")).grid(
            row=0, column=1, sticky="w"
        )
        ttk.Label(status_grid, text="Current stage", width=16).grid(row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Label(status_grid, textvariable=self.stage_var).grid(row=1, column=1, sticky="w", pady=(5, 0))
        status_grid.columnconfigure(1, weight=1)
        self.progress = ttk.Progressbar(status_card, variable=self.progress_var, maximum=100)
        self.progress.pack(fill="x", pady=(10, 0))

        metrics = ttk.LabelFrame(container, text="Liveness and throughput", padding=10)
        metrics.pack(fill="x", pady=(12, 0))
        self.elapsed_var = tk.StringVar(value="0s")
        self.eta_var = tk.StringVar(value="Calibrating")
        self.rate_var = tk.StringVar(value="0.00 stages/min")
        self.tokens_var = tk.StringVar(value="Waiting for Qwen")
        self.calls_var = tk.StringVar(value="LLM 0 · structured 0 · Ghidra 0")
        self.session_var = tk.StringVar(value="No active saved session · vectors not required")
        metric_values = (
            ("Elapsed", self.elapsed_var),
            ("ETA", self.eta_var),
            ("Stage rate", self.rate_var),
            ("Qwen throughput", self.tokens_var),
            ("Calls", self.calls_var),
            ("Session context", self.session_var),
        )
        for index, (label, variable) in enumerate(metric_values):
            row, column = divmod(index, 3)
            cell = ttk.Frame(metrics)
            cell.grid(row=row, column=column, sticky="ew", padx=(0 if column == 0 else 12, 0), pady=(0, 6))
            ttk.Label(cell, text=label, foreground="#8f98a5").pack(anchor="w")
            ttk.Label(cell, textvariable=variable).pack(anchor="w")
        for column in range(3):
            metrics.columnconfigure(column, weight=1)

        controls = ttk.Frame(container)
        controls.pack(fill="x", pady=12)
        self.mode_var = tk.StringVar(value="Fresh whole-program run")
        ttk.Combobox(
            controls,
            textvariable=self.mode_var,
            values=tuple(self.MODE_LABELS),
            state="readonly",
            width=27,
        ).pack(side="left")
        self.start_button = ttk.Button(controls, text="Start / Attach", command=self._start_selected)
        self.start_button.pack(side="left", padx=(8, 0))
        self.pause_button = ttk.Button(controls, text="Pause after function", command=self._pause)
        self.pause_button.pack(side="left", padx=(8, 0))
        self.resume_button = ttk.Button(controls, text="Resume", command=self._resume)
        self.resume_button.pack(side="left", padx=(8, 0))
        self.stop_button = ttk.Button(controls, text="Stop after function", command=self._stop)
        self.stop_button.pack(side="left", padx=(8, 0))
        self.reset_button = ttk.Button(
            controls,
            text="Clear failed & restart",
            command=self._clear_failed_restart,
        )
        self.reset_button.pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Open browser preview", command=self._preview).pack(side="right")

        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True)

        progress_tab = ttk.Frame(notebook, padding=8)
        work_tab = ttk.Frame(notebook, padding=8)
        log_tab = ttk.Frame(notebook, padding=8)
        notebook.add(progress_tab, text="Pipeline")
        notebook.add(work_tab, text="Live work")
        notebook.add(log_tab, text="Process log")

        self.stage_tree = ttk.Treeview(
            progress_tab,
            columns=("status", "detail"),
            show="tree headings",
            height=12,
        )
        self.stage_tree.heading("#0", text="Stage")
        self.stage_tree.heading("status", text="Status")
        self.stage_tree.heading("detail", text="Detail")
        self.stage_tree.column("#0", width=260, stretch=False)
        self.stage_tree.column("status", width=100, stretch=False)
        self.stage_tree.column("detail", width=520)
        self.stage_tree.tag_configure("passed", foreground="#66d9a3")
        self.stage_tree.tag_configure("failed", foreground="#ff7373")
        self.stage_tree.tag_configure("running", foreground="#6fb6ff")
        self.stage_tree.tag_configure("paused", foreground="#ffca67")
        self.stage_tree.pack(fill="both", expand=True)

        live_panes = ttk.PanedWindow(work_tab, orient="vertical")
        live_panes.pack(fill="both", expand=True)
        queue_frame = ttk.LabelFrame(live_panes, text="Current function", padding=8)
        activity_frame = ttk.LabelFrame(live_panes, text="Qwen activity", padding=8)
        live_panes.add(queue_frame, weight=1)
        live_panes.add(activity_frame, weight=4)

        self.queue_tree = ttk.Treeview(
            queue_frame,
            columns=("address", "family", "status"),
            show="headings",
            height=4,
        )
        self.queue_summary_var = tk.StringVar(value="Queue not initialized")
        ttk.Label(queue_frame, textvariable=self.queue_summary_var, foreground="#8f98a5").pack(
            fill="x",
            pady=(0, 8),
        )
        for column, label, width in (
            ("address", "Address", 180),
            ("family", "Family / unit", 360),
            ("status", "Status", 180),
        ):
            self.queue_tree.heading(column, text=label)
            self.queue_tree.column(column, width=width)
        self.queue_tree.pack(fill="both", expand=True)

        self.activity_text = scrolledtext.ScrolledText(
            activity_frame,
            wrap="word",
            font=("Cascadia Mono", 9),
            relief="flat",
            state="disabled",
            padx=10,
            pady=8,
        )
        self.activity_text.tag_configure("timestamp", foreground="#7f8a9a")
        self.activity_text.tag_configure("prompt", foreground="#70b7ff", font=("Segoe UI", 10, "bold"))
        self.activity_text.tag_configure("assistant", foreground="#7ee2a8", font=("Segoe UI", 10, "bold"))
        self.activity_text.tag_configure("tool", foreground="#ffd166", font=("Segoe UI", 10, "bold"))
        self.activity_text.tag_configure("gate", foreground="#c6a0f6", font=("Segoe UI", 10, "bold"))
        self.activity_text.tag_configure("error", foreground="#ff7373", font=("Segoe UI", 10, "bold"))
        self.activity_text.tag_configure("git", foreground="#8bd5ca", font=("Segoe UI", 10, "bold"))
        self.activity_text.tag_configure("body", foreground="#d6d9df")
        self.activity_text.pack(fill="both", expand=True)

        self.log_text = scrolledtext.ScrolledText(
            log_tab,
            wrap="word",
            font=("Cascadia Mono", 9),
            relief="flat",
            state="disabled",
        )
        self.log_text.pack(fill="both", expand=True)

        footer = ttk.Frame(container)
        footer.pack(fill="x", pady=(10, 0))
        self.updated_var = tk.StringVar(value="")
        ttk.Label(footer, textvariable=self.updated_var, foreground="#8f98a5").pack(side="left")
        if isinstance(window, tk.Toplevel):
            ttk.Button(footer, text="Hide", command=window.withdraw).pack(side="right")

        notebook.select(work_tab)

    def _start_selected(self) -> None:
        self._start(self.MODE_LABELS[self.mode_var.get()])

    def _start(self, mode: RunMode) -> None:
        try:
            pid = self.controller.start(mode, session_path=self.active_session_path())
            self.status_var.set(f"Running (PID {pid})")
            self._last_terminal_status = None
        except Exception as error:
            logger.exception("Could not start port run")
            messagebox.showerror("Finish Game Port", str(error), parent=self.window)

    def _pause(self) -> None:
        self.controller.pause()
        self.status_var.set("Pause requested; finishing the current function")

    def _resume(self) -> None:
        try:
            pid = self.controller.resume(session_path=self.active_session_path())
            self.status_var.set(f"Running (PID {pid})")
        except Exception as error:
            messagebox.showerror("Resume port run", str(error), parent=self.window)

    def _stop(self) -> None:
        if messagebox.askyesno(
            "Stop port run",
            "Stop after the active function finishes?",
            parent=self.window,
        ):
            self.controller.stop_after_stage()
            self.status_var.set("Stop requested; finishing the current function")

    def _clear_failed_restart(self) -> None:
        if self._reset_running or not messagebox.askyesno(
            "Clear failed functions and restart",
            "Stop the current Qwen request, restore its uncommitted source edits, "
            "archive the current diagnostics, and retry failed functions?\n\n"
            "Completed work and extracted Ghidra bundles are preserved.",
            parent=self.window,
        ):
            return
        self._reset_running = True
        self.reset_button.configure(state="disabled")
        self.status_var.set("Clearing failed functions and restarting…")
        session_path = self.active_session_path()

        def reset() -> None:
            try:
                result = self.controller.clear_failed_and_restart(session_path=session_path)
            except Exception as error:
                message = str(error)
                run_on_ui(lambda: self._clear_failed_restart_failed(message))
            else:
                run_on_ui(lambda: self._clear_failed_restart_done(result))

        threading.Thread(target=reset, name="port-run-reset", daemon=True).start()

    @ui_safe
    def _clear_failed_restart_done(self, result: dict) -> None:
        self._reset_running = False
        self.reset_button.configure(state="normal")
        self._last_terminal_status = None
        self.status_var.set(f"Running (PID {result['pid']})")
        self.updated_var.set(
            f"Restarted {result['reset_functions']:,} failed/active functions · "
            f"preserved {result['preserved_bundles']:,} bundles"
        )
        messagebox.showinfo(
            "Finish Game Port restarted",
            f"Requeued {result['reset_functions']:,} failed or interrupted functions.\n"
            f"Diagnostics archive: {result['archive']}",
            parent=self.window,
        )

    @ui_safe
    def _clear_failed_restart_failed(self, message: str) -> None:
        self._reset_running = False
        self.reset_button.configure(state="normal")
        self.status_var.set("Restart failed")
        messagebox.showerror("Could not restart port run", message, parent=self.window)

    def _preview(self) -> None:
        try:
            url = self.controller.start_preview()
            self.updated_var.set(f"Browser preview: {url}")
        except Exception as error:
            messagebox.showerror("Browser preview", str(error), parent=self.window)

    @ui_safe
    def _render(self, snapshot: PortRunSnapshot) -> None:
        self.status_var.set(snapshot.status.replace("_", " ").title())
        current = next(
            (stage for stage in snapshot.stages if stage.get("id") == snapshot.current_stage),
            None,
        )
        self.stage_var.set(
            str(current.get("label"))
            if current
            else ("All stages complete" if snapshot.status == "completed" else "Waiting at stage boundary")
        )
        self.progress_var.set(snapshot.progress_percent)
        self.elapsed_var.set(format_duration(snapshot.elapsed_seconds))
        self.eta_var.set(
            format_duration(snapshot.eta_seconds)
            + (" · learned stage medians" if snapshot.eta_source == "historical_stage_median" else "")
        )
        self.rate_var.set(
            f"{snapshot.items_per_second:.2f} units/s"
            if snapshot.total_work
            else f"{snapshot.stages_per_minute:.2f} stages/min"
        )
        if snapshot.model_active:
            throughput = "measuring active response"
        elif snapshot.completion_tokens:
            source = "API usage" if snapshot.token_source == "api" else "estimated tokens"
            throughput = (
                f"{snapshot.tokens_per_second:.1f} tok/s · "
                f"{snapshot.prompt_tokens:,} in / {snapshot.completion_tokens:,} out · {source}"
            )
        elif snapshot.llm_api_calls == 0 and snapshot.run_mode in {"resume", "replay"}:
            throughput = "Checkpoint replay · no live model call"
        else:
            throughput = "Waiting for Qwen"
        self.tokens_var.set(throughput)
        self.calls_var.set(
            f"LLM {snapshot.llm_api_calls} · structured {snapshot.structured_tool_calls} "
            f"· Ghidra {snapshot.ghidra_tool_calls}"
        )
        if snapshot.session_path:
            self.session_var.set(f"{snapshot.session_role.title()}: {snapshot.session_path} · vectors not required")
        else:
            self.session_var.set("No active saved session · vectors not required")
        self.updated_var.set(
            f"{snapshot.completed_stages}/{snapshot.total_stages} stages"
            + (f" · updated {snapshot.updated_at}" if snapshot.updated_at else "")
        )

        existing = set(self.stage_tree.get_children())
        for stage in snapshot.stages:
            stage_id = str(stage.get("id"))
            status = str(stage.get("status", "pending"))
            values = (status, stage.get("detail") or stage.get("error") or "")
            if stage_id in existing:
                self.stage_tree.item(stage_id, text=stage.get("label", stage_id), values=values, tags=(status,))
                existing.remove(stage_id)
            else:
                self.stage_tree.insert(
                    "",
                    "end",
                    iid=stage_id,
                    text=stage.get("label", stage_id),
                    values=values,
                    tags=(status,),
                )
        for item in existing:
            self.stage_tree.delete(item)

        for item in self.queue_tree.get_children():
            self.queue_tree.delete(item)
        for item in snapshot.queue:
            self.queue_tree.insert(
                "",
                "end",
                values=(item.get("address", ""), item.get("family", ""), item.get("status", "queued")),
            )
        self.queue_summary_var.set(
            " · ".join(f"{status}: {count:,}" for status, count in snapshot.queue_summary.items())
            if snapshot.queue_summary
            else "Preparing the first function"
        )

        running = self.controller.is_running()
        self.pause_button.configure(state="normal" if running else "disabled")
        self.stop_button.configure(state="normal" if running else "disabled")
        self.resume_button.configure(state="normal")
        self.start_button.configure(state="disabled" if running else "normal")
        self.reset_button.configure(state="disabled" if self._reset_running else "normal")

        if snapshot.status in {"completed", "failed", "stopped"} and snapshot.status != self._last_terminal_status:
            self._last_terminal_status = snapshot.status
            if snapshot.status == "completed":
                messagebox.showinfo(
                    "Finish Game Port",
                    "The verified port transaction completed and the production browser build passed.",
                    parent=self.window,
                )
            elif snapshot.status == "failed":
                messagebox.showerror(
                    "Finish Game Port",
                    "The run failed. Inspect the Pipeline and Live log tabs; any promotion was rolled back.",
                    parent=self.window,
                )

    @ui_safe
    def _append_activity(self, events: list[dict]) -> None:
        if not events:
            return
        coalesced: list[dict] = []
        for event in events:
            kind = str(event.get("kind", "event"))
            address = str(event.get("address") or "")
            if (
                kind in {"assistant_delta", "tool_delta"}
                and coalesced
                and coalesced[-1].get("kind") == kind
                and str(coalesced[-1].get("address") or "") == address
            ):
                coalesced[-1]["content"] = (
                    str(coalesced[-1].get("content") or "")
                    + str(event.get("content") or "")
                )
            else:
                coalesced.append(dict(event))

        self.activity_text.configure(state="normal")
        for event in coalesced:
            kind = str(event.get("kind", "event"))
            address = str(event.get("address") or "")
            content = str(event.get("content") or "")
            if kind == "tool_delta":
                content = (
                    content.replace("\\r\\n", "\n")
                    .replace("\\n", "\n")
                    .replace("\\t", "    ")
                    .replace('\\"', '"')
                )
            if kind in {"assistant_delta", "tool_delta"}:
                stream_kind = "assistant" if kind == "assistant_delta" else "tool"
                if self._stream_kind != kind or self._stream_address != address:
                    heading = f"\n{event.get('title', 'Qwen')}\n"
                    self.activity_text.insert("end", heading, stream_kind)
                    self._activity_chars += len(heading)
                self.activity_text.insert("end", content, "body")
                self._activity_chars += len(content)
                self._stream_kind = kind
                self._stream_address = address
                continue

            self._stream_kind = None
            self._stream_address = None
            timestamp = str(event.get("timestamp") or "")
            clock = timestamp[11:19] if len(timestamp) >= 19 else ""
            heading_tag = (
                "error"
                if kind in {"error", "retry"}
                else "assistant"
                if kind in {"assistant", "result"}
                else kind
                if kind in {"prompt", "tool", "gate", "git"}
                else "body"
            )
            prefix = f"\n{clock}  "
            heading = f"{event.get('title', kind)}\n"
            self.activity_text.insert("end", prefix, "timestamp")
            self.activity_text.insert("end", heading, heading_tag)
            self._activity_chars += len(prefix) + len(heading)
            if content:
                body = content.rstrip() + "\n"
                self.activity_text.insert("end", body, "body")
                self._activity_chars += len(body)
        if self._activity_chars > 300_000:
            self.activity_text.delete("1.0", "end-220000c")
            self._activity_chars = 220_000
        self.activity_text.see("end")
        self.activity_text.configure(state="disabled")

    def _poll(self) -> None:
        if self.window is None or not self.window.winfo_exists():
            return
        try:
            self._render(self.controller.snapshot())
            self._append_activity(self.controller.read_activity_delta())
            delta = self.controller.read_log_delta()
            if delta:
                self.log_text.configure(state="normal")
                self.log_text.insert("end", delta)
                self.log_text.see("end")
                self.log_text.configure(state="disabled")
        except Exception:
            logger.exception("Could not refresh port-run dashboard")
        if self._poll_token is not None:
            try:
                self.root.after_cancel(self._poll_token)
            except Exception:
                pass
        self._poll_token = self.root.after(500, self._poll)

    def detach(self) -> None:
        if self._poll_token is not None:
            try:
                self.root.after_cancel(self._poll_token)
            except Exception:
                pass
            self._poll_token = None
        self.controller.detach()
