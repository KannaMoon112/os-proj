#!/usr/bin/env python3
"""vma_server.py — FastAPI + WebSocket backend (diagnostic + pressure-safe)"""

import asyncio
import json
import logging
import os
import re
import time
from collections import defaultdict
from typing import Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

# ----------------------------- Logging -----------------------------
logging.basicConfig(
    level=os.getenv("VMA_LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("vma_server")

# ----------------------------- Config ------------------------------
DEBUGFS_PATH = os.getenv("VMA_DEBUGFS_PATH", "/sys/kernel/debug/vma_tracker/data")
READ_CHUNK = int(os.getenv("VMA_READ_CHUNK", "4096"))
POLL_INTERVAL = float(os.getenv("VMA_POLL_INTERVAL", "0.005"))

# IMPORTANT for ECS safety:
# Even if kernel module tracks all ("*"), server defaults to malloc_test only.
TRACK_COMM_REGEX = os.getenv("VMA_TRACK_COMM_REGEX", r"^malloc_test$")
COMM_RE = re.compile(TRACK_COMM_REGEX)

# Pressure protections
MAX_TRACKED_PIDS = int(os.getenv("VMA_MAX_TRACKED_PIDS", "32"))
PID_TTL_SECONDS = int(os.getenv("VMA_PID_TTL_SECONDS", "300"))  # stale pid cleanup
MAX_DRAIN_BYTES = int(os.getenv("VMA_MAX_DRAIN_BYTES", str(2 * 1024 * 1024)))  # reset drain cap

HEARTBEAT_SECONDS = int(os.getenv("VMA_HEARTBEAT_SECONDS", "10"))
EVENT_LOG_EVERY = int(os.getenv("VMA_EVENT_LOG_EVERY", "200"))

app = FastAPI(title="VMA Visualizer")

# ----------------------------- Model -------------------------------


def make_vma(start, end, perms, path, vma_type, pid, ts, source_op):
    return {
        "start": start,
        "end": end,
        "len": end - start,
        "perms": perms,
        "path": path,
        "type": vma_type,
        "pid": pid,
        "ts": ts,
        "source": source_op,
    }


class VMAStateManager:
    def __init__(self):
        self._state: dict[int, list] = defaultdict(list)

    def _insert(self, pid, vma):
        lst = self._state[pid]
        i = 0
        while i < len(lst) and lst[i]["start"] < vma["start"]:
            i += 1
        lst.insert(i, vma)

    def apply_mmap(self, pid, start, end, perms, path, vtype, ts):
        vma = make_vma(start, end, perms, path, vtype, pid, ts, "MMAP")
        self._insert(pid, vma)
        return {"event": "MMAP", **vma}

    def apply_brk(self, pid, start, end, ts):
        lst = self._state[pid]
        for i, v in enumerate(lst):
            if v["type"] == "heap":
                old_end = v["end"]
                lst[i] = make_vma(start, end, "rw-", "[heap]", "heap", pid, ts, "BRK")
                return {"event": "BRK", "direction": "grow" if end > old_end else "shrink", **lst[i]}
        vma = make_vma(start, end, "rw-", "[heap]", "heap", pid, ts, "BRK")
        self._insert(pid, vma)
        return {"event": "BRK", "direction": "init", **vma}

    def apply_munmap(self, pid, start, end, ts):
        lst = self._state[pid]
        new_lst, removed = [], []
        for v in lst:
            vs, ve = v["start"], v["end"]
            if ve <= start or vs >= end:
                new_lst.append(v)
                continue
            removed.append(v)
            if vs < start:
                new_lst.append(make_vma(vs, start, v["perms"], v["path"], v["type"], pid, ts, "MUNMAP_CLIP"))
            if ve > end:
                new_lst.append(make_vma(end, ve, v["perms"], v["path"], v["type"], pid, ts, "MUNMAP_CLIP"))
        self._state[pid] = sorted(new_lst, key=lambda x: x["start"])
        return {"event": "MUNMAP", "pid": pid, "ts": ts, "start": start, "end": end, "removed": removed}

    def apply_fork(self, parent_pid, child_pid, ts):
        parent_vmas = self._state.get(parent_pid, [])
        self._state[child_pid] = [dict(v, pid=child_pid, source="FORK") for v in parent_vmas]
        return {"event": "FORK", "parent_pid": parent_pid, "child_pid": child_pid, "ts": ts, "cloned": len(parent_vmas)}

    def apply_baseline(self, pid, maps_vmas):
        self._state[pid] = sorted(maps_vmas, key=lambda x: x["start"])
        return {"event": "BASELINE", "pid": pid, "count": len(maps_vmas), "ts": time.time_ns()}

    def vmas_only(self, pid):
        return {"pid": pid, "vmas": self._state.get(pid, []), "ts": time.time_ns()}

    def full_snapshot(self):
        return {"all_pids": {str(p): vmas for p, vmas in self._state.items()}, "ts": time.time_ns()}

    def reset(self, pid: Optional[int] = None):
        if pid is not None:
            self._state.pop(pid, None)
        else:
            self._state.clear()


state_mgr = VMAStateManager()

# pid -> {"baseline_ok": bool, "comm": str, "last_ts": int}
tracked_pids: dict[int, dict] = {}

stats = {
    "raw_lines": 0,
    "parsed_events": 0,
    "parse_errors": 0,
    "dropped_by_comm": 0,
    "handled_events": 0,
    "baseline_ok": 0,
    "baseline_fail": 0,
    "evicted_pids": 0,
}


def _classify(perms, path):
    if not path:
        return "anon"
    if path == "[heap]":
        return "heap"
    if path == "[stack]":
        return "stack"
    if path.startswith("["):
        return "special"
    if ".so" in path:
        return "shlib_text" if "x" in perms else "shlib_data"
    if "x" in perms:
        return "text"
    if "w" in perms:
        return "data"
    return "rodata"


def read_proc_maps(pid):
    vmas = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.strip().split(None, 5)
                if len(parts) < 5:
                    continue
                addr_range, perms = parts[0], parts[1]
                map_path = parts[5].strip() if len(parts) == 6 else ""
                s, e = addr_range.split("-")
                start, end = int(s, 16), int(e, 16)
                vmas.append(
                    make_vma(start, end, perms[:3], map_path, _classify(perms, map_path), pid, time.time_ns(), "BASELINE")
                )
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError) as ex:
        log.warning("maps read failed for pid=%s: %s", pid, ex)
    return vmas


_HEX_RE = re.compile(r"^0x[0-9a-fA-F]+$")


def parse_line(line: str):
    # ts|pid|comm|op|start|end|perms|path|type
    parts = line.strip().split("|", 8)
    if len(parts) != 9:
        return None
    ts, pid, comm, op, start, end, perms, path, vtype = parts
    if not (_HEX_RE.match(start) and _HEX_RE.match(end)):
        return None
    try:
        return {
            "ts": int(ts),
            "pid": int(pid),
            "comm": comm,
            "op": op,
            "start": int(start, 16),
            "end": int(end, 16),
            "perms": perms,
            "path": path if path != "-" else "",
            "type": vtype,
        }
    except ValueError:
        return None


class WSHub:
    def __init__(self):
        self._conns: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws):
        await ws.accept()
        async with self._lock:
            self._conns.add(ws)

    async def disconnect(self, ws):
        async with self._lock:
            self._conns.discard(ws)

    async def broadcast(self, msg):
        data = json.dumps(msg, default=str)
        dead = set()
        for ws in list(self._conns):
            try:
                await ws.send_text(data)
            except Exception:
                dead.add(ws)
        if dead:
            async with self._lock:
                self._conns -= dead


hub = WSHub()
collector_task: Optional[asyncio.Task] = None
heartbeat_task: Optional[asyncio.Task] = None


def should_track_comm(comm: str) -> bool:
    return bool(COMM_RE.match(comm))


def evict_if_needed():
    if len(tracked_pids) <= MAX_TRACKED_PIDS:
        return
    # evict oldest by last_ts
    victims = sorted(tracked_pids.items(), key=lambda kv: kv[1].get("last_ts", 0))
    overflow = len(tracked_pids) - MAX_TRACKED_PIDS
    for i in range(overflow):
        pid = victims[i][0]
        tracked_pids.pop(pid, None)
        state_mgr.reset(pid)
        stats["evicted_pids"] += 1
        log.warning("Evicted PID %d due to MAX_TRACKED_PIDS=%d", pid, MAX_TRACKED_PIDS)


def cleanup_stale_pids():
    if PID_TTL_SECONDS <= 0:
        return
    now_ns = time.monotonic_ns()
    ttl_ns = PID_TTL_SECONDS * 1_000_000_000
    stale = []
    for pid, info in tracked_pids.items():
        last = info.get("mono_last_seen_ns", now_ns)
        if now_ns - last > ttl_ns:
            stale.append(pid)
    for pid in stale:
        tracked_pids.pop(pid, None)
        state_mgr.reset(pid)
        log.info("Removed stale PID %d (TTL=%ss)", pid, PID_TTL_SECONDS)


async def ensure_baseline(pid: int, comm: str) -> bool:
    info = tracked_pids.setdefault(pid, {"baseline_ok": False, "comm": comm, "last_ts": 0, "mono_last_seen_ns": time.monotonic_ns()})
    if info["baseline_ok"]:
        return True

    baseline = read_proc_maps(pid)
    if not baseline:
        stats["baseline_fail"] += 1
        return False

    state_mgr.apply_baseline(pid, baseline)
    info["baseline_ok"] = True
    stats["baseline_ok"] += 1
    await hub.broadcast({"type": "baseline", "payload": state_mgr.vmas_only(pid)})
    log.info("Baseline PID %d (%s): %d VMAs", pid, comm, len(baseline))
    return True


def drain_debugfs(max_bytes: int = MAX_DRAIN_BYTES) -> int:
    """Drain stale bytes from debugfs kfifo with a hard byte cap."""
    if not os.path.exists(DEBUGFS_PATH):
        return 0
    total = 0
    while total < max_bytes:
        fd = os.open(DEBUGFS_PATH, os.O_RDONLY | os.O_NONBLOCK)
        try:
            chunk = os.read(fd, READ_CHUNK)
        except BlockingIOError:
            chunk = b""
        finally:
            os.close(fd)

        if not chunk:
            break
        total += len(chunk)
    return total


async def handle_event(ev):
    pid, ts, op, comm = ev["pid"], ev["ts"], ev["op"], ev["comm"]

    if not should_track_comm(comm):
        stats["dropped_by_comm"] += 1
        return

    info = tracked_pids.setdefault(pid, {"baseline_ok": False, "comm": comm, "last_ts": 0, "mono_last_seen_ns": time.monotonic_ns()})
    info["comm"] = comm
    info["last_ts"] = ts
    info["mono_last_seen_ns"] = time.monotonic_ns()

    await ensure_baseline(pid, comm)
    evict_if_needed()
    cleanup_stale_pids()

    if op == "MMAP":
        out = state_mgr.apply_mmap(pid, ev["start"], ev["end"], ev["perms"], ev["path"], ev["type"], ts)
        snap_pid = pid
    elif op == "BRK":
        out = state_mgr.apply_brk(pid, ev["start"], ev["end"], ts)
        snap_pid = pid
    elif op == "MUNMAP":
        out = state_mgr.apply_munmap(pid, ev["start"], ev["end"], ts)
        snap_pid = pid
    elif op == "FORK":
        child_pid = int(ev["start"])
        out = state_mgr.apply_fork(pid, child_pid, ts)
        tracked_pids.setdefault(
            child_pid,
            {"baseline_ok": True, "comm": f"{comm}:child", "last_ts": ts, "mono_last_seen_ns": time.monotonic_ns()},
        )
        snap_pid = child_pid
    else:
        return

    stats["handled_events"] += 1
    if stats["handled_events"] % EVENT_LOG_EVERY == 0:
        log.info("Handled events=%d tracked_pids=%d ws=%d", stats["handled_events"], len(tracked_pids), len(hub._conns))

    await hub.broadcast({"type": "vma_event", "payload": out, "snapshot": state_mgr.vmas_only(snap_pid)})


async def kernel_collector():
    log.info(
        "Collector start: debugfs=%s comm_regex=%s max_pids=%d ttl=%ss",
        DEBUGFS_PATH, TRACK_COMM_REGEX, MAX_TRACKED_PIDS, PID_TTL_SECONDS
    )
    buf = ""
    logged_ready = False

    while True:
        if not os.path.exists(DEBUGFS_PATH):
            await asyncio.sleep(1)
            continue

        try:
            fd = os.open(DEBUGFS_PATH, os.O_RDONLY | os.O_NONBLOCK)
            try:
                chunk = os.read(fd, READ_CHUNK)
            except BlockingIOError:
                chunk = b""
            finally:
                os.close(fd)

            if chunk:
                if not logged_ready:
                    log.info("Receiving events from debugfs ...")
                    logged_ready = True

                buf += chunk.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    if not line:
                        continue
                    stats["raw_lines"] += 1
                    ev = parse_line(line)
                    if not ev:
                        stats["parse_errors"] += 1
                        if stats["parse_errors"] <= 5:
                            log.warning("Parse failed line=%r", line)
                        continue
                    stats["parsed_events"] += 1
                    try:
                        await handle_event(ev)
                    except Exception:
                        log.exception("handle_event failed line=%r", line)
            else:
                await asyncio.sleep(POLL_INTERVAL)

        except OSError as e:
            log.warning("OSError reading debugfs: %s (retry 1s)", e)
            await asyncio.sleep(1)


async def heartbeat():
    while True:
        await asyncio.sleep(HEARTBEAT_SECONDS)
        log.info(
            "Heartbeat ws=%d pids=%d state_pids=%d raw=%d parsed=%d parse_err=%d drop_comm=%d handled=%d baseline_ok=%d baseline_fail=%d evicted=%d",
            len(hub._conns),
            len(tracked_pids),
            len(state_mgr._state),
            stats["raw_lines"],
            stats["parsed_events"],
            stats["parse_errors"],
            stats["dropped_by_comm"],
            stats["handled_events"],
            stats["baseline_ok"],
            stats["baseline_fail"],
            stats["evicted_pids"],
        )
        cleanup_stale_pids()


@app.post("/reset")
async def do_reset(pid: int = None, drain: bool = True):
    if pid is not None:
        state_mgr.reset(pid)
        tracked_pids.pop(pid, None)
        log.info("Reset pid=%d", pid)
    else:
        state_mgr.reset()
        tracked_pids.clear()
        dropped = drain_debugfs() if drain else 0
        log.info("Reset all drain=%s dropped_bytes=%d", drain, dropped)

    await hub.broadcast({"type": "reset", "pid": pid})
    return {"ok": True, "pid": pid}


@app.get("/snapshot")
async def get_snapshot(pid: int = None):
    return JSONResponse(state_mgr.vmas_only(pid) if pid else state_mgr.full_snapshot())


@app.get("/metrics")
async def get_metrics():
    return {
        "config": {
            "debugfs_path": DEBUGFS_PATH,
            "track_comm_regex": TRACK_COMM_REGEX,
            "max_tracked_pids": MAX_TRACKED_PIDS,
            "pid_ttl_seconds": PID_TTL_SECONDS,
            "poll_interval": POLL_INTERVAL,
            "read_chunk": READ_CHUNK,
        },
        "stats": stats,
        "runtime": {
            "tracked_pids": len(tracked_pids),
            "state_pids": len(state_mgr._state),
            "ws_clients": len(hub._conns),
        },
    }


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await hub.connect(ws)
    await ws.send_text(json.dumps({"type": "init", "payload": state_mgr.full_snapshot()}, default=str))
    try:
        while True:
            data = await asyncio.wait_for(ws.receive_text(), timeout=30)
            if data == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except (WebSocketDisconnect, asyncio.TimeoutError):
        pass
    finally:
        await hub.disconnect(ws)


@app.get("/")
async def serve_ui():
    # 你当前项目如果前端不是这个路径，改成你的实际 index.html 路径即可
    html_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.on_event("startup")
async def startup():
    global collector_task, heartbeat_task
    collector_task = asyncio.create_task(kernel_collector(), name="kernel_collector")
    heartbeat_task = asyncio.create_task(heartbeat(), name="heartbeat")

    def done_cb(task: asyncio.Task):
        try:
            exc = task.exception()
            if exc:
                log.exception("Task %s crashed: %s", task.get_name(), exc)
        except asyncio.CancelledError:
            pass

    collector_task.add_done_callback(done_cb)
    heartbeat_task.add_done_callback(done_cb)
    log.info("Startup complete")

@app.on_event("shutdown")
async def shutdown():
    for t in (collector_task, heartbeat_task):
        if t and not t.done():
            t.cancel()
    log.info("Shutdown complete")


if __name__ == "__main__":
    uvicorn.run("vma_server:app", host="0.0.0.0", port=8000, reload=False, log_level="info")
