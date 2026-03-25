#!/usr/bin/env python3
"""vma_server.py — FastAPI + WebSocket backend (lean broadcast version)"""

import asyncio
import json
import os
import re
import time
import logging
from collections import defaultdict
from typing import Optional

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

DEBUGFS_PATH  = "/sys/kernel/debug/vma_tracker/data"
READ_CHUNK    = 4096
POLL_INTERVAL = 0.005

app = FastAPI(title="VMA Visualizer")

# ── VMA model ────────────────────────────────────────────────────
def make_vma(start, end, perms, path, vma_type, pid, ts, source_op):
    return {"start": start, "end": end, "len": end - start,
            "perms": perms, "path": path, "type": vma_type,
            "pid": pid, "ts": ts, "source": source_op}

# ── State manager ─────────────────────────────────────────────────
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
                new_lst.append(v); continue
            removed.append(v)
            if vs < start:
                new_lst.append(make_vma(vs, start, v["perms"], v["path"], v["type"], pid, ts, "MUNMAP_CLIP"))
            if ve > end:
                new_lst.append(make_vma(end, ve, v["perms"], v["path"], v["type"], pid, ts, "MUNMAP_CLIP"))
        self._state[pid] = sorted(new_lst, key=lambda x: x["start"])
        return {"event": "MUNMAP", "pid": pid, "ts": ts,
                "start": start, "end": end, "removed": removed}

    def apply_fork(self, parent_pid, child_pid, ts):
        parent_vmas = self._state.get(parent_pid, [])
        self._state[child_pid] = [dict(v, pid=child_pid, source="FORK") for v in parent_vmas]
        return {"event": "FORK", "parent_pid": parent_pid,
                "child_pid": child_pid, "ts": ts, "cloned": len(parent_vmas)}

    def apply_baseline(self, pid, maps_vmas):
        self._state[pid] = sorted(maps_vmas, key=lambda x: x["start"])
        return {"event": "BASELINE", "pid": pid, "count": len(maps_vmas), "ts": time.time_ns()}

    def vmas_only(self, pid):
        """Lean snapshot: just the vma list, no events."""
        return {"pid": pid, "vmas": self._state.get(pid, []), "ts": time.time_ns()}

    def full_snapshot(self):
        return {"all_pids": {str(p): vmas for p, vmas in self._state.items()},
                "ts": time.time_ns()}

state_mgr = VMAStateManager()

# ── /proc/<pid>/maps reader ────────────────────────────────────────
def _classify(perms, path):
    if not path:          return "anon"
    if path == "[heap]":  return "heap"
    if path == "[stack]": return "stack"
    if path.startswith("["): return "special"
    if ".so" in path:     return "shlib_text" if "x" in perms else "shlib_data"
    if "x" in perms:      return "text"
    if "w" in perms:      return "data"
    return "rodata"

def read_proc_maps(pid):
    vmas = []
    try:
        with open(f"/proc/{pid}/maps") as f:
            for line in f:
                parts = line.strip().split(None, 5)
                if len(parts) < 5: continue
                addr_range, perms = parts[0], parts[1]
                map_path = parts[5].strip() if len(parts) == 6 else ""
                s, e = addr_range.split("-")
                start, end = int(s, 16), int(e, 16)
                vmas.append(make_vma(start, end, perms[:3], map_path,
                                     _classify(perms, map_path),
                                     pid, time.time_ns(), "BASELINE"))
    except (FileNotFoundError, PermissionError) as ex:
        log.warning("maps read failed: %s", ex)
    return vmas

# ── Kernel line parser ─────────────────────────────────────────────
_RE = re.compile(
    r"^(\d+)\|(\d+)\|(\S+)\|(\w+)\|(0x[0-9a-f]+)\|(0x[0-9a-f]+)\|(\S+)\|(\S+)\|(\S+)$")

def parse_line(line):
    m = _RE.match(line.strip())
    if not m: return None
    ts, pid, comm, op, start, end, perms, path, vtype = m.groups()
    return {"ts": int(ts), "pid": int(pid), "comm": comm, "op": op,
            "start": int(start, 16), "end": int(end, 16),
            "perms": perms, "path": path, "type": vtype}

# ── WebSocket hub ──────────────────────────────────────────────────
class WSHub:
    def __init__(self):
        self._conns: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws):
        await ws.accept()
        async with self._lock: self._conns.add(ws)

    async def disconnect(self, ws):
        async with self._lock: self._conns.discard(ws)

    async def broadcast(self, msg):
        data = json.dumps(msg, default=str)
        dead = set()
        for ws in list(self._conns):
            try: await ws.send_text(data)
            except: dead.add(ws)
        if dead:
            async with self._lock: self._conns -= dead

hub = WSHub()
tracked_pids: set[int] = set()

# ── Kernel collector ───────────────────────────────────────────────
async def kernel_collector():
    log.info("Collector waiting for %s …", DEBUGFS_PATH)
    buf = ""
    while True:
        if not os.path.exists(DEBUGFS_PATH):
            await asyncio.sleep(1); continue
        try:
            fd = os.open(DEBUGFS_PATH, os.O_RDONLY | os.O_NONBLOCK)
            log.info("Opened debugfs, streaming events…")
            try:
                while True:
                    try:
                        chunk = os.read(fd, READ_CHUNK)
                        if chunk:
                            buf += chunk.decode("utf-8", errors="replace")
                            while "\n" in buf:
                                line, buf = buf.split("\n", 1)
                                ev = parse_line(line)
                                if ev: await handle_event(ev)
                        else:
                            await asyncio.sleep(POLL_INTERVAL)
                    except BlockingIOError:
                        await asyncio.sleep(POLL_INTERVAL)
            finally:
                os.close(fd)
        except OSError as e:
            log.warning("OSError: %s — retry in 1s", e)
            await asyncio.sleep(1)

async def handle_event(ev):
    pid, ts, op = ev["pid"], ev["ts"], ev["op"]

    if pid not in tracked_pids:
        tracked_pids.add(pid)
        baseline = read_proc_maps(pid)
        if baseline:
            state_mgr.apply_baseline(pid, baseline)
            # Send lean baseline: vmas only, no events list
            await hub.broadcast({
                "type": "baseline",
                "payload": state_mgr.vmas_only(pid)
            })
            log.info("Baseline PID %d: %d VMAs", pid, len(baseline))

    if op == "MMAP":
        out = state_mgr.apply_mmap(pid, ev["start"], ev["end"], ev["perms"], ev["path"], ev["type"], ts)
    elif op == "BRK":
        out = state_mgr.apply_brk(pid, ev["start"], ev["end"], ts)
    elif op == "MUNMAP":
        out = state_mgr.apply_munmap(pid, ev["start"], ev["end"], ts)
    elif op == "FORK":
        out = state_mgr.apply_fork(pid, ev["start"], ts)
    else:
        return

    # Lean broadcast: event + vma list only (no events history)
    await hub.broadcast({
        "type":     "vma_event",
        "payload":  out,
        "snapshot": state_mgr.vmas_only(pid)
    })

# ── Endpoints ──────────────────────────────────────────────────────
@app.get("/snapshot")
async def get_snapshot(pid: int = None):
    return JSONResponse(state_mgr.vmas_only(pid) if pid else state_mgr.full_snapshot())

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await hub.connect(ws)
    await ws.send_text(json.dumps({"type": "init",
                                    "payload": state_mgr.full_snapshot()}, default=str))
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
    html_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "index.html")
    with open(html_path) as f:
        return HTMLResponse(f.read())

@app.on_event("startup")
async def startup():
    asyncio.create_task(kernel_collector())

if __name__ == "__main__":
    uvicorn.run("vma_server:app", host="0.0.0.0", port=8000, reload=False, log_level="info")