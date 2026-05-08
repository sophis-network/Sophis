#!/usr/bin/env python3
"""
cap_5pct_monitor.py — enforces the founder's 5% lifetime cap on mined SPHS.

Implements the auto-pause described in `FOUNDER_SELF_RESTRICTION.md` § 2.3.
Polls a Sophis full node, computes

    ratio = balance(founder_address) / total_emitted_supply

and, when `ratio >= 0.049` (margin under the public 5% commitment),
sends SIGINT to the local `sophis-miner` process so the founder stops
mining before crossing the cap.

It is also useful in `--check-once` mode for any external auditor
(regulator, journalist, holder) to verify the current ratio without
trusting the founder.

Usage:
  # Auditor mode — read once and print, exit
  python cap_5pct_monitor.py --check-once

  # Daemon mode — poll every N seconds and pause miner if needed
  python cap_5pct_monitor.py --interval 60 --auto-pause

  # Custom node / address / threshold
  python cap_5pct_monitor.py \\
      --rpc 127.0.0.1:46110 \\
      --address sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r \\
      --pause-at 0.049 \\
      --auto-pause

Run with `python -m pip install websockets` first if not already installed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
import time
from dataclasses import dataclass
from typing import Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

try:
    import websockets
except ImportError:
    print("This script requires the `websockets` package. Install with:", file=sys.stderr)
    print("    pip install websockets", file=sys.stderr)
    sys.exit(2)

# Default parameters — match `FOUNDER_SELF_RESTRICTION.md` § 1
DEFAULT_RPC_WRPC = "ws://127.0.0.1:48110"  # mainnet wRPC JSON
DEFAULT_FOUNDER_ADDRESS = (
    "sophis:q2sdls98vf40p3v53eyu2ylu3rnfyvjr3cw3gwmuhj8pwnkkgdn5677h7448r"
)
DEFAULT_PAUSE_THRESHOLD = 0.049  # 4.9% — 0.1% safety margin under the 5% public commitment
SOMPI_PER_SOPHIS = 100_000_000


# ────────────────────────────────────────────────────────────────────────────
# RPC helpers
# ────────────────────────────────────────────────────────────────────────────


@dataclass
class CapSnapshot:
    timestamp: float
    address: str
    balance_sompi: int
    total_supply_sompi: int
    ratio: float

    def threshold_status(self, threshold: float) -> str:
        if self.ratio >= threshold:
            return "OVER"
        if self.ratio >= threshold * 0.9:
            return "WARN"
        return "OK"

    def render(self, threshold: float) -> str:
        balance = self.balance_sompi / SOMPI_PER_SOPHIS
        supply = self.total_supply_sompi / SOMPI_PER_SOPHIS
        return (
            f"[{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.timestamp))}] "
            f"founder={balance:,.4f} SPHS  "
            f"emitted={supply:,.4f} SPHS  "
            f"ratio={self.ratio*100:.4f}%  "
            f"threshold={threshold*100:.2f}%  "
            f"status={self.threshold_status(threshold)}"
        )


async def _wrpc_call(endpoint: str, method: str, params: dict) -> dict:
    """Single-shot wRPC JSON call. Raises on transport error."""
    payload = json.dumps({"id": 1, "method": method, "params": params})
    async with websockets.connect(endpoint, open_timeout=10) as ws:
        await ws.send(payload)
        resp = await asyncio.wait_for(ws.recv(), timeout=15)
        return json.loads(resp).get("params", {})


async def fetch_balance(endpoint: str, address: str) -> int:
    """Returns balance in sompi at the given Sophis address."""
    resp = await _wrpc_call(
        endpoint,
        "getBalanceByAddressRequest",
        {"address": address},
    )
    return int(resp.get("balance", 0))


async def fetch_emitted_supply(endpoint: str) -> int:
    """Returns the total emitted SPHS supply (in sompi)."""
    resp = await _wrpc_call(endpoint, "getCoinSupplyRequest", {})
    # getCoinSupply returns: { circulatingSompi, maxSompi }
    return int(resp.get("circulatingSompi", 0))


async def take_snapshot(endpoint: str, address: str) -> CapSnapshot:
    balance = await fetch_balance(endpoint, address)
    supply = await fetch_emitted_supply(endpoint)
    ratio = (balance / supply) if supply > 0 else 0.0
    return CapSnapshot(
        timestamp=time.time(),
        address=address,
        balance_sompi=balance,
        total_supply_sompi=supply,
        ratio=ratio,
    )


# ────────────────────────────────────────────────────────────────────────────
# Miner pause
# ────────────────────────────────────────────────────────────────────────────


def find_miner_pids() -> list[int]:
    """Locate running `sophis-miner` processes. Best-effort across platforms."""
    try:
        import psutil
    except ImportError:
        print(
            "  warning: psutil not installed; cannot auto-pause. Install with `pip install psutil`.",
            file=sys.stderr,
        )
        return []
    pids = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            name = (p.info.get("name") or "").lower()
            if "sophis-miner" in name:
                pids.append(p.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return pids


def pause_miner(pids: list[int]) -> None:
    """Send SIGINT to each miner PID. The miner's signal handler exits cleanly."""
    if not pids:
        print("  no sophis-miner process found to pause.", file=sys.stderr)
        return
    for pid in pids:
        try:
            if sys.platform == "win32":
                # SIGINT on Windows requires a console group; we use SIGTERM.
                os.kill(pid, signal.SIGTERM)
            else:
                os.kill(pid, signal.SIGINT)
            print(f"  sent stop signal to sophis-miner PID {pid}.")
        except ProcessLookupError:
            pass
        except PermissionError as e:
            print(f"  permission denied stopping PID {pid}: {e}", file=sys.stderr)


# ────────────────────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────────────────────


async def run_once(args: argparse.Namespace) -> int:
    snap = await take_snapshot(args.rpc, args.address)
    print(snap.render(args.pause_at))
    if args.json:
        print(
            json.dumps(
                {
                    "timestamp": snap.timestamp,
                    "address": snap.address,
                    "balance_sompi": snap.balance_sompi,
                    "balance_sphs": snap.balance_sompi / SOMPI_PER_SOPHIS,
                    "emitted_sompi": snap.total_supply_sompi,
                    "emitted_sphs": snap.total_supply_sompi / SOMPI_PER_SOPHIS,
                    "ratio": snap.ratio,
                    "threshold": args.pause_at,
                    "status": snap.threshold_status(args.pause_at),
                }
            )
        )
    return 0 if snap.ratio < args.pause_at else 1


async def run_loop(args: argparse.Namespace) -> int:
    paused_once = False
    while True:
        try:
            snap = await take_snapshot(args.rpc, args.address)
            line = snap.render(args.pause_at)
            print(line, flush=True)
            if args.log_file:
                with open(args.log_file, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            if snap.ratio >= args.pause_at and args.auto_pause and not paused_once:
                print("  RATIO HIT THRESHOLD — pausing local sophis-miner.", flush=True)
                pause_miner(find_miner_pids())
                paused_once = True
                if args.exit_on_pause:
                    return 1
            elif snap.ratio < args.pause_at * 0.95 and paused_once:
                # Hysteresis: only resume if ratio drops materially below
                # the threshold (e.g., supply grew while balance unchanged).
                print(
                    "  ratio fell back below threshold; auto-pause flag cleared "
                    "(operator must manually restart sophis-miner).",
                    flush=True,
                )
                paused_once = False
        except Exception as e:
            print(f"  error fetching snapshot: {e}", file=sys.stderr, flush=True)
        await asyncio.sleep(args.interval)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    parser.add_argument("--rpc", default=DEFAULT_RPC_WRPC, help="Sophis wRPC JSON endpoint")
    parser.add_argument("--address", default=DEFAULT_FOUNDER_ADDRESS, help="Founder mining address")
    parser.add_argument(
        "--pause-at",
        type=float,
        default=DEFAULT_PAUSE_THRESHOLD,
        help="Threshold ratio (default 0.049 = 4.9%%, 0.1%% under the 5%% public commitment)",
    )
    parser.add_argument("--check-once", action="store_true", help="Take one snapshot and exit")
    parser.add_argument("--interval", type=float, default=60.0, help="Polling interval in seconds")
    parser.add_argument(
        "--auto-pause",
        action="store_true",
        help="Send SIGINT/SIGTERM to local sophis-miner when ratio crosses --pause-at",
    )
    parser.add_argument(
        "--exit-on-pause",
        action="store_true",
        help="In daemon mode, exit after one auto-pause action",
    )
    parser.add_argument("--log-file", help="Append every snapshot to this CSV-like file")
    parser.add_argument("--json", action="store_true", help="Print snapshot as JSON in --check-once mode")
    args = parser.parse_args()

    if not (0.0 < args.pause_at <= 0.05):
        print(
            f"--pause-at={args.pause_at} is outside the public commitment range (0, 0.05]. "
            "Refusing to run; this would silently override the founder's stated cap.",
            file=sys.stderr,
        )
        return 2

    if args.check_once:
        return asyncio.run(run_once(args))
    return asyncio.run(run_loop(args))


if __name__ == "__main__":
    sys.exit(main())
