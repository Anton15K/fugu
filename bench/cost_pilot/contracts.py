from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

Record = dict[str, Any]
Arm = Literal['fugu', 'agent']
Lane = Literal['security', 'functional']
ULTRA = 'nvidia/Nemotron-3-Ultra-550b-a55b'
SUPER = 'nvidia/nemotron-3-super-120b-a12b'
SPEC_SHA256 = '634e0fda03d87460d04c76f4105bbcced0307080a006b0ad6e4c87314c430017'
PLAN_SHA256 = '410e7b501f2a76473308e5121dbb6e86556a5093b7a4468c3312ada04000b1af'

class SafetyStop(RuntimeError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)

@dataclass(frozen=True)
class FrozenRun:
    path: Path
    doc: Record

@dataclass(frozen=True)
class Attribution:
    pair: str
    arm: Arm
    member: str
    stage: str
    role: str
    turn: int

@dataclass(frozen=True)
class RequestBound:
    service: str
    model: str
    max_input: int
    max_output: int
    max_cache: int
    max_credits: int
    microdollars: int
    tariff_hash: str

@dataclass(frozen=True)
class Ticket:
    id: str
    attribution: Attribution
    bound: RequestBound

@dataclass(frozen=True)
class ArmResult:
    snapshot_id: str
    arm: Arm
    workflow: Literal['complete', 'partial', 'failed', 'unattempted']
    raw: Record
    coverage: Record
    evidence_path: Path

@dataclass(frozen=True)
class ToolReply:
    text: str
    evidence_id: str
    payload: Record

@dataclass(frozen=True)
class Match:
    case: str
    masked_arm: str
    finding_id: str
    truth_id: str | None
    state: Literal['tp', 'fp', 'unresolved', 'duplicate']
    reason: str
    reviewer: str

@dataclass(frozen=True)
class ReportBundle:
    root: Path
    results: Record
    json_path: Path
    csv_path: Path
    markdown_path: Path
