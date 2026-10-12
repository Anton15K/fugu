"""Exact approved prompt bytes; no source, truth or system-specific hints."""
import hashlib
import re
from .contracts import SPEC_SHA256,SafetyStop
PROMPT_NAMES=('principal','security_task','functional_task','reviewer','finalization','report_contract')

def extract_prompts(spec):
    raw=spec.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=SPEC_SHA256:raise SafetyStop('spec_drift')
    blocks=re.findall(rb'```text\n(.*?)\n```',raw,re.DOTALL)
    if len(blocks)!=6:raise SafetyStop('prompt_block_count')
    return dict(zip(PROMPT_NAMES,[b.decode() for b in blocks]))

def prompt_hashes(prompts):return {k:hashlib.sha256(v.encode()).hexdigest() for k,v in prompts.items()}
