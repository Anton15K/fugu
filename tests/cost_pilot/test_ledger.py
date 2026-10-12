import json
import os
import subprocess
import sys
from dataclasses import replace
import pytest
from bench.cost_pilot.ledger import Ledger
from bench.cost_pilot.pricing import Pricing
from bench.cost_pilot.contracts import ULTRA, SafetyStop
from tests.cost_pilot.support import fake_tariffs, fake_attribution


def bound(): return Pricing(fake_tariffs(), test_only=True).bound('nebius', ULTRA)


def test_pair_carve_and_earmark(tmp_path):
    with Ledger(tmp_path/'ledger') as ledger:
        ledger.open_pair('c0')
        ledger.earmark(fake_attribution(), 'final', bound())
        t = ledger.reserve(fake_attribution(), bound(), earmark='final')
        assert ledger.summary()['global_admitted_micro'] == 4000000
        assert ledger.summary()['arm_outstanding_micro']['agent'] == 17000
        ledger.mark_dispatch(t)
        ledger.settle(t, 100, {'prompt_tokens':100, 'completion_tokens':0})
        with pytest.raises(SafetyStop): ledger.settle(t, 100, {})
        ledger.close_pair('c0', 'complete')
        assert ledger.summary()['global_liability_micro'] == 100
        assert [e['kind'] for e in ledger.events()][-3:] == ['dispatch','settle','close']


def test_unknown_permanently_stops_and_retains_once(tmp_path):
    with Ledger(tmp_path/'ledger') as ledger:
        ledger.open_pair('c0'); t = ledger.reserve(fake_attribution(), bound())
        ledger.retain_unknown(t, 'timeout'); ledger.close_pair('c0', 'partial')
        assert ledger.summary()['unknown_upper_micro'] == 17000
        assert ledger.summary()['global_liability_micro'] == 17000
        with pytest.raises(SafetyStop, match='timeout'): ledger.assert_admitted()
    with Ledger(tmp_path/'ledger') as ledger:
        with pytest.raises(SafetyStop): ledger.open_pair('c1')


@pytest.mark.parametrize('dispatch',[False,True])
def test_crash_and_competing_owner(tmp_path, dispatch):
    path = tmp_path/'ledger'
    script = '''import os,sys
from pathlib import Path
from bench.cost_pilot.ledger import Ledger
from tests.cost_pilot.test_ledger import bound
from tests.cost_pilot.support import fake_attribution
with Ledger(Path(sys.argv[1])) as l:
 l.open_pair('c0'); t=l.reserve(fake_attribution(),bound())
 if sys.argv[2]=='1': l.mark_dispatch(t)
 os._exit(23)
'''
    env={'PATH':os.environ['PATH'],'PYTHONPATH':os.environ['PYTHONPATH']}
    assert subprocess.run([sys.executable,'-c',script,str(path),str(int(dispatch))],env=env).returncode==23
    with Ledger(path) as l:
        assert l.summary()['unknown_upper_micro']==17000
        with pytest.raises(SafetyStop,match='orphan'): l.assert_admitted()
        probe='''import sys
from pathlib import Path
from bench.cost_pilot.ledger import Ledger
from bench.cost_pilot.contracts import SafetyStop
try:
 with Ledger(Path(sys.argv[1])): sys.exit(9)
except SafetyStop as e: sys.exit(0 if e.reason=='concurrent_owner' else 10)
'''
        assert subprocess.run([sys.executable,'-c',probe,str(path)],env=env).returncode==0


def test_caps_and_no_overlapping_pairs(tmp_path):
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0')
        with pytest.raises(SafetyStop): l.open_pair('c1')
        t=l.reserve(fake_attribution(),replace(bound(),microdollars=1990000))
        with pytest.raises(SafetyStop,match='arm_cap'): l.earmark(fake_attribution(),'review',bound())
        l.mark_dispatch(t); l.settle(t,1990000,{})
        other=replace(fake_attribution(),arm='fugu')
        u=l.reserve(other,replace(bound(),microdollars=1990000)); l.mark_dispatch(u); l.settle(u,1990000,{})
        l.close_pair('c0','complete')
        l.open_pair('c1')
        for arm in ('agent','fugu'):
            a=replace(fake_attribution(),pair='c1',arm=arm)
            u=l.reserve(a,replace(bound(),microdollars=1990000));l.mark_dispatch(u);l.settle(u,1990000,{})
        l.close_pair('c1','complete')
        with pytest.raises(SafetyStop,match='global_cap'):l.open_pair('c2')


@pytest.mark.parametrize('damage',['truncate','hash','sequence'])
def test_corrupt_tail_blocks(tmp_path,damage):
    p=tmp_path/'ledger'
    with Ledger(p) as l: l.open_pair('c0'); l.close_pair('c0','unattempted')
    rows=p.read_bytes().splitlines(keepends=True)
    if damage=='truncate': rows[-1]=rows[-1][:-3]
    else:
        r=json.loads(rows[-1]);r['event_hash' if damage=='hash' else 'seq']='bad';rows[-1]=(json.dumps(r)+'\n').encode()
    p.write_bytes(b''.join(rows))
    with pytest.raises(SafetyStop,match='ledger_corrupt'):
        with Ledger(p):pass


def test_reserve_and_dispatch_fsynced_before_callback(tmp_path,monkeypatch):
    calls=[]; original=os.fsync
    monkeypatch.setattr(os,'fsync',lambda fd:(calls.append('fsync'),original(fd))[1])
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');t=l.reserve(fake_attribution(),bound())
        assert calls[-1]=='fsync'
        l.mark_dispatch(t);calls.append('network')
        assert calls[-2]=='fsync'
        assert [e['kind'] for e in l.events()][-2:]==['reserve','dispatch']
        l.settle(t,1,{})
