"""POSIX lifetime ownership and durable bounded liabilities; no recovery dispatch."""
from __future__ import annotations
import copy
import json
import os
import threading
import uuid
from dataclasses import asdict
from pathlib import Path
from .contracts import Attribution, RequestBound, Ticket, Record, SafetyStop
from .freeze import canonical, digest
from .pricing import integer


class Ledger:
    def __init__(self,path:Path,*,cap_micro:int=10000000,arm_cap_micro:int=2000000):
        self.path=Path(path);self.cap=integer(cap_micro);self.arm_cap=integer(arm_cap_micro)
        if self.cap!=10000000 or self.arm_cap!=2000000:raise SafetyStop('caps')
        self._mutex=threading.RLock();self._records=[];self._tickets={};self._marks={}
        self._closed=set();self._pair=None;self._stop=None;self._fd=None;self._lock=None

    def __enter__(self):
        if os.name!='posix':raise SafetyStop('unsupported_ledger_platform')
        import fcntl
        self.path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        if self.path.is_symlink():raise SafetyStop('ledger_path')
        lock=self.path.with_suffix(self.path.suffix+'.lock')
        self._lock=os.open(lock,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600)
        try:
            try:fcntl.flock(self._lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise SafetyStop('concurrent_owner')
            self._fd=os.open(self.path,os.O_CREAT|os.O_RDWR|os.O_APPEND|getattr(os,'O_NOFOLLOW',0),0o600)
            os.fsync(self._fd)
            parent=os.open(self.path.parent,os.O_RDONLY)
            try:os.fsync(parent)
            finally:os.close(parent)
            with self.path.open('rb') as f:
                for line in f:
                    try:
                        if not line.endswith(b'\n'):raise ValueError()
                        record=json.loads(line);body={k:v for k,v in record.items() if k!='event_hash'}
                        if record['event_hash']!=digest(body) or record['seq']!=len(self._records)+1 or record['previous_hash']!=(self._records[-1]['event_hash'] if self._records else ''):raise ValueError()
                        self._apply(record);self._records.append(record)
                    except (ValueError,KeyError,TypeError,SafetyStop):raise SafetyStop('ledger_corrupt')
            if not self._records:self._record('config',cap=self.cap,arm_cap=self.arm_cap)
            for ident,t in list(self._tickets.items()):
                if t['state'] in {'reserved','dispatched'}:self._record('unknown',id=ident,reason='orphan_reservation')
            return self
        except BaseException:self._release();raise

    def _release(self):
        if self._fd is not None:os.close(self._fd);self._fd=None
        if self._lock is not None:os.close(self._lock);self._lock=None

    def __exit__(self,*exc):
        try:
            for ident,t in list(self._tickets.items()):
                if t['state'] in {'reserved','dispatched'}:self._record('unknown',id=ident,reason='interrupted_reservation')
        finally:self._release()

    def _record(self,kind,**payload):
        if self._fd is None:raise SafetyStop('ledger_closed')
        with self._mutex:
            body={'seq':len(self._records)+1,'previous_hash':self._records[-1]['event_hash'] if self._records else '', 'kind':kind,**payload}
            record={**body,'event_hash':digest(body)}
            data=canonical(record)+b'\n';offset=0
            while offset<len(data):
                written=os.write(self._fd,data[offset:])
                if not written:raise SafetyStop('ledger_write')
                offset+=written
            os.fsync(self._fd)
            self._apply(record);self._records.append(record)

    def _apply(self,r):
        k=r['kind']
        if k=='config':
            if self._records or r['cap']!=self.cap or r['arm_cap']!=self.arm_cap:raise SafetyStop('config')
        elif k=='open':
            if self._pair or r['pair'] in self._closed:raise SafetyStop('pair')
            self._pair=r['pair'];self._marks={}
        elif k=='earmark':self._marks[r['key']]=r['amount']
        elif k=='reserve':
            if r['id'] in self._tickets or r['attribution']['pair']!=self._pair:raise SafetyStop('ticket')
            if r['earmark'] is not None:del self._marks[r['earmark']]
            self._tickets[r['id']]={**r,'state':'reserved'}
        elif k in {'dispatch','settle','unknown'}:
            t=self._tickets[r['id']]
            if k=='dispatch' and t['state']!='reserved':raise SafetyStop('transition')
            if k=='settle' and t['state']!='dispatched':raise SafetyStop('transition')
            if k=='unknown' and t['state'] not in {'reserved','dispatched'}:raise SafetyStop('transition')
            if k=='settle':integer(r['actual']);t['actual']=r['actual']
            t['state']={'dispatch':'dispatched','settle':'settled','unknown':'unknown'}[k]
            if k=='unknown':self._stop=r['reason']
        elif k=='close':
            if r['pair']!=self._pair:raise SafetyStop('pair')
            self._closed.add(self._pair);self._pair=None;self._marks={}
        else:raise SafetyStop('event')

    def assert_admitted(self):
        if self._fd is None:raise SafetyStop('ledger_closed')
        if self._stop:raise SafetyStop(self._stop)

    def open_pair(self,pair:str):
        with self._mutex:
            self.assert_admitted()
            if self._pair or pair in self._closed:raise SafetyStop('pair_overlap_or_repeat')
            if self.summary()['global_liability_micro']+4000000>self.cap:raise SafetyStop('global_cap')
            self._record('open',pair=pair)

    def _arm(self,a):
        self.assert_admitted()
        if a.pair!=self._pair or a.arm not in {'agent','fugu'}:raise SafetyStop('attribution')
        return self.summary()['arm_outstanding_micro'][a.arm]

    def earmark(self,attribution:Attribution,name:str,bound:RequestBound):
        with self._mutex:
            current=self._arm(attribution);key=attribution.arm+':'+name
            if key in self._marks:raise SafetyStop('earmark_duplicate')
            amount=integer(bound.microdollars)
            if current+amount>self.arm_cap:raise SafetyStop('arm_cap')
            self._record('earmark',key=key,amount=amount)

    def reserve(self,attribution:Attribution,bound:RequestBound,*,earmark:str|None=None)->Ticket:
        with self._mutex:
            current=self._arm(attribution);key=attribution.arm+':'+earmark if earmark else None
            if key and (key not in self._marks or self._marks[key]<bound.microdollars):raise SafetyStop('earmark_missing')
            if current-(self._marks.get(key,0))+integer(bound.microdollars)>self.arm_cap:raise SafetyStop('arm_cap')
            ticket=Ticket(uuid.uuid4().hex,attribution,bound)
            self._record('reserve',id=ticket.id,attribution=asdict(attribution),bound=asdict(bound),earmark=key)
            return ticket

    def _ticket(self,ticket):
        t=self._tickets.get(ticket.id)
        if t is None or t['attribution']!=asdict(ticket.attribution) or t['bound']!=asdict(ticket.bound):raise SafetyStop('ticket_unknown')
        return t

    def mark_dispatch(self,ticket:Ticket):
        with self._mutex:
            self.assert_admitted()
            if self._ticket(ticket)['state']!='reserved':raise SafetyStop('ticket_transition')
            self._record('dispatch',id=ticket.id)

    def settle(self,ticket:Ticket,actual_micro:int,usage:Record):
        with self._mutex:
            t=self._ticket(ticket);actual_micro=integer(actual_micro)
            if t['state']!='dispatched' or actual_micro>ticket.bound.microdollars:raise SafetyStop('settlement_invalid')
            self._record('settle',id=ticket.id,actual=actual_micro,usage=usage)

    def retain_unknown(self,ticket:Ticket,reason:str):
        with self._mutex:
            if self._ticket(ticket)['state'] not in {'reserved','dispatched'}:raise SafetyStop('ticket_transition')
            self._record('unknown',id=ticket.id,reason=reason)

    def close_pair(self,pair:str,status:str):
        with self._mutex:
            if self._pair!=pair:raise SafetyStop('pair_invalid')
            for ident,t in list(self._tickets.items()):
                if t['attribution']['pair']==pair and t['state'] in {'reserved','dispatched'}:self._record('unknown',id=ident,reason='unsettled_close')
            self._record('close',pair=pair,status=status)

    def summary(self)->Record:
        with self._mutex:
            known=sum(t.get('actual',0) for t in self._tickets.values() if t['state']=='settled')
            unknown=sum(t['bound']['microdollars'] for t in self._tickets.values() if t['state']=='unknown')
            arms={a:sum((t.get('actual',0) if t['state']=='settled' else t['bound']['microdollars']) for t in self._tickets.values() if t['attribution']['pair']==self._pair and t['attribution']['arm']==a)+sum(v for k,v in self._marks.items() if k.startswith(a+':')) for a in ('agent','fugu')}
            prior=sum((t.get('actual',0) if t['state']=='settled' else t['bound']['microdollars'] if t['state']=='unknown' else 0) for t in self._tickets.values() if t['attribution']['pair']!=self._pair)
            return {'known_micro':known,'unknown_upper_micro':unknown,'global_liability_micro':known+unknown,'global_admitted_micro':prior+(4000000 if self._pair else 0),'arm_outstanding_micro':arms,'active_pair':self._pair,'stop':self._stop}

    def events(self):return copy.deepcopy(self._records)
