"""Four declarative tools. No auditee imports, execution or arbitrary fetch."""
from __future__ import annotations
import json
import uuid
import html
import unicodedata
import urllib.parse
from pathlib import Path,PurePosixPath
from .contracts import SafetyStop,ToolReply
from .freeze import canonical,digest,tree_manifest,immutable_json
from .transport import validate_web_query

NAMES=('list_files','read_file','search_files','search_web')
FIELDS={'list_files':{'path','cursor'},'read_file':{'path','start_line','end_line','cursor'},'search_files':{'path','query','cursor'},'search_web':{'query'}}


def validate_arguments(name,arguments):
    if name not in NAMES or not isinstance(arguments,dict) or set(arguments)-FIELDS[name]:raise SafetyStop('tool_arguments')
    a=dict(arguments)
    if name!='search_web':
        a.setdefault('path','.');a.setdefault('cursor',None)
        p=a['path']
        if not isinstance(p,str) or not p or len(p)>4096 or PurePosixPath(p).is_absolute() or '..' in PurePosixPath(p).parts or '\\' in p:raise SafetyStop('tool_path')
        if a['cursor'] is not None and not isinstance(a['cursor'],str):raise SafetyStop('cursor')
    if name=='read_file':
        a.setdefault('start_line',1);a.setdefault('end_line',a['start_line']+199 if type(a['start_line']) is int else 0)
        if any(type(a[k]) is not int for k in ('start_line','end_line')) or a['start_line']<1 or a['end_line']<a['start_line'] or a['end_line']-a['start_line']>=200:raise SafetyStop('tool_range')
    if name.startswith('search_'):
        if not isinstance(a.get('query'),str) or not a['query'] or len(a['query'])>500:raise SafetyStop('tool_query')
        if name=='search_web':
            validate_web_query(a['query'])
            q=unicodedata.normalize('NFKC',html.unescape(a['query'])).casefold()
            for _ in range(8):q=urllib.parse.unquote(q)
            if any(token in q for token in ('run_sandbox','query_osv','run_chamber')):raise SafetyStop('structured_tool_route')
    return a


def range_union(ranges):
    merged=[]
    for start,end in sorted(ranges):
        if end<start:raise ValueError('invalid_range')
        if merged and start<=merged[-1][1]:merged[-1]=(merged[-1][0],max(merged[-1][1],end))
        else:merged.append((start,end))
    return merged


def fits(payload):return len(canonical({'evidence_id':'0'*64,**payload}).decode())<=8192


class ToolRegistry:
    def __init__(self,snapshot:Path,snapshot_id:str,snapshot_hash:str,journal:Path,web):
        self.snapshot=Path(snapshot);self.id=snapshot_id;self.hash=snapshot_hash;self.journal=Path(journal);self.web=web
        self.manifest=tree_manifest(self.snapshot)
        if self.manifest['sha256']!=snapshot_hash:raise SafetyStop('source_drift')
        self.files={f['path']:f for f in self.manifest['files']};self._ranges={};self._seen=set();self._omissions={};self._errors=[];self._search=set();self._pending=set()
        self.journal.mkdir(parents=True,exist_ok=True,mode=0o700)

    def schemas(self):
        result=[]
        for name in NAMES:
            props={k:({'type':['string','null']} if k=='cursor' else {'type':'integer','minimum':1} if k.endswith('_line') else {'type':'string'}) for k in sorted(FIELDS[name])}
            required=['path'] if name=='read_file' else ['query'] if name.startswith('search_') else []
            result.append({'type':'function','function':{'name':name,'description':'Read-only '+name,'parameters':{'type':'object','properties':props,'required':required,'additionalProperties':False}}})
        return result

    def _verify(self):
        try:current=tree_manifest(self.snapshot)
        except SafetyStop:raise SafetyStop('source_drift')
        if current['sha256']!=self.hash:raise SafetyStop('source_drift')

    def _path(self,p,*,file=False):
        normalized=PurePosixPath(p).as_posix();current=self.snapshot
        for part in PurePosixPath(p).parts:
            current=current/part
            if current.is_symlink():raise SafetyStop('tool_path')
        if file and normalized not in self.files:raise SafetyStop('tool_path')
        if not file and normalized!='.' and not current.is_dir():raise SafetyStop('tool_path')
        return normalized,current

    def _text(self,p):
        _,path=self._path(p,file=True)
        raw=path.read_bytes()
        import hashlib
        if hashlib.sha256(raw).hexdigest()!=self.files[p]['sha256']:raise SafetyStop('source_drift')
        if b'\x00' in raw[:4096]:
            self._omissions[p]={'path':p,'reason':'binary','bytes':len(raw)}
            raise SafetyStop('binary_file')
        try:return raw.decode('utf-8')
        except UnicodeDecodeError:
            self._omissions[p]={'path':p,'reason':'undecodable','bytes':self.files[p]['bytes']};raise SafetyStop('undecodable')

    def _binding(self,name,a):return {'snapshot':self.id,'hash':self.hash,'name':name,'arguments':{k:v for k,v in a.items() if k!='cursor'}}

    def _cursor(self,binding,state):
        entry={'nonce':uuid.uuid4().hex,'binding':binding,'state':state}
        c=digest(entry)[:32]
        immutable_json(self.journal/'cursors'/(c+'.json'),entry)
        return c

    def dispatch(self,name,arguments):
        try:
            a=validate_arguments(name,arguments);self._path(a['path'],file=name=='read_file') if 'path' in a else None;self._verify()
            binding=self._binding(name,a);state=None
            if a.get('cursor'):
                c=a['cursor']
                if len(c)!=32 or any(ch not in '0123456789abcdef' for ch in c):raise SafetyStop('cursor')
                try:entry=json.loads((self.journal/'cursors'/(c+'.json')).read_text())
                except (OSError,ValueError):raise SafetyStop('cursor')
                if digest(entry)[:32]!=c or entry['binding']!=binding:raise SafetyStop('cursor_binding')
                state=entry['state']
            evidence=digest({'binding':binding,'cursor':a.get('cursor')});cache=self.journal/'replies'/(evidence+'.json')
            if cache.exists():payload=json.loads(cache.read_text())
            else:
                payload={**self._page(name,a,binding,state),'evidence_id':evidence}
                if not fits(payload):raise SafetyStop('tool_metadata_limit')
                immutable_json(cache,payload)
            self._coverage(name,a,payload,evidence)
            return ToolReply(canonical(payload).decode(),evidence,payload)
        except SafetyStop as exc:
            self._errors.append({'tool':name,'reason':exc.reason});raise

    def _page(self,name,a,binding,state):
        if name=='search_web':
            payload=self.web(a['query'])
            # Return bounded individual results; do not cut serialized JSON.
            out={'query':a['query'],'results':[],'omissions':0,'next_cursor':None}
            for r in payload.get('results',[]):
                candidate={**out,'results':out['results']+[r]}
                if fits(candidate):out=candidate
                else:out['omissions']+=1
            return out
        if name=='read_file':return self._read(a,binding,state)
        prefix=a['path'].rstrip('/')+'/' if a['path']!='.' else ''
        paths=[p for p in sorted(self.files) if p.startswith(prefix)]
        if name=='list_files':entries=[{'path':p,**{k:v for k,v in self.files[p].items() if k!='path'}} for p in paths];key='files';limit=200
        else:
            entries=[];key='matches';limit=100
            for p in paths:
                try:text=self._text(p)
                except SafetyStop:continue
                self._search.add(p)
                for n,line in enumerate(text.splitlines(),1):
                    index=line.find(a['query'])
                    if index>=0:entries.append({'path':p,'line':n,'excerpt':line[max(0,index-50):index+150]})
        start=state['index'] if state else 0;end=min(start+limit,len(entries))
        payload={'snapshot_id':self.id,key:entries[start:end],'next_cursor':'0'*32 if end<len(entries) else None}
        while not fits(payload) and end>start:
            end-=1;payload[key]=entries[start:end];payload['next_cursor']='0'*32
        if end==start and start<len(entries):raise SafetyStop('tool_metadata_limit')
        if end<len(entries):payload['next_cursor']=self._cursor(binding,{'index':end})
        return payload

    def _read(self,a,binding,state):
        lines=self._text(a['path']).splitlines(keepends=True);start=a['start_line'];end=min(a['end_line'],len(lines))
        line=state['line'] if state else start;offset=state['offset'] if state else 0
        payload={'snapshot_id':self.id,'path':a['path'],'file_hash':self.files[a['path']]['sha256'],'encoding':'utf-8','requested_range':[start,a['end_line']],'total_lines':len(lines),'segments':[],'next_cursor':'0'*32,'eof':False,'range_complete':False,'omissions':[]}
        while line<=end:
            text=lines[line-1];lo=0;hi=len(text)-offset
            while lo<hi:
                mid=(lo+hi+1)//2;s={'line':line,'char_start':offset,'char_end':offset+mid,'line_chars':len(text),'text':text[offset:offset+mid]}
                if fits({**payload,'segments':payload['segments']+[s]}):lo=mid
                else:hi=mid-1
            if not lo:
                if not payload['segments']:raise SafetyStop('tool_metadata_limit')
                break
            payload['segments'].append({'line':line,'char_start':offset,'char_end':offset+lo,'line_chars':len(text),'text':text[offset:offset+lo]});offset+=lo
            if offset==len(text):line+=1;offset=0
            else:break
        done=line>end;payload['range_complete']=done;payload['eof']=done and end==len(lines)
        payload['next_cursor']=None if done else self._cursor(binding,{'line':line,'offset':offset})
        return payload

    def _coverage(self,name,a,p,evidence):
        if a.get('cursor'):self._pending.discard(a['cursor'])
        if p.get('next_cursor'):self._pending.add(p['next_cursor'])
        if evidence in self._seen:return
        self._seen.add(evidence)
        if name=='read_file':
            spans=self._ranges.setdefault(a['path'],{})
            for s in p['segments']:spans[s['line']]=range_union(spans.get(s['line'],[])+[(s['char_start'],s['char_end'])])

    def coverage(self):
        full=[]
        for p,spans in self._ranges.items():
            lines=self._text(p).splitlines(keepends=True)
            if all(spans.get(n)==[(0,len(line))] for n,line in enumerate(lines,1)):full.append(p)
        return {'inventory_hash':self.hash,'inventory_count':len(self.files),'returned_ranges':self._ranges,'fully_read_paths':sorted(full),'partially_read_paths':sorted(set(self._ranges)-set(full)),'searched_paths':sorted(self._search),'pending_cursors':sorted(self._pending),'omissions':list(self._omissions.values()),'errors':list(self._errors),'incomplete':bool(self._omissions or self._errors or self._pending or len(full)<len(self.files))}
