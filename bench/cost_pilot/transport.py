"""Transparent accounting boundaries, scoped to the benchmark owner process."""
from __future__ import annotations
import contextvars
import copy
import html
import io
import json
import math
import re
import time
import threading
import unicodedata
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import asdict,replace
from pathlib import Path
from types import SimpleNamespace
from .contracts import SafetyStop,SUPER
from .freeze import immutable_json
from .pricing import integer


def serialize_response(response):
    if hasattr(response,'model_dump'):return response.model_dump(mode='json')
    if isinstance(response,dict):return copy.deepcopy(response)
    raise SafetyStop('response_schema')


def safe_artifact(value,secrets):
    forbidden={'authorization','api_key','api-key','access_token','cookie','set-cookie','headers'}
    if isinstance(value,dict):return {k:('[REDACTED]' if k.lower() in forbidden else safe_artifact(v,secrets)) for k,v in value.items()}
    if isinstance(value,(list,tuple)):return [safe_artifact(v,secrets) for v in value]
    if isinstance(value,str):
        for secret in secrets:
            if secret:value=value.replace(secret,'[REDACTED]')
    return value


def validate_web_query(query):
    if not isinstance(query,str) or not query.strip() or len(query)>500:raise SafetyStop('web_query')
    normalized=unicodedata.normalize('NFKC',html.unescape(query))
    for _ in range(8):
        decoded=urllib.parse.unquote(html.unescape(normalized))
        decoded=re.sub(r'\\u([a-fA-F0-9]{4})',lambda m:chr(int(m[1],16)),decoded)
        decoded=unicodedata.normalize('NFKC',decoded)
        if decoded==normalized:break
        normalized=decoded
    normalized=re.sub(r'\s*\.\s*','.',normalized)
    if re.search(r'run_sandbox|query_osv|run_chamber|api\.osv\.dev|/v1/query|docker\s+(exec|run)|mcp\s+call|sandbox[./_:]|chamber[./_:]',normalized,re.I):raise SafetyStop('structured_tool_route')
    return query


class _Proxy:
    def __init__(self,original,**overrides):self._original=original;self._overrides=overrides
    def __getattr__(self,name):return self._overrides[name] if name in self._overrides else getattr(self._original,name)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*a,**k):raise SafetyStop('redirect_blocked')


class GuardedTransport:
    def __init__(self,ledger,pricing,evidence:Path,keys,admission_check):
        if not callable(admission_check):raise SafetyStop('admission_guard_required')
        self.ledger=ledger;self.pricing=pricing;self.evidence=Path(evidence);self.keys=keys;self.admission_check=admission_check
        self._attr=contextvars.ContextVar('cost_pilot_attribution',default=None)
        self._inside=contextvars.ContextVar('cost_pilot_http',default=False)
        self._open=None;self._scope_depth=0;self._osv_count=0;self._turns={};self._mutex=threading.RLock()

    def _admit(self):
        self.ledger.assert_admitted()
        if self.admission_check().get('status')!='admitted':raise SafetyStop('admission_blocked')

    def _observed(self,service,model,request,call,attribution,earmark=None):
        self._admit();bound=self.pricing.bound(service,model)
        ticket=self.ledger.reserve(attribution,bound,earmark=earmark)
        try:
            self._admit();self.ledger.mark_dispatch(ticket);started=time.monotonic()
            response=call();data=serialize_response(response)
            usage=data.get('usage',{}) if service=='nebius' else self._tavily_usage(data)
            actual=self.pricing.settle(bound,usage,data.get('model',''))
            self.write_response(ticket,request,data,time.monotonic()-started)
            self.ledger.settle(ticket,actual,usage)
            return response
        except BaseException:
            self.ledger.retain_unknown(ticket,'response_or_usage_unknown');raise

    def _tavily_usage(self,data):
        observed=[]
        if 'credits' in data:observed.append(integer(data['credits']))
        if 'usage' in data:
            if not isinstance(data['usage'],dict):raise SafetyStop('usage_unknown')
            if 'credits' in data['usage']:observed.append(integer(data['usage']['credits']))
        if observed:
            if len(set(observed))!=1:raise SafetyStop('usage_conflict')
            if self.pricing.tariffs.get('basic_success_exact_credit_contract_verified') is True and observed[0]!=1:raise SafetyStop('usage_contract_drift')
            return {'credits':observed[0],'credit_source':'observed'}
        if self.pricing.tariffs.get('basic_success_exact_credit_contract_verified') is not True:raise SafetyStop('usage_unknown')
        return {'credits':1,'credit_source':'frozen_contract'}

    def sdk(self,request,call,attribution,*,earmark=None):
        allowed={'model','messages','max_tokens','temperature','tools','tool_choice','response_format','n','stream'}
        if not isinstance(request,dict) or set(request)-allowed:raise SafetyStop('request_parameters')
        limit=request.get('max_tokens');choices=request.get('n',1)
        if type(limit) is not int or not 0<=limit<=4096 or type(choices) is not int or choices!=1 or request.get('stream',False) is not False:raise SafetyStop('request_parameters')
        temperature=request.get('temperature',.1)
        if type(temperature) not in (int,float) or not math.isfinite(temperature) or not 0<=temperature<=2:raise SafetyStop('request_parameters')
        bound=self.pricing.bound('nebius',request.get('model',''))
        if limit>bound.max_output:raise SafetyStop('request_parameters')
        return self._observed('nebius',request.get('model',''),request,call,attribution,earmark)

    def write_response(self,ticket,request,response,seconds):
        value={'ticket':asdict(ticket),'request':request,'response':response,'seconds':seconds,'sdk_max_retries':0}
        immutable_json(self.evidence/(ticket.id+'.json'),safe_artifact(value,[self.keys.nebius,self.keys.tavily]))

    def validate_client(self,client):
        from fugu.config import BASE_URL_EU,BASE_URL_US
        retries=getattr(client,'max_retries',None)
        if type(retries) is not int or retries!=0:raise SafetyStop('sdk_retry_policy')
        timeout=getattr(client,'timeout',None)
        values=[timeout] if type(timeout) in (int,float) else [getattr(timeout,k,None) for k in ('connect','read','write','pool')]
        if any(type(v) not in (int,float) or not math.isfinite(v) or not 0<v<=90 for v in values):raise SafetyStop('sdk_timeout')
        endpoint=str(getattr(client,'base_url',''))
        if endpoint not in {BASE_URL_EU,BASE_URL_US} or endpoint!=self.keys.base_url:raise SafetyStop('sdk_endpoint')
        if self.pricing.tariffs.get('endpoint',endpoint)!=endpoint:raise SafetyStop('sdk_endpoint')
        if getattr(getattr(client,'_client',None),'follow_redirects',None) is not False:raise SafetyStop('sdk_redirect_policy')

    def sdk_proxy(self,client,attribution):
        self.validate_client(client)
        context=contextvars.copy_context()
        def create(**request):
            self.validate_client(client)
            with self._mutex:
                key=(attribution.pair,attribution.arm,attribution.member,attribution.stage)
                turn=self._turns.get(key,0)+1;self._turns[key]=turn
            attr=replace(attribution,turn=turn,role='reviewer' if request.get('model')==SUPER else attribution.role)
            return context.copy().run(self.sdk,request,lambda:client.chat.completions.create(**request),attr)
        return _Proxy(client,chat=_Proxy(client.chat,completions=_Proxy(client.chat.completions,create=create)))

    def _perform_http(self,req,timeout):
        token=self._inside.set(True)
        try:
            opener=self._open or urllib.request.build_opener(urllib.request.ProxyHandler({}),_NoRedirect()).open
            with opener(req,timeout=timeout) as r:
                if hasattr(r,'geturl') and r.geturl()!=req.full_url:raise SafetyStop('redirect_blocked')
                return json.loads(r.read())
        finally:self._inside.reset(token)

    def tavily(self,query,attribution):
        validate_web_query(query)
        payload={'query':query,'max_results':5,'search_depth':'basic','include_answer':False}
        req=urllib.request.Request('https://api.tavily.com/search',data=json.dumps(payload).encode(),headers={'Content-Type':'application/json','Authorization':'Bearer '+self.keys.tavily},method='POST')
        return self._observed('tavily','',payload,lambda:self._perform_http(req,20),attribution)

    @contextmanager
    def bind(self,attribution):
        token=self._attr.set(attribution)
        try:yield
        finally:self._attr.reset(token)

    @contextmanager
    def native_scope(self,attribution):
        if self._scope_depth:
            with self.bind(attribution):yield
            return
        import fugu.client
        original_factory=fugu.client.make_client;original_open=urllib.request.urlopen;original_direct=urllib.request.OpenerDirector.open
        self._scope_depth+=1
        # A preinstalled recording fake is retained for unit boundaries. Actual
        # urllib gets a fresh proxy-free, redirect-denying opener.
        self._open=original_open if original_open.__module__!='urllib.request' else None
        def factory(*args,**kw):
            attr=self._attr.get()
            if attr is None:raise SafetyStop('native_attribution_missing')
            return self.sdk_proxy(original_factory(*args,**kw),attr)
        def guarded(req,*args,**kw):
            if self._inside.get():return original_open(req,*args,**kw)
            self._admit();attr=self._attr.get()
            if attr is None:raise SafetyStop('native_attribution_missing')
            if not isinstance(req,urllib.request.Request) or req.get_method()!='POST':raise SafetyStop('native_http_route')
            if req.full_url=='https://api.tavily.com/search':
                payload=json.loads(req.data)
                if set(payload)!={'query','max_results','search_depth','include_answer'} or payload['max_results']!=5 or payload['search_depth']!='basic' or payload['include_answer'] is not False:raise SafetyStop('tavily_parameters')
                data=self.tavily(payload['query'],attr)
            elif req.full_url=='https://api.osv.dev/v1/query' and attr.arm=='fugu':
                self._admit();data=self._perform_http(req,15);self._osv_count+=1
                immutable_json(self.evidence/f'osv-{self._osv_count:06d}.json',{'attribution':asdict(attr),'request':json.loads(req.data),'response':data,'assumption':'public OSV zero-dollar; Fugu only'})
            else:raise SafetyStop('native_http_route')
            return io.BytesIO(json.dumps(data).encode())
        def direct(opener,req,*args,**kw):
            if self._inside.get():return original_direct(opener,req,*args,**kw)
            return guarded(req,*args,**kw)
        fugu.client.make_client=factory;urllib.request.urlopen=guarded;urllib.request.OpenerDirector.open=direct
        try:
            with self.bind(attribution):yield
        finally:
            fugu.client.make_client=original_factory;urllib.request.urlopen=original_open;urllib.request.OpenerDirector.open=original_direct
            self._scope_depth-=1;self._open=None
