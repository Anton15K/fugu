import io,json,urllib.request
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
import pytest
from openai.types.chat import ChatCompletion
from fugu.credentials import CredentialSet
from bench.cost_pilot.transport import GuardedTransport,serialize_response,safe_artifact,validate_web_query
from bench.cost_pilot.ledger import Ledger
from bench.cost_pilot.pricing import Pricing
from bench.cost_pilot.contracts import ULTRA,SafetyStop
from tests.cost_pilot.support import fake_tariffs,fake_attribution


def response():
    return ChatCompletion.model_validate({'id':'fake-id','object':'chat.completion','created':0,'model':ULTRA,'choices':[{'index':0,'finish_reason':'tool_calls','message':{'role':'assistant','content':None,'reasoning_content':'retained reasoning','tool_calls':[{'id':'call1','type':'function','function':{'name':'list_files','arguments':'{}'}}]}}], 'usage':{'prompt_tokens':100,'completion_tokens':10,'total_tokens':110,'completion_tokens_details':{'reasoning_tokens':9}},'request_id':'fake-request'})


def transport(l,p):return GuardedTransport(l,Pricing(fake_tariffs(),test_only=True),p,CredentialSet('FAKE-N','FAKE-T'),lambda:{'status':'admitted'})
REQ={'model':ULTRA,'messages':[{'role':'user','content':'audit'}],'max_tokens':4096,'temperature':.1}


def test_unknown_stops_after_catch(tmp_path):
    attempts=[]
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');t=transport(l,tmp_path/'events')
        def call():attempts.append('sdk');raise TimeoutError('FAKE-N')
        with pytest.raises(TimeoutError):t.sdk(REQ,call,fake_attribution('fugu'))
        with pytest.raises(SafetyStop):t.sdk(REQ,call,fake_attribution('fugu'))
        with pytest.raises(SafetyStop):t.tavily('ordinary advisory',fake_attribution('fugu'))
        assert attempts==['sdk'];assert l.summary()['unknown_upper_micro']==17000


def test_sdk_identity_metadata_and_redaction(tmp_path):
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');t=transport(l,tmp_path/'events');r=response()
        assert t.sdk(REQ,lambda:r,fake_attribution()) is r
        data=serialize_response(r)
        assert data['choices'][0]['message']['tool_calls'][0]['id']=='call1'
        assert data['choices'][0]['message']['reasoning_content']=='retained reasoning'
        assert data['request_id']=='fake-request';assert l.summary()['known_micro']==130
        assert safe_artifact({'Authorization':'Bearer FAKE-N','x':'FAKE-T','usage':data['usage']},['FAKE-N','FAKE-T'])['Authorization']=='[REDACTED]'


def test_actual_native_urllib_is_accounted_and_timeout_latches(tmp_path,monkeypatch):
    attempts=[]
    def opener(req,**kw):
        attempts.append(json.loads(req.data));return io.BytesIO(b'{"results": [], "credits": 1}')
    monkeypatch.setattr(urllib.request,'urlopen',opener)
    from fugu.pipeline.stages.reputation import _default_search
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');t=transport(l,tmp_path/'events')
        with t.native_scope(fake_attribution('fugu')):_default_search('FAKE-T','ordinary advisory')
        assert attempts[0]['search_depth']=='basic';assert l.summary()['known_micro']==8000
        assert [e['kind'] for e in l.events()][-3:]==['reserve','dispatch','settle']
    def timeout(*a,**k):raise TimeoutError()
    monkeypatch.setattr(urllib.request,'urlopen',timeout)
    with Ledger(tmp_path/'other') as l:
        l.open_pair('c0');t=transport(l,tmp_path/'other-events')
        with t.native_scope(fake_attribution('fugu')):
            with pytest.raises(TimeoutError):_default_search('FAKE-T','ordinary advisory')
        assert l.summary()['unknown_upper_micro']==8000
        with pytest.raises(SafetyStop):t.sdk(REQ,response,fake_attribution('fugu'))


def test_guard_rechecked_before_dispatch(tmp_path):
    calls=[];checks=[]
    def guard():
        checks.append(1)
        if len(checks)==2:raise SafetyStop('drift')
        return {'status':'admitted'}
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');t=GuardedTransport(l,Pricing(fake_tariffs(),test_only=True),tmp_path/'e',CredentialSet(),guard)
        with pytest.raises(SafetyStop):t.sdk(REQ,lambda:calls.append(1),fake_attribution())
        assert not calls;assert l.summary()['unknown_upper_micro']==17000


def test_native_factory_captures_executor_attribution(tmp_path,monkeypatch):
    import fugu.client
    client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw:response())))
    monkeypatch.setattr(fugu.client,'make_client',lambda *a,**k:client)
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');t=transport(l,tmp_path/'e')
        with t.native_scope(fake_attribution('fugu')):
            wrapped=fugu.client.make_client()
            with ThreadPoolExecutor() as pool:pool.submit(wrapped.chat.completions.create,**REQ).result()
        assert next(e for e in l.events() if e['kind']=='reserve')['attribution']['arm']=='fugu'
        assert fugu.client.make_client() is client


@pytest.mark.parametrize('query',['https%3A%2F%2Fapi.osv.dev%2Fv1%2Fquery','https://api.osv.dev/v1/query','docker exec chamber','ｍｃｐ call sandbox'])
def test_structured_routes_rejected(query):
    with pytest.raises(SafetyStop):validate_web_query(query)


def test_other_native_network_denied(tmp_path,monkeypatch):
    attempts=[];monkeypatch.setattr(urllib.request,'urlopen',lambda *a,**k:attempts.append(1))
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');t=transport(l,tmp_path/'e')
        with t.native_scope(fake_attribution('fugu')):
            with pytest.raises(SafetyStop):urllib.request.urlopen('https://evil.example/')
        assert not attempts


def test_proxy_rejects_unbounded_timeout_and_retries(tmp_path):
    from openai import OpenAI
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0');t=transport(l,tmp_path/'e')
        client=OpenAI(api_key='FAKE-N',base_url='https://api.tokenfactory.nebius.com/v1/',max_retries=0,timeout=300)
        try:
            with pytest.raises(SafetyStop,match='sdk_timeout'):t.sdk_proxy(client,fake_attribution())
        finally:client.close()


def test_owner_admission_context_survives_native_worker(tmp_path,monkeypatch):
    import contextvars
    import fugu.client
    presence=contextvars.ContextVar('fake_owner_presence',default=False)
    client=SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw:response())))
    monkeypatch.setattr(fugu.client,'make_client',lambda *a,**k:client)
    with Ledger(tmp_path/'ledger') as l:
        l.open_pair('c0')
        def guard():
            if not presence.get():raise SafetyStop('credential_context_missing')
            return {'status':'admitted'}
        t=GuardedTransport(l,Pricing(fake_tariffs(),test_only=True),tmp_path/'e',CredentialSet('FAKE-N','FAKE-T'),guard)
        token=presence.set(True)
        try:
            with t.native_scope(fake_attribution('fugu')):
                c=fugu.client.make_client()
                with ThreadPoolExecutor() as pool:assert pool.submit(c.chat.completions.create,**REQ).result().id=='fake-id'
        finally:presence.reset(token)


@pytest.mark.parametrize('q',[r'\u0061pi.osv.dev',r'\u0072un_sandbox','api . osv . dev'])
def test_encoded_structured_routes_do_not_pass(q):
    with pytest.raises(SafetyStop):validate_web_query(q)
