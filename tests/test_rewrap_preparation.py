"""Candidate custody only: independent old-frame and bad-provider oracles."""
import importlib,traceback
from dataclasses import replace
from types import SimpleNamespace
from uuid import UUID,uuid4
import pytest
from cryptalis.crypto import DevelopmentKeyProvider,KeyUnavailable,KeyPolicy,Keyring,KeyContext,WrappedRoot,seal_text,open_text
from cryptalis.crypto.cf1 import equality_term
from test_cf1 import setup_keys,descriptor,TENANT,RECORD


def prepare(source,target):
 return importlib.import_module('cryptalis.crypto._rewrap').prepare_rewrap(source,target)


def test_rewrap_candidate_preserves_frame_search_and_source_policy():
 old,ring=setup_keys(equality=True);source=ring.policy;f=descriptor(equality=True)
 original=seal_text('é e\u0301 雪',f,TENANT,RECORD,ring.prepare())
 target=DevelopmentKeyProvider();candidate=prepare(ring,target)
 assert ring.policy is source and candidate!=source
 assert [w.context for w in candidate.wrappers]==[w.context for w in source.wrappers]
 new=Keyring(candidate,{target.provider_id:target}).prepare()
 assert open_text(original,f,TENANT,RECORD,new)=='é e\u0301 雪'
 assert equality_term('é e\u0301 雪',f,TENANT,new)==original[14:46]
 assert open_text(original,f,TENANT,RECORD,ring.prepare())=='é e\u0301 雪'


def test_historical_reader_roots_are_preserved():
 old,ring=setup_keys(equality=True);p=ring.policy
 context=KeyContext(p.domain_id,p.tenant_id,'payload',UUID(int=81),3)
 future=old.wrap(bytes(range(64,96)),context)
 source=Keyring(replace(p,wrappers=p.wrappers+(future,),payload_generation=3),{old.provider_id:old})
 target=DevelopmentKeyProvider();candidate=prepare(source,target)
 assert candidate.payload_generation==3 and candidate.search_generation==2
 assert len(candidate.wrappers)==3
 assert [target.unwrap(w,w.context) for w in candidate.wrappers]==[old.unwrap(w,w.context) for w in source.policy.wrappers]

@pytest.mark.parametrize('fault',['wrong_root','wrong_context','wrong_provider','wrong_type','identity_drift','unwrap_outage','wrap_outage'])
def test_bad_target_never_returns_partial_candidate(fault):
 _,ring=setup_keys(equality=True);source=ring.policy
 class Target(DevelopmentKeyProvider):
  def wrap(self,root,context):
   if fault=='wrap_outage':raise RuntimeError('PRIVATE_PROVIDER_DETAIL')
   if fault=='wrong_root':root=b'x'*32
   self.last_root=root
   result=super().wrap(root,context)
   if fault=='wrong_context':return replace(result,context=replace(context,root_id=uuid4()))
   if fault=='wrong_provider':return replace(result,provider_id=uuid4())
   if fault=='wrong_type':return object()
   return result
  def unwrap(self,wrapper,context):
   if fault=='unwrap_outage':raise RuntimeError('PRIVATE_PROVIDER_DETAIL')
   if fault in ('wrong_context','wrong_provider','wrong_type'):return self.last_root
   result=super().unwrap(wrapper,context)
   if fault=='identity_drift' and context.purpose=='search':self.provider_id=uuid4()
   return result
 target=Target()
 with pytest.raises(KeyUnavailable) as caught:prepare(ring,target)
 assert 'PRIVATE_PROVIDER_DETAIL' not in ''.join(traceback.format_exception(caught.value))
 assert ring.policy is source


def test_expiry_during_provider_call_returns_no_candidate(monkeypatch):
 import cryptalis.crypto.keys as keys
 now=[100.0];monkeypatch.setattr(keys,'time',SimpleNamespace(monotonic=lambda:now[0],monotonic_ns=lambda:int(now[0]*1e9)))
 _,ring=setup_keys(equality=True,max_age=10)
 class Target(DevelopmentKeyProvider):
  def unwrap(self,wrapper,context):
   result=super().unwrap(wrapper,context)
   if context.purpose=='search':now[0]+=10
   return result
 with pytest.raises(KeyUnavailable):prepare(ring,Target())


def test_interruption_propagates_without_a_candidate():
 _,ring=setup_keys(equality=True)
 class Target(DevelopmentKeyProvider):
  def wrap(self,root,context):raise KeyboardInterrupt()
 with pytest.raises(KeyboardInterrupt):prepare(ring,Target())


def test_wrong_source_process_rejected_before_target_work(monkeypatch):
 _,ring=setup_keys(equality=True);ring._pid=-1
 class Target(DevelopmentKeyProvider):
  def wrap(self,*args):pytest.fail('target work after source process failure')
 with pytest.raises(KeyUnavailable):prepare(ring,Target())


@pytest.mark.parametrize('identity',[None,UUID(int=0),'not-a-uuid'])
def test_invalid_target_identity_refuses_before_provider_work(identity):
 _,ring=setup_keys()
 class Target:
  provider_id=identity
  def wrap(self,*args):pytest.fail('invalid target was invoked')
 with pytest.raises(KeyUnavailable):prepare(ring,Target())


def test_failure_on_second_root_keeps_original_custody_usable():
 _,ring=setup_keys(equality=True);f=descriptor(equality=True)
 original=seal_text('still readable',f,TENANT,RECORD,ring.prepare())
 class Target(DevelopmentKeyProvider):
  def wrap(self,root,context):
   if context.purpose=='search':raise RuntimeError('PRIVATE_SECOND_ROOT')
   return super().wrap(root,context)
 with pytest.raises(KeyUnavailable):prepare(ring,Target())
 assert open_text(original,f,TENANT,RECORD,ring.prepare())=='still readable'
