"""Bounded CF1 search-generation preparation without publication authority."""
from hmac import compare_digest

from ._payload_rotation import MAX_BATCH_BYTES, MAX_BATCH_ROWS, _validate_rows
from .cf1 import FieldDescriptor, open_text, seal_text
from .keys import InvalidContext, KeyUnavailable, PreparedKeys, RepresentationMismatch


def _binding(field,tenant,source,target):
    if (not isinstance(field,FieldDescriptor) or not isinstance(source,PreparedKeys)
            or not isinstance(target,PreparedKeys)):
        raise InvalidContext()
    if ((source.policy.domain_id,source.policy.tenant_id)!=(field.domain_id,tenant) or
            (target.policy.domain_id,target.policy.tenant_id)!=(field.domain_id,tenant)):
        raise KeyUnavailable()
    if field.equality and source.policy.search_generation is None:raise InvalidContext()
    _same_search_keys(source,target)


def _same_search_keys(source,target):
    a,b=source.policy,target.policy
    if (a.domain_id,a.tenant_id)!=(b.domain_id,b.tenant_id):
        raise KeyUnavailable()
    if a.payload_generation!=b.payload_generation or not set(a.wrappers)<=set(b.wrappers):
        raise InvalidContext()
    added=set(b.wrappers)-set(a.wrappers)
    if a.search_generation is None:
        if b.search_generation is not None or added:
            raise InvalidContext()
    elif (len(added)!=1 or b.search_generation is None or
            b.search_generation<=max(w.context.generation for w in a.wrappers if w.context.purpose=='search')):
        raise InvalidContext()
    materials=[]
    for wrapper in a.wrappers:
        c=wrapper.context
        old=source._resolve(c.domain_id,c.tenant_id,c.purpose,c.generation)
        new=target._resolve(c.domain_id,c.tenant_id,c.purpose,c.generation)
        if old.context!=new.context or not compare_digest(old.root,new.root):
            raise InvalidContext()
        materials.append(old)
    if added:
        wrapper=next(iter(added))
        c=wrapper.context
        if c.purpose!='search' or c.generation!=b.search_generation:
            raise InvalidContext()
        material=target._resolve(c.domain_id,c.tenant_id,c.purpose,c.generation)
        if any(c.root_id==old.context.root_id or compare_digest(material.root,old.root) for old in materials):
            raise InvalidContext()


def prepare_search_rotation_batch(rows,field,tenant,*,source,target,
                                  max_rows=1000,max_bytes=64*1024*1024):
    """Authenticate complete rows and return an immutable inactive target batch.

    Searchable frames receive a fresh OS nonce and authenticated target term.
    Storage-only frames remain exact bytes. The shared logical byte budget
    excludes Python, driver and provider overhead. No prefix escapes on failure.
    """
    if (type(rows) is not tuple or type(max_rows) is not int
            or not 1<=max_rows<=MAX_BATCH_ROWS or len(rows)>max_rows
            or type(max_bytes) is not int or not 1<=max_bytes<=MAX_BATCH_BYTES):
        raise InvalidContext()
    _binding(field,tenant,source,target)
    _validate_rows(rows,field,tenant,max_bytes)
    result=[]
    for record,frame in rows:
        if frame is not None and (
                int.from_bytes(frame[6:10],'big')!=source.policy.payload_generation or
                int.from_bytes(frame[10:14],'big')!=(source.policy.search_generation if field.equality else 0)):
            raise RepresentationMismatch()
        value=open_text(frame,field,tenant,record,source)
        transformed=seal_text(value,field,tenant,record,target) if field.equality else frame
        if frame is None:
            if transformed is not None:raise RepresentationMismatch()
        elif (type(transformed) is not bytes or len(transformed)!=len(frame)
                or transformed[:10]!=frame[:10]
                or int.from_bytes(transformed[10:14],'big')!=(target.policy.search_generation if field.equality else 0)):
            raise RepresentationMismatch()
        result.append((record,transformed))
    _binding(field,tenant,source,target)
    return tuple(result)
