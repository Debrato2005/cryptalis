import json,re,sys
from pathlib import Path
from run_stock_postgres import pg,statements,report,bytea,term
header="decode('4346310001010000000100000001','hex')"
setup = [
'SET ROLE revamp_owner;',
'CREATE TABLE revamp_packed(id bigint PRIMARY KEY,payload bytea NOT NULL);',
f'INSERT INTO revamp_packed SELECT id,{header}||eq||payload FROM revamp_protected;',
'CREATE UNIQUE INDEX revamp_packed_eq ON revamp_packed USING btree ((substring(payload FROM 15 FOR 32)) bytea_ops);',
'ANALYZE revamp_packed;',
]
output=pg(statements(([] if '--measure-only' in sys.argv else setup)+[
'SET ROLE revamp_owner;',
'EXPLAIN (ANALYZE,BUFFERS,TIMING OFF) SELECT id FROM revamp_packed WHERE substring(payload FROM 15 FOR 32)='+bytea(term('equality',b'user500000@example.test'))+';',
report('rows','SELECT count(*) FROM revamp_packed'),
report('total_bytes',"SELECT pg_total_relation_size('revamp_packed')"),
report('exact_ids',"SELECT (SELECT array_agg(id ORDER BY id) FROM revamp_packed WHERE substring(payload FROM 15 FOR 32)="+bytea(term('equality',b'user500000@example.test'))+")=(SELECT array_agg(id ORDER BY id) FROM revamp_plain WHERE email='user500000@example.test')"),
report('transport_volatility',"SELECT jsonb_object_agg(proname,provolatile) FROM pg_proc WHERE proname IN ('int8send','uuid_send','substring') AND (proname!='substring' OR oid=2012)"),
]),'packed-expression')
parsed={}
for line in output.splitlines():
    match=re.search(r'({"label".*})',line)
    if match:
        entry=json.loads(match.group(1));parsed[entry['label']]=entry['value']
assert parsed.get('rows')==1000000 and parsed.get('exact_ids') is True
result={'rows':parsed['rows'],'total_bytes':parsed['total_bytes'],'transport_volatility':parsed['transport_volatility'],'role':'SET ROLE non-superuser owner','packed_expression_index_used':'Index Scan using revamp_packed_eq' in output,'exact_id_array_match':'"value" : true' in output,'crypto_frame':'CF1-shaped physical surrogate; not CF1 authentication evidence','full_application':'UNKNOWN'}
assert result['packed_expression_index_used'] and result['exact_id_array_match']
Path(__file__).with_name('results').joinpath('packed-expression.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
