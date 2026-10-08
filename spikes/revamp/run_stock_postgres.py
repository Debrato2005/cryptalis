"""Stock-PG physical and token tests. Single-user mode does not qualify a service."""
import hashlib
import hmac
import json
import math
from pathlib import Path
import random
import re
import statistics
import subprocess
import sys
import time
from collections import Counter

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

ROOT = Path(__file__).resolve().parents[2]
PG = ROOT / "spikes/.venv/lib/python3.12/site-packages/pgserver/pginstall/bin/postgres"
DATA = Path("/tmp/cryptalis-revamp-pg/data")
RESULTS = Path(__file__).with_name("results")
KEY = bytes(range(32))  # Public lab material, never used with real data.
DOMAIN = b"stock-fixture/tenant/"
NAMES = ["Olivia", "Emma", "Amelia", "Charlotte", "Sophia", "Isabella", "Ava", "Mia", "Evelyn", "Luna", "Zoe"]
WEIGHTS = [19, 17, 14, 12, 10, 8, 7, 5, 4, 3, 1]


def term(purpose, value):
    return hmac.digest(KEY, DOMAIN + purpose.encode() + b"\x00" + value, "sha256")


def prefix_terms(value):
    return [term("prefix", value[:n].encode()) for n in range(len(value) + 1)]


def node_term(depth, prefix):
    return term("range", bytes([depth]) + prefix.to_bytes(2, "big"))


def range_terms(value, bits=7):
    assert type(value) is int and 0 <= value < 2**bits
    return [node_term(depth, value >> (bits-depth)) for depth in range(bits+1)]


def cover(lo, hi, bits=7):
    if lo > hi:
        return []
    if lo < 0 or hi >= 2**bits:
        raise ValueError("Query exceeds the declared numeric domain")
    result = []
    while lo <= hi:
        size = lo & -lo if lo else 2**bits
        size = min(size, 2**int(math.log2(hi-lo+1)))
        depth = bits - (size.bit_length()-1)
        result.append(node_term(depth, lo // size))
        lo += size
    return result


def pg(sql, name, expected_errors=()):
    output = subprocess.run([str(PG), "--single", "-D", str(DATA), "-j", "postgres"],
                            input=sql, text=True, capture_output=True)
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / f"{name}.log").write_text(output.stdout + output.stderr)
    errors = re.findall(r"(?:ERROR|FATAL|PANIC):\s*(.*)", output.stdout+output.stderr)
    if output.returncode or len(errors) != len(expected_errors):
        raise RuntimeError(f"PostgreSQL phase {name} failed. Inspect its synthetic log.")
    for actual, expected in zip(errors, expected_errors):
        if expected not in actual:
            raise RuntimeError(f"Unexpected PostgreSQL error in phase {name}")
    return output.stdout


def bytea(value):
    return "'\\x" + value.hex() + "'::bytea"


def arr(values):
    return "ARRAY[" + ",".join(bytea(x) for x in values) + "]::bytea[]"


def report(label, sql):
    return "COPY (SELECT json_build_object('label','" + label + "','value',(" + sql + "))) TO STDOUT;\n\n"


def statements(parts):
    return "\n\n".join(parts) + "\n\n"


def rank_frequency_classes(observed_counts, auxiliary_counts):
    """Attacker input contains visible class counts and auxiliary labels only."""
    encrypted = sorted(observed_counts, key=lambda value: (-observed_counts[value], value))
    plaintext = sorted(auxiliary_counts, key=lambda value: (-auxiliary_counts[value], value))
    return dict(zip(encrypted, plaintext))


def local_checks():
    checks = {}
    trials = 0
    point_sets = [set(range_terms(value)) for value in range(128)]
    for lo in range(128):
        for hi in range(lo, 128):
            query = set(cover(lo, hi))
            for value in range(128):
                assert bool(query.intersection(point_sets[value])) == (lo <= value <= hi)
                trials += 1
    checks["range_exact_cases"] = trials
    values = ["", "Deb", "Debrato", "deB", "é", "e\u0301", "İ", "ß", "a%b", "a_b", "😀a"]
    trials = 0
    for value in values:
        for prefix in values:
            assert (term("prefix", prefix.encode()) in prefix_terms(value)) == value.startswith(prefix)
            trials += 1
    checks["prefix_exact_cases"] = trials
    # Ngrams have a decisive false-positive counterexample. No hidden postfilter.
    grams = lambda value: {value[i:i+3] for i in range(max(0, len(value)-2))}
    assert grams("abcd") <= grams("abcXbcd") and "abcd" not in "abcXbcd"
    checks["ngram_contains_counterexample"] = "REJECT_EXACT_SUBSTRING_PROMISE"
    rng = random.Random(20261007)
    private = rng.choices(NAMES, weights=WEIGHTS, k=100_000)
    auxiliary = random.Random(20261008).choices(NAMES, weights=WEIGHTS, k=100_000)
    counts = {name: private.count(name) for name in NAMES}
    aux_counts = {name: auxiliary.count(name) for name in NAMES}
    observed = {term("equality", name.encode()).hex(): count for name,count in counts.items()}
    guesses = rank_frequency_classes(observed, aux_counts)
    correct = sum(count for name,count in counts.items() if guesses[term("equality", name.encode()).hex()] == name)
    checks["frequency_attack"] = {"technique": "frequency ranking (Naveed et al. CCS 2015)",
                                  "dataset": "independently sampled synthetic name frequencies; not real records",
                                  "rows": len(private), "auxiliary_rows": len(auxiliary),
                                  "row_recovery_rate": correct/len(private),
                                  "class_recovery_rate": sum(guesses[term("equality", name.encode()).hex()]==name for name in NAMES)/len(NAMES),
                                  "real_customer_distribution": "UNKNOWN"}
    def attack(values, auxiliary_values, representation):
        signature = lambda value: hashlib.sha256(b"".join(sorted(representation(value)))).hexdigest()
        private_counts = Counter(values)
        aux_counts = Counter(auxiliary_values)
        observed_counts = Counter(signature(value) for value in values)
        guesses = rank_frequency_classes(observed_counts, aux_counts)
        correct = sum(count for value,count in private_counts.items() if guesses.get(signature(value))==value)
        return {"technique":"frequency ranking of observable full token-array equivalence classes",
                "rows":len(values),"auxiliary_rows":len(auxiliary_values),"row_recovery_rate":correct/len(values),
                "class_recovery_rate":sum(guesses.get(signature(value))==value for value in private_counts)/len(private_counts),
                "real_customer_distribution":"UNKNOWN","structure_attack":"NOT_EXECUTED"}
    checks["prefix_frequency_attack"] = attack(private,auxiliary,prefix_terms)
    age_rng=random.Random(20261009);aux_age_rng=random.Random(20261010)
    ages=[max(18,min(95,round(age_rng.gauss(40,17)))) for _ in range(100000)]
    auxiliary_ages=[max(18,min(95,round(aux_age_rng.gauss(40,17)))) for _ in range(100000)]
    checks["range_frequency_attack"] = attack(ages,auxiliary_ages,range_terms)
    return checks


def main():
    RESULTS.mkdir(exist_ok=True)
    checks = local_checks()
    (RESULTS / "token-checks.json").write_text(json.dumps(checks, indent=2)+"\n")
    print(json.dumps({"token_checks": checks["range_exact_cases"], "frequency_attack": checks["frequency_attack"]}), flush=True)
    if "--offline-only" in sys.argv:
        return
    role = "SET ROLE revamp_owner;"
    ddl = [
        "CREATE UNIQUE INDEX revamp_eq ON revamp_protected USING btree(eq bytea_ops);",
        "CREATE INDEX revamp_prefix ON revamp_protected USING gin(prefix array_ops);",
        "CREATE INDEX revamp_range ON revamp_protected USING gin(range_terms array_ops);",
        "CREATE UNIQUE INDEX revamp_plain_eq ON revamp_plain USING btree(email);",
        "CREATE INDEX revamp_plain_prefix ON revamp_plain USING btree(name text_pattern_ops);",
        "CREATE INDEX revamp_plain_range ON revamp_plain USING btree(age);",
        "ANALYZE revamp_plain;", "ANALYZE revamp_protected;",
    ]
    client_seconds = None
    if "--measure-only" not in sys.argv:
        pg(statements([role,
            "CREATE TABLE revamp_plain(id bigint PRIMARY KEY,email text,name text,age bigint);",
            "CREATE TABLE revamp_protected(id bigint PRIMARY KEY,payload bytea NOT NULL,eq bytea NOT NULL,prefix bytea[] NOT NULL,range_terms bytea[] NOT NULL);",
            "CREATE TEMP TABLE fixture(name text,age bigint,prefix bytea[],range_terms bytea[]);",
        ]), "schema")
        # Client-generated tokens. Repeated fixture rows are a physical index benchmark.
        fixture = []
        for name in NAMES:
            for age in range(18,96):
                fixture.append("("+"'"+name+"',"+str(age)+","+arr(prefix_terms(name))+","+arr(range_terms(age))+")")
        pg(statements([role, "CREATE TABLE revamp_fixture(name text,age bigint,prefix bytea[],range_terms bytea[]);",
                       "INSERT INTO revamp_fixture VALUES "+",".join(fixture)+";"]), "fixture")
        # Exactly one million distinct client-generated equality terms and payloads.
        # Tokens for repeated names/ages use fixture joins. PostgreSQL gets no key.
        sql_file = Path("/tmp/cryptalis-revamp-pg/load.sql")
        rng = random.Random(20261007)
        cipher = AESGCMSIV(KEY)
        start = time.perf_counter()
        with sql_file.open("w") as sink:
            sink.write(role+"\n\nCREATE TABLE revamp_input(id bigint PRIMARY KEY,payload bytea,eq bytea,name text,age bigint);\n\n")
            for first in range(1,1_000_001,1000):
                rows = []
                for identity in range(first,first+1000):
                    email = f"user{identity}@example.test"
                    name = rng.choices(NAMES,weights=WEIGHTS,k=1)[0]
                    age = max(18,min(95,round(rng.gauss(40,17))))
                    nonce = hashlib.sha256(b"disposable-benchmark-nonce/"+identity.to_bytes(8,"big")).digest()[:12]
                    # Deterministic unique lab nonces are NOT the proposed runtime RNG.
                    payload = nonce+cipher.encrypt(nonce,email.encode(),identity.to_bytes(8,"big"))
                    rows.append(f"({identity},{bytea(payload)},{bytea(term('equality',email.encode()))},'{name}',{age})")
                sink.write("INSERT INTO revamp_input VALUES "+",".join(rows)+";\n\n")
            sink.write("INSERT INTO revamp_plain SELECT id,'user'||id||'@example.test',name,age FROM revamp_input;\n\n")
            sink.write("INSERT INTO revamp_protected SELECT i.id,i.payload,i.eq,f.prefix,f.range_terms FROM revamp_input i JOIN revamp_fixture f USING(name,age);\n\n")
        client_seconds = time.perf_counter()-start
        print(json.dumps({"load_input_bytes": sql_file.stat().st_size, "client_generation_seconds": client_seconds}),flush=True)
        with sql_file.open() as source:
            with (RESULTS/"load.log").open("w") as log:
                proc=subprocess.run([str(PG),"--single","-D",str(DATA),"-j","postgres"],stdin=source,stdout=log,stderr=subprocess.STDOUT)
        load_text=(RESULTS/"load.log").read_text()
        if proc.returncode or re.search(r"(?:ERROR|FATAL|PANIC):",load_text):
            raise RuntimeError("Physical load failed")
        pg(statements([role]+ddl),"indexes")
    needle=term("equality",b"user500000@example.test")
    queries={
        "equality": (f"SELECT id FROM revamp_protected WHERE eq={bytea(needle)}", "SELECT id FROM revamp_plain WHERE email='user500000@example.test'"),
        "prefix": (f"SELECT id FROM revamp_protected WHERE prefix @> {arr([term('prefix',b'Z')])}", "SELECT id FROM revamp_plain WHERE name LIKE 'Z%'"),
        "range": (f"SELECT id FROM revamp_protected WHERE range_terms && {arr(cover(94,95))}", "SELECT id FROM revamp_plain WHERE age BETWEEN 94 AND 95"),
    }
    measured={}
    for capability,(protected,plain) in queries.items():
        parts=[role]
        for query in (plain,protected):
            for _ in range(21):
                parts.append("EXPLAIN (ANALYZE,BUFFERS,TIMING OFF) "+query+";")
        parts.append("SELECT (SELECT array_agg(id ORDER BY id) FROM ("+plain+") p) IS NOT DISTINCT FROM (SELECT array_agg(id ORDER BY id) FROM ("+protected+") e) AS exact_match;")
        output=pg(statements(parts),capability)
        timings=[float(x) for x in re.findall(r'Execution Time: ([0-9.]+) ms',output)]
        if len(timings)!=42:
            raise RuntimeError(f"Missing timing observations for {capability}")
        assert 'exact_match = "t"' in output
        baseline=timings[1:21]; encrypted=timings[22:42]
        percentile=lambda values,p: sorted(values)[math.ceil(len(values)*p)-1]
        protected_output = "Execution Time:".join(output.split("Execution Time:")[21:42])
        measured[capability]={"index_scan": "Index Scan" in protected_output or "Index Only Scan" in protected_output or "Bitmap Index Scan" in protected_output,
                             "exact_selected_ids":True,"database_only_ms":{"plain_p50":statistics.median(baseline),"protected_p50":statistics.median(encrypted),
                             "plain_p95":percentile(baseline,.95),"protected_p95":percentile(encrypted,.95)},
                             "iterations_after_warmup":20,"ddl":ddl[["equality","prefix","range"].index(capability)]}
    size_sql=statements([role, report("rows","SELECT count(*) FROM revamp_protected"),
                       report("protected_bytes","SELECT pg_total_relation_size('revamp_protected')"),
                       report("plain_bytes","SELECT pg_total_relation_size('revamp_plain')"),
                       report("privileges","SELECT row_to_json(p) FROM (SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user) p"),
                       report("extensions","SELECT array_agg(extname) FROM pg_extension"),
                       "SELECT 1/(CASE WHEN (SELECT count(*) FROM revamp_protected)=1000000 THEN 1 ELSE 0 END);"])
    size_output=pg(size_sql,"sizes")
    parsed={}
    for line in size_output.splitlines():
        match = re.search(r'({"label".*})', line)
        if match:
            item=json.loads(match.group(1));parsed[item['label']]=item['value']
    if parsed.get("rows")!=1_000_000:
        raise RuntimeError("Missing million-row evidence")
    # The backend exit code alone does not report SQL failure.
    pg(statements([role,"CREATE FUNCTION revamp_untrusted() RETURNS integer AS 'libc','puts' LANGUAGE c;",
                   "CREATE ROLE should_be_denied;",
                   "INSERT INTO revamp_protected SELECT id+1000000,payload,eq,prefix,range_terms FROM revamp_protected WHERE id=500000;",
                  ]),"privilege-negative-controls",("permission denied for language c","permission denied to create role","duplicate key value violates unique constraint"))
    result={"postgres":"16.2","mode":"single-user SET ROLE revamp_owner","restricted_role":True,
            "service_authentication_concurrency_and_driver":"NOT_TESTED_SOCKET_BLOCKED","row_count":parsed["rows"],
            "measurements":measured,"sizes":parsed,"storage_multiplier":parsed["protected_bytes"]/parsed["plain_bytes"],
            "client_generation_seconds":client_seconds,"whole_backend_latency":"UNMEASURED",
            "scope":"Physical queries over client-generated HMAC representations. No ORM/driver/KMS timing or service privileges proven.",
            "stock_extensions_required":[],"majors_not_executed":[14,15,17,18]}
    (RESULTS/"stock-postgres.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result),flush=True)


if __name__=="__main__":
    main()
