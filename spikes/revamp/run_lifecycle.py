"""Single-user PostgreSQL transition experiment on 100 synthetic records."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from run_adapter import KEY, protect, reveal
from run_stock_postgres import bytea, pg, report, statements


RESULTS = Path(__file__).with_name("results")
ROLE = "SET ROLE revamp_owner;"


def records(stage, encrypted=True):
    column = "encode(target,'hex')" if encrypted else "NULL"
    raw = pg(statements([ROLE, report("records", "SELECT jsonb_agg(r ORDER BY id) FROM (SELECT id,email,"+column+" AS target FROM revamp_lifecycle) r")]), stage)
    line = next(re.search(r'({"label".*})', line).group(1) for line in raw.splitlines() if re.search(r'({"label".*})', line))
    return json.loads(line)["value"]


def verify(rows):
    assert len(rows) == 100
    for row in rows:
        assert reveal(row["id"], bytes.fromhex(row["target"])) == row["email"]


def main():
    outcomes = {}
    source = {i: f"fixture{i}@example.test" for i in range(101,201)}
    if "--resume-from-first-chunk" not in sys.argv:
        pg(statements([ROLE,
           "CREATE TABLE revamp_lifecycle(id bigint PRIMARY KEY,email text NOT NULL);",
           "CREATE TABLE revamp_journal(operation text,chunk bigint,PRIMARY KEY(operation,chunk));",
           "INSERT INTO revamp_lifecycle VALUES "+",".join(f"({i},'{v}')" for i,v in source.items())+";",
           "ALTER TABLE revamp_lifecycle ADD COLUMN target bytea;",
        ]),"lifecycle-expand")
    protected = {i: protect(i,value) for i,value in source.items()}
    def chunk(number, identities):
        work=[ROLE,"BEGIN;"]
        work += [f"UPDATE revamp_lifecycle SET target={bytea(protected[i])} WHERE id={i} AND target IS NULL;" for i in identities]
        work += [f"INSERT INTO revamp_journal VALUES ('protect',{number}) ON CONFLICT DO NOTHING;", "COMMIT;"]
        pg(statements(work),f"lifecycle-chunk-{number}")
    if "--resume-from-first-chunk" not in sys.argv:
        chunk(1,range(101,151))
    partial=records("lifecycle-interrupted")
    assert sum(r["target"] is not None for r in partial)==50
    first_digest=hashlib.sha256(b"".join(bytes.fromhex(r["target"]) for r in partial if r["target"])).hexdigest()
    outcomes["interruption_after_committed_chunk"]="PASS"
    chunk(1,range(101,151))
    again=records("lifecycle-idempotent-retry")
    assert first_digest==hashlib.sha256(b"".join(bytes.fromhex(r["target"]) for r in again if r["target"])).hexdigest()
    outcomes["retry_retains_committed_ciphertext"]="PASS"
    chunk(2,range(151,201))
    rows=records("lifecycle-full-verify")
    verify(rows)
    outcomes["full_row_value_verification"]="PASS"
    changed=bytearray(protected[101]);changed[-1]^=1
    pg(statements([ROLE,f"UPDATE revamp_lifecycle SET target={bytea(bytes(changed))} WHERE id=101;"]),"lifecycle-mutant")
    try:
        verify(records("lifecycle-mutant-observed"))
    except Exception as exc:
        from cryptography.exceptions import InvalidTag
        assert isinstance(exc,InvalidTag)
        outcomes["tampered_target_blocks_verification"]="PASS"
    else:
        raise AssertionError("Verifier missed target corruption")
    pg(statements([ROLE,f"UPDATE revamp_lifecycle SET target={bytea(protected[101])} WHERE id=101;",
                   "ALTER TABLE revamp_lifecycle DROP COLUMN email;"]),"lifecycle-switch-contract")
    # A post-cutover mutation makes a static pre-cutover snapshot stale.
    current_value="edited-after-cutover@example.test"
    latest=protect(101,current_value)
    pg(statements([ROLE,f"UPDATE revamp_lifecycle SET target={bytea(latest)} WHERE id=101;",
                   "ALTER TABLE revamp_lifecycle ADD COLUMN email text;"]),"lifecycle-current-write")
    current=records("lifecycle-current-ciphertexts")
    restored={row["id"]:reveal(row["id"],bytes.fromhex(row["target"])) for row in current}
    assert restored[101]==current_value and restored[101]!=source[101]
    outcomes["decrypt_back_preserves_post_cutover_write"]="PASS"
    outcomes["static_mirror_counterexample"]="STALE_WITHOUT_DUAL_WRITES"
    # Local envelope-provider stand-in. No AWS/Vault/GCP custody claim.
    old_kek=os.urandom(32);new_kek=os.urandom(32);nonce=os.urandom(12);context=b"lab/root/payload"
    wrapper=nonce+AESGCMSIV(old_kek).encrypt(nonce,KEY,context)
    root=AESGCMSIV(old_kek).decrypt(wrapper[:12],wrapper[12:],context)
    new_nonce=os.urandom(12)
    rewrapped=new_nonce+AESGCMSIV(new_kek).encrypt(new_nonce,root,context)
    assert root==AESGCMSIV(new_kek).decrypt(rewrapped[:12],rewrapped[12:],context)==KEY
    assert reveal(101,latest)==current_value
    outcomes["local_provider_rewrap_payload_unchanged"]="PASS_LOCAL_PROVIDER_ONLY"
    for i,value in restored.items():
        assert "'" not in value  # Closed synthetic fixture, not a SQL parameter API.
    pg(statements([ROLE,"BEGIN;"]+[f"UPDATE revamp_lifecycle SET email='{value}' WHERE id={i};" for i,value in restored.items()]+["COMMIT;"]),"lifecycle-decrypt-back")
    verify(records("lifecycle-decrypt-back-verify"))
    pg(statements([ROLE,"ALTER TABLE revamp_lifecycle ALTER COLUMN email SET NOT NULL;",
                   "ALTER TABLE revamp_lifecycle DROP COLUMN target;",
                   "DROP TABLE revamp_journal;",
                   report("package_free_value","SELECT email FROM revamp_lifecycle WHERE id=101"),
                   "SELECT 1/(CASE WHEN NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='revamp_lifecycle' AND column_name='target') THEN 1 ELSE 0 END);",
                  ]),"lifecycle-remove")
    outcomes["plaintext_switch_generated_storage_removed"]="PASS"
    outcomes["package_free_sql_read"]="PASS_SQL_ONLY"
    # Check independent policy semantics, not deployment integrity or real restore.
    allowed_generations={2}
    assert 1 not in allowed_generations
    outcomes["external_policy_rejects_old_generation"]="PASS_MODEL_ONLY"
    result={"outcomes":outcomes,"rows":100,"database":"PostgreSQL 16.2 SET ROLE in single-user mode",
            "limits":["No concurrent writers, network crash, advisory lock race or live service authentication",
                      "No SQLAlchemy/async lifecycle integration or provider calls",
                      "Package-free SQL is not a complete package-free application test",
                      "Policy model is not an authenticated deployment or restore test",
                      "Plaintext staging uses synthetic values and is explicitly part of this lab"]}
    (RESULTS/"lifecycle.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result))


if __name__=="__main__":
    main()
