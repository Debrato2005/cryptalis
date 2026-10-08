"""Compare a live atomic mirror with current-data decrypt-back in a small PG lab."""
import json
from pathlib import Path
import re

from run_adapter import protect, reveal
from run_stock_postgres import bytea, pg, report, statements

ROLE = 'SET ROLE revamp_owner;'
RESULTS = Path(__file__).with_name('results')


def observed(label):
    output = pg(statements([ROLE, report('rows', "SELECT jsonb_agg(r ORDER BY id) FROM (SELECT id,mirror,encode(payload,'hex') AS frame FROM revamp_mirror_lab) r")]), label)
    entries = [json.loads(match.group(1)) for line in output.splitlines() if (match := re.search(r'({"label".*})', line))]
    rows = entries[0]['value']
    assert len(rows) == 100
    return rows


def verify(rows):
    for row in rows:
        assert reveal(row['id'], bytes.fromhex(row['frame'])) == row['mirror']


def main():
    values = {i: f'mirror-fixture-{i}@example.test' for i in range(301, 401)}
    inserts = [f"({identity},{bytea(protect(identity, value))},'{value}')" for identity, value in values.items()]
    pg(statements([ROLE, "CREATE TABLE revamp_mirror_lab(id bigint PRIMARY KEY,payload bytea NOT NULL,mirror text NOT NULL CHECK(mirror <> 'reject-mirror-write'));",
                   'INSERT INTO revamp_mirror_lab VALUES ' + ','.join(inserts) + ';']), 'mirror-setup')
    changed = 'current-mirror-update@example.test'
    current = protect(301, changed)
    pg(statements([ROLE, 'BEGIN;', f'UPDATE revamp_mirror_lab SET payload={bytea(current)} WHERE id=301;',
                   f"UPDATE revamp_mirror_lab SET mirror='{changed}' WHERE id=301;", 'COMMIT;']), 'mirror-atomic-write')
    verify(observed('mirror-verified-current'))
    doomed = protect(301, 'failed-update@example.test')
    pg(statements([ROLE, 'BEGIN;', f'UPDATE revamp_mirror_lab SET payload={bytea(doomed)} WHERE id=301;',
                   "UPDATE revamp_mirror_lab SET mirror='reject-mirror-write' WHERE id=301;", 'COMMIT;']),
       'mirror-failed-write', ('violates check constraint',))
    after = observed('mirror-failure-observed')
    verify(after)
    assert bytes.fromhex(after[0]['frame']) == current
    sizes = pg(statements([ROLE, report('logical_bytes', 'SELECT json_build_object(\'payload\',sum(pg_column_size(payload)),\'plaintext_mirror\',sum(pg_column_size(mirror))) FROM revamp_mirror_lab')]), 'mirror-cost')
    size_entry = next(json.loads(match.group(1))['value'] for line in sizes.splitlines() if (match := re.search(r'({"label".*})', line)))
    # Negative control: a writer that updates only ciphertext breaks the live mirror.
    latest = protect(301, 'unmirrored-current@example.test')
    pg(statements([ROLE, f'UPDATE revamp_mirror_lab SET payload={bytea(latest)} WHERE id=301;']), 'mirror-writer-bypass')
    rows = observed('mirror-divergence-observed')
    try:
        verify(rows)
    except AssertionError:
        divergence = True
    else:
        raise AssertionError('The control failed to create stale mirror data')
    reconstructed = {row['id']: reveal(row['id'], bytes.fromhex(row['frame'])) for row in rows}
    assert reconstructed[301] == 'unmirrored-current@example.test'
    assert reconstructed[301] != rows[0]['mirror']
    result = {'rows': 100, 'cell': 'PG16.2 single-user SET ROLE',
              'atomic_mirror_retains_current_value': True, 'failed_mirror_update_rolls_back_ciphertext': True,
              'unmirrored_writer_detected_by_full_check': divergence,
              'current_data_decrypt_back_survives_mirror_divergence': True,
              'logical_column_bytes': size_entry,
              'limits': ['No concurrent writers/driver/network crash', 'Plaintext mirror is an explicit synthetic lab exposure',
                         'No whole-application migration/rollback or measured production pause']}
    pg(statements([ROLE, 'DROP TABLE revamp_mirror_lab;']), 'mirror-cleanup')
    (RESULTS/'mirror-comparison.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
