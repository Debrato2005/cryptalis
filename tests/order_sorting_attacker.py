"""Isolated stdlib-only implementation of the published dense-domain rank attack."""
import json
import os
import sys


def main():
    try:
        if not (sys.flags.isolated and sys.dont_write_bytecode and sys.flags.no_site):
            raise ValueError
        if set(os.environ) - {'PATH', 'LC_ALL', 'LC_CTYPE'}:
            raise ValueError
        if any(name.split('.')[0] not in sys.stdlib_module_names and name != '__main__'
               for name in sys.modules):
            raise ValueError
        encoded = sys.stdin.buffer.read(32 * 1024 * 1024 + 1)
        if len(encoded) > 32 * 1024 * 1024:
            raise ValueError
        data = json.loads(encoded)
        if type(data) is not dict or set(data) != {'domain', 'rows'} or data['domain'] != [-32768, 32767]:
            raise ValueError
        rows = data['rows']
        if type(rows) is not list or len(rows) > 131072:
            raise ValueError
        identifiers, decoded = set(), []
        for row in rows:
            if (type(row) is not list or len(row) != 2 or type(row[0]) is not str
                    or len(row[0]) != 32 or row[0] in identifiers
                    or row[1] is not None and (type(row[1]) is not str or len(row[1]) != 64)):
                raise ValueError
            if len(bytes.fromhex(row[0])) != 16:
                raise ValueError
            term = None if row[1] is None else bytes.fromhex(row[1])
            if term is not None and len(term) != 32:
                raise ValueError
            identifiers.add(row[0])
            decoded.append((row[0], term))
        ranked_terms = sorted({term for _, term in decoded if term is not None})
        public_domain = sorted(range(data['domain'][0], data['domain'][1] + 1))
        nonnull = sum(term is not None for _, term in decoded)
        applicable = len(ranked_terms) == len(public_domain)
        guesses = []
        if applicable:
            rank_map = dict(zip(ranked_terms, public_domain, strict=True))
            guesses = [[identifier, rank_map[term]] for identifier, term in decoded if term is not None]
        result = {
            'status': 'APPLICABLE' if applicable else 'OUT_OF_SCOPE',
            'reason': 'known domain has one observed term per value' if applicable else 'density/cardinality mismatch',
            'preconditions': {'known_domain_distinct': len(public_domain), 'observed_distinct_terms': len(ranked_terms),
                'nonnull_cells': nonnull, 'null_cells': len(decoded) - nonnull,
                'duplicate_cells': nonnull - len(ranked_terms)},
            'isolation': {'isolated': True, 'bytecode_disabled': True, 'site_disabled': True, 'stdlib_only': True},
            'guesses': guesses,
        }
        sys.stdout.write(json.dumps(result, separators=(',', ':')) + '\n')
        sys.stdout.flush()
        return 0
    except (KeyError, TypeError, ValueError, OverflowError, UnicodeError):
        sys.stderr.write('Sorting attacker refused invalid input or execution isolation.\n')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
