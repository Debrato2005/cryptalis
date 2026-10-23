"""Local research cache must refuse changed content and avoid repeat requests."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import research_extract as extraction


class ResearchExtraction(unittest.TestCase):
    def test_verified_cache_needs_no_network_and_rejects_tampering(self):
        source = 'https://example.org/docs/'
        text = '# Public fixture\nRequired passage 雪\n'
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            key = hashlib.sha256((source + '\nFalse').encode()).hexdigest()
            folder = state / 'extractions' / key
            folder.mkdir(parents=True)
            (folder / 'page.md').write_text(text)
            (folder / 'source.json').write_text(json.dumps(dict(source_url=source,
                title='Public fixture', markdown_sha256=hashlib.sha256(text.encode()).hexdigest())))
            with patch.object(extraction, 'STATE', state), patch.object(extraction, 'urlopen',
                    side_effect=AssertionError('cache attempted a network request')), patch('sys.argv',
                    ['research_extract.py', source, '--expect', 'Required passage']):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    extraction.main()
                self.assertTrue(json.loads(output.getvalue())['cache_hit'])
                (folder / 'page.md').write_text('Unrelated replacement')
                with self.assertRaisesRegex(ValueError, 'hash changed'):
                    extraction.main()

    def test_cache_does_not_accept_an_unrelated_required_passage(self):
        source = 'https://example.org/docs/'
        text = '# Public fixture\n'
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            folder = state / 'extractions' / hashlib.sha256((source + '\nFalse').encode()).hexdigest()
            folder.mkdir(parents=True)
            (folder / 'page.md').write_text(text)
            (folder / 'source.json').write_text(json.dumps(dict(source_url=source,
                title='Public fixture', markdown_sha256=hashlib.sha256(text.encode()).hexdigest())))
            with patch.object(extraction, 'STATE', state), patch.object(extraction, 'urlopen',
                    side_effect=AssertionError('cache attempted a network request')), patch('sys.argv',
                    ['research_extract.py', source, '--expect', 'Missing required passage']):
                with self.assertRaisesRegex(ValueError, 'lacks the required passage'):
                    extraction.main()

    def test_local_html_preserves_unicode_and_source_links_without_network(self):
        with patch('socket.create_connection', side_effect=AssertionError('local extraction used network')):
            title, text = extraction.markdown('<html><title>Public fixture</title><main>'
                '<h1>Source 雪</h1><a href="/original">Original</a></main></html>', 'https://example.org/docs/')
        self.assertEqual(title, 'Public fixture')
        self.assertIn('雪', text)
        self.assertIn('https://example.org/original', text)


if __name__ == '__main__':
    unittest.main()
