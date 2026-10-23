"""Cache public page Markdown with local Crawl4AI and no LLM extraction."""
import argparse
import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

STATE = Path(__file__).resolve().parents[1] / '.research-tools'
os.environ['PYTHON_DOTENV_DISABLED'] = '1'
os.environ['LITELLM_LOCAL_MODEL_COST_MAP'] = 'True'
os.environ['CRAWL4AI_NO_CLOUD_NOTICE'] = '1'
os.environ['CRAWL4_AI_BASE_DIRECTORY'] = str(STATE / 'crawl4ai-state')
os.environ['PLAYWRIGHT_BROWSERS_PATH'] = str(STATE / 'browser-cache')
ATTRIBUTION = ('This product includes software developed by UncleCode '
    '(https://x.com/unclecode) as part of the Crawl4AI project '
    '(https://github.com/unclecode/crawl4ai).')
LIMIT = 16 * 1024 * 1024


def validate_url(value):
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Supply a public HTTPS source URL without credentials.')
    return value


def markdown(html, source):
    from importlib.metadata import version
    if version('crawl4ai') != '0.9.5':
        raise ValueError('Use the pinned Crawl4AI 0.9.5 research environment.')
    from bs4 import BeautifulSoup
    from crawl4ai import DefaultMarkdownGenerator
    import litellm
    litellm.telemetry = False
    soup = BeautifulSoup(html, 'lxml')
    title = soup.title.get_text(' ', strip=True) if soup.title else ''
    body = soup.find('main') or soup.find('article') or soup.body or soup
    result = DefaultMarkdownGenerator(content_filter=None).generate_markdown(str(body), base_url=source)
    return title, result.raw_markdown


async def rendered(url):
    from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig, CacheMode
    import litellm
    litellm.telemetry = False
    browser = BrowserConfig(headless=True, enable_stealth=False, ignore_https_errors=False, verbose=False)
    config = CrawlerRunConfig(extraction_strategy=None, cache_mode=CacheMode.DISABLED,
        check_robots_txt=True, verbose=False)
    async with AsyncWebCrawler(config=browser, base_directory=str(STATE / 'crawl4ai-state')) as crawler:
        result = await crawler.arun(url=url, config=config)
    if not result.success or result.status_code != 200:
        raise ValueError('Rendered retrieval did not return a successful HTTP 200 page.')
    return result.html, validate_url(result.redirected_url or result.url), result.status_code


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog=ATTRIBUTION)
    parser.add_argument('url')
    parser.add_argument('--render', action='store_true', help='Use Chromium only when JavaScript is required.')
    parser.add_argument('--expect', required=True, help='Required source passage; reject unrelated or error content.')
    parser.add_argument('--refresh', action='store_true', help='Fetch again instead of reusing the verified cache.')
    args = parser.parse_args()
    source = validate_url(args.url)
    key = hashlib.sha256((source + '\n' + str(args.render)).encode()).hexdigest()
    folder = STATE / 'extractions' / key
    metadata_path, text_path = folder / 'source.json', folder / 'page.md'
    if metadata_path.exists() and not args.refresh:
        metadata = json.loads(metadata_path.read_text())
        text = text_path.read_text()
        if metadata['source_url'] != source or hashlib.sha256(text.encode()).hexdigest() != metadata['markdown_sha256']:
            raise ValueError('Cached source identity or Markdown hash changed.')
        if args.expect not in text and args.expect not in metadata['title']:
            raise ValueError('Cached content lacks the required passage.')
        print(json.dumps(dict(metadata, cache_hit=True), ensure_ascii=False))
        return
    if args.render:
        html, final_url, status = asyncio.run(rendered(source))
    else:
        request = Request(source, headers={'User-Agent': 'CryptalisResearch/1.0 (single-page documentation retrieval)'})
        with urlopen(request, timeout=30) as response:
            raw = response.read(LIMIT + 1)
            final_url, status = validate_url(response.url), response.status
            media_type = response.headers.get_content_type()
            encoding = response.headers.get_content_charset() or 'utf-8'
        if status != 200 or media_type not in ('text/html', 'application/xhtml+xml') or len(raw) > LIMIT:
            raise ValueError('Retrieval must return a bounded HTTP 200 HTML page.')
        html = raw.decode(encoding, errors='strict')
    if len(html.encode()) > LIMIT:
        raise ValueError('HTML exceeds the extraction limit.')
    title, text = markdown(html, final_url)
    if not title or not text.strip() or (args.expect not in title and args.expect not in text):
        raise ValueError('Reject empty, unrelated or error content; required passage/title is missing.')
    folder.mkdir(parents=True, exist_ok=True)
    text_path.write_text(text)
    (folder / 'page.html').write_text(html)
    metadata = dict(source_url=source, final_url=final_url, status=status, title=title,
        retrieved_utc=datetime.now(timezone.utc).isoformat(), rendered=args.render,
        markdown_path=str(text_path), markdown_sha256=hashlib.sha256(text.encode()).hexdigest(),
        html_sha256=hashlib.sha256(html.encode()).hexdigest(), extractor='Crawl4AI 0.9.5',
        llm_extraction=False, paid_services=False, dotenv_loading=False,
        license_url='https://github.com/unclecode/crawl4ai/blob/v0.9.5/LICENSE', attribution=ATTRIBUTION)
    metadata_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps(dict(metadata, cache_hit=False), ensure_ascii=False))


if __name__ == '__main__':
    main()
