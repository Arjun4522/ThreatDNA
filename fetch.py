#!/usr/bin/env python3
"""
download_readme_pdfs.py

Fetch README.md from a GitHub repo, find all .pdf links, and download them
into the ./reports directory.

Usage:
    python download_readme_pdfs.py
"""

from urllib.parse import urljoin, urlparse
import os
import re
import requests
import sys

# --- Configuration ---
README_URL = "https://github.com/tkruppert/Cyber_Threat_Intelligence/blob/main/README.md?plain=1"
OUT_DIR = "reports"
HEADERS = {
    "User-Agent": "cti-pdf-downloader/1.0 (+https://github.com/yourname)"
}
TIMEOUT = 30  # seconds

# --- Helpers ---
def make_raw_if_github_blob(url: str) -> str:
    """
    Convert GitHub blob URL to raw.githubusercontent URL if applicable.
    e.g. https://github.com/user/repo/blob/main/path/file.pdf
    -> https://raw.githubusercontent.com/user/repo/main/path/file.pdf
    """
    parsed = urlparse(url)
    if parsed.netloc.endswith("github.com"):
        # path like /user/repo/blob/branch/path/to/file.pdf
        parts = parsed.path.split("/")
        try:
            blob_idx = parts.index("blob")
        except ValueError:
            return url  # not a blob URL
        user = parts[1]
        repo = parts[2]
        branch = parts[blob_idx + 1]
        path_rest = "/".join(parts[blob_idx + 2 :])
        raw = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path_rest}"
        if parsed.query:
            raw = raw + "?" + parsed.query
        return raw
    return url

def find_pdf_links(text: str, base_url: str) -> list:
    """
    Find candidate PDF URLs in markdown/html text.
    Returns absolute URLs.
    """
    links = set()

    # markdown links: [text](url)
    for m in re.finditer(r"\[.*?\]\((.*?)\)", text, flags=re.IGNORECASE | re.DOTALL):
        href = m.group(1).strip()
        if href.lower().endswith(".pdf") or ".pdf?" in href.lower():
            links.add(urljoin(base_url, href))

    # bare URLs (http(s) ...)
    for m in re.finditer(r"(https?://[^\s'\"<>]+\.pdf(?:\?[^\s'\"<>]*)?)", text, flags=re.IGNORECASE):
        links.add(m.group(1))

    # html anchor tags (if page is HTML)
    for m in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', text, flags=re.IGNORECASE):
        href = m.group(1).strip()
        if href.lower().endswith(".pdf") or ".pdf?" in href.lower():
            links.add(urljoin(base_url, href))

    return sorted(links)

def download_file(url: str, out_path: str) -> bool:
    """
    Download with streaming; return True on success.
    """
    try:
        with requests.get(url, headers=HEADERS, stream=True, timeout=TIMEOUT) as r:
            r.raise_for_status()
            total = r.headers.get("Content-Length")
            total = int(total) if total and total.isdigit() else None
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, "wb") as f:
                downloaded = 0
                chunk_size = 8192
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                # optional: verify length
                if total and downloaded != total:
                    print(f"Warning: downloaded size mismatch for {url} ({downloaded} != {total})")
        return True
    except Exception as e:
        print(f"Failed to download {url}: {e}")
        return False

# --- Main flow ---
def main():
    print("Fetching README...")
    try:
        resp = requests.get(README_URL, headers=HEADERS, timeout=TIMEOUT)
        resp.raise_for_status()
        readme_text = resp.text
    except Exception as e:
        print(f"Error fetching README at {README_URL}: {e}")
        sys.exit(1)

    print("Searching for PDF links in README...")
    links = find_pdf_links(readme_text, base_url=README_URL)
    if not links:
        print("No PDF links found in README.")
        return

    print(f"Found {len(links)} candidate PDF link(s).")
    # Normalize links (handle github blob -> raw)
    normalized = []
    for u in links:
        u = u.strip()
        u = make_raw_if_github_blob(u)
        normalized.append(u)

    # create output directory
    os.makedirs(OUT_DIR, exist_ok=True)

    # download each PDF
    for idx, url in enumerate(normalized, start=1):
        # infer filename
        parsed = urlparse(url)
        filename = os.path.basename(parsed.path) or f"report_{idx}.pdf"
        # if query contains filename param, attempt to parse (rare)
        # ensure it ends with .pdf
        if not filename.lower().endswith(".pdf"):
            # try last path segment + query fallback
            filename = f"report_{idx}.pdf"
        out_path = os.path.join(OUT_DIR, filename)
        print(f"[{idx}/{len(normalized)}] Downloading: {url}")
        success = download_file(url, out_path)
        if success:
            print(f"  -> saved to {out_path}")
        else:
            print(f"  -> failed to save {url}")

    print("Done.")

if __name__ == "__main__":
    main()
