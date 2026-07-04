#!/usr/bin/env python3
"""
scrubber.py — make a sanitized copy of a project before you hand it to an AI.

Usage:
    python scrubber.py --src /path/project --out /tmp/project_for_ai --words "Brand1,Brand2,Omega"

Companion tool to the article
"What you're actually handing an AI along with a work document".

This is an EXAMPLE implementation, not a security product. It lowers the chance
of accidentally exposing sensitive data; it does NOT guarantee anonymity.
Stop-phrase scrubbing catches known strings — not paraphrased, contextual, or
inferable knowledge. Always review the sanitized copy and the reports by hand.

Note vs. the original PHP version: PHP removed its own comments with the
tokenizer (token_get_all). Python has no PHP tokenizer, so PHP comments here are
stripped with regular expressions, like every other language. The
"comments_removed_estimated" count is therefore an estimate.
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

REMOVABLE_BUILD_DIRS = [
    "vendor", "node_modules", "public/build", "public/hot", "dist", "build",
    ".next", ".nuxt", ".vite", "coverage", ".cache", "storage/logs",
    "storage/framework/cache", "storage/framework/views", "bootstrap/cache",
    "logs", "runtime", "tmp", "temp", "cache",
]

EXCLUDED_DIRS = list(dict.fromkeys([".git", ".idea", ".vscode", *REMOVABLE_BUILD_DIRS]))

SCAN_EXTENSIONS = {
    "php", "html", "htm", "js", "ts", "tsx", "jsx", "css", "scss", "vue",
    "env", "yml", "yaml", "json", "xml", "txt", "md", "ini", "conf",
    "sql", "sh", "bash", "map", "twig", "po", "mo", "pot",
}

IMAGE_EXTENSIONS = {
    "png", "jpg", "jpeg", "gif", "webp", "svg", "ico", "bmp", "avif",
}

KNOWN_TEXT_FILES = {
    ".env", ".env.example", ".env.local", ".env.production", ".env.staging",
    "dockerfile", "makefile", "composer.lock", "package-lock.json",
    "yarn.lock", "pnpm-lock.yaml", ".gitlab-ci.yml",
}

SUSPICIOUS_FILE_NAMES = [
    ".env", "id_rsa", "id_ed25519", "known_hosts", "authorized_keys",
    "config.php", "credentials", "secrets", "private", "docker-compose",
    "gitlab-ci", "postman", "insomnia", "swagger", "openapi", "kubeconfig",
    "kubernetes", "terraform", ".tfstate",
]

CREDENTIAL_PATTERNS = {
    "possible_env_secret": re.compile(
        r"\b(API_KEY|SECRET|TOKEN|PASSWORD|PASS|PRIVATE_KEY|CLIENT_SECRET|ACCESS_KEY|AWS_|DB_PASSWORD)\b",
        re.I),
    "jwt": re.compile(r"eyJ[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+?\.[a-zA-Z0-9_\-]+"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key_block": re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)?PRIVATE KEY-----"),
    "basic_auth_url": re.compile(r"https?://[^/\s:@]+:[^/\s:@]+@", re.I),
    "bearer_token": re.compile(r"Bearer\s+[a-zA-Z0-9_\-\.=]+", re.I),
    "password_assignment": re.compile(
        r"\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*['\"][^'\"]{4,}['\"]", re.I),
}

REPOSITORY_URL_PATTERNS = [
    re.compile(r"https?://(?:www\.)?github\.com/[^\s'\"<>)\]]+", re.I),
    re.compile(r"https?://(?:www\.)?gitlab\.com/[^\s'\"<>)\]]+", re.I),
    re.compile(r"git@github\.com:[^\s'\"<>)\]]+", re.I),
    re.compile(r"git@gitlab\.com:[^\s'\"<>)\]]+", re.I),
    re.compile(r"ssh://git@(?:github|gitlab)\.com/[^\s'\"<>)\]]+", re.I),
]

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
URL_PATTERN = re.compile(r"https?://[^\s'\"<>)\]]+", re.I)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I)
EMAIL_DOMAIN_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})")
INFRA_HINT_PATTERN = re.compile(
    r"\b(server_name|proxy_pass|upstream|DB_HOST|REDIS_HOST|MAIL_HOST|AWS_BUCKET|"
    r"S3_BUCKET|QUEUE_CONNECTION|PUSHER_|STRIPE_|PAYPAL_|CLOUDFLARE_|CF_|KUBE_|"
    r"DOCKER_|REGISTRY_|VAULT_|CONSUL_)\b", re.I)
REPOSITORY_URL_TEST = re.compile(
    r"^(https?://(?:www\.)?(github|gitlab)\.com/|git@(github|gitlab)\.com:|"
    r"ssh://git@(github|gitlab)\.com/)", re.I)

LINE_SPLIT = re.compile(r"\r\n|\r|\n")


def normalize_path(path: str) -> str:
    return path.replace("\\", "/")


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _dirname(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else ""


def split_lines(content: str):
    return LINE_SPLIT.split(content)


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:1024]


def clean_url_tail(url: str) -> str:
    return url.strip().rstrip(".,;:!?")


def is_repository_url(url: str) -> bool:
    return REPOSITORY_URL_TEST.match(url) is not None


def url_contains_scrub_word(url: str, words) -> bool:
    lower = url.lower()
    return any(w and w.lower() in lower for w in words)


def is_private_ip(ip: str) -> bool:
    try:
        obj = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return False
    return obj.is_private or obj.is_reserved or obj.is_loopback or obj.is_link_local


def is_valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False


def is_image_file(path: str) -> bool:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else ""
    return ext in IMAGE_EXTENSIONS


def is_text_candidate(ext: str, file_name: str) -> bool:
    return ext in SCAN_EXTENSIONS or file_name in KNOWN_TEXT_FILES


def file_name_contains_scrub_word(path: str, words) -> bool:
    name = _basename(path).lower()
    return any(w and w.lower() in name for w in words)


def scrub_file_name_words(path: str, words) -> str:
    path = normalize_path(path)
    directory = _dirname(path)
    file_name = _basename(path)
    for word in words:
        if word:
            file_name = re.sub(re.escape(word), "WORD_REDACTED", file_name, flags=re.I)
    if directory in ("", "."):
        return file_name
    return f"{directory}/{file_name}"


def mask_preview(line: str) -> str:
    line = line.strip()
    line = re.sub(r"(['\"])[^'\"]{8,}\1", r"\1[REDACTED]\1", line)
    line = re.sub(r"=\s*\S{8,}", "= [REDACTED]", line)
    line = re.sub(r":\s*\S{8,}", ": [REDACTED]", line)
    return line[:300]


# ---------------------------------------------------------------------------
# Scrubbing (mutates content)
# ---------------------------------------------------------------------------

def scrub_emails(content: str, stats) -> str:
    stats["emails_removed"] += len(EMAIL_PATTERN.findall(content))
    return EMAIL_PATTERN.sub("[EMAIL_REDACTED]", content)


def scrub_repository_urls(content: str, stats) -> str:
    for pattern in REPOSITORY_URL_PATTERNS:
        stats["repository_urls_removed"] += len(pattern.findall(content))
        content = pattern.sub("[REPOSITORY_URL_REDACTED]", content)
    return content


def scrub_words(content: str, words, stats) -> str:
    for word in words:
        if not word:
            continue
        pattern = re.compile(re.escape(word), re.I)
        content, count = pattern.subn("[WORD_REDACTED]", content)
        stats["word_replacements"] += count
    return content


def _strip(pattern: re.Pattern, content: str, stats, replacement="") -> str:
    stats["comments_removed_estimated"] += len(pattern.findall(content))
    return pattern.sub(replacement, content)


_PHP_BLOCK = re.compile(r"/\*.*?\*/", re.S)
_LINE_SLASH = re.compile(r"(?<!:)//.*$", re.M)
_LINE_HASH = re.compile(r"^\s*#.*$", re.M)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)


def remove_php_comments(content: str, stats) -> str:
    content = _strip(_PHP_BLOCK, content, stats)
    content = _strip(_LINE_SLASH, content, stats)
    content = _strip(_LINE_HASH, content, stats)
    return content


def remove_js_css_comments(content: str, stats) -> str:
    content = _strip(_PHP_BLOCK, content, stats)
    content = _strip(_LINE_SLASH, content, stats)
    return content


def remove_html_comments(content: str, stats) -> str:
    return _strip(_HTML_COMMENT, content, stats)


def remove_hash_comments(content: str, stats) -> str:
    return _strip(_LINE_HASH, content, stats)


# ---------------------------------------------------------------------------
# Scanning (read-only reports)
# ---------------------------------------------------------------------------

def scan_credentials(path, content, problem_files):
    for i, line in enumerate(split_lines(content)):
        for name, pattern in CREDENTIAL_PATTERNS.items():
            if pattern.search(line):
                problem_files[path].append(
                    {"line": i + 1, "type": name, "preview": mask_preview(line)})


def scan_words(path, content, words, word_matches):
    if not words:
        return
    for i, line in enumerate(split_lines(content)):
        lower_line = line.lower()
        for word in words:
            if word and word.lower() in lower_line:
                word_matches[word].append(
                    {"file": path, "line": i + 1, "preview": line[:300].strip()})


def scan_urls(content, unique_urls):
    for url in URL_PATTERN.findall(content):
        url = clean_url_tail(url)
        if url:
            unique_urls[url.lower()] = url


def scan_scrubbed_urls(content, words, scrubbed_urls):
    for url in URL_PATTERN.findall(content):
        url = clean_url_tail(url)
        if not url:
            continue
        if is_repository_url(url) or url_contains_scrub_word(url, words):
            scrubbed_urls[url.lower()] = url


def scan_missed_risks(path, content, report):
    file_name = _basename(path)
    for name in SUSPICIOUS_FILE_NAMES:
        if name.lower() in file_name.lower() or name.lower() in path.lower():
            report["suspicious_file_names"][path].append(name)

    for i, line in enumerate(split_lines(content)):
        line_no = i + 1
        for ip in IP_PATTERN.findall(line):
            if not is_valid_ipv4(ip):
                continue
            report["ip_addresses"][ip].append({"file": path, "line": line_no})
            if is_private_ip(ip):
                report["private_ip_addresses"][ip].append({"file": path, "line": line_no})

        for uuid in UUID_PATTERN.findall(line):
            report["uuids"][uuid].append({"file": path, "line": line_no})

        for domain in EMAIL_DOMAIN_PATTERN.findall(line):
            report["email_domains"][domain.lower()].append({"file": path, "line": line_no})

        if INFRA_HINT_PATTERN.search(line):
            report["infra_hints"][path].append(
                {"line": line_no, "preview": mask_preview(line)[:300].strip()})


# ---------------------------------------------------------------------------
# Summary / reporting
# ---------------------------------------------------------------------------

def count_nested_items(obj) -> int:
    if isinstance(obj, dict):
        return sum(count_nested_items(v) for v in obj.values())
    if isinstance(obj, list):
        return sum(count_nested_items(v) for v in obj)
    return 1


def count_report_entries(report: dict) -> int:
    return sum(len(v) for v in report.values() if isinstance(v, (list, dict)))


def group_urls_by_domain(urls) -> dict:
    grouped = defaultdict(list)
    for url in urls:
        host = (urlparse(url).hostname or "_unknown").lower()
        grouped[host].append(url)
    result = {}
    for host in sorted(grouped):
        result[host] = sorted(set(grouped[host]))
    return result


def build_summary(stats, problem_files, word_matches, unique_urls, scrubbed_urls,
                  missed_risk_report, removable_found, skipped_dirs,
                  deleted_image_files, renamed_files) -> dict:
    return {
        "files": {
            "processed_text": stats["files_processed_text"],
            "copied_binary_or_unknown": stats["files_copied_binary_or_unknown"],
            "image_files_deleted_by_stop_word": len(deleted_image_files),
            "files_renamed_by_stop_word": len(renamed_files),
            "removable_build_dirs_found": len(removable_found),
            "skipped_dirs": len(skipped_dirs),
        },
        "scrubbing": {
            "emails_removed": stats["emails_removed"],
            "repository_urls_removed": stats["repository_urls_removed"],
            "word_replacements": stats["word_replacements"],
            "comments_removed_estimated": stats["comments_removed_estimated"],
        },
        "findings": {
            "unique_urls": len(unique_urls),
            "scrubbed_urls": len(scrubbed_urls),
            "credential_warnings": count_nested_items(problem_files),
            "word_match_lines": count_nested_items(word_matches),
        },
        "missed_risks": {
            "ip_addresses": len(missed_risk_report.get("ip_addresses", {})),
            "private_ip_addresses": len(missed_risk_report.get("private_ip_addresses", {})),
            "uuids": len(missed_risk_report.get("uuids", {})),
            "email_domains": len(missed_risk_report.get("email_domains", {})),
            "infra_hints": count_report_entries(missed_risk_report.get("infra_hints", {})),
            "suspicious_file_names": len(missed_risk_report.get("suspicious_file_names", {})),
        },
    }


def write_json(path: Path, data) -> None:
    path.write_text(
        json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")


def undefault(obj):
    if isinstance(obj, defaultdict):
        obj = dict(obj)
    if isinstance(obj, dict):
        return {k: undefault(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [undefault(v) for v in obj]
    return obj


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(add_help=True, description=(
        "Make a sanitized copy of a project before handing it to an AI."))
    parser.add_argument("--src", required=False, default="")
    parser.add_argument("--out", required=False, default="")
    parser.add_argument("--words", required=False, default="")
    args = parser.parse_args()

    src = Path(args.src).resolve() if args.src else None
    out = args.out
    words = [w.strip() for w in args.words.split(",") if w.strip()]

    if not src or not src.is_dir() or not out:
        print('Usage: python scrubber.py --src /path/project '
              '--out /tmp/project_for_ai --words "Brand1,Brand2"')
        return 1

    out_path = Path(out)
    reports_dir = Path(str(out).rstrip("/\\") + "_reports")
    out_path.mkdir(parents=True, exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    problem_files = defaultdict(list)
    word_matches = defaultdict(list)
    unique_urls = {}
    scrubbed_urls = {}
    missed_risk_report = {
        "ip_addresses": defaultdict(list),
        "private_ip_addresses": defaultdict(list),
        "uuids": defaultdict(list),
        "email_domains": defaultdict(list),
        "infra_hints": defaultdict(list),
        "suspicious_file_names": defaultdict(list),
    }
    removable_found = []
    skipped_dirs = {}
    deleted_image_files = []
    renamed_files = []

    stats = {
        "files_processed_text": 0,
        "files_copied_binary_or_unknown": 0,
        "image_files_deleted_by_stop_word": 0,
        "files_renamed_by_stop_word": 0,
        "emails_removed": 0,
        "repository_urls_removed": 0,
        "word_replacements": 0,
        "comments_removed_estimated": 0,
    }

    for rel_dir in REMOVABLE_BUILD_DIRS:
        if (src / rel_dir).is_dir():
            removable_found.append({"path": rel_dir, "note": "Excluded from sanitized copy"})

    for root, dirs, files in os.walk(src):
        rel_root = normalize_path(os.path.relpath(root, src))
        rel_root = "" if rel_root == "." else rel_root

        kept = []
        for d in sorted(dirs):
            candidate = normalize_path(f"{rel_root}/{d}" if rel_root else d)
            matched = next(
                (ex for ex in EXCLUDED_DIRS
                 if candidate == ex or candidate.startswith(ex + "/")), None)
            if matched is not None:
                skipped_dirs[matched] = True
                continue
            kept.append(d)
        dirs[:] = kept

        for f in sorted(files):
            rel = normalize_path(f"{rel_root}/{f}" if rel_root else f)
            process_file(src, out_path, rel, words, stats, problem_files,
                         word_matches, unique_urls, scrubbed_urls,
                         missed_risk_report, deleted_image_files, renamed_files)

    summary = build_summary(
        stats, problem_files, word_matches, unique_urls, scrubbed_urls,
        missed_risk_report, removable_found, skipped_dirs,
        deleted_image_files, renamed_files)

    write_json(reports_dir / "problem_files.json", undefault(problem_files))
    write_json(reports_dir / "word_matches.json", undefault(word_matches))
    write_json(reports_dir / "unique_urls_by_domain.json",
               group_urls_by_domain(unique_urls.values()))
    write_json(reports_dir / "scrubbed_urls_by_domain.json",
               group_urls_by_domain(scrubbed_urls.values()))
    write_json(reports_dir / "missed_risk_report.json", undefault(missed_risk_report))
    write_json(reports_dir / "removable_build_dirs.json", removable_found)
    write_json(reports_dir / "skipped_dirs.json", list(skipped_dirs.keys()))
    write_json(reports_dir / "deleted_image_files.json", deleted_image_files)
    write_json(reports_dir / "renamed_files.json", renamed_files)
    write_json(reports_dir / "summary.json", summary)

    print()
    print("Done.")
    print(f"Sanitized copy: {out}")
    print(f"Reports: {reports_dir}\n")
    print("Summary")
    print("-----------------------------")
    print(f"Text files processed............. {summary['files']['processed_text']}")
    print(f"Binary/unknown files copied...... {summary['files']['copied_binary_or_unknown']}")
    print(f"Image files deleted.............. {summary['files']['image_files_deleted_by_stop_word']}")
    print(f"Files renamed.................... {summary['files']['files_renamed_by_stop_word']}")
    print(f"Emails removed................... {summary['scrubbing']['emails_removed']}")
    print(f"Repository URLs removed.......... {summary['scrubbing']['repository_urls_removed']}")
    print(f"Word replacements................ {summary['scrubbing']['word_replacements']}")
    print(f"Comments removed estimated....... {summary['scrubbing']['comments_removed_estimated']}")
    print(f"Unique URLs found................ {summary['findings']['unique_urls']}")
    print(f"Scrubbed URLs found.............. {summary['findings']['scrubbed_urls']}")
    print(f"Credential warnings.............. {summary['findings']['credential_warnings']}")
    print(f"Brand/word match lines........... {summary['findings']['word_match_lines']}")
    print(f"IP addresses found............... {summary['missed_risks']['ip_addresses']}")
    print(f"Private IPs found................ {summary['missed_risks']['private_ip_addresses']}")
    print(f"UUIDs found...................... {summary['missed_risks']['uuids']}")
    print(f"Email domains found.............. {summary['missed_risks']['email_domains']}")
    print(f"Infra hints found................ {summary['missed_risks']['infra_hints']}")
    print(f"Suspicious file names............ {summary['missed_risks']['suspicious_file_names']}")
    print(f"Skipped dirs..................... {summary['files']['skipped_dirs']}")
    print()
    return 0


def process_file(src, out_path, rel, words, stats, problem_files, word_matches,
                 unique_urls, scrubbed_urls, missed_risk_report,
                 deleted_image_files, renamed_files):
    source_path = src / rel
    original_rel = normalize_path(rel)
    relative_path = original_rel
    ext = source_path.suffix.lower().lstrip(".")
    file_name = source_path.name.lower()

    if file_name_contains_scrub_word(relative_path, words):
        if is_image_file(relative_path):
            deleted_image_files.append(
                {"source": relative_path, "reason": "Image file name contains stop word"})
            stats["image_files_deleted_by_stop_word"] += 1
            return
        scrubbed = scrub_file_name_words(relative_path, words)
        renamed_files.append(
            {"source": relative_path, "target": scrubbed,
             "reason": "File name contains stop word"})
        relative_path = scrubbed
        stats["files_renamed_by_stop_word"] += 1

    target_path = out_path / relative_path
    target_path.parent.mkdir(parents=True, exist_ok=True)

    if not is_text_candidate(ext, file_name):
        shutil.copy2(source_path, target_path)
        stats["files_copied_binary_or_unknown"] += 1
        return

    data = source_path.read_bytes()
    if is_binary(data):
        shutil.copy2(source_path, target_path)
        stats["files_copied_binary_or_unknown"] += 1
        return

    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        shutil.copy2(source_path, target_path)
        stats["files_copied_binary_or_unknown"] += 1
        return

    scan_credentials(original_rel, content, problem_files)
    scan_words(original_rel, content, words, word_matches)
    scan_urls(content, unique_urls)
    scan_scrubbed_urls(content, words, scrubbed_urls)
    scan_missed_risks(original_rel, content, missed_risk_report)

    clean = content
    clean = scrub_emails(clean, stats)
    clean = scrub_repository_urls(clean, stats)
    clean = scrub_words(clean, words, stats)

    if ext == "php":
        clean = remove_php_comments(clean, stats)
    elif ext in {"js", "ts", "tsx", "jsx", "css", "scss", "vue"}:
        clean = remove_js_css_comments(clean, stats)
    elif ext in {"html", "htm"}:
        clean = remove_html_comments(clean, stats)
    else:
        clean = remove_hash_comments(clean, stats)

    target_path.write_text(clean, encoding="utf-8")
    stats["files_processed_text"] += 1


if __name__ == "__main__":
    raise SystemExit(main())
