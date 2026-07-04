# scrubber

A small command-line tool that makes a **sanitized copy** of a project before you hand it to an AI assistant.

It walks a source directory, strips or redacts things you probably didn't mean to share (emails, repository URLs, your own stop-phrases, comments), skips build/dependency folders, and writes a set of **reports** flagging the risky things it did *not* touch — IP addresses, UUIDs, credential-looking lines, infra hints, and suspicious file names — so you can review them by hand.

> **This is an example implementation, not a security product.** It lowers the chance of accidental exposure. It does **not** guarantee anonymity. Read [Limitations](#limitations) before trusting it with anything.

This repo is the companion to the article [*"The Information You Didn't Mean to Share With AI."*](https://www.linkedin.com/pulse/information-you-didnt-mean-share-ai-peter-novozhilov-kdtcf/) It exists to make one point concrete: **think first, then send.**

---

## The problem

AI has become an everyday tool — it finds things, writes code, explains problems. So on autopilot we feed it the same context that's open in the next window: a repo, an exported document, a config.

Along with the visible content, two layers ride along. The first is obvious personal data. The second is broader and nearly invisible: your employer's private information — infrastructure, operational processes, team composition, vendor and intermediary contacts, deal history, plans. Often it's under an NDA, and responsibility for keeping it safe rests with whoever handed it over.

The catch is that leaks rarely look like leaks. Nobody dumps a database. It leaks in fragments and in context: an IP in a bug report, a partner's name in a comment, a sub-brand in a link. Individually trivial; together, a reconstructable picture of the company. A single question to an AI can surface contributor emails, advertiser contacts, and revenue-share terms that were simply sitting in the code the whole time.

## The solution

Treat preparing data for an AI the way finance treats customer personal data: separate the private layer *before* it leaves your machine, automate the obvious cleanup, and get a report of what's left so a human can make the final call.

`scrubber` is a minimal, dependency-free implementation of that idea.

## What it does

**Skips** dependency/build/cache folders entirely (`vendor`, `node_modules`, `dist`, `.next`, `storage/logs`, and more), plus `.git`, `.idea`, `.vscode`.

**Redacts** inside text files:

- email addresses → `[EMAIL_REDACTED]`
- GitHub/GitLab repository URLs (https, `git@`, `ssh://`) → `[REPOSITORY_URL_REDACTED]`
- your stop-phrases (case-insensitive) → `[WORD_REDACTED]`
- comments (PHP / JS / TS / CSS / Vue / HTML / hash-style)

**Handles file names** that contain a stop-phrase: image files are dropped; other files are renamed with `WORD_REDACTED`.

**Copies** binary and unknown files unchanged.

**Reports** — the part you actually review. It writes JSON files flagging things it deliberately did *not* remove, because they need human judgment:

| Report | What it flags |
| --- | --- |
| `problem_files.json` | credential-looking lines (API keys, JWTs, private keys, bearer tokens, `password=…`) |
| `missed_risk_report.json` | IPv4 addresses (public/private), UUIDs, email domains, infra hints, suspicious file names |
| `word_matches.json` | every line where a stop-phrase appeared |
| `unique_urls_by_domain.json` | all outbound URLs, grouped by host |
| `scrubbed_urls_by_domain.json` | URLs that were redacted |
| `removable_build_dirs.json` / `skipped_dirs.json` | what was excluded |
| `renamed_files.json` / `deleted_image_files.json` | file-name actions taken |
| `summary.json` | counts for everything above |

A summary is also printed to the terminal.

## Requirements

- Python 3.8+
- No third-party dependencies (standard library only)

## Usage

```bash
python scrubber.py \
  --src /path/to/project \
  --out /tmp/project_for_ai \
  --words "Brand1,Brand2,VendorName,ProjectCodename"
```

Suggested workflow (mirrors the article's `check → out → clean` idea): keep the original untouched, run a first pass and **read the reports**, add anything they surfaced to `--words`, then run again until the reports are clean. Only then open the sanitized copy in your AI tool.

Also: if you work with company-private data, turn off "allow my data to be used for training" in your AI tool. That's separate from this script — and worth doing anyway.

## Parameters

| Flag | Required | Description |
| --- | --- | --- |
| `--src` | yes | Path to the project to sanitize. Must be an existing directory. |
| `--out` | yes | Where the sanitized copy is written. Reports go to `<out>_reports/` next to it. |
| `--words` | no | Comma-separated stop-phrases (brands, vendors, names, codenames). Matched case-insensitively in file contents and file names. |

## Limitations

Be honest about the cost of a mistake — it usually lands on someone else.

- **Stop-phrase scrubbing catches known strings only.** It does not catch paraphrased, contextual, or *inferable* knowledge. You can strip every brand name and still identify a company from how you describe its processes, metrics, team structure, and the nature of the work.
- **Some sensitive data is reported, not removed.** Credential-looking lines, IPs, and UUIDs are flagged so you can decide — they are intentionally left in the copy. Review the reports.
- **Comment stripping is regex-based**, so the `comments_removed_estimated` count is an estimate and edge cases in strings can slip through. (The original PHP version used a language tokenizer for PHP comments; this port does not.)
- **This tool is a second line of defense.** The first is the habit of pausing before you hit send and asking: *what exactly am I handing over, and who does it belong to?*

## License

MIT. Use it, fork it, adapt it to your own stack. It's meant as a starting point, not a finished product.
