# CTI Automation Tool

A small Python learning project for checking IP reputation with AbuseIPDB and reviewing the results in CSV. It is an enrichment aid, not a malware detector, SIEM, or automatic blocking system.

## Setup

Use Python 3.10 or later in a virtual environment:

```sh
python -m venv .venv
# Linux/macOS
. .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install 'requests>=2.32,<3'
python main.py
```

The program reads `ips_to_check.txt` next to `main.py`, one IP per line. On first run it asks for input if that file does not exist. Blank lines and lines beginning with `#` are ignored. Invalid addresses are reported, not queried.

Set `ABUSEIPDB_API_KEY` in your process environment before running if you do not want a local key file. The environment value takes precedence. Otherwise first run prompts for a key using hidden input and saves it in a plaintext `.env` file next to the script. Do not commit that file or include it in screenshots, support logs, or archives. Environment variables and local files are not encrypted secret stores. Use a restricted local account and your API provider's key controls.

Only query addresses you are allowed to send to a third-party service. Never upload company IP inventories without permission. Live requests consume your provider quota; this project does not include an API key.

## Reading the report

`security_report.csv` contains the submitted IP, abuse score, country, usage type, verdict and error columns. Each run replaces the previous report.

| Verdict | Meaning |
| --- | --- |
| Review | The reported abuse confidence score is above 50. Investigate with other evidence. |
| Low reported abuse | A valid score is 50 or below. This is not proof that an address is safe. |
| Unknown | The returned score is missing, malformed or out of range. |
| Invalid | The input is not an IP address. No API query is made. |
| Error | The API request did not return a usable result. This is not a clean finding. |

The threshold is a simple local triage choice in `THRESHOLD`, not an independently calibrated risk model. No automatic blocking takes place. Country and usage type are provider metadata, not proof of the operator's identity or intent.

## Offline checks

```sh
python -m unittest -v test_main.py
python -m py_compile main.py test_main.py
```

The tests use mocked HTTP and synthetic documentation IPs. No network access or real API key is needed. They cover verdict boundaries, invalid/missing scores, API errors, bounded rate-limit retries and environment-key setup. Passing these checks does not establish live API compatibility or production readiness.

## Design and limits

- Standard-library `ipaddress` checks address syntax before requests.
- A request has a ten-second timeout. Rate-limit responses and connection exceptions have at most three attempts; other HTTP failures return an error. Repeated failures can still take time.
- CSV output keeps fields consistent for spreadsheet or script review. Treat input and external metadata as untrusted when opening reports in spreadsheet software.
- Input is processed sequentially in memory. There is no caching, deduplication, resume, database, UI, scheduling or unlimited-quota claim.
- The API and report are not substitutes for investigation. Provider coverage, rate limits and network availability affect results.

## Explaining the project

Start with the flow: input file, syntax validation, API lookup, cautious verdict, CSV report. Explain why a missing score must remain unknown instead of silently becoming zero, and why low abuse reports cannot establish safety. The offline tests isolate external calls so those decisions can be checked repeatably without spending quota.
