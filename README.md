# CTI Automation Tool for SOC Analysts

A lightweight automation script designed for Security Operations Center (SOC) analysts to quickly check suspicious IP addresses against the AbuseIPDB API and generate structured security reports.

## Features

- **Interactive Setup Wizard:** Automatically prompts for the AbuseIPDB API key and sets up configuration files on the first run.
- **Batch Processing:** Reads and analyzes IP lists from a local text file.
- **Input Validation:** Validates IP addresses using standard formatting checks to prevent runtime failures.
- **Rate Limit & Error Handling:** Handles API rate limits and connection drops gracefully with built-in retries.
- **Automated Reporting:** Exports scan results, risk verdicts, and metadata into a structured `security_report.csv` file.

## Requirements

- Python 3.x
- `requests` library

## Installation & Usage

1. Clone the repository or download the script:
   git clone https://github.com/bakrmohamed/cti-automation-tool.git
   cd cti-automation-tool

2. Install the required dependencies:
   pip install requests

3. Run the tool:
   python main.py
   (On the first run, the tool will interactively ask for your AbuseIPDB API key and the list of IPs to check).

## Output

The tool generates a `security_report.csv` file containing:
- IP Address
- Abuse Confidence Score
- Country Code
- Usage Type
- Final Verdict (Safe / Review / Invalid / Error)
