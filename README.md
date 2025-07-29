# Sturdy-Umberlla

**Reliable, Resilient, Ruthless SQL Injection Scanner**

## Overview

Sturdy-Umberlla is a fast, multi-target SQL Injection vulnerability scanner designed to efficiently test GET and POST parameters across numerous URLs. Crafted for penetration testers who demand a lightweight, no-nonsense tool with powerful detection capabilities — both error-based and time-based SQLi.

Built in Python 3, this tool uses threading to speed up scans and produces easy-to-parse output files for your post-exploitation reports.


## Features

- Multi-target scanning from a file (`--file`)
- Supports HTTP GET and POST methods (`--method`)
- Simple POST data injection (`--data`)
- Detects both error-based and time-based blind SQL Injection
- Threaded scanning with configurable thread count (`--threads`)
- Graceful interrupt handling (Ctrl+C)
- Logs vulnerable URLs in `vuln_results.txt`
- User-Agent spoofing for stealth scanning
- Clean, informative terminal banner and output

## Requirements

- Python 3.6+
- `requests` library

Install dependencies:

pip install requests
