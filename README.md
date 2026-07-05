# SpyTX

SpyTX is a clean public-intelligence terminal toolkit for IP, domain, DNS, TLS,
web posture, username, and phone-number metadata checks.

It uses public network data, local parsing, and safe metadata only. It does not
use private databases, secret tokens, tag/profile lookups, account bypasses, or
phone-to-person matching.

## Screenshots

### Boot

![SpyTX boot terminal](docs/screenshots/01_boot.svg)

### Dashboard

![SpyTX dashboard terminal](docs/screenshots/02_dashboard.svg)

### IP Metadata

![SpyTX IP metadata result](docs/screenshots/03_ip_result.svg)

### Geo Metadata

![SpyTX geo metadata result](docs/screenshots/05_geo_result.svg)

### Phone Metadata

![SpyTX phone metadata result](docs/screenshots/04_phone_result.svg)

## Install

```powershell
py -m pip install -r requirements.txt
py main.py
```

## Commands

Interactive terminal:

```powershell
py main.py
```

Direct commands:

```powershell
py main.py ip 8.8.8.8
py main.py deepip 8.8.8.8
py main.py checkip 8.8.8.8
py main.py iphealth
py main.py engines
py main.py geo 8.8.8.8
py main.py bestgeo 8.8.8.8
py main.py providers 8.8.8.8
py main.py precision 8.8.8.8
py main.py copygeo 8.8.8.8
py main.py copygmaps 8.8.8.8
py main.py map 8.8.8.8
py main.py domain example.com
py main.py lookup example.com
py main.py dns example.com
py main.py whois example.com
py main.py contacts example.com
py main.py tls example.com
py main.py web example.com
py main.py webcheck example.com
py main.py phone +628123456789
py main.py social syntx404
py main.py name "Ada Lovelace"
py main.py username syntx404
py main.py rdap 8.8.8.8
```

## Python

```python
from spytx import inspect_phone

result = inspect_phone("+628123456789")
print(result["e164"])
```

## Scope

- IP and domain checks are public network intelligence.
- Phone checks are validation and carrier/region metadata when available.
- Username checks generate public profile review links only.
- Reports are JSON by default for easy auditing.

## Tests

```powershell
py -m unittest discover -s tests
```
