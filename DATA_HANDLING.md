# Data handling policy

This repository contains only:
- Analysis scripts
- Sanitized schema documents
- Sanitized incident dataset (CSV)
- Sanitized writeups (brief/snapshot/matrix)

## Do NOT commit
- Working spreadsheets (XLSX/XLSM)
- Raw IoC lists (full domain/IP/email/phone lists)
- Any raw logs or screenshots of logs
- Any secrets/credentials/tokens
- Any non-public incident details

## Sanitization rules
- Keep detection signals as patterns (e.g., “deviceCodeFlow sign-ins + bulk download”).
- Do not include personal identifiers (emails, phone numbers).
- Prefer linking to the public source URL instead of copying IoCs.
