---
name: Feature or Rule Request
about: Propose a new QR payload security indicator, context consistency check, or tool enhancement
title: "[FEAT] "
labels: enhancement
assignees: ''
---

## Problem or Threat Scenario
Describe the QR attack vector, payload scheme, or benign false-positive scenario that needs coverage.

## Proposed Solution / Rule Specification
- **Target Payload Family**: `url` | `wifi` | `payment` | `contact` | `sms` | `email` | `phone` | `deep_link` | `plain_text`
- **Proposed Rule ID**: e.g., `PAY-...` or `CTX-...`
- **Proposed Severity & Family**: `info` | `weak` | `meaningful` | `strong`
- **Example Malicious Input**: `...`
- **Example Benign Counterpart (False-Positive Trap)**: `...`

## Non-Execution & Privacy Impact
Confirm that the proposed feature operates strictly on local data without executing or fetching the payload.
