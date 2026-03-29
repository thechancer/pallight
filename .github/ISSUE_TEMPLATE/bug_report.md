---
name: Bug Report
about: Report a problem with the PalLight integration
title: "[BUG] "
labels: bug
assignees: ''
---

## Describe the bug
A clear description of what the bug is.

## Device details
- Device model: TOUCH-1 / REMOT_8CH / other
- Device IP: 192.168.x.x
- Device MAC: (last 4 digits only for privacy)

## HA environment
- Home Assistant version:
- Integration version (from Settings → Integrations → PalLight):
- Installation method: HACS / manual

## To reproduce
Steps to reproduce the behaviour:
1.
2.
3.

## Expected behaviour
What you expected to happen.

## Logs
Enable debug logging by adding to `configuration.yaml`:
```yaml
logger:
  default: warning
  logs:
    custom_components.pallight: debug
```
Then paste the relevant log lines here (Settings → System → Logs).

## Additional context
Any other context about the problem.
