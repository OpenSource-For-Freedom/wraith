# WRAITH Automation

These scripts provide continuous operation for users who want scheduled scans and persistence monitoring.

## 1) Register timed scans

Run in elevated PowerShell:

```powershell
cd F:\wraith\automation
.\Register-WraithTimedScan.ps1 -IntervalMinutes 30 -ScanPath "F:\" -Hours 24 -Mode all -RunAsSystem
```

This creates a scheduled task named `WRAITH Timed Scan` that writes JSON and logs to:

- `C:\ProgramData\WRAITH\ScheduledScans`

## 2) Remove timed scans

```powershell
cd F:\wraith\automation
.\Unregister-WraithTimedScan.ps1
```

## 3) Run persistence listener

```powershell
cd F:\wraith\automation
.\Start-WraithPersistenceListener.ps1 -ScanPath "F:\" -PollSeconds 120 -AutoKillCritical
```

With Slack alerts:

```powershell
cd F:\wraith\automation
.\Start-WraithPersistenceListener.ps1 -ScanPath "F:\" -PollSeconds 120 -AutoKillCritical -SlackWebhookUrl "https://hooks.slack.com/services/XXX/YYY/ZZZ"
```

This continuously polls persistence indicators and can optionally kill critical PIDs.

## 4) Slack alerts from the WRAITH app

Edit [wraith.policy.json](../wraith.policy.json):

- set `EnableSlackWebhook` to `true`
- set `SlackWebhookUrl` to your Incoming Webhook URL
- optional: set `SlackNotifyOnHigh` to `false` if you only want CRITICAL alerts

## Safety notes

- Auto kill and auto quarantine can cause disruption if false positives occur.
- Keep `wraith.policy.json` in safe defaults first, then tune allowlists.
- Permanent delete of quarantined files requires admin and should be used after analyst verification.
