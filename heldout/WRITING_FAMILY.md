# Writing a held-out company network

You are writing a test set for a defender (a person or a learned policy) who investigates an
intrusion in a small company network and decides which machines to cut off. Write it from this
page only. Do not read the code, the configuration, the other families, the reports or any
results: a held-out set is worth something only if nobody who built the defender chose it.

## The world

A company has workstations (one per employee) and four servers: a domain controller, a file
server, a web server and a backup server. Some employees are IT administrators with separate
admin accounts. Over four hours, people work: they log on, run applications, browse; admins log on
to servers; IT and software updaters create scheduled tasks; the backup pulls data from the file
server; some users upload large files to cloud storage; CDNs produce long random-looking DNS names.

An attacker gets in (a phishing document on one workstation, or a password spray from outside),
looks around, dumps credentials, moves to other machines with a stolen admin account, sets up
persistence on the file server and tries to send data out (over DNS or HTTPS). Each attacker step
can use a quieter variant that simple detections miss.

## What you write

One YAML file, `heldout/heldout.yaml`, with exactly this shape:

```yaml
family:
  workstations: [MIN, MAX]        # integers, 4 <= MIN <= MAX <= 16
  admins: [MIN, MAX]              # integers, 1 <= MIN <= MAX <= 4, and MAX < workstations MIN
  initial_access: {phish: P, spray: P}     # non-negative weights
  lateral_hops: [MIN, MAX]        # how many machines the attacker moves through, 1 <= MIN <= MAX <= 3
  exfil: {dns: P, https: P}       # non-negative weights
  admin_remote_rate: R            # per admin per 5-minute tick, legitimate logon to a server, 0..0.4
  it_task_rate: R                 # per tick, IT creates a scheduled task somewhere, 0..0.2
  encoded_ps_rate: R              # per admin per tick, an admin runs an encoded PowerShell script, 0..0.1
  backup_ticks: [A, B]            # integers, 0 <= A <= B <= 47: when the backup runs
  helpdesk_rate: R                # per tick, an admin logs on to a user's workstation to help, 0..0.3
  macro_rate: R                   # per user per tick, a spreadsheet macro starts cmd.exe, 0..0.05
  appdata_task_rate: R            # per tick, an updater registers a task in a user folder, 0..0.1
  cdn_rate: R                     # per user per tick, a long hashed CDN name, 0..0.1
  upload_rate: R                  # per user per tick, a large upload to cloud storage, 0..0.05
  stealth: S                      # chance each attacker step uses a quieter variant, 0..0.8
notes: >
  One paragraph: what kind of company this is and why it is a fair but different test.
```

Make it different from a generic small office in at least two ways (size, how busy IT is, how
quiet the attacker is, how the attacker gets in), while keeping it a network a competent
defender should handle at least sometimes. Do not make it impossible.

When the file exists, it is run once. Its first result is recorded in
`reports/heldout/first_run.json` and is never rewritten, whatever it shows.
