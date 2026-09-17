# Policy-push

Push CyberArk UAP virtual machine (ZSP) policies. Two commands.

```powershell
python push_policy.py              # plan: build, resolve, diff, report. NO WRITES.
python push_policy.py --apply      # create or update (MERGE mode)
python push_policy.py --replace    # plan in REPLACE mode (CSV is the full truth)

python push_policy.py --discover <tenentname> #
```

Everything else is configuration. Nothing to remember, no flags.

## Files

```
push_policy.py      the only script you run
config.json         credentials, URLs, and all defaults
uap_policies.csv    the policies. this is what you edit.
principals.json     OUTPUT. audit artifact, regenerated each run. do not edit..
unresolved.txt      OUTPUT. written only when a principal fails to resolve.
```

Nothing else is needed. No PyYAML, no env vars unless you want them.

    pip install requests

## Setup

Edit `config.json`:

```json
"identity": {
  "tenant_url": "https://<tenant>.id.cyberark.cloud",
  "client_id":  "apitest@cyberark.cloud.xxxxx",
  "secret_env": "CYBERARK_CLIENT_SECRET",
  "secret":     ""
},
"uap": { "url": "https://<subdomain>.uap.cyberark.cloud/api" }
```

Secret resolution order: `identity.secret` literal, then the env var named by
`identity.secret_env`, then an interactive prompt. Leaving `secret` empty and
setting the env var keeps the credential out of the file. Putting it in
`config.json` works for handoff but the script warns you every run.

When you move to CCP, replace the body of `Config.secret()`. It is the only
place the credential is read.

The service user needs **DpaAdmin** and **Is OAuth confidential client** ticked
in Identity Administration > Core Services > Users. `client_id` is the login
name *with* the tenant suffix. No OAuth web app registration is needed;
`platformtoken` is a built-in tenant endpoint.

## How a run works

1. Read `uap_policies.csv`, build policy bodies, validate offline. Any bad row
   stops the run before a single call goes out.
2. Authenticate, resolve every principal name to a directory UUID.
   Unresolved principal means nothing is pushed.
3. `GET /policies`, match by name, diff.
4. For existing policies, `GET /policies/{id}` and apply the rows on top (merge)
   or diff against the CSV (replace). Print CREATE / UPDATE / already matches.
5. Stop, unless `--apply`.

Safe to re-run. Matching policies are skipped, so `--apply` twice does not
create duplicates.

## Merge vs replace

**Merge (default).** Each row changes only what it names. Anything already on
the live policy stays. The CSV only needs today's change; clear rows once applied.

| action | on an existing policy | policy does not exist |
|---|---|---|
| `add` or blank | adds the host / IP / principal if missing. Non-blank setting cells (days, hours, duration, idle, ssh/rdp, description, status, tags, time zone) overwrite that one field. Blank cells leave the live value alone. | created, blanks filled from `policy_defaults` |
| `remove` | removes the host / IP / principal. `fqdn_operator`, `domain`, `logical_name` narrow the match only if filled. Setting cells are ignored. | row skipped |

Examples:

```
policy_name,action,computername_pattern,domain,principals
WIN-PROD-APP,add,testserver3,engdeltek.local,
WIN-PROD-APP,remove,testserver,,
WIN-PROD-APP,add,,,jdoe@corp
WIN-PROD-APP,remove,,,olduser@corp
```

Safety: a change that would leave a policy with no targets or no principals is
blocked and nothing is pushed. Deleting a whole policy is a UI action.
Removing something that is not on the policy prints a warning, not an error.

**Replace (`--replace`, or `"options": {"mode": "replace"}`).** Old behaviour:
the CSV is the full definition and anything not in it is removed. `remove` rows
are rejected in this mode.

## The CSV

One row per target pattern. Rows sharing a `policy_name` merge their targets
and principals into one policy.

| column | notes |
|---|---|
| `policy_name` | required. the grouping key. |
| `action` | `add` (default when blank) or `remove`. merge mode only. |
| `principals` | `;` separated names. resolved automatically. required to create. |
| `computername_pattern` + `domain` | FQDN targeting |
| `ip_addresses` + `logical_name` | IP targeting. `;` separated addresses. |
| `fqdn_operator` | EXACTLY, WILDCARD, PREFIX, SUFFIX, CONTAINS. UI calls EXACTLY "Is". |
| `rdp` + `rdp_scope` + `rdp_groups` | Windows. scope is local or domain. |
| `ssh_username` | Linux. set both to cover Linux and Windows in one policy. |
| `max_session_duration` | **hours**, 1-24 |
| `idle_time` | **minutes**, 1-120 |
| `from_hour` / `to_hour` | `hh:mm`. `7:00` is normalised to `07:00` automatically. |

Any blank cell falls back to `policy_defaults` in config.json. A missing column
behaves the same as a blank one.

UAP holds **one** principals list, behavior, and conditions per policy. There is
no rules array, so one persona means one policy. Rows sharing a `policy_name`
with *different* conditions is an error, not a silent drop.

## Things to verify once

**`options.day_base`.** `daysOfTheWeek` is integers 0-6 and CyberArk does not
document which integer is which day. Default assumes 0=Sunday. Push one policy,
open it in the UI, confirm the days match. If off by one, set `"day_base":
"monday"`.

**The Operating system checkbox.** The wizard has Linux/Windows checkboxes but
there is no OS field anywhere in the API body, and CyberArk's own SDK model has
none either. It appears to be implied by whether `connectAs` carries `rdp` or
`ssh`. Confirm on your first policy.

## Access window truncates the session

`max_session_duration` is a ceiling, not a guarantee. Whichever fires first
wins: the window closing, the duration elapsing, or the idle timer. Connect at
17:00 with a 07:00-19:00 window and a 4 hour duration and you get two hours.

## Not included

Strong accounts and target sets are a separate service
(`{sub}.dpa.cyberark.cloud`) and a separate job. A Windows RDP policy with
`rdp_scope: domain` needs a strong account with a target set covering the host
or sessions fail at connect time, but that has no bearing on creating the
policy.
