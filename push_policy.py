#!/usr/bin/env python3
"""
push_policy.py - build and push CyberArk UAP virtual machine (ZSP) policies.

Two commands. That is the whole operator surface.

    python push_policy.py            plan: resolve, build, diff, report. NO WRITES.
    python push_policy.py --apply    create or update the policies

Default is MERGE: each CSV row adds (action blank/add) or removes
(action=remove) only what it names. Everything already on the policy stays.
--replace restores the old behaviour where the CSV is the full truth.

Everything else lives in config.json: credentials, tenant URLs, the CSV to read,
and the defaults that fill any blank cell. Policies are edited in the CSV.

Principal names are resolved to directory UUIDs internally, immediately before
the push. principals.json is written as an audit artifact only; nothing reads
it back.

Requires: requests, PyYAML is NOT needed.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import sys
import copy
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

try:
    import requests
except ImportError:  # pragma: no cover
    sys.exit("requests is required:  pip install requests")

TIMEOUT = 30
PAGE_SIZE = 10000
CONFIG_NAME = "config.json"

# This endpoint has lived in both namespaces depending on Identity version.
DISCOVERY_URL = "https://platform-discovery.cyberark.cloud/api/v2/services/subdomain/{sub}"

# TLS verification target. True = use certifi's bundle. A path = use that CA
# bundle (corporate TLS inspection). False = no verification, last resort.
VERIFY: Any = True


def set_verify(value: Any) -> None:
    global VERIFY
    VERIFY = value
    if value is False:
        print("warning: TLS certificate verification is DISABLED "
              "(network.verify=false in config.json)", file=sys.stderr)


def ssl_hint() -> str:
    return (
        "\nTLS verification failed. Your network is almost certainly doing TLS\n"
        "inspection, so Python does not trust the certificate your browser does.\n"
        "Pick one:\n"
        "  1. Use the Windows trust store (easiest):\n"
        "       python -m pip install pip-system-certs\n"
        "  2. Point at the corporate CA bundle in config.json:\n"
        '       "network": { "ca_bundle": "C:\\\\certs\\\\corp-ca.pem" }\n'
        "  3. Last resort, disable verification in config.json:\n"
        '       "network": { "verify": false }'
    )

DIRECTORY_QUERY_PATHS = ["/UserMgmt/DirectoryServiceQuery",
                         "/Core/DirectoryServiceQuery",
                         "/redrock/query"]

# ---- UAP schema constants -------------------------------------------------
FQDN_OPERATORS = {"EXACTLY", "WILDCARD", "PREFIX", "SUFFIX", "CONTAINS"}
IP_OPERATORS = {"EXACTLY", "WILDCARD"}
PRINCIPAL_TYPES = {"User", "Group", "Role"}
STATUSES = {"Active", "Suspended", "Expired", "Draft", "Validating"}
LOCATION_TYPES = {"FQDN/IP", "AWS", "Azure", "GCP"}

TARGET_CATEGORY_VM = "VM"
POLICY_TYPE_RECURRING = "Recurring"
LOCATION_FQDN_IP = "FQDN/IP"

MAX_NAME = 200
MAX_DESCRIPTION = 200
MAX_PATTERN = 300
MAX_SESSION_HOURS = 24
MAX_IDLE_MIN = 120

# Placeholder window used only to get an all-day policy past POST
# validation; it is replaced with nulls by the follow-up PUT.
ALL_DAY_SEED_FROM = "00:00"
ALL_DAY_SEED_TO = "23:59"

# daysOfTheWeek is a list of INTEGERS. CyberArk does not document which integer
# is which day. Set options.day_base in config.json. Verify against the UI once.
DAYS_SUNDAY_BASE = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]
DAYS_MONDAY_BASE = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


class ConfigError(Exception):
    pass


class ResolveError(Exception):
    pass


class BuildError(Exception):
    pass


class PushError(Exception):
    pass


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class Config:
    tenant_url: str
    client_id: str
    secret_literal: str | None
    secret_env: str | None
    uap_url: str
    policies_file: Path
    principals_file: Path
    unresolved_file: Path | None
    day_base: str
    keep_input_name: bool
    role_directory_uuid: str | None
    role_directory_name: str | None
    all_day_repr: str
    body_style: str
    mode: str
    policy_defaults: dict[str, Any]
    directory_labels: dict[str, str]
    ca_bundle: str | None
    verify_tls: bool

    @classmethod
    def load(cls, path: Path) -> "Config":
        if not path.exists():
            raise ConfigError(
                f"{path.name} not found in {path.parent}. It must sit next to this script.")
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{path.name} is not valid JSON: {exc}") from exc

        identity = raw.get("identity") or {}
        uap = raw.get("uap") or {}
        inp = raw.get("input") or {}
        out = raw.get("output") or {}
        opts = raw.get("options") or {}
        base = path.parent

        tenant_url = str(identity.get("tenant_url") or "").strip().rstrip("/")
        client_id = str(identity.get("client_id") or "").strip()
        uap_url = str(uap.get("url") or "").strip().rstrip("/")

        problems = []
        if not tenant_url:
            problems.append('identity.tenant_url is missing (e.g. "https://abc1234.id.cyberark.cloud")')
        elif "<tenant>" in tenant_url:
            problems.append("identity.tenant_url still has the <tenant> placeholder")
        if not client_id:
            problems.append("identity.client_id is missing")
        if not uap_url:
            problems.append('uap.url is missing (e.g. "https://sub.uap.cyberark.cloud/api")')
        day_base = str(opts.get("day_base", "sunday")).lower()
        if day_base not in ("sunday", "monday"):
            problems.append('options.day_base must be "sunday" or "monday"')
        adr = str(opts.get("all_day_representation", "null")).lower()
        if adr not in ("null", "empty", "omit"):
            problems.append('options.all_day_representation must be '
                            '"null", "empty" or "omit"')
        bs = str(opts.get("body_style", "merge")).lower()
        if bs not in ("merge", "gui"):
            problems.append('options.body_style must be "merge" or "gui"')
        md = str(opts.get("mode", "merge")).lower()
        if md not in ("merge", "replace"):
            problems.append('options.mode must be "merge" or "replace"')
        if problems:
            raise ConfigError(f"{path.name} needs fixing:\n  - " + "\n  - ".join(problems))

        unresolved = out.get("unresolved_file")
        return cls(
            tenant_url=tenant_url,
            client_id=client_id,
            secret_literal=str(identity.get("secret") or "").strip() or None,
            secret_env=identity.get("secret_env") or None,
            uap_url=uap_url,
            policies_file=base / (inp.get("policies_file") or "uap_policies.csv"),
            principals_file=base / (out.get("principals_file") or "principals.json"),
            unresolved_file=(base / unresolved) if unresolved else None,
            day_base=day_base,
            keep_input_name=bool(opts.get("keep_input_name", True)),
            role_directory_uuid=opts.get("role_directory_uuid") or None,
            role_directory_name=opts.get("role_directory_name") or None,
            all_day_repr=str(opts.get("all_day_representation", "null")).lower(),
            body_style=str(opts.get("body_style", "merge")).lower(),
            mode=str(opts.get("mode", "merge")).lower(),
            policy_defaults=raw.get("policy_defaults") or {},
            directory_labels=raw.get("directory_labels") or {},
            ca_bundle=(raw.get("network") or {}).get("ca_bundle") or None,
            verify_tls=bool((raw.get("network") or {}).get("verify", True)),
        )

    def secret(self) -> str:
        """Literal from config, else named env var, else prompt.

        Moving to CCP later means replacing only this method body.
        """
        if self.secret_literal:
            return self.secret_literal
        if self.secret_env:
            val = os.environ.get(self.secret_env)
            if val:
                return val
            print(f"warning: ${self.secret_env} is not set", file=sys.stderr)
        try:
            return getpass.getpass(f"Secret for {self.client_id}: ")
        except (EOFError, OSError):
            raise ConfigError(
                "no secret available and no terminal to prompt on.\n"
                f"  set ${self.secret_env or 'CYBERARK_CLIENT_SECRET'}, or put the value "
                'in config.json under identity.secret'
            ) from None

    def verify(self) -> Any:
        if not self.verify_tls:
            return False
        return self.ca_bundle or True

    def day_map(self) -> dict[str, int]:
        names = DAYS_MONDAY_BASE if self.day_base == "monday" else DAYS_SUNDAY_BASE
        return {n: i for i, n in enumerate(names)}


# ---------------------------------------------------------------------------
# Identity: auth + principal resolution
# ---------------------------------------------------------------------------

@dataclass
class Principal:
    id: str
    name: str
    type: str
    sourceDirectoryName: str
    sourceDirectoryId: str

    def to_entry(self) -> dict[str, str]:
        return asdict(self)


class IdentityClient:
    def __init__(self, tenant_url: str, client_id: str, secret: str):
        self.base = tenant_url.rstrip("/")
        self._client_id = client_id
        self._secret = secret
        self._session = requests.Session()
        self._session.verify = VERIFY
        self._token: str | None = None
        self._query_path_cache: str | None = None

    @property
    def token(self) -> str:
        if self._token is None:
            self.authenticate()
        return self._token  # type: ignore[return-value]

    def authenticate(self) -> None:
        resp = self._session.post(
            f"{self.base}/oauth2/platformtoken",
            data={"grant_type": "client_credentials",
                  "client_id": self._client_id,
                  "client_secret": self._secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            hint = ""
            if "invalid client creds" in resp.text or resp.status_code in (400, 401):
                hint = ("\n  check: the service user has 'Is OAuth confidential client'"
                        "\n  check: client_id includes the tenant suffix (name@cyberark.cloud.NNNNN)"
                        "\n  check: no MFA policy applies to the service user")
            raise ResolveError(f"auth failed ({resp.status_code}): {resp.text[:300]}{hint}")
        token = resp.json().get("access_token")
        if not token:
            raise ResolveError(f"no access_token returned: {resp.text[:300]}")
        self._token = token

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "X-IDAP-NATIVE-CLIENT": "true"}

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        resp = self._session.post(f"{self.base}{path}", json=payload,
                                  headers=self._headers(), timeout=TIMEOUT)
        if resp.status_code == 401:
            self.authenticate()
            resp = self._session.post(f"{self.base}{path}", json=payload,
                                      headers=self._headers(), timeout=TIMEOUT)
        resp.raise_for_status()
        body = resp.json()
        if not body.get("success", False):
            raise ResolveError(f"{path} returned: {body.get('Message') or body}")
        return body.get("Result") or {}

    def directory_map(self, labels: dict[str, str]) -> dict[str, str]:
        result = self._post("/Core/GetDirectoryServices", {})
        out: dict[str, str] = {}
        for item in result.get("Results", []):
            row = item.get("Row", {})
            uuid = row.get("directoryServiceUuid") or row.get("DirectoryServiceUuid")
            if not uuid:
                continue
            service = row.get("Service") or row.get("ServiceType") or ""
            out[uuid] = (labels.get(service) or row.get("DisplayName")
                         or row.get("Name") or service)
        return out

    def query(self, term: str) -> dict[str, list[dict[str, Any]]]:
        """Search users, groups and roles for `term`.

        The filter values must be JSON-ENCODED STRINGS, not objects. Passing an
        object gets "type casting failure. Key:user." from the server. This is
        what CyberArk's own documented example does:
            {"user": "{\\"Email\\": {\\"_end\\":\\"example.com\\"}}"}
        """
        payload = {
            "user": json.dumps({"_or": [
                {"SystemName": {"_like": term}},
                {"DisplayName": {"_like": term}},
                {"Email": {"_like": term}},
            ]}),
            "group": json.dumps({"_or": [
                {"SystemName": {"_like": term}},
                {"DisplayName": {"_like": term}},
            ]}),
            "roles": json.dumps({"_or": [{"Name": {"_like": term}}]}),
            "directoryServices": [],
            "Args": {"PageNumber": 1, "PageSize": PAGE_SIZE, "Limit": PAGE_SIZE,
                     "SortBy": "", "Caching": -1},
        }
        try:
            result = self._post(self._query_path(), payload)
        except ResolveError as exc:
            if "casting" not in str(exc).lower():
                raise
            # Older tenants reject _or. Fall back to one attribute.
            payload["user"] = json.dumps({"SystemName": {"_like": term}})
            payload["group"] = json.dumps({"SystemName": {"_like": term}})
            payload["roles"] = json.dumps({"Name": {"_like": term}})
            result = self._post(self._query_path(), payload)

        buckets = _buckets(result)
        if not buckets["Role"]:
            # Identity ROLES are not directory objects, so DirectoryServiceQuery
            # does not return them. They live in the Role table, reachable via
            # Redrock. This is why the UI's identity picker has a separate Role
            # filter from User and Group.
            buckets["Role"] = self.query_roles(term)
        return buckets

    def query_roles(self, term: str) -> list[dict[str, Any]]:
        safe = term.replace("'", "''")
        script = (f"SELECT ID, Name, Description FROM Role "
                  f"WHERE Name = '{safe}' OR Name LIKE '%{safe}%'")
        try:
            result = self._post("/Redrock/query", {"Script": script,
                                                   "Args": {"PageNumber": 1,
                                                            "PageSize": PAGE_SIZE,
                                                            "Limit": PAGE_SIZE,
                                                            "Caching": -1}})
        except (ResolveError, requests.RequestException):
            return []
        rows = []
        for item in result.get("Results") or []:
            row = item.get("Row") if isinstance(item, dict) else None
            if row and row.get("ID"):
                rows.append(row)
        return rows

    def _query_path(self) -> str:
        """Find whichever namespace this tenant serves DirectoryServiceQuery on.

        CyberArk Identity has moved this endpoint between /UserMgmt/ and /Core/
        across versions, and a wrong guess is a 404 rather than anything
        readable. Probe once, remember the answer.
        """
        if self._query_path_cache:
            return self._query_path_cache
        probe = {"user": json.dumps({"SystemName": {"_like": "__probe__"}}),
                 "directoryServices": []}
        tried = []
        for path in DIRECTORY_QUERY_PATHS:
            resp = self._session.post(f"{self.base}{path}", json=probe,
                                      headers=self._headers(), timeout=TIMEOUT)
            if resp.status_code != 404:
                self._query_path_cache = path
                return path
            tried.append(path)
        raise ResolveError(
            "DirectoryServiceQuery not found on this tenant. Tried: "
            + ", ".join(tried))


OBJECT_TYPE_MAP = {"user": "User", "group": "Group", "role": "Role", "roles": "Role"}

# The API stores and returns principal types in UPPER CASE ("USER", not "User").
UAP_PRINCIPAL_TYPE = {"User": "USER", "Group": "GROUP", "Role": "ROLE"}


def _buckets(result: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Normalise the response, which comes back in one of two shapes.

    Flat:     {"Results": [{"Row": {..., "ObjectType": "User"}}]}
    Bucketed: {"User": {"Results": [...]}, "Group": {...}, "Roles": {...}}
    """
    out: dict[str, list[dict[str, Any]]] = {"User": [], "Group": [], "Role": []}

    for key, ptype in (("User", "User"), ("Group", "Group"),
                       ("Roles", "Role"), ("Role", "Role")):
        for row in _rows(result.get(key)):
            if row not in out[ptype]:
                out[ptype].append(row)

    if isinstance(result.get("Results"), list):
        for item in result["Results"]:
            if not isinstance(item, dict):
                continue
            row = item.get("Row") or {}
            ptype = OBJECT_TYPE_MAP.get(str(row.get("ObjectType", "")).lower(), "User")
            if row and row not in out[ptype]:
                out[ptype].append(row)

    return out


def _rows(bucket: Any) -> list[dict[str, Any]]:
    if not isinstance(bucket, dict):
        return []
    return [r.get("Row", {}) for r in bucket.get("Results", []) if isinstance(r, dict)]


def _pick(row: dict[str, Any], *keys: str) -> str:
    for k in keys:
        if row.get(k):
            return str(row[k])
    return ""


def _to_principal(row: dict[str, Any], ptype: str,
                  dir_map: dict[str, str], cfg: Config) -> Principal:
    dir_uuid = _pick(row, "DirectoryServiceUuid", "directoryServiceUuid")
    dir_name = dir_map.get(dir_uuid, "") if dir_uuid else ""
    if ptype == "Role":
        # Identity roles are not directory objects, so the query returns no
        # directory for them. UAP rejects an empty sourceDirectoryName with
        # UAP1005, so use the configured label if one is set.
        dir_uuid = dir_uuid or cfg.role_directory_uuid or ""
        dir_name = dir_name or cfg.role_directory_name or ""
    return Principal(
        id=_pick(row, "InternalName", "_ID", "ID", "Id", "Uuid"),
        name=_pick(row, "SystemName", "Name", "DisplayName"),
        type=ptype,
        sourceDirectoryName=dir_name,
        sourceDirectoryId=dir_uuid,
    )


def _names_of(row: dict[str, Any]) -> set[str]:
    vals = {row.get(k) for k in
            ("SystemName", "Name", "DisplayName", "Email", "InternalName")}
    return {str(v).casefold() for v in vals if v}


def resolve_one(client: IdentityClient, term: str,
                dir_map: dict[str, str], cfg: Config) -> Principal:
    buckets = client.query(term)
    needle = term.casefold()
    exact: list[Principal] = []
    partial: list[Principal] = []
    for ptype, rows in buckets.items():
        for row in rows:
            p = _to_principal(row, ptype, dir_map, cfg)
            if not p.id:
                continue
            (exact if needle in _names_of(row) else partial).append(p)
    if len(exact) == 1:
        return exact[0]
    if len(exact) > 1:
        detail = ", ".join(f"{p.type}:{p.name} ({p.id})" for p in exact)
        raise ResolveError(f"{term!r} matched {len(exact)} principals exactly -> {detail}")
    if partial:
        detail = ", ".join(f"{p.type}:{p.name}" for p in partial[:6])
        raise ResolveError(f"{term!r} had no exact match. Near misses: {detail}")
    raise ResolveError(f"{term!r} not found in any directory")


# ---------------------------------------------------------------------------
# CSV -> policy bodies
# ---------------------------------------------------------------------------

def load_rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise BuildError(f"{path.name} not found next to this script")
    with path.open(newline="", encoding="utf-8-sig") as fh:
        rows = [{(k or "").strip(): (v or "").strip() for k, v in row.items()}
                for row in csv.DictReader(fh)]
    if not rows:
        raise BuildError(f"{path.name} has a header but no data rows")
    return rows


def _split(value: str) -> list[str]:
    return [p.strip() for p in str(value or "").split(";") if p.strip()]


def _bool(value: Any, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def _int(value: Any, default: int) -> int:
    if value is None or str(value).strip() == "":
        return default
    return int(str(value).strip())


def _hhmm(value: str, field: str) -> str:
    """Normalise 7:00 -> 07:00. Excel strips leading zeros on time cells."""
    parts = str(value).strip().split(":")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        raise BuildError(f"{field} must be hh:mm, got {value!r}")
    h, m = int(parts[0]), int(parts[1])
    if not (0 <= h <= 23 and 0 <= m <= 59):
        raise BuildError(f"{field} is out of range: {value!r}")
    return f"{h:02d}:{m:02d}"



# CSV action column. Blank means add.
ACTIONS = {"add": "add", "+": "add", "remove": "remove", "delete": "remove",
           "del": "remove", "rm": "remove", "-": "remove"}

RDP_COLUMNS = ("rdp_scope", "rdp_groups", "rdp_domain_groups", "rdp_reconnect")


def parse_row(row: dict[str, str], cfg: Config) -> dict[str, Any]:
    """One CSV row -> a spec.

    Every spec carries two views of the row:
      full      values with config defaults filled in. Used to CREATE a policy
                and in --replace mode.
      explicit  only the cells that actually have a value. Used in merge mode
                on an EXISTING policy, so a blank cell never overwrites what
                is already on the tenant.
    """
    d = cfg.policy_defaults
    days_lookup = cfg.day_map()

    raw_action = (row.get("action") or "add").strip().lower()
    action = ACTIONS.get(raw_action)
    if action is None:
        raise BuildError(f"action must be add or remove, got {raw_action!r}")

    name = row.get("policy_name", "").strip()
    if not name:
        raise BuildError("policy_name is required")
    if len(name) > MAX_NAME:
        raise BuildError(f"policy_name exceeds {MAX_NAME} chars")

    location = row.get("location_type") or d.get("location_type") or LOCATION_FQDN_IP
    if location not in LOCATION_TYPES:
        raise BuildError(f"location_type must be one of {sorted(LOCATION_TYPES)}")

    pattern = row.get("computername_pattern", "").strip()
    ips = _split(row.get("ip_addresses", ""))
    principals = _split(row.get("principals", ""))

    spec: dict[str, Any] = {"action": action, "name": name, "location": location,
                            "fqdn_rules": [], "ip_rules": [], "principals": principals}

    # ---- remove rows: match specs only, nothing else is read -------------
    if action == "remove":
        if not (pattern or ips or principals):
            raise BuildError("remove row needs computername_pattern, ip_addresses "
                             "or principals")
        if pattern:
            op = (row.get("fqdn_operator") or "").upper() or None
            if op and op not in FQDN_OPERATORS:
                raise BuildError(f"fqdn_operator must be one of {sorted(FQDN_OPERATORS)}")
            spec["fqdn_rules"].append({"computernamePattern": pattern, "operator": op,
                                       "domain": row.get("domain") or None})
        if ips:
            spec["ip_rules"].append({"ipAddresses": ips,
                                     "logicalName": row.get("logical_name") or None})
        return spec

    # ---- add rows ---------------------------------------------------------
    if pattern:
        op = (row.get("fqdn_operator") or d.get("fqdn_operator") or "EXACTLY").upper()
        if op not in FQDN_OPERATORS:
            raise BuildError(f"fqdn_operator must be one of {sorted(FQDN_OPERATORS)}")
        if len(pattern) > MAX_PATTERN:
            raise BuildError(f"computername_pattern exceeds {MAX_PATTERN} chars")
        rule: dict[str, Any] = {"operator": op, "computernamePattern": pattern}
        dom = row.get("domain") or d.get("domain") or ""
        if dom:
            rule["domain"] = dom
        spec["fqdn_rules"].append(rule)
    if ips:
        op = (row.get("ip_operator") or "EXACTLY").upper()
        if op not in IP_OPERATORS:
            raise BuildError(f"ip_operator must be one of {sorted(IP_OPERATORS)}")
        logical = row.get("logical_name") or d.get("logical_name") or ""
        if not logical:
            raise BuildError("ip_addresses requires logical_name")
        spec["ip_rules"].append({"operator": op, "ipAddresses": ips, "logicalName": logical})

    explicit: dict[str, Any] = {"accessWindow": {}, "conditions": {},
                                "connectAs": {}, "metadata": {}}

    # behavior
    connect_as: dict[str, Any] = {}
    ssh_user = row.get("ssh_username") or d.get("ssh_username") or ""
    if ssh_user:
        connect_as["ssh"] = {"username": ssh_user}
        if row.get("ssh_username"):
            explicit["connectAs"]["ssh"] = connect_as["ssh"]
    row_rdp = _bool(row.get("rdp")) or any(row.get(c) for c in RDP_COLUMNS)
    if row_rdp or _bool(d.get("rdp"), False):
        scope = (row.get("rdp_scope") or d.get("rdp_scope") or "local").lower()
        groups = _split(row.get("rdp_groups", "")) or list(
            d.get("rdp_groups") or ["Administrators"])
        dgroups = _split(row.get("rdp_domain_groups", ""))
        recon = _bool(row.get("rdp_reconnect"), _bool(d.get("rdp_reconnect"), False))
        if scope == "local":
            if dgroups:
                raise BuildError("rdp_domain_groups requires rdp_scope=domain")
            connect_as["rdp"] = {"localEphemeralUser": {
                "assignGroups": groups, "enableEphemeralUserReconnect": recon}}
        elif scope == "domain":
            connect_as["rdp"] = {"domainEphemeralUser": {
                "assignGroups": groups, "assignDomainGroups": dgroups,
                "enableEphemeralUserReconnect": recon}}
        else:
            raise BuildError("rdp_scope must be 'local' or 'domain'")
        if row_rdp:
            explicit["connectAs"]["rdp"] = connect_as["rdp"]

    # conditions
    day_names = _split(row.get("days_of_week", "")) or list(d.get("days_of_week") or [])
    if day_names:
        bad = [x for x in day_names if x not in days_lookup]
        if bad:
            raise BuildError(f"unknown days {bad}; expected from {list(days_lookup)}")
        days = sorted(days_lookup[x] for x in day_names)
    else:
        days = list(range(7))
    all_day = _bool(row.get("all_day"), _bool(d.get("all_day"), False))
    raw_from = row.get("from_hour") or d.get("from_hour") or ""
    raw_to = row.get("to_hour") or d.get("to_hour") or ""
    if all_day or not (raw_from and raw_to):
        from_hour = to_hour = (None if cfg.all_day_repr == "null"
                               else "" if cfg.all_day_repr == "empty" else "OMIT")
    else:
        from_hour = _hhmm(raw_from, "from_hour")
        to_hour = _hhmm(raw_to, "to_hour")
    duration = _int(row.get("max_session_duration"), int(d.get("max_session_duration", 2)))
    idle = _int(row.get("idle_time"), int(d.get("idle_time", 10)))
    if not 0 < duration <= MAX_SESSION_HOURS:
        raise BuildError(f"max_session_duration must be 1..{MAX_SESSION_HOURS}")
    if not 0 < idle <= MAX_IDLE_MIN:
        raise BuildError(f"idle_time must be 1..{MAX_IDLE_MIN}")
    window: dict[str, Any] = {"daysOfTheWeek": days}
    if from_hour != "OMIT":
        window["fromHour"] = from_hour
        window["toHour"] = to_hour
    conditions = {"accessWindow": window, "maxSessionDuration": duration, "idleTime": idle}

    if row.get("days_of_week"):
        explicit["accessWindow"]["daysOfTheWeek"] = days
    if (row.get("from_hour") or row.get("to_hour") or row.get("all_day")) and from_hour != "OMIT":
        explicit["accessWindow"]["fromHour"] = from_hour
        explicit["accessWindow"]["toHour"] = to_hour
    if row.get("max_session_duration"):
        explicit["conditions"]["maxSessionDuration"] = duration
    if row.get("idle_time"):
        explicit["conditions"]["idleTime"] = idle

    # metadata
    status = row.get("status") or d.get("status") or "Active"
    if status not in STATUSES:
        raise BuildError(f"status must be one of {sorted(STATUSES)}")
    tags = _split(row.get("policy_tags", "")) or list(d.get("policy_tags") or [])
    description = (row.get("description") or d.get("description") or "")[:MAX_DESCRIPTION]
    time_zone = row.get("time_zone") or d.get("time_zone") or "UTC"
    time_frame = {"fromTime": row.get("start_date") or None,
                  "toTime": row.get("end_date") or None}
    if row.get("description"):
        explicit["metadata"]["description"] = description
    if row.get("status"):
        explicit["metadata"]["status"] = {"status": status}
    if row.get("policy_tags"):
        explicit["metadata"]["policyTags"] = tags
    if row.get("time_zone"):
        explicit["metadata"]["timeZone"] = time_zone
    if row.get("start_date") or row.get("end_date"):
        explicit["metadata"]["timeFrame"] = time_frame

    spec["explicit"] = explicit
    spec["connect_as"] = connect_as
    spec["conditions"] = conditions
    spec["metadata"] = {
        "name": name, "description": description, "status": {"status": status},
        "timeFrame": time_frame,
        "policyEntitlement": {"targetCategory": TARGET_CATEGORY_VM,
                              "locationType": location,
                              "policyType": POLICY_TYPE_RECURRING},
        "policyTags": tags, "timeZone": time_zone,
    }
    spec["default_principals"] = list(d.get("principals") or [])
    return spec


def build_changes(rows: list[dict[str, str]], cfg: Config
                  ) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Group row specs by policy name, preserving CSV order."""
    grouped: dict[str, list[dict[str, Any]]] = {}
    display: dict[str, str] = {}
    cond_seen: dict[str, str] = {}
    errors: list[str] = []
    for idx, row in enumerate(rows, start=2):
        try:
            spec = parse_row(row, cfg)
        except (BuildError, ValueError) as exc:
            errors.append(f"row {idx}: {exc}")
            continue
        spec["line"] = idx
        key = spec["name"].casefold()
        display.setdefault(key, spec["name"])
        spec["name"] = display[key]
        if spec["action"] == "add":
            sig = json.dumps(spec["conditions"], sort_keys=True)
            if key in cond_seen and cond_seen[key] != sig:
                errors.append(
                    f"row {idx}: policy {spec['name']!r} already has different conditions "
                    f"from an earlier row. UAP allows one access window per policy; "
                    f"make the rows agree or split into separate policy_names.")
                continue
            cond_seen.setdefault(key, sig)
        grouped.setdefault(spec["name"], []).append(spec)
    return grouped, errors


def create_body(specs: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, list[str]]:
    """Full policy body from the add rows. Used for CREATE and --replace."""
    adds = [s for s in specs if s["action"] == "add"]
    if not adds:
        return None, ["no add rows for this policy"]
    first = adds[0]
    targets: dict[str, dict[str, list]] = {}
    principals: list[str] = []
    connect_as: dict[str, Any] = {}
    for s in adds:
        block = targets.setdefault(s["location"], {"fqdnRules": [], "ipRules": []})
        for r in s["fqdn_rules"]:
            if r not in block["fqdnRules"]:
                block["fqdnRules"].append(r)
        for r in s["ip_rules"]:
            if r not in block["ipRules"]:
                block["ipRules"].append(r)
        for p in s["principals"] or s["default_principals"]:
            if p not in principals:
                principals.append(p)
        for k, v in s["connect_as"].items():
            connect_as.setdefault(k, v)
    targets = {k: v for k, v in targets.items() if v["fqdnRules"] or v["ipRules"]}
    problems = []
    if not targets:
        problems.append("needs at least one computername_pattern or ip_addresses")
    if not principals:
        problems.append("needs principals")
    if not connect_as:
        problems.append("needs ssh_username or rdp=true / rdp_scope")
    body = {"metadata": copy.deepcopy(first["metadata"]),
            "principals": principals,
            "conditions": copy.deepcopy(first["conditions"]),
            "behavior": {"connectAs": connect_as},
            "targets": targets}
    return body, problems


def validate_body(body: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    meta = body.get("metadata") or {}
    if not meta.get("name"):
        problems.append("metadata.name is missing")
    if not meta.get("timeZone"):
        problems.append("metadata.timeZone is missing")
    if not body.get("principals"):
        problems.append("principals is empty; nobody could use this policy")
    for p in body.get("principals") or []:
        if isinstance(p, dict):
            if not p.get("id"):
                problems.append(f"principal {p.get('name', '?')!r} has no id")
            if str(p.get("type", "")).upper() not in {"USER", "GROUP", "ROLE"}:
                problems.append(f"principal {p.get('name', '?')!r} has a bad type "
                                f"{p.get('type')!r}")
    targets = body.get("targets") or {}
    if not targets:
        problems.append("targets is empty; policy matches nothing")
    for block in targets.values():
        if not (block.get("fqdnRules") or block.get("ipRules")):
            problems.append("a targets block has no rules")
    if not (body.get("behavior") or {}).get("connectAs"):
        problems.append("behavior.connectAs is empty")
    return problems


# ---------------------------------------------------------------------------
# UAP client
# ---------------------------------------------------------------------------

def discover_services(subdomain: str) -> dict[str, str]:
    """Ask CyberArk's platform discovery service what this tenant's hosts are.

    Unauthenticated. The service name -> host mapping is NOT the same for every
    tenant, which is why guessing "<sub>.uap.cyberark.cloud" fails with a DNS
    error on some of them.
    """
    url = DISCOVERY_URL.format(sub=subdomain)
    resp = requests.get(url, timeout=TIMEOUT, verify=VERIFY)
    if resp.status_code >= 400:
        raise PushError(f"discovery for {subdomain!r} -> {resp.status_code}: "
                        f"{resp.text[:300]}")
    body = resp.json()

    out: dict[str, str] = {}
    # Shape A: {"jit": {"api": "..."}, "secrets_hub": {"api": "..."}, ...}
    for name, entry in body.items():
        if isinstance(entry, dict) and entry.get("api"):
            out[name] = str(entry["api"])
    # Shape B: {"services": [{"name": "...", "api": "..."}]}
    for entry in body.get("services") or []:
        if isinstance(entry, dict) and entry.get("name") and entry.get("api"):
            out[str(entry["name"])] = str(entry["api"])
    return out


def cmd_discover(subdomain: str) -> int:
    try:
        services = discover_services(subdomain)
    except requests.exceptions.SSLError as exc:
        print(f"{exc}\n{ssl_hint()}", file=sys.stderr)
        return 2
    except (PushError, requests.RequestException, ValueError) as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    if not services:
        print(f"no services returned for subdomain {subdomain!r}. "
              f"Is that the right shared-services subdomain?", file=sys.stderr)
        return 1
    print(f"services for subdomain {subdomain!r}:\n")
    for name in sorted(services):
        print(f"  {name:28} {services[name]}")
    guess = _pick_uap(services)
    if guess:
        print(f'\nput this in config.json:\n  "uap": {{ "url": "{guess}" }}')
    else:
        print("\nnone of these look like the access-policies service. Open the "
              "policy page in the browser, check the network tab, and use the "
              "host it calls.")
    return 0


def _pick_uap(services: dict[str, str]) -> str:
    for key in ("uap", "access_policies", "accesspolicies", "unified_access_policies"):
        if key in services:
            return services[key]
    for name, url in services.items():
        if "uap." in url:
            return url
    return ""


class UapClient:
    def __init__(self, base_url: str, identity: IdentityClient):
        self.base = base_url.rstrip("/")
        self.identity = identity
        self._session = requests.Session()
        self._session.verify = VERIFY

    def _call(self, method: str, path: str, **kw) -> requests.Response:
        headers = {"Authorization": f"Bearer {self.identity.token}",
                   "Content-Type": "application/json", "Accept": "application/json"}
        resp = self._session.request(method, f"{self.base}{path}",
                                     headers=headers, timeout=TIMEOUT, **kw)
        if resp.status_code == 401:
            self.identity.authenticate()
            headers["Authorization"] = f"Bearer {self.identity.token}"
            resp = self._session.request(method, f"{self.base}{path}",
                                         headers=headers, timeout=TIMEOUT, **kw)
        if resp.status_code >= 400:
            raise PushError(f"{method} {path} -> {resp.status_code}: {resp.text[:500]}")
        return resp

    def list_policies(self) -> list[dict[str, Any]]:
        body = self._call("GET", "/policies").json()
        if isinstance(body, list):
            return body
        for key in ("policies", "items", "results", "value"):
            if isinstance(body.get(key), list):
                return body[key]
        return []

    def index_by_name(self) -> dict[str, dict[str, Any]]:
        out = {}
        for pol in self.list_policies():
            meta = pol.get("metadata") or {}
            name = pol.get("name") or meta.get("name")
            if name:
                out[str(name).casefold()] = pol
        return out

    @staticmethod
    def policy_id(pol: dict[str, Any]) -> str:
        meta = pol.get("metadata") or {}
        return str(pol.get("policyId") or pol.get("id")
                   or meta.get("policyId") or meta.get("id") or "")

    def get_policy(self, policy_id: str) -> dict[str, Any]:
        """Fetch ONE policy in full.

        GET /policies returns a summary that omits targets and behavior, so
        diffing against a list entry reports everything as changed and updating
        from it throws away real data.
        """
        resp = self._call("GET", f"/policies/{policy_id}")
        return resp.json() if resp.content else {}

    def create(self, body: dict[str, Any]) -> dict[str, Any]:
        resp = self._call("POST", "/policies", json=body)
        return resp.json() if resp.content else {}

    def update(self, policy_id: str, body: dict[str, Any]) -> dict[str, Any]:
        resp = self._call("PUT", f"/policies/{policy_id}", json=body)
        return resp.json() if resp.content else {}


# Fields the server owns. Never overwrite them on update.
SERVER_OWNED_METADATA = {"policyId", "createdBy", "createdOn", "updatedOn", "updatedBy"}

# The API does not preserve the order of these lists, so comparing them
# positionally reports a difference on every run and the plan never settles.
ORDER_INSENSITIVE = {"conditions.accessWindow.daysOfTheWeek",
                     "metadata.policyTags"}
# Fields this tool derives from the CSV. Everything else on a live policy is
# carried through untouched.
OWNED_METADATA = ("name", "description", "policyTags", "timeZone",
                  "timeFrame", "policyEntitlement")


# Exactly the fields the GUI's own PUT carries, captured from DevTools. It
# sends a leaner body than a merge does: no delegationClassification, no
# override* flags, no recording, and status without link.
def gui_style_body(live: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    meta = dict(desired["metadata"])
    live_meta = live.get("metadata") or {}
    if live_meta.get("policyId"):
        meta["policyId"] = live_meta["policyId"]
    live_status = live_meta.get("status") if isinstance(live_meta.get("status"), dict) else {}
    meta["status"] = {"status": desired["metadata"]["status"]["status"],
                      "statusCode": live_status.get("statusCode", "200"),
                      "statusDescription": live_status.get("statusDescription", "All good")}

    cond = desired["conditions"]
    conditions = {"accessWindow": cond["accessWindow"],
                  "idleTime": cond.get("idleTime"),
                  "maxSessionDuration": cond.get("maxSessionDuration")}

    # The GUI spells out domainEphemeralUser: null alongside localEphemeralUser.
    behavior = copy.deepcopy(desired["behavior"])
    rdp = (behavior.get("connectAs") or {}).get("rdp")
    if isinstance(rdp, dict):
        rdp.setdefault("domainEphemeralUser", None)
        rdp.setdefault("localEphemeralUser", None)

    return {"metadata": meta, "behavior": behavior, "conditions": conditions,
            "principals": desired["principals"], "targets": desired["targets"]}


def merge_for_update(live: dict[str, Any], desired: dict[str, Any]) -> dict[str, Any]:
    """Overlay the CSV-derived fields onto the live policy.

    A full replace drops delegationClassification, the status sub-fields,
    createdBy and anything else the server manages, which it rejects with a
    500. Start from what is there and change only what we own.
    """
    out = copy.deepcopy(live)

    out["principals"] = desired["principals"]
    out["targets"] = desired["targets"]
    out["behavior"] = desired["behavior"]

    cond = out.setdefault("conditions", {})
    for key, value in desired["conditions"].items():
        cond[key] = value

    meta = out.setdefault("metadata", {})
    dmeta = desired["metadata"]
    for key in OWNED_METADATA:
        if key in dmeta:
            meta[key] = dmeta[key]
    live_status = meta.get("status") if isinstance(meta.get("status"), dict) else {}
    meta["status"] = {**live_status, "status": dmeta["status"]["status"]}

    return out



# ---------------------------------------------------------------------------
# Merge mode: apply add/remove rows onto a live policy
# ---------------------------------------------------------------------------

PRINCIPAL_FIELDS = ("id", "name", "type", "sourceDirectoryName", "sourceDirectoryId")
PUT_METADATA = ("policyId", "name", "description", "policyEntitlement",
                "policyTags", "timeZone", "timeFrame")


def put_shape(live: dict[str, Any]) -> dict[str, Any]:
    """Reduce a full GET /policies/{id} to the shape PUT accepts.

    Same fields the CSV-built body carries, so server-managed extras like
    delegationClassification never go back (those caused the 500s).
    """
    m = live.get("metadata") or {}
    st = m.get("status")
    status = st.get("status") if isinstance(st, dict) else st
    meta = {k: copy.deepcopy(m[k]) for k in PUT_METADATA if k in m}
    meta["status"] = {"status": status or "Active"}
    c = live.get("conditions") or {}
    cond = {"accessWindow": copy.deepcopy(c.get("accessWindow") or {}),
            "maxSessionDuration": c.get("maxSessionDuration"),
            "idleTime": c.get("idleTime")}
    principals = [{k: p[k] for k in PRINCIPAL_FIELDS if p.get(k)}
                  for p in (live.get("principals") or []) if isinstance(p, dict)]
    return {"metadata": meta, "principals": principals, "conditions": cond,
            "behavior": copy.deepcopy(live.get("behavior") or {}),
            "targets": copy.deepcopy(live.get("targets") or {})}


def _cf(v: Any) -> str:
    return str(v or "").casefold()


def _fqdn_label(r: dict[str, Any]) -> str:
    host = r.get("computernamePattern", "")
    if r.get("domain"):
        host = f"{host}.{r['domain']}"
    return f"{r.get('operator') or 'ANY'} {host}"


def _fqdn_same(a: dict[str, Any], b: dict[str, Any]) -> bool:
    return (_cf(a.get("operator")) == _cf(b.get("operator"))
            and _cf(a.get("computernamePattern")) == _cf(b.get("computernamePattern"))
            and _cf(a.get("domain")) == _cf(b.get("domain")))


def _blocks(targets: dict[str, Any], location: str) -> dict[str, list]:
    block = targets.get(location)
    if not isinstance(block, dict):
        block = targets[location] = {}
    block["fqdnRules"] = list(block.get("fqdnRules") or [])
    block["ipRules"] = list(block.get("ipRules") or [])
    return block


def merge_existing(live: dict[str, Any], specs: list[dict[str, Any]],
                   resolved: dict[str, dict[str, str]]
                   ) -> tuple[dict[str, Any], list[str], list[str]]:
    """Returns (put body, change notes, warnings). No notes = nothing to push."""
    body = put_shape(live)
    notes: list[str] = []
    warns: list[str] = []
    targets = body["targets"]
    plist = body["principals"]

    for s in specs:
        tag = f"row {s['line']}"
        if s["action"] == "add":
            block = _blocks(targets, s["location"])
            for r in s["fqdn_rules"]:
                if any(_fqdn_same(x, r) for x in block["fqdnRules"]):
                    continue
                block["fqdnRules"].append(r)
                notes.append(f"    targets    + {_fqdn_label(r)}")
            for r in s["ip_rules"]:
                home = next((x for x in block["ipRules"]
                             if _cf(x.get("logicalName")) == _cf(r["logicalName"])
                             and _cf(x.get("operator")) == _cf(r["operator"])), None)
                if home is None:
                    block["ipRules"].append(copy.deepcopy(r))
                    for ip in r["ipAddresses"]:
                        notes.append(f"    targets    + {ip} ({r['logicalName']})")
                    continue
                home["ipAddresses"] = list(home.get("ipAddresses") or [])
                for ip in r["ipAddresses"]:
                    if ip not in home["ipAddresses"]:
                        home["ipAddresses"].append(ip)
                        notes.append(f"    targets    + {ip} ({r['logicalName']})")
            for n in s["principals"]:
                p = resolved[n]
                if any(x.get("id") == p["id"] for x in plist):
                    continue
                plist.append(copy.deepcopy(p))
                notes.append(f"    principals + {n}")
            ex = s["explicit"]
            aw = body["conditions"]["accessWindow"]
            for k, v in ex["accessWindow"].items():
                # "" and null both mean All Day; keep whichever the tenant stores
                if not (v in ("", None) and aw.get(k) in ("", None) and k in aw):
                    aw[k] = v
            body["conditions"].update(ex["conditions"])
            body["behavior"].setdefault("connectAs", {}).update(copy.deepcopy(ex["connectAs"]))
            body["metadata"].update(copy.deepcopy(ex["metadata"]))
            continue

        # ---- remove ------------------------------------------------------
        for r in s["fqdn_rules"]:
            hit = False
            for loc in list(targets):
                block = _blocks(targets, loc)
                keep = []
                for x in block["fqdnRules"]:
                    match = (_cf(x.get("computernamePattern")) == _cf(r["computernamePattern"])
                             and (r["operator"] is None
                                  or _cf(x.get("operator")) == _cf(r["operator"]))
                             and (r["domain"] is None
                                  or _cf(x.get("domain")) == _cf(r["domain"])))
                    if match:
                        hit = True
                        notes.append(f"    targets    - {_fqdn_label(x)}")
                    else:
                        keep.append(x)
                block["fqdnRules"] = keep
            if not hit:
                warns.append(f"{tag}: target {r['computernamePattern']!r} not on policy, skipped")
        for r in s["ip_rules"]:
            for ip in r["ipAddresses"]:
                hit = False
                for loc in list(targets):
                    block = _blocks(targets, loc)
                    for x in block["ipRules"]:
                        if r["logicalName"] and _cf(x.get("logicalName")) != _cf(r["logicalName"]):
                            continue
                        if ip in (x.get("ipAddresses") or []):
                            x["ipAddresses"] = [i for i in x["ipAddresses"] if i != ip]
                            hit = True
                            notes.append(f"    targets    - {ip} ({x.get('logicalName')})")
                    block["ipRules"] = [x for x in block["ipRules"] if x.get("ipAddresses")]
                if not hit:
                    warns.append(f"{tag}: ip {ip} not on policy, skipped")
        for n in s["principals"]:
            pid = (resolved.get(n) or {}).get("id")
            before = len(plist)
            plist[:] = [x for x in plist
                        if not ((pid and x.get("id") == pid) or _cf(x.get("name")) == _cf(n))]
            if len(plist) == before:
                warns.append(f"{tag}: principal {n!r} not on policy, skipped")
            else:
                notes.append(f"    principals - {n}")

    # drop empty target blocks we may have created or emptied
    for loc in list(targets):
        b = targets[loc]
        if not (b.get("fqdnRules") or b.get("ipRules")):
            del targets[loc]

    live_shape = put_shape(live)
    for section in ("metadata", "conditions", "behavior"):
        _leaf_diff(live_shape.get(section), body.get(section), section, notes,
                   skip=SERVER_OWNED_METADATA)
    return body, notes, warns


def _norm(value: Any) -> Any:
    """Drop null keys and sort dict lists so server reordering is not a change."""
    if isinstance(value, dict):
        return {k: _norm(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        items = [_norm(v) for v in value]
        return sorted(items, key=lambda x: json.dumps(x, sort_keys=True))
    return value


def _leaf_diff(live: Any, desired: Any, path: str, out: list[str],
               skip: set[str] | None = None) -> None:
    if isinstance(live, dict) and isinstance(desired, dict):
        for key in sorted(set(live) | set(desired)):
            if skip and key in skip:
                continue
            if key not in desired:          # server-owned extra, we keep it
                continue
            _leaf_diff(live.get(key), desired.get(key),
                       f"{path}.{key}" if path else key, out, skip)
        return
    if live in ("", None) and desired in ("", None):
        return
    if isinstance(live, list) and isinstance(desired, list):
        if _norm(live) == _norm(desired):
            return
        out.append(f"    {path}: {_short(_norm(live))} -> {_short(_norm(desired))}")
        return
    if live != desired:
        out.append(f"    {path}: {_short(live)} -> {_short(desired)}")


def _short(value: Any) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True)
        return text if len(text) <= 60 else text[:57] + "..."
    return json.dumps(value)


def diff_summary(live: dict[str, Any], desired: dict[str, Any]) -> list[str]:
    """Leaf-level diff for --replace mode, ignoring fields the server owns."""
    notes: list[str] = []
    lp = {(p.get("id"), p.get("name")) for p in (live.get("principals") or [])
          if isinstance(p, dict)}
    dp = {(p.get("id"), p.get("name")) for p in (desired.get("principals") or [])
          if isinstance(p, dict)}
    lids = {i for i, _ in lp}
    dids = {i for i, _ in dp}
    for pid, name in sorted(dp, key=lambda x: str(x[1])):
        if pid not in lids:
            notes.append(f"    principals + {name}")
    for pid, name in sorted(lp, key=lambda x: str(x[1])):
        if pid not in dids:
            notes.append(f"    principals - {name}")
    for section in ("metadata", "conditions", "behavior", "targets"):
        _leaf_diff(live.get(section), desired.get(section), section, notes,
                   skip=SERVER_OWNED_METADATA)
    return notes


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Build and push CyberArk UAP virtual machine (ZSP) policies.")
    ap.add_argument("--apply", action="store_true",
                    help="actually create or update (default is plan, no writes)")
    ap.add_argument("--replace", action="store_true",
                    help="CSV is the full truth: anything on a policy not in the CSV is "
                         "removed. Default is merge (add/remove only what rows say).")
    ap.add_argument("--config", default=CONFIG_NAME)
    ap.add_argument("--discover", metavar="SUBDOMAIN", nargs="?", const="",
                    help="list this tenant's real service URLs and exit")
    ap.add_argument("--dump-body", action="store_true",
                    help="print the parsed CSV changes as JSON, then exit")
    ap.add_argument("--dump-policy", metavar="NAME",
                    help="print a live policy as JSON and exit "
                         "(use it to see the exact shape the tenant stores)")
    args = ap.parse_args(argv)

    script_dir = Path(__file__).resolve().parent

    if args.discover is not None:
        sub = args.discover
        try:
            raw = json.loads((script_dir / args.config).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = {}
        net = raw.get("network") or {}
        set_verify(False if net.get("verify") is False
                   else (net.get("ca_bundle") or True))
        if not sub:
            sub = str((raw.get("uap") or {}).get("subdomain") or "").strip()
        if not sub:
            print("usage: push_policy.py --discover <subdomain>\n"
                  '  or set "uap": { "subdomain": "..." } in config.json',
                  file=sys.stderr)
            return 2
        return cmd_discover(sub)

    try:
        cfg = Config.load(script_dir / args.config)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    set_verify(cfg.verify())
    replace = args.replace or cfg.mode == "replace"

    mode = "APPLY" if args.apply else "PLAN (no writes)"
    print(f"mode     : {mode}, {'REPLACE (CSV is full truth)' if replace else 'MERGE (add/remove)'}")
    print(f"tenant   : {cfg.tenant_url}")
    print(f"uap      : {cfg.uap_url}")
    print(f"policies : {cfg.policies_file.name}")
    if cfg.secret_literal:
        print("secret   : plaintext in config.json  <-- rotate before handoff, use secret_env")
    print()

    # --- dump a live policy and stop ------------------------------------
    if args.dump_policy:
        try:
            identity = IdentityClient(cfg.tenant_url, cfg.client_id, cfg.secret())
            identity.authenticate()
            uap = UapClient(cfg.uap_url, identity)
            summary = uap.index_by_name().get(args.dump_policy.casefold())
            match = uap.get_policy(uap.policy_id(summary)) if summary else None
        except (ConfigError, ResolveError, PushError, requests.RequestException) as exc:
            print(f"{exc}", file=sys.stderr)
            return 2
        if not match:
            print(f"no policy named {args.dump_policy!r}", file=sys.stderr)
            return 1
        print(json.dumps(match, indent=2))
        return 0

    # --- parse CSV (offline) ---------------------------------------------
    try:
        rows = load_rows(cfg.policies_file)
    except BuildError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    changes, errors = build_changes(rows, cfg)
    if replace:
        for name, specs in changes.items():
            for s in specs:
                if s["action"] == "remove":
                    errors.append(f"row {s['line']}: action=remove is not allowed with "
                                  f"--replace (just leave the entry out of the CSV)")
    if errors:
        print(f"{len(errors)} problem(s) in {cfg.policies_file.name}, nothing pushed:",
              file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    n_add = sum(s["action"] == "add" for v in changes.values() for s in v)
    n_rm = sum(s["action"] == "remove" for v in changes.values() for s in v)
    print(f"parsed {len(rows)} row(s): {n_add} add, {n_rm} remove, "
          f"{len(changes)} polic{'y' if len(changes) == 1 else 'ies'}")

    if args.dump_body and not args.apply:
        print(json.dumps(changes, indent=2))
        return 0

    # --- resolve principals ----------------------------------------------
    hard: list[str] = []      # add rows / creates: must resolve
    soft: list[str] = []      # remove-only: can fall back to name match
    for specs in changes.values():
        for s in specs:
            names = s["principals"] + (s.get("default_principals") or [])
            for n in names:
                bucket = hard if s["action"] == "add" else soft
                if n not in bucket:
                    bucket.append(n)
    soft = [n for n in soft if n not in hard]

    try:
        identity = IdentityClient(cfg.tenant_url, cfg.client_id, cfg.secret())
        identity.authenticate()
        dir_map = identity.directory_map(cfg.directory_labels) if (hard or soft) else {}
    except requests.exceptions.SSLError as exc:
        print(f"\n{exc}\n{ssl_hint()}", file=sys.stderr)
        return 2
    except (ConfigError, ResolveError, requests.RequestException) as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 2

    resolved: dict[str, dict[str, str]] = {}
    failures: list[str] = []
    if hard or soft:
        print(f"\nresolving {len(hard) + len(soft)} principal(s):")
    for n in hard + soft:
        try:
            p = resolve_one(identity, n, dir_map, cfg)
        except (ResolveError, requests.RequestException) as exc:
            if n in soft:
                print(f"  ~~  {n}  (not found, will match by name for removal)")
                continue
            failures.append(f"{n}: {exc}")
            print(f"  !!  {n}")
            continue
        entry = p.to_entry()
        if cfg.keep_input_name:
            entry["name"] = n
        entry["type"] = UAP_PRINCIPAL_TYPE.get(p.type, p.type.upper())
        for field in ("sourceDirectoryName", "sourceDirectoryId"):
            if not entry.get(field):
                entry.pop(field, None)
        resolved[n] = entry
        print(f"  ok  {n}  ->  {p.type}  {p.id}")

    if failures:
        print("\nunresolved principals, nothing pushed:", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        if cfg.unresolved_file:
            cfg.unresolved_file.write_text(
                "\n".join(f.split(":")[0] for f in failures) + "\n", encoding="utf-8")
        return 1

    cfg.principals_file.write_text(json.dumps(resolved, indent=2) + "\n", encoding="utf-8")
    if cfg.unresolved_file and cfg.unresolved_file.exists():
        cfg.unresolved_file.unlink()

    # --- compare against live --------------------------------------------
    uap = UapClient(cfg.uap_url, identity)
    try:
        live_index = uap.index_by_name()
    except (PushError, requests.RequestException) as exc:
        msg = str(exc)
        print(f"\ncould not list existing policies: {msg}", file=sys.stderr)
        if "NameResolution" in msg or "getaddrinfo" in msg:
            host = cfg.uap_url.split("//")[-1].split("/")[0]
            print(f"\n{host} does not resolve. That subdomain is not this "
                  f"tenant's access-policies host.\n"
                  f"  run:  python push_policy.py --discover <your-subdomain>\n"
                  f"  then put the returned url in config.json under uap.url",
                  file=sys.stderr)
        return 2

    plan: list[tuple[str, dict[str, Any], str, str]] = []
    blocked: list[str] = []
    print()
    for name, specs in changes.items():
        summary = live_index.get(name.casefold())

        if summary is None:
            removes = [s for s in specs if s["action"] == "remove"]
            body, probs = create_body(specs)
            if removes and body is None:
                print(f"  skip    {name}  (does not exist, only remove rows)")
                continue
            for s in removes:
                print(f"  warn    row {s['line']}: remove ignored, {name!r} does not exist yet")
            if probs:
                blocked += [f"{name}: cannot create, {p}" for p in probs]
                continue
            body["principals"] = [resolved[n] for n in body["principals"]]
            probs = validate_body(body)
            if probs:
                blocked += [f"{name}: {p}" for p in probs]
                continue
            print(f"  CREATE  {name}")
            plan.append(("create", body, name, ""))
            continue

        pid = uap.policy_id(summary)
        try:
            live = uap.get_policy(pid) if pid else summary
        except (PushError, requests.RequestException) as exc:
            blocked.append(f"{name}: could not read live policy: {exc}")
            continue
        live = live or summary

        if replace:
            body, probs = create_body(specs)
            if probs:
                blocked += [f"{name}: {p}" for p in probs]
                continue
            body["principals"] = [resolved[n] for n in body["principals"]]
            body["metadata"]["policyId"] = pid
            notes = diff_summary(live, body)
            warns: list[str] = []
        else:
            body, notes, warns = merge_existing(live, specs, resolved)

        for w in warns:
            print(f"  warn    {w}")
        probs = validate_body(body)
        if probs:
            blocked += [f"{name}: after changes, {p}" for p in probs]
            continue
        if not notes:
            print(f"  ok      {name}  (already matches)")
            continue
        print(f"  UPDATE  {name}  (id {pid or '?'})")
        for line in notes:
            print(line)
        plan.append(("update", body, name, pid))

    if blocked:
        print("\nblocked, nothing pushed:", file=sys.stderr)
        for b in blocked:
            print(f"  {b}", file=sys.stderr)
        return 1

    if not plan:
        print("\nnothing to do.")
        return 0

    if not args.apply:
        print(f"\nplan only. {len(plan)} change(s) pending. "
              f"re-run with --apply to push.")
        return 0

    # --- push -------------------------------------------------------------
    print()
    pushed = failed = 0
    for action, body, name, pid in plan:
        try:
            if action == "create":
                if cfg.body_style == "gui":
                    body = gui_style_body({}, body)

                # POST rejects null fromHour/toHour (UAP1005) but PUT accepts
                # them. Create with placeholder hours, then PUT null.
                window = ((body.get("conditions") or {}).get("accessWindow") or {})
                needs_all_day = ("fromHour" in window and window["fromHour"] is None)
                if needs_all_day:
                    seed = copy.deepcopy(body)
                    seed["conditions"]["accessWindow"]["fromHour"] = ALL_DAY_SEED_FROM
                    seed["conditions"]["accessWindow"]["toHour"] = ALL_DAY_SEED_TO
                    result = uap.create(seed)
                else:
                    result = uap.create(body)

                new_id = (result.get("policyId") or result.get("id")
                          or (result.get("metadata") or {}).get("policyId") or "")
                print(f"  created  {name}  {new_id}")

                if needs_all_day:
                    if not new_id:
                        print(f"  !!       {name}: created, but no policyId came back, "
                              f"so All Day could not be applied. Re-run to fix it.",
                              file=sys.stderr)
                    else:
                        follow = copy.deepcopy(body)
                        follow.setdefault("metadata", {})["policyId"] = new_id
                        uap.update(new_id, follow)
                        print(f"           set All Day on {name}")
            else:
                if not pid:
                    raise PushError("live policy has no id field; cannot update")
                uap.update(pid, body)
                print(f"  updated  {name}  {pid}")
            pushed += 1
        except (PushError, requests.RequestException) as exc:
            print(f"  FAILED   {name}: {exc}", file=sys.stderr)
            if "sourceDirectoryName" in str(exc):
                names = [p.get("name") for p in body.get("principals") or []
                         if isinstance(p, dict)
                         and str(p.get("type")).upper() == "ROLE"]
                print(f"\n  UAP1005 is about the directory label on a principal."
                      f"\n  Role principal(s) here: {', '.join(names) or '(none)'}"
                      f"\n  Add the role to any policy in the UI, then run:"
                      f"\n      python push_policy.py --dump-policy <policy-name>"
                      f"\n  and copy the role's sourceDirectoryName into config.json:"
                      f'\n      "options": {{ "role_directory_name": "..." }}',
                      file=sys.stderr)
            failed += 1

    print(f"\n{pushed} pushed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
