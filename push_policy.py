#!/usr/bin/env python3
"""
push_policy.py - build and push CyberArk UAP virtual machine (ZSP) policies.

Two commands. That is the whole operator surface.

    python push_policy.py            plan: resolve, build, diff, report. NO WRITES.
    python push_policy.py --apply    create or update the policies

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
    policy_defaults: dict[str, Any]
    directory_labels: dict[str, str]

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
            policy_defaults=raw.get("policy_defaults") or {},
            directory_labels=raw.get("directory_labels") or {},
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


def build_bodies(rows: list[dict[str, str]],
                 cfg: Config) -> tuple[list[dict[str, Any]], list[str]]:
    """Rows sharing policy_name merge their targets and principals."""
    d = cfg.policy_defaults
    days_lookup = cfg.day_map()
    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    cond_seen: dict[str, str] = {}
    errors: list[str] = []

    for idx, row in enumerate(rows, start=2):
        try:
            name = row.get("policy_name", "").strip()
            if not name:
                raise BuildError("policy_name is required")
            if len(name) > MAX_NAME:
                raise BuildError(f"policy_name exceeds {MAX_NAME} chars")

            location = row.get("location_type") or d.get("location_type") or LOCATION_FQDN_IP
            if location not in LOCATION_TYPES:
                raise BuildError(f"location_type must be one of {sorted(LOCATION_TYPES)}")

            # targets
            pattern = row.get("computername_pattern", "").strip()
            ips = _split(row.get("ip_addresses", ""))
            if not pattern and not ips:
                raise BuildError("row needs computername_pattern or ip_addresses")
            fqdn_rules, ip_rules = [], []
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
                fqdn_rules.append(rule)
            if ips:
                op = (row.get("ip_operator") or "EXACTLY").upper()
                if op not in IP_OPERATORS:
                    raise BuildError(f"ip_operator must be one of {sorted(IP_OPERATORS)}")
                logical = row.get("logical_name") or d.get("logical_name") or ""
                if not logical:
                    raise BuildError("ip_addresses requires logical_name")
                ip_rules.append({"operator": op, "ipAddresses": ips, "logicalName": logical})

            # principals (names now; resolved later)
            wanted = _split(row.get("principals", "")) or list(d.get("principals") or [])
            if not wanted:
                raise BuildError("row needs principals (semicolon separated)")

            # behavior
            connect_as: dict[str, Any] = {}
            ssh_user = row.get("ssh_username") or d.get("ssh_username") or ""
            if ssh_user:
                connect_as["ssh"] = {"username": ssh_user}
            if _bool(row.get("rdp"), bool(d.get("rdp", False))) or row.get("rdp_scope"):
                scope = (row.get("rdp_scope") or d.get("rdp_scope") or "local").lower()
                groups = _split(row.get("rdp_groups", "")) or list(
                    d.get("rdp_groups") or ["Administrators"])
                dgroups = _split(row.get("rdp_domain_groups", ""))
                recon = _bool(row.get("rdp_reconnect"), bool(d.get("rdp_reconnect", False)))
                if scope == "local":
                    if dgroups:
                        raise BuildError("rdp_domain_groups requires rdp_scope=domain")
                    connect_as["rdp"] = {"localEphemeralUser": {
                        "assignGroups": groups,
                        "enableEphemeralUserReconnect": recon}}
                elif scope == "domain":
                    connect_as["rdp"] = {"domainEphemeralUser": {
                        "assignGroups": groups,
                        "assignDomainGroups": dgroups,
                        "enableEphemeralUserReconnect": recon}}
                else:
                    raise BuildError("rdp_scope must be 'local' or 'domain'")
            if not connect_as:
                raise BuildError("row needs ssh_username, or rdp=true / rdp_scope")

            # conditions
            day_names = _split(row.get("days_of_week", "")) or list(d.get("days_of_week") or [])
            if day_names:
                bad = [x for x in day_names if x not in days_lookup]
                if bad:
                    raise BuildError(f"unknown days {bad}; expected from {list(days_lookup)}")
                days = sorted(days_lookup[x] for x in day_names)
            else:
                days = list(range(7))
            from_hour = _hhmm(row.get("from_hour") or d.get("from_hour") or "00:00", "from_hour")
            to_hour = _hhmm(row.get("to_hour") or d.get("to_hour") or "23:59", "to_hour")
            duration = _int(row.get("max_session_duration"),
                            int(d.get("max_session_duration", 2)))
            idle = _int(row.get("idle_time"), int(d.get("idle_time", 10)))
            if not 0 < duration <= MAX_SESSION_HOURS:
                raise BuildError(f"max_session_duration must be 1..{MAX_SESSION_HOURS}")
            if not 0 < idle <= MAX_IDLE_MIN:
                raise BuildError(f"idle_time must be 1..{MAX_IDLE_MIN}")
            conditions = {
                "accessWindow": {"daysOfTheWeek": days,
                                 "fromHour": from_hour, "toHour": to_hour},
                "maxSessionDuration": duration,
                "idleTime": idle,
            }

            status = row.get("status") or d.get("status") or "Active"
            if status not in STATUSES:
                raise BuildError(f"status must be one of {sorted(STATUSES)}")

            body = grouped.get(name)
            if body is None:
                body = {
                    "metadata": {
                        "name": name,
                        "description": (row.get("description")
                                        or d.get("description") or "")[:MAX_DESCRIPTION],
                        "status": {"status": status},
                        "timeFrame": {"fromTime": row.get("start_date") or None,
                                      "toTime": row.get("end_date") or None},
                        "policyEntitlement": {
                            "targetCategory": TARGET_CATEGORY_VM,
                            "locationType": location,
                            "policyType": POLICY_TYPE_RECURRING},
                        "policyTags": _split(row.get("policy_tags", ""))
                                      or list(d.get("policy_tags") or []),
                        "timeZone": row.get("time_zone") or d.get("time_zone") or "UTC",
                    },
                    "principals": list(wanted),          # names; swapped for objects later
                    "conditions": conditions,
                    "behavior": {"connectAs": connect_as},
                    "targets": {location: {"fqdnRules": fqdn_rules, "ipRules": ip_rules}},
                }
                grouped[name] = body
                order.append(name)
                cond_seen[name] = json.dumps(conditions, sort_keys=True)
            else:
                block = body["targets"].setdefault(location,
                                                   {"fqdnRules": [], "ipRules": []})
                for r in fqdn_rules:
                    if r not in block["fqdnRules"]:
                        block["fqdnRules"].append(r)
                for r in ip_rules:
                    if r not in block["ipRules"]:
                        block["ipRules"].append(r)
                for p in wanted:
                    if p not in body["principals"]:
                        body["principals"].append(p)
                if cond_seen[name] != json.dumps(conditions, sort_keys=True):
                    raise BuildError(
                        f"policy {name!r} already has different conditions from an earlier "
                        f"row. UAP allows one access window per policy; split these into "
                        f"separate policy_names.")
        except (BuildError, ValueError) as exc:
            errors.append(f"row {idx}: {exc}")

    return [grouped[n] for n in order], errors


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
    resp = requests.get(url, timeout=TIMEOUT)
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
# Fields this tool derives from the CSV. Everything else on a live policy is
# carried through untouched.
OWNED_METADATA = ("name", "description", "policyTags", "timeZone",
                  "timeFrame", "policyEntitlement")


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
    if live != desired:
        out.append(f"    {path}: {_short(live)} -> {_short(desired)}")


def _short(value: Any) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True)
        return text if len(text) <= 60 else text[:57] + "..."
    return json.dumps(value)


def diff_summary(live: dict[str, Any], desired: dict[str, Any]) -> list[str]:
    """Leaf-level diff, ignoring fields the server owns."""
    notes: list[str] = []
    lp = {(p.get("id"), p.get("name")) for p in (live.get("principals") or [])
          if isinstance(p, dict)}
    dp = {(p.get("id"), p.get("name")) for p in (desired.get("principals") or [])
          if isinstance(p, dict)}
    for _, name in sorted(dp - lp, key=lambda x: str(x[1])):
        notes.append(f"    principals + {name}")
    for _, name in sorted(lp - dp, key=lambda x: str(x[1])):
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
    ap.add_argument("--config", default=CONFIG_NAME)
    ap.add_argument("--discover", metavar="SUBDOMAIN", nargs="?", const="",
                    help="list this tenant's real service URLs and exit")
    ap.add_argument("--dump-policy", metavar="NAME",
                    help="print a live policy as JSON and exit "
                         "(use it to see the exact shape the tenant stores)")
    args = ap.parse_args(argv)

    script_dir = Path(__file__).resolve().parent

    if args.discover is not None:
        sub = args.discover
        if not sub:
            try:
                raw = json.loads((script_dir / args.config).read_text(encoding="utf-8"))
                sub = str((raw.get("uap") or {}).get("subdomain") or "").strip()
            except (OSError, json.JSONDecodeError):
                sub = ""
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

    mode = "APPLY" if args.apply else "PLAN (no writes)"
    print(f"mode     : {mode}")
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

    # --- build bodies from CSV (offline) ---------------------------------
    try:
        rows = load_rows(cfg.policies_file)
    except BuildError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    bodies, errors = build_bodies(rows, cfg)
    if errors:
        print(f"{len(errors)} problem(s) in {cfg.policies_file.name}, nothing pushed:",
              file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1
    print(f"built {len(bodies)} polic{'y' if len(bodies) == 1 else 'ies'} "
          f"from {len(rows)} row(s)")

    # --- resolve principals ----------------------------------------------
    names: list[str] = []
    for b in bodies:
        for n in b["principals"]:
            if n not in names:
                names.append(n)

    try:
        identity = IdentityClient(cfg.tenant_url, cfg.client_id, cfg.secret())
        identity.authenticate()
        dir_map = identity.directory_map(cfg.directory_labels)
    except (ConfigError, ResolveError, requests.RequestException) as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 2

    print(f"\nresolving {len(names)} principal(s):")
    resolved: dict[str, dict[str, str]] = {}
    failures: list[str] = []
    for n in names:
        try:
            p = resolve_one(identity, n, dir_map, cfg)
        except (ResolveError, requests.RequestException) as exc:
            failures.append(f"{n}: {exc}")
            print(f"  !!  {n}")
            continue
        entry = p.to_entry()
        if cfg.keep_input_name:
            entry["name"] = n
        entry["type"] = UAP_PRINCIPAL_TYPE.get(p.type, p.type.upper())
        # An empty string here fails UAP1005 validation. Omit instead.
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

    for b in bodies:
        b["principals"] = [resolved[n] for n in b["principals"]]

    bad = [(b["metadata"]["name"], validate_body(b)) for b in bodies]
    bad = [(n, p) for n, p in bad if p]
    if bad:
        print("\nvalidation failed, nothing pushed:", file=sys.stderr)
        for n, probs in bad:
            for p in probs:
                print(f"  {n}: {p}", file=sys.stderr)
        return 1

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
    print()
    for b in bodies:
        name = b["metadata"]["name"]
        live = live_index.get(name.casefold())
        if live is None:
            print(f"  CREATE  {name}")
            plan.append(("create", b, name, ""))
            continue
        pid = uap.policy_id(live)
        notes = diff_summary(live, b)
        if not notes:
            print(f"  ok      {name}  (already matches)")
            continue
        print(f"  UPDATE  {name}  (id {pid or '?'})")
        for line in notes:
            print(line)
        plan.append(("update", b, name, pid))

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
                result = uap.create(body)
                new_id = (result.get("policyId") or result.get("id")
                          or (result.get("metadata") or {}).get("policyId") or "")
                print(f"  created  {name}  {new_id}")
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
