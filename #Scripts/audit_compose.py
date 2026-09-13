#!/usr/bin/env python3
"""
audit_compose.py — Recursively scans a directory for docker-compose files
and flags common security, reliability, and "don't commit this to GitHub"
issues before you push your home lab stack.

Usage:
    python3 audit_compose.py [PATH] [--output report.md] [--json report.json] [--no-color]

If PATH is omitted, the current directory is scanned.

Requires: PyYAML (pip install pyyaml --break-system-packages)
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path

try:
    import yaml
except ImportError:
    print("This script requires PyYAML. Install it with:")
    print("    pip install pyyaml --break-system-packages")
    sys.exit(1)

# Some servers (minimal Debian/Ubuntu installs, cron, SSH with no locale set)
# default stdout to ASCII/latin-1, which crashes on the emoji below. Force
# UTF-8 on stdout/stderr where possible; fall back to plain ASCII icons if not.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    _UTF8_OK = True
except (AttributeError, ValueError):
    _UTF8_OK = False

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

COMPOSE_FILENAME_RE = re.compile(
    r"^docker-compose(\.[a-zA-Z0-9_-]+)?\.ya?ml$|^compose(\.[a-zA-Z0-9_-]+)?\.ya?ml$"
)

SECRET_KEY_RE = re.compile(
    r"(PASS(WORD)?|PWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|"
    r"CLIENT[_-]?SECRET|AUTH|CREDENTIAL)",
    re.IGNORECASE,
)

# Patterns that look like real secret *values* embedded directly in the file
# (not a ${VAR} substitution, not empty, not an obvious placeholder)
PLACEHOLDER_VALUES = {
    "changeme", "change_me", "your_password", "your-password", "xxxx",
    "placeholder", "example", "todo", "replace_me", "replaceme", "secret",
    "password", "admin", "",
}

DANGEROUS_CAPS = {
    "SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL",
}

SENSITIVE_MOUNT_PREFIXES = [
    "/", "/etc", "/root", "/home", "/boot", "/proc", "/sys", "/var/run/docker.sock",
]

# Only matches a *bare* ${VAR} with no default (${VAR:-x} / ${VAR-x} are fine
# even if VAR is unset, since Compose falls back to the given default).
VAR_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")

SENSITIVE_PATH_KEYWORDS = [
    "letsencrypt", "acme.json", "id_rsa", "id_ed25519", ".ssh", "private.key",
    ".pem", ".key", "credential", "secret", "backup", ".db", "sqlite",
    "shadow", "htpasswd", "wallet", ".gnupg",
]

SEVERITY_ORDER = {"HIGH": 0, "WARNING": 1, "INFO": 2}
SEVERITY_ICON = {"HIGH": "🔴", "WARNING": "🟡", "INFO": "🔵"}
SEVERITY_ICON_ASCII = {"HIGH": "[H]", "WARNING": "[W]", "INFO": "[i]"}


@dataclass
class Issue:
    severity: str          # HIGH | WARNING | INFO
    category: str          # short tag, e.g. "secrets", "resources"
    service: str            # service name, or "(file)" for file-level issues
    message: str
    fix: str = ""


@dataclass
class FileReport:
    path: str
    issues: list = field(default_factory=list)


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def find_compose_files(root: Path):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        # skip noisy/irrelevant dirs
        dirnames[:] = [d for d in dirnames if d not in
                        {".git", "node_modules", ".venv", "__pycache__"}]
        for fn in filenames:
            if COMPOSE_FILENAME_RE.match(fn):
                files.append(Path(dirpath) / fn)
    return sorted(files)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def looks_like_hardcoded_secret(value) -> bool:
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v:
        return False
    if v.startswith("${") and v.endswith("}"):
        return False  # substitution from .env / shell — fine
    if "$" in v:
        return False  # partial substitution, don't flag
    if v.lower() in PLACEHOLDER_VALUES:
        return False
    return True


def env_as_dict(environment):
    """Normalize the `environment:` block (list or dict form) into a dict."""
    if environment is None:
        return {}
    if isinstance(environment, dict):
        return environment
    if isinstance(environment, list):
        out = {}
        for item in environment:
            if isinstance(item, str) and "=" in item:
                k, _, v = item.partition("=")
                out[k] = v
            elif isinstance(item, str):
                out[item] = None
        return out
    return {}


def has_resource_limits(service: dict) -> bool:
    deploy = service.get("deploy") or {}
    resources = deploy.get("resources") or {}
    limits = resources.get("limits") or {}
    if limits.get("cpus") or limits.get("memory"):
        return True
    if service.get("mem_limit") or service.get("cpus"):
        return True
    return False


def image_has_pinned_tag(image: str) -> bool:
    if not image:
        return True  # no image (build-only service) — handled separately
    # digest pin always counts as pinned
    if "@sha256:" in image:
        return True
    if ":" not in image.split("/")[-1]:
        return False  # no tag at all -> defaults to :latest
    tag = image.rsplit(":", 1)[-1]
    return tag.lower() not in {"latest", ""}


def parse_dotenv(path: Path) -> set:
    """Best-effort KEY extraction from a .env-style file. Returns an empty
    set if the file doesn't exist or can't be read — never raises."""
    keys = set()
    if not path.exists():
        return keys
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k = line.split("=", 1)[0].strip()
            if k.startswith("export "):
                k = k[len("export "):].strip()
            if k:
                keys.add(k)
    except OSError:
        pass
    return keys


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

def check_service(name: str, svc: dict, compose_dir: Path) -> list:
    issues = []
    if not isinstance(svc, dict):
        return issues

    # --- image / tag pinning ---------------------------------------------
    image = svc.get("image")
    if image and not image_has_pinned_tag(image):
        issues.append(Issue(
            "WARNING", "image", name,
            f"Image '{image}' has no version tag (or uses :latest).",
            "Pin to a specific version or digest so updates don't silently "
            "break the stack, e.g. 'nginx:1.27.1' instead of 'nginx:latest'.",
        ))
    if "build" in svc and not image:
        issues.append(Issue(
            "INFO", "image", name,
            "Service builds from a local Dockerfile with no 'image:' name set.",
            "Consider tagging the built image (image: + build:) so it's "
            "identifiable in `docker images` and easier to reference elsewhere.",
        ))

    # --- restart policy ----------------------------------------------------
    if "restart" not in svc:
        issues.append(Issue(
            "INFO", "reliability", name,
            "No restart policy set.",
            "Add 'restart: unless-stopped' (or 'always') so the container "
            "comes back after a reboot or crash.",
        ))

    # --- privileged / capabilities ------------------------------------------
    if svc.get("privileged") is True:
        issues.append(Issue(
            "HIGH", "security", name,
            "Container runs with 'privileged: true', giving it full access to "
            "the host.",
            "Avoid privileged mode; grant only the specific capabilities "
            "needed via 'cap_add', or use 'devices:' for hardware passthrough.",
        ))

    cap_add = svc.get("cap_add") or []
    for cap in cap_add:
        if str(cap).upper() in DANGEROUS_CAPS:
            issues.append(Issue(
                "WARNING", "security", name,
                f"Adds capability '{cap}', which is broad/dangerous.",
                "Double-check this is actually required; it can allow "
                "container breakout or host-level tampering.",
            ))

    if svc.get("network_mode") == "host":
        issues.append(Issue(
            "WARNING", "security", name,
            "Uses 'network_mode: host', bypassing Docker's network isolation.",
            "Only use host networking when strictly necessary (e.g. mDNS, "
            "VPN containers); prefer defined port mappings otherwise.",
        ))

    # --- resource limits -----------------------------------------------
    if not has_resource_limits(svc):
        issues.append(Issue(
            "INFO", "resources", name,
            "No CPU/memory limits configured.",
            "Add 'deploy.resources.limits' (Compose v3) or 'mem_limit'/'cpus' "
            "so one runaway container can't starve the rest of the host.",
        ))

    # --- healthcheck -----------------------------------------------------
    if "healthcheck" not in svc:
        issues.append(Issue(
            "INFO", "reliability", name,
            "No healthcheck defined.",
            "A basic healthcheck lets 'depends_on: condition: service_healthy' "
            "and monitoring tools detect a hung container, not just a dead one.",
        ))

    # --- environment / secrets -------------------------------------------
    env = env_as_dict(svc.get("environment"))
    for key, value in env.items():
        if SECRET_KEY_RE.search(key) and looks_like_hardcoded_secret(value):
            issues.append(Issue(
                "HIGH", "secrets", name,
                f"Environment variable '{key}' looks like a hardcoded secret "
                f"value in the compose file.",
                "Move it to an untracked .env file and reference it as "
                f"'{key}=${{{key}}}', or use 'env_file:'. Make sure that .env "
                "is in .gitignore before committing.",
            ))

    # env_file existence check
    env_files = svc.get("env_file")
    if env_files:
        if isinstance(env_files, str):
            env_files = [env_files]
        for ef in env_files:
            ef_path = (compose_dir / ef)
            if not ef_path.exists():
                issues.append(Issue(
                    "WARNING", "config", name,
                    f"'env_file: {ef}' is referenced but not found at "
                    f"{ef_path}.",
                    "Either the file is missing, or it's fine because it's "
                    "intentionally untracked — just confirm it exists on the "
                    "actual host before deploying.",
                ))

    # --- ports -------------------------------------------------------------
    for p in (svc.get("ports") or []):
        p_str = str(p)
        # flag bindings explicitly opened on all interfaces for likely
        # admin/management UIs (heuristic on common ports/names)
        if re.match(r"^\d", p_str) and "127.0.0.1" not in p_str and "::1" not in p_str:
            issues.append(Issue(
                "INFO", "network", name,
                f"Port mapping '{p_str}' is exposed on all interfaces "
                f"(0.0.0.0).",
                "If this service doesn't need to be reachable from your whole "
                "LAN/internet, bind it to localhost or a management VLAN, "
                "e.g. '127.0.0.1:8080:8080', or put it behind a reverse proxy.",
            ))

    # --- logging (unbounded disk growth) ------------------------------------
    logging_cfg = svc.get("logging")
    if not logging_cfg:
        issues.append(Issue(
            "WARNING", "resources", name,
            "No 'logging:' driver/options set — Docker's default json-file "
            "driver does not rotate logs, so this container's logs can grow "
            "unbounded and fill the disk over time.",
            "Add a logging block, e.g. driver: json-file with "
            "options: {max-size: '10m', max-file: '3'}.",
        ))
    elif isinstance(logging_cfg, dict):
        driver = logging_cfg.get("driver", "json-file")
        opts = logging_cfg.get("options") or {}
        if driver == "json-file" and "max-size" not in opts:
            issues.append(Issue(
                "WARNING", "resources", name,
                "'logging.driver: json-file' is set without 'max-size', so "
                "logs still aren't rotated/capped.",
                "Add options: {max-size: '10m', max-file: '3'} to cap log growth.",
            ))

    # --- basic hardening -----------------------------------------------------
    if "user" not in svc:
        issues.append(Issue(
            "INFO", "security", name,
            "No 'user:' set — the container runs as whatever user its image "
            "defaults to (often root).",
            "Where the image supports it, set 'user: \"UID:GID\"' to avoid "
            "running as root inside the container.",
        ))
    security_opt = svc.get("security_opt") or []
    if not any("no-new-privileges" in str(o) for o in security_opt):
        issues.append(Issue(
            "INFO", "security", name,
            "'security_opt: no-new-privileges:true' is not set.",
            "Add it to block privilege escalation inside the container "
            "(setuid binaries etc.) unless a specific service needs it.",
        ))

    # --- volumes -------------------------------------------------------------
    for v in (svc.get("volumes") or []):
        v_str = v if isinstance(v, str) else v.get("source", "") if isinstance(v, dict) else ""
        if not v_str:
            continue
        host_part = v_str.split(":")[0]
        if host_part == "/var/run/docker.sock":
            issues.append(Issue(
                "HIGH", "security", name,
                "Mounts the Docker socket ('/var/run/docker.sock') into the "
                "container.",
                "This effectively grants root on the host. Only do this for "
                "tools that truly need it (Portainer, Watchtower, Traefik), "
                "and mount it ':ro' if the tool only needs to read state.",
            ))
        elif host_part in SENSITIVE_MOUNT_PREFIXES:
            issues.append(Issue(
                "HIGH", "security", name,
                f"Bind-mounts a sensitive host path ('{host_part}') into the "
                f"container.",
                "Scope the mount to the narrowest directory actually needed, "
                "and add ':ro' if write access isn't required.",
            ))
        elif host_part.startswith(("./", "../")):
            lower = host_part.lower()
            if any(kw in lower for kw in SENSITIVE_PATH_KEYWORDS):
                issues.append(Issue(
                    "WARNING", "git", name,
                    f"Bind-mounts '{host_part}', which looks like it could "
                    f"hold credentials or runtime state (certs, keys, DB "
                    f"files) and lives inside the repo directory.",
                    "Double-check this path is covered by .gitignore before "
                    "committing, or move it outside the repo entirely.",
                ))
        if v_str.startswith(str(compose_dir)) or v_str.startswith(("./", "../")):
            pass  # relative/local bind mounts are normal for a home lab

    return issues


def check_file_level(data: dict, path: Path) -> list:
    issues = []

    if isinstance(data, dict) and "version" in data:
        issues.append(Issue(
            "INFO", "config", "(file)",
            f"Top-level 'version: {data.get('version')!r}' key is present.",
            "The Compose Spec deprecated the 'version' field; modern Docker "
            "Compose ignores it. Safe to remove for a cleaner file.",
        ))

    services = (data or {}).get("services") or {}
    if len(services) > 1:
        networks = (data or {}).get("networks")
        if not networks:
            issues.append(Issue(
                "INFO", "network", "(file)",
                "Multiple services share Docker's default bridge network "
                "with no custom networks defined.",
                "Define explicit 'networks:' to isolate stacks from each "
                "other, especially if you run several compose projects on "
                "the same host.",
            ))

    return issues


def check_depends_on(data: dict) -> list:
    """Flags depends_on entries pointing at a service that doesn't exist in
    this file — usually a typo, since Compose doesn't support cross-file
    depends_on without an explicit 'include:'/multi-file setup."""
    issues = []
    services = (data or {}).get("services") or {}
    names = set(services.keys())
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        deps = svc.get("depends_on")
        if not deps:
            continue
        if isinstance(deps, dict):
            dep_names = list(deps.keys())
        elif isinstance(deps, list):
            dep_names = deps
        else:
            dep_names = []
        for d in dep_names:
            if d not in names:
                issues.append(Issue(
                    "WARNING", "config", svc_name,
                    f"'depends_on' references service '{d}', which is not "
                    f"defined in this file.",
                    "Check for a typo — Compose doesn't resolve depends_on "
                    "across separate compose files unless you're using "
                    "'include:' or `docker compose -f` with multiple files.",
                ))
    return issues


def check_undefined_vars(raw_text: str, data: dict, compose_dir: Path) -> list:
    """Flags ${VAR} substitutions with no default that aren't defined in
    .env, any referenced env_file, or the current shell environment —
    Compose silently substitutes an empty string for these."""
    issues = []
    referenced = set(VAR_REF_RE.findall(raw_text))
    if not referenced:
        return issues

    defined = set(os.environ.keys())
    defined |= parse_dotenv(compose_dir / ".env")

    services = (data or {}).get("services") or {}
    for svc in services.values():
        if not isinstance(svc, dict):
            continue
        env_files = svc.get("env_file")
        if env_files:
            if isinstance(env_files, str):
                env_files = [env_files]
            for ef in env_files:
                defined |= parse_dotenv(compose_dir / ef)

    for var in sorted(referenced - defined):
        issues.append(Issue(
            "WARNING", "config", "(file)",
            f"'${{{var}}}' is referenced but not defined in .env, any "
            f"env_file, or the shell environment.",
            f"Define {var} in the .env file next to this compose file, or "
            f"Compose will silently substitute an empty string for it.",
        ))
    return issues


def check_secrets_hygiene(compose_dir: Path) -> list:
    """File-system level checks relevant to 'about to push this to GitHub'."""
    issues = []
    gitignore = compose_dir / ".gitignore"
    env_file = compose_dir / ".env"
    if env_file.exists():
        if not gitignore.exists():
            issues.append(Issue(
                "HIGH", "git", "(repo)",
                f".env file exists at {env_file} but there's no .gitignore "
                f"next to it.",
                "Add a .gitignore that excludes '.env' before committing, or "
                "you'll push secrets straight to GitHub.",
            ))
        else:
            content = gitignore.read_text(errors="ignore")
            if ".env" not in content:
                issues.append(Issue(
                    "HIGH", "git", "(repo)",
                    f".env exists at {env_file} but is not listed in "
                    f"{gitignore}.",
                    "Add '.env' (or '*.env') to .gitignore before committing.",
                ))
    return issues


def check_git_tracked_secrets(root: Path) -> list:
    """
    If this directory is (or is inside) a git repo, check whether any .env
    files are already tracked/staged — a .gitignore entry added *after* a
    file was committed does not remove it from history or the index.
    """
    issues = []
    try:
        import subprocess
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "*.env", ".env", "**/.env"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            tracked = [line for line in result.stdout.splitlines() if line.strip()]
            for t in tracked:
                issues.append(Issue(
                    "HIGH", "git", "(repo)",
                    f"'{t}' is already tracked by git (staged or committed), "
                    f"so adding it to .gitignore now will NOT remove it from "
                    f"the repo or its history.",
                    f"Run 'git rm --cached {t}' to untrack it, add it to "
                    f".gitignore, then rotate any secrets it contained — "
                    f"they're already in git history even after removal.",
                ))
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        pass  # git not installed or not a repo — skip silently
    return issues


def check_cross_file(parsed: list) -> dict:
    """
    Checks that only make sense across the whole scan: same host port,
    container_name, or bind-mount path declared in more than one compose
    file will conflict at runtime even though each file is individually
    valid. `parsed` is a list of (relative_path, data, compose_dir).
    Returns {relative_file_path: [Issue, ...]} to merge into existing reports.
    """
    port_map = {}       # host_port -> [(file, service), ...]
    name_map = {}        # container_name -> [(file, service), ...]
    volume_map = {}       # resolved host path -> [(file, service), ...]

    for rel_path, data, compose_dir in parsed:
        services = (data or {}).get("services") or {}
        for svc_name, svc in services.items():
            if not isinstance(svc, dict):
                continue
            cname = svc.get("container_name")
            if cname:
                name_map.setdefault(cname, []).append((rel_path, svc_name))
            for p in (svc.get("ports") or []):
                p_str = str(p)
                # host port is the part before the last ':' (strip protocol suffix)
                host_part = p_str.split(":")[0] if ":" in p_str else None
                if host_part and host_part.split("/")[0].isdigit():
                    port_map.setdefault(host_part.split("/")[0], []).append((rel_path, svc_name))
            for v in (svc.get("volumes") or []):
                v_str = v if isinstance(v, str) else v.get("source", "") if isinstance(v, dict) else ""
                if not v_str:
                    continue
                parts = v_str.split(":")
                host_part = parts[0]
                mode = parts[2] if len(parts) >= 3 else "rw"
                if not host_part.startswith(("/", "./", "../")):
                    continue  # named volume, not a filesystem path
                try:
                    resolved = str(Path(host_part).resolve()) if host_part.startswith("/") \
                        else str((compose_dir / host_part).resolve())
                except OSError:
                    resolved = host_part
                volume_map.setdefault(resolved, []).append((rel_path, svc_name, mode))

    extra = {}

    def add(rel_path, issue):
        extra.setdefault(rel_path, []).append(issue)

    for port, locations in port_map.items():
        files_involved = {loc[0] for loc in locations}
        if len(files_involved) > 1:
            desc = ", ".join(f"{f}:{s}" for f, s in locations)
            for f, s in locations:
                add(f, Issue(
                    "HIGH", "conflict", s,
                    f"Host port {port} is also mapped in another compose "
                    f"file ({desc}) — only one of these can actually bind "
                    f"it on this host.",
                    "Change one of the host-side port numbers, or confirm "
                    "these stacks never run at the same time.",
                ))

    for cname, locations in name_map.items():
        files_involved = {loc[0] for loc in locations}
        if len(files_involved) > 1:
            desc = ", ".join(f"{f}:{s}" for f, s in locations)
            for f, s in locations:
                add(f, Issue(
                    "HIGH", "conflict", s,
                    f"container_name '{cname}' is also used in another "
                    f"compose file ({desc}) — Docker will refuse to start "
                    f"whichever one comes up second.",
                    "Give each service a unique container_name, or drop the "
                    "explicit name and let Compose derive it from the "
                    "project/service.",
                ))

    for path_str, locations in volume_map.items():
        files_involved = {loc[0] for loc in locations}
        services_involved = {(f, s) for f, s, _ in locations}
        any_writable = any(mode != "ro" for _, _, mode in locations)
        if (len(files_involved) > 1 or len(services_involved) > 1) and any_writable:
            desc = ", ".join(f"{f}:{s}" for f, s, _ in locations)
            for f, s, _ in locations:
                add(f, Issue(
                    "WARNING", "conflict", s,
                    f"Bind-mounts host path '{path_str}' with write access, "
                    f"and it's also mounted by another service ({desc}) — "
                    f"if both write to it concurrently this can corrupt "
                    f"data or cause lock contention.",
                    "Confirm this is intentional (e.g. multiple *arr apps "
                    "organizing a shared media library) rather than an "
                    "accidental path collision. Mount ':ro' wherever write "
                    "access isn't actually needed.",
                ))

    return extra


# --------------------------------------------------------------------------
# Main scan
# --------------------------------------------------------------------------

def scan(root: Path):
    reports = []
    parsed_for_cross_check = []  # (relative_path, data, compose_dir) for files that parsed OK
    compose_files = find_compose_files(root)

    checked_dirs = set()
    for cf in compose_files:
        rel_path = str(cf.relative_to(root))
        fr = FileReport(path=rel_path)
        try:
            with open(cf, "r", encoding="utf-8") as f:
                raw_text = f.read()
                data = yaml.safe_load(raw_text)
        except yaml.YAMLError as e:
            fr.issues.append(Issue("HIGH", "parse", "(file)",
                                    f"Could not parse YAML: {e}"))
            reports.append(fr)
            continue

        if not isinstance(data, dict):
            fr.issues.append(Issue("HIGH", "parse", "(file)",
                                    "File is empty or not a valid compose mapping."))
            reports.append(fr)
            continue

        compose_dir = cf.parent
        fr.issues.extend(check_file_level(data, cf))
        fr.issues.extend(check_depends_on(data))
        fr.issues.extend(check_undefined_vars(raw_text, data, compose_dir))

        services = data.get("services") or {}
        if not services:
            fr.issues.append(Issue("WARNING", "config", "(file)",
                                    "No 'services:' block found."))
        for name, svc in services.items():
            fr.issues.extend(check_service(name, svc, compose_dir))

        if compose_dir not in checked_dirs:
            fr.issues.extend(check_secrets_hygiene(compose_dir))
            checked_dirs.add(compose_dir)

        parsed_for_cross_check.append((rel_path, data, compose_dir))
        reports.append(fr)

    # cross-file checks: port, container_name, and volume-path collisions
    cross_issues = check_cross_file(parsed_for_cross_check)
    for fr in reports:
        if fr.path in cross_issues:
            fr.issues.extend(cross_issues[fr.path])

    # repo-wide: any .env already committed/staged despite .gitignore
    repo_issues = check_git_tracked_secrets(root)
    if repo_issues:
        fr = FileReport(path="(git repository)")
        fr.issues.extend(repo_issues)
        reports.append(fr)

    return reports, compose_files


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------

def colorize(text, code, enabled):
    return f"\033[{code}m{text}\033[0m" if enabled else text


def _filter_high_only(reports):
    return [
        FileReport(path=fr.path, issues=[i for i in fr.issues if i.severity == "HIGH"])
        for fr in reports
    ]


def print_console(reports, color=True, high_only=False):
    icons = SEVERITY_ICON if _UTF8_OK else SEVERITY_ICON_ASCII
    doc_icon = "📄" if _UTF8_OK else "-"
    check_icon = "✅" if _UTF8_OK else "OK:"
    arrow = "→" if _UTF8_OK else "->"

    if high_only:
        reports = _filter_high_only(reports)

    total = {"HIGH": 0, "WARNING": 0, "INFO": 0}
    for fr in reports:
        for i in fr.issues:
            total[i.severity] += 1

    print()
    print(colorize("=" * 70, "90", color))
    print(colorize(" Docker Compose Audit Report", "1", color))
    print(colorize("=" * 70, "90", color))
    print(f" Files scanned: {len(reports)}")
    print(f" {icons['HIGH']} HIGH: {total['HIGH']}   "
          f"{icons['WARNING']} WARNING: {total['WARNING']}   "
          f"{icons['INFO']} INFO: {total['INFO']}")
    print(colorize("=" * 70, "90", color))

    for fr in reports:
        if not fr.issues:
            continue
        print()
        print(colorize(f"{doc_icon} {fr.path}", "1;36", color))
        sorted_issues = sorted(fr.issues, key=lambda i: SEVERITY_ORDER[i.severity])
        for i in sorted_issues:
            icon = icons[i.severity]
            svc_tag = f"[{i.service}]" if i.service != "(file)" and i.service != "(repo)" else ""
            print(f"  {icon} {colorize(i.severity, '1', color):8} "
                  f"{colorize(svc_tag, '2', color)} {i.message}")
            if i.fix:
                print(f"      {colorize(arrow + ' ' + i.fix, '90', color)}")

    clean_files = [fr.path for fr in reports if not fr.issues]
    if clean_files:
        print()
        print(colorize(f"{check_icon} No issues found:", "32", color))
        for p in clean_files:
            print(f"   - {p}")
    print()


def write_markdown(reports, out_path: Path, high_only=False):
    if high_only:
        reports = _filter_high_only(reports)

    total = {"HIGH": 0, "WARNING": 0, "INFO": 0}
    for fr in reports:
        for i in fr.issues:
            total[i.severity] += 1

    lines = ["# Docker Compose Audit Report", ""]
    lines.append(f"- Files scanned: **{len(reports)}**")
    lines.append(f"- 🔴 HIGH: **{total['HIGH']}**  ·  🟡 WARNING: **{total['WARNING']}**  "
                 f"·  🔵 INFO: **{total['INFO']}**")
    lines.append("")

    for fr in reports:
        if not fr.issues:
            continue
        lines.append(f"## `{fr.path}`")
        lines.append("")
        sorted_issues = sorted(fr.issues, key=lambda i: SEVERITY_ORDER[i.severity])
        for i in sorted_issues:
            icon = SEVERITY_ICON[i.severity]
            svc_tag = f"`{i.service}` — " if i.service not in ("(file)", "(repo)") else ""
            lines.append(f"- {icon} **{i.severity}** ({i.category}) {svc_tag}{i.message}")
            if i.fix:
                lines.append(f"  - *Fix:* {i.fix}")
        lines.append("")

    clean_files = [fr.path for fr in reports if not fr.issues]
    if clean_files:
        lines.append("## ✅ Clean files")
        lines.append("")
        for p in clean_files:
            lines.append(f"- `{p}`")
        lines.append("")

    out_path.write_text("\n".join(lines), encoding="utf-8")


def write_json(reports, out_path: Path):
    payload = [
        {"path": fr.path, "issues": [asdict(i) for i in fr.issues]}
        for fr in reports
    ]
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", nargs="?", default=".",
                         help="Root directory to scan (default: current directory)")
    parser.add_argument("--output", "-o", help="Write a Markdown report to this path")
    parser.add_argument("--json", help="Write a JSON report to this path")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--high-only", action="store_true",
                         help="Only show/report HIGH severity issues (console and --output).")
    parser.add_argument("--fail-on-high", action="store_true",
                         help="Exit with status 1 if any HIGH severity issue is found "
                              "(handy in a pre-commit hook or CI check).")
    args = parser.parse_args()

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"Path does not exist: {root}")
        sys.exit(1)

    reports, compose_files = scan(root)

    if not compose_files:
        print(f"No docker-compose files found under {root}")
        sys.exit(0)

    print_console(reports, color=not args.no_color, high_only=args.high_only)

    if args.output:
        write_markdown(reports, Path(args.output), high_only=args.high_only)
        print(f"Markdown report written to {args.output}")
    if args.json:
        write_json(reports, Path(args.json))
        print(f"JSON report written to {args.json}")

    if args.fail_on_high:
        has_high = any(i.severity == "HIGH" for fr in reports for i in fr.issues)
        if has_high:
            sys.exit(1)


if __name__ == "__main__":
    main()