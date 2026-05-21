import platform
import socket
import subprocess
import time
from dataclasses import dataclass

from pydantic import BaseModel, Field


class Input(BaseModel):
    vm_host: str = Field(
        ...,
        description="Hostname or IP address of the VM to test.",
    )
    vm_port: int = Field(
        3389,
        ge=1,
        le=65535,
        description="TCP port used to confirm the VM is reachable. Defaults to RDP.",
    )
    timeout_seconds: float = Field(
        5.0,
        gt=0,
        le=60,
        description="Timeout for each smoke-test check.",
    )
    microsoft_account_hint: str | None = Field(
        None,
        description="Optional email, UPN, or account text expected in the sign-in evidence.",
    )
    require_account_hint_match: bool = Field(
        False,
        description="When true, the Microsoft account hint must appear in the sign-in evidence.",
    )


class CheckResult(BaseModel):
    name: str
    passed: bool
    details: str
    evidence: dict[str, str] = Field(default_factory=dict)


class Output(BaseModel):
    passed: bool
    summary: str
    microsoft_account: CheckResult
    vm_access: CheckResult


@dataclass
class CommandResult:
    exit_code: int
    stdout: str
    stderr: str


def main(input: Input) -> Output:
    microsoft_account = _check_microsoft_account(input)
    vm_access = _check_vm_access(input)
    passed = microsoft_account.passed and vm_access.passed

    failed_checks = [
        check.name for check in (microsoft_account, vm_access) if not check.passed
    ]
    if passed:
        summary = "Smoke test passed: Microsoft sign-in and VM access checks succeeded."
    else:
        summary = "Smoke test failed: " + ", ".join(failed_checks)

    return Output(
        passed=passed,
        summary=summary,
        microsoft_account=microsoft_account,
        vm_access=vm_access,
    )


def _check_microsoft_account(input: Input) -> CheckResult:
    if platform.system() != "Windows":
        return CheckResult(
            name="microsoft_account",
            passed=False,
            details="Microsoft account sign-in check is only supported on Windows.",
            evidence={"platform": platform.system()},
        )

    if input.require_account_hint_match and not input.microsoft_account_hint:
        return CheckResult(
            name="microsoft_account",
            passed=False,
            details="Account hint matching was required, but no account hint was provided.",
            evidence={},
        )

    result = _run_command(["dsregcmd", "/status"], input.timeout_seconds)
    output = f"{result.stdout}\n{result.stderr}"
    status = _parse_dsreg_status(output)

    if result.exit_code != 0:
        return CheckResult(
            name="microsoft_account",
            passed=False,
            details="Unable to read Microsoft sign-in state from dsregcmd.",
            evidence={
                "exit_code": str(result.exit_code),
                "stderr": result.stderr.strip()[:500],
            },
        )

    user_sign_in_signals = {
        "AzureAdPrt": status.get("AzureAdPrt", ""),
        "EnterprisePrt": status.get("EnterprisePrt", ""),
        "WamDefaultSet": status.get("WamDefaultSet", ""),
        "WorkplaceJoined": status.get("WorkplaceJoined", ""),
    }
    device_signals = {
        "AzureAdJoined": status.get("AzureAdJoined", ""),
        "DomainJoined": status.get("DomainJoined", ""),
    }
    signed_in = any(value.upper() == "YES" for value in user_sign_in_signals.values())

    hint = input.microsoft_account_hint
    hint_found = bool(hint and hint.lower() in output.lower())
    hint_required = input.require_account_hint_match

    passed = signed_in and (not hint_required or hint_found)
    details = "dsregcmd reports an active Microsoft sign-in signal."
    if not signed_in:
        details = "dsregcmd did not report an active Microsoft sign-in signal."
    elif hint and not hint_found:
        details = "Microsoft sign-in is present, but the account hint was not found."

    evidence = {
        key: value or "UNKNOWN"
        for key, value in {**user_sign_in_signals, **device_signals}.items()
    }
    if hint:
        evidence["account_hint"] = hint
        evidence["account_hint_found"] = str(hint_found)

    return CheckResult(
        name="microsoft_account",
        passed=passed,
        details=details,
        evidence=evidence,
    )


def _check_vm_access(input: Input) -> CheckResult:
    host = input.vm_host.strip()
    port = input.vm_port
    timeout = input.timeout_seconds

    if not host:
        return CheckResult(
            name="vm_access",
            passed=False,
            details="VM host is required.",
            evidence={},
        )

    try:
        resolved_addresses = _resolve_host(host, port)
    except socket.gaierror as error:
        return CheckResult(
            name="vm_access",
            passed=False,
            details="Unable to resolve the VM host.",
            evidence={
                "host": host,
                "port": str(port),
                "error": str(error),
            },
        )

    started_at = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            elapsed = time.monotonic() - started_at
    except OSError as error:
        return CheckResult(
            name="vm_access",
            passed=False,
            details="Unable to open a TCP connection to the VM.",
            evidence={
                "host": host,
                "port": str(port),
                "timeout_seconds": str(timeout),
                "resolved_addresses": ", ".join(resolved_addresses),
                "error": str(error),
            },
        )

    return CheckResult(
        name="vm_access",
        passed=True,
        details="TCP connection to the VM succeeded.",
        evidence={
            "host": host,
            "port": str(port),
            "elapsed_seconds": f"{elapsed:.3f}",
            "resolved_addresses": ", ".join(resolved_addresses),
        },
    )


def _run_command(command: list[str], timeout_seconds: float) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as error:
        return CommandResult(exit_code=127, stdout="", stderr=str(error))
    except subprocess.TimeoutExpired as error:
        return CommandResult(
            exit_code=124,
            stdout=error.stdout or "",
            stderr=f"Timed out after {timeout_seconds} seconds.",
        )

    return CommandResult(
        exit_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def _parse_dsreg_status(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if key:
            values[key] = value

    return values


def _resolve_host(host: str, port: int) -> list[str]:
    address_info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = []
    for info in address_info:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)

    return addresses
