from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import portalocker

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import PlainTextResponse

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

USERS_FILE = DATA_DIR / "users.json"
KEYS_FILE = DATA_DIR / "keys.json"

USERS_LOCK = USERS_FILE.with_suffix(".json.lock")
KEYS_LOCK = KEYS_FILE.with_suffix(".json.lock")

SUPPORTED_PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
)

app = FastAPI(
    title="Private Subscription API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )

def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def read_json_file(
    path: Path,
    list_name: str,
) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError:
        raise HTTPException(
            status_code=500,
            detail=f"{path.name} not found",
        )
    except json.JSONDecodeError:
        raise HTTPException(
            status_code=500,
            detail=f"Invalid JSON in {path.name}",
        )

    if not isinstance(data, dict):
        raise HTTPException(
            status_code=500,
            detail=f"Invalid structure in {path.name}",
        )

    if not isinstance(data.get(list_name), list):
        raise HTTPException(
            status_code=500,
            detail=f"Invalid {list_name} list in {path.name}",
        )

    return data

def read_users() -> dict[str, Any]:
    return read_json_file(USERS_FILE, "users")

def read_keys() -> dict[str, Any]:
    return read_json_file(KEYS_FILE, "keys")

def atomic_write_users(data: dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(
        prefix=USERS_FILE.name + ".",
        suffix=".tmp",
        dir=DATA_DIR,
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)
            file.write("\n")
            file.flush()
            os.fsync(file.fileno())

        os.replace(temp_name, USERS_FILE)

        dir_fd = os.open(DATA_DIR, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)

def find_user(
    data: dict[str, Any],
    token: str,
) -> dict[str, Any] | None:
    supplied_hash = token_digest(token)

    for user in data["users"]:
        if not isinstance(user, dict):
            continue

        stored_hash = str(
            user.get("token_sha256", "")
        ).lower()

        if stored_hash and hmac.compare_digest(
            supplied_hash,
            stored_hash,
        ):
            return user

    return None

def reject(
    message: str,
    hwid_required: bool = False,
) -> PlainTextResponse:
    headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate, private",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
    }

    if hwid_required:
        headers["subscription-always-hwid-enable"] = "1"

    return PlainTextResponse(
        message + "\n",
        status_code=403,
        headers=headers,
    )

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/get/token={token}")
def subscription(
    token: str,
    x_hwid: str | None = Header(default=None, alias="x-hwid"),
    x_device_model: str | None = Header(
        default=None,
        alias="x-device-model",
    ),
    x_device_os: str | None = Header(
        default=None,
        alias="x-device-os",
    ),
):
    if not token or len(token) > 256:
        raise HTTPException(
            status_code=404,
            detail="Subscription not found",
        )

    try:
        # Блокировка пользователей нужна для безопасного
        # обновления списка устройств при параллельных запросах.
        with portalocker.Lock(
            str(USERS_LOCK),
            mode="a",
            timeout=20,
        ):
            users_data = read_users()
            user = find_user(users_data, token)

            if user is None:
                raise HTTPException(
                    status_code=404,
                    detail="Subscription not found",
                )

            if not user.get("enabled", True):
                raise HTTPException(
                    status_code=404,
                    detail="Subscription disabled",
                )

            role = user.get("role", "user")
            device_check = bool(
                user.get("device_check_enabled", True)
            )

            if device_check:
                hwid = (x_hwid or "").strip()

                if not hwid:
                    return reject(
                        "HWID_REQUIRED",
                        hwid_required=True,
                    )

                if len(hwid) > 256:
                    return reject(
                        "INVALID_HWID",
                        hwid_required=True,
                    )

                devices = user.setdefault("devices", [])

                if not isinstance(devices, list):
                    raise HTTPException(
                        status_code=500,
                        detail="Invalid devices list",
                    )

                existing = next(
                    (
                        device
                        for device in devices
                        if isinstance(device, dict)
                        and device.get("hwid") == hwid
                    ),
                    None,
                )

                if existing is None:
                    try:
                        max_devices = int(
                            user.get("max_devices", 1)
                        )
                    except (TypeError, ValueError):
                        max_devices = 1

                    if max_devices < 1 or len(devices) >= max_devices:
                        return reject(
                            "DEVICE_LIMIT_REACHED",
                            hwid_required=True,
                        )

                    now = utc_now()

                    existing = {
                        "hwid": hwid,
                        "model": (
                            x_device_model or "unknown"
                        )[:120],
                        "os": (
                            x_device_os or "unknown"
                        )[:80],
                        "first_seen": now,
                        "last_seen": now,
                    }

                    devices.append(existing)

                else:
                    existing["model"] = (
                        x_device_model
                        or existing.get("model")
                        or "unknown"
                    )[:120]

                    existing["os"] = (
                        x_device_os
                        or existing.get("os")
                        or "unknown"
                    )[:80]

                    existing["last_seen"] = utc_now()

                atomic_write_users(users_data)

            if role == "admin":
                allowed_ids = None
            else:
                key_ids = user.get("key_ids", [])

                if not isinstance(key_ids, list):
                    raise HTTPException(
                        status_code=500,
                        detail="Invalid user key_ids",
                    )

                allowed_ids = set(key_ids)

            # Отдельно читаем файл VPN-ключей.
            with portalocker.Lock(
                str(KEYS_LOCK),
                mode="a",
                timeout=20,
            ):
                keys_data = read_keys()

            output = []

            for key in keys_data["keys"]:
                if not isinstance(key, dict):
                    continue

                if not key.get("enabled", True):
                    continue

                if (
                    allowed_ids is not None
                    and key.get("id") not in allowed_ids
                ):
                    continue

                uri = str(key.get("uri", "")).strip()

                if (
                    uri.startswith(SUPPORTED_PROTOCOLS)
                    and "\n" not in uri
                    and "\r" not in uri
                ):
                    output.append(uri)

            if not output:
                raise HTTPException(
                    status_code=404,
                    detail="No active keys",
                )

            headers = {
                "Cache-Control": "no-store, no-cache, must-revalidate, private",
                "Pragma": "no-cache",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
                "Content-Disposition": 'inline; filename="subscription.txt"',
            }

            if device_check:
                headers["subscription-always-hwid-enable"] = "1"

            return PlainTextResponse(
                "\n".join(output) + "\n",
                media_type="text/plain",
                headers=headers,
            )

    except portalocker.exceptions.LockException:
        raise HTTPException(
            status_code=503,
            detail="Service busy. Retry later.",
        )
