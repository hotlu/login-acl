#!/usr/bin/env python3

import json
import os
import sys
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import unquote

import requests
from PIL import Image, ImageDraw, ImageFont


BASE_URL = os.getenv("ACL_BASE_URL", "https://dash.aclclouds.com").rstrip("/")
SERVER_ID = os.getenv("ACL_SERVER_ID", "").strip()
COOKIE_STRING = os.getenv("ACL_COOKIE", "").strip()
ACCOUNT_LOGIN = os.getenv("ACL_ACCOUNT_LOGIN", "").strip()
ACCOUNT_PASSWORD = os.getenv("ACL_ACCOUNT_PASSWORD", "").strip()
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "").strip()
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "").strip()
ARTIFACT_DIR = Path(os.getenv("ACL_ARTIFACT_DIR", "artifacts")).resolve()
LOG_PATH = ARTIFACT_DIR / "renew.log"
SCREENSHOT_PATH = ARTIFACT_DIR / "failure.png"
STATE_PATH = ARTIFACT_DIR / "state.json"
TIMEOUT = 25


class StepError(Exception):
    def __init__(self, step: str, message: str, payload: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.step = step
        self.message = message
        self.payload = payload or {}


@dataclass
class ServerInfo:
    server_id: str
    name: str
    expires_at: Optional[str]
    remaining: str
    can_renew: bool
    is_free: bool
    plan_name: str
    service_type: str


def ensure_dirs() -> None:
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)


def log(line: str) -> None:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    text = f"[{timestamp}] {line}"
    print(text, flush=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(text + "\n")


def save_state(data: Dict[str, Any]) -> None:
    with STATE_PATH.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)


def build_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "User-Agent": "aclclouds-renew-check/1.0",
            "X-Requested-With": "XMLHttpRequest",
        }
    )
    return session


def apply_cookie_string(session: requests.Session, cookie_string: str) -> None:
    for piece in cookie_string.split(";"):
        if "=" not in piece:
            continue
        key, value = piece.strip().split("=", 1)
        session.cookies.set(key, value, domain="dash.aclclouds.com")


def update_xsrf_header(session: requests.Session) -> None:
    token = session.cookies.get("XSRF-TOKEN")
    if token:
        session.headers["X-XSRF-TOKEN"] = unquote(token)


def request_json(
    session: requests.Session,
    method: str,
    url: str,
    *,
    expected: Optional[tuple[int, ...]] = None,
    allow_error_json: bool = False,
    **kwargs: Any,
) -> Any:
    response = session.request(method, url, timeout=TIMEOUT, **kwargs)
    update_xsrf_header(session)
    content_type = response.headers.get("content-type", "")
    body: Any
    if "application/json" in content_type:
        body = response.json()
    else:
        body = response.text
    if expected and response.status_code not in expected:
        if allow_error_json:
            return response.status_code, body
        raise StepError(
            "http_request",
            f"Unexpected status {response.status_code} for {method} {url}",
            {"status": response.status_code, "body": body},
        )
    return body


def login_with_password(session: requests.Session) -> None:
    if not ACCOUNT_LOGIN or not ACCOUNT_PASSWORD:
        raise StepError(
            "auth",
            "Cookie expired and password login is unavailable. Set ACL_ACCOUNT_LOGIN and ACL_ACCOUNT_PASSWORD.",
        )

    log("Cookie may be invalid. Trying password login.")
    login_page = session.get(f"{BASE_URL}/auth/login", timeout=TIMEOUT)
    update_xsrf_header(session)
    if login_page.status_code != 200:
        raise StepError("auth", "Unable to load login page.", {"status": login_page.status_code})

    payload = {
        "user": ACCOUNT_LOGIN,
        "email": ACCOUNT_LOGIN,
        "password": ACCOUNT_PASSWORD,
    }
    response = session.post(
        f"{BASE_URL}/auth/login",
        timeout=TIMEOUT,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
        },
        data=payload,
        allow_redirects=False,
    )
    update_xsrf_header(session)

    if response.status_code not in (200, 204, 302):
        raise StepError(
            "auth",
            "Password login failed.",
            {"status": response.status_code, "body": response.text[:1000]},
        )

    log("Password login succeeded.")


def fetch_server(session: requests.Session) -> ServerInfo:
    log(f"Fetching server info for {SERVER_ID}.")
    status, body = request_json(
        session,
        "GET",
        f"{BASE_URL}/api/client/servers/{SERVER_ID}",
        allow_error_json=True,
    )

    if status in (401, 403, 419):
        login_with_password(session)
        body = request_json(session, "GET", f"{BASE_URL}/api/client/servers/{SERVER_ID}", expected=(200,))
    elif status != 200:
        raise StepError("fetch_server", "Server info request failed.", {"status": status, "body": body})

    attrs = body["attributes"]
    expires_at = attrs.get("expires_at")
    can_renew = bool(attrs.get("can_renew"))
    return ServerInfo(
        server_id=attrs.get("identifier", SERVER_ID),
        name=attrs.get("name", SERVER_ID),
        expires_at=expires_at,
        remaining=remaining_text(expires_at),
        can_renew=can_renew,
        is_free=bool(attrs.get("is_free")),
        plan_name=(attrs.get("plan") or {}).get("name", "unknown"),
        service_type=attrs.get("service_type", "unknown"),
    )


def remaining_text(expires_at: Optional[str]) -> str:
    if not expires_at:
        return "unlimited"
    try:
        target = datetime.fromisoformat(expires_at)
        now = datetime.now(target.tzinfo or timezone.utc)
        delta = target - now
        total_seconds = int(delta.total_seconds())
        sign = "-" if total_seconds < 0 else ""
        total_seconds = abs(total_seconds)
        days, rem = divmod(total_seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours or days:
            parts.append(f"{hours}h")
        parts.append(f"{minutes}m")
        return sign + " ".join(parts)
    except Exception:
        return expires_at


def renew_server(session: requests.Session) -> Dict[str, Any]:
    log(f"Attempting renewal for {SERVER_ID}.")
    status, body = request_json(
        session,
        "POST",
        f"{BASE_URL}/api/client/servers/{SERVER_ID}/upgrade/renew",
        allow_error_json=True,
        json={},
    )

    if status in (401, 403, 419):
        login_with_password(session)
        body = request_json(
            session,
            "POST",
            f"{BASE_URL}/api/client/servers/{SERVER_ID}/upgrade/renew",
            expected=(200, 201, 400),
            json={},
        )
        status = 200 if isinstance(body, dict) and "error" not in body else 400

    if status in (200, 201):
        return body if isinstance(body, dict) else {"raw": body}

    if isinstance(body, dict) and body.get("error") == "renewal_not_available":
        hours = body.get("hours_remaining")
        raise StepError("not_ready", f"Renewal not available yet. Hours remaining: {hours}.", body)

    if isinstance(body, dict) and body.get("requires_payment"):
        raise StepError("renew", "Renewal requires payment.", body)

    raise StepError("renew", "Renewal request failed.", {"status": status, "body": body})


def send_telegram_message(text: str) -> None:
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log("Telegram secrets are missing. Skip Telegram text notification.")
        return
    requests.post(
        f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
        timeout=TIMEOUT,
        data={"chat_id": TG_CHAT_ID, "text": text},
    ).raise_for_status()


def send_telegram_document(path: Path, caption: str) -> None:
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log("Telegram secrets are missing. Skip Telegram document notification.")
        return
    with path.open("rb") as fh:
        requests.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendDocument",
            timeout=TIMEOUT,
            data={"chat_id": TG_CHAT_ID, "caption": caption[:1024]},
            files={"document": fh},
        ).raise_for_status()


def send_telegram_photo(path: Path, caption: str) -> None:
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        log("Telegram secrets are missing. Skip Telegram photo notification.")
        return
    with path.open("rb") as fh:
        requests.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendPhoto",
            timeout=TIMEOUT,
            data={"chat_id": TG_CHAT_ID, "caption": caption[:1024]},
            files={"photo": fh},
        ).raise_for_status()


def create_failure_image(title: str, detail: str, context: Dict[str, Any]) -> None:
    width, height = 1500, 900
    image = Image.new("RGB", (width, height), color=(16, 18, 24))
    draw = ImageDraw.Draw(image)
    font_title = ImageFont.load_default()
    font_body = ImageFont.load_default()

    y = 40
    draw.rectangle((30, 30, width - 30, height - 30), outline=(210, 68, 68), width=3)
    draw.text((50, y), "ACLClouds Renewal Failure", fill=(255, 110, 110), font=font_title)
    y += 40
    draw.text((50, y), f"Step: {title}", fill=(255, 255, 255), font=font_body)
    y += 25
    draw.text((50, y), f"Detail: {detail}", fill=(220, 220, 220), font=font_body)
    y += 40

    lines = [
        f"Server ID: {SERVER_ID or 'missing'}",
        f"Base URL: {BASE_URL}",
        f"UTC Time: {datetime.now(timezone.utc).isoformat()}",
    ]
    for key, value in context.items():
        lines.append(f"{key}: {value}")

    for line in lines:
        for chunk in wrap_text(line, 160):
            draw.text((50, y), chunk, fill=(210, 210, 210), font=font_body)
            y += 18

    y += 12
    draw.text((50, y), "Recent log tail:", fill=(255, 255, 255), font=font_body)
    y += 24
    tail = LOG_PATH.read_text(encoding="utf-8")[-5000:] if LOG_PATH.exists() else ""
    for raw in tail.splitlines()[-25:]:
        for chunk in wrap_text(raw, 160):
            draw.text((50, y), chunk, fill=(180, 220, 255), font=font_body)
            y += 18
            if y > height - 60:
                break
        if y > height - 60:
            break

    image.save(SCREENSHOT_PATH)


def wrap_text(text: str, width: int) -> list[str]:
    if len(text) <= width:
        return [text]
    out = []
    while text:
        out.append(text[:width])
        text = text[width:]
    return out


def notify_success(info: ServerInfo, renew_result: Dict[str, Any]) -> None:
    message = "\n".join(
        [
            "ACLClouds renewal succeeded.",
            f"Server: {info.name}",
            f"Server ID: {info.server_id}",
            f"Plan: {info.plan_name}",
            f"Type: {info.service_type}",
            f"Expires At: {info.expires_at or 'unlimited'}",
            f"Remaining: {info.remaining}",
            f"Response: {json.dumps(renew_result, ensure_ascii=False)[:1200]}",
        ]
    )
    send_telegram_message(message)


def notify_failure(step: str, detail: str, payload: Optional[Dict[str, Any]] = None) -> None:
    payload = payload or {}
    create_failure_image(step, detail, payload)
    send_telegram_photo(SCREENSHOT_PATH, f"ACLClouds renewal failed\nStep: {step}\nDetail: {detail}")
    send_telegram_document(LOG_PATH, f"renew.log - failed at {step}")
    send_telegram_message(
        "\n".join(
            [
                "ACLClouds renewal failed.",
                f"Step: {step}",
                f"Detail: {detail}",
                f"Payload: {json.dumps(payload, ensure_ascii=False)[:1500]}",
            ]
        )
    )


def validate_env() -> None:
    missing = []
    if not SERVER_ID:
        missing.append("ACL_SERVER_ID")
    if not COOKIE_STRING:
        missing.append("ACL_COOKIE")
    if not TG_CHAT_ID:
        missing.append("TG_CHAT_ID")
    if not TG_BOT_TOKEN:
        missing.append("TG_BOT_TOKEN")
    if missing:
        raise StepError("config", f"Missing required environment variables: {', '.join(missing)}")


def run() -> int:
    ensure_dirs()
    validate_env()
    session = build_session()
    apply_cookie_string(session, COOKIE_STRING)
    update_xsrf_header(session)

    info = fetch_server(session)
    save_state(
        {
            "server": info.__dict__,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    log(
        f"Server fetched. name={info.name} expires_at={info.expires_at} remaining={info.remaining} can_renew={info.can_renew}"
    )

    if not info.can_renew:
        log(f"Renewal not open yet. Remaining time: {info.remaining}.")
        return 0

    result = renew_server(session)
    updated = fetch_server(session)
    log(f"Renewal succeeded. New remaining time: {updated.remaining}.")
    notify_success(updated, result)
    return 0


def main() -> int:
    try:
        return run()
    except StepError as exc:
        if exc.step == "not_ready":
            log(exc.message)
            return 0
        log(f"Failure at step={exc.step}: {exc.message}")
        if exc.payload:
            log(json.dumps(exc.payload, ensure_ascii=False, indent=2))
        notify_failure(exc.step, exc.message, exc.payload)
        return 1
    except Exception as exc:
        detail = f"{exc.__class__.__name__}: {exc}"
        tb = traceback.format_exc()
        log(detail)
        log(tb)
        notify_failure("unexpected", detail, {"traceback": tb[-3000:]})
        return 1


if __name__ == "__main__":
    sys.exit(main())
