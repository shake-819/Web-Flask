from flask import Flask, request, Response, session
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse, quote
import chardet
import mimetypes
import uuid
import urllib3
import re
import concurrent.futures
import json  # ← 追加

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.secret_key = "supersecret"  # 本番ではos.urandom(32)などに変更推奨
sessions = {}

# FlareSolverr設定（ここをあなたのRender URLに合わせる）
FLARESOLVERR_URL = "https://flaresolverr-latest-nrsp.onrender.com/v1"
FLARESOLVERR_TIMEOUT = 90  # 秒（Turnstile系は長めに）

# ----------------- ヘルパ -----------------
def get_user_session():
    uid = session.get("uid")
    if not uid:
        uid = str(uuid.uuid4())
        session["uid"] = uid
    if uid not in sessions:
        s = requests.Session()
        s.headers.update({
            "User-Agent": "Mozilla/5.0",
            "Accept": "*/*",
            "Accept-Language": "ja,en-US;q=0.9",
            "Connection": "keep-alive",
        })
        adapter = requests.adapters.HTTPAdapter(pool_connections=20,
                                                pool_maxsize=50,
                                                max_retries=2)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        sessions[uid] = s
    return sessions[uid]

def detect_encoding(resp):
    ct = resp.headers.get("Content-Type", "")
    if "charset=" in ct and resp.encoding:
        return resp.encoding
    enc = chardet.detect(resp.content)["encoding"]
    return enc or "utf-8"

SCHEME_FIX_RE = re.compile(r'^(https?):/{3,}', re.IGNORECASE)
MULTISLASH_RE = re.compile(r'(?<!:)/{2,}')
WS_RE = re.compile(r'\s+')

def normalize_input_url(u: str) -> str:
    if not u:
        return ""
    u = u.strip()
    u = WS_RE.sub(" ", u).strip().strip('\'"')
    if u.startswith("//"):
        u = "https:" + u
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', u):
        u = "https://" + u.lstrip("/")
    u = SCHEME_FIX_RE.sub(r'\1://', u)
    pu = urlparse(u)
    fixed = pu.scheme + "://" + pu.netloc + MULTISLASH_RE.sub("/", pu.path)
    if pu.params:
        fixed += ";" + pu.params
    if pu.query:
        fixed += "?" + pu.query
    if pu.fragment:
        fixed += "#" + pu.fragment
    return fixed

def abs_url(base, val):
    if not val or isinstance(val, bytes) or str(val).startswith("data:"):
        return val
    v = str(val).strip().strip('"\'')
    if v.startswith("//"):
        v = "https:" + v
    if re.match(r'^(javascript:|mailto:|tel:|#)', v, re.IGNORECASE):
        return v
    return urljoin(base, v)

def make_proxy_url(url, base):
    if not url:
        return url
    absu = abs_url(base, url)
    if not absu or str(absu).startswith("data:"):
        return absu
    if absu.startswith("/go?url=") or "/go?url=" in absu:
        return absu
    return "/go?url=" + quote(absu, safe='')

def stream_response(origin_resp):
    headers = {}
    for h in [
        "Content-Type", "Content-Length", "Content-Range", "Accept-Ranges",
        "ETag", "Last-Modified", "Cache-Control", "Content-Disposition"
    ]:
        if h in origin_resp.headers:
            headers[h] = origin_resp.headers[h]
    if "Cache-Control" not in headers:
        if headers.get("Content-Type", "").startswith("image/"):
            headers["Cache-Control"] = "public, max-age=86400"
        else:
            headers["Cache-Control"] = "no-transform, max-age=0"

    def generate():
        for chunk in origin_resp.iter_content(chunk_size=64 * 1024):
            if chunk:
                yield chunk

    return Response(generate(),
                    status=origin_resp.status_code,
                    headers=headers)

# ----------------- FlareSolverr経由でHTMLを取得 -----------------
def get_via_flaresolverr(target_url, user_session):
    payload = {
        "cmd": "request.get",
        "url": target_url,
        "maxTimeout": FLARESOLVERR_TIMEOUT * 1000,  # ミリ秒
        "returnOnlyCookies": False,
    }
    try:
        fs_resp = requests.post(FLARESOLVERR_URL, json=payload, timeout=FLARESOLVERR_TIMEOUT + 10)
        fs_resp.raise_for_status()
        solution = fs_resp.json()

        if solution.get("status") != "ok":
            raise Exception(f"FlareSolverr failed: {solution.get('message', '不明なエラー')}")

        html = solution["solution"]["response"]
        cookies = solution["solution"].get("cookies", [])

        # cookiesをuser_sessionに反映（.ts / m3u8などで必要）
        parsed = urlparse(target_url)
        domain = parsed.netloc
        for cookie in cookies:
            user_session.cookies.set(
                cookie.get("name"),
                cookie.get("value"),
                domain=domain,
                path=cookie.get("path", "/"),
                secure=cookie.get("secure", False),
                expires=cookie.get("expiry", None)
            )

        status_code = solution["solution"].get("status", 200)
        return html, status_code

    except Exception as e:
        return f"FlareSolverrエラー: {str(e)}", 503

# ----------------- HTML 書き換え高速化 -----------------
def rewrite_html_urls(soup, base_url):
    tags_attrs = {
        "img": ["src", "data-src", "data-lazy-src", "data-original", "data-image", "data-file", "data-thumb", "srcset", "data-srcset"],
        "iframe": ["src"],
        "form": ["action"]
    }

    def process_tag(t, tag, attr_list):
        if tag == "img":
            for lazy_attr in ["data-src", "data-lazy-src", "data-original", "data-image", "data-file", "data-thumb"]:
                if t.has_attr(lazy_attr):
                    t["src"] = make_proxy_url(t.get(lazy_attr), base_url)
            if t.has_attr("loading"):
                del t["loading"]

        if t.has_attr("srcset") or t.has_attr("data-srcset"):
            attr_name = "srcset" if t.has_attr("srcset") else "data-srcset"
            srcset_val = t.get(attr_name)
            if srcset_val:
                new_srcset = []
                for item in srcset_val.split(","):
                    parts = item.strip().split()
                    if parts:
                        parts[0] = make_proxy_url(parts[0], base_url)
                        new_srcset.append(" ".join(parts))
                t[attr_name] = ", ".join(new_srcset)

        for attr in attr_list:
            if t.has_attr(attr):
                t[attr] = make_proxy_url(t.get(attr), base_url)

        if tag == "form":
            if not t.get("method"):
                t["method"] = "GET"
            act = t.get("action") or base_url
            t["action"] = "/go"
            hidden = soup.new_tag("input", attrs={"type": "hidden", "name": "url", "value": make_proxy_url(act, base_url)})
            t.append(hidden)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for tag, attr_list in tags_attrs.items():
            for t in soup.find_all(tag):
                futures.append(executor.submit(process_tag, t, tag, attr_list))
        concurrent.futures.wait(futures)

    # style内のurl()書き換え
    bg_url_pattern = re.compile(r'url\(([^)]+)\)')
    for elem in soup.find_all(style=True):
        style_val = elem.get("style", "")
        def repl(m):
            raw = m.group(1).strip("\"'")
            return f"url({make_proxy_url(raw, base_url)})"
        elem["style"] = bg_url_pattern.sub(repl, style_val)

    # img最大化スタイル
    style_tag = soup.new_tag("style")
    style_tag.string = "img{max-width:100%;height:auto;}"
    if soup.head:
        soup.head.append(style_tag)
    else:
        soup.insert(0, style_tag)

    return soup

# ----------------- ルータ -----------------
REAL_CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/121.0.0.0 Safari/537.36"
)

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST", "HEAD"])
def proxy(path):
    if not path:
        return '''
        <h2>URLを入力してください</h2>
        <form action="/go" method="get" style="margin:1rem 0;">
          <input name="url" placeholder="https://example.com" size="50" />
          <button type="submit">表示</button>
        </form>
        '''

    parsed_path = urlparse(path)
    if not parsed_path.scheme and not parsed_path.netloc:
        path = path.lstrip("/")
        path = "https://momon-ga.com/" + path
        parsed_path = urlparse(path)
    if not parsed_path.scheme:
        parsed_path = parsed_path._replace(scheme="https")
    target_url = urlunparse(parsed_path)

    user_session = get_user_session()
    headers = {
        "User-Agent": REAL_CHROME_UA,
        "Referer": target_url,
        "Accept": request.headers.get("Accept", "*/*"),
        "Accept-Language": "ja-JP,ja;q=0.9,en-US;q=0.8",
        "Upgrade-Insecure-Requests": "1",
    }

    try:
        # HTMLの場合のみFlareSolverrを使う
        content_type_guess = mimetypes.guess_type(target_url)[0] or ""
        if "html" in content_type_guess.lower() or target_url.lower().endswith((".html", ".htm", "/")):
            html, status_code = get_via_flaresolverr(target_url, user_session)
            if isinstance(html, str) and "FlareSolverrエラー" in html:
                return html, status_code

            soup = BeautifulSoup(html, "html.parser")

            # lazyload対応
            for img in soup.find_all("img"):
                for attr in ["data-src", "data-original", "data-lazy", "data-url", "data-img"]:
                    if img.get(attr) and not img.get("src"):
                        img["src"] = img.get(attr)
                if img.get("srcset"):
                    del img["srcset"]
                if img.get("loading"):
                    del img["loading"]

            # video/source/poster
            for video in soup.find_all("video"):
                if video.get("src"):
                    video["src"] = make_proxy_url(abs_url(target_url, video["src"]), target_url)
                if video.get("poster"):
                    video["poster"] = make_proxy_url(abs_url(target_url, video["poster"]), target_url)

            for source in soup.find_all("source"):
                if source.get("src"):
                    source["src"] = make_proxy_url(abs_url(target_url, source["src"]), target_url)

            # CSSインライン
            for link in soup.find_all("link", rel=lambda v: v and "stylesheet" in v):
                href = link.get("href")
                if not href:
                    continue
                css_url = abs_url(target_url, href)
                try:
                    css_resp = user_session.get(css_url, headers=headers, timeout=10, verify=False)
                    css_text = css_resp.content.decode(detect_encoding(css_resp), errors="replace")
                    style = soup.new_tag("style")
                    style.string = css_text
                    link.replace_with(style)
                except:
                    link["href"] = make_proxy_url(css_url, target_url)

            soup = rewrite_html_urls(soup, target_url)
            return Response(str(soup), content_type="text/html; charset=utf-8")

        # m3u8処理（cookiesがFlareSolverrから入ってるので通る可能性↑）
        resp = user_session.get(target_url, headers=headers, timeout=20, verify=False, allow_redirects=True)
        content_type = resp.headers.get("Content-Type", "") or ""
        if (
            "application/vnd.apple.mpegurl" in content_type.lower()
            or target_url.lower().endswith(".m3u8")
            or ".m3u8?" in target_url.lower()
        ):
            text = resp.content.decode("utf-8", errors="replace")
            lines = []
            for line in text.splitlines():
                line = line.rstrip()
                if not line or line.startswith("#"):
                    lines.append(line)
                    continue
                if line.startswith(("http://", "https://")):
                    proxied = make_proxy_url(line, target_url)
                else:
                    full_url = urljoin(target_url, line)
                    proxied = make_proxy_url(full_url, target_url)
                lines.append(proxied)
            return Response("\n".join(lines) + "\n", content_type="application/vnd.apple.mpegurl; charset=utf-8")

        # その他のリソース（動画含む）
        video_exts = (".mp4", ".m4s", ".ts", ".m3u8", ".key", ".vtt", ".webm", ".m4a")
        resource_headers = {
            "User-Agent": REAL_CHROME_UA,
            "Accept": "*/*",
            "Accept-Language": "ja-JP,ja;q=0.9,en-US;q=0.8",
            "Referer": f"{parsed_path.scheme}://{parsed_path.netloc}/",
            "Origin": f"{parsed_path.scheme}://{parsed_path.netloc}",
        }
        if "Range" in request.headers:
            resource_headers["Range"] = request.headers["Range"]
        if request.headers.get("Cookie"):
            resource_headers["Cookie"] = request.headers["Cookie"]

        method = request.method if request.method != "HEAD" else "GET"
        r = user_session.request(
            method, target_url,
            headers=resource_headers,
            stream=True,
            timeout=30,
            verify=False,
            allow_redirects=True,
        )

        excluded_headers = {"content-encoding", "transfer-encoding", "connection", "content-security-policy", "strict-transport-security"}
        response_headers = [(k, v) for k, v in r.headers.items() if k.lower() not in excluded_headers]

        if not any(h[0].lower() == "content-type" for h in response_headers):
            guessed = mimetypes.guess_type(target_url)[0]
            if guessed:
                response_headers.append(("Content-Type", guessed))

        def generate():
            for chunk in r.iter_content(chunk_size=8192):
                if chunk:
                    yield chunk

        return Response(generate(), status=r.status_code, headers=response_headers, direct_passthrough=True)

    except Exception as e:
        return f"<h1>エラー</h1><pre>{str(e)}</pre>", 500

@app.route("/go")
def redirect_form():
    raw = request.args.get("url", "")
    if not raw:
        return "URLが空です"
    url = normalize_input_url(raw)
    return proxy(url)

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 3000))
    app.run(host="0.0.0.0", port=port, debug=False)
