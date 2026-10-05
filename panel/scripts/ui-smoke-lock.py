#!/usr/bin/env python3
"""用 chromedriver 验证「手动锁定节点」的 UI 路径：点第一行「锁定」→ 校验状态 → 点「恢复自动」。

用法：python3 scripts/ui-smoke-lock.py http://192.0.2.10:8080/
"""
import base64
import json
import subprocess
import sys
import time
import urllib.request

PORT = 9516
BASE = f"http://127.0.0.1:{PORT}"


def call(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.loads(r.read().decode())


def find(sid, using, value):
    r = call("POST", f"/session/{sid}/element", {"using": using, "value": value})
    return r["value"]["element-6066-11e4-a52e-4f735466cecf"]


def find_all(sid, using, value):
    r = call("POST", f"/session/{sid}/elements", {"using": using, "value": value})
    return [e["element-6066-11e4-a52e-4f735466cecf"] for e in r["value"]]


def text_of(sid, eid):
    return call("GET", f"/session/{sid}/element/{eid}/text")["value"]


def click(sid, eid):
    call("POST", f"/session/{sid}/element/{eid}/click", {})


def shot(sid, path):
    r = call("GET", f"/session/{sid}/screenshot")
    open(path, "wb").write(base64.b64decode(r["value"]))
    print(f"截图 -> {path}")


def main(url, out):
    drv = subprocess.Popen(
        ["chromedriver", f"--port={PORT}", "--log-level=WARNING"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.5)
        sid = call("POST", "/session", {"capabilities": {"alwaysMatch": {
            "browserName": "chrome",
            "goog:chromeOptions": {
                "binary": "/usr/sbin/chromium",
                "args": ["--headless=new", "--no-sandbox", "--disable-gpu",
                         "--hide-scrollbars", "--window-size=1680,1300"],
            },
        }}})["value"]["sessionId"]
        call("POST", f"/session/{sid}/url", {"url": url})
        time.sleep(6)

        # 第一行「锁定」按钮（xpath 里锁定与解锁同排，取第一个锁定）
        btns = find_all(sid, "xpath", "//table//button[normalize-space(.)='锁定']")
        assert btns, "找不到「锁定」按钮"
        print(f"锁定按钮数: {len(btns)}")
        # 该行节点名
        row_name = text_of(sid, find(sid, "xpath", "//table//button[normalize-space(.)='锁定']/ancestor::tr[1]/td[2]"))
        print(f"第一行节点: {row_name!r}")
        click(sid, btns[0])
        time.sleep(7)

        # 校验：标题栏出现「已锁定」chip 且行内出现「使用中」
        chips = [text_of(sid, e) for e in find_all(sid, "css selector", ".chip-use")]
        print("chip-use:", chips)
        shot(sid, out)

        # 恢复自动
        try:
            auto = find(sid, "xpath", "//button[normalize-space(.)='恢复自动']")
            click(sid, auto)
            time.sleep(7)
            chips2 = [text_of(sid, e) for e in find_all(sid, "css selector", ".chip-use")]
            print("恢复后 chip-use:", chips2)
        except Exception as e:
            print("恢复自动按钮不可用:", e)

        call("DELETE", f"/session/{sid}")
    finally:
        drv.terminate()


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
