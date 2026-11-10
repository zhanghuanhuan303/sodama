#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Jimmy Zhang <62113606+zhanghuanhuan303@users.noreply.github.com>
# Copyright (C) 2026 sodama contributors

"""用 chromedriver（WebDriver/HTTP，无第三方依赖）做配置页端到端点击测试：
填订阅表单 → 点「解析预览」→ 等结果 → 截图。"""
import base64
import json
import subprocess
import sys
import time
import urllib.request

PORT = 9515
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


def type_into(sid, eid, text):
    call("POST", f"/session/{sid}/element/{eid}/value", {"text": text, "value": list(text)})


def click(sid, eid):
    call("POST", f"/session/{sid}/element/{eid}/click", {})


def shot(sid, path):
    r = call("GET", f"/session/{sid}/screenshot")
    with open(path, "wb") as f:
        f.write(base64.b64decode(r["value"]))
    print(f"截图 -> {path}")


def main(url, tag, sub_url, out):
    drv = subprocess.Popen(
        ["chromedriver", f"--port={PORT}", "--log-level=WARNING"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.5)
        caps = {
            "capabilities": {
                "alwaysMatch": {
                    "browserName": "chrome",
                    "goog:chromeOptions": {
                        "binary": "/usr/sbin/chromium",
                        "args": ["--headless=new", "--no-sandbox", "--disable-gpu",
                                 "--hide-scrollbars", "--window-size=1680,1500"],
                    },
                }
            }
        }
        sid = call("POST", "/session", caps)["value"]["sessionId"]
        print("session:", sid)
        call("POST", f"/session/{sid}/url", {"url": url})
        time.sleep(4)

        e_tag = find(sid, "css selector", 'input[placeholder*="名称"]')
        type_into(sid, e_tag, tag)
        e_url = find(sid, "css selector", 'input[placeholder*="订阅链接"]')
        type_into(sid, e_url, sub_url)
        time.sleep(0.5)

        btn = find(sid, "xpath", "//button[contains(., '解析预览')]")
        click(sid, btn)
        print("已点击「解析预览」，等待解析…")
        for _ in range(40):
            time.sleep(1)
            try:
                el = find(sid, "css selector", ".inspect-card")
                if el:
                    break
            except Exception:
                continue
        time.sleep(1.5)
        shot(sid, out)

        # 解析结果摘要（从 DOM 读回，验证渲染内容）
        r = call("POST", f"/session/{sid}/elements", {"using": "css selector", "value": ".chip"})
        chips = []
        for e in r["value"]:
            eid = e["element-6066-11e4-a52e-4f735466cecf"]
            txt = call("GET", f"/session/{sid}/element/{eid}/text")["value"]
            chips.append(txt)
        print("协议 chips:", chips)
        r = call("POST", f"/session/{sid}/elements", {"using": "css selector", "value": ".node-row"})
        print("预览节点行数:", len(r["value"]))
        r = call("POST", f"/session/{sid}/elements", {"using": "css selector", "value": ".banner-msg"})
        if r["value"]:
            eid = r["value"][0]["element-6066-11e4-a52e-4f735466cecf"]
            print("状态条:", call("GET", f"/session/{sid}/element/{eid}/text")["value"])
        call("DELETE", f"/session/{sid}")
    finally:
        drv.terminate()


if __name__ == "__main__":
    main(
        url=sys.argv[1],
        tag=sys.argv[2],
        sub_url=sys.argv[3],
        out=sys.argv[4],
    )
