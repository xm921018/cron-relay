# -*- coding: utf-8 -*-
"""手动删号的通知派发（2026-10-26 新增）。

解决什么问题
------------
控制台删号是在 Cloudflare Worker 里直接删 D1 行完成的，全程没有 Python 进程参与，
而 smtp.qq.com:465 只能从 Actions 侧连 → 以前 12 条手动删除的号主一封邮件都没收到。
run.py 那条「判死→删号→直邮」的链路只覆盖 cookie_invalid，管不到手动删除。

为什么不是「删了就发」
----------------------
最近 12 条 manual 实测：7 条是 hz→dz 迁移、2 条是删了当天重登、只有 3 条真删。
给前 9 位发「账号信息过期，麻烦重新登记」是纯误报（他们的号还在正常听歌）。
所以判定放在 worker（/api/dead_pending）：删除满 12 小时后，看这个 uid/账号名
有没有在任一池又出现——出现就是迁移或重登，不发；没出现才发。

流程
----
worker 每天把「够 12 小时、确认没回来、有邮箱」的记录标成 claimed 交给这里 →
逐条用 notify.notify_relogin()（就是现有的那封模板）发信 →
回调 /api/dead_sent 标 sent；发失败的标 retry 退回 pending，明天再试。

环境变量（GitHub Secret 注入）：WORKER_URL / ASSIGN_PASS / EMAIL_FROM / EMAIL_AUTH_CODE
用法：
  python notify_dead.py           # 正常派发
  python notify_dead.py --dry     # 只查询不发送（不动状态）
"""
import json
import os
import sys

import requests

WORKER = (os.environ.get("WORKER_URL", "") or "https://xx1031.xyz").strip().rstrip("/")
PASS = (os.environ.get("ASSIGN_PASS", "") or os.environ.get("NB_PASS", "")).strip()
WAIT_H = int(os.environ.get("DEAD_WAIT_H", "12") or 12)
DRY = "--dry" in sys.argv


def call(path, payload, timeout=60):
    r = requests.post(WORKER + path, json=payload, timeout=timeout)
    try:
        return r.status_code, r.json()
    except Exception:
        return r.status_code, {"message": (r.text or "")[:200]}


def main():
    if not PASS:
        print("[notify-dead] 缺 ASSIGN_PASS，退出")
        return 1

    code, data = call("/api/dead_pending", {"pass": PASS, "wait_h": WAIT_H, "dry": DRY})
    if code != 200 or not data.get("ok"):
        print(f"[notify-dead] 拉取待发名单失败 HTTP {code}: {data.get('message')}")
        return 1

    todo = data.get("to_send") or []
    skipped = data.get("skipped") or []
    print(f"[notify-dead] 判定窗口 {data.get('wait_h')}h（删除早于 {data.get('cutoff')}）")
    print(f"[notify-dead] 待发 {len(todo)} 个，本轮判定不发 {len(skipped)} 个")
    for s in skipped:
        print(f"   - 不发 {s.get('name') or s.get('uid')}：{s.get('why')}")

    if not todo:
        print("[notify-dead] 没有需要发信的号，结束")
        return 0

    if DRY:
        for t in todo:
            print(f"   [dry] 将发给 {t.get('email')}（{t.get('name') or t.get('uid')}）")
        return 0

    import notify
    if not notify.mail_ready():
        print("[notify-dead] EMAIL_FROM/EMAIL_AUTH_CODE 未配置，跳过（状态保持 claimed，2 小时后自动回退）")
        return 1

    sent, failed = [], []
    for t in todo:
        # 邮件称呼用的是账号名。管理工具手工加的号 name 会被写成 manual:12345678，
        # 直接塞进「你好，manual:12345678：」很难看 —— 去掉前缀，退化成 uid。
        who = str(t.get("name") or t.get("uid") or "")
        if who.startswith("manual:"):
            who = who[7:] or str(t.get("uid") or "")
        ok = False
        try:
            ok = notify.notify_relogin(t.get("email"), "", who)
        except Exception as e:
            print(f"   [{who}] 发信异常：{e}")
        if ok:
            sent.append(t)
            print(f"   [{who}] 已直邮 {t.get('email')}")
        else:
            failed.append(t)
            print(f"   [{who}] 发信失败")

    # 回写状态：成功的标 sent，失败的退回 pending 明天再试
    if sent:
        code, d = call("/api/dead_sent", {"pass": PASS, "result": "sent",
                                          "items": [{"pool": x["pool"], "uid": x["uid"], "removed_at": x["removed_at"]} for x in sent]})
        print(f"[notify-dead] 已标记 sent {len(sent)} 条（HTTP {code} {d.get('updated')}）")
    if failed:
        code, d = call("/api/dead_sent", {"pass": PASS, "result": "retry",
                                          "items": [{"pool": x["pool"], "uid": x["uid"], "removed_at": x["removed_at"]} for x in failed]})
        print(f"[notify-dead] 已退回 pending {len(failed)} 条（HTTP {code} {d.get('updated')}）")

    print(f"[notify-dead] 完成：成功 {len(sent)} / 失败 {len(failed)}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
