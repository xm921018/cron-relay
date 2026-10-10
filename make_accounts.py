# -*- coding: utf-8 -*-
"""
从运行环境读取加密分片 NB_POOL_1..5，按当前片 (NS / SLICE) 过滤出本片账号，
生成本片专用的 accounts.json，供 signin.py / notes.py 消费。

与 run.py 的分片规则一致：账号 i 归属于片 (i % NS)。每个账号只会被一个片处理，
签到/笔记全局恰好执行一次，不会重复。

角色：signin（每日签到+云贝+云豆） + notes（每 5 天发一条笔记）。
"""
import base64
import json
import os


def load_pool():
    entries = []
    for i in range(1, 6):
        raw = os.environ.get(f"NB_POOL_{i}")
        if not raw:
            continue
        try:
            chunk = json.loads(base64.b64decode(raw).decode("utf-8"))
            if isinstance(chunk, list):
                entries.extend(chunk)
        except Exception:
            pass
    return entries


def main():
    ns = max(1, int(os.environ.get("NS", "1")))
    slice_idx = int(os.environ.get("SLICE", "0"))

    entries = load_pool()
    mine = [e for i, e in enumerate(entries) if i % ns == slice_idx]

    accounts = []
    for e in mine:
        cookie = (e.get("ck") or "").strip()
        if not cookie:
            continue
        accounts.append({
            "name": e.get("name", "unknown"),
            "cookie": cookie,
            "roles": "signin,notes",
            "is_musician": True,   # 互助群成员均为音乐人账号；非音乐人会被接口自动跳过
            "enabled": True,
        })

    with open("accounts.json", "w", encoding="utf-8") as f:
        json.dump({"accounts": accounts}, f, ensure_ascii=False, indent=2)

    print(f"[slice {slice_idx}] 本片签到/笔记账号 {len(accounts)} 个 (号池总数 {len(entries)}, NS={ns})")


if __name__ == "__main__":
    main()
