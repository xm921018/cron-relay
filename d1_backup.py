# -*- coding: utf-8 -*-
"""D1 账号池自动备份（2026-10-22 新增）。

背景：2026-10-22 起账号池的权威数据（accounts / snapshots / kv_misc）只在 Cloudflare D1 里，
KV 只是双写备份，GitHub Secrets 分片已降级为只读回退。D1 是单点，必须有独立备份。

做三件事：
  1) 通过 Cloudflare D1 HTTP API 导出 accounts / snapshots / kv_misc 三张表为 JSON；
  2) gzip 后用 openssl aes-256-cbc 加密（备份里有明文 CK，绝不能以明文落在 public 仓库）；
  3) 输出到指定目录，由工作流提交进仓库 backup/ 并上传 artifact。

环境变量：
  CF_TOKEN        Cloudflare API 令牌（需 D1 读权限）
  CF_ACCOUNT_ID   账户 ID
  D1_UUID         D1 数据库 uuid（不填用默认 netpool）
  BACKUP_PASS     加密口令（GitHub Secret；丢了就解不开，务必与本地保管的一致）
  BACKUP_DIR      输出目录，默认 backup

用法：
  python d1_backup.py                # 备份到今天
  python d1_backup.py --no-encrypt   # 本地排查用，输出明文 json.gz（慎用）
"""
import datetime
import gzip
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

ACC = os.environ.get("CF_ACCOUNT_ID", "").strip() or "c60450bfb7f2c2becfd744ba2508a4f2"
D1_UUID = (os.environ.get("D1_UUID", "").strip()
           or "54f742fc-5f56-4723-a7a0-a832953d38c7")
TOK = (os.environ.get("CF_TOKEN", "") or "").strip()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"
OUT_DIR = os.environ.get("BACKUP_DIR", "backup").strip() or "backup"

# 账号池全字段（含 ck，恢复时必需）
# 2026-10-27：加 agent / plan（客服 + 套餐）。少备这两列的话，恢复一次客服归属就全没了。
COLS = ["pool", "uid", "name", "song", "ck", "added", "exp", "no_listen",
        "email", "updated_at", "note", "agent", "plan"]
PAGE = 200          # 单次查询行数，避免 D1 HTTP 响应过大被截断
SNAP_DAYS = 60      # 快照只备最近 60 天（控制台最多回看 90 天，够用）


def api(sql, params=None):
    url = f"https://api.cloudflare.com/client/v4/accounts/{ACC}/d1/database/{D1_UUID}/query"
    body = {"sql": sql}
    if params:
        body["params"] = params
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": "Bearer " + TOK, "User-Agent": UA,
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            d = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"D1 查询失败 HTTP {e.code}: {e.read().decode()[:600]}")
    if not d.get("success"):
        raise SystemExit(f"D1 查询失败: {json.dumps(d.get('errors'), ensure_ascii=False)[:600]}")
    res = d.get("result") or []
    return (res[0].get("results") or []) if res else []


def dump_accounts():
    rows = []
    off = 0
    while True:
        part = api(f"SELECT {','.join(COLS)} FROM accounts ORDER BY pool, uid LIMIT ? OFFSET ?",
                   [PAGE, off])
        rows.extend(part)
        if len(part) < PAGE:
            break
        off += PAGE
    return rows


def dump_snapshots():
    since = (datetime.date.today() - datetime.timedelta(days=SNAP_DAYS)).isoformat()
    rows = []
    off = 0
    while True:
        part = api("SELECT day,pool,uid,name,rate,rpc30,missions,dur,at,cnt "
                   "FROM snapshots WHERE day >= ? ORDER BY day, pool, uid LIMIT ? OFFSET ?",
                   [since, PAGE, off])
        rows.extend(part)
        if len(part) < PAGE:
            break
        off += PAGE
    return rows


def dump_misc():
    try:
        return api("SELECT k,v,updated_at FROM kv_misc")
    except SystemExit:
        return []


def dump_dead():
    """失效账号流水（含清理原因/时间）——恢复时能看出哪些号是确认死号、不要往回捞。"""
    try:
        return api("SELECT id,pool,uid,name,reason,at FROM dead_log ORDER BY id DESC LIMIT 2000")
    except SystemExit:
        return []


def main():
    if not TOK:
        raise SystemExit("缺 CF_TOKEN")
    today = (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).date().isoformat()
    accounts, snapshots, misc, dead = (dump_accounts(), dump_snapshots(),
                                       dump_misc(), dump_dead())
    by_pool = {}
    for r in accounts:
        by_pool[r.get("pool")] = by_pool.get(r.get("pool"), 0) + 1
    payload = {
        "meta": {"date": today, "exported_at": datetime.datetime.utcnow().isoformat() + "Z",
                 "d1_uuid": D1_UUID, "accounts": len(accounts),
                 "by_pool": by_pool, "snapshots": len(snapshots), "misc": len(misc), "dead_log": len(dead),
                 "snap_days": SNAP_DAYS},
        "accounts": accounts,
        "snapshots": snapshots,
        "kv_misc": misc,
        "dead_log": dead,
    }
    os.makedirs(OUT_DIR, exist_ok=True)
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    gz_path = os.path.join(OUT_DIR, f"d1-{today}.json.gz")
    with gzip.open(gz_path, "wb", compresslevel=9) as f:
        f.write(raw)
    print(f"[backup] 导出 {len(accounts)} 个号（{by_pool}）、{len(snapshots)} 条快照、"
          f"{len(misc)} 条 misc、{len(dead)} 条死号流水 → {os.path.getsize(gz_path)/1024:.0f}KB")

    if "--no-encrypt" in sys.argv:
        print("[backup] 明文模式（仅排查用）：", gz_path)
        # 2026-10-29：删掉 ::set-output（GitHub 2023 年已移除，纯 no-op 死代码）
        return

    pwd = (os.environ.get("BACKUP_PASS") or "").strip()
    if not pwd:
        # 没有口令就不落地明文：直接失败，让工作流报警，避免 CK 明文进仓库
        os.remove(gz_path)
        raise SystemExit("缺 BACKUP_PASS：拒绝以明文形式保存含 CK 的备份")
    enc_path = gz_path + ".enc"
    subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-iter", "200000", "-salt",
         "-in", gz_path, "-out", enc_path, "-pass", "env:BACKUP_PASS"],
        check=True, env={**os.environ, "BACKUP_PASS": pwd})
    os.remove(gz_path)
    print(f"[backup] 已加密 → {enc_path}（{os.path.getsize(enc_path)/1024:.0f}KB）")


if __name__ == "__main__":
    main()
