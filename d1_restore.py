# -*- coding: utf-8 -*-
"""D1 账号池恢复（配合 d1_backup.py / d1-backup.yml 使用）。

用途：D1 被误删、写坏、或换账号重建时，把某一天的加密备份灌回去。

安全约束：
  - 只写 accounts 表（唯一不可再生的数据）；
    2026-10-29：INSERT OR REPLACE 改成 INSERT ... ON CONFLICT(pool,uid) DO UPDATE，
    并且只覆盖「备份里确实存在」的列 —— 否则将来给 accounts 加列之后，用旧备份恢复一次
    就会把新列全清空（OR REPLACE = 整行替换，缺列即 NULL）；
  - 默认 dry-run，只打印将要写入多少条，加 --write 才真的写；
  - 不会删除库里现有的号：备份里有、库里也多出来的号会留着（宁可多不可少）。

环境变量：CF_TOKEN / CF_ACCOUNT_ID / D1_UUID / BACKUP_PASS

用法：
  python d1_restore.py backup/d1-2026-10-26.json.gz.enc            # 预演
  python d1_restore.py backup/d1-2026-10-26.json.gz.enc --write    # 真写
"""
import gzip
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

ACC = os.environ.get("CF_ACCOUNT_ID", "").strip() or "c60450bfb7f2c2becfd744ba2508a4f2"
D1_UUID = (os.environ.get("D1_UUID", "").strip() or "54f742fc-5f56-4723-a7a0-a832953d38c7")
TOK = (os.environ.get("CF_TOKEN", "") or "").strip()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"
COLS = ["pool", "uid", "name", "song", "ck", "added", "exp", "no_listen",
        "email", "updated_at", "note", "agent", "plan"]
BATCH = 7   # 上限值：7 行 × 13 列 = 91 个绑定参数，低于 D1 单查询 100 参数上限
            # 实际每批行数按「列数」重算（见 main），备份列少时可以更宽


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
        raise SystemExit(f"D1 失败 HTTP {e.code}: {e.read().decode()[:500]}")
    if not d.get("success"):
        raise SystemExit(f"D1 失败: {json.dumps(d.get('errors'), ensure_ascii=False)[:500]}")
    return d


def load_payload(path):
    pwd = (os.environ.get("BACKUP_PASS") or "").strip()
    if path.endswith(".enc"):
        if not pwd:
            raise SystemExit("缺 BACKUP_PASS，无法解密备份")
        with tempfile.TemporaryDirectory() as td:
            gz = os.path.join(td, "b.json.gz")
            subprocess.run(["openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2", "-iter", "200000",
                            "-in", path, "-out", gz, "-pass", "env:BACKUP_PASS"],
                           check=True, env={**os.environ, "BACKUP_PASS": pwd})
            with gzip.open(gz, "rb") as f:
                return json.loads(f.read().decode("utf-8"))
    with gzip.open(path, "rb") as f:
        return json.loads(f.read().decode("utf-8"))


def main():
    if len(sys.argv) < 2:
        raise SystemExit("用法: python d1_restore.py <备份文件> [--write]")
    path = sys.argv[1]
    write = "--write" in sys.argv
    if not TOK:
        raise SystemExit("缺 CF_TOKEN")
    if not os.path.exists(path):
        raise SystemExit(f"文件不存在: {path}")
    data = load_payload(path)
    accs = data.get("accounts") or []
    meta = data.get("meta") or {}
    print(f"[restore] 备份日期 {meta.get('date')}，{len(accs)} 个号 {meta.get('by_pool')}")
    if not write:
        print("[restore] dry-run（未写入）。确认无误后加 --write")
        return
    # 列清单按「备份里实际出现过哪些键」推出来（扫前 200 行足够，同一次导出行结构一致）。
    # COLS 只作为顺序模板；备份里没有的列不出现在 SET 里 → 库里该列保持原值。
    present = set()
    for r in accs[:200]:
        present.update(r.keys())
    use_cols = [c for c in COLS if c in present]
    for req in ("pool", "uid"):
        if req not in use_cols:
            raise SystemExit(f"备份里缺 {req} 列，无法恢复")
    missing = [c for c in COLS if c not in use_cols]
    if missing:
        print("[restore] 备份里没有这些列，恢复时保持库里原值不动：" + ", ".join(missing))
    sets = ",".join(f"{c}=excluded.{c}" for c in use_cols if c not in ("pool", "uid"))
    batch = max(1, 100 // max(1, len(use_cols)))
    print(f"[restore] 覆盖 {len(use_cols)} 列，每批 {batch} 行")

    done = 0
    for i in range(0, len(accs), batch):
        chunk = accs[i:i + batch]
        ph = []
        vals = []
        for r in chunk:
            ph.append("(" + ",".join(["?"] * len(use_cols)) + ")")
            for c in use_cols:
                v = r.get(c)
                if c == "no_listen" and v is not None:
                    v = 1 if v in (1, True, "1", "true") else 0
                vals.append(v)
        sql = (f"INSERT INTO accounts ({','.join(use_cols)}) VALUES " + ",".join(ph)
               + f" ON CONFLICT(pool,uid) DO UPDATE SET {sets}")
        api(sql, vals)
        done += len(chunk)
        print(f"[restore] {done}/{len(accs)}", flush=True)
    rows = api("SELECT pool, COUNT(*) c FROM accounts GROUP BY pool")
    print("[restore] 恢复后：", (rows.get("result") or [{}])[0].get("results"))


if __name__ == "__main__":
    main()
