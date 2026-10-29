# -*- coding: utf-8 -*-
"""D1 账号池恢复（配合 d1_backup.py / d1-backup.yml 使用）。

用途：D1 被误删、写坏、或换账号重建时，把某一天的加密备份灌回去。

恢复范围（2026-10-29 扩展到可选表）：
  默认只写 accounts（与旧行为完全一致）——
    安全约束：默认 dry-run，只打印将要写入多少条，加 --write 才真的写；
             不会删除库里现有的号：备份里有、库里也多出来的号会留着（宁可多不可少）。
  --tables 可显式追加其它表（写法 `--tables accounts,snapshots,kv_misc,dead_log,schema`，
  或 `--tables all` 全恢复）：
    schema      建表 / 建索引 DDL（必须先于数据，否则表都不存在）
    accounts    号池（唯一不可再生的运行数据）
    snapshots   每日快照（650/rate/rpc30 历史；网易后台只给当前值，过了就查不到 → 不可再生）
    kv_misc     配置（reg_cfg = 套餐档位 + 客服名单的唯一权威）
    dead_log    判死流水（审计用；按原 id 插入，已存在则跳过，不覆盖）
  2026-10-29 之前只恢复 accounts，快照和配置在备份文件里躺着却从不写回 —— 一旦真出事，
  650 历史要重新长 60 天、登记页套餐/客服下拉框会回默认值。

写入语义（2026-10-29）：
  accounts 用按列 upsert 而非 INSERT OR REPLACE：只覆盖「备份里确实存在」的列，
  将来给 accounts 加列之后，用旧备份恢复一次也不会把新列清空（OR REPLACE = 整行替换，缺列即 NULL）。

环境变量：CF_TOKEN / CF_ACCOUNT_ID / D1_UUID / BACKUP_PASS

用法：
  python d1_restore.py backup/d1-2026-10-26.json.gz.enc                      # 预演（只看 accounts）
  python d1_restore.py backup/d1-2026-10-26.json.gz.enc --write              # 真写 accounts
  python d1_restore.py backup/d1-2026-10-26.json.gz.enc --tables all         # 预演全量
  python d1_restore.py backup/d1-2026-10-26.json.gz.enc --tables all --write # 全量真写
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
            # 实际每批行数按「列数」重算（见 restore_table），备份列少时可以更宽

# 每张表的恢复规格：pkey=冲突键，cols=写哪些列，coalesce=「备份里为 NULL 时保留库里原值」的列，
# mode=upsert（冲突则更新）/ ignore（冲突则跳过，用于带自增 id 的流水表）。
SPECS = {
    "accounts": {"pkey": ["pool", "uid"], "cols": COLS, "coalesce": (), "mode": "upsert"},
    "snapshots": {"pkey": ["day", "pool", "uid"],
                  "cols": ["day", "pool", "uid", "rate", "rpc30", "cnt", "missions", "dur", "at"],
                  # 与 worker 写入口径一致：cnt/dur 为空时保留原值（时长由 run.py 播放时写）
                  "coalesce": ("cnt", "dur"), "mode": "upsert"},
    "kv_misc": {"pkey": ["k"], "cols": ["k", "v", "updated_at"], "coalesce": (), "mode": "upsert"},
    "dead_log": {"pkey": ["id"], "cols": ["id", "pool", "uid", "name", "reason", "at"],
                 "coalesce": (), "mode": "ignore"},
}
DATA_ORDER = ["accounts", "snapshots", "kv_misc", "dead_log"]


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


def parse_tables(argv):
    """默认只 accounts（与旧行为一致）。支持 --tables a,b 与 --tables all。"""
    for i, a in enumerate(argv):
        if a == "--tables" and i + 1 < len(argv):
            raw = argv[i + 1].strip().lower()
            if raw in ("all", "*"):
                return ["schema"] + list(DATA_ORDER)
            want = [x.strip() for x in raw.split(",") if x.strip()]
            bad = [x for x in want if x not in SPECS and x != "schema"]
            if bad:
                raise SystemExit(f"--tables 里有不认识的表：{','.join(bad)}"
                                 f"（可选 {'/'.join(['schema'] + DATA_ORDER)} 或 all）")
            return want
        if a.startswith("--tables="):
            raw = a.split("=", 1)[1].strip().lower()
            if raw in ("all", "*"):
                return ["schema"] + list(DATA_ORDER)
            want = [x.strip() for x in raw.split(",") if x.strip()]
            bad = [x for x in want if x not in SPECS and x != "schema"]
            if bad:
                raise SystemExit(f"--tables 里有不认识的表：{','.join(bad)}")
            return want
    return ["accounts"]


def restore_schema(data):
    rows = data.get("schema") or []
    if not rows:
        raise SystemExit("这份备份里没有 schema（2026-10-29 之前的备份都不含建表语句），"
                         "请改用带 schema 的新备份，或手工建表后再恢复数据")
    created = existed = 0
    for r in rows:
        sql = (r.get("sql") or "").strip()
        if not sql:
            continue
        try:
            api(sql)
            created += 1
        except SystemExit as e:
            if "already exists" in str(e).lower():
                existed += 1
                continue
            raise SystemExit(f"建表失败：{sql[:160]}\n{e}")
    print(f"[restore] schema：新建 {created} 条，已存在跳过 {existed} 条")


def restore_table(name, rows):
    spec = SPECS[name]
    if not rows:
        print(f"[restore] {name}：备份里 0 行，跳过")
        return 0
    # 列清单按「备份里实际出现过哪些键」推出来（扫前 200 行足够，同一次导出行结构一致）。
    # spec["cols"] 只作为顺序模板；备份里没有的列不出现在 SET 里 → 库里该列保持原值。
    present = set()
    for r in rows[:200]:
        present.update(r.keys())
    cols = [c for c in spec["cols"] if c in present]
    missing = [c for c in spec["pkey"] if c not in cols]
    if missing:
        raise SystemExit(f"{name}：备份里缺主键列 {','.join(missing)}，无法恢复")
    skipped_cols = [c for c in spec["cols"] if c not in cols]
    if skipped_cols:
        print(f"[restore] {name}：备份里没有这些列，保持库里原值不动：" + ", ".join(skipped_cols))

    non_key = [c for c in cols if c not in spec["pkey"]]
    if spec["mode"] == "ignore" or not non_key:
        conflict = " DO NOTHING"
    else:
        sets = []
        for c in non_key:
            if c in spec["coalesce"]:
                sets.append(f"{c}=COALESCE(excluded.{c}, {name}.{c})")
            else:
                sets.append(f"{c}=excluded.{c}")
        conflict = f" ON CONFLICT({','.join(spec['pkey'])}) DO UPDATE SET " + ",".join(sets)

    batch = max(1, 90 // max(1, len(cols)))     # 90 留一点余量，硬上限是 100 个参数
    print(f"[restore] {name}：{len(rows)} 行，覆盖 {len(cols)} 列，每批 {batch} 行")
    done = 0
    step = max(1, len(rows) // 10)              # 进度每 10% 打一次，避免刷屏
    for i in range(0, len(rows), batch):
        chunk = rows[i:i + batch]
        ph = []
        vals = []
        for r in chunk:
            ph.append("(" + ",".join(["?"] * len(cols)) + ")")
            for c in cols:
                v = r.get(c)
                if c == "no_listen" and v is not None:
                    v = 1 if v in (1, True, "1", "true") else 0
                vals.append(v)
        sql = (f"INSERT INTO {name} ({','.join(cols)}) VALUES " + ",".join(ph) + conflict)
        api(sql, vals)
        done += len(chunk)
        if done % step < batch or done == len(rows):
            print(f"[restore] {name} {done}/{len(rows)}", flush=True)
    return done


def main():
    if len(sys.argv) < 2:
        raise SystemExit("用法: python d1_restore.py <备份文件> [--tables a,b|all] [--write]")
    path = sys.argv[1]
    write = "--write" in sys.argv
    tables = parse_tables(sys.argv)
    if not os.path.exists(path):
        raise SystemExit(f"文件不存在: {path}")
    data = load_payload(path)
    meta = data.get("meta") or {}
    print(f"[restore] 备份日期 {meta.get('date')}，{len(data.get('accounts') or [])} 个号 {meta.get('by_pool')}")
    print(f"[restore] 备份内容：schema {len(data.get('schema') or [])} 条、"
          f"accounts {len(data.get('accounts') or [])}、snapshots {len(data.get('snapshots') or [])}、"
          f"kv_misc {len(data.get('kv_misc') or [])}、dead_log {len(data.get('dead_log') or [])}")
    print(f"[restore] 本次将恢复：{', '.join(tables)}")
    if not write:
        print("[restore] dry-run（未写入，不需要 CF_TOKEN）。确认无误后加 --write")
        return
    if not TOK:
        raise SystemExit("缺 CF_TOKEN，无法真写")

    if "schema" in tables:
        restore_schema(data)
    total = 0
    for name in tables:
        if name == "schema":
            continue
        total += restore_table(name, data.get(name) or [])
    rows = api("SELECT (SELECT COUNT(*) FROM accounts) AS accounts, "
               "(SELECT COUNT(*) FROM snapshots) AS snapshots, "
               "(SELECT COUNT(*) FROM kv_misc) AS kv_misc, "
               "(SELECT COUNT(*) FROM dead_log) AS dead_log")
    print(f"[restore] 写入 {total} 行；恢复后库内计数：",
          (rows.get("result") or [{}])[0].get("results"))


if __name__ == "__main__":
    main()
