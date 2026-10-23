# -*- coding: utf-8 -*-
"""每周号池汇总邮件（2026-10-22 新增）。

目的：不用每天翻 Actions 日志，也能知道这一周号池的底子——
  人数涨了多少、清理了多少失效号、650 任务整体完成到几成、有没有哪天没跑。
只读 D1（权威数据），不碰 KV/GitHub，失败只记日志不影响任何主流程。

环境变量：
  CF_TOKEN / CF_ACCOUNT_ID / D1_UUID   读 D1
  EMAIL_FROM / EMAIL_AUTH_CODE         QQ 邮箱 SMTP（与其它邮件共用）
  ALERT_TO                             收件人（GitHub Secret 注入；未设置则跳过发信）

用法：python weekly_report.py            # 打印 + 发信
      python weekly_report.py --dry      # 只打印不发信
"""
import datetime
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import notify  # noqa: E402

ACC = os.environ.get("CF_ACCOUNT_ID", "").strip() or "c60450bfb7f2c2becfd744ba2508a4f2"
D1_UUID = (os.environ.get("D1_UUID", "").strip() or "54f742fc-5f56-4723-a7a0-a832953d38c7")
TOK = (os.environ.get("CF_TOKEN", "") or "").strip()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"
POOL_NAME = {"hz": "互助版", "dz": "定制版"}


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
        with urllib.request.urlopen(req, timeout=90) as r:
            d = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[weekly] D1 HTTP {e.code}: {e.read().decode()[:300]}")
        return []
    if not d.get("success"):
        print("[weekly] D1 失败:", json.dumps(d.get("errors"), ensure_ascii=False)[:300])
        return []
    res = d.get("result") or []
    return (res[0].get("results") or []) if res else []


def bj_today():
    return (datetime.datetime.utcnow() + datetime.timedelta(hours=8)).date()


def main():
    if not TOK:
        raise SystemExit("缺 CF_TOKEN")
    today = bj_today()
    week_ago = (today - datetime.timedelta(days=7)).isoformat()

    base = api("SELECT pool, COUNT(*) total, "
               "SUM(CASE WHEN no_listen=1 THEN 1 ELSE 0 END) nolisten, "
               "SUM(CASE WHEN added >= ? THEN 1 ELSE 0 END) new7 "
               "FROM accounts GROUP BY pool", [week_ago])
    dead = api("SELECT pool, COUNT(*) c FROM dead_log WHERE at >= ? GROUP BY pool", [week_ago])
    exp = api("SELECT pool, COUNT(*) c FROM accounts WHERE exp IS NOT NULL AND exp<>'forever' "
              "AND exp <= ? GROUP BY pool", [(today + datetime.timedelta(days=7)).isoformat()])
    snap_days = api("SELECT day, pool, COUNT(*) c FROM snapshots GROUP BY day, pool "
                    "ORDER BY day DESC LIMIT 30")
    last_day = snap_days[0]["day"] if snap_days else None
    r650 = []
    if last_day:
        r650 = api("SELECT pool, COUNT(*) n, AVG(rate) avg_rate, "
                   "SUM(CASE WHEN rate>=100 THEN 1 ELSE 0 END) done, "
                   "SUM(CASE WHEN rate=0 THEN 1 ELSE 0 END) zero "
                   "FROM snapshots WHERE day=? GROUP BY pool", [last_day])

    dead_map = {r["pool"]: r["c"] for r in dead}
    exp_map = {r["pool"]: r["c"] for r in exp}
    r650map = {r["pool"]: r for r in r650}
    days_map = {}
    for r in snap_days:
        days_map.setdefault(r["pool"], set()).add(r["day"])

    L = []
    L.append(f"统计区间：{week_ago} ~ {today.isoformat()}（北京时间）")
    L.append("")
    L.append("【号池人数】")
    for r in base:
        p = r["pool"]
        L.append(f"· {POOL_NAME.get(p, p)}：{r['total']} 个号"
                 f"（本周新增 {r['new7']}，其中只收不听 {r['nolisten'] or 0}，"
                 f"7 天内到期 {exp_map.get(p, 0)}，本周清理失效 {dead_map.get(p, 0)}）")
    L.append("")
    L.append(f"【650 任务】（最近一次快照 {last_day or '无'}）")
    if r650:
        for r in r650:
            p = r["pool"]
            avg = r["avg_rate"] or 0
            L.append(f"· {POOL_NAME.get(p, p)}：可查 {r['n']} 个号，平均进度 {avg:.1f}%，"
                     f"已完成 {r['done']} 个，仍为 0 {r['zero'] or 0} 个")
        L.append("  说明：只有开通「音乐人 VIP」的号才有工作台数据，数字少不代表漏号。")
    else:
        L.append("· 没有快照数据（run.py 上报失败或本周没跑）")
    L.append("")
    L.append("【近 7 天快照覆盖】")
    for p, ds in days_map.items():
        recent = sorted(d for d in ds if d >= week_ago)
        L.append(f"· {POOL_NAME.get(p, p)}：{len(recent)}/7 天有数据"
                 + ("" if len(recent) == 7 else "  ← 有缺天，留意是否漏跑"))
    L.append("")
    L.append("——网易音乐人小助手（每周自动汇总）")

    body = "\n".join(L)
    print(body)

    if "--dry" in sys.argv:
        print("\n[weekly] dry-run，未发信")
        return
    to = (os.environ.get("ALERT_TO") or "").strip()
    if not to:
        print("[weekly] 未配置 ALERT_TO（GitHub Secret），跳过发信")
        return
    ok = notify.send_user_email(to, f"【网易音乐人650任务】本周号池汇总 {today.isoformat()}", body)
    print(f"[weekly] 发信 {'成功' if ok else '失败'} → {to}")


if __name__ == "__main__":
    main()
