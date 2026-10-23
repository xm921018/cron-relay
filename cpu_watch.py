# -*- coding: utf-8 -*-
"""Worker CPU 临近上限预警（2026-10-22 新增）。

背景：Cloudflare Workers 免费版每个请求 10ms CPU，超了直接 1102 报错（页面打不开 / 接口 500）。
这个脚本每天跑一次，用 Cloudflare GraphQL Analytics 拉最近 24 小时的 CPU 分位；
一旦 p50（中位请求 CPU）≥ 阈值（默认 9.5ms），就给号主邮箱发一封提醒，好提前扩容/优化，
而不是等某天整站 1102 之后才发现。

数据来源：
  https://api.cloudflare.com/client/v4/graphql  → workersInvocationsAdaptive
  quantiles.cpuTimeP50 / cpuTimeP99 单位是微秒（µs）

需要的环境变量（GitHub Secrets 注入）：
  CF_TOKEN         Cloudflare API 令牌（需 Account Analytics:Read）
  CF_ACCOUNT_ID    账号 ID
  ALERT_TO         告警收件邮箱（GitHub Secret 注入；未设置则跳过发信）
  EMAIL_FROM / EMAIL_AUTH_CODE  复用现成的 QQ 邮箱直邮通道
  CPU_THRESH_MS    阈值毫秒（默认 9.5）

用法：
  python cpu_watch.py            # 正常跑（超阈值才发信）
  python cpu_watch.py --force    # 无论是否超阈值都发一封（配置自测用）
"""
import json
import os
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

API = "https://api.cloudflare.com/client/v4/graphql"
SCRIPTS = ("cron-relay", "dingzhi")
ALERT_TO = (os.environ.get("ALERT_TO") or "").strip()
THRESH_MS = float(os.environ.get("CPU_THRESH_MS") or 9.5)
LIMIT_MS = 10.0  # 免费版每请求 CPU 上限
ERR_TRIP = int(os.environ.get("CPU_ERR_TRIP") or 3)   # 24h 错误数达到这个值就告警
STRICT = (os.environ.get("CPU_ALERT_MODE") or "").strip().lower() == "strict"

Q = """
query ($acc: String!, $geq: String!, $leq: String!) {
  viewer {
    accounts(filter: {accountTag: $acc}) {
      workersInvocationsAdaptive(limit: 1000,
        filter: {datetime_geq: $geq, datetime_leq: $leq}) {
        sum { requests errors }
        quantiles { cpuTimeP50 cpuTimeP99 }
        dimensions { scriptName datetimeHour }
      }
    }
  }
}
"""


def cf(acc, tok, geq, leq):
    body = json.dumps({"query": Q, "variables": {"acc": acc, "geq": geq, "leq": leq}}).encode()
    req = urllib.request.Request(API, data=body, headers={
        "Authorization": "Bearer " + tok,
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0 (compatible; cpu-watch/1.0)",
    })
    with urllib.request.urlopen(req, timeout=60) as r:
        d = json.loads(r.read().decode("utf-8"))
    if not d.get("success", True) and d.get("errors"):
        raise RuntimeError(json.dumps(d["errors"], ensure_ascii=False)[:300])
    return d["data"]["viewer"]["accounts"][0]["workersInvocationsAdaptive"]


def window(hours, offset_hours=0):
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    end = now - timedelta(hours=offset_hours)
    start = end - timedelta(hours=hours)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ"), end.strftime("%Y-%m-%dT%H:%M:%SZ")


def summarize(rows):
    """按脚本聚合：总请求、错误、加权 p50（用各小时请求数加权）。"""
    out = {}
    for x in rows:
        name = (x.get("dimensions") or {}).get("scriptName") or "?"
        q = x.get("quantiles") or {}
        s = x.get("sum") or {}
        n = int(s.get("requests") or 0)
        p50 = q.get("cpuTimeP50")
        p99 = q.get("cpuTimeP99")
        if not n or p50 is None:
            continue
        o = out.setdefault(name, {"req": 0, "err": 0, "p50w": 0.0, "p50max": 0, "p99max": 0,
                                  "hours": []})
        o["req"] += n
        o["err"] += int(s.get("errors") or 0)
        o["p50w"] += float(p50) * n
        o["p50max"] = max(o["p50max"], int(p50))
        o["p99max"] = max(o["p99max"], int(p99 or 0))
        o["hours"].append(("2026", (x.get("dimensions") or {}).get("datetimeHour"), n, int(p50)))
    for o in out.values():
        o["p50"] = int(o["p50w"] / o["req"]) if o["req"] else 0
        o["hours"].sort(key=lambda t: t[3], reverse=True)
    return out


def us(v):
    return f"{v / 1000.0:.2f}ms" if v >= 1000 else f"{v}µs"


def main():
    tok = (os.environ.get("CF_TOKEN") or "").strip()
    acc = (os.environ.get("CF_ACCOUNT_ID") or "").strip()
    force = "--force" in sys.argv
    if not tok or not acc:
        print("[cpu] 缺 CF_TOKEN / CF_ACCOUNT_ID，跳过")
        return 2

    geq, leq = window(24)
    rows = cf(acc, tok, geq, leq)
    cur = summarize(rows)

    # 7 天日线，用来判断"是不是在持续变差"
    trend = []
    for d in range(1, 8):
        try:
            g2, l2 = window(24, offset_hours=24 * d)
            tr = summarize(cf(acc, tok, g2, l2))
            trend.append((l2[:10], {k: v["p50"] for k, v in tr.items()}))
        except Exception as e:
            print(f"[cpu] 第 {d} 天趋势拉取失败：{e}")

    lines, alerts = [], []
    for name in SCRIPTS:
        o = cur.get(name)
        if not o:
            lines.append(f"- {name}: 最近 24h 无请求")
            continue
        lines.append(f"- {name}: p50 {us(o['p50'])}（峰值小时 {us(o['p50max'])}）| "
                     f"p99(峰值) {us(o['p99max'])} | 请求 {o['req']} | 错误 {o['err']}")
        # 判断规则（2026-10-22 定版）：
        #   实测发现"p50 超过 10ms"本身并不等于出事——24h p50 20ms、p99 500ms 的这天，错误数依然是 0，
        #   说明这个账号的请求并没有被 CPU 上限杀掉（要么额度不是 10ms，要么该指标包含等待时间）。
        #   所以只在下面两种情况下才发信，避免每天一封无效告警：
        #     ① 出现 CPU/未捕获异常类错误（真的在挂）；
        #     ② p50 越过阈值「且」比之前 7 天均值恶化 50% 以上（真的在变坏）。
        #   想恢复"只要过阈值就发"的字面行为：环境变量 CPU_ALERT_MODE=strict。
        prev_avg = [v.get(name) for _, v in trend if v.get(name)]
        base = sum(prev_avg) / len(prev_avg) if prev_avg else 0
        o["base"] = int(base)
        if o["err"] >= ERR_TRIP:
            alerts.append(f"{name} 最近 24h 出现 {o['err']} 次错误（CPU 超限/未捕获异常），请检查")
        elif o["p50"] >= THRESH_MS * 1000:
            if STRICT:
                alerts.append(f"{name} p50 = {us(o['p50'])}，已达阈值 {THRESH_MS}ms（上限 {LIMIT_MS}ms）")
            elif base and o["p50"] >= base * 1.5:
                alerts.append(f"{name} p50 = {us(o['p50'])}，达阈值 {THRESH_MS}ms 且比前 7 天均值 {us(int(base))} 恶化 "
                              f"{o['p50'] / base:.1f} 倍")
            else:
                lines[-1] += f"｜已超阈值但未恶化（前 7 天均值 {us(int(base))}），仅记录不发信"

    print("[cpu] 最近 24h：")
    print("\n".join(lines))
    for d, v in trend:
        print(f"[cpu] {d} p50: " + ", ".join(f"{k}={us(x)}" for k, x in v.items()))

    if not alerts and not force:
        print("[cpu] 未达阈值，不发邮件")
        return 0

    body = ["号主你好：", ""]
    if alerts:
        body += ["Worker CPU 出现异常，可能已经影响打开速度或接口成功率，看一眼为好。", ""]
        body += ["触发项："] + [f"  · {a}" for a in alerts] + [""]
    else:
        body += ["这是 CPU 预警通道的自测邮件（手动触发，非告警）。", ""]

    body += ["最近 24 小时："] + lines + [""]
    if trend:
        body.append("最近 7 天 p50 走势（免费版上限 10ms；持续抬升才需要处理）：")
        for d, v in trend:
            body.append(f"  {d}  " + "  ".join(f"{k}={us(x)}" for k, x in v.items()))
        body.append("")
    for name in SCRIPTS:
        o = cur.get(name) or {}
        hrs = (o.get("hours") or [])[:5]
        if hrs:
            body.append(f"{name} CPU 最高的 5 个小时：")
            for _, h, n, p50 in hrs:
                body.append(f"  {h}  p50 {us(p50)}，请求 {n}")
            body.append("")

    body += [
        "怎么处理（按性价比排序）：",
        "  1. 停掉不必要的 Secrets 全量推送（登记时 12 次加密 PUT 是最大 CPU 消耗）；",
        "  2. 控制台/接口减少全表 SELECT，改成按需分页；",
        "  3. 仍不够再考虑 Workers 付费版（$5/月，CPU 上限提到 30 秒）。",
        "",
        "——网易音乐人650任务",
    ]

    subj = ("【网易音乐人650任务】Worker CPU 临近上限" if alerts
            else "【网易音乐人650任务】CPU 预警通道测试")
    try:
        if not ALERT_TO:
            print("[cpu] 未配置 ALERT_TO（GitHub Secret），跳过发信")
            return 0
        from notify import send_user_email
        ok = send_user_email(ALERT_TO, subj, "\n".join(body))
        print(f"[cpu] 发信 {ALERT_TO}: {'成功' if ok else '失败'}")
        return 0 if ok else 1
    except Exception as e:
        print(f"[cpu] 发信失败：{e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
