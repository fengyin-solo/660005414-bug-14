from __future__ import annotations

import zlib, random
import numpy as np
from collections import Counter
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Log Anomaly Detector")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ---------------------------------------------------------------------------
# 统一阈值标准：切窗、统计判定、严重级分级全部使用这里的常量，
# analyze_logs 对同一份输入必须给出完全一致的分数与判定（纯函数、无随机、无墙钟）。
# ---------------------------------------------------------------------------
WINDOW_SIZE = 20            # 每个窗口固定容量（条数）
MIN_WINDOWS_FOR_STATS = 3   # 参与统计判定所需的最少（完整）窗口数
SIGMA_ANOMALY = 2.5         # 3-sigma 异常阈值
IQR_ANOMALY = 3.0           # IQR 异常阈值（|x-mean|/iqr）
SIGMA_CRITICAL = 4.0        # 3-sigma 严重异常阈值
IQR_CRITICAL = 6.0          # IQR 严重异常阈值（与 SIGMA 保持同一档比例）
IQR_FENCE = 1.5             # IQR 围栏系数
SCORE_CAP = 10.0
EPS = 1e-9

# custom 类型生成时间戳时使用的固定基准，避免墙钟导致不可复现
_FIXED_BASE_EPOCH = 1700000000

_MONTHS = 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split()
_WEEKDAYS = 'Sun Mon Tue Wed Thu Fri Sat'.split()


def _gen_nginx(rng):
    return {
        "timestamp": f"{rng.randint(1,28):02d}/{_MONTHS[rng.randint(0,11)]}/2024:"
                     f"{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d} +0000",
        "source": rng.choice(["nginx", "api-gateway", "load-balancer"]),
        "level": rng.choices(["INFO", "WARN", "ERROR", "DEBUG"], weights=[50, 15, 5, 30])[0],
        "message": rng.choice([
            'GET /api/users 200 0.032s', 'POST /api/orders 201 0.145s', 'GET /api/products 304 0.008s',
            'GET /static/main.js 200 0.002s', 'POST /api/login 401 0.023s', 'GET /admin 403 0.005s',
            'GET /api/health 200 0.001s', 'GET /api/orders?page=2 200 0.056s', 'connection timeout upstream',
            'SSL handshake failed', 'worker process exited on signal 9', 'upstream server unavailable'
        ])
    }


def _gen_apache(rng):
    return {
        "timestamp": f"{_WEEKDAYS[rng.randint(0,6)]} {_MONTHS[rng.randint(0,11)]} "
                     f"{rng.randint(1,28):02d} {rng.randint(0,23):02d}:{rng.randint(0,59):02d}:"
                     f"{rng.randint(0,59):02d} 2024",
        "source": rng.choice(["httpd", "mod_ssl", "mod_rewrite"]),
        "level": rng.choices(["notice", "warn", "error", "info"], weights=[40, 15, 5, 40])[0],
        "message": rng.choice(["server configured", "caught SIGTERM", "resuming normal ops", "request exceeded limit",
                               "file does not exist", "client denied by server", "Invalid method in request"])
    }


def _gen_json_app(rng):
    return {
        "timestamp": f"2024-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}T"
                     f"{rng.randint(0,23):02d}:{rng.randint(0,59):02d}:{rng.randint(0,59):02d}."
                     f"{rng.randint(0,999):03d}Z",
        "source": rng.choice(["user-service", "order-service", "payment-service", "auth-service"]),
        "level": rng.choices(["INFO", "WARN", "ERROR", "DEBUG"], weights=[45, 20, 5, 30])[0],
        "message": rng.choice([
            'User login successful user_id=10' + str(rng.randint(100, 999)),
            'Order created order_id=ORD-' + str(rng.randint(10000, 99999)),
            'Payment processed amount=' + str(rng.randint(10, 999)),
            'Database connection pool exhausted',
            'Cache miss for key user_session_' + str(rng.randint(100, 999)),
            'Circuit breaker opened for service payment',
            'Request latency exceeds threshold 5000ms',
            'NullPointerException at com.app.controller.UserController.getProfile'
        ])
    }


def _gen_custom(rng):
    return {
        "timestamp": str(_FIXED_BASE_EPOCH - rng.randint(0, 86400)),
        "source": rng.choice(["cron", "systemd", "kernel", "docker"]),
        "level": rng.choices(["info", "warning", "error", "debug"], weights=[40, 20, 5, 35])[0],
        "message": rng.choice(["OOM killer invoked", "disk usage above 90%", "container restarted", "NTP sync lost",
                               "process oom_score_adj=500", "firewall rule updated", "mount point not found"])
    }


LOG_GENERATORS = {
    "nginx": _gen_nginx,
    "apache": _gen_apache,
    "json_app": _gen_json_app,
    "custom": _gen_custom,
}

class GenerateRequest(BaseModel):
    type: str = "nginx"
    count: int = 1000
    # 不传 seed 时按 type+count 派生确定性种子：同样参数（含服务重启后）生成完全相同的日志
    seed: int | None = None


class DetectRequest(BaseModel):
    logs: list
    rules: list = []
    query: str = ""


def _default_seed(log_type: str, count: int) -> int:
    return zlib.crc32(f"{log_type}:{count}".encode("utf-8"))


def _severity_by_ratio(ratio: float) -> str:
    """覆盖率告警与流量告警共用同一套分级依据：实际值相对阈值的超出倍数。"""
    if ratio >= 2.0:
        return "critical"
    if ratio >= 1.5:
        return "high"
    return "medium"


@app.post("/api/generate")
def generate_logs(req: GenerateRequest):
    generator = LOG_GENERATORS.get(req.type, _gen_nginx)
    seed = req.seed if req.seed is not None else _default_seed(req.type, req.count)
    rng = random.Random(seed)
    logs = []
    for i in range(req.count):
        entry = generator(rng)
        logs.append({
            "id": i + 1,
            "timestamp": entry["timestamp"],
            "level": entry["level"],
            "source": entry["source"],
            "message": entry["message"],
            "raw": f"[{entry['timestamp']}] [{entry['level']}] [{entry['source']}] {entry['message']}"
        })
    return analyze_logs(logs, [], "")


@app.post("/api/detect")
def detect_anomalies(req: DetectRequest):
    return analyze_logs(req.logs, req.rules, req.query)


def _build_windows(logs):
    """按日志原始顺序、固定条数切窗。最后一个不满容量的窗口标记 partial，
    数据不完整，不参与流量统计与流量异常判定。"""
    windows = []
    for index, i in enumerate(range(0, len(logs), WINDOW_SIZE)):
        chunk = logs[i:i + WINDOW_SIZE]
        windows.append({
            "index": index,
            "start": i,
            "end": i + len(chunk),
            "count": len(chunk),
            "partial": len(chunk) < WINDOW_SIZE,
            "firstTimestamp": chunk[0].get("timestamp", "") if chunk else "",
            "levels": dict(Counter(l.get("level", "") for l in chunk)),
            "sources": dict(Counter(l.get("source", "") for l in chunk)),
        })
    return windows


def analyze_logs(logs_data, rules, query):
    logs = list(logs_data)
    n = len(logs)

    # 1) 窗口：始终基于原始顺序的完整日志，搜索/过滤不影响切窗与分数
    windows = _build_windows(logs)

    # 2) 3-sigma + IQR：只有完整窗口参与统计；样本不足时不做统计判定（分数一律 0）
    full_counts = [w["count"] for w in windows if not w["partial"]]
    sample_sufficient = len(full_counts) >= MIN_WINDOWS_FOR_STATS

    mean = std = q1 = q3 = iqr = 0.0
    if sample_sufficient:
        mean = float(np.mean(full_counts))
        std = float(np.std(full_counts))  # 总体标准差，确定性
        q1 = float(np.percentile(full_counts, 25))
        q3 = float(np.percentile(full_counts, 75))
        iqr = q3 - q1

    anomalies = []
    for w in windows:
        eligible = sample_sufficient and not w["partial"] and std > EPS
        sigma_score = 0.0
        iqr_score = 0.0
        if eligible:
            sigma_score = abs(w["count"] - mean) / std
            if iqr > EPS and (w["count"] < q1 - IQR_FENCE * iqr or w["count"] > q3 + IQR_FENCE * iqr):
                iqr_score = min(SCORE_CAP, abs(w["count"] - mean) / iqr)
        is_anomaly = eligible and (sigma_score > SIGMA_ANOMALY or iqr_score > IQR_ANOMALY)
        anomalies.append({
            "windowIndex": w["index"],
            "sigmaScore": round(sigma_score, 2),
            "iqrScore": round(iqr_score, 2),
            "isAnomaly": is_anomaly,
            "partial": w["partial"],
            "timestamp": w["firstTimestamp"]
        })

    # 3) 告警规则（编号统一使用窗口序号；时间戳取窗口内首条日志，保证可复现）
    alerts = []

    def add_alert(rule_name, severity, message, timestamp):
        alerts.append({
            "id": len(alerts) + 1,
            "ruleName": rule_name,
            "severity": severity,
            "message": message,
            "timestamp": timestamp,
        })

    for rule in rules:
        rule = rule if isinstance(rule, dict) else {}
        rule_type = rule.get("type")
        rule_name = rule.get("name") or ("高频ERROR" if rule_type == "level" else "异常流量")
        threshold = rule.get("threshold", 0)
        for w in windows:
            if rule_type == "level":
                # 覆盖率口径：ERROR 占窗口实际条数的比例，阈值按满窗口容量折算成期望覆盖率。
                # 满窗口时与原来的「ERROR 条数 > threshold」判定完全等价，且尾窗口口径一致。
                expected_rate = max(threshold, 0) / WINDOW_SIZE
                error_count = w["levels"].get("ERROR", 0)
                error_rate = error_count / w["count"] if w["count"] else 0.0
                if expected_rate > EPS and error_rate > expected_rate:
                    severity = _severity_by_ratio(error_rate / expected_rate)
                    add_alert(
                        rule_name, severity,
                        f"窗口{w['index']}内ERROR覆盖率{error_rate:.0%}超过阈值{expected_rate:.0%}"
                        f"（{error_count}/{w['count']}条）",
                        w["firstTimestamp"]
                    )
            elif rule_type == "count":
                # 流量口径：partial 窗口数据不完整，不参与流量超限判定
                threshold = max(threshold, 0)
                if not w["partial"] and threshold > 0 and w["count"] > threshold:
                    severity = _severity_by_ratio(w["count"] / threshold)
                    add_alert(
                        rule_name, severity,
                        f"窗口{w['index']}日志量{w['count']}超过阈值{threshold}",
                        w["firstTimestamp"]
                    )

    # 统计异常告警：判定与分级使用与上面完全相同的一套阈值
    for a in anomalies:
        if a["isAnomaly"]:
            severity = "critical" if (a["sigmaScore"] >= SIGMA_CRITICAL or a["iqrScore"] >= IQR_CRITICAL) else "high"
            add_alert(
                "统计异常检测",
                severity,
                f"窗口{a['windowIndex']}: 3-sigma={a['sigmaScore']}, IQR={a['iqrScore']}",
                a["timestamp"]
            )

    # 4) 全文检索：只产出单独的 matchedLogs，绝不重排/截断参与切窗的 logs
    matched_logs = []
    if query:
        query_terms = query.lower().split()
        scored = []
        for log in logs:
            raw_lower = log.get("raw", "").lower()
            score = sum(1 for t in query_terms if t in raw_lower)
            if score > 0:
                scored.append((score, log))
        matched_logs = [l for _, l in sorted(scored, key=lambda x: x[0], reverse=True)]

    return {
        "logs": logs,
        "matchedLogs": matched_logs[:200],
        "windows": windows,
        "anomalies": anomalies,
        "alerts": alerts[:20],
        "totalLogs": n,
        "detectionStats": {
            "windowCount": len(windows),
            "fullWindowCount": len(full_counts),
            "sampleSufficient": sample_sufficient,
            "mean": round(mean, 4),
            "std": round(std, 4),
            "q1": round(q1, 4),
            "q3": round(q3, 4),
            "thresholds": {
                "sigma": SIGMA_ANOMALY,
                "iqr": IQR_ANOMALY,
                "sigmaCritical": SIGMA_CRITICAL,
                "iqrCritical": IQR_CRITICAL,
                "minWindows": MIN_WINDOWS_FOR_STATS,
                "windowSize": WINDOW_SIZE,
            },
        },
    }
