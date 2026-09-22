import math
import random
from collections import Counter

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="Log Anomaly Detector")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

WINDOW_SIZE = 20
MIN_WINDOWS_FOR_STATISTICAL_DETECTION = 3
SIGMA_THRESHOLD = 2.5
IQR_THRESHOLD = 3.0
DEFAULT_ERROR_THRESHOLD = 5
DEFAULT_TRAFFIC_THRESHOLD = 18
STABLE_EPOCH = 1704067200

MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
WEEKDAYS = "Sun Mon Tue Wed Thu Fri Sat".split()


def make_nginx(rng):
    return {
        "timestamp": f"{rng.randint(1, 28):02d}/{MONTHS[rng.randint(0, 11)]}/2024:"
                     f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:"
                     f"{rng.randint(0, 59):02d} +0000",
        "source": rng.choice(["nginx", "api-gateway", "load-balancer"]),
        "level": rng.choices(["INFO", "WARN", "ERROR", "DEBUG"], weights=[50, 15, 5, 30])[0],
        "message": rng.choice([
            'GET /api/users 200 0.032s', 'POST /api/orders 201 0.145s',
            'GET /api/products 304 0.008s', 'GET /static/main.js 200 0.002s',
            'POST /api/login 401 0.023s', 'GET /admin 403 0.005s',
            'GET /api/health 200 0.001s', 'GET /api/orders?page=2 200 0.056s',
            'connection timeout upstream', 'SSL handshake failed',
            'worker process exited on signal 9', 'upstream server unavailable'
        ])
    }


def make_apache(rng):
    return {
        "timestamp": f"{WEEKDAYS[rng.randint(0, 6)]} {MONTHS[rng.randint(0, 11)]} "
                     f"{rng.randint(1, 28):02d} {rng.randint(0, 23):02d}:"
                     f"{rng.randint(0, 59):02d}:{rng.randint(0, 59):02d} 2024",
        "source": rng.choice(["httpd", "mod_ssl", "mod_rewrite"]),
        "level": rng.choices(["NOTICE", "WARN", "ERROR", "INFO"], weights=[40, 15, 5, 40])[0],
        "message": rng.choice([
            "server configured", "caught SIGTERM", "resuming normal ops",
            "request exceeded limit", "file does not exist",
            "client denied by server", "Invalid method in request"
        ])
    }


def make_json_app(rng):
    return {
        "timestamp": f"2024-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}T"
                     f"{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}:"
                     f"{rng.randint(0, 59):02d}.{rng.randint(0, 999):03d}Z",
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


def make_custom(rng):
    return {
        "timestamp": str(STABLE_EPOCH - rng.randint(0, 86400)),
        "source": rng.choice(["cron", "systemd", "kernel", "docker"]),
        "level": rng.choices(["INFO", "WARNING", "ERROR", "DEBUG"], weights=[40, 20, 5, 35])[0],
        "message": rng.choice([
            "OOM killer invoked", "disk usage above 90%", "container restarted",
            "NTP sync lost", "process oom_score_adj=500",
            "firewall rule updated", "mount point not found"
        ])
    }


LOG_TEMPLATES = {
    "nginx": {"pattern": r'(?P<timestamp>\S+ \+\d{4}) (?P<source>\S+) (?P<level>\w+) (?P<message>.+)', "generator": make_nginx},
    "apache": {"pattern": r'\[(?P<timestamp>[^\]]+)\] \[(?P<level>\w+)\] \[(?P<source>\S+)\] (?P<message>.+)', "generator": make_apache},
    "json_app": {"pattern": None, "generator": make_json_app},
    "custom": {"pattern": None, "generator": make_custom},
}


class GenerateRequest(BaseModel):
    type: str = "nginx"
    count: int = 1000


class DetectRequest(BaseModel):
    logs: list = []
    rules: list = []
    query: str = ""


@app.post("/api/generate")
def generate_logs(req: GenerateRequest):
    log_type = req.type if req.type in LOG_TEMPLATES else "nginx"
    count = max(req.count, 0)
    # The seed contains exactly the request parameters, so regenerating the
    # same parameters gives the same logs, windows, scores and decisions.
    rng = random.Random(f"log-generator:v1:{log_type}:{count}")
    tmpl = LOG_TEMPLATES[log_type]

    logs = []
    for i in range(count):
        entry = tmpl["generator"](rng)
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


def normalize_logs(logs_data):
    if not isinstance(logs_data, list):
        return []

    logs = []
    for i, item in enumerate(logs_data):
        if not isinstance(item, dict):
            item = {}
        timestamp = str(item.get("timestamp") or "")
        level = str(item.get("level") or "UNKNOWN").upper()
        source = str(item.get("source") or "unknown")
        message = str(item.get("message") or "")
        raw = str(item.get("raw") or f"[{timestamp}] [{level}] [{source}] {message}")

        try:
            log_id = int(item.get("id", i + 1))
        except (TypeError, ValueError):
            log_id = i + 1

        logs.append({
            "id": log_id,
            "timestamp": timestamp,
            "level": level,
            "source": source,
            "message": message,
            "raw": raw,
        })
    return logs


def build_windows(logs):
    window_records = []
    for index, start in enumerate(range(0, len(logs), WINDOW_SIZE)):
        chunk = logs[start:start + WINDOW_SIZE]
        levels = Counter(log["level"] for log in chunk)
        error_count = levels.get("ERROR", 0)
        count = len(chunk)
        window = {
            "index": index,
            "windowIndex": index,
            "start": start,
            "end": start + count,
            "count": count,
            "capacity": WINDOW_SIZE,
            "coverage": round(count / WINDOW_SIZE, 4),
            "errorCount": error_count,
            "errorRate": round(error_count / count, 4) if count else 0.0,
            "errorCoverage": round(error_count / WINDOW_SIZE, 4),
            "levels": dict(levels),
            "sources": dict(Counter(log["source"] for log in chunk)),
            "timestamp": chunk[0]["timestamp"] if chunk else "",
        }
        window_records.append((window, chunk))
    return window_records


def percentile(values, q):
    ordered = sorted(values)
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def score_windows(windows):
    if not windows:
        return []

    def insufficient_score(window):
        return {
            "windowIndex": window["index"],
            "sigmaScore": 0.0,
            "iqrScore": 0.0,
            "isAnomaly": False,
            "status": "insufficient_samples",
            "timestamp": window["timestamp"],
        }

    if len(windows) < MIN_WINDOWS_FOR_STATISTICAL_DETECTION:
        return [insufficient_score(window) for window in windows]

    counts = [window["count"] for window in windows]
    mean = sum(counts) / len(counts)
    variance = sum((count - mean) ** 2 for count in counts) / len(counts)
    std = math.sqrt(variance)
    q1 = percentile(counts, 0.25)
    q3 = percentile(counts, 0.75)
    iqr = q3 - q1 if q3 > q1 else 1.0

    anomalies = []
    for window in windows:
        count = window["count"]
        sigma_score = abs(count - mean) / max(std, 1e-5)

        iqr_low = q1 - 1.5 * iqr
        iqr_high = q3 + 1.5 * iqr
        iqr_score = 0.0
        if count < iqr_low or count > iqr_high:
            iqr_score = min(10.0, abs(count - mean) / max(iqr, 1e-5))

        sigma_score = round(float(sigma_score), 2)
        iqr_score = round(float(iqr_score), 2)
        is_anomaly = sigma_score > SIGMA_THRESHOLD or iqr_score > IQR_THRESHOLD
        anomalies.append({
            "windowIndex": window["index"],
            "sigmaScore": sigma_score,
            "iqrScore": iqr_score,
            "isAnomaly": is_anomaly,
            "status": "anomaly" if is_anomaly else "normal",
            "timestamp": window["timestamp"],
        })
    return anomalies


def numeric_threshold(value, default):
    try:
        threshold = float(value)
    except (TypeError, ValueError):
        return default
    return threshold if math.isfinite(threshold) and threshold >= 0 else default


def evaluate_rules(window_records, rules):
    alerts = []

    def add_alert(rule_name, severity, message, timestamp):
        alerts.append({
            "id": len(alerts) + 1,
            "ruleName": rule_name,
            "severity": severity,
            "message": message,
            "timestamp": timestamp,
        })

    if not isinstance(rules, list):
        return alerts

    for raw_rule in rules:
        rule = raw_rule if isinstance(raw_rule, dict) else {}
        rule_type = rule.get("type")
        rule_name = str(rule.get("name") or "")

        if rule_type == "level":
            threshold = numeric_threshold(rule.get("threshold", DEFAULT_ERROR_THRESHOLD), DEFAULT_ERROR_THRESHOLD)
            coverage_threshold = threshold / WINDOW_SIZE
            for window, _ in window_records:
                if window["errorCoverage"] > coverage_threshold:
                    add_alert(
                        rule_name or "高频ERROR",
                        "high",
                        f"窗口{window['index']} ERROR覆盖率{window['errorCoverage']:.1%}"
                        f"（{window['errorCount']}/{window['capacity']}），超过阈值{coverage_threshold:.1%}",
                        window["timestamp"],
                    )

        if rule_type == "count":
            threshold = numeric_threshold(rule.get("threshold", DEFAULT_TRAFFIC_THRESHOLD), DEFAULT_TRAFFIC_THRESHOLD)
            coverage_threshold = threshold / WINDOW_SIZE
            for window, _ in window_records:
                if window["coverage"] > coverage_threshold:
                    add_alert(
                        rule_name or "异常流量",
                        "medium",
                        f"窗口{window['index']}流量覆盖率{window['coverage']:.1%}"
                        f"（{window['count']}/{window['capacity']}），超过阈值{coverage_threshold:.1%}",
                        window["timestamp"],
                    )

    return alerts


def search_logs(logs, query):
    terms = query.strip().lower().split()
    if not terms:
        return logs[:200]

    scored = []
    for index, log in enumerate(logs):
        raw_lower = log["raw"].lower()
        score = sum(1 for term in terms if term in raw_lower)
        if score > 0:
            scored.append((score, index, log))

    scored.sort(key=lambda item: (-item[0], item[1]))
    return [item[2] for item in scored[:200]]


def analyze_logs(logs_data, rules, query):
    # Keep one canonical, ordered copy of the input logs. Search results only
    # affect the displayed logs; they must not change the windows or scores.
    all_logs = normalize_logs(logs_data)
    window_records = build_windows(all_logs)
    windows = [window for window, _ in window_records]
    anomalies = score_windows(windows)
    alerts = evaluate_rules(window_records, rules)

    for anomaly in anomalies:
        if anomaly["isAnomaly"]:
            alerts.append({
                "id": len(alerts) + 1,
                "ruleName": "统计异常检测",
                "severity": "critical" if anomaly["sigmaScore"] > 4 else "high",
                "message": f"窗口{anomaly['windowIndex']}: 3-sigma={anomaly['sigmaScore']}, IQR={anomaly['iqrScore']}",
                "timestamp": anomaly["timestamp"],
            })

    return {
        "logs": search_logs(all_logs, query or ""),
        "allLogs": all_logs,
        "windows": windows,
        "anomalies": anomalies,
        "alerts": alerts[:20],
        "totalLogs": len(all_logs),
        "metadata": {
            "windowSize": WINDOW_SIZE,
            "minWindows": MIN_WINDOWS_FOR_STATISTICAL_DETECTION,
            "sigmaThreshold": SIGMA_THRESHOLD,
            "iqrThreshold": IQR_THRESHOLD,
            "windowCount": len(windows),
            "reliable": len(windows) >= MIN_WINDOWS_FOR_STATISTICAL_DETECTION,
            "defaultThresholds": {
                "level": DEFAULT_ERROR_THRESHOLD,
                "count": DEFAULT_TRAFFIC_THRESHOLD,
            },
        },
    }
