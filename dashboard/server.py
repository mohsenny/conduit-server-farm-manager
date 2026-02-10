import argparse
import json
import os
import re
import sqlite3
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from urllib.request import urlopen, Request

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH_DEFAULT = os.path.join(ROOT_DIR, "config.json")
DB_PATH_DEFAULT = os.path.join(ROOT_DIR, "data.db")
POLL_INTERVAL_DEFAULT = 10
MAX_SERIES_POINTS = 600
COUNTRY_TOP_N_DEFAULT = 12

METRIC_RE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{.*\})?\s+([-+eE0-9\.]+)$")
LABEL_RE = re.compile(r"(\w+)=" "\"((?:\\.|[^\"])*)\"")

STATE_LOCK = threading.Lock()
STATE = {
    "vps": {},
    "last_fetch": None,
    "last_error": None,
}

CACHE_LOCK = threading.Lock()
AGENT_SUMMARY_CACHE = {}
AGENT_TIMESERIES_CACHE = {}
SYS_CACHE = {}
TIMESERIES_CACHE = {}

AGENT_CACHE_TTL_MIN = 2
AGENT_CACHE_TTL_MAX = 15


def cache_ttl(poll_interval):
    try:
        poll = int(poll_interval)
    except Exception:
        poll = POLL_INTERVAL_DEFAULT
    ttl = max(AGENT_CACHE_TTL_MIN, min(AGENT_CACHE_TTL_MAX, poll // 2))
    return ttl if ttl > 0 else AGENT_CACHE_TTL_MIN


def timeseries_cache_ttl(range_value, poll_interval):
    if not range_value or range_value == "all":
        return max(120, poll_interval * 6)
    if range_value.endswith("h"):
        hours = int(range_value[:-1] or 0)
        if hours <= 1:
            return max(10, poll_interval)
        if hours <= 5:
            return max(15, poll_interval * 2)
        return max(60, poll_interval * 6)
    if range_value.endswith("d"):
        days = int(range_value[:-1] or 0)
        if days <= 1:
            return max(30, poll_interval * 3)
        if days <= 7:
            return max(120, poll_interval * 12)
        return max(300, poll_interval * 30)
    return max(60, poll_interval * 6)


def cached_fetch(cache, key, ttl, fetcher):
    now = time.time()
    with CACHE_LOCK:
        entry = cache.get(key)
        if entry and (now - entry["ts"] < ttl) and entry.get("data") is not None:
            return entry["data"], entry.get("error")
    try:
        data = fetcher()
    except Exception as exc:
        if entry and entry.get("data") is not None:
            with CACHE_LOCK:
                entry["error"] = str(exc)
                cache[key] = entry
            return entry["data"], str(exc)
        raise
    with CACHE_LOCK:
        cache[key] = {"ts": now, "data": data, "error": None}
    return data, None


def parse_labels(raw):
    if not raw:
        return {}
    raw = raw.strip("{}")
    labels = {}
    for match in LABEL_RE.finditer(raw):
        key = match.group(1)
        val = match.group(2).replace("\\\"", "\"")
        labels[key] = val
    return labels


def parse_prometheus(text):
    metrics = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = METRIC_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        labels = parse_labels(m.group(2))
        try:
            value = float(m.group(3))
        except ValueError:
            continue
        metrics.setdefault(name, []).append({"labels": labels, "value": value})
    return metrics


def metric_names(metrics):
    return sorted(metrics.keys())


def pick_metric_name(metrics, candidates):
    for candidate in candidates:
        for name in metrics.keys():
            if candidate in name:
                return name
    return ""


def sum_metric(metrics, name):
    if not name or name not in metrics:
        return None
    return sum(sample["value"] for sample in metrics[name])


def top_countries(metrics, country_metric, country_label):
    if not country_metric or country_metric not in metrics:
        return []
    totals = {}
    for sample in metrics[country_metric]:
        labels = sample["labels"]
        if country_label not in labels:
            continue
        country = labels[country_label]
        totals[country] = totals.get(country, 0.0) + sample["value"]
    rows = [{"country": k, "value": v} for k, v in totals.items()]
    rows.sort(key=lambda r: r["value"], reverse=True)
    return rows[:10]


def init_db(db_path):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS samples (
            ts INTEGER PRIMARY KEY,
            clients REAL,
            bytes_up REAL,
            bytes_down REAL
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS samples_vps (
            ts INTEGER,
            vps TEXT,
            clients REAL,
            bytes_up REAL,
            bytes_down REAL,
            PRIMARY KEY (ts, vps)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS country_samples (
            ts INTEGER,
            country TEXT,
            value REAL,
            metric TEXT,
            PRIMARY KEY (ts, country, metric)
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS country_samples_vps (
            ts INTEGER,
            vps TEXT,
            country TEXT,
            value REAL,
            metric TEXT,
            PRIMARY KEY (ts, vps, country, metric)
        )
        """
    )
    conn.commit()
    conn.close()


def migrate_legacy_samples(db_path, vps_id):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(1) FROM samples")
    legacy_samples = cur.fetchone()[0] or 0
    cur.execute("SELECT COUNT(1) FROM samples_vps WHERE vps = ?", (vps_id,))
    vps_samples = cur.fetchone()[0] or 0
    if legacy_samples > 0 and vps_samples < legacy_samples:
        cur.execute(
            "INSERT OR IGNORE INTO samples_vps (ts, vps, clients, bytes_up, bytes_down) "
            "SELECT ts, ?, clients, bytes_up, bytes_down FROM samples",
            (vps_id,),
        )
    cur.execute("SELECT COUNT(1) FROM country_samples")
    legacy_country = cur.fetchone()[0] or 0
    cur.execute("SELECT COUNT(1) FROM country_samples_vps WHERE vps = ?", (vps_id,))
    vps_country = cur.fetchone()[0] or 0
    if legacy_country > 0 and vps_country < legacy_country:
        cur.execute(
            "INSERT OR IGNORE INTO country_samples_vps (ts, vps, country, value, metric) "
            "SELECT ts, ?, country, value, metric FROM country_samples",
            (vps_id,),
        )
    conn.commit()
    conn.close()


def store_sample(db_path, ts, clients, bytes_up, bytes_down, vps_id=None):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    if vps_id:
        cur.execute(
            "INSERT OR REPLACE INTO samples_vps (ts, vps, clients, bytes_up, bytes_down) VALUES (?, ?, ?, ?, ?)",
            (ts, vps_id, clients, bytes_up, bytes_down),
        )
    else:
        cur.execute(
            "INSERT OR REPLACE INTO samples (ts, clients, bytes_up, bytes_down) VALUES (?, ?, ?, ?)",
            (ts, clients, bytes_up, bytes_down),
        )
    conn.commit()
    conn.close()


def store_country_samples(db_path, ts, metric, country_rows, vps_id=None):
    if not country_rows:
        return
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    if vps_id:
        cur.executemany(
            "INSERT OR REPLACE INTO country_samples_vps (ts, vps, country, value, metric) VALUES (?, ?, ?, ?, ?)",
            [(ts, vps_id, row["country"], row["value"], metric) for row in country_rows],
        )
    else:
        cur.executemany(
            "INSERT OR REPLACE INTO country_samples (ts, country, value, metric) VALUES (?, ?, ?, ?)",
            [(ts, row["country"], row["value"], metric) for row in country_rows],
        )
    conn.commit()
    conn.close()


def parse_range(value):
    if not value or value == "all":
        return None
    if value.endswith("h"):
        return int(value[:-1]) * 3600
    if value.endswith("d"):
        return int(value[:-1]) * 86400
    return None


def compute_bucket(range_sec, poll_interval):
    try:
        poll = int(poll_interval)
    except Exception:
        poll = POLL_INTERVAL_DEFAULT
    if not range_sec:
        return max(poll, 3600)
    bucket = int(range_sec / MAX_SERIES_POINTS) if range_sec else poll
    if bucket < poll:
        bucket = poll
    if bucket < 1:
        bucket = 1
    return bucket


def downsample_series(series, bucket_sec):
    if not series or not bucket_sec or bucket_sec <= 1:
        return series
    buckets = {}
    for row in series:
        ts = row.get("ts")
        if ts is None:
            continue
        bucket = ts - (ts % bucket_sec)
        existing = buckets.get(bucket)
        if not existing or ts >= existing.get("ts", 0):
            buckets[bucket] = {
                "ts": bucket,
                "clients": row.get("clients"),
                "bytes_up": row.get("bytes_up"),
                "bytes_down": row.get("bytes_down"),
            }
    return [buckets[k] for k in sorted(buckets.keys())]


def downsample_country_series(country_series, bucket_sec):
    if not country_series or not bucket_sec or bucket_sec <= 1:
        return country_series
    merged = {}
    for key, rows in country_series.items():
        for row in rows:
            ts = row.get("ts")
            if ts is None:
                continue
            bucket = ts - (ts % bucket_sec)
            mkey = (key, bucket)
            existing = merged.get(mkey)
            if not existing or ts >= existing.get("ts", 0):
                merged[mkey] = {
                    "ts": bucket,
                    "value": row.get("value"),
                    "country": row.get("country"),
                    "metric": row.get("metric"),
                }
    out = {}
    for (key, _), row in merged.items():
        out.setdefault(key, []).append(row)
    for key in out.keys():
        out[key].sort(key=lambda r: r["ts"])
    return out


def limit_country_series(country_series, limit):
    if not country_series or not limit:
        return country_series
    ranked = []
    for key, rows in country_series.items():
        if not rows:
            continue
        last = rows[-1]
        val = last.get("value") or 0.0
        ranked.append((key, val))
    ranked.sort(key=lambda r: r[1], reverse=True)
    keep = {key for key, _ in ranked[:limit]}
    return {key: rows for key, rows in country_series.items() if key in keep}


def build_status(last_error, last_fetch, poll_interval):
    age_sec = None
    stale = False
    if last_fetch:
        age_sec = max(0, int(time.time() - last_fetch))
        stale = age_sec > max(30, int(poll_interval) * 3)
    return {
        "metrics_ok": last_error is None,
        "last_error": last_error,
        "age_sec": age_sec,
        "stale": stale,
    }


def detect_metrics(metrics, config):
    clients_metric = config.get("clients_metric") or ""
    bytes_up_metric = config.get("bytes_up_metric") or ""
    bytes_down_metric = config.get("bytes_down_metric") or ""
    country_metric = config.get("country_metric") or ""
    country_label = config.get("country_label") or "country"
    auto_detected = False
    if metrics:
        if not clients_metric:
            clients_metric = pick_metric_name(metrics, [
                "connected_clients", "clients_connected", "clients", "conduit_clients"
            ])
            auto_detected = True if clients_metric else auto_detected
        if not bytes_up_metric:
            bytes_up_metric = pick_metric_name(metrics, [
                "bytes_sent", "bytes_out", "upload_bytes", "tx_bytes", "egress_bytes", "bytes_uploaded"
            ])
            auto_detected = True if bytes_up_metric else auto_detected
        if not bytes_down_metric:
            bytes_down_metric = pick_metric_name(metrics, [
                "bytes_received", "bytes_in", "download_bytes", "rx_bytes", "ingress_bytes", "bytes_downloaded"
            ])
            auto_detected = True if bytes_down_metric else auto_detected
        if not country_metric:
            country_metric = pick_metric_name(metrics, [
                "country", "countries"
            ])
            auto_detected = True if country_metric else auto_detected
    return {
        "clients_metric": clients_metric,
        "bytes_up_metric": bytes_up_metric,
        "bytes_down_metric": bytes_down_metric,
        "country_metric": country_metric,
        "country_label": country_label,
        "auto_detected": auto_detected,
    }


def load_series(db_path, range_sec, vps_id=None, bucket_sec=None, since_ts=None):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    if since_ts is None and range_sec:
        since_ts = int(time.time()) - range_sec
    if bucket_sec and bucket_sec > 1:
        if vps_id:
            params = [bucket_sec, bucket_sec, vps_id]
            where = "WHERE vps = ?"
            if since_ts is not None:
                where += " AND ts >= ?"
                params.append(since_ts)
            cur.execute(
                f"""
                SELECT bucket, AVG(clients), MAX(bytes_up), MAX(bytes_down)
                FROM (
                    SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, clients, bytes_up, bytes_down
                    FROM samples_vps {where}
                )
                GROUP BY bucket
                ORDER BY bucket
                """,
                params,
            )
        else:
            cur.execute("SELECT COUNT(1) FROM samples_vps")
            has_multi = cur.fetchone()[0] > 0
            if has_multi:
                params = [bucket_sec, bucket_sec]
                where = ""
                if since_ts is not None:
                    where = "WHERE ts >= ?"
                    params.append(since_ts)
                cur.execute(
                    f"""
                    WITH per_vps AS (
                        SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, vps,
                               AVG(clients) AS clients,
                               MAX(bytes_up) AS bytes_up,
                               MAX(bytes_down) AS bytes_down
                        FROM samples_vps
                        {where}
                        GROUP BY bucket, vps
                    )
                    SELECT bucket, SUM(clients), SUM(bytes_up), SUM(bytes_down)
                    FROM per_vps
                    GROUP BY bucket
                    ORDER BY bucket
                    """,
                    params,
                )
            else:
                params = [bucket_sec, bucket_sec]
                where = ""
                if since_ts is not None:
                    where = "WHERE ts >= ?"
                    params.append(since_ts)
                cur.execute(
                    f"""
                    SELECT bucket, AVG(clients), MAX(bytes_up), MAX(bytes_down)
                    FROM (
                        SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, clients, bytes_up, bytes_down
                        FROM samples
                        {where}
                    )
                    GROUP BY bucket
                    ORDER BY bucket
                    """,
                    params,
                )
    else:
        if vps_id:
            if since_ts is not None:
                cur.execute(
                    "SELECT ts, clients, bytes_up, bytes_down FROM samples_vps WHERE vps = ? AND ts >= ? ORDER BY ts",
                    (vps_id, since_ts),
                )
            else:
                cur.execute(
                    "SELECT ts, clients, bytes_up, bytes_down FROM samples_vps WHERE vps = ? ORDER BY ts",
                    (vps_id,),
                )
        else:
            cur.execute("SELECT COUNT(1) FROM samples_vps")
            has_multi = cur.fetchone()[0] > 0
            if has_multi:
                if since_ts is not None:
                    cur.execute(
                        "SELECT ts, SUM(clients), SUM(bytes_up), SUM(bytes_down) FROM samples_vps WHERE ts >= ? GROUP BY ts ORDER BY ts",
                        (since_ts,),
                    )
                else:
                    cur.execute(
                        "SELECT ts, SUM(clients), SUM(bytes_up), SUM(bytes_down) FROM samples_vps GROUP BY ts ORDER BY ts"
                    )
            else:
                if since_ts is not None:
                    cur.execute("SELECT ts, clients, bytes_up, bytes_down FROM samples WHERE ts >= ? ORDER BY ts", (since_ts,))
                else:
                    cur.execute("SELECT ts, clients, bytes_up, bytes_down FROM samples ORDER BY ts")
    rows = cur.fetchall()
    conn.close()
    return [
        {"ts": ts, "clients": clients, "bytes_up": bytes_up, "bytes_down": bytes_down}
        for ts, clients, bytes_up, bytes_down in rows
    ]


def load_latest_sample(db_path, vps_id=None):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    row = None
    if vps_id:
        cur.execute(
            "SELECT ts, clients, bytes_up, bytes_down FROM samples_vps WHERE vps = ? ORDER BY ts DESC LIMIT 1",
            (vps_id,),
        )
        row = cur.fetchone()
    else:
        cur.execute("SELECT COUNT(1) FROM samples_vps")
        has_multi = cur.fetchone()[0] > 0
        if has_multi:
            cur.execute(
                "SELECT ts, SUM(clients), SUM(bytes_up), SUM(bytes_down) FROM samples_vps GROUP BY ts ORDER BY ts DESC LIMIT 1"
            )
            row = cur.fetchone()
        else:
            cur.execute(
                "SELECT ts, clients, bytes_up, bytes_down FROM samples ORDER BY ts DESC LIMIT 1"
            )
            row = cur.fetchone()
    conn.close()
    if not row:
        return None
    return {"ts": row[0], "clients": row[1], "bytes_up": row[2], "bytes_down": row[3]}


def load_country_series(db_path, range_sec, vps_id=None, bucket_sec=None, since_ts=None):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    if since_ts is None and range_sec:
        since_ts = int(time.time()) - range_sec
    if bucket_sec and bucket_sec > 1:
        if vps_id:
            params = [bucket_sec, bucket_sec, vps_id]
            where = "WHERE vps = ?"
            if since_ts is not None:
                where += " AND ts >= ?"
                params.append(since_ts)
            cur.execute(
                f"""
                SELECT bucket, country, AVG(value), metric
                FROM (
                    SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, country, value, metric
                    FROM country_samples_vps {where}
                )
                GROUP BY bucket, country, metric
                ORDER BY bucket
                """,
                params,
            )
        else:
            cur.execute("SELECT COUNT(1) FROM country_samples_vps")
            has_multi = cur.fetchone()[0] > 0
            if has_multi:
                params = [bucket_sec, bucket_sec]
                where = ""
                if since_ts is not None:
                    where = "WHERE ts >= ?"
                    params.append(since_ts)
                cur.execute(
                    f"""
                    WITH per_vps AS (
                        SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, vps, country, metric,
                               AVG(value) AS value
                        FROM country_samples_vps
                        {where}
                        GROUP BY bucket, vps, country, metric
                    )
                    SELECT bucket, country, SUM(value), metric
                    FROM per_vps
                    GROUP BY bucket, country, metric
                    ORDER BY bucket
                    """,
                    params,
                )
            else:
                params = [bucket_sec, bucket_sec]
                where = ""
                if since_ts is not None:
                    where = "WHERE ts >= ?"
                    params.append(since_ts)
                cur.execute(
                    f"""
                    SELECT bucket, country, AVG(value), metric
                    FROM (
                        SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, country, value, metric
                        FROM country_samples
                        {where}
                    )
                    GROUP BY bucket, country, metric
                    ORDER BY bucket
                    """,
                    params,
                )
    else:
        if vps_id:
            if since_ts is not None:
                cur.execute(
                    "SELECT ts, country, value, metric FROM country_samples_vps WHERE vps = ? AND ts >= ? ORDER BY ts",
                    (vps_id, since_ts),
                )
            else:
                cur.execute(
                    "SELECT ts, country, value, metric FROM country_samples_vps WHERE vps = ? ORDER BY ts",
                    (vps_id,),
                )
        else:
            cur.execute("SELECT COUNT(1) FROM country_samples_vps")
            has_multi = cur.fetchone()[0] > 0
            if has_multi:
                if since_ts is not None:
                    cur.execute(
                        "SELECT ts, country, SUM(value), metric FROM country_samples_vps WHERE ts >= ? GROUP BY ts, country, metric ORDER BY ts",
                        (since_ts,),
                    )
                else:
                    cur.execute(
                        "SELECT ts, country, SUM(value), metric FROM country_samples_vps GROUP BY ts, country, metric ORDER BY ts"
                    )
            else:
                if since_ts is not None:
                    cur.execute(
                        "SELECT ts, country, value, metric FROM country_samples WHERE ts >= ? ORDER BY ts",
                        (since_ts,),
                    )
                else:
                    cur.execute("SELECT ts, country, value, metric FROM country_samples ORDER BY ts")
    rows = cur.fetchall()
    conn.close()
    series = {}
    for ts, country, value, metric in rows:
        key = f"{metric}:{country}"
        series.setdefault(key, []).append({"ts": ts, "value": value, "country": country, "metric": metric})
    return series


def collector_loop(vps_list, config, db_path, poll_interval):
    while True:
        ts = int(time.time())
        any_success = False
        last_error = None
        for vps in vps_list:
            vps_id = vps.get("id")
            metrics_url = vps.get("metrics_url")
            geo_url = vps.get("geo_url") or ""
            sys_url = vps.get("sys_url") or ""
            metrics_error = None
            try:
                metrics = fetch_metrics(metrics_url)
                names = metric_names(metrics)

                clients_metric = config.get("clients_metric") or ""
                bytes_up_metric = config.get("bytes_up_metric") or ""
                bytes_down_metric = config.get("bytes_down_metric") or ""
                country_metric = config.get("country_metric") or ""
                country_label = config.get("country_label") or "country"

                if not clients_metric:
                    clients_metric = pick_metric_name(metrics, [
                        "connected_clients", "clients_connected", "clients", "conduit_clients"
                    ])
                if not bytes_up_metric:
                    bytes_up_metric = pick_metric_name(metrics, [
                        "bytes_sent", "bytes_out", "upload_bytes", "tx_bytes", "egress_bytes", "bytes_uploaded"
                    ])
                if not bytes_down_metric:
                    bytes_down_metric = pick_metric_name(metrics, [
                        "bytes_received", "bytes_in", "download_bytes", "rx_bytes", "ingress_bytes", "bytes_downloaded"
                    ])

                clients_val = sum_metric(metrics, clients_metric)
                up_val = sum_metric(metrics, bytes_up_metric)
                down_val = sum_metric(metrics, bytes_down_metric)

                store_sample(db_path, ts, clients_val, up_val, down_val, vps_id=vps_id)
                if country_metric:
                    store_country_samples(
                        db_path, ts, country_metric,
                        top_countries(metrics, country_metric, country_label),
                        vps_id=vps_id
                    )

                conduit_is_live = sum_metric(metrics, "conduit_is_live")
                conduit_announcing = sum_metric(metrics, "conduit_announcing")
                conduit_connecting = sum_metric(metrics, "conduit_connecting_clients")
                conduit_connected = sum_metric(metrics, "conduit_connected_clients")

                with STATE_LOCK:
                    STATE["vps"][vps_id] = {
                        "metrics": metrics,
                        "metric_names": names,
                        "last_fetch": ts,
                        "last_error": None,
                        "clients_value": clients_val,
                        "bytes_up_value": up_val,
                        "bytes_down_value": down_val,
                        "host": vps.get("host"),
                        "conduit": {
                            "is_live": conduit_is_live,
                            "announcing": conduit_announcing,
                            "connecting": conduit_connecting,
                            "connected": conduit_connected,
                        },
                        "system": STATE["vps"].get(vps_id, {}).get("system"),
                    }
                any_success = True
            except Exception as exc:
                metrics_error = str(exc)
                with STATE_LOCK:
                    existing = STATE["vps"].get(vps_id, {})
                    existing["last_error"] = metrics_error
                    STATE["vps"][vps_id] = existing
                last_error = metrics_error

            if geo_url:
                try:
                    geo = fetch_geo(geo_url)
                    rows = []
                    for row in geo.get("countries", []):
                        country = row.get("country")
                        value = row.get("clients")
                        if country and value is not None:
                            rows.append({"country": country, "value": float(value)})
                    store_country_samples(db_path, ts, "geo_active_clients", rows, vps_id=vps_id)
                except Exception:
                    pass

            if sys_url:
                sys_data = None
                try:
                    sys_data = fetch_sys(sys_url)
                except Exception as exc:
                    sys_data = {"error": str(exc)}
                with STATE_LOCK:
                    existing = STATE["vps"].get(vps_id, {})
                    existing["system"] = sys_data
                    STATE["vps"][vps_id] = existing

        with STATE_LOCK:
            STATE["last_fetch"] = ts if any_success else STATE.get("last_fetch")
            if not any_success and last_error:
                STATE["last_error"] = last_error
            elif any_success:
                STATE["last_error"] = None
        time.sleep(poll_interval)


class DashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.metrics_url = kwargs.pop("metrics_url")
        self.config = kwargs.pop("config")
        self.db_path = kwargs.pop("db_path")
        super().__init__(*args, directory=ROOT_DIR, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        super().end_headers()

    def do_GET(self):
        if self.path.startswith("/api/summary"):
            self.handle_summary()
            return
        if self.path.startswith("/api/vps_sparks"):
            self.handle_vps_sparks()
            return
        if self.path.startswith("/api/vps"):
            self.handle_vps()
            return
        if self.path.startswith("/api/metrics"):
            self.handle_metrics()
            return
        if self.path.startswith("/api/timeseries"):
            self.handle_timeseries()
            return
        super().do_GET()

    def handle_metrics(self):
        try:
            params = parse_qs(urlparse(self.path).query)
            vps_id = params.get("vps", [""])[0]
            metrics_url = self.metrics_url
            if vps_id:
                for vps in self.config.get("vps", []):
                    if vps.get("id") == vps_id:
                        metrics_url = vps.get("metrics_url") or metrics_url
                        break
            elif self.config.get("vps"):
                metrics_url = self.config["vps"][0].get("metrics_url") or metrics_url
            metrics = fetch_metrics(metrics_url)
            payload = {"metrics": metrics}
            self.send_json(payload)
        except Exception as exc:
            self.safe_send_error(502, f"Failed to fetch metrics: {exc}")

    def handle_summary(self):
        try:
            params = parse_qs(urlparse(self.path).query)
            vps_id = params.get("vps", [""])[0]
            poll_interval = int(self.config.get("poll_interval_sec") or POLL_INTERVAL_DEFAULT)
            if self.config.get("use_agent"):
                ttl = cache_ttl(poll_interval)
                vps_list = self.config.get("vps", [])
                if vps_id:
                    target = next((v for v in vps_list if v.get("id") == vps_id), None)
                    if not target:
                        self.safe_send_error(404, "Unknown VPS")
                        return
                    agent_url = target.get("agent_url")
                    if not agent_url:
                        summary = {
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "last_fetch": None,
                            "metric_count": 0,
                            "selected": {
                                "clients_metric": "conduit_connected_clients",
                                "bytes_up_metric": "conduit_bytes_uploaded",
                                "bytes_down_metric": "conduit_bytes_downloaded",
                                "clients_value": None,
                                "bytes_up_value": None,
                                "bytes_down_value": None,
                                "auto_detected": True,
                            },
                            "status": build_status("Agent not configured for this VPS", None, poll_interval),
                            "conduit": {},
                            "system": None,
                            "countries": [],
                            "vps_id": vps_id,
                            "vps_ip": target.get("host") or vps_id,
                        }
                        self.send_json(summary)
                        return
                    try:
                        agent, agent_err = get_agent_summary(agent_url, ttl)
                    except Exception as exc:
                        agent = None
                        agent_err = str(exc)
                    latest = (agent or {}).get("latest") or {}
                    totals = (agent or {}).get("totals") or {}
                    status = (agent or {}).get("status") or {}
                    system = None
                    if target.get("sys_url"):
                        try:
                            system, _ = get_sys_data(target.get("sys_url"), ttl)
                        except Exception:
                            system = None
                    status_error = agent_err or status.get("last_error")
                    bytes_up_total = totals.get("bytes_up")
                    bytes_down_total = totals.get("bytes_down")
                    summary = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "last_fetch": (agent or {}).get("last_fetch"),
                        "metric_count": 0,
                        "selected": {
                            "clients_metric": "conduit_connected_clients",
                            "bytes_up_metric": "conduit_bytes_uploaded",
                            "bytes_down_metric": "conduit_bytes_downloaded",
                            "clients_value": latest.get("clients"),
                            "bytes_up_value": bytes_up_total if bytes_up_total is not None else latest.get("bytes_up"),
                            "bytes_down_value": bytes_down_total if bytes_down_total is not None else latest.get("bytes_down"),
                            "auto_detected": True,
                        },
                        "status": build_status(status_error, (agent or {}).get("last_fetch"), poll_interval),
                        "conduit": {},
                        "system": system,
                        "countries": [],
                        "vps_id": vps_id,
                        "vps_ip": target.get("host") or vps_id,
                    }
                    self.send_json(summary)
                    return

                totals = {"clients": 0.0, "bytes_up": 0.0, "bytes_down": 0.0}
                last_fetch = None
                last_error = None
                for vps in vps_list:
                    agent_url = vps.get("agent_url")
                    if not agent_url:
                        continue
                    try:
                        agent, agent_err = get_agent_summary(agent_url, ttl)
                    except Exception as exc:
                        agent = None
                        agent_err = str(exc)
                    latest = (agent or {}).get("latest") or {}
                    ag_totals = (agent or {}).get("totals") or {}
                    totals["clients"] += latest.get("clients") or 0.0
                    totals["bytes_up"] += ag_totals.get("bytes_up") if ag_totals.get("bytes_up") is not None else (latest.get("bytes_up") or 0.0)
                    totals["bytes_down"] += ag_totals.get("bytes_down") if ag_totals.get("bytes_down") is not None else (latest.get("bytes_down") or 0.0)
                    if (agent or {}).get("last_fetch"):
                        last_fetch = max(last_fetch or 0, (agent or {}).get("last_fetch"))
                    status = (agent or {}).get("status") or {}
                    if agent_err:
                        last_error = agent_err
                    elif status.get("last_error"):
                        last_error = status.get("last_error")
                summary = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_fetch": last_fetch,
                    "metric_count": 0,
                    "selected": {
                        "clients_metric": "conduit_connected_clients",
                        "bytes_up_metric": "conduit_bytes_uploaded",
                        "bytes_down_metric": "conduit_bytes_downloaded",
                        "clients_value": totals["clients"],
                        "bytes_up_value": totals["bytes_up"],
                        "bytes_down_value": totals["bytes_down"],
                        "auto_detected": True,
                    },
                    "status": build_status(last_error, last_fetch, poll_interval),
                    "conduit": {},
                    "system": None,
                    "countries": [],
                    "vps_count": len(vps_list),
                }
                self.send_json(summary)
                return

            with STATE_LOCK:
                vps_state = dict(STATE["vps"])
                last_error = STATE.get("last_error")
                last_fetch = STATE.get("last_fetch")

            if vps_id:
                state = vps_state.get(vps_id)
                if not state or not state.get("metrics"):
                    raise Exception(state.get("last_error") if state else "No metrics collected yet.")
                metrics = state.get("metrics")
                names = state.get("metric_names", [])
                detected = detect_metrics(metrics, self.config)
                conduit = state.get("conduit") or {}
                latest = load_latest_sample(self.db_path, vps_id=vps_id)
                clients_value = sum_metric(metrics, detected["clients_metric"])
                bytes_up_value = sum_metric(metrics, detected["bytes_up_metric"])
                bytes_down_value = sum_metric(metrics, detected["bytes_down_metric"])
                if latest:
                    clients_value = latest["clients"]
                    bytes_up_value = latest["bytes_up"]
                    bytes_down_value = latest["bytes_down"]
                summary = {
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_fetch": state.get("last_fetch"),
                    "metric_count": len(names),
                    "selected": {
                        "clients_metric": detected["clients_metric"],
                        "bytes_up_metric": detected["bytes_up_metric"],
                        "bytes_down_metric": detected["bytes_down_metric"],
                        "clients_value": clients_value,
                        "bytes_up_value": bytes_up_value,
                        "bytes_down_value": bytes_down_value,
                        "auto_detected": detected["auto_detected"],
                    },
                    "status": build_status(state.get("last_error"), state.get("last_fetch"), poll_interval),
                    "conduit": conduit,
                    "system": state.get("system"),
                    "countries": top_countries(metrics, detected["country_metric"], detected["country_label"]),
                    "vps_id": vps_id,
                    "vps_ip": state.get("host") or vps_id,
                }
                self.send_json(summary)
                return

            total_clients = 0.0
            total_up = 0.0
            total_down = 0.0
            any_metrics = False
            first_metrics = None
            first_names = []
            for _, state in vps_state.items():
                if state.get("metrics") and not first_metrics:
                    first_metrics = state.get("metrics")
                    first_names = state.get("metric_names", [])
                if state.get("clients_value") is not None:
                    total_clients += state.get("clients_value") or 0.0
                if state.get("bytes_up_value") is not None:
                    total_up += state.get("bytes_up_value") or 0.0
                if state.get("bytes_down_value") is not None:
                    total_down += state.get("bytes_down_value") or 0.0
                if state.get("metrics"):
                    any_metrics = True

            if not any_metrics:
                raise Exception(last_error or "No metrics collected yet.")

            detected = detect_metrics(first_metrics, self.config) if first_metrics else detect_metrics(None, self.config)
            latest = load_latest_sample(self.db_path, vps_id=None)
            if latest:
                total_clients = latest["clients"] or 0.0
                total_up = latest["bytes_up"] or 0.0
                total_down = latest["bytes_down"] or 0.0
            summary = {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "last_fetch": last_fetch,
                "metric_count": len(first_names),
                "selected": {
                    "clients_metric": detected["clients_metric"],
                    "bytes_up_metric": detected["bytes_up_metric"],
                    "bytes_down_metric": detected["bytes_down_metric"],
                    "clients_value": total_clients,
                    "bytes_up_value": total_up,
                    "bytes_down_value": total_down,
                    "auto_detected": detected["auto_detected"],
                },
                "status": build_status(last_error, last_fetch, poll_interval),
                "conduit": {},
                "system": None,
                "countries": top_countries(first_metrics, detected["country_metric"], detected["country_label"]) if first_metrics else [],
                "vps_count": len(self.config.get("vps", [])),
            }
            self.send_json(summary)
        except Exception as exc:
            self.safe_send_error(502, f"Failed to fetch summary: {exc}")

    def handle_vps(self):
        try:
            poll_interval = int(self.config.get("poll_interval_sec") or POLL_INTERVAL_DEFAULT)
            ttl = cache_ttl(poll_interval)
            rows = []
            if self.config.get("use_agent"):
                for vps in self.config.get("vps", []):
                    vps_id = vps.get("id")
                    agent_url = vps.get("agent_url")
                    status = {"metrics_ok": False, "last_error": "agent missing"}
                    latest = {}
                    if agent_url:
                        try:
                            agent, agent_err = get_agent_summary(agent_url, ttl)
                        except Exception as exc:
                            agent = None
                            agent_err = str(exc)
                        latest = (agent or {}).get("latest") or {}
                        status_error = agent_err or (agent or {}).get("status", {}).get("last_error")
                        status = build_status(status_error, (agent or {}).get("last_fetch"), poll_interval)
                    system = None
                    if vps.get("sys_url"):
                        try:
                            system, _ = get_sys_data(vps.get("sys_url"), ttl)
                        except Exception:
                            system = None
                    rows.append({
                        "id": vps_id,
                        "label": vps.get("label") or vps_id,
                        "host": vps.get("host"),
                        "status": status,
                        "clients": latest.get("clients"),
                        "bytes_up": latest.get("bytes_up"),
                        "bytes_down": latest.get("bytes_down"),
                        "system": system,
                        "conduit": {},
                    })
            else:
                with STATE_LOCK:
                    vps_state = dict(STATE["vps"])
                for vps in self.config.get("vps", []):
                    vps_id = vps.get("id")
                    state = vps_state.get(vps_id, {})
                    rows.append({
                        "id": vps_id,
                        "label": vps.get("label") or vps_id,
                        "host": vps.get("host"),
                        "status": build_status(state.get("last_error"), state.get("last_fetch"), poll_interval),
                        "clients": state.get("clients_value"),
                        "bytes_up": state.get("bytes_up_value"),
                        "bytes_down": state.get("bytes_down_value"),
                        "system": state.get("system"),
                        "conduit": state.get("conduit"),
                    })
            payload = {"vps": rows, "vps_count": len(rows)}
            self.send_json(payload)
        except Exception as exc:
            self.safe_send_error(502, f"Failed to fetch vps list: {exc}")

    def handle_vps_sparks(self):
        try:
            params = parse_qs(urlparse(self.path).query)
            range_value = params.get("range", ["24h"])[0]
            poll_interval = int(self.config.get("poll_interval_sec") or POLL_INTERVAL_DEFAULT)
            range_sec = parse_range(range_value)
            spark_points = int(self.config.get("spark_points") or 48)
            bucket_sec = max(compute_bucket(range_sec, poll_interval), max(1, int(range_sec / spark_points)))
            ttl = timeseries_cache_ttl(range_value, poll_interval)
            cache_key = f"vps_sparks|{range_value}|{bucket_sec}|{self.config.get('use_agent')}"
            with CACHE_LOCK:
                cached = TIMESERIES_CACHE.get(cache_key)
                if cached and (time.time() - cached["ts"] < ttl):
                    self.send_json(cached["payload"])
                    return

            sparks = {}
            vps_list = self.config.get("vps", [])
            if self.config.get("use_agent"):
                for vps in vps_list:
                    vps_id = vps.get("id")
                    agent_url = vps.get("agent_url")
                    if not agent_url or not vps_id:
                        continue
                    try:
                        data, _ = get_agent_timeseries(agent_url, range_value, ttl, None)
                        series = downsample_series(data.get("series", []), bucket_sec)
                        sparks[vps_id] = [
                            {"ts": row.get("ts"), "value": row.get("clients")} for row in series
                        ]
                    except Exception:
                        continue
            else:
                for vps in vps_list:
                    vps_id = vps.get("id")
                    if not vps_id:
                        continue
                    series = load_series(
                        self.db_path,
                        range_sec,
                        vps_id=vps_id,
                        bucket_sec=bucket_sec,
                        since_ts=None,
                    )
                    sparks[vps_id] = [{"ts": row.get("ts"), "value": row.get("clients")} for row in series]

            payload = {"range": range_value, "bucket_sec": bucket_sec, "sparks": sparks}
            with CACHE_LOCK:
                TIMESERIES_CACHE[cache_key] = {"ts": time.time(), "payload": payload}
            self.send_json(payload)
        except Exception as exc:
            self.safe_send_error(502, f"Failed to fetch vps sparks: {exc}")

    def handle_timeseries(self):
        try:
            params = parse_qs(urlparse(self.path).query)
            range_value = params.get("range", ["24h"])[0]
            vps_id = params.get("vps", [""])[0] or None
            since_raw = params.get("since", [None])[0]
            since_ts = int(since_raw) if since_raw and str(since_raw).isdigit() else None
            range_sec = parse_range(range_value)
            poll_interval = int(self.config.get("poll_interval_sec") or POLL_INTERVAL_DEFAULT)
            bucket_sec = compute_bucket(range_sec, poll_interval)
            top_n = int(self.config.get("country_top_n") or COUNTRY_TOP_N_DEFAULT)
            partial = since_ts is not None
            if since_ts is not None:
                since_ts = since_ts - (since_ts % bucket_sec)
            cache_key = f"{vps_id or 'all'}|{range_value}|{bucket_sec}|{top_n}|{self.config.get('use_agent')}"
            ttl = timeseries_cache_ttl(range_value, poll_interval)
            if not partial:
                with CACHE_LOCK:
                    cached = TIMESERIES_CACHE.get(cache_key)
                    if cached and (time.time() - cached["ts"] < ttl):
                        self.send_json(cached["payload"])
                        return
            if self.config.get("use_agent"):
                ttl = cache_ttl(poll_interval)
                vps_list = self.config.get("vps", [])
                if vps_id:
                    target = next((v for v in vps_list if v.get("id") == vps_id), None)
                    if not target or not target.get("agent_url"):
                        raise Exception("Agent not configured for this VPS")
                    try:
                        data, _ = get_agent_timeseries(target.get("agent_url"), range_value, ttl, since_ts)
                    except Exception:
                        data = {"series": [], "country_series": {}}
                    data_series = downsample_series(data.get("series", []), bucket_sec)
                    data_countries = downsample_country_series(data.get("country_series", {}), bucket_sec)
                    data_countries = limit_country_series(data_countries, top_n)
                    payload = {
                        "range": range_value,
                        "bucket_sec": bucket_sec,
                        "partial": partial,
                        "series": data_series,
                        "country_series": data_countries,
                    }
                    if not partial:
                        with CACHE_LOCK:
                            TIMESERIES_CACHE[cache_key] = {"ts": time.time(), "payload": payload}
                    self.send_json(payload)
                    return

                series_list = []
                country_list = []
                for vps in vps_list:
                    agent_url = vps.get("agent_url")
                    if not agent_url:
                        continue
                    try:
                        data, _ = get_agent_timeseries(agent_url, range_value, ttl, since_ts)
                        series_list.append(data.get("series", []))
                        country_list.append(data.get("country_series", {}))
                    except Exception:
                        continue
                series = aggregate_series(series_list, bucket_sec)
                country_series = aggregate_country_series(country_list, bucket_sec)
                country_series = limit_country_series(country_series, top_n)
                payload = {
                    "range": range_value,
                    "bucket_sec": bucket_sec,
                    "partial": partial,
                    "series": series,
                    "country_series": country_series,
                }
                if not partial:
                    with CACHE_LOCK:
                        TIMESERIES_CACHE[cache_key] = {"ts": time.time(), "payload": payload}
                self.send_json(payload)
                return

            series = load_series(self.db_path, range_sec, vps_id=vps_id, bucket_sec=bucket_sec, since_ts=since_ts)
            country_series = load_country_series(self.db_path, range_sec, vps_id=vps_id, bucket_sec=bucket_sec, since_ts=since_ts)
            country_series = limit_country_series(country_series, top_n)
            payload = {
                "range": range_value,
                "bucket_sec": bucket_sec,
                "partial": partial,
                "series": series,
                "country_series": country_series,
            }
            if not partial:
                with CACHE_LOCK:
                    TIMESERIES_CACHE[cache_key] = {"ts": time.time(), "payload": payload}
            self.send_json(payload)
        except Exception as exc:
            self.safe_send_error(502, f"Failed to fetch timeseries: {exc}")

    def safe_send_error(self, code, message):
        try:
            self.send_error(code, message)
        except (ConnectionAbortedError, BrokenPipeError):
            pass

    def send_json(self, payload):
        data = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (ConnectionAbortedError, BrokenPipeError):
            pass


def fetch_metrics(metrics_url):
    req = Request(metrics_url, headers={"User-Agent": "conduit-dashboard"})
    with urlopen(req, timeout=5) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return parse_prometheus(text)


def fetch_geo(geo_url):
    req = Request(geo_url, headers={"User-Agent": "conduit-dashboard"})
    with urlopen(req, timeout=5) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return json.loads(text)


def fetch_sys(sys_url):
    req = Request(sys_url, headers={"User-Agent": "conduit-dashboard"})
    with urlopen(req, timeout=5) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return json.loads(text)


def fetch_agent_summary(agent_url):
    req = Request(f"{agent_url}/summary", headers={"User-Agent": "conduit-dashboard"})
    with urlopen(req, timeout=5) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return json.loads(text)


def fetch_agent_timeseries(agent_url, range_value, since_ts=None):
    qs = f"range={range_value}"
    if since_ts is not None:
        qs += f"&since={since_ts}"
    req = Request(f"{agent_url}/timeseries?{qs}", headers={"User-Agent": "conduit-dashboard"})
    with urlopen(req, timeout=10) as resp:
        text = resp.read().decode("utf-8", errors="replace")
    return json.loads(text)


def get_agent_summary(agent_url, ttl):
    return cached_fetch(
        AGENT_SUMMARY_CACHE, agent_url, ttl, lambda: fetch_agent_summary(agent_url)
    )


def get_agent_timeseries(agent_url, range_value, ttl, since_ts=None):
    cache_key = f"{agent_url}|{range_value}"
    if since_ts is not None:
        cache_key += f"|since={since_ts}"
    return cached_fetch(
        AGENT_TIMESERIES_CACHE, cache_key, ttl, lambda: fetch_agent_timeseries(agent_url, range_value, since_ts)
    )


def get_sys_data(sys_url, ttl):
    return cached_fetch(SYS_CACHE, sys_url, ttl, lambda: fetch_sys(sys_url))


def aggregate_series(series_list, bucket_sec):
    merged = {}
    for series in series_list:
        bucketed = {}
        for row in series:
            ts = row.get("ts")
            if ts is None:
                continue
            bucket = ts - (ts % bucket_sec)
            existing = bucketed.get(bucket)
            if not existing or ts >= existing.get("ts", 0):
                bucketed[bucket] = row
        for bucket, row in bucketed.items():
            agg = merged.setdefault(bucket, {"ts": bucket, "clients": 0.0, "bytes_up": 0.0, "bytes_down": 0.0})
            agg["clients"] += row.get("clients") or 0.0
            agg["bytes_up"] += row.get("bytes_up") or 0.0
            agg["bytes_down"] += row.get("bytes_down") or 0.0
    return [merged[k] for k in sorted(merged.keys())]


def aggregate_country_series(series_list, bucket_sec):
    merged = {}
    for series in series_list:
        bucketed = {}
        for key, rows in series.items():
            for row in rows:
                ts = row.get("ts")
                if ts is None:
                    continue
                bucket = ts - (ts % bucket_sec)
                bkey = (key, bucket, row.get("country"), row.get("metric"))
                existing = bucketed.get(bkey)
                if not existing or ts >= existing.get("ts", 0):
                    bucketed[bkey] = {
                        "ts": bucket,
                        "country": row.get("country"),
                        "value": row.get("value"),
                        "metric": row.get("metric"),
                    }
        for (key, bucket, country, metric), row in bucketed.items():
            mkey = (key, bucket, country, metric)
            agg = merged.setdefault(mkey, {"ts": bucket, "country": country, "value": 0.0, "metric": metric})
            agg["value"] += row.get("value") or 0.0
    out = {}
    for (key, bucket, country, metric), row in merged.items():
        out.setdefault(key, []).append(row)
    for key in out.keys():
        out[key].sort(key=lambda r: r["ts"])
    return out


def load_config(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8-sig") as handle:
        return json.load(handle)


def normalize_config(cfg, metrics_url):
    cfg = cfg or {}
    vps_list = cfg.get("vps")
    if isinstance(vps_list, list) and vps_list:
        normalized = []
        for idx, item in enumerate(vps_list):
            vps = dict(item)
            vps_id = vps.get("id") or vps.get("name") or vps.get("host") or f"vps-{idx + 1}"
            vps["id"] = vps_id
            if "label" not in vps:
                vps["label"] = vps.get("name") or vps.get("host") or vps_id
            normalized.append(vps)
        cfg["vps"] = normalized
        return cfg

    vps_id = cfg.get("id") or cfg.get("name") or cfg.get("host") or "vps-1"
    single = {
        "id": vps_id,
        "label": cfg.get("name") or cfg.get("host") or vps_id,
        "host": cfg.get("host"),
        "metrics_url": cfg.get("metrics_url") or metrics_url,
        "geo_url": cfg.get("geo_url") or "",
        "sys_url": cfg.get("sys_url") or "",
    }
    cfg["vps"] = [single]
    return cfg


def run_server(port, metrics_url, config):
    cfg = normalize_config(config, metrics_url)
    db_path = cfg.get("db_path") or DB_PATH_DEFAULT
    poll_interval = int(cfg.get("poll_interval_sec") or POLL_INTERVAL_DEFAULT)
    init_db(db_path)
    vps_list = cfg.get("vps", [])
    if len(vps_list) == 1:
        migrate_legacy_samples(db_path, vps_list[0].get("id"))
    use_agent = any((vps.get("agent_url") for vps in vps_list))
    cfg["use_agent"] = use_agent
    if not use_agent:
        thread = threading.Thread(
            target=collector_loop, args=(vps_list, cfg, db_path, poll_interval), daemon=True
        )
        thread.start()
    handler = lambda *args, **kwargs: DashboardHandler(
        *args, metrics_url=metrics_url, config=cfg, db_path=db_path, **kwargs
    )
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    print(f"Dashboard running on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--metrics-url", default="http://127.0.0.1:9090/metrics")
    parser.add_argument("--config", default=CONFIG_PATH_DEFAULT)
    args = parser.parse_args()

    cfg = load_config(args.config)
    run_server(args.port, args.metrics_url, cfg)
