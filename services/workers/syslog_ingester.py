import json
import os
import re
import socketserver
import threading
import time
from datetime import datetime, timezone
from typing import Optional

import redis

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
STREAM_KEY = os.getenv("REDIS_STREAM_KEY", "stream:syslog")
STREAM_MAXLEN = int(os.getenv("REDIS_STREAM_MAXLEN", "100000"))

SYSLOG_BIND_HOST = os.getenv("SYSLOG_BIND_HOST", "0.0.0.0")
SYSLOG_UDP_PORT = int(os.getenv("SYSLOG_UDP_PORT", "5514"))
SYSLOG_TCP_PORT = int(os.getenv("SYSLOG_TCP_PORT", "5514"))
SYSLOG_DEFAULT_HOSTNAME = os.getenv("SYSLOG_DEFAULT_HOSTNAME", "unknown")

RFC3164_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<ts>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+(?P<program>[^:\[]+)?(?:\[(?P<pid>\d+)\])?:?\s*(?P<message>.*)$"
)

RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<appname>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<structured_data>(?:-|\[.*?\]))\s*"
    r"(?P<message>.*)$"
)


def connect_redis() -> redis.Redis:
    while True:
        try:
            client = redis.Redis(
                host=REDIS_HOST,
                port=REDIS_PORT,
                decode_responses=True,
            )
            client.ping()
            print("[syslog-ingester] connected to redis", flush=True)
            return client
        except Exception as exc:
            print(f"[syslog-ingester] redis not ready: {exc}", flush=True)
            time.sleep(2)


REDIS_CLIENT = connect_redis()


def parse_pri(pri: int) -> tuple[int, int]:
    facility = pri // 8
    severity = pri % 8
    return facility, severity


def parse_rfc3164_timestamp(value: str) -> str:
    now = datetime.now(timezone.utc)
    try:
        dt = datetime.strptime(f"{now.year} {value}", "%Y %b %d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        return now.isoformat()


def normalize_timestamp(value: Optional[str]) -> str:
    if not value or value == "-":
        return datetime.now(timezone.utc).isoformat()
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).astimezone(timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def parse_syslog_message(raw_message: str, source_ip: str, transport: str) -> dict:
    raw_message = raw_message.strip()

    match_5424 = RFC5424_RE.match(raw_message)
    if match_5424:
        pri = int(match_5424.group("pri"))
        facility, severity = parse_pri(pri)
        return {
            "source": "syslog",
            "event_type": "syslog",
            "timestamp": normalize_timestamp(match_5424.group("ts")),
            "src_ip": source_ip,
            "dest_ip": "",
            "proto": transport,
            "raw": json.dumps(
                {
                    "format": "rfc5424",
                    "priority": pri,
                    "facility": facility,
                    "severity": severity,
                    "hostname": match_5424.group("hostname"),
                    "appname": None if match_5424.group("appname") == "-" else match_5424.group("appname"),
                    "program": None if match_5424.group("appname") == "-" else match_5424.group("appname"),
                    "procid": None if match_5424.group("procid") == "-" else match_5424.group("procid"),
                    "msgid": None if match_5424.group("msgid") == "-" else match_5424.group("msgid"),
                    "structured_data": None if match_5424.group("structured_data") == "-" else match_5424.group("structured_data"),
                    "message": match_5424.group("message"),
                    "source_ip": source_ip,
                    "transport": transport,
                    "original_timestamp": match_5424.group("ts"),
                    "raw_message": raw_message,
                },
                ensure_ascii=False,
            ),
        }

    match_3164 = RFC3164_RE.match(raw_message)
    if match_3164:
        pri = int(match_3164.group("pri"))
        facility, severity = parse_pri(pri)
        program = match_3164.group("program")
        return {
            "source": "syslog",
            "event_type": "syslog",
            "timestamp": parse_rfc3164_timestamp(match_3164.group("ts")),
            "src_ip": source_ip,
            "dest_ip": "",
            "proto": transport,
            "raw": json.dumps(
                {
                    "format": "rfc3164",
                    "priority": pri,
                    "facility": facility,
                    "severity": severity,
                    "hostname": match_3164.group("hostname") or SYSLOG_DEFAULT_HOSTNAME,
                    "appname": program,
                    "program": program,
                    "pid": match_3164.group("pid"),
                    "message": match_3164.group("message"),
                    "source_ip": source_ip,
                    "transport": transport,
                    "original_timestamp": match_3164.group("ts"),
                    "raw_message": raw_message,
                },
                ensure_ascii=False,
            ),
        }

    return {
        "source": "syslog",
        "event_type": "syslog",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip": source_ip,
        "dest_ip": "",
        "proto": transport,
        "raw": json.dumps(
            {
                "format": "unparsed",
                "hostname": SYSLOG_DEFAULT_HOSTNAME,
                "appname": None,
                "program": None,
                "facility": None,
                "severity": None,
                "message": raw_message,
                "source_ip": source_ip,
                "transport": transport,
                "original_timestamp": None,
                "raw_message": raw_message,
            },
            ensure_ascii=False,
        ),
    }


def push_event(payload: dict) -> str:
    global REDIS_CLIENT
    while True:
        try:
            return REDIS_CLIENT.xadd(
                STREAM_KEY,
                payload,
                maxlen=STREAM_MAXLEN,
                approximate=True,
            )
        except Exception as exc:
            print(f"[syslog-ingester] redis push failed: {exc}", flush=True)
            time.sleep(2)
            REDIS_CLIENT = connect_redis()


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        source_ip = self.client_address[0]
        message = data.decode("utf-8", errors="replace").strip()
        if not message:
            return

        payload = parse_syslog_message(message, source_ip, "udp")
        message_id = push_event(payload)
        print(
            f"[syslog-ingester][udp] pushed id={message_id} src_ip={source_ip}",
            flush=True,
        )


class SyslogTCPHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        source_ip = self.client_address[0]
        while True:
            line = self.rfile.readline()
            if not line:
                break
            message = line.decode("utf-8", errors="replace").strip()
            if not message:
                continue

            payload = parse_syslog_message(message, source_ip, "tcp")
            message_id = push_event(payload)
            print(
                f"[syslog-ingester][tcp] pushed id={message_id} src_ip={source_ip}",
                flush=True,
            )


def start_udp_server() -> socketserver.ThreadingUDPServer:
    server = socketserver.ThreadingUDPServer((SYSLOG_BIND_HOST, SYSLOG_UDP_PORT), SyslogUDPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[syslog-ingester] UDP listening on {SYSLOG_BIND_HOST}:{SYSLOG_UDP_PORT}", flush=True)
    return server


def start_tcp_server() -> socketserver.ThreadingTCPServer:
    server = socketserver.ThreadingTCPServer((SYSLOG_BIND_HOST, SYSLOG_TCP_PORT), SyslogTCPHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"[syslog-ingester] TCP listening on {SYSLOG_BIND_HOST}:{SYSLOG_TCP_PORT}", flush=True)
    return server


def main() -> None:
    udp_server = start_udp_server()
    tcp_server = start_tcp_server()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[syslog-ingester] shutdown requested", flush=True)
    finally:
        udp_server.shutdown()
        tcp_server.shutdown()


if __name__ == "__main__":
    main()
