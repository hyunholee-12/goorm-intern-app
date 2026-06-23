#!/usr/bin/env python3
"""SastClient 에러 처리 검증용 가짜 SAST 서버.

실제 분석은 하지 않는다. 업로드된 번들은 읽어서 버리고(curl 이 정상 종료하도록
Content-Length 만큼 소비), MODE 에 따라 정해진 HTTP 코드 + body 를 돌려준다.
이것만으로 SastResponse 의 5개 분기(NORMAL/SERVER_ERROR/BAD_REQUEST/
RESPONSE_INVALID/NO_RESPONSE)를 전부 재현할 수 있다.

모드 선택 우선순위:
  1) 요청 쿼리스트링  POST /scan?mode=503   (apiUrl 안 바꾸려면 server 만 재시작)
  2) 환경변수         MOCK_MODE=503 python3 mock_sast_server.py
  3) 아래 DEFAULT_MODE 상수

지원 모드:
  pass      200, blocking 0            → NORMAL → 게이트 PASS
  blocking  200, blocking 2            → NORMAL → 게이트 FAIL(정상 차단)
  review    200, review_required 1     → NORMAL → 이슈 라우팅 경로
  500/502/503/504  해당 5xx            → SERVER_ERROR (재시도 대상)
  400       400                        → BAD_REQUEST (재시도 안 함)
  empty     200 + 빈 body              → RESPONSE_INVALID
  nonjson   200 + 'not json'           → RESPONSE_INVALID
  array     200 + JSON 배열            → RESPONSE_INVALID
  missing   200, count 필드 1개 누락    → RESPONSE_INVALID
  negative  200, blocking_count = -1   → RESPONSE_INVALID
  noreport  200, report_url 없음        → NORMAL(fail-open, 사유만 기록)
  slow      sleep 후 200               → curl --max-time 초과 시 NO_RESPONSE
            (지연 시간은 MOCK_SLOW_SECONDS, 기본 130 > 기본 maxTime 120)

연결 실패(NO_RESPONSE/000)는 서버를 끄거나 닫힌 포트로 보내면 자연 재현되므로
별도 모드가 필요 없다.
"""
from __future__ import annotations

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

DEFAULT_MODE = "pass"
SLOW_SECONDS = int(os.environ.get("MOCK_SLOW_SECONDS", "130"))

# 정상 응답 베이스(필수 등급 필드 4종 + 선택 필드).
_NORMAL_BASE = {
    "blocking_count": 0,
    "review_required_count": 0,
    "warning_count": 0,
    "sca_review_count": 0,
    "report_url": "s3://mock-bucket/reports/mock-scan.html",
    "build_decision": "PASS",
    "message": "mock scan ok",
    "findings": [],
}


def _normal(**overrides) -> dict:
    body = dict(_NORMAL_BASE)
    body.update(overrides)
    return body


def _sample_finding() -> dict:
    return {
        "severity": "BLOCKING",
        "ruleId": "mock.sql-injection",
        "message": "Possible SQL injection",
        "cwe": ["CWE-89"],
        "detail": "user input flows into query",
        "recommendation": "use parameterized queries",
        "file": "app/db.js",
        "line": 42,
    }


def resolve(mode: str):
    """모드 → (http_status, body_text). body_text=None 이면 빈 body."""
    if mode in ("pass", "normal", "200"):
        return 200, json.dumps(_normal())
    if mode == "blocking":
        return 200, json.dumps(_normal(
            blocking_count=2, build_decision="FAIL", message="2 blocking findings",
            findings=[_sample_finding()]))
    if mode == "review":
        return 200, json.dumps(_normal(
            review_required_count=1, build_decision="REVIEW", message="1 review required",
            findings=[dict(_sample_finding(), severity="REVIEW")]))
    if mode in ("500", "502", "503", "504"):
        return int(mode), json.dumps({"error": "scan_error", "message": f"mock {mode} server error"})
    if mode == "400":
        return 400, json.dumps({"error": "bad_request", "message": "mock 400 bad input"})
    if mode == "empty":
        return 200, ""
    if mode == "nonjson":
        return 200, "not json at all"
    if mode == "array":
        return 200, json.dumps([1, 2, 3])
    if mode == "missing":
        body = _normal()
        del body["sca_review_count"]  # 필수 필드 1개 누락
        return 200, json.dumps(body)
    if mode == "negative":
        return 200, json.dumps(_normal(blocking_count=-1))
    if mode == "noreport":
        body = _normal()
        del body["report_url"]
        return 200, json.dumps(body)
    # 알 수 없는 모드는 안전하게 pass 처리(오타로 인한 오검출 방지)하되 경고 로그.
    print(f"[mock] unknown mode '{mode}', falling back to pass")
    return 200, json.dumps(_normal())


class Handler(BaseHTTPRequestHandler):
    server_version = "mock-sast/1"

    def _send(self, status: int, body_text: str) -> None:
        data = body_text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _drain_body(self) -> None:
        # 업로드 번들을 읽어서 버린다. 소비하지 않으면 일부 curl/keep-alive 조합에서
        # connection reset 이 나 NO_RESPONSE 와 구분이 안 되므로 반드시 비운다.
        length = int(self.headers.get("Content-Length", "0") or "0")
        remaining = length
        while remaining > 0:
            chunk = self.rfile.read(min(remaining, 65536))
            if not chunk:
                break
            remaining -= len(chunk)

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/healthz":
            self._send(200, json.dumps({"status": "ok", "mode": self._mode()}))
            return
        self._send(404, json.dumps({"error": "not_found"}))

    def do_POST(self) -> None:
        self._drain_body()
        if urlparse(self.path).path != "/scan":
            self._send(404, json.dumps({"error": "not_found"}))
            return
        mode = self._mode()
        if mode == "slow":
            print(f"[mock] slow mode — sleeping {SLOW_SECONDS}s to trigger client --max-time")
            time.sleep(SLOW_SECONDS)
            self._send(200, json.dumps(_normal()))
            return
        status, body = resolve(mode)
        print(f"[mock] mode={mode} -> HTTP {status} ({len(body)} bytes)")
        self._send(status, body)

    def _mode(self) -> str:
        q = parse_qs(urlparse(self.path).query)
        if "mode" in q and q["mode"]:
            return q["mode"][0]
        return os.environ.get("MOCK_MODE", DEFAULT_MODE)

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.address_string()} - {fmt % args}")


def main() -> int:
    host = os.environ.get("MOCK_HOST", "127.0.0.1")
    port = int(os.environ.get("MOCK_PORT", "8080"))
    mode = os.environ.get("MOCK_MODE", DEFAULT_MODE)
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"mock SAST server on http://{host}:{port}  (default mode={mode})")
    print("  POST /scan          현재 모드대로 응답")
    print("  POST /scan?mode=503 요청별 모드 오버라이드")
    print("  GET  /healthz       헬스체크")
    print()
    print("사용 가능한 MOCK_MODE 목록:")
    print("  [200 정상]   200 / pass / blocking / review / noreport")
    print("  [200 오류]   empty(빈 body) / nonjson(JSON 파싱 실패) / missing(등급 필드 누락) / negative(음수) / array")
    print("  [4xx/5xx]   400 / 500 / 502 / 503 / 504")
    print("  [타임아웃]   slow  (curl --max-time 초과 재현)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nmock SAST server shutting down")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
