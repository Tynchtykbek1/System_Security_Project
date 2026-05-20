import json
import sys
from urllib import error, request


BASE_URL = "http://127.0.0.1:8101"


def call_api(method, path, payload=None):
    url = BASE_URL + path
    data = None
    headers = {"Accept": "application/json"}

    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = request.Request(url, data=data, headers=headers, method=method)

    try:
        with request.urlopen(req) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body)
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            details = json.loads(body)
        except json.JSONDecodeError:
            details = {"detail": body}
        print_response(method, path, exc.code, details)
        return None, None
    except error.URLError as exc:
        print(f"{method} {path}")
        print(f"Request failed: {exc.reason}")
        return None, None


def print_response(method, path, status, body):
    print(f"{method} {path}")
    print(f"Status: {status}")
    print(json.dumps(body, indent=2, sort_keys=True))
    print()


def main():
    sample_payload = {
        "device": "edgeA-demo",
        "message": "hello from demo client",
        "value": 42,
    }

    steps = [
        ("GET", "/health", None),
        ("POST", "/encrypt-and-backup", sample_payload),
        ("POST", "/recover-from-cloud", {"request_reason": "recovery"}),
        ("GET", "/local-storage", None),
        ("GET", "/audit-log", None),
    ]

    for method, path, payload in steps:
        status, body = call_api(method, path, payload)
        if status is None:
            sys.exit(1)
        print_response(method, path, status, body)


if __name__ == "__main__":
    main()
