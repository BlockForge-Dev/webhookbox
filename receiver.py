from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import hmac, hashlib

SECRET = b"dev_secret_123"
MAX_SKEW_SECS = 5 * 60  # 5 minutes

def compute_v1(ts, delivery_id, attempt_id, event_id, body_bytes):
    msg = (
        str(ts).encode() + b"." +
        delivery_id.encode() + b"." +
        attempt_id.encode() + b"." +
        event_id.encode() + b"." +
        body_bytes
    )
    return hmac.new(SECRET, msg, hashlib.sha256).hexdigest()

def parse_signature(sig_header: str):
    # "t=...,v1=..."
    parts = {}
    for chunk in sig_header.split(","):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            parts[k.strip()] = v.strip()
    return parts.get("t"), parts.get("v1")

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body_bytes = self.rfile.read(length)  # IMPORTANT: bytes, not decoded
        body_str = body_bytes.decode("utf-8", errors="replace")

        print("\n--- WEBHOOK RECEIVED ---")
        print("Path:", self.path)
        print("Headers:")
        for k in ["X-Event-Id", "X-Delivery-Id", "X-Attempt-Id", "X-Timestamp", "X-Signature"]:
            print(f"  {k}: {self.headers.get(k)}")
        print("Body:\n", body_str)

        # --- Verify signature + replay protection ---
        event_id = self.headers.get("X-Event-Id")
        delivery_id = self.headers.get("X-Delivery-Id")
        attempt_id = self.headers.get("X-Attempt-Id")
        ts_header = self.headers.get("X-Timestamp")
        sig_header = self.headers.get("X-Signature")

        # 1) required headers
        if not all([event_id, delivery_id, attempt_id, ts_header, sig_header]):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"missing_required_headers")
            print("❌ signature failed: missing_required_headers")
            return

        # 2) parse ts (and also parse Stripe-style header for sanity)
        try:
            ts = int(ts_header)
        except ValueError:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"invalid_timestamp")
            print("❌ signature failed: invalid_timestamp")
            return

        # optional: ensure X-Signature has matching t=
        t_from_sig, v1 = parse_signature(sig_header)
        if t_from_sig is None or v1 is None or str(ts) != str(t_from_sig):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"invalid_signature_header")
            print("❌ signature failed: invalid_signature_header")
            return

        # 3) replay protection
        now = int(time.time())
        if abs(now - ts) > MAX_SKEW_SECS:
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"timestamp_out_of_window")
            print(f"❌ signature failed: timestamp_out_of_window (now={now}, ts={ts})")
            return

        # 4) signature check
        expected = compute_v1(ts, delivery_id, attempt_id, event_id, body_bytes)
        got = v1
        if not hmac.compare_digest(expected, got):
            self.send_response(401)
            self.end_headers()
            self.wfile.write(b"signature_mismatch")
            print("❌ signature failed: signature_mismatch")
            print("expected:", expected)
            print("got     :", got)
            print("raw_body repr:", repr(body_bytes))
            return

        # ok
        self.send_response(401)

        self.end_headers()
        self.wfile.write(b"ok")
        print("✅ signature ok")

if __name__ == "__main__":
    print("Listening on http://127.0.0.1:4000/webhook")
    HTTPServer(("127.0.0.1", 4000), Handler).serve_forever()
