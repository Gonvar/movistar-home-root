#!/usr/bin/env python3
"""
Capture server for the Movistar Home recon flow.
- GET  /recon.sh        -> serves the recon script to the device (Termux curl)
- POST/PUT /upload      -> stores whatever the device sends (recon.tar.gz)
Everything logged to upload_server.log.
"""
import datetime
import hashlib
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
UPLOADS = os.path.join(BASE, "uploads")
os.makedirs(UPLOADS, exist_ok=True)
LOCK = threading.Lock()


def log(msg):
    line = f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    with LOCK:
        print(line, flush=True)
        with open(os.path.join(BASE, "upload_server.log"), "a") as f:
            f.write(line + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    # Per-connection deadline: a stalled device connection can no longer wedge
    # the whole server (threaded server + this timeout).
    timeout = 15

    def log_message(self, fmt, *args):
        log(f"req: {self.command} {self.path} from {self.client_address[0]}")

    def _serve_recon(self):
        try:
            with open(os.path.join(BASE, "recon.sh"), "rb") as f:
                data = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "application/x-sh")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            log("served recon.sh")
        except FileNotFoundError:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def _save_upload(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        name = os.path.join(UPLOADS, f"upload-{stamp}.bin")
        with open(name, "wb") as f:
            f.write(body)
        log(f"SAVED {length} bytes -> {name}")
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def _serve_file(self, name):
        """Serve a whitelisted file from the toolkit dir."""
        whitelist = {"recon.sh", "probe.apk", "control.apk", "recon2.sh", "recon3.sh", "recon4.sh", "MH-Helper.apk", "recon5.sh", "recon6.sh", "recon7.sh", "recon8.sh", "recon9.sh", "recon10.sh", "recon11.sh", "recon12.sh", "recon13.sh", "recon14.sh", "recon15.sh", "recon16.sh", "recon17.sh", "poller.sh", "job.sh", "poc-m1", "poc-m2", "poc-m2.gz", "poc-m3.gz", "poc-m4.gz", "poc-fp4.gz", "poc-fp5.gz", "probe-surface.gz", "kgsl-probe.gz", "unix-probe.gz", "unix-uaf.gz", "unix-ring.gz", "unix-gpz.gz", "unix-gpz", "unix-gpz2.gz", "unix-gpz2", "unix-gpz3.gz", "unix-gpz3", "unix-gpz4.gz", "unix-gpz4", "unix-gpz5.gz", "unix-gpz5", "kgsl-1905.gz", "kgsl-1905b.gz", "kgsl-1905c.gz", "kgsl-svm.gz", "kgsl-svms", "kgsl-svms2", "kgsl-svms3", "stage0", "stage0.gz", "stage1", "stage1.gz", "unix-gpz6", "unix-gpz6.gz", "kgsl-cp", "kgsl-cp.gz", "kgsl-pend", "kgsl-pend.gz", "kgsl-pend2", "kgsl-pend2.gz", "kgsl-svmdbl", "kgsl-svmdbl.gz", "kgsl-svmstale", "kgsl-svmstale.gz", "kgsl-svmcp", "kgsl-svmcp.gz", "kgsl-svmdual", "kgsl-svmdual.gz", "kgsl-poolreclaim", "kgsl-poolreclaim.gz", "kgsl-svmg1", "kgsl-svmg1.gz", "kgsl-svmsize", "kgsl-svmsize.gz", "kgsl-stalelive", "kgsl-stalelive.gz", "kgsl-reclaim", "kgsl-reclaim.gz", "kgsl-g1map", "kgsl-g1map.gz", "kgsl-faulttest", "kgsl-faulttest.gz", "kgsl-dblcheck", "kgsl-dblcheck.gz", "kgsl-race", "kgsl-race.gz", "kgsl-importvma", "kgsl-importvma.gz", "kgsl-racefree", "kgsl-racefree.gz", "kgsl-reclaimscan", "kgsl-reclaimscan.gz", "kgsl-pagemap", "kgsl-pagemap.gz", "kgsl-m2m", "kgsl-m2m.gz", "kgsl-telescope", "kgsl-telescope.gz", "kgsl-ptescan", "kgsl-ptescan.gz", "kgsl-forge", "kgsl-forge.gz"}
        if name not in whitelist:
            return False
        path = os.path.join(BASE, name)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except FileNotFoundError:
            return False
        ctype = ("application/vnd.android.package-archive" if name.endswith(".apk")
                 else "application/x-sh")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'attachment; filename="{name}"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        log(f"served {name} ({len(data)} bytes)")
        return True

    def _job_sig(self):
        """Signature of job.sh; changes the instant the file is edited."""
        try:
            with open(os.path.join(BASE, "job.sh"), "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except OSError:
            return ""

    def _serve_job_wait(self):
        """Long-poll: hold the request open until job.sh changes (or ~20s),
        then serve it.  Makes job delivery near-instant vs a 15s poll."""
        since = self._job_sig()
        deadline = time.time() + 20.0
        while time.time() < deadline and self._job_sig() == since:
            time.sleep(0.08)
        if not self._serve_file("job.sh"):
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_GET(self):
        if self.path.split("?")[0].strip("/") == "wait":
            self._serve_job_wait()
            return
        name = self.path.strip("/") or "recon.sh"
        if self._serve_file(name):
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self._save_upload()

    do_PUT = do_POST


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8010
    log(f"capture server on :{port} (GET /recon.sh, POST /upload)")
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    srv.daemon_threads = True
    srv.serve_forever()