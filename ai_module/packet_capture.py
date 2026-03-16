#!/usr/bin/env python3
"""
Live Packet Capture & NSL-KDD Feature Extractor
Sniffs network packets on the honeypot port and builds
real NSL-KDD feature vectors for the AI model.

Runs as a background thread alongside the honeypot server.
Requires: sudo / root privileges (for raw socket access)
"""

import threading
import time
import socket
from collections import defaultdict, deque
from datetime import datetime

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
    SCAPY_AVAILABLE = True
    # Suppress scapy warnings
    conf.verb = 0
except ImportError:
    SCAPY_AVAILABLE = False

# ─── NSL-KDD Service Port Mapping ────────────────────────────────────────────
PORT_SERVICE_MAP = {
    20: 'ftp_data', 21: 'ftp', 22: 'ssh', 23: 'telnet',
    25: 'smtp', 53: 'domain', 67: 'dhcp', 68: 'dhcp',
    80: 'http', 110: 'pop_3', 111: 'sunrpc', 119: 'nntp',
    123: 'ntp_u', 143: 'imap4', 194: 'IRC', 389: 'ldap',
    443: 'http_443', 445: 'microsoft_ds', 512: 'exec',
    513: 'login', 514: 'shell', 515: 'printer',
    520: 'efs', 543: 'klogin', 544: 'kshell',
    587: 'smtp', 993: 'imap4', 995: 'pop_3',
    1080: 'proxy', 3306: 'sql_net', 5000: 'http',
    5432: 'sql_net', 6667: 'IRC', 8080: 'http',
}

# TCP flag combinations → NSL-KDD connection flag
def get_connection_flag(syn, fin, rst, ack, established):
    if syn and not ack and not fin and not rst:
        return 'S0'    # SYN sent, no response
    if rst:
        return 'RSTO' if ack else 'REJ'
    if established and fin:
        return 'SF'    # Normal close
    if established:
        return 'S1'
    if syn and ack:
        return 'S2'
    return 'OTH'


class Connection:
    """Tracks a single TCP/UDP connection and its NSL-KDD-compatible metrics."""

    def __init__(self, src_ip, src_port, dst_ip, dst_port, protocol):
        self.src_ip    = src_ip
        self.src_port  = src_port
        self.dst_ip    = dst_ip
        self.dst_port  = dst_port
        self.protocol  = protocol  # 'tcp' | 'udp' | 'icmp'

        self.start_time    = time.time()
        self.last_seen     = self.start_time
        self.end_time      = None

        # Byte counters
        self.src_bytes = 0   # attacker → honeypot
        self.dst_bytes = 0   # honeypot → attacker

        # TCP state
        self.syn_seen  = False
        self.ack_seen  = False
        self.fin_seen  = False
        self.rst_seen  = False
        self.established = False

        # Fragment / urgency
        self.wrong_fragment = 0
        self.urgent_count   = 0

        # Flag: land attack
        self.land = 1 if (src_ip == dst_ip and src_port == dst_port) else 0

        self.completed = False


class PacketCapture:
    """
    Background packet sniffer that maintains connection state and
    provides NSL-KDD feature vectors keyed by attacker IP.
    """

    TIMEOUT_SECS   = 120   # Close idle connections after 2 min
    HISTORY_SIZE   = 200   # Keep last N completed connections for rate calcs
    WINDOW_SECS    = 2     # Time window for same-host/same-service rates

    def __init__(self, honeypot_port=5000):
        self.honeypot_port  = honeypot_port
        self.active_conns   = {}          # key: (src_ip,src_port,dst_ip,dst_port)
        self.recent_conns   = deque(maxlen=self.HISTORY_SIZE)  # completed
        self.features_by_ip = {}          # latest feature vector per attacker IP
        self._lock          = threading.Lock()
        self._running       = False
        self._thread        = None

        # Get local IP for direction detection
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            self.local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            self.local_ip = '127.0.0.1'

    # ── Public API ─────────────────────────────────────────────────────────

    def start(self):
        """Start background sniffing thread."""
        if not SCAPY_AVAILABLE:
            print("⚠️  Scapy not available — packet capture disabled")
            return False

        self._running = True
        self._thread  = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

        # Separate thread for timing out stale connections
        threading.Thread(target=self._timeout_loop, daemon=True).start()

        print(f"✅ Packet capture started (port {self.honeypot_port})")
        print(f"   Local IP detected: {self.local_ip}")
        return True

    def stop(self):
        self._running = False

    def get_features(self, attacker_ip):
        """
        Return the latest NSL-KDD feature vector for an attacker IP.
        Returns None if no packet data captured yet (falls back to heuristic).
        """
        with self._lock:
            return self.features_by_ip.get(attacker_ip)

    # ── Internal capture ───────────────────────────────────────────────────

    def _capture_loop(self):
        try:
            sniff(
                filter=f"tcp port {self.honeypot_port}",
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running
            )
        except PermissionError:
            print("❌ Packet capture needs root/sudo privileges.")
            print("   Run: sudo ./venv/bin/python3 controller.py --mode monitor")
            print("   ⚠️  Falling back to heuristic AI detection without packet data.")
        except Exception as e:
            print(f"⚠️  Packet capture error: {e}")

    def _process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return

        ip  = pkt[IP]
        now = time.time()

        # ── Determine direction and connection key ──────────────────────
        if pkt.haslayer(TCP):
            proto    = 'tcp'
            tcp      = pkt[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
        elif pkt.haslayer(UDP):
            proto    = 'udp'
            udp      = pkt[UDP]
            src_port = udp.sport
            dst_port = udp.dport
        elif pkt.haslayer(ICMP):
            proto    = 'icmp'
            src_port = 0
            dst_port = 0
        else:
            return

        # Normalise: key always has attacker as src
        if dst_port == self.honeypot_port:
            src_ip, dst_ip = ip.src, ip.dst
        else:
            src_ip, dst_ip = ip.dst, ip.src
            src_port, dst_port = dst_port, src_port

        key = (src_ip, src_port, dst_ip, dst_port)

        with self._lock:
            if key not in self.active_conns:
                self.active_conns[key] = Connection(
                    src_ip, src_port, dst_ip, dst_port, proto
                )
            conn = self.active_conns[key]
            conn.last_seen = now

            # ── Byte accounting ───────────────────────────────────────
            pkt_len = len(pkt[IP].payload)
            if ip.src == src_ip:           # attacker → honeypot
                conn.src_bytes += pkt_len
            else:                           # honeypot → attacker
                conn.dst_bytes += pkt_len

            # ── TCP state machine ─────────────────────────────────────
            if proto == 'tcp':
                tcp = pkt[TCP]
                if tcp.flags & 0x02:   # SYN
                    conn.syn_seen = True
                if tcp.flags & 0x10:   # ACK
                    conn.ack_seen = True
                    if conn.syn_seen:
                        conn.established = True
                if tcp.flags & 0x01:   # FIN
                    conn.fin_seen = True
                    self._close_connection(key, conn)
                if tcp.flags & 0x04:   # RST
                    conn.rst_seen = True
                    self._close_connection(key, conn)
                if tcp.flags & 0x20:   # URG
                    conn.urgent_count += 1

            # ── Fragment check ────────────────────────────────────────
            if ip.frag > 0:
                conn.wrong_fragment += 1

    def _close_connection(self, key, conn):
        """Finalise a connection, build features, store them."""
        if conn.completed:
            return
        conn.completed = True
        conn.end_time  = time.time()

        features = self._build_feature_vector(conn)
        self.features_by_ip[conn.src_ip] = features

        self.recent_conns.append(conn)
        self.active_conns.pop(key, None)

    def _timeout_loop(self):
        """Periodically close idle connections."""
        while self._running:
            time.sleep(10)
            now = time.time()
            with self._lock:
                stale = [
                    k for k, c in self.active_conns.items()
                    if now - c.last_seen > self.TIMEOUT_SECS
                ]
                for k in stale:
                    self._close_connection(k, self.active_conns[k])

    # ── NSL-KDD Feature Vector Builder ─────────────────────────────────────

    def _build_feature_vector(self, conn):
        """
        Build the full 41-feature NSL-KDD vector from a Connection object.
        Feature order matches the column order used during training exactly.
        """
        now     = time.time()
        dur     = (conn.end_time or now) - conn.start_time
        service = PORT_SERVICE_MAP.get(conn.dst_port, 'other')
        flag    = get_connection_flag(
                      conn.syn_seen, conn.fin_seen,
                      conn.rst_seen, conn.ack_seen,
                      conn.established)

        # ── Same-host / same-service rates over past WINDOW_SECS ──────
        window_conns = [
            c for c in self.recent_conns
            if c.end_time and (now - c.end_time) <= self.WINDOW_SECS
        ]

        same_host_conns = [c for c in window_conns if c.dst_ip == conn.dst_ip]
        same_srv_conns  = [c for c in window_conns
                           if PORT_SERVICE_MAP.get(c.dst_port, 'other') == service]

        count     = len(same_host_conns) or 1
        srv_count = len(same_srv_conns)  or 1

        def rate(lst, cond):
            return sum(1 for c in lst if cond(c)) / len(lst) if lst else 0.0

        serror_flag   = lambda c: get_connection_flag(c.syn_seen, c.fin_seen, c.rst_seen, c.ack_seen, c.established) in ('S0','S1','S2','S3')
        rerror_flag   = lambda c: get_connection_flag(c.syn_seen, c.fin_seen, c.rst_seen, c.ack_seen, c.established) == 'REJ'
        same_srv_flag = lambda c: PORT_SERVICE_MAP.get(c.dst_port, 'other') == service

        serror_rate       = rate(same_host_conns, serror_flag)
        srv_serror_rate   = rate(same_srv_conns,  serror_flag)
        rerror_rate       = rate(same_host_conns, rerror_flag)
        srv_rerror_rate   = rate(same_srv_conns,  rerror_flag)
        same_srv_rate     = rate(same_host_conns, same_srv_flag)
        diff_srv_rate     = 1.0 - same_srv_rate
        srv_diff_host_rate= rate(same_srv_conns,
                                 lambda c: c.dst_ip != conn.dst_ip)

        # ── Last-100-connection rates (dst_host_* features) ────────────
        last100 = list(self.recent_conns)[-100:]
        h100    = [c for c in last100 if c.dst_ip == conn.dst_ip]
        hs100   = [c for c in h100
                   if PORT_SERVICE_MAP.get(c.dst_port, 'other') == service]

        dst_host_count              = len(h100)   or 1
        dst_host_srv_count          = len(hs100)  or 1
        dst_host_same_srv_rate      = rate(h100,  same_srv_flag)
        dst_host_diff_srv_rate      = 1.0 - dst_host_same_srv_rate
        dst_host_same_src_port_rate = rate(h100,
                                           lambda c: c.src_port == conn.src_port)
        dst_host_srv_diff_host_rate = rate(hs100,
                                           lambda c: c.src_ip != conn.src_ip)
        dst_host_serror_rate        = rate(h100,  serror_flag)
        dst_host_srv_serror_rate    = rate(hs100, serror_flag)
        dst_host_rerror_rate        = rate(h100,  rerror_flag)
        dst_host_srv_rerror_rate    = rate(hs100, rerror_flag)

        # ── Assemble vector in exact NSL-KDD column order ──────────────
        vector = [
            dur,                          # 0  duration
            conn.protocol,                # 1  protocol_type  (encoded later)
            service,                      # 2  service         (encoded later)
            flag,                         # 3  flag            (encoded later)
            conn.src_bytes,               # 4  src_bytes
            conn.dst_bytes,               # 5  dst_bytes
            conn.land,                    # 6  land
            conn.wrong_fragment,          # 7  wrong_fragment
            conn.urgent_count,            # 8  urgent
            0,                            # 9  hot
            0,                            # 10 num_failed_logins (filled by controller)
            0,                            # 11 logged_in
            0,                            # 12 num_compromised
            0,                            # 13 root_shell
            0,                            # 14 su_attempted
            0,                            # 15 num_root
            0,                            # 16 num_file_creations
            0,                            # 17 num_shells
            0,                            # 18 num_access_files
            0,                            # 19 num_outbound_cmds
            0,                            # 20 is_host_login
            0,                            # 21 is_guest_login
            count,                        # 22 count
            srv_count,                    # 23 srv_count
            serror_rate,                  # 24 serror_rate
            srv_serror_rate,              # 25 srv_serror_rate
            rerror_rate,                  # 26 rerror_rate
            srv_rerror_rate,              # 27 srv_rerror_rate
            same_srv_rate,                # 28 same_srv_rate
            diff_srv_rate,                # 29 diff_srv_rate
            srv_diff_host_rate,           # 30 srv_diff_host_rate
            dst_host_count,               # 31 dst_host_count
            dst_host_srv_count,           # 32 dst_host_srv_count
            dst_host_same_srv_rate,       # 33 dst_host_same_srv_rate
            dst_host_diff_srv_rate,       # 34 dst_host_diff_srv_rate
            dst_host_same_src_port_rate,  # 35 dst_host_same_src_port_rate
            dst_host_srv_diff_host_rate,  # 36 dst_host_srv_diff_host_rate
            dst_host_serror_rate,         # 37 dst_host_serror_rate
            dst_host_srv_serror_rate,     # 38 dst_host_srv_serror_rate
            dst_host_rerror_rate,         # 39 dst_host_rerror_rate
            dst_host_srv_rerror_rate,     # 40 dst_host_srv_rerror_rate
        ]

        return {
            'vector':   vector,
            'service':  service,
            'flag':     flag,
            'protocol': conn.protocol,
            'src_bytes':conn.src_bytes,
            'dst_bytes':conn.dst_bytes,
            'duration': dur,
            'captured_at': datetime.now().isoformat()
        }


# ── Standalone test ─────────────────────────────────────────────────────────
if __name__ == '__main__':
    import os
    port = int(os.getenv('HONEYPOT_PORT', 5000))

    print(f"🔍 Starting packet capture test on port {port}")
    print("   (Make a request to the honeypot to see features)")
    print("   Press Ctrl+C to stop\n")

    capture = PacketCapture(honeypot_port=port)
    if capture.start():
        try:
            while True:
                time.sleep(5)
                with capture._lock:
                    if capture.features_by_ip:
                        print("\n📊 Captured features by IP:")
                        for ip, feat in capture.features_by_ip.items():
                            print(f"   {ip}: service={feat['service']}, "
                                  f"flag={feat['flag']}, "
                                  f"src_bytes={feat['src_bytes']}, "
                                  f"dst_bytes={feat['dst_bytes']}, "
                                  f"duration={feat['duration']:.2f}s")
                    else:
                        print("   (waiting for connections...)")
        except KeyboardInterrupt:
            capture.stop()
            print("\n✅ Capture stopped.")
