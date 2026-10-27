"""A RADIUS conversation built packet by packet, as a capture would hold it.

Requests and replies are signed with a shared secret when one is given
(see radius_sign), and each packet can carry the direction a Linux cooked
capture would record on the capturing host.
"""

import pcapbuild as pb
import radius_sign as sign
from pcap_analyser import layers, radius
from pcap_analyser import radius_exchange as rx

SERVER_SECRET = b"sample-server-secret"
NAS_SECRET = SERVER_SECRET
OTHER_CLIENT, OTHER_SERVER = "198.51.100.20", "198.51.100.2"
LOOPBACK = "127.0.0.1"


def auth_for(ident, salt=0):
    return bytes((ident + salt + i) % 256 for i in range(16))


class Trace:
    def __init__(self):
        self.packets = []
        self.ips = []  # (ts, raw IP bytes), for writing the trace out as a capture file

    def raw(self, ts, ip, direction=None):
        p = layers.decode(len(self.packets) + 1, ts, layers.LINKTYPE_RAW, ip, direction)
        assert isinstance(p, layers.Packet)
        self.packets.append(p)
        self.ips.append((ts, ip))
        return p

    def request(self, ts, ident, user="dave", code=1, client=pb.CLIENT, cport=40000, server=pb.SERVER,
                sport=1812, auth=None, extra=(), secret=None, password=None, direction=None, nas="nas"):
        """An unsigned request by default; with secret, signed with Message-Authenticator (Access-Request
        and Status-Server) and with User-Password hidden when password is given."""
        auth = auth if auth is not None else auth_for(ident)
        attrs = ([(1, user.encode())] if user else []) + ([(32, nas.encode())] if nas else []) + list(extra)
        if secret is None:
            plain = [(t, v.encode() if isinstance(v, str) else v) for t, v in attrs]
            if password is not None:
                plain.append((2, b"\x00" * 16))
            data = pb.radius(code, ident, plain, auth)
        elif code == 12:
            data = sign.status_server(ident, auth, secret)
        else:
            data = sign.access_request(ident, auth, attrs, secret, password=password)
        return self.raw(ts, pb.udp(client, server, cport, sport, data), direction)

    def reply(self, ts, ident, code=2, client=pb.CLIENT, cport=40000, server=pb.SERVER, sport=1812, attrs=(),
              secret=None, request_auth=None, direction=None, src=None, src_port=None):
        attrs = [(t, v.encode() if isinstance(v, str) else v) for t, v in attrs]
        if secret is None:
            data = pb.radius(code, ident, attrs)
        else:
            data = sign.reply(code, ident, request_auth if request_auth is not None else auth_for(ident), attrs,
                              secret)
        return self.raw(ts, pb.udp(src or server, client, src_port or sport, cport, data), direction)

    def health_check(self, ts, ident, secret=SERVER_SECRET):
        """A Status-Server on the capturing host's loopback, answered, as a container health check does."""
        self.request(ts, ident, user=None, code=12, client=LOOPBACK, cport=50000 + ident, server=LOOPBACK,
                     secret=secret, nas=None)
        self.reply(ts + 0.0001, ident, client=LOOPBACK, cport=50000 + ident, server=LOOPBACK, secret=secret)

    def analyse(self, ports=radius.DEFAULT_PORTS, capture_end=None):
        end = capture_end if capture_end is not None else max(p.ts for p in self.packets) + 60
        return rx.analyse(self.packets, ports, end)
