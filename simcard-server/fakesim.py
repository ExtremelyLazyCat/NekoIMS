#!/usr/bin/env python3
"""
fakesim: a software USIM speaking the simcard-server HTTP API, for test SIMs
whose K and OPc (or OP) are known. No card reader or third-party packages.

  GET /?type=imsi                         -> {"imsi": "..."}
  GET /?type=rand-autn&rand=<hex>&autn=<hex>
      -> {"res": "<hex>", "ck": "<hex>", "ik": "<hex>"}
      -> {"res": "<auts>", "ck": null, "ik": null, "auts": "<auts>"}  (resync)

AKA is Milenage (TS 35.205/35.206). SQN freshness is checked against the
highest SQN accepted so far (in memory, starting at --sqn), so a replayed or
stale challenge triggers a resync just like a real card.

    python3 fakesim.py --imsi 001010000000001 \\
        --k 465b5ce8b199b49faa5f0a2ee238a6bc \\
        --opc cd63cb71954a9f4e48a5994e37a02baf

then point NekoIMS at it with "simcard_server": "http://127.0.0.1:8443".
"""
from __future__ import annotations

import argparse
import hmac
import json
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

##############################################################################
#
# AES-128 (encrypt only), enough for Milenage
#

_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def _expand_key(key: bytes) -> list[bytes]:
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [_SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [bytes(sum(w[r * 4:r * 4 + 4], [])) for r in range(11)]


def aes128(key: bytes, block: bytes) -> bytes:
    rk = _expand_key(key)
    s = [b ^ k for b, k in zip(block, rk[0])]
    for r in range(1, 11):
        s = [_SBOX[b] for b in s]
        # ShiftRows (column-major state)
        s = [s[(i + 4 * (i % 4)) % 16] for i in range(16)]
        if r != 10:
            m = []
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                x = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[i] ^ x ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = m
        s = [b ^ k for b, k in zip(s, rk[r])]
    return bytes(s)

##############################################################################
#
# Milenage (TS 35.206)
#


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _rot(x: bytes, bits: int) -> bytes:
    n = bits // 8
    return x[n:] + x[:n]


_C = [bytes(15) + bytes([i]) for i in (0, 1, 2, 4, 8)]
_R = [64, 0, 32, 64, 96]


def opc_from_op(k: bytes, op: bytes) -> bytes:
    return _xor(aes128(k, op), op)


class Milenage:
    def __init__(self, k: bytes, opc: bytes):
        self.k, self.opc = k, opc

    def _out(self, temp: bytes, i: int) -> bytes:
        x = _xor(_rot(_xor(temp, self.opc), _R[i]), _C[i])
        return _xor(aes128(self.k, x), self.opc)

    def _temp(self, rand: bytes) -> bytes:
        return aes128(self.k, _xor(rand, self.opc))

    def f1(self, rand: bytes, sqn: bytes, amf: bytes) -> tuple[bytes, bytes]:
        """MAC-A, MAC-S"""
        in1 = sqn + amf + sqn + amf
        x = _xor(self._temp(rand), _rot(_xor(in1, self.opc), _R[0]))
        out1 = _xor(aes128(self.k, _xor(x, _C[0])), self.opc)
        return out1[:8], out1[8:]

    def f2345(self, rand: bytes) -> tuple[bytes, bytes, bytes, bytes, bytes]:
        """RES, CK, IK, AK, AK*"""
        t = self._temp(rand)
        out2, out3, out4, out5 = (self._out(t, i) for i in (1, 2, 3, 4))
        return out2[8:], out3, out4, out2[:6], out5[:6]


def _selftest():
    # TS 35.208 test set 1
    m = Milenage(bytes.fromhex("465b5ce8b199b49faa5f0a2ee238a6bc"),
                 bytes.fromhex("cd63cb71954a9f4e48a5994e37a02baf"))
    assert opc_from_op(m.k, bytes.fromhex("cdc202d5123e20f62b6d676ac72cb318")) == m.opc
    rand = bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")
    mac_a, mac_s = m.f1(rand, bytes.fromhex("ff9bb4d0b607"), bytes.fromhex("b9b9"))
    res, ck, ik, ak, aks = m.f2345(rand)
    assert mac_a.hex() == "4a9ffac354dfafb3" and mac_s.hex() == "01cfaf9ec4e871e9"
    assert res.hex() == "a54211d5e3ba50bf" and ak.hex() == "aa689c648370"
    assert ck.hex() == "b40ba9a3c58b2a05bbf0d987b21bf8cb"
    assert ik.hex() == "f769bcd751044604127672711c6d3441"
    assert aks.hex() == "451e8beca43b"

##############################################################################
#
# USIM
#


class AkaError(Exception):
    pass


class FakeUsim:
    def __init__(self, imsi: str, mil: Milenage, sqn: int):
        self.imsi, self.mil, self.sqn = imsi, mil, sqn
        self.lock = threading.Lock()

    def authenticate(self, rand: bytes, autn: bytes) -> dict:
        res, ck, ik, ak, aks = self.mil.f2345(rand)
        sqn = _xor(autn[:6], ak)
        amf, mac = autn[6:8], autn[8:]

        if not hmac.compare_digest(self.mil.f1(rand, sqn, amf)[0], mac):
            raise AkaError("MAC failure (AUTN rejected, wrong K/OPc?)")

        with self.lock:
            if int.from_bytes(sqn, "big") <= self.sqn:
                # TS 33.102 6.3.3: AUTS = SQNms ^ AK* || MAC-S (AMF = 0)
                sqn_ms = self.sqn.to_bytes(6, "big")
                mac_s = self.mil.f1(rand, sqn_ms, bytes(2))[1]
                auts = (_xor(sqn_ms, aks) + mac_s).hex()
                print(f"fakesim: stale SQN {sqn.hex()}, resync to {sqn_ms.hex()}")
                return {"res": auts, "ck": None, "ik": None, "auts": auts}
            self.sqn = int.from_bytes(sqn, "big")

        return {"res": res.hex(), "ck": ck.hex(), "ik": ik.hex()}

##############################################################################
#
# HTTP
#


def parse_hex(q: dict, name: str, length: int) -> bytes:
    try:
        value = bytes.fromhex(q[name][0])
    except (KeyError, IndexError, ValueError):
        raise ValueError(f"missing or invalid hex parameter '{name}'")
    if len(value) != length:
        raise ValueError(f"'{name}' must be {length} bytes")
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "NekoIMS-fakesim/1.0"
    usim: FakeUsim = None  # set in main()

    def _reply(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        q = parse_qs(urlparse(self.path).query)
        kind = q.get("type", [""])[0]
        try:
            if kind == "imsi":
                self._reply(200, {"imsi": self.usim.imsi})
            elif kind == "rand-autn":
                self._reply(200, self.usim.authenticate(
                    parse_hex(q, "rand", 16), parse_hex(q, "autn", 16)))
            else:
                self._reply(400, {"error": f"unknown type '{kind}'"})
        except ValueError as e:
            self._reply(400, {"error": str(e)})
        except AkaError as e:
            self._reply(502, {"error": str(e)})


class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--imsi", required=True)
    ap.add_argument("--k", required=True, help="subscriber key, 32 hex")
    key = ap.add_mutually_exclusive_group(required=True)
    key.add_argument("--opc", help="OPc, 32 hex")
    key.add_argument("--op", help="OP, 32 hex (OPc is derived)")
    ap.add_argument("--sqn", type=lambda s: int(s, 0), default=0,
                    help="highest SQN already seen (default 0)")
    ap.add_argument("--listen", default="127.0.0.1:8443", help="host:port")
    args = ap.parse_args()

    _selftest()

    k = bytes.fromhex(args.k)
    opc = bytes.fromhex(args.opc) if args.opc else opc_from_op(k, bytes.fromhex(args.op))
    if len(k) != 16 or len(opc) != 16:
        ap.error("K and OP/OPc must be 16 bytes (32 hex)")

    Handler.usim = FakeUsim(args.imsi, Milenage(k, opc), args.sqn)
    host, _, port = args.listen.rpartition(":")
    srv = Server((host, int(port)), Handler)
    print(f"fakesim: IMSI {args.imsi} on http://{args.listen}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
