
import base64, json
from tricrown_hybrid import ctx_init, client_hello, server_hello, client_finish, server_finish, seal, open_, rekey, _HAS_OQS

cli = ctx_init("client", enable_pq=True)
srv = ctx_init("server", enable_pq=True)

m1 = client_hello(cli)
m2 = server_hello(srv, m1)
m3 = client_finish(cli, m2)
server_finish(srv, m3)

def b64(x): return base64.b64encode(x).decode()

aad = b"v=1|suite=TRICROWN2-PQ-hybrid|dir=c2s"
pt1 = b"hybrid test 1"
pt2 = b"hybrid test 2"

rec1 = seal(cli, aad, pt1)
rec2 = seal(cli, aad, pt2)

out1 = open_(srv, rec1)
out2 = open_(srv, rec2)

# tamper
bad = dict(rec1); bad["ct"] = bytes([rec1["ct"][0]^1]) + rec1["ct"][1:]
tamper = False
try:
    open_(srv, bad)
except Exception:
    tamper = True

rekey(cli); rekey(srv)
rec3 = seal(cli, aad, b"post-rekey")
out3 = open_(srv, rec3)

print(json.dumps({
    "pq_backend_available": _HAS_OQS,
    "root_keys_equal": cli.chains.rk == srv.chains.rk,
    "decrypt_ok": (out1==pt1 and out2==pt2 and out3==b'post-rekey'),
    "tamper_detected": tamper,
    "nonce1_b64": b64(rec1["nonce"]),
    "nonce2_b64": b64(rec2["nonce"]),
    "commit1_b64": b64(rec1["commit"])
}, indent=2))
