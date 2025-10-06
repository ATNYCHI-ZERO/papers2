
import os, base64
from dataclasses import dataclass
from hashlib import sha3_256, sha3_512
from hmac import compare_digest
from typing import Tuple, Dict, Optional

# crypto primitives
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# try liboqs
try:
    import oqs
    _HAS_OQS = True
except Exception:
    _HAS_OQS = False

SUITE_ID = b"TRICROWN2-PQ-hybrid"
ALG_MLKEM = "ML-KEM-1024"
ALG_MCE = "Classic-McEliece-6960119"

def hkdf_extract(salt:bytes, ikm:bytes)->bytes:
    return HKDF(algorithm=hashes.SHA3_512(), length=64, salt=salt, info=b"TRICROWN2 extract").derive(ikm)

def hkdf_expand(prk:bytes, info:bytes, L:int)->bytes:
    return HKDF(algorithm=hashes.SHA3_512(), length=L, salt=None, info=info).derive(prk)

def transcript_hash(parts:list[bytes])->bytes:
    h=sha3_512()
    for p in parts: h.update(p)
    return h.digest()

def commit_tag(kc:bytes, sid:bytes, seq:int, nonce:bytes, aad:bytes, ct:bytes)->bytes:
    h=sha3_256()
    for b in (kc, SUITE_ID, sid, seq.to_bytes(8,'big'), nonce, aad, ct): h.update(b)
    return h.digest()

def derive_nonce(k_nonce:bytes, seq:int, nlen:int=12)->bytes:
    return hkdf_expand(k_nonce, b"nonce"+seq.to_bytes(8,'big'), nlen)

def next_mk(ck:bytes, seq:int)->Tuple[bytes,bytes]:
    mk = hkdf_expand(ck, b"mk"+seq.to_bytes(8,'big'), 32)
    ck2 = hkdf_extract(b"step", ck)
    return mk, ck2

# ===== liboqs KEM wrappers =====
class ServerKEMCtx:
    def __init__(self, alg:str):
        if not _HAS_OQS: 
            self.kem = None; self.pk = b""; return
        self.kem = oqs.KeyEncapsulation(alg)
        self.pk = self.kem.generate_keypair()  # returns public key bytes
    def decap(self, ct:bytes)->bytes:
        if self.kem is None: return b""
        return self.kem.decap_secret(ct)

def client_encap(alg:str, pk:bytes)->Tuple[bytes,bytes]:
    if not _HAS_OQS: return b"", b""
    kem = oqs.KeyEncapsulation(alg)
    ct, ss = kem.encap_secret(pk)
    return ct, ss

@dataclass
class Chains:
    rk: bytes
    ck_s: bytes
    ck_r: bytes
    k_commit: bytes
    k_nonce: bytes

@dataclass
class Ctx:
    role: str
    sid: bytes
    th: bytes
    chains: Chains
    x_sk: x25519.X25519PrivateKey
    x_pk: x25519.X25519PublicKey
    peer_x_pk: Optional[x25519.X25519PublicKey]
    # transcript copies
    last_chlo: Optional[bytes]
    last_shlo: Optional[bytes]
    # PQ server keys (server only)
    srv_mlkem: Optional[ServerKEMCtx]
    srv_mce: Optional[ServerKEMCtx]
    # presence flags
    pq_enabled: bool
    # seq
    seq_s:int=0
    seq_r:int=0

def ctx_init(role:str, enable_pq:bool=True)->Ctx:
    x_sk = x25519.X25519PrivateKey.generate()
    x_pk = x_sk.public_key()
    sid = os.urandom(16)
    chains = Chains(b"",b"",b"",b"",b"")
    pq_enabled = bool(enable_pq and _HAS_OQS)
    srv_mlkem = ServerKEMCtx(ALG_MLKEM) if (pq_enabled and role=="server") else None
    srv_mce   = ServerKEMCtx(ALG_MCE)   if (pq_enabled and role=="server") else None
    return Ctx(role, sid, b"", chains, x_sk, x_pk, None, None, None, srv_mlkem, srv_mce, pq_enabled, 0, 0)

def client_hello(ctx:Ctx)->bytes:
    pk = ctx.x_pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    msg=b"CHLO|"+SUITE_ID+b"|"+base64.b64encode(ctx.sid)+b"|"+base64.b64encode(pk)
    ctx.last_chlo = msg
    ctx.th = transcript_hash([msg])
    return msg

def server_hello(ctx_srv:Ctx, chlo:bytes)->bytes:
    parts = chlo.split(b"|")
    ctx_srv.sid = base64.b64decode(parts[2])
    pkb = base64.b64decode(parts[3])
    Xe_c = x25519.X25519PublicKey.from_public_bytes(pkb)
    ctx_srv.peer_x_pk = Xe_c
    # server X25519 pk
    pk_s = ctx_srv.x_pk.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    # add PQ pubs if enabled
    mlpk = base64.b64encode(ctx_srv.srv_mlkem.pk) if (ctx_srv.pq_enabled and ctx_srv.srv_mlkem) else b""
    mcpk = base64.b64encode(ctx_srv.srv_mce.pk) if (ctx_srv.pq_enabled and ctx_srv.srv_mce) else b""
    msg=b"SHLO|"+SUITE_ID+b"|"+base64.b64encode(pk_s)+b"|"+mlpk+b"|"+mcpk
    ctx_srv.last_shlo = msg
    ctx_srv.last_chlo = chlo
    ctx_srv.th = transcript_hash([chlo, msg])
    return msg

def client_finish(ctx:Ctx, shlo:bytes)->bytes:
    parts = shlo.split(b"|")
    pkb_s = base64.b64decode(parts[2])
    Xe_s = x25519.X25519PublicKey.from_public_bytes(pkb_s)
    ss_X = ctx.x_sk.exchange(Xe_s)
    # PQ encaps if present
    ss_ml = b""; ss_mce = b""; ct_ml=b""; ct_mce=b""
    if ctx.pq_enabled:
        # ML-KEM
        if len(parts[3])>0:
            srv_ml_pk = base64.b64decode(parts[3])
            ct_ml, ss_ml = client_encap(ALG_MLKEM, srv_ml_pk)
        # McEliece
        if len(parts[4])>0:
            srv_mce_pk = base64.b64decode(parts[4])
            ct_mce, ss_mce = client_encap(ALG_MCE, srv_mce_pk)
    th_pair = transcript_hash([ctx.last_chlo, shlo])
    ikm = ss_X + ss_ml + ss_mce
    mix = hkdf_extract(th_pair, ikm)
    hs = hkdf_expand(mix, b"TRICROWN2 hs"+SUITE_ID, 128)
    ctx.chains = Chains(hs[0:32], hs[32:64], hs[64:96], hs[96:128-32], hs[128-32:128])
    # send ciphertexts so server can decap
    msg=b"FIN|"+base64.b64encode(ct_ml)+b"|"+base64.b64encode(ct_mce)
    ctx.last_shlo = shlo
    ctx.th = transcript_hash([th_pair, msg])
    return msg

def server_finish(ctx_srv:Ctx, fin:bytes)->None:
    parts = fin.split(b"|")
    ct_ml = base64.b64decode(parts[1]) if len(parts)>1 and parts[1] else b""
    ct_mce= base64.b64decode(parts[2]) if len(parts)>2 and parts[2] else b""
    ss_X = ctx_srv.x_sk.exchange(ctx_srv.peer_x_pk)
    ss_ml = ctx_srv.srv_mlkem.decap(ct_ml) if (ctx_srv.pq_enabled and ctx_srv.srv_mlkem and len(ct_ml)>0) else b""
    ss_mce= ctx_srv.srv_mce.decap(ct_mce) if (ctx_srv.pq_enabled and ctx_srv.srv_mce and len(ct_mce)>0) else b""
    th_pair = transcript_hash([ctx_srv.last_chlo, ctx_srv.last_shlo])
    mix = hkdf_extract(th_pair, ss_X + ss_ml + ss_mce)
    hs = hkdf_expand(mix, b"TRICROWN2 hs"+SUITE_ID, 128)
    # swap send/recv for server
    ctx_srv.chains = Chains(hs[0:32], hs[64:96], hs[32:64], hs[96:128-32], hs[128-32:128])
    ctx_srv.th = transcript_hash([th_pair, fin])

def seal(ctx:Ctx, aad:bytes, pt:bytes)->Dict:
    seq = ctx.seq_s; ctx.seq_s += 1
    mk, ctx.chains.ck_s = next_mk(ctx.chains.ck_s, seq)
    nonce = derive_nonce(ctx.chains.k_nonce, seq, 12)
    aead = ChaCha20Poly1305(mk)
    ct = aead.encrypt(nonce, pt, aad)
    commit = commit_tag(ctx.chains.k_commit, ctx.sid, seq, nonce, aad, ct)
    return {"seq":seq, "nonce":nonce, "aad":aad, "ct":ct, "commit":commit}

def open_(ctx:Ctx, rec:Dict)->bytes:
    seq = rec["seq"]
    expect = commit_tag(ctx.chains.k_commit, ctx.sid, seq, rec["nonce"], rec["aad"], rec["ct"])
    if not compare_digest(expect, rec["commit"]):
        raise ValueError("commitment mismatch")
    mk, ctx.chains.ck_r = next_mk(ctx.chains.ck_r, seq)
    aead = ChaCha20Poly1305(mk)
    return aead.decrypt(rec["nonce"], rec["ct"], rec["aad"])

def rekey(ctx:Ctx)->None:
    mix = hkdf_extract(ctx.th, ctx.chains.rk)
    hs = hkdf_expand(mix, b"TRICROWN2 rk"+SUITE_ID, 128)
    if ctx.role == 'server':
        ctx.chains = Chains(hs[0:32], hs[64:96], hs[32:64], hs[96:128-32], hs[128-32:128])
    else:
        ctx.chains = Chains(hs[0:32], hs[32:64], hs[64:96], hs[96:128-32], hs[128-32:128])
