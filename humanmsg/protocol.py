"""Versioned experimental envelope. Does not provide forward secrecy."""
import base64
import hashlib
import json
import os
import re
import sqlite3
import struct
import uuid
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SUITE = 'RSA2048-OAEP-SHA256+A256GCM+RSA2048-PSS-SHA256'
DOMAIN = b'HumanMsg-1-envelope\x00'
MAX_CONTENT = 1024 * 1024
MAX_ENVELOPE = 1500000
HEADER_FIELDS = {'version','suite','sender','recipient','sender_fp','recipient_fp','message_id','conversation_id'}
FIELDS = {'header','nonce','wrapped_key','ciphertext','signature'}

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')

def b64(b):
    return base64.b64encode(b).decode('ascii')

def unb64(s):
    if not isinstance(s, str):
        raise ValueError('base64 field must be text')
    return base64.b64decode(s, validate=True)

def generate_identity():
    return {k:rsa.generate_private_key(public_exponent=65537,key_size=2048) for k in ('enc','sig')}

def public_bundle(identity):
    return {k:b64(v.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)) for k,v in identity.items()}

def load_bundle(bundle):
    if not isinstance(bundle,dict) or set(bundle) != {'enc','sig'}:
        raise ValueError('invalid public bundle')
    keys={k:serialization.load_der_public_key(unb64(v)) for k,v in bundle.items()}
    for key in keys.values():
        if not isinstance(key,rsa.RSAPublicKey) or key.key_size != 2048 or key.public_numbers().e != 65537:
            raise ValueError('invalid RSA profile')
    if bundle['enc'] == bundle['sig']:
        raise ValueError('separate keys required')
    return keys

def fingerprint(bundle):
    load_bundle(bundle)
    return hashlib.sha256(canonical(bundle)).hexdigest()

def pss():
    return padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32)

def oaep(header):
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),algorithm=hashes.SHA256(),label=canonical(header))

def validate_envelope(env):
    if not isinstance(env,dict) or set(env) != FIELDS or len(canonical(env)) > MAX_ENVELOPE:
        raise ValueError('invalid envelope')
    h=env['header']
    if not isinstance(h,dict) or set(h) != HEADER_FIELDS or type(h['version']) is not int or h['version'] != 1 or h['suite'] != SUITE:
        raise ValueError('unsupported profile')
    for k in ('sender','recipient'):
        if not isinstance(h[k],str) or not re.fullmatch('[a-zA-Z0-9_-]{1,32}',h[k]):raise ValueError('invalid account')
    for k in ('sender_fp','recipient_fp'):
        if not isinstance(h[k],str) or not re.fullmatch('[0-9a-f]{64}',h[k]):raise ValueError('invalid fingerprint')
    for k in ('message_id','conversation_id'):
        if not isinstance(h[k],str) or not re.fullmatch('[0-9a-f]{32}',h[k]):raise ValueError('invalid identifier')
    if len(unb64(env['nonce'])) != 12 or len(unb64(env['wrapped_key'])) != 256 or len(unb64(env['signature'])) != 256:
        raise ValueError('invalid field length')
    if not 23 <= len(unb64(env['ciphertext'])) <= MAX_CONTENT+4096+23:
        raise ValueError('invalid ciphertext length')
    return h

def signed_bytes(env):
    return DOMAIN+canonical({k:v for k,v in env.items() if k != 'signature'})

def verify_signature(env,sender_bundle):
    h=validate_envelope(env)
    if fingerprint(sender_bundle) != h['sender_fp']:raise ValueError('sender key mismatch')
    load_bundle(sender_bundle)['sig'].verify(unb64(env['signature']),signed_bytes(env),pss(),hashes.SHA256())

def seal(identity,sender,recipient,recipient_bundle,content,metadata=None,conversation_id=None):
    if not isinstance(content,bytes) or len(content)>MAX_CONTENT:raise ValueError('content limit exceeded')
    if metadata is not None and not isinstance(metadata,dict):raise ValueError('metadata must be an object')
    meta=canonical(metadata or {})
    if len(meta)>4096:raise ValueError('metadata limit exceeded')
    h={'version':1,'suite':SUITE,'sender':sender,'recipient':recipient,'sender_fp':fingerprint(public_bundle(identity)),
       'recipient_fp':fingerprint(recipient_bundle),'message_id':uuid.uuid4().hex,'conversation_id':conversation_id or uuid.uuid4().hex}
    cek=os.urandom(32);nonce=os.urandom(12)
    inner=b'HM1'+struct.pack('>I',len(meta))+meta+content
    env={'header':h,'nonce':b64(nonce),'wrapped_key':b64(load_bundle(recipient_bundle)['enc'].encrypt(cek,oaep(h))),
         'ciphertext':b64(AESGCM(cek).encrypt(nonce,inner,canonical(h)))}
    env['signature']=b64(identity['sig'].sign(signed_bytes(env),pss(),hashes.SHA256()))
    validate_envelope(env)
    return env

def open_envelope(identity,recipient,sender_bundle,env):
    h=validate_envelope(env)
    if h['recipient'] != recipient or h['recipient_fp'] != fingerprint(public_bundle(identity)):raise ValueError('wrong recipient')
    verify_signature(env,sender_bundle)
    cek=identity['enc'].decrypt(unb64(env['wrapped_key']),oaep(h))
    inner=AESGCM(cek).decrypt(unb64(env['nonce']),unb64(env['ciphertext']),canonical(h))
    if inner[:3] != b'HM1' or len(inner)<7:raise ValueError('invalid inner frame')
    size=struct.unpack('>I',inner[3:7])[0]
    if size>4096 or 7+size>len(inner):raise ValueError('invalid metadata length')
    meta=json.loads(inner[7:7+size])
    if not isinstance(meta,dict):raise ValueError('invalid metadata')
    return inner[7+size:],meta

def save_identity(path,identity,password):
    """Scrypt 2^15/8/1 then AES-GCM. No plaintext keys written."""
    if len(password)<12:raise ValueError('vault password must have 12 characters')
    salt=os.urandom(16);nonce=os.urandom(12)
    key=Scrypt(salt=salt,length=32,n=32768,r=8,p=1).derive(password.encode())
    data={k:b64(v.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())) for k,v in identity.items()}
    vault={'version':1,'salt':b64(salt),'nonce':b64(nonce),'ciphertext':b64(AESGCM(key).encrypt(nonce,canonical(data),b'HumanMsg-1-vault'))}
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(canonical(vault))

def load_identity(path,password):
    vault=json.loads(Path(path).read_bytes())
    if set(vault)!={'version','salt','nonce','ciphertext'} or vault['version']!=1:raise ValueError('invalid vault')
    key=Scrypt(salt=unb64(vault['salt']),length=32,n=32768,r=8,p=1).derive(password.encode())
    data=json.loads(AESGCM(key).decrypt(unb64(vault['nonce']),unb64(vault['ciphertext']),b'HumanMsg-1-vault'))
    identity={k:serialization.load_der_private_key(unb64(v),password=None) for k,v in data.items()}
    fingerprint(public_bundle(identity))
    return identity

class ClientState:
    """Local pinning and durable duplicate detection; never stores plaintext."""
    def __init__(self,path):
        self.path=str(path)
        with self.connect() as c:
            c.execute('CREATE TABLE IF NOT EXISTS pins (user TEXT PRIMARY KEY, fp TEXT NOT NULL)')
            c.execute('CREATE TABLE IF NOT EXISTS seen (sender TEXT, conversation TEXT, message TEXT, PRIMARY KEY(sender,conversation,message))')
    def connect(self):return sqlite3.connect(self.path)
    def pin(self,user,bundle,expected=None):
        fp=fingerprint(bundle)
        with self.connect() as c:
            old=c.execute('SELECT fp FROM pins WHERE user=?',(user,)).fetchone()
            if old and old[0]!=fp:raise ValueError('IDENTITY CHANGED: independently verify before re-enrolment')
            if not old:
                if expected!=fp:raise ValueError('first contact requires independently verified fingerprint')
                c.execute('INSERT INTO pins VALUES (?,?)',(user,fp))
        return fp
    def require_pin(self,user,bundle):
        fp=fingerprint(bundle)
        with self.connect() as c:old=c.execute('SELECT fp FROM pins WHERE user=?',(user,)).fetchone()
        if not old or old[0]!=fp:raise ValueError('unverified identity')
    def receive(self,identity,recipient,sender_bundle,env):
        self.require_pin(env['header']['sender'],sender_bundle)
        plaintext,metadata=open_envelope(identity,recipient,sender_bundle,env)
        h=env['header']
        with self.connect() as c:
            try:c.execute('INSERT INTO seen VALUES (?,?,?)',(h['sender_fp'],h['conversation_id'],h['message_id']))
            except sqlite3.IntegrityError:raise ValueError('duplicate envelope') from None
        return plaintext,metadata
