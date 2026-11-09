"""Portable reference client; credentials prompted rather than logged."""
import argparse
import getpass
import json
import os
import sys
import time
import jwt
import urllib.request
from pathlib import Path
import pyotp
from cryptography.hazmat.primitives import hashes
from .protocol import *

def api(base,path,method='GET',body=None,token=None,enrol=None):
    if not base.startswith(('https://','http://127.0.0.1:','http://localhost:')):
        raise ValueError('HTTPS required except for local loopback experiments')
    headers={'Content-Type':'application/json'}
    if token:headers['Authorization']='Bearer '+token
    if enrol:headers['X-Enrolment-Token']=enrol
    req=urllib.request.Request(base.rstrip('/')+path,data=canonical(body) if body is not None else None,headers=headers,method=method)
    with urllib.request.urlopen(req,timeout=30) as r:return json.load(r)

def main():
    p=argparse.ArgumentParser();p.add_argument('--server',default='http://127.0.0.1:8765');p.add_argument('--user',required=True);p.add_argument('--state',required=True)
    sub=p.add_subparsers(dest='command',required=True)
    sub.add_parser('register');pin=sub.add_parser('pin');pin.add_argument('peer');pin.add_argument('fingerprint')
    send=sub.add_parser('send');send.add_argument('peer');send.add_argument('file');send.add_argument('--conversation')
    sub.add_parser('inbox');recv=sub.add_parser('receive');recv.add_argument('sender');recv.add_argument('message_id');recv.add_argument('output')
    sub.add_parser('logout');args=p.parse_args()
    state=Path(args.state);state.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(state,0o700)
    vault=state/'identity.vault';pins=ClientState(state/'client.sqlite')
    if args.command=='register':
        if vault.exists():
            identity=load_identity(vault,getpass.getpass('Existing local vault password: '))
        else:
            identity=generate_identity();pw=getpass.getpass('New local vault password (12+ characters): ')
            save_identity(vault,identity,pw)
        bundle=public_bundle(identity);seed=pyotp.random_base32()
        print('Store this TOTP enrolment URI securely; it is not sent in messages:')
        print(pyotp.TOTP(seed).provisioning_uri(args.user,issuer_name='HumanMsg research'))
        password=getpass.getpass('New server account password (12–72 UTF-8 bytes): ')
        enrol=getpass.getpass('Organisation enrolment token: ')
        proof=identity['sig'].sign(b'HumanMsg-1-register\x00'+canonical({'username':args.user,'bundle':bundle}),pss(),hashes.SHA256())
        result=api(args.server,'/register','POST',{'username':args.user,'password':password,'totp_secret':seed,'totp':pyotp.TOTP(seed).now(),'bundle':bundle,'proof':b64(proof)},enrol=enrol)
        print('Account fingerprint:',result['fingerprint']);return
    session=state/'session.json';token=None
    if session.exists():
        saved=json.loads(session.read_bytes())
        if saved.get('server')==args.server and saved.get('user')==args.user:
            candidate=saved['token']
            # Local expiry is a convenience; the relay always validates signatures.
            if jwt.decode(candidate,options={'verify_signature':False})['exp']>time.time()+5:token=candidate
    if token is None:
        password=getpass.getpass('Server account password: ');code=getpass.getpass('Current TOTP code: ')
        token=api(args.server,'/login','POST',{'username':args.user,'password':password,'totp':code})['token']
        fd=os.open(session,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(fd,'wb') as f:f.write(canonical({'server':args.server,'user':args.user,'token':token}))
    if args.command=='logout':
        print(api(args.server,'/logout','POST',{},token));session.unlink(missing_ok=True);return
    if args.command=='inbox':print(json.dumps(api(args.server,'/api/messages',token=token),indent=2));return
    peer=args.peer if args.command in ('pin','send') else args.sender
    bundle=api(args.server,'/api/public-key/'+peer,token=token)['bundle']
    if args.command=='pin':
        pins.pin(peer,bundle,args.fingerprint);print('Verified key pinned.');return
    pins.require_pin(peer,bundle)
    identity=load_identity(vault,getpass.getpass('Local vault password: '))
    if args.command=='send':
        path=Path(args.file);content=path.read_bytes()
        env=seal(identity,args.user,peer,bundle,content,{'filename':path.name,'type':'file'},args.conversation)
        print(api(args.server,'/api/messages/send','POST',env,token));return
    env=api(args.server,'/api/messages/'+peer+'/'+args.message_id,token=token)
    content,metadata=pins.receive(identity,args.user,bundle,env)
    # Output path is explicitly chosen by the user; never trust sender filenames.
    fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as f:f.write(content)
    print('Decrypted to the requested output path. Metadata:',json.dumps(metadata))

if __name__=='__main__':main()
