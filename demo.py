"""Synthetic live HTTP demonstration using ephemeral loopback storage."""
import json
import logging
import secrets
import tempfile
import threading
import time
from pathlib import Path
import pyotp
from cryptography.hazmat.primitives import hashes
from werkzeug.serving import make_server
from humanmsg.server import create_app
from humanmsg.cli import api
from humanmsg.protocol import *

def run():
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp);invite=secrets.token_urlsafe(32);secret=secrets.token_urlsafe(48)
        app=create_app(p/'relay.sqlite',secret,invite)
        server=make_server('127.0.0.1',0,app);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        base=f'http://127.0.0.1:{server.server_port}';identities={};bundles={};tokens={}
        try:
            for user in ('alice','bob'):
                identity=generate_identity();save_identity(p/(user+'.vault'),identity,'synthetic-local-vault-password')
                identity=load_identity(p/(user+'.vault'),'synthetic-local-vault-password');identities[user]=identity
                bundle=public_bundle(identity);bundles[user]=bundle;seed=pyotp.random_base32()
                proof=identity['sig'].sign(b'HumanMsg-1-register\x00'+canonical({'username':user,'bundle':bundle}),pss(),hashes.SHA256())
                api(base,'/register','POST',{'username':user,'password':'synthetic-demo-account-password','totp_secret':seed,'totp':pyotp.TOTP(seed).now(),'bundle':bundle,'proof':b64(proof)},enrol=invite)
                tokens[user]=api(base,'/login','POST',{'username':user,'password':'synthetic-demo-account-password','totp':pyotp.TOTP(seed).now()})['token']
            bob_bundle=api(base,'/api/public-key/bob',token=tokens['alice'])['bundle']
            sender=ClientState(p/'alice-state.sqlite');sender.pin('bob',bob_bundle,fingerprint(bundles['bob']))
            receiver=ClientState(p/'bob-state.sqlite');receiver.pin('alice',bundles['alice'],fingerprint(bundles['alice']))
            payload=b'Synthetic humanitarian referral. No real beneficiary data.'
            e=seal(identities['alice'],'alice','bob',bob_bundle,payload,{'filename':'synthetic-referral.txt'})
            sent=api(base,'/api/messages/send','POST',e,tokens['alice'])
            inbox=api(base,'/api/messages',token=tokens['bob']);assert len(inbox['messages'])==1
            got=api(base,'/api/messages/alice/'+sent['id'],token=tokens['bob'])
            plaintext,meta=receiver.receive(identities['bob'],'bob',bundles['alice'],got)
            assert plaintext==payload and meta['filename']=='synthetic-referral.txt'
            replay=False
            try:ClientState(p/'bob-state.sqlite').receive(identities['bob'],'bob',bundles['alice'],got)
            except ValueError:replay=True
            assert replay
            api(base,'/api/messages/alice/'+sent['id'],'DELETE',token=tokens['bob'])
            assert not api(base,'/api/messages',token=tokens['bob'])['messages']
            return {'date_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'transport':'live HTTP loopback, no TLS','bcrypt_rounds':12,
                    'registration':True,'vault_reload':True,'totp_login':True,'verified_pinning':True,'send_and_receive':True,'file_bytes_equal':True,'replay_rejected_after_client_restart':True,'recipient_delete':True,'synthetic_payload_bytes':len(payload)}
        finally:server.shutdown();thread.join();server.server_close()

if __name__=='__main__':
    result=run();(Path(__file__).resolve().parent/'evidence/http-demo.json').write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
