import copy
import json
import io
import contextlib
import os
import platform
import sqlite3
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import jwt
import pyotp
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from humanmsg.protocol import *
from humanmsg.server import create_app

ROOT=Path(__file__).resolve().parents[1]
NODE=os.environ.get('HUMANMSG_NODE','node')
SECRET='test-jwt-secret-'+'X'*48
INVITE='test-enrolment-'+'Y'*32
PASSWORD='synthetic-account-password'

class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.identities={u:generate_identity() for u in ('alice','bob','mallory')}
        cls.bundles={u:public_bundle(k) for u,k in cls.identities.items()}
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)
        self.db=self.path/'relay.sqlite'
        # Reduced bcrypt cost in functional fixtures ONLY; shipping default is 12.
        self.app=create_app(self.db,SECRET,INVITE,bcrypt_rounds=4);self.app.testing=True
        self.http=self.app.test_client();self.seeds={};self.tokens={}
        for user in self.identities:
            seed=pyotp.random_base32();self.seeds[user]=seed
            bundle=self.bundles[user]
            proof=self.identities[user]['sig'].sign(b'HumanMsg-1-register\x00'+canonical({'username':user,'bundle':bundle}),pss(),hashes.SHA256())
            d={'username':user,'password':PASSWORD,'bundle':bundle,'totp_secret':seed,'totp':pyotp.TOTP(seed).now(),'proof':b64(proof)}
            r=self.http.post('/register',json=d,headers={'X-Enrolment-Token':INVITE});self.assertEqual(r.status_code,201)
            r=self.login(user);self.assertEqual(r.status_code,200);self.tokens[user]=r.json['token']
        self.env=seal(self.identities['alice'],'alice','bob',self.bundles['bob'],b'SYNTHETIC_BENEFICIARY_MARKER_6839',{'filename':'SYNTHETIC_PRIVATE_NAME_6839.csv'})
    def tearDown(self):self.tmp.cleanup()
    def login(self,user,**overrides):
        d={'username':user,'password':PASSWORD,'totp':pyotp.TOTP(self.seeds[user]).now()};d.update(overrides)
        return self.http.post('/login',json=d)
    def headers(self,user='alice'):return {'Authorization':'Bearer '+self.tokens[user]}
    def send(self,e=None,user='alice'):return self.http.post('/api/messages/send',json=e or self.env,headers=self.headers(user))
    def receive(self,e=None):return open_envelope(self.identities['bob'],'bob',self.bundles['alice'],e or self.env)
    def resign(self,e):e['signature']=b64(self.identities['alice']['sig'].sign(signed_bytes(e),pss(),hashes.SHA256()));return e
    def flipped(self,field):
        e=copy.deepcopy(self.env);v=bytearray(unb64(e[field]));v[0]^=1;e[field]=b64(v);return e
    def test_01_text_round_trip(self):
        self.assertEqual(self.receive()[0],b'SYNTHETIC_BENEFICIARY_MARKER_6839')
    def test_02_empty_round_trip(self):
        self.assertEqual(self.receive(seal(self.identities['alice'],'alice','bob',self.bundles['bob'],b''))[0],b'')
    def test_03_unicode_round_trip(self):
        content='Windhoek – Harare: rubatsiro 援助'.encode()
        e=seal(self.identities['alice'],'alice','bob',self.bundles['bob'],content,{'filename':'援助.txt'})
        self.assertEqual(self.receive(e),(content,{'filename':'援助.txt'}))
    def test_04_maximum_file(self):
        content=os.urandom(MAX_CONTENT)
        self.assertEqual(self.receive(seal(self.identities['alice'],'alice','bob',self.bundles['bob'],content))[0],content)
    def test_05_oversize_rejected(self):
        with self.assertRaises(ValueError):seal(self.identities['alice'],'alice','bob',self.bundles['bob'],b'x'*(MAX_CONTENT+1))
    def test_06_ciphertext_mutation(self):
        with self.assertRaises(Exception):self.receive(self.flipped('ciphertext'))
    def test_07_tag_mutation_with_valid_signature(self):
        e=copy.deepcopy(self.env);v=bytearray(unb64(e['ciphertext']));v[-1]^=1;e['ciphertext']=b64(v);self.resign(e)
        with self.assertRaises(Exception):self.receive(e)
    def test_08_nonce_mutation_with_valid_signature(self):
        with self.assertRaises(Exception):self.receive(self.resign(self.flipped('nonce')))
    def test_09_wrapped_key_mutation(self):
        with self.assertRaises(Exception):self.receive(self.resign(self.flipped('wrapped_key')))
    def test_10_signature_mutation(self):
        with self.assertRaises(Exception):self.receive(self.flipped('signature'))
    def test_11_each_header_field_mutation(self):
        for key in sorted(self.env['header']):
            with self.subTest(key=key):
                e=copy.deepcopy(self.env);e['header'][key]=2 if key=='version' else 'modified'
                with self.assertRaises(Exception):self.receive(e)
    def test_12_unknown_field_and_algorithm_rejected(self):
        e=copy.deepcopy(self.env);e['extra']='ignored?'
        with self.assertRaises(ValueError):self.receive(e)
        e=copy.deepcopy(self.env);e['header']['suite']='none'
        with self.assertRaises(ValueError):self.receive(e)
    def test_13_wrong_recipient(self):
        with self.assertRaises(ValueError):open_envelope(self.identities['mallory'],'mallory',self.bundles['alice'],self.env)
    def test_14_sender_substitution(self):
        with self.assertRaises(ValueError):open_envelope(self.identities['bob'],'bob',self.bundles['mallory'],self.env)
    def test_15_first_contact_requires_verified_fingerprint(self):
        state=ClientState(self.path/'client.sqlite')
        with self.assertRaises(ValueError):state.pin('alice',self.bundles['alice'])
        state.pin('alice',self.bundles['alice'],fingerprint(self.bundles['alice']))
        state.require_pin('alice',self.bundles['alice'])
    def test_16_changed_key_blocked(self):
        state=ClientState(self.path/'client.sqlite');state.pin('alice',self.bundles['alice'],fingerprint(self.bundles['alice']))
        with self.assertRaises(ValueError):state.pin('alice',self.bundles['mallory'],fingerprint(self.bundles['mallory']))
    def test_17_client_replay_rejected_after_restart(self):
        p=self.path/'client.sqlite';state=ClientState(p);state.pin('alice',self.bundles['alice'],fingerprint(self.bundles['alice']))
        self.assertTrue(state.receive(self.identities['bob'],'bob',self.bundles['alice'],self.env)[0])
        with self.assertRaises(ValueError):ClientState(p).receive(self.identities['bob'],'bob',self.bundles['alice'],self.env)
    def test_18_relay_replay_rejected_after_restart(self):
        self.assertEqual(self.send().status_code,201)
        self.http=create_app(self.db,SECRET,INVITE,bcrypt_rounds=4).test_client()
        self.assertEqual(self.send().status_code,409)
    def test_19_cross_account_read_blocked(self):
        self.send();h=self.env['header'];url=f"/api/messages/alice/{h['message_id']}"
        self.assertEqual(self.http.get(url,headers=self.headers('mallory')).status_code,404)
        self.assertEqual(self.http.get(url,headers=self.headers('bob')).status_code,200)
    def test_20_cross_account_send_and_delete_blocked(self):
        self.assertEqual(self.send(user='mallory').status_code,400)
        self.send();url='/api/messages/alice/'+self.env['header']['message_id']
        self.assertEqual(self.http.delete(url,headers=self.headers('mallory')).status_code,404)
        self.assertEqual(self.http.delete(url,headers=self.headers('bob')).status_code,200)
    def test_21_missing_and_expired_token(self):
        self.assertEqual(self.http.get('/api/messages').status_code,401)
        token=jwt.encode({'sub':'bob','iss':'humanmsg-relay','aud':'humanmsg-api','iat':int(time.time())-60,'exp':int(time.time())-1,'jti':'x','epoch':0},SECRET,algorithm='HS256')
        self.assertEqual(self.http.get('/api/messages',headers={'Authorization':'Bearer '+token}).status_code,401)
    def test_22_wrong_audience_and_algorithm(self):
        for alg,aud in [('HS256','other'),('HS384','humanmsg-api')]:
            token=jwt.encode({'sub':'bob','iss':'humanmsg-relay','aud':aud,'iat':int(time.time()),'exp':int(time.time())+60,'jti':'x','epoch':0},SECRET,algorithm=alg)
            self.assertEqual(self.http.get('/api/messages',headers={'Authorization':'Bearer '+token}).status_code,401)
    def test_23_totp_reuse_rejected(self):self.assertEqual(self.login('alice').status_code,401)
    def test_24_wrong_password_and_totp_rate_limit(self):
        for _ in range(5):self.assertEqual(self.login('alice',password='wrong').status_code,401)
        self.assertEqual(self.login('alice',password='wrong').status_code,429)
        self.assertEqual(self.login('bob',totp='0000000').status_code,401)
    def test_25_logout_revokes_token(self):
        self.assertEqual(self.http.post('/logout',headers=self.headers()).status_code,200)
        self.assertEqual(self.http.get('/api/messages',headers=self.headers()).status_code,401)
    def test_26_enrolment_protected(self):self.assertEqual(self.http.post('/register',json={}).status_code,403)
    def test_27_storage_contains_no_seeded_content(self):
        self.send()
        with sqlite3.connect(self.db) as c:
            dump='\n'.join(c.iterdump())
        self.assertNotIn('SYNTHETIC_BENEFICIARY_MARKER_6839',dump)
        self.assertNotIn('SYNTHETIC_PRIVATE_NAME_6839',dump)
        self.assertNotIn('PRIVATE KEY',dump)
        self.assertNotIn(PASSWORD,dump)
        self.assertIn('alice',dump) # Metadata exposure is expected.
        self.assertIn(self.seeds['alice'],dump) # TOTP seed protection is a deployment limitation.
    def test_28_vault_round_trip_and_wrong_password(self):
        p=self.path/'identity.vault';save_identity(p,self.identities['alice'],'local-vault-password')
        loaded=load_identity(p,'local-vault-password')
        self.assertEqual(public_bundle(loaded),self.bundles['alice'])
        with self.assertRaises(Exception):load_identity(p,'wrong-password')
        self.assertEqual(p.stat().st_mode&0o777,0o600)
    def test_29_long_term_compromise_exposes_recorded_message(self):
        # Expected limitation, NOT a forward-secrecy success.
        h=self.env['header'];cek=self.identities['bob']['enc'].decrypt(unb64(self.env['wrapped_key']),oaep(h))
        inner=AESGCM(cek).decrypt(unb64(self.env['nonce']),unb64(self.env['ciphertext']),canonical(h))
        self.assertIn(b'SYNTHETIC_BENEFICIARY_MARKER_6839',inner)
    def node(self,mode,data):
        src=self.path/'input.json';dst=self.path/'output.json';src.write_bytes(canonical(data))
        subprocess.run([NODE,str(ROOT/'web/interop.mjs'),mode,str(src),str(dst)],check=True,capture_output=True)
        return json.loads(dst.read_bytes())
    def export(self,user):
        return {'bundle':self.bundles[user],'private':{k:b64(v.private_bytes(serialization.Encoding.DER,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())) for k,v in self.identities[user].items()}}
    def test_30_python_to_webcrypto(self):
        r=self.node('open',{'identity':self.export('bob'),'recipient':'bob','sender_bundle':self.bundles['alice'],'envelope':self.env})
        self.assertEqual(unb64(r['content']),self.receive()[0])
    def test_31_webcrypto_to_python(self):
        e=self.node('seal',{'identity':self.export('alice'),'sender':'alice','recipient':'bob','recipient_bundle':self.bundles['bob'],'content':b64(b'JS interoperable file'),'metadata':{'filename':'test.dat'}})
        self.assertEqual(self.receive(e),(b'JS interoperable file',{'filename':'test.dat'}))
    def test_32_webcrypto_rejects_tampering(self):
        with self.assertRaises(subprocess.CalledProcessError):self.node('open',{'identity':self.export('bob'),'recipient':'bob','sender_bundle':self.bundles['alice'],'envelope':self.flipped('ciphertext')})
    def test_33_relay_rejects_tampered_signature(self):self.assertEqual(self.send(self.flipped('signature')).status_code,400)
    def test_34_ciphertext_persists_after_restart(self):
        self.send();h=self.env['header'];self.http=create_app(self.db,SECRET,INVITE,bcrypt_rounds=4).test_client()
        r=self.http.get('/api/messages/alice/'+h['message_id'],headers=self.headers('bob'))
        self.assertEqual(r.status_code,200);self.assertEqual(self.receive(r.json),self.receive())
    def test_35_request_limit(self):
        self.assertEqual(self.http.post('/api/messages/send',data=b'x'*1550001,content_type='application/json',headers=self.headers()).status_code,413)
    def test_36_totp_reuse_rejected_after_restart(self):
        self.http=create_app(self.db,SECRET,INVITE,bcrypt_rounds=4).test_client()
        self.assertEqual(self.login('alice').status_code,401)

    def test_37_cli_pin_send_receive_with_cached_sessions(self):
        from humanmsg.cli import main
        for user in ('alice','bob'):
            d=self.path/(user+'-state');d.mkdir()
            save_identity(d/'identity.vault',self.identities[user],'synthetic-vault-password')
            (d/'session.json').write_bytes(canonical({'server':'http://127.0.0.1:8765','user':user,'token':self.tokens[user]}))
        def transport(base,path,method='GET',body=None,token=None,enrol=None):
            headers={}
            if token:headers['Authorization']='Bearer '+token
            if enrol:headers['X-Enrolment-Token']=enrol
            response=self.http.open(path,method=method,json=body,headers=headers)
            if response.status_code>=400:raise ValueError(response.json)
            return response.json
        def command(user,*args):
            argv=['humanmsg','--user',user,'--state',str(self.path/(user+'-state')),*args]
            with patch('sys.argv',argv),patch('humanmsg.cli.api',side_effect=transport),patch('getpass.getpass',return_value='synthetic-vault-password'),contextlib.redirect_stdout(io.StringIO()):main()
        command('alice','pin','bob',fingerprint(self.bundles['bob']))
        command('bob','pin','alice',fingerprint(self.bundles['alice']))
        source=self.path/'synthetic.txt';source.write_bytes(b'CLI synthetic transfer')
        command('alice','send','bob',str(source))
        messages=self.http.get('/api/messages',headers=self.headers('bob')).json['messages']
        target=self.path/'received.txt'
        command('bob','receive','alice',messages[0]['id'],str(target))
        self.assertEqual(target.read_bytes(),source.read_bytes())
        self.assertEqual(target.stat().st_mode&0o777,0o600)

class EvidenceResult(unittest.TextTestResult):
    def __init__(self,*a,**kw):super().__init__(*a,**kw);self.records=[]
    def startTest(self,test):self.started=time.perf_counter();super().startTest(test)
    def addSuccess(self,test):self.records.append({'test':test.id(),'status':'passed','seconds':time.perf_counter()-self.started});super().addSuccess(test)
    def addFailure(self,test,err):self.records.append({'test':test.id(),'status':'failed','detail':self._exc_info_to_string(err,test)});super().addFailure(test,err)
    def addError(self,test,err):self.records.append({'test':test.id(),'status':'error','detail':self._exc_info_to_string(err,test)});super().addError(test,err)

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ReferenceTests)
    result=unittest.TextTestRunner(verbosity=2,resultclass=EvidenceResult).run(suite)
    out=ROOT/'evidence/security-tests.json';out.write_text(json.dumps({'version':'1.0.0','date_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'platform':platform.platform(),'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'fixture_bcrypt_rounds':4,'production_default_bcrypt_rounds':12,'records':result.records},indent=2))
    raise SystemExit(not result.wasSuccessful())
