"""Local research relay. Public hosting requires a separate deployment review."""
import functools
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
import bcrypt
import jwt
import pyotp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from flask import Flask, request, jsonify, g
from .protocol import canonical, fingerprint, load_bundle, unb64, pss, verify_signature

def create_app(database,jwt_secret,enrollment_token,bcrypt_rounds=12):
    if len(jwt_secret)<32 or len(enrollment_token)<24:raise ValueError('strong server secrets required')
    app=Flask(__name__)
    app.config['MAX_CONTENT_LENGTH']=1550000
    app.config['DATABASE']=str(database)
    def db():
        c=sqlite3.connect(app.config['DATABASE']);c.row_factory=sqlite3.Row
        return c
    with db() as c:
        c.executescript('''PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password BLOB NOT NULL, totp TEXT NOT NULL, last_step INTEGER NOT NULL, bundle TEXT NOT NULL, epoch INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS messages (sender TEXT, recipient TEXT, id TEXT, envelope TEXT, created INTEGER, PRIMARY KEY(sender,id));
        CREATE TABLE IF NOT EXISTS attempts (name TEXT PRIMARY KEY, count INTEGER, since INTEGER);
        CREATE TABLE IF NOT EXISTS audit (user TEXT, action TEXT, created INTEGER);''')
    def auth(f):
        @functools.wraps(f)
        def wrapped(*a,**kw):
            try:
                kind,token=request.headers.get('Authorization','').split(' ',1)
                if kind!='Bearer':raise ValueError()
                claims=jwt.decode(token,jwt_secret,algorithms=['HS256'],audience='humanmsg-api',issuer='humanmsg-relay',options={'require':['exp','iat','sub','jti','epoch']})
                with db() as c:u=c.execute('SELECT epoch FROM users WHERE name=?',(claims['sub'],)).fetchone()
                if not u or claims['epoch']!=u['epoch']:raise ValueError()
                g.user=claims['sub']
            except (ValueError,jwt.PyJWTError):return jsonify(error='unauthorised'),401
            return f(*a,**kw)
        return wrapped
    def issue(u,epoch):
        now=int(time.time())
        return jwt.encode({'sub':u,'iss':'humanmsg-relay','aud':'humanmsg-api','iat':now,'exp':now+900,'jti':secrets.token_hex(16),'epoch':epoch},jwt_secret,algorithm='HS256')
    @app.errorhandler(413)
    def too_large(e):return jsonify(error='request too large'),413
    @app.errorhandler(400)
    def bad_request(e):return jsonify(error='invalid request'),400
    @app.post('/register')
    def register():
        if not secrets.compare_digest(request.headers.get('X-Enrolment-Token',''),enrollment_token):return jsonify(error='enrolment denied'),403
        try:
            d=request.get_json();name=d['username'];pw=d['password'];seed=d['totp_secret'];bundle=d['bundle']
            if not isinstance(name,str) or not re.fullmatch('[a-zA-Z0-9_-]{1,32}',name):raise ValueError()
            if not isinstance(pw,str) or not 12<=len(pw.encode())<=72:raise ValueError()
            if not isinstance(seed,str) or not re.fullmatch('[A-Z2-7]{32}',seed):raise ValueError()
            keys=load_bundle(bundle)
            proof=canonical({'username':name,'bundle':bundle})
            keys['sig'].verify(unb64(d['proof']),b'HumanMsg-1-register\x00'+proof,pss(),hashes.SHA256())
            if not pyotp.TOTP(seed).verify(d['totp'],valid_window=0):raise ValueError()
            hashed=bcrypt.hashpw(pw.encode(),bcrypt.gensalt(rounds=bcrypt_rounds))
            with db() as c:
                c.execute('INSERT INTO users(name,password,totp,last_step,bundle) VALUES (?,?,?,?,?)',(name,hashed,seed,int(time.time())//30-1,canonical(bundle).decode()))
            return jsonify(username=name,fingerprint=fingerprint(bundle)),201
        except sqlite3.IntegrityError:return jsonify(error='account exists'),409
        except (KeyError,TypeError,ValueError,InvalidSignature):return jsonify(error='invalid registration'),400
    @app.post('/login')
    def login():
        d=request.get_json(silent=True) or {};name=d.get('username');pw=d.get('password');code=d.get('totp')
        if not isinstance(name,str) or not isinstance(pw,str) or len(pw.encode())>72 or not isinstance(code,str):return jsonify(error='invalid credentials'),401
        now=int(time.time())
        with db() as c:
            c.execute('BEGIN IMMEDIATE')
            a=c.execute('SELECT count,since FROM attempts WHERE name=?',(name,)).fetchone()
            if a and now-a['since']<300 and a['count']>=5:return jsonify(error='temporarily rate limited'),429
            u=c.execute('SELECT * FROM users WHERE name=?',(name,)).fetchone()
            step=now//30
            good=u and bcrypt.checkpw(pw.encode(),u['password']) and pyotp.TOTP(u['totp']).verify(code,for_time=now,valid_window=0) and step>u['last_step']
            if not good:
                count=a['count']+1 if a and now-a['since']<300 else 1
                since=a['since'] if a and now-a['since']<300 else now
                c.execute('INSERT OR REPLACE INTO attempts VALUES (?,?,?)',(name,count,since))
                return jsonify(error='invalid credentials'),401
            c.execute('UPDATE users SET last_step=? WHERE name=?',(step,name))
            c.execute('DELETE FROM attempts WHERE name=?',(name,))
            c.execute('INSERT INTO audit VALUES (?,?,?)',(name,'login',now))
        return jsonify(token=issue(name,u['epoch']))
    @app.post('/logout')
    @auth
    def logout():
        with db() as c:c.execute('UPDATE users SET epoch=epoch+1 WHERE name=?',(g.user,))
        return jsonify(status='all existing account sessions revoked')
    @app.get('/api/public-key/<name>')
    @auth
    def key(name):
        with db() as c:u=c.execute('SELECT bundle FROM users WHERE name=?',(name,)).fetchone()
        if not u:return jsonify(error='not found'),404
        bundle=json.loads(u['bundle']);return jsonify(bundle=bundle,fingerprint=fingerprint(bundle))
    @app.post('/api/messages/send')
    @auth
    def send():
        env=request.get_json()
        try:
            with db() as c:
                s=c.execute('SELECT bundle FROM users WHERE name=?',(g.user,)).fetchone()
                verify_signature(env,json.loads(s['bundle']))
                h=env['header']
                if h['sender']!=g.user:raise ValueError()
                r=c.execute('SELECT bundle FROM users WHERE name=?',(h['recipient'],)).fetchone()
                if not r or h['recipient_fp']!=fingerprint(json.loads(r['bundle'])):raise ValueError()
                c.execute('INSERT INTO messages VALUES (?,?,?,?,?)',(g.user,h['recipient'],h['message_id'],canonical(env).decode(),int(time.time())))
                c.execute('INSERT INTO audit VALUES (?,?,?)',(g.user,'send',int(time.time())))
            return jsonify(id=h['message_id']),201
        except sqlite3.IntegrityError:return jsonify(error='duplicate message identifier'),409
        except (KeyError,TypeError,ValueError,InvalidSignature):return jsonify(error='invalid envelope'),400
    @app.get('/api/messages')
    @auth
    def inbox():
        with db() as c:rows=c.execute('SELECT sender,id FROM messages WHERE recipient=? ORDER BY created,id LIMIT 100',(g.user,)).fetchall()
        return jsonify(messages=[dict(r) for r in rows])
    @app.get('/api/messages/<sender>/<mid>')
    @auth
    def message(sender,mid):
        with db() as c:r=c.execute('SELECT envelope FROM messages WHERE sender=? AND id=? AND recipient=?',(sender,mid,g.user)).fetchone()
        return (jsonify(json.loads(r['envelope'])),200) if r else (jsonify(error='not found'),404)
    @app.delete('/api/messages/<sender>/<mid>')
    @auth
    def delete(sender,mid):
        with db() as c:r=c.execute('DELETE FROM messages WHERE sender=? AND id=? AND recipient=?',(sender,mid,g.user))
        return (jsonify(status='deleted'),200) if r.rowcount else (jsonify(error='not found'),404)
    @app.get('/api/audit-logs')
    @auth
    def logs():
        with db() as c:rows=c.execute('SELECT action,created FROM audit WHERE user=? ORDER BY created DESC LIMIT 100',(g.user,)).fetchall()
        return jsonify(events=[dict(r) for r in rows])
    return app

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--database',default='relay.sqlite');p.add_argument('--port',type=int,default=8765);a=p.parse_args()
    create_app(a.database,os.environ['HUMANMSG_JWT_SECRET'],os.environ['HUMANMSG_ENROLMENT_TOKEN']).run(host='127.0.0.1',port=a.port,debug=False)
