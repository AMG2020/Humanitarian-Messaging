/* Independent Web Crypto implementation of HumanMsg-1. */
const te = new TextEncoder();
const td = new TextDecoder('utf-8', {fatal:true});
const suite='RSA2048-OAEP-SHA256+A256GCM+RSA2048-PSS-SHA256';
export const canonical = x => JSON.stringify(x, Object.keys(x).sort());
// Recursively sort keys, including the nested envelope header.
export const encode = x => te.encode(JSON.stringify(x, function(k,v){
  if(v && typeof v==='object' && !Array.isArray(v)) return Object.fromEntries(Object.keys(v).sort().map(k=>[k,v[k]]));
  return v;
}));
export const b64 = x => {
  let s='';for(const n of new Uint8Array(x))s+=String.fromCharCode(n);return btoa(s);
};
export const unb64 = s => {
  if(typeof s!=='string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(s))throw Error('invalid base64');
  return Uint8Array.from(atob(s),x=>x.charCodeAt(0));
};
const concat = (...xs) => {
  const out=new Uint8Array(xs.reduce((s,x)=>s+x.length,0));let n=0;
  for(const x of xs){out.set(x,n);n+=x.length;}return out;
};
const hex = x => [...new Uint8Array(x)].map(b=>b.toString(16).padStart(2,'0')).join('');
const random = n => crypto.getRandomValues(new Uint8Array(n));
const id = () => hex(random(16));
const importPublic = (key,alg,use) => crypto.subtle.importKey('spki',unb64(key),{name:alg,hash:'SHA-256'},false,[use]);
const importPrivate = (key,alg,use) => crypto.subtle.importKey('pkcs8',unb64(key),{name:alg,hash:'SHA-256'},false,[use]);
export const fingerprint = async bundle => hex(await crypto.subtle.digest('SHA-256',encode(bundle)));
const unsigned = e => Object.fromEntries(Object.entries(e).filter(([k])=>k!=='signature'));
const signed = e => concat(te.encode('HumanMsg-1-envelope\x00'),encode(unsigned(e)));
export async function seal(identity,sender,recipient,recipientBundle,content,metadata={},conversationId=null){
  content=new Uint8Array(content);
  if(content.length>1048576)throw Error('content limit');
  const meta=encode(metadata);if(meta.length>4096)throw Error('metadata limit');
  const h={version:1,suite,sender,recipient,sender_fp:await fingerprint(identity.bundle),recipient_fp:await fingerprint(recipientBundle),message_id:id(),conversation_id:conversationId||id()};
  const aad=encode(h),cek=random(32),nonce=random(12),size=new Uint8Array(4);
  new DataView(size.buffer).setUint32(0,meta.length);
  const key=await crypto.subtle.importKey('raw',cek,'AES-GCM',false,['encrypt']);
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:aad,tagLength:128},key,concat(te.encode('HM1'),size,meta,content));
  const enc=await importPublic(recipientBundle.enc,'RSA-OAEP','encrypt');
  const wrapped=await crypto.subtle.encrypt({name:'RSA-OAEP',label:aad},enc,cek);
  const e={header:h,nonce:b64(nonce),wrapped_key:b64(wrapped),ciphertext:b64(ciphertext)};
  const sk=await importPrivate(identity.private.sig,'RSA-PSS','sign');
  e.signature=b64(await crypto.subtle.sign({name:'RSA-PSS',saltLength:32},sk,signed(e)));
  return e;
}
export async function openEnvelope(identity,recipient,senderBundle,e){
  if(!e || Object.keys(e).sort().join(',')!=='ciphertext,header,nonce,signature,wrapped_key')throw Error('envelope fields');
  const h=e.header;
  if(!h || Object.keys(h).sort().join(',')!=='conversation_id,message_id,recipient,recipient_fp,sender,sender_fp,suite,version' || h.version!==1 || h.suite!==suite)throw Error('profile');
  for(const k of ['sender','recipient'])if(!/^[A-Za-z0-9_-]{1,32}$/.test(h[k]))throw Error('account');
  for(const k of ['sender_fp','recipient_fp'])if(!/^[0-9a-f]{64}$/.test(h[k]))throw Error('fingerprint');
  for(const k of ['message_id','conversation_id'])if(!/^[0-9a-f]{32}$/.test(h[k]))throw Error('identifier');
  if(h.recipient!==recipient || h.recipient_fp!==await fingerprint(identity.bundle) || h.sender_fp!==await fingerprint(senderBundle))throw Error('identity');
  const nonce=unb64(e.nonce),wrapped=unb64(e.wrapped_key),sig=unb64(e.signature),ct=unb64(e.ciphertext);
  if(nonce.length!==12 || wrapped.length!==256 || sig.length!==256 || ct.length<23 || ct.length>1052695)throw Error('field length');
  const pk=await importPublic(senderBundle.sig,'RSA-PSS','verify');
  if(!await crypto.subtle.verify({name:'RSA-PSS',saltLength:32},pk,sig,signed(e)))throw Error('signature');
  const sk=await importPrivate(identity.private.enc,'RSA-OAEP','decrypt');
  const cek=await crypto.subtle.decrypt({name:'RSA-OAEP',label:encode(h)},sk,wrapped);
  const key=await crypto.subtle.importKey('raw',cek,'AES-GCM',false,['decrypt']);
  const inner=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:nonce,additionalData:encode(h),tagLength:128},key,ct));
  if(td.decode(inner.slice(0,3))!=='HM1' || inner.length<7)throw Error('inner frame');
  const n=new DataView(inner.buffer,inner.byteOffset,inner.byteLength).getUint32(3);
  if(n>4096 || n+7>inner.length)throw Error('metadata length');
  const metadata=JSON.parse(td.decode(inner.slice(7,7+n)));
  if(!metadata || typeof metadata!=='object' || Array.isArray(metadata))throw Error('metadata');
  return {content:inner.slice(7+n),metadata};
}
