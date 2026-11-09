// Node harness only. The protocol module itself uses browser-standard Web Crypto.
import {readFile,writeFile} from 'node:fs/promises';
import {webcrypto} from 'node:crypto';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const {seal,openEnvelope,b64,unb64}=await import('./protocol.mjs');
const input=JSON.parse(await readFile(process.argv[3],'utf8'));
let result;
if(process.argv[2]==='open'){
 const r=await openEnvelope(input.identity,input.recipient,input.sender_bundle,input.envelope);
 result={content:b64(r.content),metadata:r.metadata};
}else if(process.argv[2]==='seal'){
 result=await seal(input.identity,input.sender,input.recipient,input.recipient_bundle,unb64(input.content),input.metadata);
}else throw Error('unknown command');
await writeFile(process.argv[4],JSON.stringify(result));
