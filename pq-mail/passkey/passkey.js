'use strict';
(() => {
 const dec=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
 const enc=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 const text=new TextEncoder(),button=document.getElementById('continue'),status=document.getElementById('status');
 let request;
 try {
  if(window.top!==window.self||location.origin!=='https://ve7jtb.github.io')throw Error('Open this page directly from PQ Mail.');
  request=JSON.parse(new TextDecoder().decode(dec(location.hash.slice(1))));history.replaceState(null,'',location.pathname);
  const url=new URL(request.callback);
  if(url.protocol!=='http:'||url.hostname!=='127.0.0.1'||!/^\d+$/.test(url.port)||url.pathname!=='/prf/'+request.nonce||url.search||url.hash||url.username||url.password)throw Error('Invalid local callback.');
  for(const field of ['challenge','nonce','salt'])if(dec(request[field]).length!==32)throw Error('Invalid request.');
  document.getElementById('description').textContent=(request.create?'Create':request.discover?'Use an existing passkey for':'Unlock with')+' your PQ Mail passkey: '+request.name;
  button.disabled=false;
 } catch(e){status.textContent='Start this operation from PQ Mail → Keys → Passkey vault.';return;}
 function serialize(c){
  const response={clientDataJSON:enc(c.response.clientDataJSON)};
  for(const key of ['attestationObject','authenticatorData','signature','userHandle'])if(c.response[key])response[key]=enc(c.response[key]);
  const prf=c.getClientExtensionResults().prf;
  return {type:c.type,rawId:enc(c.rawId),response,clientExtensionResults:{prf:prf?{enabled:prf.enabled,results:prf.results?{first:enc(prf.results.first)}:undefined}:undefined}};
 }
 button.onclick=async()=>{
  button.disabled=true;status.textContent='Complete the passkey prompt. No vault password is needed.';
  let prf;
  try{
   const common={challenge:dec(request.challenge),timeout:120000,extensions:{prf:{eval:{first:dec(request.salt)}}}};
   let credential,reply;
   if(request.create){
    credential=await navigator.credentials.create({publicKey:{...common,rp:{id:'ve7jtb.github.io',name:'PQ Mail vault'},user:{id:dec(request.user),name:request.name,displayName:request.name},pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],authenticatorSelection:{residentKey:'required',userVerification:'required'},attestation:'none'}});
    reply=serialize(credential);
    if(!reply.clientExtensionResults.prf?.results){
     if(reply.clientExtensionResults.prf?.enabled===false)throw Error('This provider does not support PRF. Choose a PRF-capable passkey provider.');
     status.textContent='Your provider needs one more passkey approval to finish setup.';
     credential=await navigator.credentials.get({publicKey:{...common,rpId:'ve7jtb.github.io',userVerification:'required',allowCredentials:[{type:'public-key',id:credential.rawId}]}});
     reply=serialize(credential);reply.registration=true;
    }
   }else{
    credential=await navigator.credentials.get({publicKey:{...common,rpId:'ve7jtb.github.io',userVerification:'required',...(request.discover?{}:{allowCredentials:[{type:'public-key',id:dec(request.credential)}]})}});reply=serialize(credential);
   }
   if(!reply.clientExtensionResults.prf?.results?.first)throw Error('This provider did not return PRF output. Nothing was saved.');
   const server=await crypto.subtle.importKey('spki',dec(request.publicKey),{name:'ECDH',namedCurve:'P-256'},false,[]);
   const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
   const shared=await crypto.subtle.deriveBits({name:'ECDH',public:server},pair.privateKey,256);
   const hash=await crypto.subtle.digest('SHA-256',shared);new Uint8Array(shared).fill(0);
   const key=await crypto.subtle.importKey('raw',hash,'AES-GCM',false,['encrypt']);new Uint8Array(hash).fill(0);
   const nonce=crypto.getRandomValues(new Uint8Array(12));prf=text.encode(JSON.stringify(reply));
   const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce,additionalData:text.encode(request.nonce)},key,prf);
   const payload={publicKey:enc(await crypto.subtle.exportKey('spki',pair.publicKey)),nonce:enc(nonce),ciphertext:enc(ciphertext)};
   const response=await fetch(request.callback,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload),credentials:'omit',cache:'no-store',redirect:'error',targetAddressSpace:'loopback'});
   if(!response.ok)throw Error('PQ Mail rejected the response or the operation expired.');
   status.textContent='Completed. Return to PQ Mail. You can close this tab.';button.hidden=true;request=null;
  }catch(e){status.textContent='Passkey operation did not complete: '+e.message+'\nReturn to PQ Mail if the operation has expired.';button.disabled=false;}
  finally{if(prf)prf.fill(0);}
 };
})();
