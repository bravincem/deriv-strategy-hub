import {DERIV_API,cookieValue,corsHeaders,json,unseal} from "../_lib.js";
export default async function handler(request){
 if(request.method==="OPTIONS")return new Response(null,{status:204,headers:corsHeaders()});
 if(request.method!=="GET")return json({ok:false,error:"Method Not Allowed"},405);
 const s=unseal(cookieValue(request,"deriv_session"),process.env.SESSION_SECRET);
 if(!s?.accessToken)return json({ok:false,error:"Not connected to Deriv"},401);
 if(s.expiresAt&&Date.now()>s.expiresAt)return json({ok:false,error:"Deriv session expired. Please reconnect."},401);
 const r=await fetch(DERIV_API+"/trading/v1/options/accounts",{headers:{Authorization:"Bearer "+s.accessToken},cache:"no-store"});
 const tx=await r.text();let d={};try{d=JSON.parse(tx)}catch{}
 if(!r.ok)return json({ok:false,error:d?.errors?.[0]?.message||"Deriv account request failed",upstream_status:r.status},r.status);
 const list=Array.isArray(d?.data)?d.data:(d?.data?[d.data]:[]);
 const out=list.map(a=>({id:a.account_id||a.id,currency:a.currency||"USD",balance:Number(a.balance??0),account_type:a.account_type||"",is_demo:String(a.account_type||"").toLowerCase()==="demo"||/^(VRTC|VRT|VR|DOT)/i.test(String(a.account_id||a.id||"")),status:a.status||"active"})).filter(a=>a.id);
 return json({ok:true,accounts:out,raw:d});
}