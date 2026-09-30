import {DERIV_AUTH,randomUrlSafe,seal,setCookie,redirect} from "../_lib.js";
export default async function handler(request){
 if(request.method!=="GET")return new Response("Method Not Allowed",{status:405});
 const clientId=process.env.DERIV_CLIENT_ID,redirectUri=process.env.DERIV_REDIRECT_URI,secret=process.env.SESSION_SECRET;
 if(!clientId||!redirectUri||!secret)return new Response("Vercel is not configured yet. Add DERIV_CLIENT_ID, DERIV_REDIRECT_URI and SESSION_SECRET.",{status:500});
 const state=randomUrlSafe(24),verifier=randomUrlSafe(64);
 const hash=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(verifier));
 const challenge=Buffer.from(hash).toString("base64url");
 const p=new URLSearchParams({response_type:"code",client_id:clientId,redirect_uri:redirectUri,scope:"trade",state,code_challenge:challenge,code_challenge_method:"S256"});
 return redirect(DERIV_AUTH+"?"+p.toString(),{"Set-Cookie":setCookie("deriv_oauth_state",seal({state,verifier},secret),600)});
}