import * as oauth from "oauth4webapi";
import {FRONTEND_ORIGIN,cookieValue,unseal,seal,setCookie,clearCookie,redirect,errorMessage} from "../_lib.js";

export default async function handler(request){
  const u=new URL(request.url);
  const secret=process.env.SESSION_SECRET;
  const clientId=process.env.DERIV_CLIENT_ID;
  const redirectUri=process.env.DERIV_REDIRECT_URI;
  const fail=m=>redirect(FRONTEND_ORIGIN+"/deriv-strategy-hub/?deriv_error="+encodeURIComponent(m),{"Set-Cookie":clearCookie("deriv_oauth_state")});
  if(!secret||!clientId||!redirectUri)return fail("Vercel OAuth settings are incomplete.");
  if(u.searchParams.get("error"))return fail(u.searchParams.get("error_description")||u.searchParams.get("error"));
  const saved=unseal(cookieValue(request,"deriv_oauth_state"),secret);
  const returnedState=u.searchParams.get("state");
  if(!saved||!returnedState||saved.state!==returnedState)return fail("OAuth state check failed. Please try CONNECT DERIV again.");
  if(!u.searchParams.get("code"))return fail("Deriv did not return an authorization code.");

  const as={issuer:new URL("https://auth.deriv.com"),authorization_endpoint:new URL("https://auth.deriv.com/oauth2/auth"),token_endpoint:new URL("https://auth.deriv.com/oauth2/token")};
  const client={client_id:clientId};
  const params=oauth.validateAuthResponse(as,client,u.searchParams);
  let response;
  try{
    response=await oauth.authorizationCodeGrantRequest(as,client,params,redirectUri,saved.verifier);
  }catch(e){
    return fail("Deriv authorization exchange failed: "+(e.message||String(e)));
  }
  let tokens;
  try{tokens=await oauth.processAuthorizationCodeResponse(as,client,response)}
  catch(e){return fail("Deriv token response failed: "+(e.message||String(e)))}
  if(!tokens||!tokens.access_token)return fail("Deriv did not return a usable authorization result.");

  const session=seal({accessToken:tokens.access_token,expiresAt:Date.now()+Number(tokens.expires_in||3600)*1000},secret);
  return redirect(FRONTEND_ORIGIN+"/deriv-strategy-hub/?deriv_connected=1",{"Set-Cookie":[setCookie("deriv_session",session,Math.min(Number(tokens.expires_in||3600),3600)),clearCookie("deriv_oauth_state")].join(", ")});
}