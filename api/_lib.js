import crypto from "node:crypto";
export const FRONTEND_ORIGIN = "https://bravincem.github.io";
export const DERIV_AUTH = "https://auth.deriv.com/oauth2/auth";
export const DERIV_TOKEN = "https://auth.deriv.com/oauth2/token";
export const DERIV_API = "https://api.derivws.com";
export function corsHeaders(){return {"Access-Control-Allow-Origin":FRONTEND_ORIGIN,"Access-Control-Allow-Credentials":"true","Access-Control-Allow-Headers":"Content-Type","Access-Control-Allow-Methods":"GET,POST,OPTIONS","Cache-Control":"no-store"}}
export function json(data,status=200,extra={}){return new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8",...corsHeaders(),...extra}})}
function key(secret){return crypto.createHash("sha256").update(String(secret)).digest()}
export function seal(value,secret){const iv=crypto.randomBytes(12),c=crypto.createCipheriv("aes-256-gcm",key(secret),iv);const data=Buffer.concat([c.update(JSON.stringify(value),"utf8"),c.final()]);return [iv,c.getAuthTag(),data].map(x=>x.toString("base64url")).join(".")}
export function unseal(value,secret){try{if(!value||!secret)return null;const p=String(value).split(".");if(p.length!==3)return null;const d=crypto.createDecipheriv("aes-256-gcm",key(secret),Buffer.from(p[0],"base64url"));d.setAuthTag(Buffer.from(p[1],"base64url"));return JSON.parse(Buffer.concat([d.update(Buffer.from(p[2],"base64url")),d.final()]).toString("utf8"))}catch{return null}}
export function cookieValue(request,name){const raw=request.headers.get("cookie")||"";for(const part of raw.split(";")){const i=part.indexOf("=");if(i<0)continue;if(part.slice(0,i).trim()===name)return decodeURIComponent(part.slice(i+1).trim())}return ""}
export function setCookie(name,value,maxAge=600){return name+"="+encodeURIComponent(value)+"; Max-Age="+maxAge+"; Path=/; Secure; HttpOnly; SameSite=None"}
export function clearCookie(name){return name+"=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=None"}
export function randomUrlSafe(bytes=48){return crypto.randomBytes(bytes).toString("base64url")}
export function redirect(url,headers={}){return new Response(null,{status:302,headers:{Location:url,...headers}})}
export function errorMessage(data){return data?.errors?.[0]?.message||data?.error_description||data?.error||data?.message||"Unknown error"}
