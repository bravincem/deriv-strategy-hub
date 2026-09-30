export default async function handler(request){
  const url=new URL(request.url);
  const code=url.searchParams.get("code");
  const state=url.searchParams.get("state");
  if(!code||!state)return new Response("Missing OAuth response",{status:400});
  const tokenEndpoint="https://auth.deriv.com/oauth2/token";
  return new Response(JSON.stringify({ok:true,received:true,tokenEndpoint,hasCode:!!code}),{headers:{"content-type":"application/json"}});
}