const E=new TextEncoder(),b64=b=>btoa(String.fromCharCode(...new Uint8Array(b)));
const J=(o,s=200)=>new Response(JSON.stringify(o),{status:s,headers:{'content-type':'application/json'}});
let ready;
async function hash(p,s){const k=await crypto.subtle.importKey('raw',E.encode(p),'PBKDF2',false,['deriveBits']);return b64(await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:E.encode(s),iterations:20000},k,256))}
async function sign(env,s){const k=await crypto.subtle.importKey('raw',E.encode(env.SECRET),{name:'HMAC',hash:'SHA-256'},false,['sign']);return b64(await crypto.subtle.sign('HMAC',k,E.encode(s)))}
async function onRequest({request,env}){
 const db=env.DB,path=new URL(request.url).pathname.replace(/^\/api\//,''),m=request.method;
 if(!db||!env.SECRET)return J({e:'اربط D1 باسم DB وأضف SECRET'},500);
 ready=ready||db.batch([db.prepare('CREATE TABLE IF NOT EXISTS users(u TEXT PRIMARY KEY,salt TEXT,h TEXT,role TEXT)'),db.prepare('CREATE TABLE IF NOT EXISTS d(u TEXT,k TEXT,v TEXT,PRIMARY KEY(u,k))')]);
 await ready;
 let b={};try{b=await request.json()}catch{}
 if(path==='login'){
  const u=String(b.u||'').toLowerCase(),p=String(b.p||'');
  let r=await db.prepare('SELECT * FROM users WHERE u=?').bind(u).first();
  if(!r&&u==='admin'&&env.ADMIN_PASS&&p===env.ADMIN_PASS&&!(await db.prepare('SELECT 1 x FROM users').first())){
   const salt=crypto.randomUUID(),h=await hash(p,salt);r={u,salt,h,role:'admin'};
   await db.prepare('INSERT INTO users VALUES(?,?,?,?)').bind(u,salt,h,'admin').run()}
  if(!r||r.h!==await hash(p,r.salt))return J({e:'بيانات الدخول خاطئة'},401);
  const x=Date.now()+30*864e5;return J({t:`${u}.${x}.${await sign(env,u+x)}`,u,role:r.role})}
 const a=(request.headers.get('authorization')||'').slice(7).split('.');
 if(a.length!==3||+a[1]<Date.now()||a[2]!==await sign(env,a[0]+a[1]))return J({e:'auth'},401);
 const me=await db.prepare('SELECT role FROM users WHERE u=?').bind(a[0]).first();
 if(!me)return J({e:'auth'},401);const u=a[0];
 if(path==='data'){
  if(m==='GET'){const {results}=await db.prepare('SELECT k,v FROM d WHERE u=?').bind(u).all();
   const o={db:null,th:{}};for(const r of results){if(r.k==='db')o.db=JSON.parse(r.v);else o.th[r.k.slice(2)]=r.v}return J(o)}
  const q=[db.prepare('INSERT OR REPLACE INTO d VALUES(?,?,?)').bind(u,'db',JSON.stringify(b.db))];
  for(const[id,v]of Object.entries(b.th||{}))q.push(db.prepare('INSERT OR REPLACE INTO d VALUES(?,?,?)').bind(u,'t:'+id,v));
  for(const id of b.rm||[])q.push(db.prepare('DELETE FROM d WHERE u=? AND k=?').bind(u,'t:'+id));
  await db.batch(q);return J({ok:1})}
 if(me.role!=='admin')return J({e:'للأدمن فقط'},403);
 if(path==='users'){
  if(m==='GET')return J((await db.prepare('SELECT u,role FROM users').all()).results);
  const n=String(b.n||'').toLowerCase();if(!/^[a-z0-9_]{3,20}$/.test(n))return J({e:'اسم: حروف إنجليزية/أرقام 3-20'},400);
  if(m==='DELETE'){if(n===u)return J({e:'لا يمكن حذف نفسك'},400);await db.batch([db.prepare('DELETE FROM users WHERE u=?').bind(n),db.prepare('DELETE FROM d WHERE u=?').bind(n)]);return J({ok:1})}
  if(String(b.p||'').length<6)return J({e:'كلمة المرور 6+ أحرف'},400);
  const salt=crypto.randomUUID();
  await db.prepare('INSERT OR REPLACE INTO users VALUES(?,?,?,?)').bind(n,salt,await hash(b.p,salt),b.role==='admin'?'admin':'user').run();return J({ok:1})}
 return J({e:'404'},404)}
export default{fetch:(request,env)=>new URL(request.url).pathname.startsWith('/api/')?onRequest({request,env}):env.ASSETS.fetch(request)};
