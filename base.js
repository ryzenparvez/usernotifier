const UI=__UI__;
const $=id=>document.getElementById(id);
const bn=s=>String(s).replace(/\d/g,d=>"০১২৩৪৫৬৭৮৯"[d]);
const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
try{const t=localStorage.getItem("jsn_theme");if(t)document.documentElement.dataset.theme=t}catch(e){}
function curTheme(){return document.documentElement.dataset.theme||(matchMedia("(prefers-color-scheme:dark)").matches?"dark":"light")}
function themeUI(){const d=curTheme()==="dark";document.querySelectorAll(".ti").forEach(e=>e.textContent=d?"☀️":"🌙");document.querySelectorAll(".tl").forEach(e=>e.textContent=d?"লাইট মোড":"ডার্ক মোড")}
function toggleTheme(){const n=curTheme()==="dark"?"light":"dark";document.documentElement.dataset.theme=n;try{localStorage.setItem("jsn_theme",n)}catch(e){}themeUI()}
async function logout(){if(typeof DEMO==="undefined"||!DEMO)await fetch("/admin/logout",{method:"POST",headers:{"X-Requested-With":"jsn"}});location.href="/admin"}
function route(){const secs=[...document.querySelectorAll(".sect")];if(!secs.length)return;let h=(location.hash||"").slice(1);if(!secs.some(s=>s.id==="s-"+h))h="overview";
 secs.forEach(s=>s.classList.toggle("on",s.id==="s-"+h));document.querySelectorAll("#nav a").forEach(a=>a.classList.toggle("on",a.dataset.sec===h));
 const s=$("s-"+h);$("pt").textContent=s.dataset.title;$("ps").textContent=s.dataset.sub||"";window.scrollTo({top:0})}
window.addEventListener("hashchange",route);
document.addEventListener("DOMContentLoaded",()=>{if($("blogo")){$("blogo").textContent=UI.logo;$("bname").textContent=UI.title;$("bsub").textContent=UI.brand}themeUI();route()});
