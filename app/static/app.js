let token = null, partners = [], policies = {};
const $ = id => document.getElementById(id);
async function api(path, options={}) {
  const res = await fetch(path, {headers:{"Content-Type":"application/json"}, ...options});
  const data = await res.json();
  if (!res.ok) throw new Error(data.detail || "Request failed");
  return data;
}
function show(el, html, cls="") { el.className = "result " + cls; el.innerHTML = html; }
async function boot() {
  const [users,p,pol] = await Promise.all([api("/api/users"),api("/api/partners"),api("/api/policies")]);
  partners=p; policies=pol;
  $("user").innerHTML=users.map(u=>`<option value="${u.id}">${u.name} — ${u.role} — MFA ${u.mfa?"enabled":"disabled"}</option>`).join("");
  $("partner").innerHTML=p.map(x=>`<option value="${x.id}">${x.name}</option>`).join("");
  renderPartners(); renderPolicies(); updateResources(); await refreshAudit();
}
function renderPartners(){ $("partners").innerHTML=partners.map(p=>`<div class="item"><strong>${p.name}</strong><span class="muted">Issuer: ${p.issuer} · Status: ${p.status} · Resources: ${p.resources.join(", ")}</span></div>`).join("");}
function renderPolicies(){ $("policies").innerHTML=Object.entries(policies).map(([id,p])=>`<div class="item"><strong>${id}</strong><span class="muted">${p.description} · Roles: ${p.allowed_roles.join(", ")} · MFA: ${p.mfa_required?"required":"not required"}</span></div>`).join("");}
function updateResources(){const p=partners.find(x=>x.id===$("partner").value);$("resource").innerHTML=(p?.resources||[]).map(r=>`<option value="${r}">${r}</option>`).join("");}
$("partner").addEventListener("change",updateResources);
$("login").addEventListener("click",async()=>{try{const r=await api("/api/login",{method:"POST",body:JSON.stringify({username:$("user").value})});token=r.token;$("access").disabled=false;show($("identity"),`<strong>${r.identity.name}</strong><br>${r.identity.email}<br>Role: ${r.identity.role} · MFA: ${r.identity.mfa?"verified":"not verified"}<br><span class="muted">Signed demo identity assertion issued; expires in ${r.expires_in/60} minutes.</span>`,"success");}catch(e){show($("identity"),e.message,"denied");}});
$("access").addEventListener("click",async()=>{if(!token)return;try{const r=await api("/api/access",{method:"POST",body:JSON.stringify({token,partner_id:$("partner").value,resource:$("resource").value})});const allow=r.decision==="ALLOW";show($("decision"),`<strong>${r.decision}</strong> — ${r.reason}<br>Partner: ${r.partner}<br>Resource: ${r.resource}<br>Claims released: ${allow?Object.keys(r.claims_released).join(", "):"none"}` ,allow?"success":"denied");await refreshAudit();}catch(e){show($("decision"),e.message,"denied");await refreshAudit();}});
async function refreshAudit(){try{const rows=await api("/api/audit");$("audit").innerHTML=rows.length?rows.map(r=>`<tr><td>${new Date(r.timestamp).toLocaleString()}</td><td>${r.username}</td><td>${r.partner_id}</td><td>${r.resource}</td><td class="${r.decision==="ALLOW"?"allow":"deny"}">${r.decision}</td><td>${r.reason}</td></tr>`).join(""):`<tr><td colspan="6" class="muted">No events yet. Sign in and request access to generate an audit event.</td></tr>`;}catch(e){console.error(e);}}
$("refresh").addEventListener("click",refreshAudit);
boot().catch(e=>console.error(e));
