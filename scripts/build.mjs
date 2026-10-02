import {readFile,writeFile} from "node:fs/promises";
import {fileURLToPath} from "node:url";
import {resolve} from "node:path";

const FIRST_YEAR=2021;
const days=(from,to)=>(Date.parse(to+"T00:00:00Z")-Date.parse(from+"T00:00:00Z"))/86400000;
export const BUCKETS=[
  ["Before disclosure",g=>g<0],["Same day",g=>g===0],["1–7 days",g=>g>=1&&g<=7],["8–30 days",g=>g>=8&&g<=30],
  ["31–90 days",g=>g>=31&&g<=90],["91–365 days",g=>g>=91&&g<=365],["Over a year",g=>g>365],
];

export function median(values){
  if(!values.length)return null;
  const a=[...values].sort((x,y)=>x-y),m=Math.floor(a.length/2);
  return a.length%2?a[m]:(a[m-1]+a[m])/2;
}
function quantile(sorted,p){
  const i=(sorted.length-1)*p,lo=Math.floor(i),hi=Math.ceil(i);
  return sorted[lo]+(sorted[hi]-sorted[lo])*(i-lo);
}

// Window = VulnCheck KEV date (first reported exploitation) minus CVE.org publication.
export function yearlyGap(records,asOf){
  const last=Number(asOf.slice(0,4));
  const rows=records.filter(r=>r.published&&r.vulncheck&&r.published<=asOf&&r.vulncheck<=asOf)
    .map(r=>({...r,year:Number(r.published.slice(0,4)),gap:days(r.published,r.vulncheck)}));
  const years=[];
  for(let year=FIRST_YEAR;year<=last;year++){
    const cohort=rows.filter(r=>r.year===year),gaps=cohort.map(r=>r.gap),sorted=[...gaps].sort((a,b)=>a-b);
    const pct=f=>gaps.length?Math.round(gaps.filter(f).length/gaps.length*100):null;
    const zero=cohort.filter(r=>r.gap<=0).sort((a,b)=>b.published.localeCompare(a.published)||a.cve.localeCompare(b.cve));
    const rest=cohort.filter(r=>r.gap>0).sort((a,b)=>a.gap-b.gap||a.cve.localeCompare(b.cve));
    years.push({
      year,n:gaps.length,median:median(gaps),within7:pct(g=>g<=7),atOrBefore:pct(g=>g<=0),partial:year===last,
      q1:gaps.length?quantile(sorted,.25):null,q3:gaps.length?quantile(sorted,.75):null,
      ransomware:cohort.filter(r=>r.ransomware==="Known").length,
      buckets:BUCKETS.map(([label,test])=>({label,count:gaps.filter(test).length})),
      examples:[...zero,...rest].slice(0,5).map(r=>({cve:r.cve,vendor:r.vendor??null,product:r.product??null,window:r.gap,published:r.published,ransomware:r.ransomware==="Known"})),
    });
  }
  return years;
}

const escape=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"})[c]);
const fmt=n=>Number.isInteger(n)?String(n):n.toFixed(1);
const fmtDate=d=>new Intl.DateTimeFormat("en-GB",{day:"numeric",month:"short",year:"numeric",timeZone:"UTC"}).format(new Date(d+"T00:00:00Z"));

function chart(years){
  const W=960,H=360,L=56,R=16,T=40,B=64,band=(W-L-R)/years.length;
  const max=Math.ceil(Math.max(...years.map(y=>y.median??0))/50)*50;
  const y=v=>T+(H-T-B)*(1-v/max);
  let svg=`<svg viewBox="0 0 ${W} ${H}" role="img" aria-labelledby="chart-title"><title id="chart-title">Median days from CVE publication to first reported exploitation, by year</title>`;
  for(let v=0;v<=max;v+=max/5)svg+=`<line class="${v?"grid":"axis"}" x1="${L}" x2="${W-R}" y1="${y(v)}" y2="${y(v)}"/><text class="tick" x="${L-12}" y="${y(v)+4}" text-anchor="end">${v}</text>`;
  years.forEach((yr,i)=>{
    const x=L+band*i+band/2,top=y(Math.max(0,yr.median)),w=Math.min(64,band*.42),h=Math.max(2,H-B-top);
    svg+=`<g class="col" data-i="${i}" tabindex="0" role="button" aria-label="${yr.year}: median window ${fmt(yr.median)} days, ${yr.n} exploited CVEs">`;
    svg+=`<rect class="hit" x="${x-band/2}" y="${T-30}" width="${band}" height="${H-T+30}"/>`;
    svg+=`<rect class="bar${yr.partial?" partial":""}" style="--d:${i*90}ms" x="${x-w/2}" y="${H-B-h}" width="${w}" height="${h}"/>`;
    svg+=`<text class="value" x="${x}" y="${H-B-h-12}" text-anchor="middle">${fmt(yr.median)}</text>`;
    svg+=`<text class="year" x="${x}" y="${H-B+26}" text-anchor="middle">${yr.year}${yr.partial?"*":""}</text><text class="tick" x="${x}" y="${H-B+44}" text-anchor="middle">n=${yr.n}</text></g>`;
  });
  return svg+`<text class="tick" x="${L-46}" y="16">DAYS</text></svg>`;
}

export function renderPage(years,meta){
  const latest=years.at(-1),peak=years.reduce((a,b)=>b.median>a.median?b:a);
  const rows=years.map((y,i)=>`<tr data-i="${i}" tabindex="0"><td>${y.year}${y.partial?"*":""}</td><td>${y.n}</td><td class="hl">${fmt(y.median)}</td><td>${y.within7}%</td><td>${y.atOrBefore}%</td></tr>`).join("");
  const data=JSON.stringify({years,peak:peak.median,latest:latest.median}).replace(/</g,"\\u003c");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Defender's Window</title>
<meta name="description" content="How long defenders have between a vulnerability's disclosure and its first reported exploitation in the wild, by year. Data: VulnCheck KEV.">
<meta property="og:title" content="Defender's Window">
<meta property="og:description" content="The time defenders get between disclosure and exploitation, measured every year since ${FIRST_YEAR}.">
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3E%3Crect x='2' y='2' width='12' height='12' fill='none' stroke='%23ff3b30' stroke-width='2'/%3E%3Crect x='7' y='2' width='2' height='12' fill='%23ff3b30'/%3E%3C/svg%3E">
<style>
:root{
  --bg:#0a0a0b;--panel:#111113;--panel-2:#16161a;--line:#1f1f23;--line-strong:#2e2e34;
  --text:#ececee;--muted:#8b8b93;--faint:#5a5a62;
  --red:#ff3b30;--red-soft:rgba(255,59,48,.12);--amber:#ffb020;
  --mono:"JetBrains Mono","SF Mono",Consolas,"Liberation Mono",Menlo,monospace;
  --sans:"Inter","Segoe UI",-apple-system,BlinkMacSystemFont,Roboto,sans-serif;
}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;color:var(--text);font:15px/1.6 var(--sans);-webkit-font-smoothing:antialiased}
main{max-width:1000px;margin:auto;padding:56px 24px 40px}
a{color:var(--text);text-decoration:underline;text-decoration-color:var(--faint);text-underline-offset:3px}
a:hover{text-decoration-color:var(--red)}
.top{display:flex;justify-content:space-between;align-items:center;font:12px var(--mono);color:var(--muted);letter-spacing:.08em;text-transform:uppercase;margin-bottom:56px}
.brand{display:flex;align-items:center;gap:10px;color:var(--text)}
.brand i{width:12px;height:12px;border:2px solid var(--red);background:linear-gradient(90deg,transparent 4px,var(--red) 4px,var(--red) 6px,transparent 6px)}
h1{font-size:clamp(22px,3vw,30px);line-height:1.25;font-weight:600;letter-spacing:-.02em;margin:22px 0 0;max-width:620px}
.sub{color:var(--muted);margin:10px 0 0;max-width:560px}
.hero{display:grid;grid-template-columns:1fr auto;gap:40px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:40px}
.label{font:12px var(--mono);color:var(--muted);letter-spacing:.08em;text-transform:uppercase}
.clock{font:700 clamp(88px,15vw,168px)/.9 var(--mono);letter-spacing:-.06em;color:var(--red);margin:14px 0 0;font-variant-numeric:tabular-nums}
.clock small{font-size:.3em;letter-spacing:0;color:var(--text);margin-left:.3em}
.side{display:grid;gap:22px;min-width:220px;padding-bottom:6px}
.side strong{display:block;font:600 34px/1.1 var(--mono);letter-spacing:-.03em;margin-top:6px}
.side span.note{font:12px var(--mono);color:var(--faint)}
section{margin-top:48px}
h2{font:12px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:400;margin:0 0 18px;display:flex;justify-content:space-between;gap:16px}
h2 .hint{color:var(--faint);text-transform:none;letter-spacing:0}
.chart-wrap{position:relative;overflow-x:auto}
svg{display:block;width:100%;height:auto;min-width:640px}
svg text{font-family:var(--mono);pointer-events:none}
.grid{stroke:var(--line)}.axis{stroke:var(--line-strong)}
.tick{fill:var(--faint);font-size:12px}
.hit{fill:transparent}
.col{cursor:pointer;outline:none}
.bar{fill:var(--red);transform-box:fill-box;transform-origin:bottom;animation:grow .9s cubic-bezier(.2,.8,.2,1) both;animation-delay:var(--d);transition:opacity .2s,fill .2s}
.bar.partial{fill-opacity:.7}
@keyframes grow{from{transform:scaleY(0)}to{transform:scaleY(1)}}
.value{fill:var(--text);font-size:17px;font-weight:600;transition:opacity .2s}.year{fill:var(--text);font-size:14px}
.chart-wrap.hovering .col:not(.hover) .bar{opacity:.25}
.chart-wrap.hovering .col:not(.hover) .value{opacity:.35}
.col.hover .hit,.col:focus-visible .hit{fill:rgba(255,255,255,.03)}
.col.selected .year{fill:var(--red);font-weight:700}
.col.selected .hit{fill:var(--red-soft)}
.tip{position:absolute;pointer-events:none;background:var(--panel-2);border:1px solid var(--line-strong);padding:12px 14px;font:12px/1.6 var(--mono);color:var(--muted);min-width:210px;opacity:0;transform:translate(-50%,-100%) translateY(-8px);transition:opacity .15s;z-index:2;white-space:nowrap}
.tip.show{opacity:1}
.tip b{display:block;color:var(--text);font-size:14px;margin-bottom:4px}
.tip span{color:var(--text)}.tip em{color:var(--red);font-style:normal;font-weight:700}
.detail{margin-top:28px;border:1px solid var(--line);background:var(--panel);padding:24px}
.detail-head{display:flex;justify-content:space-between;align-items:baseline;gap:16px;flex-wrap:wrap}
.detail-head h3{margin:0;font:600 20px var(--mono);letter-spacing:-.02em}.detail-head h3 span{color:var(--red)}
.year-tabs{display:flex;gap:4px;flex-wrap:wrap}
.year-tabs button{font:12px var(--mono);background:none;border:1px solid var(--line-strong);color:var(--muted);padding:5px 10px;cursor:pointer}
.year-tabs button:hover{color:var(--text);border-color:var(--muted)}
.year-tabs button[aria-pressed="true"]{background:var(--red);border-color:var(--red);color:#0a0a0b}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--line);border:1px solid var(--line);margin:20px 0}
.stats div{background:var(--panel);padding:14px 16px}
.stats strong{display:block;font:600 24px/1.2 var(--mono);margin-top:4px}
.stats .label{font-size:11px}
.cols{display:grid;grid-template-columns:1.1fr 1fr;gap:28px}
.dist div{display:grid;grid-template-columns:118px 1fr 74px;align-items:center;gap:12px;font:12px var(--mono);color:var(--muted);margin-bottom:9px}
.dist .track{display:block;height:10px;background:var(--line)}
.dist .fill{display:block;height:100%;background:var(--red);width:0;transition:width .6s cubic-bezier(.2,.8,.2,1)}
.dist .fill.slow{background:var(--line-strong)}
.dist b{color:var(--text);font-weight:400;text-align:right}
.examples{list-style:none;margin:0;padding:0;font:12px var(--mono)}
.examples li{display:grid;grid-template-columns:1fr auto;gap:10px;padding:9px 0;border-bottom:1px solid var(--line)}
.examples li:last-child{border-bottom:0}
.examples a{color:var(--text)}
.examples small{display:block;color:var(--faint);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:300px}
.examples .w{color:var(--red);text-align:right}
.tag{display:inline-block;margin-left:6px;padding:0 5px;border:1px solid var(--amber);color:var(--amber);font-size:10px}
.caveat{border-left:2px solid var(--amber);padding:2px 0 2px 18px;color:var(--muted);font-size:14px;max-width:760px}
.caveat strong{color:var(--text);font-weight:600}
table{width:100%;border-collapse:collapse;font:14px var(--mono)}
th,td{text-align:right;padding:12px 10px;border-bottom:1px solid var(--line)}
th:first-child,td:first-child{text-align:left}
th{font-size:11px;color:var(--faint);font-weight:400;letter-spacing:.06em;text-transform:uppercase}
tbody tr{cursor:pointer;transition:background .15s}
tbody tr:hover,tbody tr:focus-visible{background:var(--panel-2);outline:none}
tbody tr.selected td:first-child{color:var(--red);font-weight:700}
.hl{color:var(--red);font-weight:600}
.table-wrap{overflow-x:auto}
.notes{font-size:13px;color:var(--faint);max-width:760px}
footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--line);display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;font:12px var(--mono);color:var(--faint)}
footer a{color:var(--muted)}
@media(max-width:720px){main{padding:32px 18px}.top{margin-bottom:36px}.hero{grid-template-columns:1fr;gap:28px}.side{grid-template-columns:1fr 1fr}.stats{grid-template-columns:1fr 1fr}.cols{grid-template-columns:1fr}.detail{padding:18px}}
@media(prefers-reduced-motion:reduce){.bar{animation:none}.dist .fill{transition:none}}
</style>
</head>
<body>
<main>
<div class="top"><span class="brand"><i></i>Defender's Window</span><span>Updated ${escape(fmtDate(meta.asOf))}</span></div>
<header class="hero">
  <div>
    <div class="label">${latest.year}${latest.partial?" so far":""} &middot; median window before exploitation</div>
    <div class="clock"><span id="clock">${fmt(latest.median)}</span><small>day${latest.median===1?"":"s"}</small></div>
    <h1>The defender's window is closing.</h1>
    <p class="sub">How long defenders get between a vulnerability's public disclosure and its first reported exploitation in the wild.</p>
  </div>
  <div class="side">
    <div><span class="label">${peak.year} median window</span><strong>${fmt(peak.median)} days</strong><span class="note">n=${peak.n}</span></div>
    <div><span class="label">${latest.year}: exploited within 7 days</span><strong>${latest.within7}%</strong><span class="note">${peak.within7}% in ${peak.year}</span></div>
  </div>
</header>
<section>
  <h2><span>Median window by CVE publication year</span><span class="hint">Hover or tap a year</span></h2>
  <div class="chart-wrap" id="chart">${chart(years)}<div class="tip" id="tip" role="status"></div></div>
  <div class="detail" id="detail" aria-live="polite">
    <div class="detail-head"><h3 id="d-title"></h3><div class="year-tabs" id="tabs">${years.map((y,i)=>`<button type="button" data-i="${i}">${y.year}</button>`).join("")}</div></div>
    <div class="stats">
      <div><span class="label">Median window</span><strong id="d-median"></strong></div>
      <div><span class="label">Middle half</span><strong id="d-iqr"></strong></div>
      <div><span class="label">Within 7 days</span><strong id="d-w7"></strong></div>
      <div><span class="label">Ransomware use</span><strong id="d-ransom"></strong></div>
    </div>
    <div class="cols">
      <div><div class="label" style="margin-bottom:12px">How long defenders got</div><div class="dist" id="d-dist"></div></div>
      <div><div class="label" style="margin-bottom:6px" id="d-ex-label">Examples</div><ul class="examples" id="d-ex"></ul></div>
    </div>
  </div>
</section>
<section>
  <p class="caveat"><strong>Recent years look faster than they really are.</strong> Older CVEs have had years to collect late exploitation reports; recent ones have not yet. Measured over the same 90 days after publication, the median has been about zero days every year since ${FIRST_YEAR}. What has grown is volume: roughly 130 CVEs a year were exploited within a week of disclosure in 2021&ndash;22, versus about 350 in 2024&ndash;25.</p>
</section>
<section>
  <h2><span>By year</span></h2>
  <div class="table-wrap"><table><thead><tr><th>Year</th><th>Exploited CVEs</th><th>Median window (days)</th><th>Exploited within 7 days</th><th>No window: exploited on/before disclosure</th></tr></thead><tbody id="rows">${rows}</tbody></table></div>
  <p class="notes">* Partial year, through ${escape(fmtDate(meta.asOf))}. Window = first exploitation report recorded by VulnCheck KEV minus CVE.org publication date. Reported dates can trail actual attacks. VulnCheck KEV coverage grew after its 2023 launch. These figures do not show what causes any change.</p>
</section>
<footer><span>Data: <a href="https://vulncheck.com/kev">VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV)</a> &middot; <a href="https://www.cve.org/">CVE.org</a></span><span>Bertug Berkay Yemen</span></footer>
</main>
<script id="data" type="application/json">${data}</script>
<script>
(()=>{
  const D=JSON.parse(document.getElementById("data").textContent),Y=D.years;
  const $=id=>document.getElementById(id),chart=$("chart"),tip=$("tip"),cols=[...chart.querySelectorAll(".col")],rows=[...$("rows").children],tabs=[...$("tabs").children];
  const fmt=n=>Number.isInteger(n)?String(n):n.toFixed(1),days=n=>fmt(n)+" day"+(Math.abs(n)===1?"":"s");
  const esc=s=>String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"})[c]);
  const reduce=matchMedia("(prefers-reduced-motion: reduce)").matches;
  let selected=Y.length-1;

  function showTip(i){
    const y=Y[i],bar=cols[i].querySelector(".bar"),box=bar.getBoundingClientRect(),wrap=chart.getBoundingClientRect();
    tip.innerHTML="<b>"+y.year+(y.partial?" (so far)":"")+"</b>Median window <em>"+days(y.median)+"</em><br>Exploited CVEs <span>"+y.n+"</span><br>Within 7 days <span>"+y.within7+"%</span><br>No window at all <span>"+y.atOrBefore+"%</span><br>Middle half <span>"+fmt(y.q1)+" to "+fmt(y.q3)+" days</span>";
    const left=Math.min(Math.max(box.left+box.width/2-wrap.left+chart.scrollLeft,120),chart.scrollWidth-120);
    tip.style.left=left+"px";tip.style.top=Math.max(box.top-wrap.top,tip.offsetHeight+12)+"px";tip.classList.add("show");
    chart.classList.add("hovering");cols.forEach((c,j)=>c.classList.toggle("hover",j===i));
  }
  function hideTip(){tip.classList.remove("show");chart.classList.remove("hovering");cols.forEach(c=>c.classList.remove("hover"));}

  function select(i){
    selected=i;const y=Y[i];
    cols.forEach((c,j)=>c.classList.toggle("selected",j===i));
    rows.forEach((r,j)=>r.classList.toggle("selected",j===i));
    tabs.forEach((t,j)=>t.setAttribute("aria-pressed",String(j===i)));
    $("d-title").innerHTML="<span>"+y.year+"</span>"+(y.partial?" so far":"")+" &middot; "+y.n+" exploited CVEs";
    $("d-median").textContent=days(y.median);
    $("d-iqr").textContent=fmt(y.q1)+" to "+fmt(y.q3)+"d";
    $("d-w7").textContent=y.within7+"%";
    $("d-ransom").textContent=y.ransomware+" CVEs";
    const max=Math.max(...y.buckets.map(b=>b.count));
    $("d-dist").innerHTML=y.buckets.map((b,k)=>"<div><span>"+esc(b.label)+"</span><span class=track><span class='fill"+(k>3?" slow":"")+"' style='width:0' data-w='"+(max?b.count/max*100:0)+"'></span></span><b>"+b.count+" &middot; "+Math.round(b.count/y.n*100)+"%</b></div>").join("");
    requestAnimationFrame(()=>requestAnimationFrame(()=>$("d-dist").querySelectorAll(".fill").forEach(f=>f.style.width=f.dataset.w+"%")));
    const zero=y.examples.filter(e=>e.window<=0).length;
    $("d-ex-label").textContent=zero?"Latest with no window at all":"Fastest exploited";
    $("d-ex").innerHTML=y.examples.map(e=>"<li><div><a href='https://nvd.nist.gov/vuln/detail/"+esc(e.cve)+"' target=_blank rel=noopener>"+esc(e.cve)+"</a>"+(e.ransomware?"<span class=tag>RANSOMWARE</span>":"")+"<small>"+esc([e.vendor,e.product].filter(Boolean).join(" "))+"</small></div><span class=w>"+(e.window<0?fmt(-e.window)+"d before":e.window===0?"same day":fmt(e.window)+"d after")+"</span></li>").join("");
  }

  cols.forEach((c,i)=>{
    c.addEventListener("pointerenter",()=>showTip(i));
    c.addEventListener("pointerleave",hideTip);
    c.addEventListener("focus",()=>showTip(i));
    c.addEventListener("blur",hideTip);
    c.addEventListener("click",()=>select(i));
    c.addEventListener("keydown",e=>{if(e.key==="Enter"||e.key===" "){e.preventDefault();select(i);}
      if(e.key==="ArrowRight"||e.key==="ArrowLeft"){e.preventDefault();cols[(i+(e.key==="ArrowRight"?1:-1)+cols.length)%cols.length].focus();}});
  });
  rows.forEach((r,i)=>{
    r.addEventListener("pointerenter",()=>showTip(i));r.addEventListener("pointerleave",hideTip);
    r.addEventListener("click",()=>{select(i);$("detail").scrollIntoView({behavior:reduce?"auto":"smooth",block:"center"});});
    r.addEventListener("keydown",e=>{if(e.key==="Enter"){r.click();}});
  });
  tabs.forEach((t,i)=>t.addEventListener("click",()=>select(i)));
  select(selected);

  // Count the headline down from the widest window to today's.
  if(!reduce){
    const el=$("clock"),from=D.peak,to=D.latest,start=performance.now(),dur=1600;
    const step=t=>{const p=Math.min(1,(t-start)/dur),e=1-Math.pow(1-p,3),v=from+(to-from)*e;el.textContent=p<1?Math.round(v):fmt(to);if(p<1)requestAnimationFrame(step);};
    requestAnimationFrame(step);
  }
})();
</script>
</body>
</html>
`;
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const data=JSON.parse(await readFile(new URL("../data/vulncheck-kev.json",import.meta.url),"utf8"));
  const years=yearlyGap(data.records,data.meta.asOf);
  if(years.some(y=>!y.n))throw new Error("A year has no records; refusing to build an empty chart");
  await writeFile(new URL("../index.html",import.meta.url),renderPage(years,data.meta));
  console.table(years.map(({year,n,median,within7})=>({year,n,median,within7})));
}
