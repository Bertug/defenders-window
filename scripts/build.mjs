import {readFile,writeFile} from "node:fs/promises";
import {fileURLToPath} from "node:url";
import {resolve} from "node:path";

const FIRST_YEAR=2021;
const days=(from,to)=>(Date.parse(to+"T00:00:00Z")-Date.parse(from+"T00:00:00Z"))/86400000;

export function median(values){
  if(!values.length)return null;
  const a=[...values].sort((x,y)=>x-y),m=Math.floor(a.length/2);
  return a.length%2?a[m]:(a[m-1]+a[m])/2;
}

// Gap = VulnCheck KEV date (first reported exploitation) minus CVE.org publication.
export function yearlyGap(records,asOf){
  const last=Number(asOf.slice(0,4));
  const rows=records.filter(r=>r.published&&r.vulncheck&&r.published<=asOf&&r.vulncheck<=asOf)
    .map(r=>({year:Number(r.published.slice(0,4)),gap:days(r.published,r.vulncheck)}));
  const years=[];
  for(let year=FIRST_YEAR;year<=last;year++){
    const gaps=rows.filter(r=>r.year===year).map(r=>r.gap);
    const pct=f=>gaps.length?Math.round(gaps.filter(f).length/gaps.length*100):null;
    years.push({year,n:gaps.length,median:median(gaps),within7:pct(g=>g<=7),atOrBefore:pct(g=>g<=0),partial:year===last});
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
  const pts=years.map((yr,i)=>({x:L+band*i+band/2,y:y(Math.max(0,yr.median)),yr}));
  years.forEach((yr,i)=>{
    const {x,y:top}=pts[i],w=Math.min(64,band*.42),h=Math.max(2,H-B-top);
    svg+=`<g><title>${yr.year}: median ${fmt(yr.median)} days (n=${yr.n})</title><rect class="bar${yr.partial?" partial":""}" x="${x-w/2}" y="${H-B-h}" width="${w}" height="${h}"/>`;
    svg+=`<text class="value" x="${x}" y="${H-B-h-12}" text-anchor="middle">${fmt(yr.median)}</text></g>`;
    svg+=`<text class="year" x="${x}" y="${H-B+26}" text-anchor="middle">${yr.year}${yr.partial?"*":""}</text><text class="tick" x="${x}" y="${H-B+44}" text-anchor="middle">n=${yr.n}</text>`;
  });
  return svg+`<text class="tick" x="${L-46}" y="16">DAYS</text></svg>`;
}

export function renderPage(years,meta){
  const latest=years.at(-1),peak=years.reduce((a,b)=>b.median>a.median?b:a);
  const rows=years.map(y=>`<tr><td>${y.year}${y.partial?"*":""}</td><td>${y.n}</td><td class="hl">${fmt(y.median)}</td><td>${y.within7}%</td><td>${y.atOrBefore}%</td></tr>`).join("");
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
  --bg:#0a0a0b;--panel:#111113;--line:#1f1f23;--line-strong:#2e2e34;
  --text:#ececee;--muted:#8b8b93;--faint:#5a5a62;
  --red:#ff3b30;--red-dim:#7a1d18;--amber:#ffb020;
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
.live{display:flex;align-items:center;gap:10px;color:var(--text)}
.live i{width:12px;height:12px;border:2px solid var(--red);background:linear-gradient(90deg,transparent 4px,var(--red) 4px,var(--red) 6px,transparent 6px)}
h1{font-size:clamp(22px,3vw,30px);line-height:1.25;font-weight:600;letter-spacing:-.02em;margin:22px 0 0;max-width:620px}
.sub{color:var(--muted);margin:10px 0 0;max-width:560px}
.hero{display:grid;grid-template-columns:1fr auto;gap:40px;align-items:end;border-bottom:1px solid var(--line);padding-bottom:40px}
.label{font:12px var(--mono);color:var(--muted);letter-spacing:.08em;text-transform:uppercase}
.clock{font:700 clamp(88px,15vw,168px)/.9 var(--mono);letter-spacing:-.06em;color:var(--red);margin:14px 0 0}
.clock small{font-size:.3em;letter-spacing:0;color:var(--text);margin-left:.3em}
.side{display:grid;gap:22px;min-width:220px;padding-bottom:6px}
.side strong{display:block;font:600 34px/1.1 var(--mono);letter-spacing:-.03em;margin-top:6px}
.side span.note{font:12px var(--mono);color:var(--faint)}
section{margin-top:48px}
h2{font:12px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);font-weight:400;margin:0 0 18px;display:flex;justify-content:space-between;gap:16px}
svg{display:block;width:100%;height:auto}
.chart-wrap{overflow-x:auto}.chart-wrap svg{min-width:640px}
svg text{font-family:var(--mono)}
.grid{stroke:var(--line)}.axis{stroke:var(--line-strong)}
.tick{fill:var(--faint);font-size:12px}
.bar{fill:var(--red)}.bar.partial{fill:var(--red);opacity:.65}
.value{fill:var(--text);font-size:17px;font-weight:600}.year{fill:var(--text);font-size:14px}
.caveat{border-left:2px solid var(--amber);padding:2px 0 2px 18px;color:var(--muted);font-size:14px;max-width:760px}
.caveat strong{color:var(--text);font-weight:600}
table{width:100%;border-collapse:collapse;font:14px var(--mono)}
th,td{text-align:right;padding:12px 10px;border-bottom:1px solid var(--line)}
th:first-child,td:first-child{text-align:left}
th{font-size:11px;color:var(--faint);font-weight:400;letter-spacing:.06em;text-transform:uppercase}
.hl{color:var(--red);font-weight:600}
.table-wrap{overflow-x:auto}
.notes{font-size:13px;color:var(--faint);max-width:760px}
footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--line);display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;font:12px var(--mono);color:var(--faint)}
footer a{color:var(--muted)}
@media(max-width:720px){main{padding:32px 18px}.top{margin-bottom:36px}.hero{grid-template-columns:1fr;gap:28px}.side{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<main>
<div class="top"><span class="live"><i></i>Defender's Window</span><span>Updated ${escape(fmtDate(meta.asOf))}</span></div>
<header class="hero">
  <div>
    <div class="label">${latest.year}${latest.partial?" so far":""} &middot; median window before exploitation</div>
    <div class="clock">${fmt(latest.median)}<small>day${latest.median===1?"":"s"}</small></div>
    <h1>The defender's window is closing.</h1>
    <p class="sub">How long defenders get between a vulnerability's public disclosure and its first reported exploitation in the wild.</p>
  </div>
  <div class="side">
    <div><span class="label">${peak.year} median window</span><strong>${fmt(peak.median)} days</strong><span class="note">n=${peak.n}</span></div>
    <div><span class="label">${latest.year}: exploited within 7 days</span><strong>${latest.within7}%</strong><span class="note">${peak.within7}% in ${peak.year}</span></div>
  </div>
</header>
<section>
  <h2><span>Median window by CVE publication year</span></h2>
  <div class="chart-wrap">${chart(years)}</div>
</section>
<section>
  <p class="caveat"><strong>Recent years look faster than they really are.</strong> Older CVEs have had years to collect late exploitation reports; recent ones have not yet. Measured over the same 90 days after publication, the median has been about zero days every year since ${FIRST_YEAR}. What has grown is volume: roughly 130 CVEs a year were exploited within a week of disclosure in 2021&ndash;22, versus about 350 in 2024&ndash;25.</p>
</section>
<section>
  <h2><span>By year</span></h2>
  <div class="table-wrap"><table><thead><tr><th>Year</th><th>Exploited CVEs</th><th>Median window (days)</th><th>Exploited within 7 days</th><th>No window: exploited on/before disclosure</th></tr></thead><tbody>${rows}</tbody></table></div>
  <p class="notes">* Partial year, through ${escape(fmtDate(meta.asOf))}. Window = first exploitation report recorded by VulnCheck KEV minus CVE.org publication date. Reported dates can trail actual attacks. VulnCheck KEV coverage grew after its 2023 launch. These figures do not show what causes any change.</p>
</section>
<footer><span>Data: <a href="https://vulncheck.com/kev">VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV)</a> &middot; <a href="https://www.cve.org/">CVE.org</a></span><span>Bertug Berkay Yemen</span></footer>
</main>
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
