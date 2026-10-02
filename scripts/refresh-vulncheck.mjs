#!/usr/bin/env node
// Downloads VulnCheck KEV (Community) and CVE.org publication dates.
// Run through scripts/with-vulncheck-token.ps1 so the token stays out of files.
import {createHash} from "node:crypto";
import {mkdtemp,readFile,writeFile,readdir,rm,mkdir} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {execFileSync} from "node:child_process";

const root=new URL("../",import.meta.url);
const token=process.env.VULNCHECK_API_TOKEN;
if(!token)throw new Error("VULNCHECK_API_TOKEN is not loaded. Use scripts/with-vulncheck-token.ps1.");
const asOf=process.argv[2]??new Intl.DateTimeFormat("en-CA",{timeZone:"Europe/Berlin"}).format(new Date());
if(!/^\d{4}-\d{2}-\d{2}$/.test(asOf))throw new Error("Usage: refresh-vulncheck.mjs [YYYY-MM-DD]");
const sha=b=>createHash("sha256").update(b).digest("hex");
const day=v=>{
  if(typeof v!=="string")return null;
  const t=Date.parse(v.length===10?v+"T00:00:00Z":v);
  return Number.isFinite(t)?new Date(t).toISOString().slice(0,10):null;
};

async function get(url,options={},attempts=3){
  for(let i=1;;i++){
    try{
      const r=await fetch(url,{...options,signal:AbortSignal.timeout(120000)});
      if(r.ok||r.status===404||i>=attempts||(r.status<500&&r.status!==429))return r;
    }catch(error){if(i>=attempts)throw error;}
    await new Promise(res=>setTimeout(res,2000*i));
  }
}

// 1. VulnCheck KEV bulk backup.
const meta=await get("https://api.vulncheck.com/v3/backup/vulncheck-kev",{headers:{Accept:"application/json",Authorization:`Bearer ${token}`}});
if(!meta.ok)throw new Error(`VulnCheck backup metadata failed: HTTP ${meta.status}`);
const backup=(await meta.json()).data?.[0];
if(!backup?.url||!backup?.sha256)throw new Error("Unexpected VulnCheck backup response");
const zipResponse=await get(backup.url);
if(!zipResponse.ok)throw new Error(`VulnCheck backup download failed: HTTP ${zipResponse.status}`);
const zip=Buffer.from(await zipResponse.arrayBuffer());
if(sha(zip)!==backup.sha256)throw new Error("VulnCheck backup checksum mismatch");
const work=await mkdtemp(join(tmpdir(),"vckev-"));
let kev;
try{
  await writeFile(join(work,"kev.zip"),zip);
  // Windows bsdtar reads ZIP files; Linux runners use unzip.
  if(process.platform==="win32")execFileSync("tar",["-xf",join(work,"kev.zip"),"-C",work]);
  else execFileSync("unzip",["-q","-o",join(work,"kev.zip"),"-d",work]);
  const file=(await readdir(work)).find(f=>f.endsWith(".json"));
  if(!file)throw new Error("No JSON file inside the VulnCheck backup");
  const parsed=JSON.parse(await readFile(join(work,file),"utf8"));
  kev=Array.isArray(parsed)?parsed:parsed.data;
}finally{await rm(work,{recursive:true,force:true});}
if(!Array.isArray(kev)||kev.length<1000)throw new Error("VulnCheck KEV backup is unexpectedly small");

const byCve=new Map();
for(const e of kev){
  const vc=day(e.date_added),cisa=day(e.cisa_date_added);
  const reports=(e.vulncheck_reported_exploitation??[]).map(x=>day(x?.date_added)).filter(Boolean).sort();
  for(const cve of e.cve??[]){
    if(!/^CVE-\d{4}-\d{4,}$/.test(cve))continue;
    const prev=byCve.get(cve);
    const earliest=(a,b)=>!a?b:!b?a:a<b?a:b;
    byCve.set(cve,{cve,vulncheck:earliest(prev?.vulncheck,vc),cisa:earliest(prev?.cisa,cisa),
      firstReport:earliest(prev?.firstReport,reports[0]??null),reports:(prev?.reports??0)+reports.length,
      vendor:prev?.vendor??(typeof e.vendorProject==="string"?e.vendorProject.slice(0,80):null),
      product:prev?.product??(typeof e.product==="string"?e.product.slice(0,80):null),
      ransomware:prev?.ransomware==="Known"||e.knownRansomwareCampaignUse==="Known"?"Known":"Unknown"});
  }
}

// 2. CVE.org publication dates (cached; only missing CVEs are fetched).
await mkdir(new URL("data/",root),{recursive:true});
const cachePath=new URL("data/cve-published.json",root);
let cache={};
try{cache=JSON.parse(await readFile(cachePath,"utf8"));}catch(error){if(error.code!=="ENOENT")throw error;}
const pending=[...byCve.keys()].filter(c=>!(c in cache));
let next=0,failed=0;
async function worker(){
  while(next<pending.length){
    const cve=pending[next++];
    const [,year,num]=cve.split("-");
    const url=`https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${Math.floor(Number(num)/1000)}xxx/${cve}.json`;
    try{
      const r=await get(url);
      if(r.status===404){cache[cve]=null;continue;}
      if(!r.ok){failed++;continue;}
      const record=await r.json();
      cache[cve]=day(record.cveMetadata?.datePublished)??null;
    }catch{failed++;}
  }
}
await Promise.all(Array.from({length:12},worker));
await writeFile(cachePath,JSON.stringify(cache)+"\n");
if(failed)throw new Error(`${failed} CVE.org lookups failed; rerun to complete the cache`);

const records=[...byCve.values()].map(r=>({...r,published:cache[r.cve]??null})).sort((a,b)=>a.cve.localeCompare(b.cve));
const out={meta:{source:"VulnCheck KEV",attribution:"VulnCheck Known Exploited Vulnerabilities (VulnCheck KEV)",
  attributionUrl:"https://docs.vulncheck.com/community/vulncheck-kev/attribution",publication:"CVE.org cveMetadata.datePublished",
  asOf,retrievedAt:new Date().toISOString(),backupFile:backup.filename,backupDate:backup.date_added,backupSha256:backup.sha256,
  entries:kev.length,cves:records.length,missingPublication:records.filter(r=>!r.published).length},records};
await writeFile(new URL("data/vulncheck-kev.json",root),JSON.stringify(out)+"\n");
console.log(`VulnCheck KEV: ${kev.length} entries, ${records.length} CVEs; ${out.meta.missingPublication} without a CVE.org publication date.`);
