import test from "node:test";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import {median,yearlyGap,renderPage} from "../scripts/build.mjs";

const data=JSON.parse(await readFile(new URL("../data/vulncheck-kev.json",import.meta.url),"utf8"));

test("median handles odd, even, negative and empty samples",()=>{
  assert.equal(median([3,-1,7]),3);
  assert.equal(median([1,2,3,4]),2.5);
  assert.equal(median([]),null);
});

test("gap uses CVE publication and VulnCheck date, by publication year",()=>{
  const r=[{published:"2025-12-30",vulncheck:"2026-01-02"},{published:"2025-12-30",vulncheck:"2025-12-28"},{published:null,vulncheck:"2025-01-01"}];
  const y=yearlyGap(r,"2026-10-01").find(x=>x.year===2025);
  assert.equal(y.n,2);assert.equal(y.median,0.5);assert.equal(y.atOrBefore,50);
});

test("current snapshot is real VulnCheck data with every year populated",()=>{
  assert.equal(data.meta.source,"VulnCheck KEV");
  assert(data.meta.entries>1000);
  const years=yearlyGap(data.records,data.meta.asOf);
  assert.deepEqual(years.map(y=>y.year),[2021,2022,2023,2024,2025,2026]);
  assert(years.every(y=>y.n>0&&y.median!==null));
  assert.equal(years.at(-1).partial,true);
});

test("page credits VulnCheck, shows the caveat and has no upload or secrets",()=>{
  const html=renderPage(yearlyGap(data.records,data.meta.asOf),data.meta);
  assert.match(html,/VulnCheck KEV/);
  assert.match(html,/Recent years look faster/);
  assert.doesNotMatch(html,/type="file"|vulncheck_[0-9a-f]{20}|Bearer|X-Amz|Signature=/);
});

test("yearly details add up and examples belong to their year",()=>{
  for(const y of yearlyGap(data.records,data.meta.asOf)){
    assert.equal(y.buckets.reduce((s,b)=>s+b.count,0),y.n);
    assert(y.q1<=y.median&&y.median<=y.q3);
    assert(y.examples.length>0&&y.examples.length<=5);
    assert(y.examples.every(e=>e.published.startsWith(String(y.year))));
  }
});

test("page links back to the blog from the main navigation",()=>{
  const html=renderPage(yearlyGap(data.records,data.meta.asOf),data.meta);
  assert.match(html,/<nav class="top-end" aria-label="Main navigation"><a href="https:\/\/blog\.copperwyre\.com\/">Blog <span aria-hidden="true">&nearr;<\/span><\/a>/);
  assert.equal(html.match(/href="https:\/\/blog\.copperwyre\.com\/"/g)?.length,1);
});

test("page ends with the requested footer quote without attribution",()=>{
  const html=renderPage(yearlyGap(data.records,data.meta.asOf),data.meta);
  assert.match(html,/<\/footer>\s*<p class="footer-quote"><em>&ldquo;Men of the north, you stand at the precipice! Your kings have failed you, so now you turn to the gods!&rdquo;<\/em><\/p>\s*<\/main>/);
  assert.equal(html.match(/class="footer-quote"/g)?.length,1);
});

test("page has a light/dark toggle that sets the theme before first paint",()=>{
  const html=renderPage(yearlyGap(data.records,data.meta.asOf),data.meta);
  assert.match(html,/class="theme-toggle"/);
  assert.match(html,/\.theme-toggle svg\{width:14px;height:14px;min-width:0\}/);
  assert.match(html,/html\[data-theme="light"\]\{/);
  const init=html.indexOf("cw-theme"),style=html.indexOf("<style>");
  assert(init>-1&&init<style,"theme init script must run before the stylesheet");
  assert.doesNotMatch(html.slice(style,html.indexOf("</style>")),/color:#0a0a0b|rgba\(255,255,255,\.03\)\}/,"component rules must use theme variables");
});
