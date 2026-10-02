import test from "node:test";
import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {fileURLToPath} from "node:url";
test("static preview serves the index, nested data and missing routes",{timeout:15000},async()=>{
  const child=spawn(process.execPath,[fileURLToPath(new URL("../scripts/serve.mjs",import.meta.url))],{env:{...process.env,PORT:"0"},stdio:["ignore","pipe","pipe"]});
  try{
    const url=await new Promise((resolve,reject)=>{
      let output="";
      const timer=setTimeout(()=>reject(new Error("Preview startup timeout")),8000);
      child.once("error",e=>{clearTimeout(timer);reject(e);});
      child.once("exit",code=>{clearTimeout(timer);reject(new Error("Preview exited: "+code));});
      child.stdout.on("data",chunk=>{
        output+=chunk;
        const match=output.match(/http:\/\/127\.0\.0\.1:\d+/);
        if(match){clearTimeout(timer);resolve(match[0]);}
      });
      child.stderr.on("data",chunk=>{output+=chunk;});
    });
    const index=await fetch(url+"/");
    assert.equal(index.status,200);
    assert.match(index.headers.get("content-type"),/text\/html/);
    assert.match(await index.text(),/Defender's Window/);
    assert.equal((await fetch(url+"/data/vulncheck-kev.json")).status,200);
    assert.equal((await fetch(url+"/missing.html")).status,404);
  }finally{child.kill();}
});
