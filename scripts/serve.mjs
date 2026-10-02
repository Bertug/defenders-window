import {createServer} from "node:http";
import {readFile,stat} from "node:fs/promises";
import {resolve,extname,sep} from "node:path";
import {fileURLToPath} from "node:url";
const root=resolve(fileURLToPath(new URL("../",import.meta.url))),port=Number(process.env.PORT||8875);
const server=createServer(async(req,res)=>{
  try{
    const path=resolve(root,"."+decodeURIComponent(new URL(req.url,"http://localhost").pathname));
    if(path!==root&&!path.startsWith(root+sep)){res.writeHead(403);res.end("Forbidden");return;}
    const file=(await stat(path)).isDirectory()?resolve(path,"index.html"):path;
    const body=await readFile(file);
    res.writeHead(200,{"Content-Type":({".html":"text/html; charset=utf-8",".json":"application/json",".js":"text/javascript",".css":"text/css"})[extname(file)]||"application/octet-stream","Cache-Control":"no-cache"});
    res.end(body);
  }catch(error){
    const status=error.code==="ENOENT"?404:error instanceof URIError?400:500;
    if(status===500) console.error(error);
    res.writeHead(status);res.end(status===404?"Not found":"Request failed");
  }
});
server.listen(port,"127.0.0.1",()=>console.log(`Exploitation Observatory: http://127.0.0.1:${server.address().port}`));
