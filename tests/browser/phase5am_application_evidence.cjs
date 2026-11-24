"use strict";
const assert=require("node:assert/strict"),fs=require("node:fs"),path=require("node:path");
const {pathToFileURL}=require("node:url"),{chromium}=require("playwright");
(async()=>{
 const root=process.env.TEST_SITE_DIR||path.join(process.cwd(),"public"),dir=path.join(root,"applications");
 const data=JSON.parse(fs.readFileSync(path.join(dir,"RECORDED-APPLICATION-AGGREGATES.json"),"utf8"));
 assert.equal(data.scale.aggregate.unique_cases,129);
 assert.equal(data.scale.aggregate.archived_not_found,1);
 assert.equal(data.limits.better_than_verdict_baseline,false);
 assert.ok(fs.readFileSync(path.join(root,"index.html"),"utf8").includes('href="/applications/"'));
 const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
 try{
  const errors=[];
  for(const width of [1440,768,390,320]){
   const page=await browser.newPage({viewport:{width,height:900}});
   page.on("pageerror",e=>errors.push(e.message));
   await page.goto(pathToFileURL(path.join(dir,"index.html")).href);
   assert.match(await page.title(),/Application evidence/);
   assert.equal(await page.locator("h1").count(),1);
   assert.equal(await page.getByRole("table",{name:"Vulnerable label policy outcomes",exact:true}).locator("tbody tr").count(),4);
   assert.match(await page.getByRole("table",{name:"Vulnerable label policy outcomes",exact:true}).locator("tbody tr").last().innerText(),/FALSUM policy\s+89\s+0\s+18/);
   assert.match(await page.getByRole("table",{name:"Audited control policy outcomes",exact:true}).locator("tbody tr").last().innerText(),/FALSUM policy\s+5\s+9\s+8/);
   const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1);
   assert.equal(overflow,false,"horizontal overflow at "+width);
   await page.locator("summary").first().focus();
   await page.keyboard.press("Enter");
   assert.equal(await page.locator("details").first().getAttribute("open"),"");
   await page.locator("summary").nth(1).click();
   assert.match(await page.locator("details").nth(1).innerText(),/one NOT_FOUND/);
   assert.equal(await page.getByRole("link",{name:"Recorded JSON"}).getAttribute("href"),"./RECORDED-APPLICATION-AGGREGATES.json");
   await page.screenshot({path:path.join(dir,"phase5am-"+width+".png"),fullPage:true});
   await page.close();
  }
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({pass:true,viewports:[1440,768,390,320],keyboard:true,recordedReceiptUncertainty:true,pageErrors:errors}));
 }finally{await browser.close();}
})().catch(e=>{console.error(e.stack||e);process.exitCode=1});
