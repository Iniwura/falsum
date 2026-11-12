"use strict";
/* Real recorded f32 proof, not real-time model inference. */
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const {pathToFileURL}=require("node:url");
const {chromium}=require("playwright");
(async()=>{
 const dir=process.env.TEST_SITE_DIR||path.join(process.cwd(),"public");
 const pageFile=path.join(dir,"proof","index.html");
 const report=JSON.parse(fs.readFileSync(path.join(dir,"proof","ACTUAL-RECORDED-FOUNDATION-MODEL-SCORES.json"),"utf8"));
 assert.equal(report.status,"PHASE4C_STATIC_AUTHENTIC_RECORDED_MODEL_EVIDENCE_NOT_A_LIVE_EVALUATOR");
 assert.equal(report.model_matches_narrow_source_facts,3);
 assert.equal(report.complete_factual_reversals,0);
 assert.equal(report.real_model_score_inputs,12);
 assert.equal(report.recorded_inference_not_live,true);
 assert.equal(report.model_registered_to_telegraph,false);
 assert.equal(report.cases.length,3);
 const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
 const errors=[], results={};
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900}});
  page.on("pageerror",e=>errors.push(e.message));
  await page.goto(pathToFileURL(pageFile).href);
  assert.match(await page.title(),/Actual model evidence/);
  assert.match(await page.locator("h1").textContent(),/THE MODEL.*MISSED THE FIX/s);
  assert.equal(await page.locator("h1").count(),1);
  assert.equal(await page.locator("[data-project]").count(),3);
  assert.equal(await page.locator("#package-title").textContent(),"docling-core");
  assert.equal(await page.locator("#selected").textContent(),"A");
  assert.equal(await page.locator("#expected").textContent(),"A");
  assert.match(await page.locator("#verdict").textContent(),/matches this narrow source fact/);
  await page.screenshot({path:path.join(dir,"proof","phase4c-desktop-affected.png"),fullPage:true});
  await page.locator("#version-1").click();
  assert.equal(await page.locator("#expected").textContent(),"B");
  assert.equal(await page.locator("#selected").textContent(),"A");
  assert.match(await page.locator("#verdict").textContent(),/Failure/);
  assert.equal(await page.locator("#version-1").getAttribute("aria-pressed"),"true");
  assert.equal(await page.locator("#catalogue-answer").textContent(),"Outside this GHSA range");
  assert.match(await page.locator("#bits").textContent(),/0x[0-9a-f]{8}.*0x[0-9a-f]{8}/);
  await page.screenshot({path:path.join(dir,"proof","phase4c-desktop-fixed.png"),fullPage:true});
  for(let i=0;i<3;i++){
   await page.locator('[data-project="'+i+'"]').click();
   assert.equal(await page.locator("#package-title").textContent(),report.cases[i].project);
   assert.equal(await page.locator("#version-0").getAttribute("aria-pressed"),"true");
   assert.equal(await page.locator("#expected").textContent(),"A");
   await page.locator("#version-1").click();
   assert.equal(await page.locator("#expected").textContent(),"B");
   assert.equal(await page.locator("#selected").textContent(),"A");
   assert.match(await page.locator("#verdict").textContent(),/Failure/);
   assert.equal(await page.locator("#ghsa").textContent(),report.cases[i].ghsa);
   assert.equal(await page.locator("#advisory-link").getAttribute("href"),report.cases[i].ghsa_url);
   assert.ok((await page.locator("#bits").textContent()).includes(report.cases[i].versions[1].score_a_f32_bits));
  }
  results.desktop={threeGroups:true,allFixedVersionsFail:true,realScoreBitsVisible:true};
  const mobile=await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1,isMobile:true,hasTouch:true});
  mobile.on("pageerror",e=>errors.push(e.message));
  await mobile.goto(pathToFileURL(pageFile).href);
  for(const width of [390,320]){
   await mobile.setViewportSize({width:width,height:844});
   const dims=await mobile.evaluate(()=>({width:document.documentElement.clientWidth,body:document.body.scrollWidth,doc:document.documentElement.scrollWidth}));
   assert.ok(dims.body<=dims.width+1&&dims.doc<=dims.width+1,"horizontal overflow "+JSON.stringify(dims));
   await mobile.locator("#version-1").tap();
   assert.equal(await mobile.locator("#expected").textContent(),"B");
   assert.equal(await mobile.locator("#selected").textContent(),"A");
   await mobile.locator('[data-project="2"]').tap();
   assert.equal(await mobile.locator("#package-title").textContent(),"python-multipart");
   await mobile.locator("#version-1").tap();
   assert.match(await mobile.locator("#verdict").textContent(),/Failure/);
   await mobile.screenshot({path:path.join(dir,"proof","phase4c-"+width+"px.png"),fullPage:true});
  }
  await mobile.locator('[data-project="1"]').focus();
  await mobile.keyboard.press("Enter");
  assert.equal(await mobile.locator("#package-title").textContent(),"hydra-core");
  results.mobile={responsive390and320:true,keyboardAndTouch:true};
  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({pass:true,...results,pageErrors:errors},null,2));
 }finally{await browser.close();}
})().catch(e=>{console.error(e.stack||String(e));process.exitCode=1});
