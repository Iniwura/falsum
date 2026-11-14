"use strict";
/* Authentically recorded source-comparison browser QA; zero live model calls. */
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const {pathToFileURL}=require("node:url");
const {chromium}=require("playwright");

(async()=>{
 const base=process.env.TEST_SITE_DIR||path.join(process.cwd(),"public");
 const pagefile=path.join(base,"compare","index.html");
 const data=JSON.parse(fs.readFileSync(path.join(base,"compare","ACTUAL-PHASE4H-FROZEN-SOURCE-MODEL-COMPARISON.json"),"utf8"));
 assert.equal(data.status,"PHASE4I_FOUR_PROJECT_RECORDED_MODEL_COMPARISON_NOT_INDEPENDENT_ACCURACY");
 assert.equal(data.project_count,4);
 assert.equal(data.case_count,8);
 assert.equal(data.model_source_author_matches,5);
 assert.equal(data.model_complete_reversals,1);
 assert.equal(data.constant_A_matches,4);
 assert.equal(data.constant_B_matches,4);
 assert.equal(data.model_f32_inputs,16);
 assert.equal(data.independent_expert_gold_labels,0);
 assert.equal(data.current_live_inference,false);
 assert.equal(data.model_registered,false);
 assert.equal(data.source_aware_oracle_is_hardcoded_from_author_hypotheses,true);
 const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
 const errs=[];
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900}});
  page.on("pageerror",e=>errs.push(e.message));
  page.on("request",req=>{if(!req.url().startsWith("file:"))errs.push("unexpected network: "+req.url())});
  await page.goto(pathToFileURL(pagefile).href);
  assert.match(await page.title(),/Source changes/);
  assert.equal(await page.locator("h1").count(),1);
  assert.equal(await page.locator("[data-case]").count(),4);
  assert.equal(await page.locator("#model-answer").textContent(),"A");
  assert.equal(await page.locator("#source-answer").textContent(),"A");
  await page.screenshot({path:path.join(base,"compare","phase4i-desktop-before.png"),fullPage:true});
  await page.locator("#revision-fixed").click();
  assert.equal(await page.locator("#source-answer").textContent(),"B");
  assert.equal(await page.locator("#model-answer").textContent(),"B");
  assert.match(await page.locator("#verdict").textContent(),/Matches/);
  assert.equal(await page.locator("#revision-fixed").getAttribute("aria-pressed"),"true");
  assert.equal(await page.locator("#source-link").getAttribute("href"),data.groups[0].revisions[1].source_url);
  assert.match(await page.locator("#bits-a").textContent(),/0x[0-9a-f]{8}/);
  await page.screenshot({path:path.join(base,"compare","phase4i-desktop-after.png"),fullPage:true});
  for(let i=0;i<4;i++){
   await page.locator('[data-case="'+i+'"]').click();
   assert.equal(await page.locator("#source-project").textContent(),data.groups[i].name);
   assert.equal(await page.locator("#revision-parent").getAttribute("aria-pressed"),"true");
   assert.equal(await page.locator("#source-answer").textContent(),"A");
   assert.equal(await page.locator("#model-answer").textContent(),data.groups[i].revisions[0].model_chose);
   await page.locator("#revision-fixed").click();
   assert.equal(await page.locator("#source-answer").textContent(),"B");
   assert.equal(await page.locator("#model-answer").textContent(),data.groups[i].revisions[1].model_chose);
   assert.equal(await page.locator("#test-link").getAttribute("href"),data.groups[i].revisions[1].test_url);
   assert.equal(await page.locator("#advisory-link").getAttribute("href"),data.groups[i].advisory);
   assert.ok((await page.locator("#bits-b").textContent()).includes(data.groups[i].revisions[1].score_b_f32));
   assert.equal((await page.locator("#group-result").textContent()).includes("Complete"),true);
  }
  assert.match(await page.locator("#test-caveat").textContent(),/did NOT change/);
  const phone=await browser.newPage({viewport:{width:390,height:844},isMobile:true,hasTouch:true});
  phone.on("pageerror",e=>errs.push(e.message));
  phone.on("request",req=>{if(!req.url().startsWith("file:"))errs.push("unexpected mobile network: "+req.url())});
  await phone.goto(pathToFileURL(pagefile).href);
  for(const width of [390,320]){
    await phone.setViewportSize({width,height:844});
    const sizes=await phone.evaluate(()=>({body:document.body.scrollWidth,doc:document.documentElement.scrollWidth,client:document.documentElement.clientWidth}));
    assert.ok(sizes.body<=sizes.client+1&&sizes.doc<=sizes.client+1,"horizontal overflow "+width+": "+JSON.stringify(sizes));
    await phone.locator('[data-case="2"]').tap();
    await phone.locator("#revision-fixed").tap();
    assert.equal(await phone.locator("#source-project").textContent(),"MCP Python SDK");
    assert.equal(await phone.locator("#model-answer").textContent(),"B");
    assert.equal(await phone.locator("#source-answer").textContent(),"B");
    await phone.screenshot({path:path.join(base,"compare","phase4i-"+width+"px.png"),fullPage:true});
  }
  await phone.locator('[data-case="3"]').focus();
  await phone.keyboard.press("Enter");
  assert.equal(await phone.locator("#source-project").textContent(),"Pillow");
  await phone.locator("#revision-parent").focus();
  await phone.keyboard.press("Enter");
  assert.equal(await phone.locator("#source-answer").textContent(),"A");
  assert.deepEqual(errs,[]);
  console.log(JSON.stringify({passed:true,sourceProjects:4,sourceContexts:8,
    realScoreInputs:16,desktop:true,mobile390:true,mobile320:true,
    keyboard:true,touch:true,networkRequests:0,pageErrors:errs},null,2));
 }finally{await browser.close();}
})().catch(e=>{console.error(e.stack||String(e));process.exitCode=1});
