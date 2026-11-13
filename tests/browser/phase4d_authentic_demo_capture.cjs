"use strict";
/*
 * FALSUM public-safe REAL BROWSER screencast of the static production build.
 * No fabricated transactions, no live AI inference, no hidden Anjoman inputs.
 * The tested page contains recorded authentic model scores and fictional
 * Python cases from local real execution. This captures actual UI clicks.
 */
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const {pathToFileURL}=require("node:url");
const {chromium}=require("playwright");
(async()=>{
 const base=process.env.FALSUM_DEMO_SITE_DIR||path.join(process.cwd(),"public");
 const out=process.env.FALSUM_DEMO_OUT||path.join(process.cwd(),"demo-capture");
 fs.mkdirSync(out,{recursive:true});
 const source=JSON.parse(fs.readFileSync(path.join(base,"proof","ACTUAL-RECORDED-FOUNDATION-MODEL-SCORES.json"),"utf8"));
 const synthetic=JSON.parse(fs.readFileSync(path.join(base,"ACTUAL-SYNTHETIC-RUNTIME-PROOF.json"),"utf8"));
 assert.equal(source.status,"PHASE4C_STATIC_AUTHENTIC_RECORDED_MODEL_EVIDENCE_NOT_A_LIVE_EVALUATOR");
 assert.equal(source.model_matches_narrow_source_facts,3);
 assert.equal(source.complete_factual_reversals,0);
 assert.equal(source.real_model_score_inputs,12);
 assert.equal(source.recorded_inference_not_live,true);
 assert.equal(source.model_registered_to_telegraph,false);
 assert.equal(synthetic.synthetic_before_after_executions,6);
 assert.equal(synthetic.actual_third_party_mission_apps_verified,0);
 assert.equal(synthetic.actual_evaluator_model_scoring_executed,false);
 const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
 const context=await browser.newContext({
   viewport:{width:1920,height:1080},
   screen:{width:1920,height:1080},
   deviceScaleFactor:1,
   reducedMotion:"reduce",
   recordVideo:{dir:out,size:{width:1920,height:1080}},
 });
 const page=await context.newPage();
 const video=page.video();
 const errors=[],chapters=[];
 page.on("pageerror",error=>errors.push(error.message));
 const started=Date.now();
 const hold=async(secs)=>page.waitForTimeout(Math.round(1000*secs));
 const chapter=(id,title)=>{const row={id,title,offset_ms:Date.now()-started};chapters.push(row);console.log(JSON.stringify(row));};
 async function scroll(top){
   await page.evaluate(top=>window.scrollTo({top,behavior:"smooth"}),top);
   await hold(1.2);
 }
 async function click(selector,secs=1){
   const element=page.locator(selector);
   await element.scrollIntoViewIfNeeded();
   await hold(.3);
   await element.click();
   await hold(secs);
 }
 try{
   await page.goto(pathToFileURL(path.join(base,"proof","index.html")).href,{waitUntil:"load"});
   assert.match(await page.title(),/Actual model evidence/);
   chapter("01","The actual recorded model failure");
   await hold(8);
   await scroll(400);await hold(6);
   chapter("02","Source facts change when package versions change");
   await scroll(955);await hold(4);
   await click("#version-0",2.5);await hold(4);
   await click("#version-1",1.2);
   assert.equal(await page.locator("#selected").textContent(),"A");
   assert.equal(await page.locator("#expected").textContent(),"B");
   await hold(11);
   chapter("03","Additional real package-version reversals");
   await click('[data-project="1"]',2);await hold(3);
   await click("#version-1",1);await hold(7);
   await click('[data-project="2"]',2);await hold(2);
   await click("#version-1",1);await hold(8);
   chapter("04","Published provenance and honest baseline");
   await scroll(0);await hold(8);
   await scroll(1440);await hold(7);
   chapter("05","The executable three-case review challenge");
   await page.goto(pathToFileURL(path.join(base,"index.html")).href,{waitUntil:"load"});
   assert.match(await page.locator("h1").textContent(),/PICK THE/);
   await hold(7);
   await click("#answer-a",1);
   assert.match(await page.locator("#feedback-head").textContent(),/Not quite/);
   await hold(4);
   await click("#show-proof",2);
   assert.equal(await page.locator("#proof").isVisible(),true);
   await hold(13);
   chapter("06","Forged agent callbacks and legitimate controls");
   await click("#next-case",1);await hold(3);
   await click("#answer-a",1);await click("#show-proof",1);
   assert.match(await page.locator("#proof-after-detail").textContent(),/rejected invalid signature/);
   await hold(9);
   chapter("07","Relayer replay protection");
   await click("#next-case",1);await hold(2);
   await click("#answer-b",1);await click("#show-proof",1);
   assert.match(await page.locator("#proof-after-detail").textContent(),/12/);
   await hold(9);
   await click("#next-case",1);
   assert.equal(await page.locator("#final-score").textContent(),"2/3");
   await hold(8);
   chapter("08","Verify the exact recorded evidence");
   await page.goto(pathToFileURL(path.join(base,"proof","index.html")).href,{waitUntil:"load"});
   await hold(3);await scroll(1500);await hold(7);
   await scroll(0);await hold(10);
   assert.deepEqual(errors,[]);
   const result={
    status:"PHASE4D_ACTUAL_CHROMIUM_STATIC_BUILD_CAPTURE_NOT_LIVE_INFERENCE",
    duration_ms:Date.now()-started,
    video_recorded_from_real_browser_interactions:true,
    source_model_real_scores_recorded_not_recomputed:true,
    model_fact_matches:3,
    complete_version_reversals:0,
    fiction_pr_challenge:true,
    independent_network_evaluator:false,
    independent_expert_labels:0,
    hidden_network_material_in_capture:false,
    chapters,errors,
   };
   fs.writeFileSync(path.join(out,"actual-browser-capture-manifest.json"),JSON.stringify(result,null,2)+"\n");
   console.log(JSON.stringify({pass:true,minutes:(result.duration_ms/60000).toFixed(2),chapters:chapters.length},null,2));
 }finally{
   await context.close();
   await browser.close();
   fs.copyFileSync(await video.path(),path.join(out,"FALSUM-REAL-BROWSER-CAPTURE.webm"));
 }
})().catch(e=>{console.error(e.stack||String(e));process.exitCode=1});
