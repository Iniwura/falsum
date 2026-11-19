"use strict";
/* FALSUM Phase 4V: real third-party upstream tests, not browser-run tests or trained inference. */
const assert=require("node:assert/strict");
const fs=require("node:fs");
const path=require("node:path");
const {pathToFileURL}=require("node:url");
const {chromium}=require("playwright");

(async()=>{
 const root=process.env.TEST_SITE_DIR||path.join(process.cwd(),"public");
 const folder=path.join(root,"witness");
 const file=path.join(folder,"index.html");
 const data=JSON.parse(fs.readFileSync(path.join(folder,"FIVE-AUTHENTIC-UPSTREAM-SOURCE-REGRESSIONS.json"),"utf8"));
 assert.equal(data.status,"PHASE5D_STATIC_FIVE_REAL_SOURCE_EXECUTIONS_PRECOMPUTED_CLAIMS_NOT_MODEL_ACCURACY");
 assert.equal(data.source_fix_stage_count,5);
 assert.equal(data.upstream_project_count,4);
 assert.equal(data.precomputed_python_evaluations,80);
 assert.deepEqual(data.by_construction_verdict_counts,{ABSTAIN:60,CONTRADICTED:10,SUPPORTED:10});
 assert.equal(data.trained_model_improvement_proven,false);
 assert.equal(data.independent_appsec_expert_gold_labels,0);
 assert.equal(data.new_anjoman_eligible_rows,0);
 assert.equal(data.network_evaluator_registered,false);
 assert.equal(data.no_live_browser_tests_or_model_inference,true);
 assert.equal(data.cases.length,5);

 const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
 const errors=[];
 const pageError=err=>errors.push("pageerror: "+err.message);
 const request=req=>{if(!req.url().startsWith("file:"))errors.push("unrequested network: "+req.url())};
 try{
  const page=await browser.newPage({viewport:{width:1440,height:900}});
  page.on("pageerror",pageError);page.on("request",request);
  await page.goto(pathToFileURL(file).href);
  assert.match(await page.title(),/Real source evidence/);
  assert.equal(await page.locator("h1").count(),1);
  assert.equal(await page.locator("#case-list button").count(),5);
  assert.equal(await page.locator("#claim-list button").count(),4);
  assert.equal(await page.locator("#case-list button[aria-pressed=true]").count(),1);
  assert.equal(await page.locator("#claim-list button[aria-pressed=true]").count(),1);
  assert.equal(await page.locator("#case-title").textContent(),data.cases[0].title);
  assert.equal(await page.locator("#commit").textContent(),data.cases[0].parent_commit);
  assert.equal(await page.locator("#source-link").getAttribute("href"),data.cases[0].source_parent_url);
  assert.equal(await page.locator("#verdict").isHidden(),true);
  await page.screenshot({path:path.join(folder,"phase4v-desktop-initial.png"),fullPage:true});

  // An incorrect "new security test passes on old code" claim contradicts real upstream evidence.
  await page.locator("#verify").click();
  assert.equal(await page.locator("#verdict-word").textContent(),"CONTRADICTED");
  assert.equal(await page.locator("#observed").textContent(),"FAILS");
  assert.match(await page.locator("#verdict-message").textContent(),/opposite/);

  // Same test on fixed commit supports exactly the bounded claim.
  await page.locator("#revision-fixed").click();
  assert.equal(await page.locator("#verdict").isHidden(),true);
  assert.equal(await page.locator("#source-link").getAttribute("href"),data.cases[0].source_fixed_url);
  assert.equal(await page.locator("#commit").textContent(),data.cases[0].fixed_commit);
  assert.equal(await page.locator("#revision-fixed").getAttribute("aria-pressed"),"true");
  await page.locator("#verify").click();
  assert.equal(await page.locator("#verdict-word").textContent(),"SUPPORTED");
  assert.equal(await page.locator("#observed").textContent(),"PASSES");
  await page.screenshot({path:path.join(folder,"phase4v-desktop-source-supported.png"),fullPage:true});

  // A wrong signed-off execution digest never becomes "SUPPORTED" even for a true claim.
  await page.locator("#integrity-tampered").click();
  assert.equal(await page.locator("#receipt").textContent(),"0".repeat(64));
  assert.equal(await page.locator("#verdict").isHidden(),true);
  await page.locator("#verify").click();
  assert.equal(await page.locator("#verdict-word").textContent(),"ABSTAIN");
  assert.match(await page.locator("#verdict-message").textContent(),/does not match/);
  await page.screenshot({path:path.join(folder,"phase4v-desktop-bad-receipt-abstain.png"),fullPage:true});

  // A real source fix is not a production exploit or universal security certification.
  await page.locator("#integrity-original").click();
  await page.locator('[data-claim="CONFIRMED_PRODUCTION_EXPLOIT"]').click();
  await page.locator("#verify").click();
  assert.equal(await page.locator("#verdict-word").textContent(),"ABSTAIN");
  assert.match(await page.locator("#verdict-message").textContent(),/source-level regression/);
  await page.locator('[data-claim="GUARANTEED_UNIVERSAL_APPLICATION_SAFETY"]').click();
  await page.locator("#verify").click();
  assert.equal(await page.locator("#verdict-word").textContent(),"ABSTAIN");

  for(let i=0;i<5;i++){
    const record=data.cases[i];
    await page.locator('#case-list button[data-case="'+i+'"]').click();
    assert.equal(await page.locator("#case-title").textContent(),record.title);
    assert.equal(await page.locator("#run-link").getAttribute("href"),record.actions_run_url);
    assert.equal(await page.locator("#test-link").getAttribute("href"),record.upstream_test_url);
    assert.equal(await page.locator("#test-blob").textContent(),record.new_regression_test_blob_sha1);
    assert.equal(await page.locator("#receipt").textContent(),record.original_execution_receipt_sha256);
    assert.equal(await page.locator("#revision-parent").getAttribute("aria-pressed"),"true");
    await page.locator('[data-claim="UPSTREAM_REGRESSION_FAILS"]').click();
    await page.locator("#verify").click();
    assert.equal(await page.locator("#verdict-word").textContent(),"SUPPORTED");
    assert.equal(await page.locator("#observed").textContent(),"FAILS");
    await page.locator("#revision-fixed").click();
    await page.locator('[data-claim="UPSTREAM_REGRESSION_PASSES"]').click();
    await page.locator("#verify").click();
    assert.equal(await page.locator("#verdict-word").textContent(),"SUPPORTED");
    assert.equal(await page.locator("#observed").textContent(),"PASSES");
  }
  await page.screenshot({path:path.join(folder,"phase5d-desktop-flask.png"),fullPage:true});
  // Fifth case independently pins Flask source and a separately recovered original Actions ZIP.
  const flask=data.cases[4];
  assert.equal(flask.id,"flask-session-cookie-vary");
  assert.equal(flask.repository,"pallets/flask");
  assert.equal(flask.original_execution_receipt_sha256,
    "65150bc4d196d715386bd758d37ad0b41dc8b2f242bd8628825b3158da15efb5");
  assert.equal(await page.locator("#case-title").textContent(),flask.title);
  assert.equal(await page.locator("#run-link").getAttribute("href"),
    "https://github.com/Iniwura/falsum/actions/runs/44524997174");
  await page.locator("#integrity-tampered").click();
  await page.locator("#verify").click();
  assert.equal(await page.locator("#verdict-word").textContent(),"ABSTAIN");
  await page.locator("#integrity-original").click();
  await page.locator("#revision-fixed").click();
  await page.locator('[data-claim="UPSTREAM_REGRESSION_PASSES"]').click();
  await page.locator("#verify").click();
  assert.equal(await page.locator("#verdict-word").textContent(),"SUPPORTED");
  

  const phone=await browser.newPage({viewport:{width:390,height:844},hasTouch:true,isMobile:true});
  phone.on("pageerror",pageError);phone.on("request",request);
  await phone.goto(pathToFileURL(file).href);
  for(const width of [390,320]){
    await phone.setViewportSize({width,height:844});
    const dims=await phone.evaluate(()=>({
      client:document.documentElement.clientWidth,
      body:document.body.scrollWidth,
      html:document.documentElement.scrollWidth,
    }));
    assert.ok(dims.body<=dims.client+1&&dims.html<=dims.client+1,
      "horizontal overflow on "+width+"px: "+JSON.stringify(dims));
    await phone.locator('#case-list button[data-case="1"]').tap();
    assert.equal(await phone.locator("#case-title").textContent(),data.cases[1].title);
    await phone.locator("#revision-fixed").tap();
    await phone.locator("#verify").tap();
    assert.equal(await phone.locator("#verdict-word").textContent(),"SUPPORTED");
    await phone.locator("#integrity-tampered").tap();
    await phone.locator("#verify").tap();
    assert.equal(await phone.locator("#verdict-word").textContent(),"ABSTAIN");
    await phone.screenshot({path:path.join(folder,"phase4v-mobile-"+width+".png"),fullPage:true});
  }
  await phone.locator('#case-list button[data-case="2"]').focus();
  await phone.keyboard.press("Enter");
  assert.equal(await phone.locator("#case-title").textContent(),data.cases[2].title);
  await phone.locator("#revision-fixed").focus();
  await phone.keyboard.press("Enter");
  await phone.locator("#verify").focus();
  await phone.keyboard.press("Enter");
  assert.equal(await phone.locator("#verdict-word").textContent(),"SUPPORTED");

  assert.deepEqual(errors,[]);
  console.log(JSON.stringify({
    passed:true,realSourceStages:5,precomputedPythonVerdicts:80,
    authenticSourceAndTestLinks:true,parentFailFixedPassAcrossAll:true,
    wrongReceiptAbstains:true,unprovenProductionClaimsAbstain:true,
    mobile390:true,mobile320:true,keyboard:true,touch:true,
    networkRequests:0,independentExpertGold:0,originalModelImproved:false,
  },null,2));
 }finally{await browser.close();}
})().catch(e=>{console.error(e.stack||String(e));process.exitCode=1;});
