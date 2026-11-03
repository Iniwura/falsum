"use strict";
/* Headless judge-flow QA for PUBLIC handcrafted reviews + captured real Python fixtures.
   Browser interactions are real, but no live LLM, network account or outside app is tested. */
const assert=require("node:assert/strict");
const {pathToFileURL}=require("node:url");
const path=require("node:path");
const fs=require("node:fs");
const {chromium}=require("playwright");
(async()=>{
  const file=path.join(process.env.TEST_SITE_DIR||path.join(process.cwd(),"public"),"index.html");
  const report=JSON.parse(fs.readFileSync(path.join(path.dirname(file),"ACTUAL-SYNTHETIC-RUNTIME-PROOF.json"),"utf8"));
  assert.equal(report.cases.length,3);
  const browser=await chromium.launch({headless:true,args:["--no-sandbox"]});
  const results={desktop:{},mobile:{},smallMobile:{},pageErrors:[]};
  try{
    const page=await browser.newPage({viewport:{width:1440,height:900},deviceScaleFactor:1});
    page.on("pageerror",error=>results.pageErrors.push(error.message));
    await page.goto(pathToFileURL(file).href,{waitUntil:"load"});
    assert.match(await page.title(),/Security review/);
    assert.match(await page.locator("h1").textContent(),/PICK THE/);
    assert.equal(await page.locator("h1").count(),1);
    assert.equal(await page.locator(".answer").count(),2);
    assert.equal(await page.locator("#show-proof").isDisabled(),true);
    await page.screenshot({path:path.join(path.dirname(file),"phase3t-desktop-hero.png")});
    // Deliberate wrong choice should explain the mistake without hiding proof.
    await page.locator("#answer-a").click();
    assert.match(await page.locator("#feedback-head").textContent(),/Not quite/);
    assert.equal(await page.locator("#show-proof").isEnabled(),true);
    await page.locator("#show-proof").click();
    assert.equal(await page.locator("#proof").isVisible(),true);
    assert.match(await page.locator("#proof-before-detail").textContent(),/\$80/);
    assert.match(await page.locator("#proof-after-detail").textContent(),/\$100/);
    assert.match(await page.locator("#proof-control").textContent(),/\$80/);
    await page.locator(".code-details summary").click();
    assert.match(await page.locator("#code-before").textContent(),/def exchange_before/);
    assert.match(await page.locator("#code-after").textContent(),/def exchange_after/);
    assert.equal((await page.locator("#hash-before").textContent()).length,64);
    assert.equal((await page.locator("#hash-after").textContent()).length,64);
    await page.screenshot({path:path.join(path.dirname(file),"phase3t-desktop-proof.png")});
    await page.locator("#next-case").click();
    assert.match(await page.locator("#scene-title").textContent(),/message that looks real/);
    assert.equal(await page.locator("#show-proof").isDisabled(),true);
    await page.locator("#answer-a").click();
    assert.match(await page.locator("#feedback-head").textContent(),/Good catch/);
    await page.locator("#show-proof").click();
    assert.match(await page.locator("#proof-after-detail").textContent(),/rejected invalid signature/);
    await page.locator("#next-case").click();
    assert.match(await page.locator("#scene-title").textContent(),/Paid twice/);
    await page.locator("#answer-b").click();
    assert.match(await page.locator("#feedback-head").textContent(),/Good catch/);
    await page.locator("#show-proof").click();
    assert.match(await page.locator("#proof-before-detail").textContent(),/24/);
    assert.match(await page.locator("#proof-after-detail").textContent(),/12/);
    await page.locator("#next-case").click();
    assert.equal(await page.locator("#finish-view").isVisible(),true);
    assert.equal(await page.locator("#final-score").textContent(),"2/3");
    results.desktop={threeCasesCompleted:true,wrongChoiceExplained:true,positiveControlShown:true,actualPythonSourceVisible:true,score:"2/3"};
    await page.locator("#try-again").click();
    assert.equal(await page.locator("#stage-view").isVisible(),true);
    assert.equal(await page.locator("#show-proof").isDisabled(),true);
    assert.equal(await page.locator("#case-counter").textContent(),"01");
    await page.locator("#answer-b").click();
    assert.match(await page.locator("#feedback-head").textContent(),/Good catch/);
    results.desktop.restart=true;

    const mobile=await browser.newPage({viewport:{width:390,height:844},deviceScaleFactor:1,isMobile:true,hasTouch:true});
    mobile.on("pageerror",error=>results.pageErrors.push(error.message));
    await mobile.goto(pathToFileURL(file).href,{waitUntil:"load"});
    const sizes=await mobile.evaluate(()=>({body:document.body.scrollWidth,doc:document.documentElement.scrollWidth,viewport:document.documentElement.clientWidth}));
    assert.ok(sizes.body<=sizes.viewport+1 && sizes.doc<=sizes.viewport+1,"Mobile horizontal scroll: "+JSON.stringify(sizes));
    await mobile.screenshot({path:path.join(path.dirname(file),"phase3t-mobile-hero.png")});
    // Keyboard remains accessible even on touch-sized layout.
    await mobile.locator("#answer-b").focus();
    await mobile.keyboard.press("Enter");
    assert.match(await mobile.locator("#feedback-head").textContent(),/Good catch/);
    await mobile.locator("#show-proof").tap();
    assert.equal(await mobile.locator("#proof").isVisible(),true);
    await mobile.screenshot({path:path.join(path.dirname(file),"phase3t-mobile-proof.png")});
    results.mobile={widths:sizes,keyboardSelection:true,touchReveal:true};

    const small=await browser.newPage({viewport:{width:320,height:720},deviceScaleFactor:1});
    small.on("pageerror",error=>results.pageErrors.push(error.message));
    await small.goto(pathToFileURL(file).href);
    const narrow=await small.evaluate(()=>({body:document.body.scrollWidth,doc:document.documentElement.scrollWidth,viewport:document.documentElement.clientWidth}));
    assert.ok(narrow.body<=narrow.viewport+1&&narrow.doc<=narrow.viewport+1,"320px horizontal scroll: "+JSON.stringify(narrow));
    results.smallMobile=narrow;
    assert.deepEqual(results.pageErrors,[]);
    console.log(JSON.stringify({success:true,...results},null,2));
  }finally{await browser.close();}
})().catch(err=>{console.error(err.stack||String(err));process.exitCode=1});
