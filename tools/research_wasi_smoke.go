// Run the actual packaged V2 WASI model and compare with exporter FP32 reference.
// Research-only, no network registration and no quality claims.
package main
import (
 "bytes"
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "flag"
 "fmt"
 "math"
 "os"
 "path/filepath"
 "regexp"
 "strconv"
 "strings"
 "time"
 "github.com/tetratelabs/wazero"
 "github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)
const wasmHash="52db6ad999cd262af915b6b908dcead7920bc08036cdfae01fee60bfd196d6e8"
const onnxHash="3f373ea41ae27c64931798cf7b5a7037ed2beeaa0ca5be047ce5c118e68df91d"
const tolerance=0.05
var pattern=regexp.MustCompile("(?m)^HEX[[:space:]]*:[[:space:]]*0x([0-9a-fA-F]{8})[[:space:]]+")
func must(err error){if err!=nil{panic(err)}}
func one(root,name string) string {
 var found []string
 must(filepath.WalkDir(root,func(p string,d os.DirEntry,err error) error{
  if err!=nil{return err}
  if d.Type()&os.ModeSymlink!=0{return fmt.Errorf("symlink forbidden: %s",p)}
  if !d.IsDir()&&d.Name()==name{found=append(found,p)}
  return nil
 }))
 if len(found)!=1{panic(fmt.Sprintf("expected one %s, found %d",name,len(found)))}
 return found[0]
}
func readJSON(path string) map[string]any{
 b,err:=os.ReadFile(path);must(err)
 var x map[string]any
 must(json.Unmarshal(b,&x));return x
}
func main(){
 root:=flag.String("archive","","downloaded quarantined WASM archive")
 reportFile:=flag.String("report","","new research-only report path")
 flag.Parse()
 if *root==""||*reportFile==""{panic("archive and report args required")}
 if _,err:=os.Stat(*reportFile);err==nil{panic("refusing report overwrite")}
 wasm:=one(*root,"SECURITY_REVIEW_GENERAL.wasm")
 manifest:=readJSON(one(*root,"SECURITY_REVIEW_GENERAL.wasm.manifest.json"))
 exporter:=readJSON(one(*root,"model.onnx.export.json"))
 provenance:=readJSON(one(*root,"RESEARCH-ONLY-SOURCE-PROVENANCE.json"))
 if manifest["bundle_sha256"]!=wasmHash||manifest["intent"]!="SECURITY_REVIEW_GENERAL"||
    manifest["class"]!="hybrid"||manifest["runtime"]!="onnx_f32"||
    manifest["abi_version"]!=float64(2)||manifest["max_tokens"]!=float64(512)||
    manifest["verified"]!=true||exporter["base_model"]!="answerdotai/ModernBERT-base"||
    provenance["source_run"]!=float64(41126779406)||
    provenance["source_status"]!="BLOCKED_RESEARCH_ONLY"||
    provenance["registration_authorized"]!=false||provenance["network_eligible"]!=false{
  panic("official kit metadata/provenance mismatch or promotion attempt")
 }
 onnxTxt,err:=os.ReadFile(one(*root,"ONNX-SHA256.txt"));must(err)
 if !strings.HasPrefix(strings.TrimSpace(string(onnxTxt)),onnxHash+" "){panic("ONNX hash mismatch")}
 blob,err:=os.ReadFile(wasm);must(err)
 sum:=sha256.Sum256(blob)
 if hex.EncodeToString(sum[:])!=wasmHash{panic("actual wasm hash mismatch")}
 fmt.Fprintf(os.Stderr,"WASM %d bytes, ABI v2 hybrid metadata, SHA-256 verified\n",len(blob))
 input:=map[string]any{"input_ids":[]int64{50281,4118,17526,27,187,18658,436,13814,1818,50282},
  "attention_mask":[]int64{1,1,1,1,1,1,1,1,1,1}}
 inputBytes,err:=json.Marshal(input);must(err)
 dir,err:=os.MkdirTemp("","falsum-wasi-");must(err);defer os.RemoveAll(dir)
 must(os.WriteFile(filepath.Join(dir,"input.json"),inputBytes,0600))
 ctx,cancel:=context.WithTimeout(context.Background(),600*time.Second);defer cancel()
 rt:=wazero.NewRuntimeWithConfig(ctx,wazero.NewRuntimeConfig().WithCloseOnContextDone(true))
 defer rt.Close(context.Background())
 _,err=wasi_snapshot_preview1.Instantiate(ctx,rt);must(err)
 compiled,err:=rt.CompileModule(ctx,blob);must(err)
 defer compiled.Close(context.Background())
 var stdout,stderr bytes.Buffer
 cfg:=wazero.NewModuleConfig().WithArgs("baked","/in/input.json","1").
  WithFSConfig(wazero.NewFSConfig().WithDirMount(dir,"/in")).
  WithStdout(&stdout).WithStderr(&stderr)
 begin:=time.Now()
 _,err=rt.InstantiateModule(ctx,compiled,cfg)
 if err!=nil{panic(fmt.Sprintf("WASI score failed: %v stderr=%q",err,stderr.String()))}
 groups:=pattern.FindStringSubmatch(stdout.String())
 if len(groups)!=2{panic(fmt.Sprintf("invalid score output: %q stderr=%q",stdout.String(),stderr.String()))}
 bits,err:=strconv.ParseUint(groups[1],16,32);must(err)
 score:=float64(math.Float32frombits(uint32(bits)))
 expected,ok:=exporter["reference_f32"].(float64)
 if !ok||math.IsNaN(score)||math.IsInf(score,0)||math.IsNaN(expected)||math.IsInf(expected,0){
  panic("non-finite actual score or missing model reference")
 }
 delta:=math.Abs(score-expected)
 outcome:="WASI_EXECUTED_REFERENCE_MISMATCH"
 if delta<=tolerance{outcome="WASI_EXECUTED_REFERENCE_PARITY_WITHIN_TOLERANCE"}
 result:=map[string]any{
  "schema_version":1,"status":outcome,"source_model_run":41126779406,
  "wasm_sha256":wasmHash,"onnx_sha256":onnxHash,
  "abi_version":2,"class":"hybrid","runtime":"onnx_f32","token_limit":512,
  "reference_pytorch_f32":expected,"actual_wasi_f32":score,
  "absolute_delta":delta,"absolute_tolerance":tolerance,
  "elapsed_ms":time.Since(begin).Milliseconds(),
  "human_reviewed":0,"network_eligible":false,
  "registration_authorized":false,"real_world_accuracy_measured":false,
  "warning":"One runtime smoke only. Not independent answer quality, node acceptance or network registration.",
 }
 out,err:=json.MarshalIndent(result,"","  ");must(err)
 must(os.WriteFile(*reportFile,append(out,10),0600))
 fmt.Println(string(out))
 if delta>tolerance{panic("WASI score fails FP32 reference comparison")}
}
