// Cross-language code-injection detector (CWE-94) — Java/C#/Go/Kotlin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCodeInjectionMultilang as s } from '../src/sast/code-injection-multilang.js';

const fires = (fp, code) => s(fp, code).some((f) => f.cwe === 'CWE-94');
const clean = (fp, code) => s(fp, code).every((f) => f.cwe !== 'CWE-94');

test('Java — ScriptEngine.eval / Groovy / SpEL / MVEL on non-literal fire; literal clean', () => {
  assert.ok(fires('E.java', 'import javax.script.*;\nclass E { Object r(String c) throws Exception { return new ScriptEngineManager().getEngineByName("js").eval(c); } }'));
  assert.ok(fires('E.java', 'import groovy.lang.GroovyShell;\nclass E { Object r(String c){ return new GroovyShell().evaluate(c); } }'));
  assert.ok(fires('E.java', 'import org.springframework.expression.spel.standard.SpelExpressionParser;\nclass E { Object r(String c){ return new SpelExpressionParser().parseExpression(c).getValue(); } }'));
  assert.ok(fires('E.java', 'import org.mvel2.MVEL;\nclass E { Object r(String c){ return MVEL.eval(c); } }'));
  assert.ok(clean('E.java', 'import javax.script.*;\nclass E { Object r() throws Exception { return new ScriptEngineManager().getEngineByName("js").eval("1+1"); } }'));
  assert.ok(clean('E.java', 'class E { int add(int a,int b){ return a+b; } }'));
});

test('C# — CSharpScript.EvaluateAsync / DataTable.Compute on non-literal fire; literal clean', () => {
  assert.ok(fires('E.cs', 'using Microsoft.CodeAnalysis.CSharp.Scripting;\nclass E { async void r(string c){ await CSharpScript.EvaluateAsync(c); } }'));
  assert.ok(fires('E.cs', 'using System.Data;\nclass E { object r(string expr){ return new DataTable().Compute(expr, ""); } }'));
  assert.ok(clean('E.cs', 'using System.Data;\nclass E { object r(){ return new DataTable().Compute("1+1", ""); } }'));
  // Compute without a DataTable gate must not fire.
  assert.ok(clean('E.cs', 'class E { object r(string x){ return Helper.Compute(x); } }'));
});

test('Go — yaegi interp.Eval / template.Parse of non-literal fire; literal template clean', () => {
  assert.ok(fires('e.go', 'package main\nimport "github.com/traefik/yaegi/interp"\nfunc r(code string){ i := interp.New(interp.Options{}); i.Eval(code) }'));
  assert.ok(fires('e.go', 'package main\nimport "text/template"\nfunc r(in string, w io.Writer){ t,_ := template.New("x").Parse(in); t.Execute(w, nil) }'));
  assert.ok(clean('e.go', 'package main\nimport "text/template"\nfunc r(w io.Writer){ t,_ := template.New("x").Parse("hello {{.Name}}"); t.Execute(w, nil) }'));
  assert.ok(clean('e.go', 'package main\nfunc add(a,b int) int { return a+b }'));
});

test('Kotlin — ScriptEngine.eval / Groovy on non-literal fire', () => {
  assert.ok(fires('E.kt', 'import javax.script.ScriptEngineManager\nclass E { fun r(c: String): Any? { return ScriptEngineManager().getEngineByName("js").eval(c) } }'));
  assert.ok(fires('E.kt', 'import groovy.lang.GroovyShell\nclass E { fun r(c: String): Any? { return GroovyShell().evaluate(c) } }'));
});

test('non-target languages produce nothing', () => {
  assert.deepEqual(s('e.js', 'eval(userInput)'), []);
  assert.deepEqual(s('e.py', 'eval(user_input)'), []);
});
