export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/api/status") {
      return Response.json({
        name: "AI Security Trainer",
        status: "online",
        mode: "basic-static-analysis",
        note: "This starter does not train model weights. It checks source code for a few common risky patterns."
      }, { headers: securityHeaders() });
    }

    if (url.pathname === "/api/analyze" && request.method === "POST") {
      let body;
      try {
        body = await request.json();
      } catch {
        return Response.json({ error: "Request body must be valid JSON." }, {
          status: 400, headers: securityHeaders()
        });
      }

      const code = typeof body.code === "string" ? body.code.slice(0, 12000) : "";
      if (!code.trim()) {
        return Response.json({ error: "Enter source code to analyze." }, {
          status: 400, headers: securityHeaders()
        });
      }

      const checks = [
        {
          name: "Possible dynamic code execution",
          severity: "High",
          pattern: /\beval\s*\(|new\s+Function\s*\(/,
          recommendation: "Avoid evaluating untrusted strings as code."
        },
        {
          name: "Possible unsafe HTML insertion",
          severity: "Medium",
          pattern: /\.innerHTML\s*=/,
          recommendation: "Prefer textContent, or sanitize HTML with a trusted library."
        },
        {
          name: "Possible hardcoded credential",
          severity: "High",
          pattern: /(api[_-]?key|password|secret)\s*[:=]\s*["'][^"']{6,}["']/i,
          recommendation: "Move secrets to protected environment variables and rotate exposed credentials."
        },
        {
          name: "Possible SQL string concatenation",
          severity: "Medium",
          pattern: /(?:SELECT|INSERT|UPDATE|DELETE)[\s\S]{0,180}\+/i,
          recommendation: "Use parameterized database queries."
        }
      ];

      const findings = checks.filter(check => check.pattern.test(code)).map(check => ({
        name: check.name,
        severity: check.severity,
        recommendation: check.recommendation
      }));

      return Response.json({
        findings,
        count: findings.length,
        message: findings.length
          ? "Potential issues found. Review each finding manually."
          : "No matches from these basic checks. This does not prove the code is secure.",
        engine: "Basic pattern checks; not an AI model or full security audit."
      }, { headers: securityHeaders() });
    }

    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed", {
        status: 405, headers: securityHeaders()
      });
    }

    return new Response(PAGE, {
      headers: {
        ...securityHeaders(),
        "content-type": "text/html; charset=UTF-8",
        "cache-control": "no-store"
      }
    });
  }
};

function securityHeaders() {
  return {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"
  };
}

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#101827">
<title>AI Security Trainer</title>
<style>
:root{color-scheme:dark;--bg:#0b1120;--panel:#141e30;--line:#2a3950;--text:#edf4ff;--muted:#9aabc2;--accent:#69e5b1}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px system-ui,-apple-system,sans-serif}
header{padding:24px 18px;background:#101827;border-bottom:1px solid var(--line)}h1{font-size:25px;margin:0 0 8px}h2{font-size:18px;margin:0 0 8px}
p{line-height:1.5}.sub,.note{color:var(--muted)}.sub{margin:0}main{max-width:850px;margin:auto;padding:18px;display:grid;gap:16px}
section{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:17px}
label{display:block;margin:13px 0 7px;font-weight:600}input,textarea{width:100%;padding:12px;border-radius:9px;border:1px solid var(--line);background:#0b1120;color:var(--text);font:inherit}
textarea{min-height:140px;resize:vertical}button{padding:12px 16px;border:0;border-radius:9px;background:var(--accent);color:#092017;font-weight:750;font-size:14px;margin-top:12px;cursor:pointer}
button:disabled{opacity:.5}.note{font-size:13px}.result{white-space:pre-wrap;overflow-wrap:anywhere;background:#0b1120;border-radius:9px;padding:12px;margin-top:12px}
.status{color:var(--accent)}.item{border-bottom:1px solid var(--line);padding:12px 0}.item:last-child{border:0}.pill{display:inline-block;border:1px solid var(--line);border-radius:99px;padding:4px 9px;color:var(--muted);font-size:12px}
</style>
</head>
<body>
<header>
<h1>AI Security Trainer</h1>
<p class="sub">Import model files · inspect training data · evaluate code security</p>
<p class="status" id="status">Checking platform…</p>
</header>
<main>
<section>
<h2>01 / Import a model</h2>
<p class="note">Select a model file or adapter to inspect its name and size. This starter does not upload, load, or train the model.</p>
<label for="model">Model file</label>
<input id="model" type="file" accept=".gguf,.safetensors,.onnx,.bin,.pt,.pth,.json">
<div id="modelInfo" class="result">No file selected.</div>
</section>
<section>
<h2>02 / Training dataset</h2>
<p class="note">Choose a JSONL file to check its format. Each non-empty line should be a valid JSON object. This checks data formatting only; it does not train the model.</p>
<label for="dataset">Dataset file</label>
<input id="dataset" type="file" accept=".jsonl,.json,.csv,.txt">
<button id="inspect">Inspect dataset</button>
<div id="datasetInfo" class="result">No dataset inspected.</div>
</section>
<section>
<h2>03 / Security code analysis</h2>
<p class="note">Run basic static checks against code you own or are authorized to assess.</p>
<label for="code">Source code</label>
<textarea id="code" placeholder="Paste JavaScript or other source code here…"></textarea>
<button id="analyze">Analyze code</button>
<div id="analysis" class="result">Analysis results will appear here.</div>
</section>
<section>
<h2>04 / Training roadmap</h2>
<div class="item"><b>Stage 1 — Prepare examples</b><p class="note">Collect labeled examples of vulnerable and secure code.</p></div>
<div class="item"><b>Stage 2 — Evaluate a base model</b><p class="note">Use a fixed benchmark and record accuracy before training.</p></div>
<div class="item"><b>Stage 3 — Fine-tune a compatible model</b><p class="note">Requires a supported training runtime; this Worker does not perform weight training.</p></div>
<div class="item"><b>Stage 4 — Compare and export</b><p class="note">Compare results after training and export compatible artifacts where supported.</p></div>
</section>
<p class="note">Prototype notice: the checks are intentionally basic and can miss vulnerabilities or produce false positives. Do not treat results as proof that software is secure.</p>
</main>
<script>
const $=id=>document.getElementById(id);
fetch("/api/status").then(r=>r.json()).then(s=>{$("status").textContent="● "+s.status+" — "+s.mode;}).catch(()=>{$("status").textContent="Platform status unavailable";});
$("model").addEventListener("change",()=>{
 const f=$("model").files[0];
 $("modelInfo").textContent=f?"Name: "+f.name+"\\nSize: "+(f.size/1048576).toFixed(2)+" MB\\nSelected on this device only; no upload or training occurred.":"No file selected.";
});
$("inspect").addEventListener("click",async()=>{
 const f=$("dataset").files[0];
 if(!f){$("datasetInfo").textContent="Choose a dataset file first.";return;}
 if(f.size>2*1024*1024){$("datasetInfo").textContent="For this preview, choose a file smaller than 2 MB.";return;}
 const content=await f.text(); const lines=content.split(/\\r?\\n/).filter(x=>x.trim()); let valid=0;const errors=[];
 for(let i=0;i<lines.length;i++){try{JSON.parse(lines[i]);valid++;}catch(e){if(errors.length<3)errors.push("Line "+(i+1)+": invalid JSON");}}
 $("datasetInfo").textContent="File: "+f.name+"\\nNon-empty lines: "+lines.length+"\\nValid JSON lines: "+valid+"\\n"+(errors.join("\\n")||"No JSONL syntax errors found.")+"\\n\\nThis is a format check, not model training. CSV/plain text need their own parser.";
});
$("analyze").addEventListener("click",async()=>{
 $("analyze").disabled=true;$("analysis").textContent="Analyzing…";
 try{const r=await fetch("/api/analyze",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({code:$("code").value})});const data=await r.json();$("analysis").textContent=JSON.stringify(data,null,2);}
 catch(e){$("analysis").textContent="Request failed: "+e.message;}
 finally{$("analyze").disabled=false;}
});
</script>
</body>
</html>`;
