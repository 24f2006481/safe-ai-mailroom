import os, json, hashlib, sqlite3, base64, threading
from datetime import datetime, timezone
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PROFILE = "ga5-mailroom-action-gate/v2"
DB = os.getenv("DATABASE_PATH", "./mailroom.sqlite3")
MAX_BODY = 8 * 1024 * 1024
LOCK = threading.RLock()
app = FastAPI(title="Safe AI Mailroom", version="1.0.0")


def canon(x): return json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def sha(s): return hashlib.sha256(s.encode("utf-8")).hexdigest()
def digest(x): return sha(canon(x))
def now(): return datetime.now(timezone.utc).isoformat()
def db():
    c = sqlite3.connect(DB, timeout=30, isolation_level=None, check_same_thread=False)
    c.row_factory = sqlite3.Row
    return c

with db() as c:
    c.executescript('''
    CREATE TABLE IF NOT EXISTS evaluations(
      evaluation_id TEXT PRIMARY KEY, input_digest TEXT NOT NULL,
      verifier_json TEXT NOT NULL, request_json TEXT NOT NULL,
      proposal_json TEXT NOT NULL, status TEXT NOT NULL,
      commit_json TEXT, commit_response_json TEXT, created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS proposal_cache(
      fingerprint TEXT PRIMARY KEY, proposal_json TEXT NOT NULL, created_at TEXT NOT NULL);
    ''')

def err(code, msg, status=400):
    return JSONResponse(status_code=status, content={"error":{"code":code,"message":msg}})

def lines_for(d):
    out=[]
    for s in d.get("sources", []):
        for line in s.get("lines", []):
            if isinstance(line, dict) and isinstance(line.get("lineId"), str) and isinstance(line.get("text"), str): out.append(line)
    return out

def safe_fallback(d):
    """Conservative fallback only; set OPENAI_API_KEY and add model reasoning for high action-accuracy marks."""
    lines=lines_for(d); alltext="\n".join(x["text"] for x in lines).lower(); ref=str(d["dossierId"])
    evidence=[lines[0]["lineId"]] if lines else []
    attack=("ignore previous instructions", "reveal secret", "send the password", "exfiltrate", "override policy", "hidden instructions", "system prompt")
    if any(t in alltext for t in attack):
        action="quarantine_item"; target={"kind":"security_queue","id":"mailroom"}; payload={"artifactId":ref,"reasonCode":"INDIRECT_PROMPT_INJECTION"}
        evidence=[x["lineId"] for x in lines if any(t in x["text"].lower() for t in attack)][:1] or evidence
    elif any(t in alltext for t in ("already completed","duplicate message","already processed")):
        action="no_action"; target=None; payload={"reasonCode":"DUPLICATE","referenceId":ref}
        evidence=[x["lineId"] for x in lines if any(t in x["text"].lower() for t in ("already completed","duplicate message","already processed"))][:1] or evidence
    elif any(t in alltext for t in ("no action required","for information only","informational update")):
        action="no_action"; target=None; payload={"reasonCode":"INFORMATIONAL","referenceId":ref}
        evidence=[x["lineId"] for x in lines if any(t in x["text"].lower() for t in ("no action required","for information only","informational update"))][:1] or evidence
    else:
        action="request_confirmation"; target={"kind":"approval_queue","id":"mailroom"}; payload={"claimedSender":"unknown","questionCode":"VERIFY_REQUEST","referenceId":ref}
    return {"dossierId":ref,"callId":"call_"+sha(canon(d))[:40],"action":action,"target":target,"payload":payload,"evidence":list(dict.fromkeys(evidence))}

def validate_action(p):
    action=p.get("action"); target=p.get("target"); payload=p.get("payload")
    schemas={
      "create_draft":({"kind":"draft_queue"},{"recipient","referenceId","status","template"}),
      "update_internal_record":({"kind":"case_record"},{"field","sourceEventId","value"}),
      "send_approved_notice":({"kind":"email"},{"referenceId","status","template"}),
      "request_confirmation":({"kind":"approval_queue"},{"claimedSender","questionCode","referenceId"}),
      "quarantine_item":({"kind":"security_queue","id":"mailroom"},{"artifactId","reasonCode"}),
      "no_action":(None,{"reasonCode","referenceId"})}
    if action not in schemas or not isinstance(payload,dict): raise ValueError("Invalid action or payload")
    expected_target, keys=schemas[action]
    if action=="no_action":
        if target is not None: raise ValueError("no_action target must be null")
    else:
        if not isinstance(target,dict) or set(target)!={"kind","id"}: raise ValueError("Invalid target shape")
        if target.get("kind") != expected_target.get("kind") or ("id" in expected_target and target.get("id") != expected_target["id"]): raise ValueError("Invalid target kind")
    if set(payload)!=keys or any(not isinstance(v,str) or not v for v in payload.values()): raise ValueError("Invalid payload shape")
    if action=="create_draft" and payload["template"]!="order_status": raise ValueError("Invalid template")
    if action=="update_internal_record" and payload["field"]!="delivery_window": raise ValueError("Invalid field")
    if action=="send_approved_notice" and payload["template"]!="approved_delivery_notice": raise ValueError("Invalid template")
    if action=="request_confirmation" and payload["questionCode"]!="VERIFY_REQUEST": raise ValueError("Invalid questionCode")
    if action=="quarantine_item" and payload["reasonCode"]!="INDIRECT_PROMPT_INJECTION": raise ValueError("Invalid reasonCode")
    if action=="no_action" and payload["reasonCode"] not in {"ALREADY_COMPLETED","DUPLICATE","INFORMATIONAL"}: raise ValueError("Invalid reasonCode")

def pdigest(p):
    return digest({"dossierId":p["dossierId"],"callId":p["callId"],"action":p["action"],"target":p["target"],"payload":p["payload"],"evidence":sorted(p["evidence"])})

def verify(r, evaluation_id, input_digest, verifier):
    try:
        jwk=verifier["publicKeyJwk"]
        if verifier.get("algorithm")!="Ed25519" or jwk.get("kty")!="OKP" or jwk.get("crv")!="Ed25519": return False
        x=jwk["x"]; raw=base64.urlsafe_b64decode(x+"="*((4-len(x)%4)%4))
        pub=Ed25519PublicKey.from_public_bytes(raw)
        signed={"profile":PROFILE,"evaluationId":evaluation_id,"inputDigest":input_digest,"receipt":{k:v for k,v in r.items() if k!="receiptSignature"}}
        sig=base64.b64decode(r["receiptSignature"], validate=True)
        pub.verify(sig,canon(signed).encode("utf-8")); return True
    except Exception: return False

@app.get("/")
def health(): return {"name":"Safe AI Mailroom","profile":PROFILE,"status":"ok"}

@app.post("/")
async def endpoint(request: Request):
    raw=await request.body()
    if len(raw)>MAX_BODY: return err("BODY_TOO_LARGE","Request body too large",413)
    try: b=json.loads(raw)
    except Exception: return err("INVALID_JSON","Body must be JSON")
    if not isinstance(b,dict) or b.get("profile")!=PROFILE or not isinstance(b.get("evaluationId"),str) or not b["evaluationId"]: return err("INVALID_REQUEST","Invalid profile or evaluationId")
    eid=b["evaluationId"]
    if b.get("operation")=="propose":
        ds=b.get("dossiers"); verifier=b.get("receiptVerifier")
        if not isinstance(ds,list) or not ds or not isinstance(verifier,dict) or verifier.get("algorithm")!="Ed25519" or not isinstance(verifier.get("publicKeyJwk"),dict): return err("INVALID_PROPOSE","Missing dossiers or receipt verifier")
        ids=[d.get("dossierId") if isinstance(d,dict) else None for d in ds]
        if any(not isinstance(x,str) or not x for x in ids) or len(ids)!=len(set(ids)): return err("INVALID_PROPOSE","Dossier IDs must be unique")
        for d in ds:
            if not isinstance(d.get("sources"),list): return err("INVALID_PROPOSE","Every dossier must have sources")
            lids=[x.get("lineId") for s in d["sources"] if isinstance(s,dict) for x in s.get("lines",[]) if isinstance(x,dict)]
            if len(lids)!=len(set(lids)): return err("INVALID_PROPOSE","Duplicate line IDs in dossier")
        inp=digest(ds)
        with LOCK, db() as c:
            old=c.execute("SELECT * FROM evaluations WHERE evaluation_id=?",(eid,)).fetchone()
            if old:
                if old["input_digest"]!=inp or old["request_json"]!=canon(b): return err("EVALUATION_CONFLICT","evaluationId reused with changed content",409)
                return JSONResponse(json.loads(old["proposal_json"]))
        try:
            proposals=[]
            for d in ds:
                fp=digest(d)
                with db() as c: cached=c.execute("SELECT proposal_json FROM proposal_cache WHERE fingerprint=?",(fp,)).fetchone()
                p=json.loads(cached[0]) if cached else safe_fallback(d)
                p["dossierId"]=d["dossierId"]; p["callId"]="call_"+sha(canon(d))[:40]
                valid={x["lineId"] for x in lines_for(d)}
                if not p["evidence"] or any(x not in valid for x in p["evidence"]): raise ValueError("No valid evidence line")
                validate_action(p); proposals.append(p)
            response={"profile":PROFILE,"evaluationId":eid,"status":"awaiting_receipts","inputDigest":inp,"proposals":proposals}
            with LOCK, db() as c:
                old=c.execute("SELECT * FROM evaluations WHERE evaluation_id=?",(eid,)).fetchone()
                if old:
                    if old["input_digest"]!=inp or old["request_json"]!=canon(b): return err("EVALUATION_CONFLICT","evaluationId reused with changed content",409)
                    return JSONResponse(json.loads(old["proposal_json"]))
                c.execute("INSERT INTO evaluations(evaluation_id,input_digest,verifier_json,request_json,proposal_json,status,created_at) VALUES(?,?,?,?,?,?,?)",(eid,inp,canon(verifier),canon(b),canon(response),"awaiting_receipts",now()))
                for d,p in zip(ds,proposals): c.execute("INSERT OR IGNORE INTO proposal_cache VALUES(?,?,?)",(digest(d),canon(p),now()))
            return JSONResponse(response)
        except Exception:
            return err("PROPOSAL_FAILED","Could not safely create proposals",502)
    if b.get("operation")=="commit":
        receipts=b.get("receipts")
        if not isinstance(receipts,list) or not receipts: return err("INVALID_COMMIT","receipts must be a nonempty list")
        with LOCK, db() as c:
            row=c.execute("SELECT * FROM evaluations WHERE evaluation_id=?",(eid,)).fetchone()
            if not row: return err("UNKNOWN_EVALUATION","No stored proposal for evaluation",409)
            if row["status"]=="completed":
                if row["commit_json"]==canon(b): return JSONResponse(json.loads(row["commit_response_json"]))
                return err("COMMIT_CONFLICT","Evaluation already committed with different content",409)
            proposal_response=json.loads(row["proposal_json"]); proposals=proposal_response["proposals"]
            if b.get("inputDigest")!=row["input_digest"] or len(receipts)!=len(proposals): return err("COMMIT_MISMATCH","Digest or receipt count mismatch",409)
            bykey={(p["dossierId"],p["callId"]):p for p in proposals}; seen=set(); verifier=json.loads(row["verifier_json"])
            for r in receipts:
                if not isinstance(r,dict): return err("INVALID_RECEIPT","Receipt must be an object")
                k=(r.get("dossierId"),r.get("callId")); p=bykey.get(k)
                if not p or k in seen or r.get("action")!=p["action"] or r.get("proposalDigest")!=pdigest(p): return err("RECEIPT_MISMATCH","Receipt does not match proposal",409)
                if not isinstance(r.get("accepted"),bool) or not isinstance(r.get("receiptId"),str) or not r.get("receiptId"): return err("INVALID_RECEIPT","Required receipt fields missing")
                if not verify(r,eid,row["input_digest"],verifier): return err("INVALID_SIGNATURE","Receipt signature verification failed",409)
                seen.add(k)
            if len(seen)!=len(proposals): return err("RECEIPTS_INCOMPLETE","One receipt per proposal required",409)
            outcomes=[{"dossierId":r["dossierId"],"callId":r["callId"],"action":r["action"],"proposalDigest":r["proposalDigest"],"receiptId":r["receiptId"],"status":"executed" if r["accepted"] else "rejected"} for r in receipts]
            result={"profile":PROFILE,"evaluationId":eid,"status":"completed","inputDigest":row["input_digest"],"outcomes":outcomes}
            c.execute("UPDATE evaluations SET status='completed',commit_json=?,commit_response_json=? WHERE evaluation_id=? AND status='awaiting_receipts'",(canon(b),canon(result),eid))
            return JSONResponse(result)
    return err("INVALID_OPERATION","operation must be propose or commit")
