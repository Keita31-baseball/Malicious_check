import csv
import time
import requests
from pymongo import MongoClient

# ==========================
# 設定
# ==========================

MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "DB_NAME"
COLLECTION_NAME = "CO_NAME"

VT_API_KEY = "MY_VT_KEY"
URLSCAN_API_KEY = "MY_URLCAN_KEY"

OUTPUT_CSV = "mongo_domain_recheck_results.csv"

LIMIT = 0

# MongoDB内のドメイン欄
DOMAIN_FIELD = "domain"

# API
VT_URL = "https://www.virustotal.com/api/v3/domains/"
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
URLSCAN_SCAN_URL = "https://urlscan.io/api/v1/scan/"
URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/"

# 待機
VT_SLEEP_SEC = 16
URLSCAN_RESULT_WAIT = 40
REQUEST_TIMEOUT = 30


def normalize_domain(value: str) -> str:
    if not value:
        return ""
    s = str(value).strip().lower()
    s = s.replace("http://", "").replace("https://", "").strip("/")
    return s


def check_vt(domain: str):
    headers = {"x-apikey": VT_API_KEY}

    try:
        r = requests.get(VT_URL + domain, headers=headers, timeout=REQUEST_TIMEOUT)
        print(f"[VT] {domain} status={r.status_code}")

        if r.status_code != 200:
            print(f"[VT FAIL] {domain}: {r.text[:300]}")
            return 0, 0, "unknown"

        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))

        if malicious > 0:
            label = "malicious"
        elif suspicious > 0:
            label = "suspicious"
        else:
            label = "clean"

        return malicious, suspicious, label

    except Exception as e:
        print(f"[VT ERROR] {domain}: {e}")
        return 0, 0, "unknown"


def urlscan_search(domain: str):
    headers = {"API-Key": URLSCAN_API_KEY}
    params = {
        "q": f"domain:{domain}",
        "size": 1
    }

    try:
        r = requests.get(URLSCAN_SEARCH_URL, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        print(f"[URLSCAN SEARCH] {domain} status={r.status_code}")

        if r.status_code != 200:
            print(f"[URLSCAN SEARCH FAIL] {domain}: {r.text[:300]}")
            return None

        data = r.json()
        results = data.get("results", [])

        if not results:
            print(f"[URLSCAN SEARCH] no results for {domain}")
            return None

        res = results[0]
        overall = res.get("verdicts", {}).get("overall", {})

        score = int(overall.get("score", 0))
        malicious = bool(overall.get("malicious", False))

        if malicious:
            label = "malicious"
        elif score > 10:
            label = "suspicious"
        else:
            label = "clean"

        return score, malicious, label

    except Exception as e:
        print(f"[URLSCAN SEARCH ERROR] {domain}: {e}")
        return None


def urlscan_scan(domain: str):
    headers = {
        "API-Key": URLSCAN_API_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "url": "https://" + domain,
        "visibility": "unlisted"
    }

    try:
        r = requests.post(URLSCAN_SCAN_URL, headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        print(f"[URLSCAN SUBMIT] {domain} status={r.status_code}")

        if r.status_code not in (200, 201):
            print(f"[URLSCAN SUBMIT FAIL] {domain}: {r.text[:300]}")
            return 0, False, "unknown"

        data = r.json()
        scan_id = data.get("uuid")

        if not scan_id:
            print(f"[URLSCAN SUBMIT FAIL] {domain}: uuid not found")
            return 0, False, "unknown"

        print(f"[URLSCAN SUBMITTED] {domain} scan_id={scan_id}")
        time.sleep(URLSCAN_RESULT_WAIT)

        result = requests.get(
            URLSCAN_RESULT_URL + scan_id + "/",
            headers={"API-Key": URLSCAN_API_KEY},
            timeout=REQUEST_TIMEOUT
        )
        print(f"[URLSCAN RESULT] {domain} status={result.status_code}")

        if result.status_code != 200:
            print(f"[URLSCAN RESULT FAIL] {domain}: {result.text[:300]}")
            return 0, False, "unknown"

        result_json = result.json()
        overall = result_json.get("verdicts", {}).get("overall", {})

        score = int(overall.get("score", 0))
        malicious = bool(overall.get("malicious", False))

        if malicious:
            label = "malicious"
        elif score > 10:
            label = "suspicious"
        else:
            label = "clean"

        return score, malicious, label

    except Exception as e:
        print(f"[URLSCAN SCAN ERROR] {domain}: {e}")
        return 0, False, "unknown"


def load_domains_from_mongo():
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    col = db[COLLECTION_NAME]

    query = {
        DOMAIN_FIELD: {"$exists": True, "$ne": None}
    }

    projection = {
        "_id": 1,
        DOMAIN_FIELD: 1,
        "label": 1,
        "issuer": 1,
        "not_before": 1,
        "not_after": 1,
        "f1_levenshtein": 1,
        "f2_deep_subdomain": 1,
        "f3_free_ca": 1,
        "f4_suspicious_tld": 1,
        "f5_inner_tld": 1,
        "f6_keyword": 1,
        "f7_entropy_value": 1,
        "f7_high_entropy": 1,
        "f8_hyphen_first_label": 1,
    }

    cursor = col.find(query, projection)

    if LIMIT > 0:
        cursor = cursor.limit(LIMIT)

    docs = list(cursor)
    print(f"[*] Loaded {len(docs)} documents from MongoDB")
    return docs


def main():
    docs = load_domains_from_mongo()

    if not docs:
        print("[!] MongoDBから1件も読めていません")
        return

    results = []

    for i, doc in enumerate(docs, 1):
        raw_domain = doc.get(DOMAIN_FIELD, "")
        domain = normalize_domain(raw_domain)

        print(f"\n===== [{i}/{len(docs)}] {domain} =====")

        if not domain:
            print("[!] domain が空なのでスキップ")
            continue

        vt_mal, vt_susp, vt_label = check_vt(domain)

        us = urlscan_search(domain)
        if us:
            us_score, us_mal, us_label = us
        else:
            print(f"[URLSCAN] no search result -> scan {domain}")
            us_score, us_mal, us_label = urlscan_scan(domain)

        results.append({
            "_id": str(doc.get("_id")),
            "domain": domain,
            "issuer": doc.get("issuer"),
            "not_before": doc.get("not_before"),
            "not_after": doc.get("not_after"),
            "original_label": doc.get("label"),
            "f1_levenshtein": doc.get("f1_levenshtein"),
            "f2_deep_subdomain": doc.get("f2_deep_subdomain"),
            "f3_free_ca": doc.get("f3_free_ca"),
            "f4_suspicious_tld": doc.get("f4_suspicious_tld"),
            "f5_inner_tld": doc.get("f5_inner_tld"),
            "f6_keyword": doc.get("f6_keyword"),
            "f7_entropy_value": doc.get("f7_entropy_value"),
            "f7_high_entropy": doc.get("f7_high_entropy"),
            "f8_hyphen_first_label": doc.get("f8_hyphen_first_label"),
            "VT_malicious": vt_mal,
            "VT_suspicious": vt_susp,
            "VT_label": vt_label,
            "urlscan_score": us_score,
            "urlscan_malicious": us_mal,
            "urlscan_label": us_label,
        })

        time.sleep(VT_SLEEP_SEC)

    fieldnames = [
        "_id",
        "domain",
        "issuer",
        "not_before",
        "not_after",
        "original_label",
        "f1_levenshtein",
        "f2_deep_subdomain",
        "f3_free_ca",
        "f4_suspicious_tld",
        "f5_inner_tld",
        "f6_keyword",
        "f7_entropy_value",
        "f7_high_entropy",
        "f8_hyphen_first_label",
        "VT_malicious",
        "VT_suspicious",
        "VT_label",
        "urlscan_score",
        "urlscan_malicious",
        "urlscan_label",
    ]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"\n✅ saved: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()