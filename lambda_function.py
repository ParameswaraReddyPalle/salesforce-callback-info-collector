import json, os, time, urllib.parse, urllib.request, ssl
import boto3

secrets = boto3.client("secretsmanager")
_token = {"access_token": None, "instance_url": None, "expires_at": 0}

def _get_secret():
    name = os.environ["SF_SECRET_NAME"]
    resp = secrets.get_secret_value(SecretId=name)
    return json.loads(resp["SecretString"])

def _post_form(url, data_dict):
    data = urllib.parse.urlencode(data_dict).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=8) as r:
        return r.read().decode("utf-8"), r.getcode()

def _post_json(url, body, token):
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=8) as r:
            return r.read().decode("utf-8"), r.getcode()
    except urllib.error.HTTPError as e:
        return (e.read().decode("utf-8") if e.fp else ""), e.code

def _get_token(cfg):
    now = int(time.time() * 1000)
    if _token["access_token"] and (_token["expires_at"] - now) > 60000:
        return _token["access_token"], _token["instance_url"]

    body, code = _post_form(cfg["SF_TOKEN_URL"], {
        "grant_type": "client_credentials",
        "client_id": cfg["SF_CLIENT_ID"],
        "client_secret": cfg["SF_CLIENT_SECRET"]
    })
    if code < 200 or code >= 300:
        raise Exception(f"OAuth failed {code}: {body}")

    js = json.loads(body)
    issued_ms = int(js.get("issued_at") or (time.time() * 1000))
    expires_ms = int(js.get("expires_in") or 900) * 1000

    _token["access_token"] = js["access_token"]
    _token["instance_url"] = cfg.get("SF_APEX_BASE") or js["instance_url"]
    _token["expires_at"] = issued_ms + expires_ms

    return _token["access_token"], _token["instance_url"]

def lambda_handler(event, context):
    # Accept Connect event OR direct dict
    details = (event or {}).get("Details") or {}
    params  = details.get("Parameters") or (event or {})

    # If Connect didn't pass these, try to derive from ContactData
    contact = details.get("ContactData") or {}
    phone = ((contact.get("CustomerEndpoint") or {}).get("Address"))
    aws_key = contact.get("ContactId")

    payload = {
        "aws_key": params.get("aws_key") or aws_key,
        "phoneNumber": params.get("phoneNumber") or phone,
        "tenantCode": params.get("tenantCode")
    }

    for k in ("aws_key", "phoneNumber", "tenantCode"):
        if not payload.get(k):
            return {"status": "ERROR", "error": f"Missing {k}", "transferToAgent": False}

    cfg = _get_secret()
    token, base = _get_token(cfg)

    body, code = _post_json(f"{base}/services/apexrest/ivr/addtoCallBack", payload, token)

    # return SF response as-is (plus HTTP code if you want)
    try:
        out = json.loads(body) if body else {}
    except Exception:
        out = {"raw": body}

    out["httpStatus"] = code
    return out
