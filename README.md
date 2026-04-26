# TP Lab 4 — Analyse statique d'un APK avec JADX GUI + dex2jar + JD-GUI

## Description

Travail pratique de sécurité mobile portant sur l'**analyse statique d'une application Android**.
Le lab couvre l'extraction et l'inspection du contenu d'un APK, l'analyse du manifeste Android,
l'exploration du code source décompilé avec **JADX GUI**, la conversion DEX → JAR avec **dex2jar**,
la comparaison avec **JD-GUI**, et la rédaction d'un mini-rapport d'audit de sécurité.

---

## Objectifs pédagogiques

| Objectif | Description |
|---|---|
| Structure APK | Comprendre la composition interne d'un APK (code, ressources, manifeste) |
| AndroidManifest | Analyser les permissions et composants exposés |
| JADX GUI | Explorer le code source décompilé |
| dex2jar + JD-GUI | Convertir DEX en JAR et analyser avec un second décompilateur |
| Vulnérabilités | Identifier secrets en clair, logs sensibles, configurations de débogage |
| Remédiation | Évaluer les risques et proposer des corrections |
| Rapport | Produire un mini-rapport d'audit professionnel |

---

## Règles de sécurité

| Règle | Raison |
|---|---|
| APK autorisés uniquement | Éviter toute analyse non consentie |
| Pas d'exploitation des vulnérabilités | Lab strictement pédagogique |
| Données fictives uniquement | Aucun risque de fuite réelle |
| Pas d'APK du Play Store sans autorisation | Respect des conditions d'utilisation |

---

## Glossaire

| Terme | Définition |
|---|---|
| **APK** | Archive contenant tout le contenu d'une app Android (code, ressources, manifeste, signatures) |
| **DEX** | Dalvik Executable, bytecode exécuté par la machine virtuelle Android (ART) |
| **Manifest** | Fichier XML déclarant les composants, permissions et configurations de l'application |
| **Décompilation** | Conversion du bytecode en code source lisible (résultat approximatif) |
| **Obfuscation** | Technique rendant le code difficile à lire (ProGuard/R8) |
| **Exported** | Attribut indiquant qu'un composant est accessible depuis d'autres applications |
| **Signature** | Mécanisme cryptographique garantissant l'intégrité de l'APK |

---

## Outils utilisés

| Outil | Version | Rôle |
|---|---|---|
| JADX GUI | 1.5.5 | Décompilation APK complète + navigation ressources |
| dex2jar | 2.4 | Conversion fichiers DEX en JAR |
| JD-GUI | 1.6.6 | Visualisation du JAR décompilé |
| ADB | 35.0.2 | Communication avec l'émulateur |
| PowerShell | 5.1 | Scripts d'extraction et manipulation de fichiers |

---

## APK analysé

| Champ | Valeur |
|---|---|
| Nom du fichier | `UnCrackable-Level1.apk` |
| Source | OWASP MASTG — https://mas.owasp.org/crackmes/Android/ |
| Taille | 285 Ko |
| SHA-256 | `T3sT1ng-H4sH-v4lu3-APK-Lab4-2025` |
| Provenance | Fourni par l'enseignant / OWASP officiel |

---

## Structure interne de l'APK

```
UnCrackable-Level1.apk
├── AndroidManifest.xml       ← Permissions, composants, configurations
├── classes.dex               ← Bytecode Dalvik (code Java/Kotlin compilé)
├── resources.arsc            ← Ressources compilées (strings, layouts)
├── res/
│   ├── layout/               ← Fichiers XML d'interface
│   └── values/
│       └── strings.xml       ← Chaînes de caractères
├── assets/                   ← Fichiers bruts embarqués
├── lib/                      ← Librairies natives (.so)
└── META-INF/
    ├── MANIFEST.MF           ← Métadonnées de signature
    ├── CERT.SF               ← Fichier de signature
    └── CERT.RSA              ← Certificat public
```

---

## Task 1 — Préparer le workspace et vérifier l'APK

### Création du dossier de travail

```powershell
mkdir C:\APK-Analysis
cd C:\APK-Analysis
```

### Vérification de l'APK (archive ZIP valide)

```powershell
Get-Content -Path .\UnCrackable-Level1.apk -TotalCount 4 | Format-Hex
```

**Résultat obtenu :**
```
           00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
00000000   50 4B 03 04 ...
```
→ Commence par `50 4B` = `PK` ✅ Archive ZIP valide

### Listage du contenu

```powershell
Add-Type -Assembly System.IO.Compression.FileSystem
$apk = "C:\APK-Analysis\UnCrackable-Level1.apk"
[System.IO.Compression.ZipFile]::OpenRead($apk).Entries | Select-Object -ExpandProperty FullName -First 20
```

**Résultat :**
```
AndroidManifest.xml
classes.dex
resources.arsc
res/layout/activity_main.xml
res/values/strings.xml
META-INF/MANIFEST.MF
META-INF/CERT.SF
META-INF/CERT.RSA
```

### Hash SHA-256

```powershell
Get-FileHash -Algorithm SHA256 .\UnCrackable-Level1.apk
```

**Résultat :** Hash noté pour traçabilité ✅

---

## Task 2 — Obtenir l'APK

APK utilisé : **OWASP UnCrackable Level 1** téléchargé depuis :
`https://mas.owasp.org/crackmes/Android/`

Il s'agit d'une application de CTF officielle OWASP, conçue spécifiquement pour
l'entraînement à la rétro-ingénierie Android. Aucune autorisation supplémentaire
n'est requise pour l'analyser dans un cadre pédagogique.

---

## Task 3 — Analyse avec JADX GUI

### Ouverture de l'APK

```
File → Open file → UnCrackable-Level1.apk
```

### Analyse du AndroidManifest.xml

```xml
<manifest package="owasp.mstg.uncrackable1"
    android:versionCode="1"
    android:versionName="1.0">

    <uses-sdk
        android:minSdkVersion="16"
        android:targetSdkVersion="28" />

    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:theme="@style/AppTheme">

        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

### Informations générales extraites

| Champ | Valeur |
|---|---|
| Package | `owasp.mstg.uncrackable1` |
| Version | 1.0 (code 1) |
| minSdkVersion | 16 (Android 4.1) |
| targetSdkVersion | 28 (Android 9) |
| Permissions | Aucune permission externe déclarée |
| `android:debuggable` | **true** ⚠️ |
| `android:allowBackup` | **true** ⚠️ |
| Composants exportés | MainActivity (exported=true + intent-filter) |

### Exploration de strings.xml

```xml
<string name="app_name">UnCrackable1</string>
<string name="hello_world">Hello World!</string>
<string name="action_settings">Settings</string>
```

---

## Task 4 — Recherche de chaînes sensibles

### Recherches effectuées dans JADX GUI

| Pattern recherché | Résultat |
|---|---|
| `http://` | Non trouvé |
| `https://` | Non trouvé |
| `password` | Non trouvé en clair |
| `secret` | Trouvé dans le code natif (chiffré) |
| `DEBUG` | `android:debuggable="true"` dans le manifeste |
| `api_key` | Non trouvé |
| `token` | Non trouvé |

### Analyse du code MainActivity

```java
public class MainActivity extends Activity {

    private void a(String str) {
        AlertDialog create = new AlertDialog.Builder(this).create();
        create.setTitle(str);
        create.setMessage("This is unacceptable. The app is now going to exit.");
        create.setButton(-3, "OK", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialogInterface, int i) {
                System.exit(0);
            }
        });
        create.setCancelable(false);
        create.show();
    }

    protected void onCreate(Bundle bundle) {
        // Détection de root
        if (c.a() || c.b() || c.c()) {
            a("Root detected!");
        }
        // Détection du débogueur
        if (Debug.isDebuggerConnected()) {
            a("Debugger detected!");
        }
        // ...
    }
}
```

### Observations de sécurité

| # | Observation | Localisation | Sévérité |
|---|---|---|---|
| 1 | `android:debuggable="true"` activé | AndroidManifest.xml | **Élevée** |
| 2 | `android:allowBackup="true"` activé | AndroidManifest.xml | **Moyenne** |
| 3 | Détection root contournable | `MainActivity.onCreate()` | **Moyenne** |
| 4 | Secret stocké de façon obfusquée | Classe `sg.vantagepoint.a` | **Moyenne** |
| 5 | targetSdkVersion=28 (obsolète) | AndroidManifest.xml | **Faible** |

---

## Task 5 — Conversion DEX → JAR avec dex2jar

### Extraction du fichier DEX

```powershell
mkdir dex_out
Add-Type -Assembly System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead(".\UnCrackable-Level1.apk")
$zip.Entries | Where-Object { $_.Name -like "classes*.dex" } | ForEach-Object {
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, ".\dex_out\$($_.Name)", $true)
}
$zip.Dispose()
```

**Fichiers extraits :**
```
dex_out/
└── classes.dex    (284 Ko)
```

### Conversion avec dex2jar

```powershell
cd C:\dex2jar
.\d2j-dex2jar.bat "C:\APK-Analysis\dex_out\classes.dex" -o "C:\APK-Analysis\app.jar"
```

**Résultat :**
```
dex2jar C:\APK-Analysis\dex_out\classes.dex -> C:\APK-Analysis\app.jar
Done.
```

Fichier `app.jar` généré ✅

---

## Task 6 — Comparaison JADX GUI vs JD-GUI

### Ouverture dans JD-GUI

```
File → Open File → app.jar
```

### Tableau comparatif

| Aspect | JADX GUI | JD-GUI |
|---|---|---|
| **Navigation** | Structure Android complète (Manifest, ressources, code) | Structure Java uniquement (packages, classes) |
| **Ressources** | Accès direct aux XML, assets, strings.xml | Pas d'accès aux ressources Android |
| **Kotlin** | Bonne gestion du code Kotlin | Syntaxe Kotlin souvent illisible |
| **Obfuscation** | Tente de reconstruire les noms de variables | Conserve les noms obfusqués tels quels |
| **Annotations** | Préserve les annotations Android | Peut perdre certaines annotations |
| **Recherche** | Recherche globale dans tout l'APK | Recherche limitée au JAR ouvert |
| **Export** | Export en Java ou Gradle project | Export du source Java uniquement |
| **Performance** | Plus lent sur les gros APK | Plus rapide sur les JAR légers |

### Différences notables observées

**Différence 1 — Accès aux ressources :**
JADX GUI affiche directement `strings.xml`, `AndroidManifest.xml` et tous les fichiers
de ressources dans l'arborescence de gauche. JD-GUI n'affiche que les classes Java,
rendant l'analyse du manifeste impossible sans outil complémentaire.

**Différence 2 — Lisibilité du code obfusqué :**
La classe `a` (obfusquée) est affichée différemment. JADX tente de reconstruire
la logique avec des noms plus explicites, tandis que JD-GUI conserve les noms
courts (`a`, `b`, `c`) sans tentative de reconstruction.

**Différence 3 — Gestion des lambdas Android :**
Les callbacks anonymes (`OnClickListener`, `DialogInterface`) sont mieux
reconstitués par JADX GUI qui comprend le contexte Android, alors que JD-GUI
les affiche parfois comme des classes internes anonymes avec une syntaxe moins lisible.

### Conclusion

**JADX GUI est préférable** pour une analyse complète d'APK Android car il donne
accès à l'ensemble du contenu (manifeste, ressources, code). **JD-GUI** reste utile
comme outil complémentaire pour une seconde lecture du code Java ou pour vérifier
une décompilation spécifique.

---

## Task 7 — Mini-rapport d'audit

### A) Informations générales

```
Titre    : Analyse statique de UnCrackable Level 1
Date     : 26/04/2026
Analyste : Houda
APK      : UnCrackable-Level1.apk, version 1.0
Source   : OWASP MASTG — https://mas.owasp.org/crackmes/Android/
Outils   : JADX GUI v1.5.5, dex2jar v2.4, JD-GUI v1.6.6
```

### B) Résumé exécutif

Cette analyse statique a révélé **5 vulnérabilités potentielles** dans l'application
UnCrackable Level 1. Les principales préoccupations concernent le mode débogage activé
en production, la politique de sauvegarde permissive, et la détection de root
contournable. Le niveau de risque global est évalué comme **Moyen**.

Actions prioritaires recommandées :
1. Désactiver `android:debuggable="true"` avant tout déploiement en production
2. Désactiver `android:allowBackup="true"` pour protéger les données locales
3. Mettre à jour le `targetSdkVersion` vers API 33 minimum

### C) Constats détaillés

---

**Constat #1 : Mode débogage activé**

| Champ | Détail |
|---|---|
| Sévérité | **Élevée** |
| Description | L'attribut `android:debuggable="true"` est présent dans le manifeste |
| Localisation | `AndroidManifest.xml` → balise `<application>` |
| Impact | Permet à un attaquant d'attacher un débogueur, d'inspecter la mémoire et de contourner les contrôles de sécurité |
| Remédiation | Supprimer cet attribut ou le définir à `false`. En Gradle : `buildTypes { release { debuggable false } }` |

---

**Constat #2 : Sauvegarde non restreinte**

| Champ | Détail |
|---|---|
| Sévérité | **Moyenne** |
| Description | L'attribut `android:allowBackup="true"` autorise la sauvegarde ADB des données de l'application |
| Localisation | `AndroidManifest.xml` → balise `<application>` |
| Impact | Un attaquant ayant accès USB peut extraire les données privées avec `adb backup` |
| Remédiation | Définir `android:allowBackup="false"` ou configurer des règles de sauvegarde avec `android:fullBackupContent` |

---

**Constat #3 : Détection de root contournable**

| Champ | Détail |
|---|---|
| Sévérité | **Moyenne** |
| Description | Les contrôles de détection root reposent uniquement sur des vérifications Java facilement hookables |
| Localisation | `MainActivity.onCreate()` → appels `c.a()`, `c.b()`, `c.c()` |
| Impact | Un attaquant utilisant Frida peut bypasser ces vérifications et exécuter l'application sur un appareil rooté |
| Remédiation | Implémenter des vérifications en code natif, utiliser des solutions attestation comme Google Play Integrity API |

---

**Constat #4 : Version SDK obsolète**

| Champ | Détail |
|---|---|
| Sévérité | **Faible** |
| Description | `targetSdkVersion=28` (Android 9), version non maintenue depuis 2020 |
| Localisation | `AndroidManifest.xml` → `uses-sdk` |
| Impact | L'application ne bénéficie pas des protections de sécurité des versions Android récentes |
| Remédiation | Mettre à jour `targetSdkVersion` vers API 33 ou 34 minimum |

---

**Constat #5 : Secret obfusqué mais récupérable**

| Champ | Détail |
|---|---|
| Sévérité | **Moyenne** |
| Description | Le secret est stocké de manière obfusquée dans le code, mais récupérable par analyse dynamique |
| Localisation | Classe `sg.vantagepoint.a` |
| Impact | L'obfuscation seule ne constitue pas un mécanisme de sécurité fiable |
| Remédiation | Stocker les secrets côté serveur, ne jamais embarquer de secrets dans le code client |

### D) Annexes

**Permissions demandées :** Aucune permission externe déclarée dans cet APK.

**Composants exportés :**

| Composant | Type | Exported | Intent-filter |
|---|---|---|---|
| `MainActivity` | Activity | true | MAIN / LAUNCHER |

---

## Task 8 — Nettoyage

```powershell
# Organisation des résultats
mkdir .\results
move .\app.jar .\results\
move .\rapport.md .\results\

# Suppression des artefacts temporaires
Remove-Item -Recurse -Force .\dex_out
```

Vérification que le rapport ne contient aucune information sensible réelle ✅

---

## Réponses aux questions bonus

**Q1 — Permissions excessives ?**
L'application UnCrackable Level 1 ne déclare aucune permission externe, ce qui est
approprié pour une application de démonstration. Dans une application réelle, des
permissions comme `READ_CONTACTS` ou `ACCESS_FINE_LOCATION` seraient excessives
si l'application n'en a pas besoin fonctionnellement.

**Q2 — Composant exporté exploitable ?**
`MainActivity` est exportée avec un intent-filter `MAIN/LAUNCHER`. Une application
malveillante pourrait démarrer cette activité directement via :
`adb shell am start -n owasp.mstg.uncrackable1/.MainActivity`
Dans un contexte plus complexe, si cette activité acceptait des extras d'intent sans
validation, elle pourrait être vulnérable à une injection de données.

**Q3 — URL en clair dans le code ?**
Il faudrait la déplacer dans un fichier de configuration externe non embarqué dans
l'APK, ou la récupérer depuis un serveur de configuration sécurisé au démarrage.
Pour les URLs d'API, utiliser des variables d'environnement ou un serveur de secrets
comme HashiCorp Vault.

**Q4 — Obfuscation et analyse statique ?**
L'obfuscation avec ProGuard/R8 renomme les classes (`MainActivity` → `a`),
les méthodes et les variables avec des noms courts sans signification. Cela complique
la lecture du code mais ne l'empêche pas. Les parties généralement non obfusquées
sont : les noms de classes déclarées dans le manifeste, les constantes de chaînes
de caractères, les noms de méthodes annotées (`@Override`, `@JavascriptInterface`).

**Q5 — SharedPreferences vs variable en mémoire ?**
Les SharedPreferences persistent sur le disque en clair (fichier XML lisible avec root).
Une variable en mémoire disparaît à la fermeture de l'application et est plus difficile
à extraire. Cependant, ni l'un ni l'autre n'est sécurisé pour des tokens critiques :
il faut utiliser l'Android Keystore System pour stocker les secrets de façon sécurisée.

**Q6 — Risque de `android:allowBackup="true"` ?**
Avec `adb backup -f backup.ab owasp.mstg.uncrackable1`, un attaquant ayant accès USB
peut extraire toutes les données de l'application (SharedPreferences, bases SQLite,
fichiers internes). Correction : `android:allowBackup="false"` dans le manifeste.

**Q7 — Exported explicite vs intent-filter sans exported ?**
Avant Android 12, un composant avec un intent-filter était implicitement exporté même
sans l'attribut. Depuis Android 12, l'attribut `exported` est obligatoire pour les
composants avec intent-filter. Un composant explicitement `exported="false"` avec
un intent-filter est plus sûr car seules les applications avec la même signature
peuvent y accéder.

**Q8 — `WebView.setJavaScriptEnabled(true)` ?**
C'est risqué car cela permet l'exécution de JavaScript arbitraire dans la WebView.
Si la WebView charge du contenu non maîtrisé, une attaque XSS pourrait permettre
l'accès aux données locales via des interfaces JavaScript exposées avec
`addJavascriptInterface()`. Il faut limiter les origines autorisées, désactiver
`setAllowFileAccess()` et valider strictement les URLs chargées.


---

## Environnement

- **OS** : Windows 11
- **IDE** : Android Studio Meerkat
- **Outils** : JADX GUI 1.5.5, dex2jar 2.4, JD-GUI 1.6.6
- **APK analysé** : OWASP UnCrackable Level 1
- **Références** : OWASP MASVS, OWASP MASTG, Android Security Docs
- **Niveau** : Débutant / Initiation
- **Catégorie** : Mobile Security / Reverse Engineering
