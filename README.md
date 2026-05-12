# 🐍 Lab 19 — Exploitation d'une Vulnérabilité de Désérialisation SnakeYAML sur Android
> **Discipline** : Mobile Security / CTF | **Niveau** : Avancé | **Plateforme** : Android (Émulé)

---

## 📌 Vue d'ensemble

Ce laboratoire aborde une vulnérabilité critique et souvent sous-estimée dans l'écosystème Android : la **désérialisation non sécurisée via SnakeYAML**. En combinant analyse statique, patch Smali, et crafting d'un payload YAML malveillant, nous allons forcer l'application à instancier une classe arbitraire (`BigBoss`) et révéler un flag caché dans les logs système.

> **Application cible :** `com.pwnsec.snake`  
> **Vulnérabilité exploitée :** Unsafe Deserialization — SnakeYAML arbitrary class instantiation  
> **Vecteur d'attaque :** Intent Android + payload YAML + patch Smali

---

## 🎯 Objectifs pédagogiques

| # | Objectif | Technique utilisée |
|---|----------|--------------------|
| 1 | Extraire et analyser l'APK | `adb pull` + JADX |
| 2 | Identifier les classes sensibles | Analyse statique Java |
| 3 | Bypasser la détection de root | Patch Smali |
| 4 | Forger un payload YAML malveillant | SnakeYAML type coercion |
| 5 | Déclencher la désérialisation via Intent | `adb shell am start` |
| 6 | Récupérer le flag via logcat | `adb logcat` |

---

## 🛠️ Arsenal technique

| Outil | Rôle dans ce lab |
|-------|-----------------|
| [apktool](https://apktool.org/) | Décompilation et recompilation de l'APK (Smali) |
| [JADX](https://github.com/skylot/jadx) | Analyse statique du bytecode Java/Kotlin |
| [uber-apk-signer](https://github.com/patrickfav/uber-apk-signer) | Re-signature de l'APK avec un debug keystore |
| ADB | Communication, installation, logcat |

---

## 🔬 Comprendre la surface d'attaque

Avant de commencer, voici la chaîne d'exploitation complète que nous allons construire :

```
Attaquant
    │
    ├── [1] Intent SNAKE=BigBoss → déclenche MainActivity.C()
    │
    ├── [2] MainActivity.C() → parse /sdcard/Snake/Skull_Face.yml avec SnakeYAML
    │
    ├── [3] SnakeYAML → instancie BigBoss("Snaaaaaaaaaaaaaake") via !!class
    │
    └── [4] BigBoss → compare le secret, appelle hexToAscii() → log FLAG
```

---

## 🚀 Déroulement du Lab

---

### Étape 1 — Extraction de l'APK depuis l'émulateur

La première étape consiste à récupérer le fichier APK directement depuis le système de fichiers de l'émulateur. `pm path` retourne le chemin exact de l'APK installé.

```bash
# Localisation du chemin de l'APK sur l'émulateur
adb shell pm path com.pwnsec.snake

# Extraction vers la machine hôte
adb pull /data/app/.../base.apk snake_real.apk
```

---

### Étape 2 — Analyse statique avec JADX

JADX décompile le bytecode Dalvik en code Java lisible. L'objectif est d'identifier les deux classes clés de l'application.

#### 🔎 Classe `BigBoss` — La cible

<img width="1028" height="710" alt="image" src="https://github.com/user-attachments/assets/9a78800b-1754-471c-9bdd-20a152644156" />


**Comportement identifié :**
- Prend une `String` en paramètre dans son constructeur
- La compare à `"Snaaaaaaaaaaaaaake"` (**16 x 'a'** — à ne pas se tromper)
- Si la comparaison est vraie → appelle `hexToAscii()` → logue le flag avec le tag `BigBoss`

#### 🔎 Classe `MainActivity` — Le point d'entrée

<img width="1011" height="597" alt="image" src="https://github.com/user-attachments/assets/0ff9303b-fe8b-4de0-bb47-ccb8052d9eed" />


**Deux méthodes critiques identifiées :**

| Méthode | Rôle | Obstacle |
|---------|------|----------|
| `isDeviceRooted()` | 4 vérifications de root | Bloque l'exécution → **à patcher** |
| `C()` | Lit l'Intent extra `SNAKE`, si = `"BigBoss"` → parse `Skull_Face.yml` avec SnakeYAML | Point d'entrée de l'exploitation |

---

### Étape 3 — Décompilation et patch Smali

#### 3a — Décompilation de l'APK

```bash
java -jar apktool_3.0.2.jar d snake_real.apk -o snake_smali
```

<img width="1020" height="232" alt="image" src="https://github.com/user-attachments/assets/ce323c10-e778-41fb-9d1d-6113520e99a1" />


#### 3b — Patch de `isDeviceRooted()` en Smali

La méthode `isDeviceRooted()` cumule 4 vérifications de root. On la remplace par une version qui retourne directement `false`, neutralisant l'obstacle d'un seul coup.

**Avant (Java original) :**
```java
public static boolean isDeviceRooted(Context context) {
    return checkForDangerousBinaries() || checkForRootManagementApps(context)
        || checkForWritableSystem() || checkForRootShell();
}
```

**Après (Smali patché) :**
```smali
.method public static isDeviceRooted(Landroid/content/Context;)Z
    .locals 1

    const/4 p0, 0x0   # Retourne toujours false → root non détecté

    return p0
.end method
```

> 💡 **Pourquoi Smali ?** Le bytecode Dalvik (`.dex`) n'est pas directement éditable. Apktool le convertit en Smali (assembleur Dalvik) que l'on peut modifier, puis recompiler.

---

### Étape 4 — Recompilation et signature de l'APK

Après le patch, l'APK doit être recompilé et re-signé pour être installable. Un APK non signé est rejeté par Android.

```bash
# Recompilation
java -jar apktool_3.0.2.jar b snake_smali -o snake_patched.apk

# Signature avec debug keystore
java -jar uber-apk-signer.jar --apks snake_patched.apk
```

<!-- 📸 IMAGE 4 — Capture de la signature uber-apk-signer -->
<img width="1458" height="667" alt="3" src="https://github.com/user-attachments/assets/502e1c89-284e-4cdc-bd82-eb0e3ac56528" />

---

### Étape 5 — Installation de l'APK patché

```bash
# Désinstallation de la version originale
adb uninstall com.pwnsec.snake

# Installation de l'APK patché et signé
adb install snake_patched-aligned-debugSigned.apk
```

<!-- 📸 IMAGE 5 — Capture de l'installation ADB -->
<img width="1553" height="265" alt="4" src="https://github.com/user-attachments/assets/d475caf0-bdb7-45fa-a868-b75791283584" />

---

### Étape 6 — Création du payload YAML malveillant

C'est ici que réside la vulnérabilité centrale : **SnakeYAML permet d'instancier n'importe quelle classe Java** via la syntaxe `!!NomDeClasse`. On forge un fichier YAML qui force l'instanciation de `BigBoss` avec l'argument secret attendu.

```bash
# Création du répertoire cible sur l'émulateur
adb shell mkdir -p /sdcard/Snake

# Push du payload YAML
adb push Skull_Face.yml /sdcard/Snake/Skull_Face.yml
```

**Contenu de `Skull_Face.yml` :**
```yaml
!!com.pwnsec.snake.BigBoss ["Snaaaaaaaaaaaaaake"]
```

> ⚠️ **Précision critique :** Le paramètre contient exactement **16 fois la lettre 'a'** après "Sn". Une erreur de compte = pas de flag.

<!-- 📸 IMAGE 6 — Capture du fichier Skull_Face.yml -->
<img width="1325" height="49" alt="7" src="https://github.com/user-attachments/assets/ccf30cd4-20b1-40ee-9d3f-3a42ebd2530f" />

---

### Étape 7 — Déclenchement via Intent Android

On envoie l'Intent directement depuis ADB, en passant `SNAKE=BigBoss` comme extra. Cela déclenche la méthode `C()` dans `MainActivity`, qui parse le YAML et instancie `BigBoss`.

```bash
adb shell am start -n com.pwnsec.snake/.MainActivity -e SNAKE BigBoss
```

<img width="307" height="646" alt="image" src="https://github.com/user-attachments/assets/f8562f27-ee9e-4f19-918a-a9d1d46a565e" />


---

### Étape 8 — Récupération du flag via logcat

Le flag est loggué par `BigBoss` avec le tag `BigBoss`. On filtre logcat pour ne lire que ce tag.

```bash
adb logcat -s BigBoss:I
```

---

## 🚩 Flag

```
PWNSEC{W3'r3_N0t_T00l5_0f_The_g0v3rnm3n7_0R_4ny0n3_3ls3}
```

---

## 📊 Résumé de l'exploitation

| # | Étape | Action | Outil |
|---|-------|--------|-------|
| 1 | Extraction | Récupération de l'APK depuis l'émulateur | ADB |
| 2 | Analyse | Identification de `BigBoss` et `MainActivity` | JADX |
| 3 | Patch | Bypass `isDeviceRooted()` en Smali | apktool |
| 4 | Build | Recompilation + signature debug | apktool + uber-apk-signer |
| 5 | Deploy | Installation de l'APK patché | ADB |
| 6 | Payload | Forge du fichier `Skull_Face.yml` | Manuel |
| 7 | Exploit | Déclenchement via Intent `SNAKE=BigBoss` | ADB |
| 8 | Flag | Lecture du flag dans logcat | ADB logcat |

---

## 🧠 Analyse de la vulnérabilité

### Pourquoi SnakeYAML est dangereux

SnakeYAML supporte nativement la **désérialisation de types Java arbitraires** via la syntaxe `!!`. Contrairement à JSON, il ne se contente pas de mapper des données : il peut **instancier et exécuter du code** lors du parsing. C'est l'équivalent YAML de la désérialisation Java classique (CVE-2022-1471).

```
Payload : !!com.pwnsec.snake.BigBoss ["secret"]
               ↓
SnakeYAML appelle : new BigBoss("secret")
               ↓
Constructeur exécuté → logique métier déclenchée → FLAG
```

### Recommandations défensives

- 🔒 Utiliser `SafeConstructor` dans SnakeYAML pour **désactiver l'instanciation arbitraire**
- 🔒 Ne jamais parser des fichiers YAML provenant de sources non fiables (sdcard, Intent)
- 🔒 Valider et restreindre les extras d'Intent avec des permissions appropriées
- 🔒 Stocker les données sensibles côté serveur, jamais dans des logs locaux

---

## 📚 Ressources complémentaires

- [SnakeYAML CVE-2022-1471](https://nvd.nist.gov/vuln/detail/CVE-2022-1471)
- [OWASP – Insecure Deserialization](https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data)
- [Smali/Baksmali Documentation](https://github.com/JesusFreke/smali)
- [JADX – Java Decompiler](https://github.com/skylot/jadx)

---

*Lab réalisé dans un cadre pédagogique — environnement isolé et contrôlé.*
