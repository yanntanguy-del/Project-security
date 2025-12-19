# 🛡️ Security Scanner

Application d'analyse de sécurité pour Windows, macOS et Linux basée sur les Microsoft Security Baselines et CIS Benchmarks.

---

## 📋 Prérequis

Avant de commencer, assurez-vous d'avoir installé :

- **Node.js** (version 18 ou supérieure) : [Télécharger Node.js](https://nodejs.org/)

Pour vérifier si Node.js est installé, ouvrez un terminal et tapez :
```bash
node --version
```

---


### 📥 Étape 1 : Télécharger le projet

1. Cliquez sur le bouton vert **"Code"** en haut de cette page GitHub
2. Cliquez sur **"Download ZIP"**
3. Décompressez le fichier ZIP téléchargé dans un dossier de votre choix (par exemple sur votre Bureau ou dans Documents)

**Note** : Vous téléchargez le code source du projet. Il faudra installer les dépendances et lancer l'application (voir les étapes suivantes).

### 📁 Étape 2 : Ouvrir le projet dans VS Code (ou votre éditeur de code préféré)

1. **Ouvrez Visual Studio Code** (ou votre éditeur de code préféré)

2. **Ouvrez le dossier décompressé** :
   - Menu : **Fichier** → **Ouvrir le dossier**
   - Naviguez jusqu'au dossier que vous avez décompressé (généralement nommé `Project-security` ou `projet-security`)
   - Cliquez sur **Sélectionner un dossier**

3. **C'est tout !** Vous devriez maintenant voir les fichiers du projet dans l'explorateur de VS Code à gauche.

💡 **Note** : Le fichier `package.json` est nécessaire pour installer les dépendances à l'étape suivante. Si vous ne le voyez pas dans VS Code, vérifiez que vous avez bien ouvert le dossier racine (celui qui contient aussi les dossiers `app/`, `components/`, `data/`, etc.), et non un sous-dossier comme `app/`.

### ⌨️ Étape 4 : Ouvrir un terminal

- Menu : **Terminal** → **Nouveau terminal**
- Ou raccourci : `Ctrl + ù` (Windows/Linux) ou `Cmd + ù` (macOS)

**Vérifiez que vous êtes dans le bon dossier** : Vous devez voir `package.json` dans la liste des fichiers.

Dans le terminal, vous devriez voir quelque chose comme :
```
PS C:\...\projet-security>
```
Ou sur macOS/Linux :
```
user@computer:~/projet-security$
```

**Vérification** : Tapez `dir` (Windows) ou `ls` (macOS/Linux) dans le terminal. Vous devez voir `package.json` dans la liste, pas seulement le dossier `app`.

### 📦 Étape 5 : Installer les dépendances

```bash
npm install
```

⏳ **Attendez** que l'installation se termine (1-2 minutes). Vous verrez des messages comme :
```
added 762 packages, and audited 763 packages in 60s
```

⚠️ Les avertissements `npm warn deprecated` sont normaux, vous pouvez les ignorer.

### Étape 5 : Lancer l'application

```bash
npm run dev
```

### ✅ Étape 6 : C'est prêt ! 🎉

L'application Electron s'ouvre automatiquement et affiche directement l'interface d'analyse de sécurité.

**Important** : 
- Dans l'application Electron, vous verrez directement la page d'analyse (pas la page d'accueil web)

---

## 🔧 Résolution des problèmes

### ❌ "'concurrently' n'est pas reconnu"

```
'concurrently' n'est pas reconnu en tant que commande interne
ou externe, un programme exécutable ou un fichier de commandes.
```

**Cause** : Vous n'avez pas exécuté `npm install`  
**Solution** : Exécutez `npm install` puis réessayez `npm run dev`

---

### ❌ "Missing script: dev"

```
npm error Missing script: "dev"
```

**Cause** : Vous êtes dans le mauvais dossier (probablement dans `app/`)  
**Solution** : 
1. Tapez `cd ..` pour remonter d'un niveau
2. Vérifiez avec `ls` (ou `dir`) que vous voyez `package.json`
3. Réessayez `npm install` puis `npm run dev`

---

### ❌ "up to date, audited 1 package"

Si `npm install` affiche seulement :
```
up to date, audited 1 package in 425ms
```

**Cause** : Vous êtes dans le mauvais dossier et avez créé un `package.json` vide avec `npm init`  
**Solution** :
1. Supprimez le fichier `package.json` créé par erreur dans `app/`
2. Remontez au bon dossier avec `cd ..`
3. Relancez `npm install`

---

### ❌ L'application se ferme immédiatement

Si vous voyez :
```
[ELECTRON] electron . exited with code 0
```

C'est normal si vous fermez la fenêtre. Pour relancer : `npm run dev`

---

### ❌ L'application affiche la page de téléchargement au lieu de l'interface d'analyse

**Cause** : L'application n'a pas détecté qu'elle tourne dans Electron  
**Solution** : 
1. Vérifiez que vous avez bien exécuté `npm run dev` (pas juste `npm start`)
2. Fermez l'application et relancez `npm run dev`
3. L'application devrait automatiquement rediriger vers la page d'analyse

---

### ❌ Certains paramètres affichent "Non vérifié" avec un message sur les droits administrateur

**Cause** : Certains paramètres Windows nécessitent des privilèges administrateur pour être lus  
**Solution** : 
1. Fermez l'application
2. Faites un clic droit sur votre terminal/éditeur
3. Sélectionnez "Exécuter en tant qu'administrateur" (Windows) ou utilisez `sudo` (macOS/Linux)
4. Relancez `npm run dev`
5. Relancez le scan dans l'application

---

## 📖 Utilisation

### Première utilisation

1. **Lancer l'application** : Exécutez `npm run dev` dans le terminal
2. **L'interface s'ouvre automatiquement** : L'application Electron affiche directement la page d'analyse de sécurité
3. **Le scan démarre automatiquement** : L'application analyse votre système dès l'ouverture

### Utiliser l'application

1. **Voir les résultats** : 
   - Les résultats s'affichent automatiquement après le scan
   - Les failles sont listées par statut : ✓ Conformes (vert), ✗ Non conformes (rouge), ? Non vérifiés (jaune)
   - Utilisez les filtres en haut pour voir uniquement les failles qui vous intéressent

2. **Comprendre une faille** : 
   - Cliquez sur une faille pour voir les détails complets
   - Chaque faille contient :
     - 💡 **C'est quoi ?** : Explication simple et accessible du paramètre
     - ⚠️ **Pourquoi c'est important ?** : Risques si non corrigé
     - 🔧 **Comment activer cette protection ?** : Instructions de remédiation

3. **Corriger une faille** : 
   - Copiez la commande PowerShell fournie dans la section "Comment activer cette protection ?"
   - Ouvrez PowerShell en tant qu'**administrateur** (clic droit → Exécuter en tant qu'administrateur)
   - Collez et exécutez la commande
   - ⚠️ **Important** : Certaines corrections nécessitent les droits administrateur

4. **Relancer un scan** : Cliquez sur le bouton "🔄 Relancer" en haut à droite pour réanalyser votre système

### Notes importantes

- **Droits administrateur** : Pour analyser certains paramètres système, vous devrez peut-être exécuter l'application en tant qu'administrateur
- **Certaines protections ne sont pas disponibles** : Si vous voyez "Non vérifié", consultez les détails pour comprendre pourquoi (édition Windows incompatible, matériel non supporté, etc.)
- **Relancez le scan après correction** : Après avoir appliqué une correction, relancez le scan pour vérifier que le problème est résolu

---

## 🖥️ Systèmes supportés

| Système | Versions |
|---------|----------|
| Windows | 10 (22H2), 11 (22H2, 24H2) |
| macOS | Sonoma (14), Sequoia (15) |
| Linux | Ubuntu 24.04, Debian 12, Fedora 40, Arch |

---

## 🌐 Différence entre la version web et l'application Electron

- **Version web (Vercel)** : Affiche une page de téléchargement avec des informations sur le projet
- **Application Electron** : Affiche directement l'interface d'analyse de sécurité et permet de scanner votre système

Quand vous lancez `npm run dev`, l'application Electron détecte automatiquement qu'elle tourne dans Electron et affiche l'interface d'analyse au lieu de la page de téléchargement.

---

## ⚠️ Note importante

Cette version de démonstration expire le **30 décembre 2025**.

---

## 📞 Support

En cas de problème, créez une [Issue](https://github.com/yanntanguy-del/Project-security/issues) sur GitHub.


