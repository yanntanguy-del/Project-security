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

## 🚀 Installation (étape par étape)

### Étape 1 : Télécharger le projet

1. Cliquez sur le bouton vert **"Code"** en haut de cette page
2. Cliquez sur **"Download ZIP"**
3. Décompressez le fichier ZIP téléchargé

### Étape 2 : Naviguer vers le BON dossier

⚠️ **TRÈS IMPORTANT** : Après décompression, vous aurez cette structure :
```
Project-security-feat-coding-interfaces/
└── Project-security-feat-coding-interfaces/   ← C'EST CE DOSSIER !
    ├── app/                                    ← PAS celui-ci !
    ├── components/
    ├── data/
    ├── main/
    ├── package.json                           ← Le fichier doit être visible ici
    └── ...
```

**Vous devez ouvrir le dossier qui contient `package.json`**, pas le dossier `app` !

### Étape 3 : Ouvrir dans VS Code

1. Ouvrez Visual Studio Code
2. **Fichier** → **Ouvrir le dossier**
3. Naviguez jusqu'au dossier `Project-security-feat-coding-interfaces` (le deuxième niveau, celui avec `package.json`)
4. Cliquez sur **Sélectionner un dossier**

### Étape 4 : Ouvrir un terminal

- Menu : **Terminal** → **Nouveau terminal**
- Ou raccourci : `Ctrl + ù`

Vérifiez que vous voyez quelque chose comme :
```
PS C:\...\Project-security-feat-coding-interfaces>
```
Et **PAS** :
```
PS C:\...\Project-security-feat-coding-interfaces\app>    ← MAUVAIS !
```

### Étape 5 : Installer les dépendances

```bash
npm install
```

⏳ **Attendez** que l'installation se termine (1-2 minutes). Vous verrez des messages comme :
```
added 762 packages, and audited 763 packages in 60s
```

⚠️ Les avertissements `npm warn deprecated` sont normaux, ignorez-les.

### Étape 6 : Lancer l'application

```bash
npm run dev
```

### Étape 7 : C'est prêt ! 🎉

L'application Electron s'ouvre automatiquement. Si elle ne s'ouvre pas, allez sur http://localhost:3000 dans votre navigateur.

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

## 📖 Utilisation

1. **Lancer un scan** : Cliquez sur "Lancer l'analyse de sécurité"
2. **Voir les résultats** : Les failles sont listées par catégorie et sévérité
3. **Corriger une faille** : 
   - Cliquez sur une faille pour voir les détails
   - Cliquez sur "Corriger" pour appliquer la remédiation
   - ⚠️ Certaines corrections nécessitent les droits administrateur

---

## 🖥️ Systèmes supportés

| Système | Versions |
|---------|----------|
| Windows | 10 (22H2), 11 (22H2, 24H2) |
| macOS | Sonoma (14), Sequoia (15) |
| Linux | Ubuntu 24.04, Debian 12, Fedora 40, Arch |

---

## ⚠️ Note importante

Cette version de démonstration expire le **30 décembre 2025**.

---

## 📞 Support

En cas de problème, créez une [Issue](https://github.com/yanntanguy-del/Project-security/issues) sur GitHub.


