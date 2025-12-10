# 🛡️ Security Scanner

Application d'analyse de sécurité pour Windows, macOS et Linux basée sur les Microsoft Security Baselines et CIS Benchmarks.

---

## 📋 Prérequis

Avant de commencer, assurez-vous d'avoir installé :

- **Node.js** (version 18 ou supérieure) : [Télécharger Node.js](https://nodejs.org/)
- **Git** (optionnel, pour cloner le repo) : [Télécharger Git](https://git-scm.com/)

Pour vérifier si Node.js est installé, ouvrez un terminal et tapez :
```bash
node --version
```

---

## 🚀 Installation (étape par étape)

### Méthode 1 : Téléchargement ZIP (plus simple)

1. **Télécharger le projet**
   - Cliquez sur le bouton vert **"Code"** en haut de cette page
   - Cliquez sur **"Download ZIP"**
   - Décompressez le fichier ZIP téléchargé

2. **Ouvrir le dossier dans VS Code**
   - Ouvrez Visual Studio Code
   - Fichier → Ouvrir le dossier
   - ⚠️ **IMPORTANT** : Sélectionnez le dossier racine `Project-security-feat-coding-interfaces` (celui qui contient `package.json`)
   - **NE PAS** ouvrir le sous-dossier `app`

3. **Ouvrir un terminal dans VS Code**
   - Menu : Terminal → Nouveau terminal
   - Ou raccourci : `Ctrl + ù` (Windows) / `Cmd + ù` (Mac)

4. **Installer les dépendances**
   ```bash
   npm install
   ```
   ⏳ Attendez que l'installation se termine (peut prendre 1-2 minutes)

5. **Lancer l'application**
   ```bash
   npm run dev
   ```

6. **C'est prêt !** 🎉
   - L'application Electron s'ouvre automatiquement
   - Si elle ne s'ouvre pas, allez sur http://localhost:3000 dans votre navigateur

---

### Méthode 2 : Avec Git (pour développeurs)

```bash
# 1. Cloner le repository
git clone https://github.com/yanntanguy-del/Project-security.git

# 2. Entrer dans le dossier
cd Project-security

# 3. Installer les dépendances
npm install

# 4. Lancer l'application
npm run dev
```

---

## 🔧 Résolution des problèmes courants

### ❌ Erreur : "'concurrently' n'est pas reconnu"
**Cause** : Les dépendances ne sont pas installées.  
**Solution** : Exécutez `npm install` avant `npm run dev`

### ❌ Erreur : "Missing script: dev"
**Cause** : Vous êtes dans le mauvais dossier.  
**Solution** : Assurez-vous d'être dans le dossier racine (celui avec `package.json`), pas dans le sous-dossier `app`

### ❌ Erreur : "Port 3000 is in use"
**Cause** : Une autre application utilise le port 3000.  
**Solution** : Fermez l'autre application ou redémarrez votre ordinateur

### ❌ L'application ne s'ouvre pas
**Solution** : Ouvrez manuellement http://localhost:3000 dans votre navigateur

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

## 📁 Structure du projet

```
Project-security/
├── app/                    # Pages et API Next.js
├── components/             # Composants UI
├── data/baselines/         # Baselines de sécurité (JSON)
│   ├── windows/
│   ├── macos/
│   └── linux/
├── main/                   # Code Electron
├── package.json            # ← Le fichier doit être ici !
└── README.md
```

---

## ⚠️ Note importante

Cette version de démonstration expire le **30 décembre 2025**.

---

## 📞 Support

En cas de problème, créez une [Issue](https://github.com/yanntanguy-del/Project-security/issues) sur GitHub.


