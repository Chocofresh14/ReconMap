# **ReconMap**

ReconMap est un outil de scan de ports réseau écrit en C, conçu pour être à la fois efficace, furtif et intuitif. Ce scanner offre des fonctionnalités avancées pour détecter les ports ouverts tout en évitant les systèmes de détection d'intrusion (IDS).

---

## **Fonctionnalités principales**
### 🕵️ **Mode Ghost (furtif)**
- Réduit le nombre de paquets envoyés pour minimiser les chances de détection.
- Espacement intelligent des requêtes pour simuler une activité normale.
- Compatible avec les réseaux équipés de pare-feux ou d’IDS.

### 🔍 **Scan des ports**
- Identifie les **ports ouverts** ou **fermés** sur une cible donnée.
- Détecte et affiche le **type de service** (HTTP, FTP, SSH, etc.) associé à chaque port ouvert.
- Support des protocoles **TCP** et **UDP**.

### 📊 **Rapports détaillés**
- Affiche une liste organisée des résultats, incluant :
  - Numéro du port.
  - État du port (ouvert)
  - Type de service (si détecté).
- Option d’export des résultats dans un fichier texte pour analyse ultérieure.

### ⚙️ **Options avancées**
- **Scan personnalisé** : Limite le scan à une plage de ports spécifique.
- **Timeout configurable** : Ajuste le temps d’attente pour les réponses réseau.
- **Multi-threading** : Accélère les scans grâce à l’utilisation de plusieurs threads.

---

## **Installation**
### Prérequis
- Un compilateur C (GCC recommandé).
- Bibliothèque réseau (optionnelle si non incluse dans le code, ex. `libpcap`).

### Compilation
Clonez le dépôt Github :
```bash
git clone https://github.com/Chocofresh14/ReconMap.git
```

Allez dans le dossier `ReconMap` :
```bash
cd ReconMap
```

Exécutez le fichier shell pour l'installer et le compiler :
```bash
sudo bash install.sh
```

En cas de problème avec le fichier d'installation .sh vous pouvez effectuez :
```bash
sudo make
sudo make install
```

### Exécution
Lancez le scanner avec les permissions administratives (nécessaires pour accéder aux sockets bas niveau) :
```bash
sudo rmap [options]
```

---

## **Options d’utilisation**
| Option                | Description                                                        |
|-----------------------|--------------------------------------------------------------------|
| `-t <IP cible>`       | Spécifie l’adresse IP cible.                                       |
| `-u <URL cible>`      | Spécifie l’adresse URL cible.                                      |
| `-p <plage>`          | Spécifie une plage de ports à scanner (ex. `20-80`).               |
| `--ghost`             | Active le mode furtif.                                             |
| `--timeout <valeur>`  | Définir le timeout (en ms) pour chaque requête.                    |
| `--udp`               | Active le scan des ports UDP (par défaut : scan TCP uniquement) (non disponible).   |
| `--exclude <ports>`   | Ports à exclure (ex: 80,443,8000-8010).                            |
| `-o <fichier>`        | Exporte les résultats dans un fichier texte.                       |

---

## **Avertissements**
- Ce projet est à but éducatif uniquement. L’utilisation sur des réseaux sans autorisation explicite est illégale.
- Respectez les lois et politiques en vigueur dans votre région.

---

## **Contribution**
Les contributions sont les bienvenues ! Si vous avez des idées ou des suggestions, n’hésitez pas à ouvrir une **issue** ou soumettre une **pull request**.

---

## **Licence**
Ce projet est sous licence GPLv3. Vous êtes libre de l’utiliser, de le modifier et de le distribuer tout en respectant les termes de la licence.