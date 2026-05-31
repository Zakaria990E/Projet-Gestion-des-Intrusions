# 🔒 API Security Academic Auditor

**Assistant pédagogique d'audit de sécurité pour APIs mobiles**

## 📋 Description

Ce projet est un outil académique et pédagogique d'analyse de sécurité pour les APIs mobiles. Il permet d'apprendre les bonnes pratiques de sécurité des APIs en analysant une API locale de démonstration et en générant un rapport de conformité basé sur les recommandations OWASP API Security et OWASP Mobile.

## 🎓 Contexte Académique

Ce projet est réalisé uniquement dans un cadre académique, pédagogique et professionnel. L'objectif n'est pas de créer un outil offensif, ni de tester des systèmes réels. Le projet fonctionne uniquement avec une API locale de démonstration fournie dans le projet. Il sert à apprendre les bonnes pratiques de sécurité des APIs mobiles et à générer un rapport pédagogique.

## 🎯 Objectif Pédagogique

- Apprendre les principes fondamentaux de la sécurité des APIs
- Comprendre les vulnérabilités courantes dans les APIs mobiles
- Maîtriser les recommandations OWASP pour les APIs
- Générer des rapports d'audit structurés et professionnels
- Développer des compétences en analyse défensive

## 🏗️ Architecture

```
Local Demo API → Security Checklist Analyzer → Educational Security Report
```

Le projet suit une architecture simple en trois couches :

1. **API Locale de Démonstration** - API simplifiée avec des vulnérabilités pédagogiques intentionnelles
2. **Analyseur de Checklist de Sécurité** - Module d'analyse passive vérifiant la conformité OWASP
3. **Générateur de Rapport Pédagogique** - Création de rapports JSON et HTML détaillés

## 🛠️ Technologies Utilisées

- **Python 3.8+** - Langage principal
- **FastAPI** - Framework web pour l'application principale
- **Uvicorn** - Serveur ASGI
- **Requests** - Client HTTP pour l'analyse
- **Pydantic** - Validation des données
- **Jinja2** - Moteur de templates pour les rapports HTML
- **HTML/CSS** - Interface web

## 📁 Structure du Projet

```
api_security_academic_auditor/
│
├── main.py                          # Application FastAPI principale
├── demo_api.py                      # API locale de démonstration
├── requirements.txt                 # Dépendances Python
├── README.md                        # Documentation du projet
│
├── models/
│   └── schemas.py                   # Modèles Pydantic
│
├── analyzer/
│   ├── checklist_analyzer.py       # Analyseur de checklist OWASP
│   ├── sensitive_data_checker.py    # Détection de données sensibles
│   ├── error_message_checker.py    # Analyse des messages d'erreur
│   └── header_checker.py           # Vérification des headers de sécurité
│
├── reports/
│   ├── report_generator.py         # Générateur de rapports
│   └── templates/
│       └── report_template.html    # Template HTML pour les rapports
│
├── results/
│   └── example_report.json         # Exemple de rapport JSON
│
├── templates/
│   └── index.html                  # Interface web principale
│
└── static/
    └── style.css                   # Styles CSS de l'interface
```

## 🚀 Installation

### Prérequis

- Python 3.8 ou supérieur
- pip (gestionnaire de paquets Python)

### Étapes d'installation

1. Cloner ou télécharger le projet
2. Naviguer dans le répertoire du projet :
   ```bash
   cd api_security_academic_auditor
   ```
3. Installer les dépendances :
   ```bash
   pip install -r requirements.txt
   ```

## 🎮 Lancement

### 1. Lancer l'API Locale de Démonstration

Ouvrez un terminal et lancez l'API de démonstration :

```bash
uvicorn demo_api:app --reload --port 9000
```

L'API sera accessible sur : http://127.0.0.1:9000

### 2. Lancer l'Application Principale

Ouvrez un deuxième terminal et lancez l'application principale :

```bash
uvicorn main:app --reload --port 8000
```

L'application sera accessible sur : http://127.0.0.1:8000

### 3. Accéder à l'Interface Web

Ouvrez votre navigateur et accédez à :

```
http://127.0.0.1:8000
```

## 🧪 Test de l'API Locale

L'API de démonstration contient les endpoints suivants pour les tests pédagogiques :

- `GET /` - Endpoint racine
- `GET /api/public` - Endpoint public (sans authentification)
- `GET /api/profile` - Endpoint de profil (expose des données sensibles)
- `GET /api/admin` - Endpoint admin (sans authentification appropriée)
- `GET /api/debug` - Endpoint de debug (expose des détails techniques)
- `GET /api/headers-check` - Endpoint pour vérifier les headers de sécurité

Vous pouvez tester ces endpoints directement via :
- L'interface web de l'application
- La documentation Swagger : http://127.0.0.1:9000/docs
- Un client HTTP comme curl ou Postman

## 📊 Génération du Rapport

### Via l'Interface Web

1. Accédez à http://127.0.0.1:8000
2. Entrez l'URL de l'API locale (par défaut : http://127.0.0.1:9000)
3. Cliquez sur "Launch Analysis"
4. Attendez la fin de l'analyse
5. Accédez au rapport HTML ou JSON généré

### Via l'API

Lancer une analyse :

```bash
curl -X POST "http://127.0.0.1:8000/analyze" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://127.0.0.1:9000"}'
```

Lister les rapports :

```bash
curl "http://127.0.0.1:8000/reports"
```

Accéder à un rapport spécifique :

```bash
curl "http://127.0.0.1:8000/reports/{report_id}"
```

Accéder au rapport HTML :

```bash
curl "http://127.0.0.1:8000/reports/{report_id}/html"
```

## 🔍 Fonctionnalités d'Analyse

### A. Vérification d'Authentification Déclarative

Vérifie si certains endpoints sensibles sont marqués comme nécessitant une authentification dans la configuration locale.

### B. Vérification des Données Sensibles

Analyse les réponses locales et signale la présence de mots sensibles :
- password
- token
- secret
- api_key
- private_key
- role
- isAdmin
- credit_card
- ssn
- pin

### C. Vérification des Messages d'Erreur

Signale si une réponse contient des messages techniques :
- traceback
- exception
- debug
- internal server error
- database error
- stack trace

### D. Vérification des Headers de Sécurité

Vérifie la présence des headers de sécurité :
- X-Content-Type-Options
- X-Frame-Options
- Content-Security-Policy
- Strict-Transport-Security (recommandé)
- X-XSS-Protection (recommandé)

### E. Checklist OWASP Pédagogique

Affiche une checklist simple basée sur OWASP :
- Authentification présente
- Autorisation côté serveur
- Données sensibles protégées
- Erreurs techniques masquées
- Headers de sécurité présents
- Journalisation recommandée
- Limitation de requêtes recommandée

## 📄 Contenu du Rapport

Le rapport généré contient :

- **ID du rapport** - Identifiant unique
- **Date de l'analyse** - Horodatage
- **Nom du projet** - API Security Academic Auditor
- **Contexte académique** - Description du cadre pédagogique
- **Environnement** - localhost uniquement
- **Endpoints analysés** - Liste des endpoints testés
- **Règles vérifiées** - Checklist OWASP
- **Problèmes observés** - Liste des vulnérabilités trouvées
- **Niveau de risque pédagogique** - Low, Medium, High
- **Explication simple** - Description pédagogique
- **Recommandation de correction** - Solutions proposées
- **Conclusion** - Synthèse de l'analyse

Le rapport est généré en deux formats :
- **JSON** - Dans le répertoire `results/`
- **HTML** - Dans le répertoire `reports/`

## ⚠️ Limites du Projet

Ce projet a des limites importantes à connaître :

1. **Analyse Passive Seulement** - L'outil effectue uniquement des analyses passives sans tentatives d'exploitation
2. **Localhost Uniquement** - L'outil ne peut analyser que des APIs locales pour des raisons pédagogiques
3. **API de Démonstration** - L'analyse se base sur une API de démonstration avec des vulnérabilités intentionnelles
4. **Pas de Tests Agressifs** - Aucun bruteforce, fuzzing, ou tests d'intrusion
5. **Vérifications Simples** - Les vérifications sont basées sur des règles simples et non sur une analyse approfondie
6. **Pas d'Automatisation Complexe** - L'outil ne remplace pas un audit de sécurité professionnel

## 🔮 Améliorations Futures

Des améliorations possibles pour les versions futures :

- Ajout de plus de règles de vérification OWASP
- Support de l'authentification JWT pour l'API de démonstration
- Export PDF des rapports
- Historique des analyses avec comparaison
- Support de plusieurs APIs de démonstration
- Interface de configuration des règles personnalisées
- Intégration de tests unitaires
- Documentation plus détaillée des vulnérabilités
- Support multilingue

## ⚖️ Note Éthique

**Ce projet est uniquement destiné à un usage académique, pédagogique et défensif. Il fonctionne avec une API locale de démonstration et ne doit pas être utilisé pour analyser des systèmes tiers sans autorisation.**

L'outil est conçu pour :
- ✅ L'apprentissage des bonnes pratiques de sécurité
- ✅ La compréhension des vulnérabilités courantes
- ✅ La formation à l'audit défensif
- ✅ L'enseignement académique

L'outil ne doit pas être utilisé pour :
- ❌ Analyser des systèmes de production sans autorisation
- ❌ Effectuer des tests offensifs sur des systèmes tiers
- ❌ Exploiter des vulnérabilités réelles
- ❌ Contourner des mesures de sécurité

## 📚 Ressources Pédagogiques

Pour approfondir vos connaissances :

- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)

## 🤝 Contribution

Ce projet est académique et pédagogique. Les contributions sont les bienvenues dans le respect de l'objectif éducatif du projet.

## 📄 Licence

Ce projet est destiné à un usage académique et pédagogique.

## 👨‍🏫 Contact

Pour toute question académique ou pédagogique relative à ce projet, veuillez contacter votre professeur ou responsable de formation.

---

**Développé dans un cadre académique pour l'apprentissage de la sécurité des APIs mobiles**
