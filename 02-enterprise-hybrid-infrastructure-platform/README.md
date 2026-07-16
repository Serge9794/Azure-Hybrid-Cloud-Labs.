# Enterprise Hybrid Infrastructure Platform
## Plateforme Hybride d'Infrastructure d'Entreprise sous Red Hat Enterprise Linux et Microsoft Azure

![RHEL](https://img.shields.io/badge/RHEL-10.2-red)
![Azure](https://img.shields.io/badge/Microsoft-Azure-blue)
![Ansible](https://img.shields.io/badge/Automation-Ansible-black)
![RHCSA](https://img.shields.io/badge/RHCSA-Lab-success)
![SecurityHardened](https://img.shields.io/badge/Security-SELinux%20%7C%20Firewalld%20%7C%20PrivateLink-critical)

---

# Présentation

**Enterprise Hybrid Infrastructure Platform** est un laboratoire avancé reproduisant une infrastructure informatique d'entreprise moderne intégrant **Red Hat Enterprise Linux 9.8** et **Microsoft Azure**.

L'objectif est de démontrer les compétences attendues d'un **Administrateur Système Linux**, d'un **Ingénieur Cloud Azure** ou d'un **Ingénieur DevOps**, en mettant en œuvre une plateforme hybride complète reposant sur des bonnes pratiques d'administration, d'automatisation, de supervision, de sécurité et de gouvernance.

Contrairement à un simple laboratoire RHCSA, ce projet reproduit une infrastructure proche d'un environnement de production, en s'appuyant sur la version actuelle de RHEL 9.8 et sur les mécanismes de sécurité réseau recommandés par la documentation Microsoft Azure pour les charges de travail hybrides.

> 📸 **Vue d'ensemble du laboratoire**

<img width="958" height="260" alt="1" src="https://github.com/user-attachments/assets/24538bfd-7f1a-4ee2-a784-d12b5b0e564e" />


---

# Objectifs

Cette plateforme met en œuvre :

- Administration système sous Red Hat Enterprise Linux 10
- Gestion des utilisateurs et des permissions
- Sécurisation du système (SELinux 3.8, Firewalld, SSH, auditd)
- Gestion du stockage avec LVM
- Automatisation avec Ansible (y compris les rôles système RHEL natifs)
- Intégration hybride avec Azure Arc
- Supervision avec Azure Monitor
- Gestion des mises à jour avec Azure Update Manager
- Gouvernance avec Azure Policy
- Sauvegarde et restauration
- Documentation complète inspirée des projets Open Source

---

# Technologies utilisées

| Domaine | Technologie | Version / précision |
|----------|-------------|----------------------|
| Système | Red Hat Enterprise Linux | 9.8 |
| Administration distante | OpenSSH | 9.9 |
| Sécurité obligatoire | SELinux userspace | 3.8 |
| Cryptographie | Post-quantum crypto policies | Technology Preview |
| Gestion sudo centralisée | Rôle système `sudo` (Ansible System Roles) | RHEL  |
| Cloud | Microsoft Azure | — |
| Hybride | Azure Arc | Private Link Scope (Arc PLS) |
| Supervision | Azure Monitor | Azure Monitor Private Link Scope (AMPLS) |
| Gouvernance | Azure Policy | — |
| Gestion des mises à jour | Azure Update Manager | — |
| Automatisation | Ansible | Inventaire + rôles + rôles système RHEL |
| Pare-feu | Firewalld | — |
| Stockage | LVM | — |
| Versionning | Git & GitHub | — |

---

# Architecture de la plateforme

L'infrastructure est organisée autour de deux machines virtuelles Red Hat Enterprise Linux :

- **client.lab.local**
  - Poste d'administration
  - Nœud de contrôle Ansible
  - Accès SSH (OpenSSH 9.9)
  - Git
  - Visual Studio Code

- **server.lab.local**
  - Serveur Linux administré
  - Services applicatifs
  - Agent Azure Arc (`azcmagent`)
  - Azure Monitor Agent (AMA)
  - LVM
  - SELinux (mode enforcing)
  - Firewalld

Ces deux serveurs communiquent via SSH sur un réseau privé VirtualBox, tandis que le serveur est connecté à Microsoft Azure afin de bénéficier des services hybrides.

> 📸 **Identification du client**


> 📸 **Capture 3 — Identification du serveur**
> `![hostnamectl server](docs/screenshots/03-hostnamectl-server.png)`
> *À insérer juste après la capture 2 : sortie de `hostnamectl` sur server.lab.local, pour comparaison directe.*

> 📸 **Capture 4 — Configuration réseau**
> `![ip addr client et serveur](docs/screenshots/04-ip-addr.png)`
> *À insérer ici : sortie de `ip addr` sur les deux machines.*

> 📸 **Capture 5 — Connectivité réseau**
> `![ping entre les deux VM](docs/screenshots/05-ping-test.png)`
> *À insérer ici : test croisé `ping server.lab.local` / `ping client.lab.local`.*

> 📸 **Capture 6 — Accès SSH**
> `![connexion SSH](docs/screenshots/06-ssh-connection.png)`
> *À insérer ici : connexion `ssh user@server.lab.local` réussie, en précisant la version OpenSSH avec `ssh -V`.*

---

# Évolution de l'architecture : Azure Arc Private Link et Azure Monitor Private Link

Ce projet constitue une évolution de mon précédent laboratoire hybride.

À la suite de sa publication sur LinkedIn, **Bryan Bernet**, Architecte Technique chez ITS, a formulé une remarque pertinente concernant l'utilisation de **Azure Arc Private Link** et **Azure Monitor Private Link** afin de sécuriser les communications entre les serveurs hybrides et Azure.

Cette remarque met en évidence une différence essentielle entre une architecture de laboratoire et une architecture de production.

Dans un environnement de test, l'utilisation des points d'accès publics Azure est acceptable pour simplifier le déploiement.

En revanche, dans un contexte d'entreprise soumis à des exigences telles que **PCI-DSS**, **ISO 27001** ou les recommandations **Zero Trust**, les communications avec Azure doivent transiter par des **Private Endpoints**, limitant ainsi l'exposition aux réseaux publics.

**Point technique important à documenter** (souvent mal compris, y compris dans certaines discussions communautaires) : Azure Arc Private Link et Azure Monitor Private Link ne sont **pas la même ressource** et ne se configurent pas ensemble automatiquement.

- L'**Azure Arc Private Link Scope (Arc PLS)** sécurise uniquement l'enregistrement et la gestion de la machine Arc elle-même.
- La connectivité vers **tout autre service Azure** consommé via une extension Arc — Azure Monitor, Azure Automation, Azure Key Vault, Azure Blob Storage — nécessite un **Private Link distinct, configuré service par service**.
- Azure Monitor utilise sa propre ressource dédiée, l'**Azure Monitor Private Link Scope (AMPLS)**, avec un point de terminaison privé unique regroupant les workspaces Log Analytics et les Azure Monitor workspaces à protéger.
- Le trafic vers Microsoft Entra ID et Azure Resource Manager ne transite pas par le Arc PLS par défaut ; il continue d'emprunter la route internet standard, sauf si l'on configure en complément un private link de gestion des ressources (Resource Management Private Link).
- Le déploiement d'un Private Link (Arc ou Monitor) suppose une connectivité établie au préalable entre le réseau local et un réseau virtuel Azure, via VPN site-to-site ou ExpressRoute — ce qui structure la roadmap de production du projet.

Cette nouvelle version du projet est donc conçue pour évoluer progressivement vers une architecture plus sécurisée intégrant :

- Un **Azure Arc Private Link Scope** dédié au serveur Arc
- Un **Azure Monitor Private Link Scope (AMPLS)** dédié au Log Analytics workspace
- Une connectivité VPN/ExpressRoute simulée en documentation (schéma de production)
- Réduction de l'exposition Internet et renforcement de la conformité PCI-DSS / ISO 27001

Une première implémentation reposera sur les endpoints publics afin de rester reproductible dans un laboratoire personnel, avant de documenter une architecture de niveau production utilisant les Private Endpoints, avec Arc PLS et AMPLS clairement représentés comme deux ressources séparées sur le schéma.



> 📊 **Architecture v1 (endpoints publics)**

<img width="680" height="390" alt="07-architecture-v1-public" src="https://github.com/user-attachments/assets/416b9021-cad5-4371-a974-de681d14b378" />







> 📊 **Schéma 2 — Architecture cible (Arc PLS + AMPLS séparés)**

<img width="680" height="410" alt="08-architecture-v2-privatelink" src="https://github.com/user-attachments/assets/4d4e518f-e283-4c55-92b6-4483f213b4b1" />

---

# Machines virtuelles

| Machine | Nom d'hôte | Rôle |
|----------|------------|------|
| Client | client.lab.local | Poste d'administration |
| Serveur | server.lab.local | Serveur Linux administré |

---

# Objectif final

À l'issue de ce projet, cette plateforme permettra de démontrer des compétences couvrant :

- Administration Linux (RHCSA sur RHEL 10)
- Automatisation avec Ansible et les rôles système RHEL natifs
- Gestion d'une infrastructure hybride Azure (Arc, Monitor, Update Manager, Policy)
- Supervision et distinction claire entre Arc Private Link et Monitor Private Link
- Sécurisation des systèmes (SELinux, Firewalld, SSH durci)
- Gouvernance et conformité (PCI-DSS, ISO 27001)
- Documentation technique professionnelle

> 📸 **Capture 7 — Structure du projet**
> `![Arborescence du dépôt](docs/screenshots/09-tree-structure.png)`
> *À insérer en toute fin de chapitre : sortie de `tree Enterprise-Hybrid-Infrastructure-Platform`.*
