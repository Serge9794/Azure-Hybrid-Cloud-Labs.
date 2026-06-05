# 🏢 Gouvernance et Supervision Hybride de Serveurs Linux avec Azure Arc, Azure Monitor et Update Manager

> **Auteur :** Serge TOGNON | Administrateur Cloud Azure Certifié (AZ-104) | Candidat RHCSA		
> [![LinkedIn](https://img.shields.io/badge/LinkedIn-Serge_TOGNON-0077B5?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/serge-tognon)
> [![AZ-104](https://img.shields.io/badge/Microsoft-AZ--104_Certified-0078D4?logo=microsoftazure&logoColor=white)](https://learn.microsoft.com/certifications/azure-administrator/)
> [![RHCSA](https://img.shields.io/badge/Red_Hat-Candidat_RHCSA-EE0000?logo=redhat&logoColor=white)](https://www.redhat.com/en/services/certification/rhcsa)

---

## 📋 Table des matières

1. [Présentation du projet](#-chapitre-1--présentation-du-projet)
2. [Installation des VM RHEL 9](#-chapitre-2--installation-des-vm-rhel-9)
3. [Sécurisation Linux](#-chapitre-3--sécurisation-linux)
4. [Préparation Azure](#-chapitre-4--préparation-azure)
5. [Log Analytics Workspace](#-chapitre-5--log-analytics-workspace)
6. [Déploiement Azure Arc](#-chapitre-6--déploiement-azure-arc)
7. [Validation Azure Arc](#-chapitre-7--validation-azure-arc)
8. [Azure Monitor Agent](#-chapitre-8--azure-monitor-agent)
9. [Data Collection Rules](#-chapitre-9--data-collection-rules)
10. [Analyse des journaux KQL](#-chapitre-10--analyse-des-journaux-kql)
11. [Alertes Azure](#-chapitre-11--alertes-azure)
12. [Azure Update Manager](#-chapitre-12--azure-update-manager)
13. [Validation des mises à jour](#-chapitre-13--validation-des-mises-à-jour)
14. [Azure Dashboards](#-chapitre-14--azure-dashboards)
15. [Audit de conformité](#-chapitre-15--audit-de-conformité)
16. [Dépannage](#-chapitre-16--dépannage)
17. [Validation finale](#-chapitre-17--validation-finale)
18. [Compétences démontrées](#-compétences-démontrées)

---

## 🎯 Chapitre 1 — Présentation du projet

### Contexte entreprise

**FinSecure SA** est une société de services financiers basée à Cotonou, opérant dans l'espace UEMOA. Elle gère des données sensibles soumises aux réglementations **RGPD**, **ISO 27001** et **PCI-DSS**.

La Direction des Systèmes d'Information (DSI) administre plusieurs serveurs Linux hébergés dans un datacenter local. Face à la complexification de l'infrastructure et aux exigences de conformité croissantes, le DSI a décidé de **moderniser l'administration sans migration immédiate vers Azure** — une approche hybride via **Azure Arc**.

### Problématiques résolues

| Problème actuel | Solution apportée |
|---|---|
| Administration manuelle serveur par serveur | Gestion centralisée via Azure Arc |
| Aucune supervision temps réel | Azure Monitor + métriques et alertes |
| Journaux dispersés sur chaque serveur | Collecte centralisée Log Analytics |
| Mises à jour non coordonnées | Azure Update Manager |
| Aucun inventaire centralisé | Inventaire automatique Azure Arc |
| Conformité impossible à auditer | Tableaux de bord et rapports Azure |

### Architecture du projet

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          MICROSOFT AZURE                                 │
│                                                                           │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │              Resource Group : rg-finsecure-arc                   │    │
│  │                                                                   │    │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │    │
│  │  │  Azure Arc   │  │Log Analytics │  │   Azure Monitor      │  │    │
│  │  │  Connected   │  │  Workspace   │  │   + DCR              │  │    │
│  │  │  Machines    │  │law-finsecure │  │   + Alertes          │  │    │
│  │  └──────┬───────┘  └──────┬───────┘  └──────────────────────┘  │    │
│  │         │                  │                                      │    │
│  │  ┌──────▼───────────────────▼──────────────────────────────┐    │    │
│  │  │              Update Manager + Dashboard                   │    │    │
│  │  └────────────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                          ▲                ▲                               │
│                     HTTPS 443        HTTPS 443                           │
│                     Arc Agent        AMA Agent                           │
└──────────────────────────┼────────────────┼──────────────────────────────┘
                           │                │
                 ┌─────────▼────────────────▼──────────┐
                 │       DATACENTER LOCAL               │
                 │       FinSecure SA — Cotonou         │
                 │                                      │
                 │  ┌─────────────────────────────┐    │
                 │  │  VM1 : admin.lab.local        │    │
                 │  │  IP  : 192.168.10.1           │    │
                 │  │  OS  : RHEL 9                 │    │
                 │  │  Rôle: Bastion SSH / Admin    │    │
                 │  │  Agent Arc  ✅                │    │
                 │  │  Agent AMA  ✅                │    │
                 │  └─────────────────────────────┘    │
                 │                                      │
                 │  ┌─────────────────────────────┐    │
                 │  │  VM2 : server.lab.local       │    │
                 │  │  IP  : 192.168.10.2           │    │
                 │  │  OS  : RHEL 9                 │    │
                 │  │  Rôle: Serveur métier          │    │
                 │  │  Agent Arc  ✅                │    │
                 │  │  Agent AMA  ✅                │    │
                 │  └─────────────────────────────┘    │
                 └──────────────────────────────────────┘
```

### Flux réseau

| Flux | Protocole | Port | Description |
|---|---|---|---|
| VMs → Azure Arc | HTTPS | 443 | Enregistrement et heartbeat |
| VMs → Log Analytics | HTTPS | 443 | Envoi des métriques et logs |
| VMs → Update Manager | HTTPS | 443 | Inventaire et déploiement MAJ |
| admin → server | SSH | 22 | Administration interne |

### Environnement technique

| Composant | Détail |
|---|---|
| Hyperviseur | VirtualBox 7.2.8|
| OS VMs | RHEL 9.7|
| VM Admin | admin.lab.local — 192.168.10.1 |
| VM Serveur | server.lab.local — 192.168.10.2 |
| Région Azure | France Central |
| Resource Group | rg-finsecure-arc |

---

## 🖥️ Chapitre 2 — Installation des VM RHEL 9

### Configuration VirtualBox

Créer deux VMs avec les paramètres suivants :

| Paramètre | VM1 — admin | VM2 — server |
|---|---|---|
| RAM | 2 Go minimum | 2 Go minimum |
| CPU | 2 vCPU | 2 vCPU |
| Disque | 20 Go | 20 Go |
| Réseau | Host-Only + NAT | Host-Only + NAT |
| OS | RHEL 9 | RHEL 9 |

### Configuration réseau statique — VM1 (admin.lab.local)

```bash
# Configurer l'interface Host-Only avec IP statique
nmcli con mod "enp0s8" \
  ipv4.addresses 192.168.10.1/24 \
  ipv4.method manual \
  connection.autoconnect yes

nmcli con up "enp0s8"

# Configurer l'interface NAT pour l'accès Internet
nmcli con mod "enp0s3" \
  ipv4.method auto \
  connection.autoconnect yes

nmcli con up "enp0s3"
```

### Configuration réseau statique — VM2 (server.lab.local)

```bash
nmcli con mod "enp0s8" \
  ipv4.addresses 192.168.10.2/24 \
  ipv4.method manual \
  connection.autoconnect yes

nmcli con up "enp0s8"

nmcli con mod "enp0s3" \
  ipv4.method auto \
  connection.autoconnect yes

nmcli con up "enp0s3"
```

### Configuration des hostnames

```bash
# Sur VM1
hostnamectl set-hostname admin.lab.local

# Sur VM2
hostnamectl set-hostname server.lab.local
```

### Configuration DNS local (fichier /etc/hosts)

```bash
# Ajouter sur les DEUX VMs
cat >> /etc/hosts << EOF
192.168.10.1    admin.lab.local    admin
192.168.10.2    server.lab.local   server
EOF
```

### Vérifications post-installation

```bash
# Vérifier le hostname
hostnamectl status

# Vérifier les interfaces réseau
ip addr show

# Vérifier la connectivité entre VMs
ping -c 4 192.168.10.2      # depuis admin
ping -c 4 192.168.10.1      # depuis server

# Vérifier la connectivité Internet (nécessaire pour Azure Arc)
ping -c 4 8.8.8.8
curl -s https://management.azure.com/ | head -5

# Vérifier la résolution DNS
nslookup management.azure.com
```

### 📸 Captures d'écran à faire

> **Capture 2a** — `screenshots/02a_vm1_network_config.png`
> - **Quoi :** Résultat de `ip addr show` sur admin.lab.local — interface avec IP 192.168.10.1 visible

> **Capture 2b** — `screenshots/02b_vm2_network_config.png`
> - **Quoi :** Résultat de `ip addr show` sur server.lab.local — interface avec IP 192.168.10.2 visible

> **Capture 2c** — `screenshots/02c_ping_connectivity.png`
> - **Quoi :** Résultat du `ping` entre les deux VMs — paquets reçus sans perte

> **Capture 2d** — `screenshots/02d_internet_connectivity.png`
> - **Quoi :** Résultat de `curl https://management.azure.com/` — confirmation de l'accès Internet vers Azure

---

## 🔒 Chapitre 3 — Sécurisation Linux

### Création des utilisateurs

```bash
# Créer un utilisateur dédié à l'administration (sur les DEUX VMs)
useradd -m -s /bin/bash arcadmin
passwd arcadmin

# Créer un groupe d'administration
groupadd azureadmins
usermod -aG azureadmins arcadmin
```

### Configuration sudo

```bash
# Ajouter les droits sudo sans mot de passe pour arcadmin
cat > /etc/sudoers.d/arcadmin << EOF
# Compte d'administration Azure Arc  FinSecure SA
arcadmin ALL=(ALL) NOPASSWD: ALL
EOF

chmod 440 /etc/sudoers.d/arcadmin

# Vérifier la configuration
visudo -c
```

### Configuration SSH sécurisée

```bash
# Générer une paire de clés SSH sur admin.lab.local
ssh-keygen -t ed25519 -C "arcadmin@finsecure-sa" -f ~/.ssh/id_arc

# Copier la clé publique vers server.lab.local
ssh-copy-id -i ~/.ssh/id_arc.pub arcadmin@192.168.10.2

# Sécuriser la configuration SSH sur les DEUX VMs
# 1. Sécuriser la configuration SSH (via un fichier de configuration dédié)
sudo tee /etc/ssh/sshd_config.d/01-finsecure.conf << 'EOF'
# FinSecure SA — Hardening SSH
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
Banner /etc/ssh/banner
EOF

# 2. Créer le banner d'avertissement de sécurité
sudo tee /etc/ssh/banner << 'EOF'
**********************************************************************
*  FINSECURE SA — Accès réservé au personnel autorisé               *
*  Toute connexion est enregistrée et auditée                        *
*  Conformité : RGPD | ISO 27001 | PCI-DSS                           *
**********************************************************************
EOF

# 3. Validation de la syntaxe et redémarrage du service
sudo sshd -t 

sudo systemctl restart sshd
```

### Configuration Firewalld

```bash
# Sur admin.lab.local
# 1. Autoriser uniquement le flux ENTRANT indispensable (le SSH pour l'administration)
sudo firewall-cmd --permanent --add-service=ssh

# 2. Recharger la configuration pour appliquer les changements
sudo firewall-cmd --reload

# 3. Valider la configuration de la zone active
sudo firewall-cmd --list-all

# Sur server.lab.local
# 1. Autoriser uniquement le flux ENTRANT indispensable (le SSH pour l'administration)
sudo firewall-cmd --permanent --add-service=ssh

# 2. Recharger la configuration pour appliquer les changements
sudo firewall-cmd --reload

# 3. Valider la configuration de la zone active
sudo firewall-cmd --list-all
```

### Vérification SELinux

```bash
# Vérifier le statut SELinux (doit être Enforcing)
# 1. Vérifier le statut actuel (Pas besoin de sudo pour la lecture)
getenforce
sestatus

# 2. Si le statut est "Permissive", basculer immédiatement en mode Enforcing (Sudo requis)
sudo setenforce 1

# 3. Rendre la configuration permanente de manière ROBUSTE
# On cible précisément la ligne pour éviter de corrompre le fichier si SELINUX était sur 'disabled'
sudo sed -i '/^SELINUX=/c\SELINUX=enforcing' /etc/selinux/config

# 4. Vérifier le contexte SELinux du répertoire de l'agent Arc
ls -dZ /opt/azcmagent/
ls -Z /opt/azcmagent/
```

### 📸 Captures d'écran à faire

> **Capture 3a** — `screenshots/03a_firewalld_rules.png`
> - **Quoi :** Résultat de `firewall-cmd --list-all` — ports SSH et 443 autorisés

> **Capture 3b** — `screenshots/03b_selinux_enforcing.png`
> - **Quoi :** Résultat de `sestatus` — SELinux en mode **Enforcing**

> **Capture 3c** — `screenshots/03c_ssh_key_auth.png`
> - **Quoi :** Connexion SSH réussie depuis admin vers server avec clé (sans mot de passe)

---

## ☁️ Chapitre 4 — Préparation Azure

### Convention de nommage FinSecure SA

| Ressource | Nom | Justification |
|---|---|---|
| Resource Group | `rg-finsecure-arc` | rg = resource group |
| Log Analytics Workspace | `law-finsecure-prod` | law = log analytics workspace |
| Data Collection Rule | `dcr-finsecure-linux` | dcr = data collection rule |
| Alertes | `alert-cpu-finsecure` | prefixe alert + métrique |

### Création du Resource Group

```bash
# Via Azure CLI (Cloud Shell)
az group create \
  --name rg-finsecure-arc \
  --location francecentral \
  --tags \
    Entreprise="FinSecure SA" \
    Projet="Hybrid-Governance" \
    Environnement="Production" \
    Responsable="Serge TOGNON" \
    CentreCoût="DSI-2024"
```

### Vérification

```bash
az group show \
  --name rg-finsecure-arc \
  --output table
```

### 📸 Captures d'écran à faire

> **Capture 4a** — `screenshots/04a_resource_group_created.png`
> - **Chemin :** Portail Azure → **Groupes de ressources → rg-finsecure-arc → Vue d'ensemble**
> - **Quoi :** Le groupe de ressources avec ses tags visibles (Entreprise, Projet, Responsable)

---

## 📊 Chapitre 5 — Log Analytics Workspace

### Rôle et architecture

Le **Log Analytics Workspace** est le socle central de collecte des données. Toutes les métriques et journaux collectés par Azure Monitor Agent sont envoyés ici et stockés dans des tables interrogeables en KQL.

| Table | Contenu |
|---|---|
| `Heartbeat` | Disponibilité des agents toutes les 60 secondes |
| `Syslog` | Journaux Linux (/var/log/messages, /var/log/secure) |
| `InsightsMetrics` | CPU, mémoire, disque, réseau |
| `SecurityEvent` | Événements de sécurité |

### Création du workspace

```bash
az monitor log-analytics workspace create \
  --resource-group rg-finsecure-arc \
  --workspace-name law-finsecure-prod \
  --location francecentral \
  --sku PerGB2018 \
  --retention-time 90
```

> 💡 **Coût estimé :** ~2,76 $/Go ingéré. Pour un lab avec 2 VMs, compter moins de 5 $/mois. Les 90 premiers jours de données sont conservés gratuitement jusqu'à 5 Go/mois.

### 📸 Captures d'écran à faire

> **Capture 5a** — `screenshots/05a_law_created.png`
> - **Chemin :** Portail Azure → **Log Analytics Workspaces → law-finsecure-prod → Vue d'ensemble**
> - **Quoi :** Le workspace créé avec son ID et la région France Central visibles

> **Capture 5b** — `screenshots/05b_law_tables.png`
> - **Chemin :** Portail Azure → **law-finsecure-prod → Tables**
> - **Quoi :** La liste des tables disponibles dans le workspace

---

## 🔗 Chapitre 6 — Déploiement Azure Arc

### Principe de fonctionnement

Azure Arc installe un agent `azcmagent` sur chaque serveur Linux. Cet agent :
- S'authentifie auprès d'Azure via HTTPS (port 443)
- Enregistre le serveur comme ressource Azure
- Maintient un heartbeat permanent
- Permet l'application de policies Azure
- Sert de vecteur de déploiement pour les extensions (AMA, etc.)

### Étape 1 — Générer le script d'installation depuis Azure

```bash
# Via Azure CLI
az connectedmachine generate-install-script \
  --resource-group "rg-finsecure-hybrid-prod" \
  --location "francecentral" \
  --os-type "Linux" \
  --authentication-type "service-principal" \
  --output-file "./arc-install.sh"
```

Ou depuis le portail : **Azure Arc → Machines → + Ajouter → Générer un script**

### Étape 2 — Installation sur admin.lab.local

```bash

# Connecter le serveur à Azure Arc
# Sur admin.lab.local — en tant que root ou finsecadmin
# 1. Télécharger et exécuter le script d'installation officiel de l'agent
curl -sL https://aka.ms/installazcmagent | sudo bash

# 2. Connecter le serveur à Azure Arc avec le Service Principal et la région France Central
sudo azcmagent connect \
  --service-principal-id "<ID_DE_TON_SERVICE_PRINCIPAL>" \
  --service-principal-secret "<SECRET_DE_TON_SERVICE_PRINCIPAL>" \
  --tenant-id "<VOTRE-TENANT-ID>" \
  --subscription-id "<VOTRE-SUBSCRIPTION-ID>" \
  --resource-group "rg-finsecure-hybrid-prod" \
  --location "francecentral" \
  --resource-name "admin.lab.local" \
  --cloud "AzureCloud" \
  --tags "Environment=Production,Project=Hybrid Governance,Owner=Serge TOGNON,HostRoleType=LinuxAdminServer"

# 3. Vérifier le statut de l'agent local
sudo azcmagent show
```

### Étape 3 — Installation sur server.lab.local

```bash
# Sur server.lab.local — en tant que root ou finsecadmin

# 1. Télécharger et installer l'agent local
curl -sL https://aka.ms/installazcmagent | sudo bash

# 2. Connecter le serveur à Azure Arc 
sudo azcmagent connect \
  --service-principal-id "<ID_DE_TON_SERVICE_PRINCIPAL>" \
  --service-principal-secret "<SECRET_DE_TON_SERVICE_PRINCIPAL>" \
  --tenant-id "<VOTRE-TENANT-ID>" \
  --subscription-id "<VOTRE-SUBSCRIPTION-ID>" \
  --resource-group "rg-finsecure-hybrid-prod" \
  --location "francecentral" \
  --resource-name "server.lab.local" \
  --cloud "AzureCloud" \
  --tags "Environment=Production,Project=Hybrid Governance,Owner=Serge TOGNON,HostRoleType=LinuxApplicationServer"

# 3. Vérifier le statut de l'agent
sudo azcmagent show
```

### Vérification locale de l'agent

```bash
# 1. Vérifier le statut des démons de l'agent Arc 
systemctl status himds
systemctl status gcad

# 2. Vérifier la version de l'agent installé
azcmagent version

# 3. Vérifier l'état de la connexion et l'intégration des politiques
sudo azcmagent show
```

### Résultat attendu de `azcmagent show`

```
Agent Status    : Connected
Agent Version   : 1.x.x
Resource Name   : admin-lab-local
Resource Group  : rg-finsecure-arc
Subscription    : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Location        : francecentral
```

### 📸 Captures d'écran à faire

> **Capture 6a** — `screenshots/06a_arc_script_portal.png`
> - **Chemin :** Portail Azure → **Azure Arc → Machines → Ajouter → Générer un script**
> - **Quoi :** L'interface de génération du script avec les paramètres remplis (Resource Group, région)

> **Capture 6b** — `screenshots/06b_arc_agent_install_vm1.png`
> - **Chemin :** Terminal admin.lab.local
> - **Quoi :** L'installation de l'agent azcmagent avec le message de succès final

> **Capture 6c** — `screenshots/06c_arc_connect_vm1.png`
> - **Chemin :** Terminal admin.lab.local
> - **Quoi :** La commande `azcmagent connect` avec le résultat **"Successfully onboarded"**

> **Capture 6d** — `screenshots/06d_arc_connect_vm2.png`
> - **Chemin :** Terminal server.lab.local
> - **Quoi :** Même résultat pour server.lab.local

---

## ✅ Chapitre 7 — Validation Azure Arc

### Vérification dans le portail Azure

1. Portail Azure → **Azure Arc → Machines**
2. Vérifier que les deux machines apparaissent avec le statut **Connected**

### Vérification via Azure CLI

```bash
# Lister les machines Arc connectées
az connectedmachine list \
  --resource-group rg-finsecure-arc \
  --output table

# Détail d'une machine
az connectedmachine show \
  --name admin-lab-local \
  --resource-group rg-finsecure-arc \
  --output json
```

### Résultat attendu

```
Name              ResourceGroup      Status     OS          Location
----------------  -----------------  ---------  ----------  ---------------
admin-lab-local   rg-finsecure-arc   Connected  linux       francecentral
server-lab-local  rg-finsecure-arc   Connected  linux       francecentral
```

### Informations d'inventaire collectées automatiquement

- Hostname, OS, version du kernel
- Adresses IP
- Version de l'agent Arc
- Dernière heure de connexion
- Extensions installées

### 📸 Captures d'écran à faire

> **Capture 7a** — `screenshots/07a_arc_machines_connected.png`
> - **Chemin :** Portail Azure → **Azure Arc → Machines**
> - **Quoi :** Les deux machines listées avec le statut **"Connecté"** (point vert) — admin-lab-local et server-lab-local

> **Capture 7b** — `screenshots/07b_arc_machine_details.png`
> - **Chemin :** Portail Azure → **Azure Arc → Machines → admin-lab-local → Vue d'ensemble**
> - **Quoi :** Le détail de la machine : OS, version agent, IP, dernière connexion

> **Capture 7c** — `screenshots/07c_arc_inventory.png`
> - **Chemin :** Portail Azure → **Azure Arc → Machines → admin-lab-local → Extensions**
> - **Quoi :** La liste des extensions installées sur la machine

---

## 📡 Chapitre 8 — Azure Monitor Agent (AMA)

### Rôle de l'AMA

L'Azure Monitor Agent remplace les anciens agents (MMA/OMS). Il collecte les métriques et journaux selon des **Data Collection Rules (DCR)** et les envoie au Log Analytics Workspace.

### Installation via le portail Azure Arc

1. Portail Azure → **Azure Arc → Machines → admin-lab-local**
2. Menu gauche → **Extensions**
3. Cliquer **+ Ajouter**
4. Sélectionner **Azure Monitor Agent (Linux)**
5. Cliquer **Vérifier + créer**
6. Répéter pour **server-lab-local**

### Installation via Azure CLI

```bash
# Installer AMA sur admin-lab-local
az connectedmachine extension create \
  --name AzureMonitorLinuxAgent \
  --machine-name admin-lab-local \
  --resource-group rg-finsecure-arc \
  --type AzureMonitorLinuxAgent \
  --publisher Microsoft.Azure.Monitor \
  --type-handler-version 1.0 \
  --location francecentral

# Installer AMA sur server-lab-local
az connectedmachine extension create \
  --name AzureMonitorLinuxAgent \
  --machine-name server-lab-local \
  --resource-group rg-finsecure-arc \
  --type AzureMonitorLinuxAgent \
  --publisher Microsoft.Azure.Monitor \
  --type-handler-version 1.0 \
  --location francecentral
```

### Vérification locale de l'agent

```bash
# Sur chaque VM — vérifier le service AMA
systemctl status azuremonitoragent

# Vérifier les logs de l'agent
journalctl -u azuremonitoragent -n 50

# Vérifier les processus
ps aux | grep -i azure
```

### 📸 Captures d'écran à faire

> **Capture 8a** — `screenshots/08a_ama_extension_install.png`
> - **Chemin :** Portail Azure → **Azure Arc → admin-lab-local → Extensions → Ajouter**
> - **Quoi :** La sélection de l'extension "Azure Monitor Agent" dans la liste

> **Capture 8b** — `screenshots/08b_ama_installed_both_vms.png`
> - **Chemin :** Portail Azure → **Azure Arc → Machines → admin-lab-local → Extensions**
> - **Quoi :** L'extension AzureMonitorLinuxAgent avec le statut **"Succeeded"**

> **Capture 8c** — `screenshots/08c_ama_service_running.png`
> - **Chemin :** Terminal VM
> - **Quoi :** Résultat de `systemctl status azuremonitoragent` — statut **active (running)**

---

## 📐 Chapitre 9 — Data Collection Rules (DCR)

### Rôle des DCR

Les DCR définissent **quoi collecter** et **où envoyer** les données. Elles associent des sources de données (métriques, journaux) à des destinations (Log Analytics Workspace).

### Création de la DCR depuis le portail

1. Portail Azure → **Monitor → Data Collection Rules → + Créer**
2. Nom : `dcr-finsecure-linux`
3. Resource Group : `rg-finsecure-arc`
4. Région : France Central
5. Type de plateforme : Linux

### Collecte des métriques système

Dans la DCR, ajouter les sources de données suivantes :

**Performance Counters Linux :**

| Compteur | Fréquence | Description |
|---|---|---|
| `Processor/% Processor Time` | 60s | Utilisation CPU |
| `Memory/% Used Memory` | 60s | Utilisation RAM |
| `Memory/% Available Memory` | 60s | RAM disponible |
| `LogicalDisk/% Used Space` | 300s | Espace disque utilisé |
| `LogicalDisk/Disk Read Bytes/sec` | 60s | Lectures disque |
| `LogicalDisk/Disk Write Bytes/sec` | 60s | Écritures disque |
| `Network/Total Bytes Received` | 60s | Trafic réseau entrant |
| `Network/Total Bytes Transmitted` | 60s | Trafic réseau sortant |

### Collecte des journaux Linux (Syslog)

| Facility | Niveau minimum | Logs collectés |
|---|---|---|
| `auth` | Warning | Authentifications SSH, sudo |
| `authpriv` | Warning | Connexions privilégiées |
| `cron` | Warning | Tâches planifiées |
| `daemon` | Warning | Services système |
| `kern` | Warning | Noyau Linux |
| `syslog` | Warning | Logs système généraux |
| `user` | Warning | Messages utilisateurs |

### Association de la DCR aux machines Arc

```bash
# Récupérer l'ID de la DCR
DCR_ID=$(az monitor data-collection rule show \
  --name dcr-finsecure-linux \
  --resource-group rg-finsecure-arc \
  --query id -o tsv)

# Associer admin-lab-local
az monitor data-collection rule association create \
  --name dcra-admin-lab \
  --resource "/subscriptions/<sub-id>/resourceGroups/rg-finsecure-arc/providers/Microsoft.HybridCompute/machines/admin-lab-local" \
  --data-collection-rule-id $DCR_ID

# Associer server-lab-local
az monitor data-collection rule association create \
  --name dcra-server-lab \
  --resource "/subscriptions/<sub-id>/resourceGroups/rg-finsecure-arc/providers/Microsoft.HybridCompute/machines/server-lab-local" \
  --data-collection-rule-id $DCR_ID
```

### 📸 Captures d'écran à faire

> **Capture 9a** — `screenshots/09a_dcr_created.png`
> - **Chemin :** Portail Azure → **Monitor → Data Collection Rules → dcr-finsecure-linux → Vue d'ensemble**
> - **Quoi :** La DCR créée avec ses sources de données et sa destination (law-finsecure-prod)

> **Capture 9b** — `screenshots/09b_dcr_performance_counters.png`
> - **Chemin :** Portail Azure → **dcr-finsecure-linux → Sources de données → Performance Counters**
> - **Quoi :** La liste des compteurs de performance configurés (CPU, RAM, Disque, Réseau)

> **Capture 9c** — `screenshots/09c_dcr_syslog.png`
> - **Chemin :** Portail Azure → **dcr-finsecure-linux → Sources de données → Syslog**
> - **Quoi :** Les facilities Syslog configurées (auth, authpriv, kern, daemon…)

> **Capture 9d** — `screenshots/09d_dcr_associations.png`
> - **Chemin :** Portail Azure → **dcr-finsecure-linux → Ressources**
> - **Quoi :** Les deux machines Arc associées à la DCR

---

## 🔍 Chapitre 10 — Analyse des journaux KQL

### Accès à Log Analytics

Portail Azure → **law-finsecure-prod → Journaux**

### Requête 1 — Disponibilité des agents (Heartbeat)

```kql
// Vérifier la disponibilité des deux serveurs sur les dernières 24h
Heartbeat
| where TimeGenerated > ago(24h)
| summarize
    LastSeen = max(TimeGenerated),
    HeartbeatCount = count()
    by Computer, OSType, Version
| project Computer, OSType, Version, LastSeen, HeartbeatCount
| order by Computer asc
```

### Requête 2 — Utilisation CPU

```kql
// Moyenne d'utilisation CPU par serveur sur les dernières 2h
InsightsMetrics
| where TimeGenerated > ago(2h)
| where Namespace == "Processor"
| where Name == "utilization"
| summarize AvgCPU = avg(Val) by bin(TimeGenerated, 5m), Computer
| render timechart
```

### Requête 3 — Utilisation mémoire

```kql
// Pourcentage de mémoire utilisée par serveur
InsightsMetrics
| where TimeGenerated > ago(2h)
| where Namespace == "Memory"
| where Name == "utilization"
| summarize AvgMem = avg(Val) by bin(TimeGenerated, 5m), Computer
| render timechart
```

### Requête 4 — Tentatives de connexion SSH

```kql
// Détecter les tentatives de connexion SSH (réussies et échouées)
Syslog
| where TimeGenerated > ago(24h)
| where Facility == "auth" or Facility == "authpriv"
| where SyslogMessage contains "sshd"
| project TimeGenerated, Computer, SyslogMessage
| order by TimeGenerated desc
```

### Requête 5 — Échecs d'authentification (sécurité)

```kql
// Compter les échecs de connexion par IP source
Syslog
| where TimeGenerated > ago(24h)
| where SyslogMessage contains "Failed password"
| extend SourceIP = extract(@"from (\d+\.\d+\.\d+\.\d+)", 1, SyslogMessage)
| summarize FailedAttempts = count() by SourceIP, Computer
| where FailedAttempts > 3
| order by FailedAttempts desc
```

### Requête 6 — Redémarrages système

```kql
// Détecter les redémarrages des serveurs sur les 7 derniers jours
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage contains "reboot" or SyslogMessage contains "shutdown"
| project TimeGenerated, Computer, SyslogMessage
| order by TimeGenerated desc
```

### Requête 7 — Utilisation disque

```kql
// Espace disque utilisé par partition et serveur
InsightsMetrics
| where TimeGenerated > ago(1h)
| where Namespace == "LogicalDisk"
| where Name == "FreeSpacePercentage"
| extend UsedPercent = 100 - Val
| summarize AvgUsed = avg(UsedPercent) by Computer, tostring(Tags)
| order by AvgUsed desc
```

### Requête 8 — Événements sudo (conformité)

```kql
// Auditer les commandes exécutées avec sudo
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage contains "sudo"
| where SyslogMessage contains "COMMAND"
| extend
    User = extract(@"(\w+) : TTY", 1, SyslogMessage),
    Command = extract(@"COMMAND=(.+)$", 1, SyslogMessage)
| project TimeGenerated, Computer, User, Command
| order by TimeGenerated desc
```

### 📸 Captures d'écran à faire

> **Capture 10a** — `screenshots/10a_kql_heartbeat.png`
> - **Chemin :** Portail Azure → **law-finsecure-prod → Journaux**
> - **Quoi :** Résultat de la requête Heartbeat avec les deux serveurs et leur statut

> **Capture 10b** — `screenshots/10b_kql_cpu_chart.png`
> - **Quoi :** Le graphique de la requête CPU en timechart avec les courbes des deux serveurs

> **Capture 10c** — `screenshots/10c_kql_ssh_logins.png`
> - **Quoi :** Résultats de la requête sur les connexions SSH avec les événements listés

> **Capture 10d** — `screenshots/10d_kql_sudo_audit.png`
> - **Quoi :** Résultats de la requête d'audit sudo avec les commandes exécutées

---

## 🚨 Chapitre 11 — Alertes Azure

### Alerte 1 — CPU > 80%

```bash
az monitor metrics alert create \
  --name "alert-cpu-finsecure" \
  --resource-group rg-finsecure-arc \
  --description "CPU > 80% sur serveurs FinSecure SA" \
  --condition "avg Percentage CPU > 80" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --severity 2 \
  --auto-mitigate true
```

### Alerte 2 — Serveur indisponible (Heartbeat)

Portail Azure → **Monitor → Alertes → + Créer → Règle d'alerte**

```kql
// Signal : Log Analytics — Requête personnalisée
Heartbeat
| where TimeGenerated > ago(5m)
| summarize LastHeartbeat = max(TimeGenerated) by Computer
| where LastHeartbeat < ago(5m)
```

Seuil : **Résultats > 0** → le serveur ne répond plus.

### Alerte 3 — Espace disque faible (< 20% libre)

```kql
InsightsMetrics
| where Namespace == "LogicalDisk"
| where Name == "FreeSpacePercentage"
| where Val < 20
| summarize count() by Computer
```

### Alerte 4 — Mémoire > 85%

```kql
InsightsMetrics
| where Namespace == "Memory"
| where Name == "utilization"
| where Val > 85
| summarize AvgMem = avg(Val) by Computer
```

### Configuration des groupes d'actions

1. Portail Azure → **Monitor → Groupes d'actions → + Créer**
2. Nom : `ag-finsecure-ops`
3. Ajouter une action : **Email** → votre adresse email
4. Ajouter une action : **Notification Azure** (optionnel)

### Bonnes pratiques d'alerting

| Bonne pratique | Détail |
|---|---|
| Seuils progressifs | Warning à 70%, Critical à 85% |
| Fenêtre d'évaluation | 5 min minimum pour éviter les faux positifs |
| Auto-résolution | Activer `auto-mitigate` pour fermer automatiquement |
| Groupement | Regrouper les alertes similaires |

### 📸 Captures d'écran à faire

> **Capture 11a** — `screenshots/11a_alert_cpu_created.png`
> - **Chemin :** Portail Azure → **Monitor → Alertes → Règles d'alerte**
> - **Quoi :** La liste des alertes créées avec leur statut (activé)

> **Capture 11b** — `screenshots/11b_action_group.png`
> - **Chemin :** Portail Azure → **Monitor → Groupes d'actions → ag-finsecure-ops**
> - **Quoi :** Le groupe d'action avec l'email configuré

---

## 🔄 Chapitre 12 — Azure Update Manager

### Rôle d'Update Manager

Azure Update Manager permet de **gérer les mises à jour Linux depuis Azure** sans accès direct aux serveurs. Il offre :
- Inventaire des mises à jour disponibles
- Évaluation de la conformité
- Déploiement planifié ou immédiat
- Rapport de conformité post-déploiement

### Évaluation de conformité

```bash
# Déclencher une évaluation depuis Azure CLI
az maintenance update list \
  --resource-group rg-finsecure-arc \
  --provider-name Microsoft.HybridCompute \
  --resource-type machines \
  --resource-name admin-lab-local
```

Ou depuis le portail : **Azure Update Manager → Machines → admin-lab-local → Vérifier les mises à jour**

### Inventaire des mises à jour disponibles

Portail Azure → **Update Manager → Machines → [sélectionner les deux VMs] → Vérifier les mises à jour**

### Déploiement des mises à jour

1. Portail Azure → **Update Manager → Déploiements de mises à jour → + Créer**
2. Nom : `deploy-finsecure-monthly`
3. Machines : admin-lab-local + server-lab-local
4. Planification : Premier dimanche du mois à 02h00
5. Fenêtre de maintenance : 2 heures
6. Reboot : Si nécessaire uniquement

### Vérification locale avant/après

```bash
# AVANT — lister les mises à jour disponibles
sudo dnf check-update

# AVANT — noter la version du kernel
uname -r

# Après déploiement Azure Update Manager
# Vérifier les paquets installés récemment
sudo rpm -qa --last | head -20

# Vérifier la nouvelle version du kernel
uname -r
```

### 📸 Captures d'écran à faire

> **Capture 12a** — `screenshots/12a_update_manager_overview.png`
> - **Chemin :** Portail Azure → **Azure Update Manager → Vue d'ensemble**
> - **Quoi :** Le tableau de bord général avec l'état de conformité des deux machines

> **Capture 12b** — `screenshots/12b_updates_available.png`
> - **Chemin :** Portail Azure → **Update Manager → Machines → admin-lab-local → Mises à jour**
> - **Quoi :** La liste des mises à jour disponibles classées par criticité

> **Capture 12c** — `screenshots/12c_deployment_schedule.png`
> - **Chemin :** Portail Azure → **Update Manager → Déploiements → deploy-finsecure-monthly**
> - **Quoi :** Le calendrier de déploiement avec les machines cibles et la planification

---

## 📋 Chapitre 13 — Validation des mises à jour

### Comparaison avant/après

```bash
# Enregistrer l'état AVANT sur chaque VM
sudo rpm -qa | sort > /tmp/packages_before.txt
uname -r > /tmp/kernel_before.txt
sudo dnf check-update > /tmp/updates_before.txt 2>&1

# Après déploiement Azure Update Manager
# Enregistrer l'état APRÈS
sudo rpm -qa | sort > /tmp/packages_after.txt
uname -r > /tmp/kernel_after.txt

# Comparer les deux listes
diff /tmp/packages_before.txt /tmp/packages_after.txt

# Résumé des paquets installés
echo "=== Paquets mis à jour ==="
diff /tmp/packages_before.txt /tmp/packages_after.txt | grep "^>"
```

### Vérification dans Azure Update Manager

Portail Azure → **Update Manager → Historique → [sélectionner le déploiement]**

Résultats attendus :
- Statut : **Réussi**
- Mises à jour installées : N paquets
- Reboot : Non requis (ou effectué)

### 📸 Captures d'écran à faire

> **Capture 13a** — `screenshots/13a_update_history.png`
> - **Chemin :** Portail Azure → **Update Manager → Historique des mises à jour**
> - **Quoi :** L'historique du déploiement avec le statut **"Réussi"** et le nombre de paquets installés

> **Capture 13b** — `screenshots/13b_diff_packages.png`
> - **Chemin :** Terminal VM
> - **Quoi :** Résultat de la commande `diff` montrant les paquets mis à jour

---

## 📊 Chapitre 14 — Azure Dashboards

### Création du tableau de bord

Portail Azure → **Tableaux de bord → + Créer → Personnalisé**
Nom : `dashboard-finsecure-ops`

### Tuiles recommandées

| Tuile | Source | Métrique |
|---|---|---|
| État Arc machines | Azure Arc | Statut Connected/Disconnected |
| CPU en temps réel | InsightsMetrics | % utilisation CPU |
| Mémoire en temps réel | InsightsMetrics | % utilisation RAM |
| Espace disque | InsightsMetrics | % espace libre |
| Alertes actives | Azure Monitor | Nombre d'alertes actives |
| Conformité MAJ | Update Manager | % machines conformes |
| Dernière connexion SSH | Syslog | Événements auth |
| Disponibilité 24h | Heartbeat | Uptime % |

### Requête KQL pour la tuile de disponibilité

```kql
Heartbeat
| where TimeGenerated > ago(24h)
| summarize
    Availability = round(countif(TimeGenerated > ago(24h)) * 100.0 / 1440, 1)
    by Computer
| project Computer, Availability
```

### 📸 Captures d'écran à faire

> **Capture 14a** — `screenshots/14a_dashboard_overview.png`
> - **Chemin :** Portail Azure → **Tableaux de bord → dashboard-finsecure-ops**
> - **Quoi :** Le tableau de bord complet avec toutes les tuiles affichant des données réelles

---

## 🛡️ Chapitre 15 — Audit de conformité

### Checklist d'audit Azure

```bash
# Via Azure CLI — lister toutes les ressources du projet
az resource list \
  --resource-group rg-finsecure-arc \
  --output table

# Statut des machines Arc
az connectedmachine list \
  --resource-group rg-finsecure-arc \
  --query "[].{Nom:name, Statut:status, OS:osName, Version:agentVersion}" \
  --output table

# Extensions installées sur chaque machine
az connectedmachine extension list \
  --machine-name admin-lab-local \
  --resource-group rg-finsecure-arc \
  --output table
```

### Requête KQL — Rapport de conformité

```kql
// Résumé de conformité : toutes les machines sur les 24 dernières heures
Heartbeat
| where TimeGenerated > ago(24h)
| summarize
    LastSeen = max(TimeGenerated),
    TotalHeartbeats = count()
    by Computer, OSType, Version, RemoteIPCountry
| extend
    AvailabilityScore = round(TotalHeartbeats * 100.0 / 1440, 1),
    Status = iff(LastSeen > ago(5m), "✅ En ligne", "❌ Hors ligne")
| project Computer, Status, AvailabilityScore, LastSeen, Version
```

### 📸 Captures d'écran à faire

> **Capture 15a** — `screenshots/15a_compliance_report.png`
> - **Chemin :** Portail Azure → **law-finsecure-prod → Journaux** (requête conformité)
> - **Quoi :** Le résultat de la requête de conformité avec les scores de disponibilité

---

## 🔧 Chapitre 16 — Dépannage

### Cas 1 — Agent Arc déconnecté

```bash
# Symptôme : statut "Disconnected" dans Azure Arc

# Vérifier le service
systemctl status himdsd
journalctl -u himdsd -n 50

# Vérifier la connectivité réseau vers Azure
curl -v https://management.azure.com/
curl -v https://guestnotificationservice.azure.com/

# Redémarrer l'agent
systemctl restart himdsd

# Reconnecter si nécessaire
azcmagent disconnect
azcmagent connect [options]
```

### Cas 2 — Logs non collectés dans Log Analytics

```bash
# Symptôme : aucune donnée dans les tables Syslog ou InsightsMetrics

# Vérifier le service AMA
systemctl status azuremonitoragent
journalctl -u azuremonitoragent -n 100

# Vérifier que la DCR est associée à la machine
az monitor data-collection rule association list \
  --resource-group rg-finsecure-arc \
  --output table

# Redémarrer l'agent AMA
systemctl restart azuremonitoragent

# Tester l'envoi de logs manuellement
logger -p auth.warning "TEST AMA - FinSecure SA diagnostics"
# Attendre 2-3 min puis chercher dans Log Analytics :
# Syslog | where SyslogMessage contains "TEST AMA"
```

### Cas 3 — Mises à jour bloquées

```bash
# Vérifier les dépôts actifs
sudo dnf repolist

# Vérifier la connexion à Red Hat ou repository local
sudo dnf check-update

# Vider le cache DNF
sudo dnf clean all
sudo dnf makecache

# Vérifier les logs DNF
sudo cat /var/log/dnf.log | tail -50
```

### Cas 4 — Problèmes réseau (port 443 bloqué)

```bash
# Tester les endpoints Azure Arc (port 443)
curl -v https://management.azure.com/ 2>&1 | grep -E "Connected|SSL|TLS"
curl -v https://login.microsoftonline.com/ 2>&1 | grep -E "Connected|SSL"

# Vérifier Firewalld
firewall-cmd --list-all
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --reload

# Vérifier SELinux (peut bloquer les connexions réseau de l'agent)
ausearch -m avc -ts recent | grep azcmagent
sealert -a /var/log/audit/audit.log
```

---

## ✅ Chapitre 17 — Validation finale

### Checklist complète du projet

#### Azure Arc
- [ ] admin-lab-local → statut **Connected** dans Azure Arc
- [ ] server-lab-local → statut **Connected** dans Azure Arc
- [ ] Inventaire automatique collecté (OS, IP, version agent)
- [ ] Extensions visibles dans Azure Arc

#### Azure Monitor Agent
- [ ] AMA installé sur admin-lab-local → statut **Succeeded**
- [ ] AMA installé sur server-lab-local → statut **Succeeded**
- [ ] Service `azuremonitoragent` actif sur les deux VMs

#### Data Collection Rules
- [ ] DCR `dcr-finsecure-linux` créée
- [ ] Compteurs performance configurés (CPU, RAM, Disque, Réseau)
- [ ] Syslog configuré (auth, authpriv, kern, daemon)
- [ ] DCR associée aux deux machines

#### Log Analytics
- [ ] Table `Heartbeat` → données des deux serveurs
- [ ] Table `InsightsMetrics` → métriques CPU et mémoire
- [ ] Table `Syslog` → journaux Linux collectés
- [ ] Requêtes KQL fonctionnelles

#### Alertes
- [ ] Alerte CPU > 80% créée et activée
- [ ] Alerte mémoire > 85% créée et activée
- [ ] Alerte serveur indisponible créée et activée
- [ ] Groupe d'action email configuré

#### Update Manager
- [ ] Évaluation de conformité effectuée
- [ ] Inventaire des mises à jour disponibles visible
- [ ] Déploiement planifié configuré
- [ ] Historique de déploiement documenté

#### Linux — admin.lab.local et server.lab.local
- [ ] Hostname configuré correctement
- [ ] IP statique configurée
- [ ] Connectivité Internet confirmée (port 443)
- [ ] Utilisateur `arcadmin` avec sudo créé
- [ ] SSH par clé configuré
- [ ] Authentification par mot de passe désactivée
- [ ] Firewalld actif avec règles minimales
- [ ] SELinux en mode **Enforcing**

---

## 🎓 Compétences démontrées

### Linux Administration (RHCSA)

| Compétence | Implémentation dans ce projet |
|---|---|
| Gestion des utilisateurs | Création de `arcadmin`, sudo sans mot de passe |
| Configuration réseau | IP statique avec `nmcli`, résolution DNS |
| SSH sécurisé | Clés ed25519, désactivation mot de passe, banner |
| Firewalld | Règles entrantes/sortantes, port 443 |
| SELinux | Mode Enforcing, audit des contextes |
| Systemd | Gestion des services Arc et AMA |
| Administration RHEL 9 | DNF, RPM, journald, /var/log/* |

### Azure Administration (AZ-104)

| Compétence | Implémentation |
|---|---|
| Resource Management | Resource Group avec tags, convention de nommage |
| Azure Arc | Connexion de serveurs Linux on-premises |
| Azure Monitor | DCR, métriques, alertes |
| Log Analytics | Tables, requêtes KQL, rétention |
| Update Manager | Inventaire, conformité, déploiement |
| Governance | Inventaire centralisé, audit de conformité |

### Hybrid Cloud

| Compétence | Implémentation |
|---|---|
| Connectivity | HTTPS 443, agents Arc et AMA |
| Unified Management | Un seul portail pour on-premises et cloud |
| Security | SELinux + Firewalld + SSH + Azure RBAC |
| Monitoring | Observabilité unifiée on-premises/Azure |

---

## 📁 Structure du dépôt

```
05-azure-arc-hybrid-governance/
│
├── README.md                          ← Ce fichier
│
├── screenshots/
│   ├── 02a_vm1_network_config.png
│   ├── 02b_vm2_network_config.png
│   ├── 02c_ping_connectivity.png
│   ├── 02d_internet_connectivity.png
│   ├── 03a_firewalld_rules.png
│   ├── 03b_selinux_enforcing.png
│   ├── 03c_ssh_key_auth.png
│   ├── 04a_resource_group_created.png
│   ├── 05a_law_created.png
│   ├── 05b_law_tables.png
│   ├── 06a_arc_script_portal.png
│   ├── 06b_arc_agent_install_vm1.png
│   ├── 06c_arc_connect_vm1.png
│   ├── 06d_arc_connect_vm2.png
│   ├── 07a_arc_machines_connected.png
│   ├── 07b_arc_machine_details.png
│   ├── 07c_arc_inventory.png
│   ├── 08a_ama_extension_install.png
│   ├── 08b_ama_installed_both_vms.png
│   ├── 08c_ama_service_running.png
│   ├── 09a_dcr_created.png
│   ├── 09b_dcr_performance_counters.png
│   ├── 09c_dcr_syslog.png
│   ├── 09d_dcr_associations.png
│   ├── 10a_kql_heartbeat.png
│   ├── 10b_kql_cpu_chart.png
│   ├── 10c_kql_ssh_logins.png
│   ├── 10d_kql_sudo_audit.png
│   ├── 11a_alert_cpu_created.png
│   ├── 11b_action_group.png
│   ├── 12a_update_manager_overview.png
│   ├── 12b_updates_available.png
│   ├── 12c_deployment_schedule.png
│   ├── 13a_update_history.png
│   ├── 13b_diff_packages.png
│   ├── 14a_dashboard_overview.png
│   └── 15a_compliance_report.png
│
└── scripts/
    ├── install_arc_agent.sh           ← Script installation Azure Arc
    ├── configure_linux_security.sh   ← Hardening SSH/Firewalld/SELinux
    ├── kql_queries.md                 ← Toutes les requêtes KQL
    └── cleanup.sh                     ← Suppression des ressources
```

---

## 🔗 Ressources

- [Documentation Azure Arc](https://learn.microsoft.com/azure/azure-arc/servers/overview)
- [Azure Monitor Agent](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-overview)
- [Data Collection Rules](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-rule-overview)
- [Azure Update Manager](https://learn.microsoft.com/azure/update-manager/overview)
- [KQL Reference](https://learn.microsoft.com/azure/data-explorer/kusto/query/)
- [RHCSA Exam Objectives](https://www.redhat.com/en/services/training/ex200-red-hat-certified-system-administrator-rhcsa-exam)

---

*Réalisé par **Serge TOGNON** — Administrateur Cloud Azure Certifié (AZ-104) | Candidat RHCSA*
*LinkedIn : [Serge TOGNON](https://www.linkedin.com/in/serge-tognon)*

