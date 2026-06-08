# 🏢 Gouvernance et Supervision Hybride de Serveurs Linux
## Azure Arc · Azure Monitor · Update Manager

> **Auteur :** Serge TOGNON — Administrateur Cloud Azure Certifié (AZ-104) | Candidat RHCSA
> [![LinkedIn](https://img.shields.io/badge/LinkedIn-Serge_TOGNON-0077B5?logo=linkedin&logoColor=white)](www.linkedin.com/in/serge-tognon-a63443187)
> [![AZ-104](https://img.shields.io/badge/Microsoft-AZ--104_Certified-0078D4?logo=microsoftazure&logoColor=white)](https://learn.microsoft.com/certifications/azure-administrator/)
> [![RHCSA](https://img.shields.io/badge/Red_Hat-Candidat_RHCSA-EE0000?logo=redhat&logoColor=white)](https://www.redhat.com/en/services/certification/rhcsa)

---

## 📋 Table des matières

1. [Présentation du projet](#-chapitre-1--présentation-du-projet)
2. [Installation des VM RHEL 9](#-chapitre-2--installation-des-vm-rhel-9)
3. [Sécurisation Linux (Hardening)](#-chapitre-3--sécurisation-linux)
4. [Préparation Azure](#-chapitre-4--préparation-azure)
5. [Log Analytics Workspace](#-chapitre-5--log-analytics-workspace)
6. [Déploiement Azure Arc](#-chapitre-6--déploiement-azure-arc)
7. [Validation Azure Arc](#-chapitre-7--validation-azure-arc)
8. [Azure Monitor Agent (AMA)](#-chapitre-8--azure-monitor-agent-ama)
9. [Data Collection Rules (DCR)](#-chapitre-9--data-collection-rules-dcr)
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

**FinSecure SA** est une société de services financiers basée à Cotonou, opérant dans l'espace UEMOA. Elle gère des données sensibles hautement soumises aux réglementations **RGPD**, **ISO 27001** et **PCI-DSS**.

La Direction des Systèmes d'Information (DSI) administre plusieurs serveurs Linux hébergés dans un datacenter local. Face à la complexification de l'infrastructure et aux exigences de conformité croissantes, le DSI a décidé de **moderniser l'administration et d'unifier la gouvernance sans migration immédiate vers le cloud public** une approche hybride via **Azure Arc**.

### Problématiques résolues

| Problème actuel | Solution apportée |
|---|---|
| Administration manuelle serveur par serveur | Gestion centralisée via **Azure Arc** |
| Aucune supervision en temps réel | **Azure Monitor** — métriques & alertes |
| Journaux dispersés et volatils | Collecte centralisée dans **Log Analytics Workspace** |
| Mises à jour non coordonnées (risques de failles) | Gestion automatisée via **Azure Update Manager** |
| Aucun inventaire centralisé | Inventaire automatique et dynamique via le plan de contrôle Azure |
| Conformité impossible à auditer | Tableaux de bord unifiés et rapports de gouvernance Azure |

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
                 │       FinSecure SA  Cotonou         │
                 │                                      │
                 │  ┌─────────────────────────────┐    │
                 │  │  VM1 : admin.lab.local        │    │
                 │  │  IP  : 192.168.10.1           │    │
                 │  │  OS  : RHEL 9                 │    │
                 │  │  Rôle: Bastion SSH / Admin    │    │
                 │  │  Agent Arc  ✅                │    │
                 │  │  Agent AMA  ✅                │    │
                 │  └─────────────────────────────┘    │
                 │              │  SSH :22              │
                 │              ▼                       │
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
| VMs → Azure Arc | HTTPS | 443 | Enregistrement, heartbeat et gestion de configuration |
| VMs → Log Analytics | HTTPS | 443 | Envoi sécurisé des métriques et journaux système |
| VMs → Update Manager | HTTPS | 443 | Évaluation des correctifs et déploiement des packages |
| admin.lab.local → server.lab.local | SSH | 22 | Administration interne locale (rebond bastion) |

### Environnement technique

| Composant | Détail |
|---|---|
| Hyperviseur | VirtualBox 7.2.8 |
| OS Invités | Red Hat Enterprise Linux 9 (RHEL 9) |
| VM Admin | `admin.lab.local` IP : 192.168.10.1 |
| VM Serveur | `server.lab.local`  IP : 192.168.10.2 |
| Région Azure | France Central (`francecentral`) |
| Resource Group | `rg-finsecure-arc` |

---

## 🖥️ Chapitre 2 — Installation des VM RHEL 9

### Configuration VirtualBox

Créer deux machines virtuelles avec les paramètres suivants :

| Paramètre | VM1 — admin.lab.local | VM2 — server.lab.local |
|---|---|---|
| RAM | 2 Go minimum | 2 Go minimum |
| vCPU | 2 | 2 |
| Disque | 20 Go (allocation dynamique) | 20 Go (allocation dynamique) |
| Carte réseau 1 | NAT (accès Internet sortant) | NAT (accès Internet sortant) |
| Carte réseau 2 | Host-Only (réseau privé) | Host-Only (réseau privé) |

### Configuration réseau statique — VM1 (admin.lab.local)

```bash
# Interface Host-Only avec IP statique
sudo nmcli con mod "Internal-LAN" \
  ipv4.addresses 192.168.10.1/24 \
  ipv4.method manual \
  ipv4.never-default yes \
  connection.autoconnect yes

sudo nmcli con up "enp0s8"

# Interface NAT pour l'accès Internet
sudo nmcli con mod "enp0s3" \
  ipv4.method auto \
  connection.autoconnect yes

sudo nmcli con up "enp0s3"
```
<img width="650" height="311" alt="2a" src="https://github.com/user-attachments/assets/80d3a62f-d367-4dd3-b400-dbbc0a3e5377" />


---

### Configuration réseau statique — VM2 (server.lab.local)

```bash
# Interface Host-Only avec IP statique
sudo nmcli con mod "enp0s8" \
  ipv4.addresses 192.168.10.2/24 \
  ipv4.method manual \
  ipv4.never-default yes \
  connection.autoconnect yes

sudo nmcli con up "enp0s8"

# Interface NAT pour l'accès Internet
sudo nmcli con mod "enp0s3" \
  ipv4.method auto \
  connection.autoconnect yes

sudo nmcli con up "enp0s3"
```

<img width="656" height="404" alt="2b" src="https://github.com/user-attachments/assets/cbf259c5-8905-4947-8c30-3f37ddbd4006" />


---

### Configuration des hostnames et DNS local

```bash
# Appliquer le FQDN sur chaque VM
# Sur VM1 :
sudo hostnamectl set-hostname admin.lab.local

# Sur VM2 :
sudo hostnamectl set-hostname server.lab.local

# Ajouter la résolution locale sur les DEUX VMs
sudo tee -a /etc/hosts << EOF
192.168.10.1    admin.lab.local    admin
192.168.10.2    server.lab.local   server
EOF
```
<img width="662" height="193" alt="2a&#39;" src="https://github.com/user-attachments/assets/a569b152-3a1e-4ad2-8b4d-4dfe9b804809" />
<img width="692" height="197" alt="2b&#39;" src="https://github.com/user-attachments/assets/0939e3c1-d790-4752-883b-953e735a1fad" />

--
### Vérifications de connectivité

```bash
# Connectivité interne entre VMs
ping -c 4 server.lab.local    # depuis admin.lab.local

# Connectivité Internet (requis pour Azure Arc)
ping -c 4 8.8.8.8
curl -sI https://management.azure.com/ | head -n 5
```
<img width="688" height="401" alt="2c" src="https://github.com/user-attachments/assets/e5e12bdf-08ea-4e3e-a46f-fa62070f8c97" />

---

## 🔒 Chapitre 3 — Sécurisation Linux

### Gestion des utilisateurs et privilèges

```bash
# Créer un compte d'administration non-root dédié (sur les DEUX VMs)
sudo useradd -m -s /bin/bash arcadmin
sudo passwd arcadmin

# Créer un groupe d'administration dédié
sudo groupadd azureadmins
sudo usermod -aG azureadmins arcadmin

# Configurer une isolation des privilèges sudo stricte
sudo tee /etc/sudoers.d/arcadmin << 'EOF'
# Compte d'administration Azure Arc — FinSecure SA
arcadmin ALL=(ALL) NOPASSWD: ALL
EOF

sudo chmod 440 /etc/sudoers.d/arcadmin

# Valider la syntaxe sudoers
sudo visudo -c
```
<img width="645" height="324" alt="2d" src="https://github.com/user-attachments/assets/328b72bb-cf88-4bb2-956e-e2c19be7b4b2" />
<img width="641" height="295" alt="2d&#39;" src="https://github.com/user-attachments/assets/3ded7433-16a2-488f-beda-33358af22fcb" />


### Authentification SSH par clé (depuis arcadmin sur VM1)

```bash
# 1. Générer une paire de clés asymétriques sécurisées (Ed25519)
ssh-keygen -t ed25519 -C "Arc_projet@Finsecure-sa" -f ~/.ssh/id_arc -N ""

# 2. Copier la clé publique vers le serveur métier
ssh-copy-id -i ~/.ssh/id_arc.pub arcadmin@192.168.10.2
```
<img width="650" height="321" alt="3-c" src="https://github.com/user-attachments/assets/66b629cb-d157-4362-a747-3e8eb634f736" />


---

### Durcissement du démon SSH

```bash
# Appliquer les restrictions SSH (sur les DEUX VMs)
sudo tee /etc/ssh/sshd_config.d/01-finsecure.conf << 'EOF'
# FinSecure SA — Hardening SSH | Conformité RGPD / ISO 27001 / PCI-DSS
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
Banner /etc/ssh/banner
EOF

# Créer le bandeau légal d'avertissement
sudo tee /etc/ssh/banner << 'EOF'
**********************************************************************
*  FINSECURE SA — Accès réservé au personnel autorisé               *
*  Toute connexion est enregistrée et auditée                        *
*  Conformité : RGPD | ISO 27001 | PCI-DSS                           *
**********************************************************************
EOF

# Valider la syntaxe puis redémarrer le service
sudo sshd -t && sudo systemctl restart sshd
```

### Configuration Firewalld

```bash
# Restreindre les flux entrants au seul trafic SSH légitime (sur les DEUX VMs)
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --remove-service=dhcpv6-client
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```
<img width="682" height="417" alt="3a" src="https://github.com/user-attachments/assets/6bced4aa-31da-4f4b-a0dd-e68436d247bd" />
<img width="661" height="350" alt="3a&#39;" src="https://github.com/user-attachments/assets/b30aaf9f-65d1-46c5-849f-dbd5dee4e141" />



---

### Durcissement SELinux (Mandatory Access Control)
 **Sur les deux VMs**
```bash
# Activer immédiatement le mode Enforcing
sudo setenforce 1

# Rendre la configuration persistante au reboot
sudo sed -i '/^SELINUX=/c\SELINUX=enforcing' /etc/selinux/config

# Si SELinux était préalablement désactivé, forcer un relabel au prochain démarrage
# sudo touch /.autorelabel && sudo reboot

# Vérifier le statut
sestatus
```
<img width="645" height="263" alt="3b" src="https://github.com/user-attachments/assets/0df30927-d198-4f6a-8415-77f0933a6b57" />

<img width="642" height="337" alt="3b&#39;" src="https://github.com/user-attachments/assets/b01c5496-2be6-4ba0-bc56-a3388ec82a83" />

---

## ☁️ Chapitre 4 — Préparation Azure

### Convention de nommage FinSecure SA

| Type de ressource | Préfixe | Nom appliqué |
|---|---|---|
| Resource Group | `rg-` | `rg-finsecure-arc` |
| Log Analytics Workspace | `law-` | `law-finsecure-prod` |
| Data Collection Rule | `dcr-` | `dcr-finsecure-linux` |
| Règles d'alertes | `alert-` | `alert-[métrique]-finsecure` |
| Groupe d'actions | `ag-` | `ag-finsecure-ops` |

### Création du Resource Group

```bash
az group create \
  --name rg-finsecure-arc \
  --location francecentral \
  --tags \
    Entreprise="FinSecure SA" \
    Projet="Hybrid-Governance" \
    Environnement="Production" \
    Responsable="Serge TOGNON" \
    CentreCoût="DSI-2026"

# Vérification
az group show --name rg-finsecure-arc --output table
```
<img width="949" height="82" alt="4a" src="https://github.com/user-attachments/assets/bd4f6891-9761-411d-970a-bc3e5f58f897" />
<img width="923" height="415" alt="4a&#39;" src="https://github.com/user-attachments/assets/3abad903-af63-4fb4-90c1-5a3add9e3dce" />


---

## 📊 Chapitre 5 — Log Analytics Workspace

### Architecture des données centralisées

Le Log Analytics Workspace est le puits central de logs. Azure Monitor Agent (AMA) y pousse les flux structurés selon les tables suivantes :

| Table | Type de télémétrie |
|---|---|
| `Heartbeat` | État de santé et présence réseau (toutes les 60s) |
| `Syslog` | Journaux système Linux (`/var/log/messages`, `/var/log/secure`) |
| `InsightsMetrics` | Compteurs de performance (CPU, RAM, Disque, Réseau) |
| `SecurityEvent` | Événements de sécurité |

### Déploiement du workspace

```bash
az monitor log-analytics workspace create \
  --resource-group rg-finsecure-arc \
  --workspace-name law-finsecure-prod \
  --location francecentral \
  --sku PerGB2018 \
  --retention-time 90
```
<img width="960" height="217" alt="5a" src="https://github.com/user-attachments/assets/89221511-2add-43dc-8fa8-3660201aa0be" />
<img width="917" height="356" alt="5b" src="https://github.com/user-attachments/assets/57682316-d08d-43c4-a228-ed9c16e83aac" />
<img width="916" height="391" alt="5c" src="https://github.com/user-attachments/assets/9edaf8f1-c1e3-481c-8f22-2dd1426ee327" />

----

## 🔗 Chapitre 6 — Déploiement Azure Arc

### Principe de fonctionnement

Azure Arc installe un agent `azcmagent` sur chaque serveur Linux. Cet agent :
- S'authentifie auprès d'Azure via HTTPS (port 443)
- Enregistre le serveur comme ressource Azure managée
- Maintient un heartbeat permanent vers Azure Resource Manager
- Permet l'application de policies Azure Policy
- Sert de vecteur de déploiement pour les extensions (AMA, etc.)
### Installation de l'extension
az extension add --name connectedmachine
az extension list --output table
# → connectedmachine doit apparaître dans la liste
<img width="960" height="196" alt="5d" src="https://github.com/user-attachments/assets/61b1bbab-737a-4f34-9b7c-27b35310b08e" />


### Étape 1 — Génération du script d'onboarding
Utiliser le portail Azure pour créer un script qui automatise le téléchargement et l'installation de l'agent et établit la connexion avec Azure Arc.
Depuis le portail : **Azure Arc → Machines → + Ajouter existant → Générer un script**

<img width="845" height="401" alt="6a" src="https://github.com/user-attachments/assets/565698e1-a301-41ed-aab4-1fb69e198c77" />
<img width="960" height="326" alt="6b" src="https://github.com/user-attachments/assets/7670b9aa-ec38-4d90-9b4f-3c064b5dc61d" />

---

### Étape 2 — Installation sur admin.lab.local

```bash
# Télécharger et installer le binaire de l'agent hybride
wget https://gbl.his.arc.azure.com/azcmagent-linux -O install_linux_azcmagent.sh
# Exécuter l'installation
sudo bash install_linux_azcmagent.sh
```
<img width="651" height="184" alt="6c" src="https://github.com/user-attachments/assets/d31ace9a-cacd-4a11-a803-71516a627665" />

```bash
# Connexion au plan de contrôle Azure Resource Manager
  sudo azcmagent connect \
  --tenant-id "b3818c8a-2ac2-44a2-8e36-4ac319fbf2ed" \
  --subscription-id "1c677bf6-bd7e-4e0f-8ee7-409c32dfb66b" \
  --resource-group "rg-finsecure-arc" \
  --location "francecentral" \
  --resource-name "admin-lab-local" \
  --cloud "AzureCloud" \
  --tags "Environment=Production,Project=Hybrid Governance,Owner=Serge TOGNON,HostRoleType=LinuxAdminServer"
```

> **📸 Capture 6c** — `screenshots/06c_arc_connect_vm1.png`
> Le message **"Successfully onboarded resource to Azure"** doit apparaître avec le nom `admin-lab-local`.

---

### Étape 3 — Installation sur server.lab.local

```bash
# Télécharger et installer le binaire de l'agent hybride
wget https://gbl.his.arc.azure.com/azcmagent-linux -O install_linux_azcmagent.sh
# Exécuter l'installation
sudo bash install_linux_azcmagent.sh

# Connecter le serveur à Azure Arc
sudo azcmagent connect \
  --tenant-id "<TENANT_ID>" \
  --subscription-id "<SUBSCRIPTION_ID>" \
  --resource-group "rg-finsecure-arc" \
  --location "francecentral" \
  --resource-name "server-lab-local" \
  --cloud "AzureCloud" \
  --tags "Environment=Production,Project=Hybrid Governance,Owner=Serge TOGNON,HostRoleType=LinuxApplicationServer"
```

> **📸 Capture 6d** — `screenshots/06d_arc_connect_vm2.png`
> Le message **"Successfully onboarded resource to Azure"** doit apparaître avec le nom `server-lab-local`.

---

### Diagnostic local de l'agent

```bash
# Vérifier le statut des démons Arc sous SELinux Enforcing
sudo azcmagent show

# Vérifier les services
systemctl status himds
systemctl status gcad
```

Résultat attendu de `azcmagent show` :

```
Agent Status    : Connected
Agent Version   : 1.x.x
Resource Name   : admin-lab-local
Resource Group  : rg-finsecure-arc
Location        : francecentral
```

---

## ✅ Chapitre 7 — Validation Azure Arc

### Vérification via Azure CLI

```bash
# Lister les machines Arc connectées
az connectedmachine list \
  --resource-group rg-finsecure-arc \
  --output table
```

Résultat attendu :

```
Name              ResourceGroup      Status     OS      Location
----------------  -----------------  ---------  ------  -------------
admin-lab-local   rg-finsecure-arc   Connected  linux   francecentral
server-lab-local  rg-finsecure-arc   Connected  linux   francecentral
```

> **📸 Capture 7a** — `screenshots/07a_arc_machines_connected.png`
> Chemin portail : `Azure Arc → Machines`
> Les deux machines doivent afficher le **point vert "Connecté"** avec la région `France Central`.

> **📸 Capture 7b** — `screenshots/07b_arc_machine_details.png`
> Chemin portail : `Azure Arc → Machines → admin-lab-local → Vue d'ensemble`
> Le panneau doit afficher : nom d'hôte, OS (RHEL 9.x), version de l'agent, adresse IP (192.168.10.1), et date de dernière connexion.

> **📸 Capture 7c** — `screenshots/07c_arc_inventory.png`
> Chemin portail : `Azure Arc → Machines → admin-lab-local → Extensions`
> Cette capture sert de référence **"avant AMA"** — la liste des extensions peut être vide à cette étape.

---

## 📡 Chapitre 8 — Azure Monitor Agent (AMA)

### Rôle de l'AMA

L'extension `AzureMonitorLinuxAgent` remplace les anciens agents hérités (MMA/OMS). C'est le vecteur sécurisé de collecte des métriques et journaux, piloté par des **Data Collection Rules (DCR)** et transmettant les données vers le Log Analytics Workspace.

### Déploiement via Azure CLI

```bash
# Déploiement sur admin-lab-local
az connectedmachine extension create \
  --name AzureMonitorLinuxAgent \
  --machine-name admin-lab-local \
  --resource-group rg-finsecure-arc \
  --type AzureMonitorLinuxAgent \
  --publisher Microsoft.Azure.Monitor \
  --type-handler-version 1.0 \
  --location francecentral

# Déploiement sur server-lab-local
az connectedmachine extension create \
  --name AzureMonitorLinuxAgent \
  --machine-name server-lab-local \
  --resource-group rg-finsecure-arc \
  --type AzureMonitorLinuxAgent \
  --publisher Microsoft.Azure.Monitor \
  --type-handler-version 1.0 \
  --location francecentral
```

> **📸 Capture 8a** — `screenshots/08a_ama_extension_install.png`
> Chemin portail : `Azure Arc → Machines → admin-lab-local → Extensions → Ajouter`
> La fiche de l'extension **"Azure Monitor Agent"** avec l'éditeur `Microsoft.Azure.Monitor` doit être visible.

> **📸 Capture 8b** — `screenshots/08b_ama_installed_both_vms.png`
> Chemin portail : `Azure Arc → Machines → admin-lab-local → Extensions`
> L'extension `AzureMonitorLinuxAgent` doit afficher le statut **"Succès"** ✅ avec son numéro de version.

---

### Vérification locale du service AMA

```bash
# Vérifier le service sur chaque VM
sudo systemctl status azuremonitoragent

# Consulter les logs de l'agent
journalctl -u azuremonitoragent -n 50

# Vérifier les processus actifs
ps aux | grep -i azure
```

> **📸 Capture 8c** — `screenshots/08c_ama_service_running.png`
> La commande `systemctl status azuremonitoragent` doit afficher **`active (running)`** en vert, sans erreur dans les dernières lignes de journald.

---

## 📐 Chapitre 9 — Data Collection Rules (DCR)

### Rôle des DCR

Les DCR définissent **quoi collecter** et **où envoyer** les données. Elles associent des sources (métriques système, journaux Syslog) à des destinations (Log Analytics Workspace), avec un contrôle granulaire de la fréquence et du niveau de sévérité.

### Compteurs de performance (fréquence : 60s)

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

### Flux de logs Syslog (niveau minimum : Warning)

| Facility | Logs collectés |
|---|---|
| `auth` | Authentifications SSH, sudo |
| `authpriv` | Connexions privilégiées |
| `cron` | Tâches planifiées |
| `daemon` | Services système |
| `kern` | Noyau Linux |
| `syslog` | Logs système généraux |
| `user` | Messages utilisateurs |

> 💡 Ces 7 facilities couvrent les exigences d'audit **PCI-DSS** relatives à la traçabilité des accès et des privilèges.

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

> **📸 Capture 9a** — `screenshots/09a_dcr_created.png`
> Chemin portail : `Monitor → Data Collection Rules → dcr-finsecure-linux → Vue d'ensemble`
> Les sources (Performance Counters + Syslog) et la destination `law-finsecure-prod` doivent être clairement indiquées.

> **📸 Capture 9b** — `screenshots/09b_dcr_performance_counters.png`
> Les 8 compteurs de performance avec leurs fréquences d'échantillonnage doivent être visibles.

> **📸 Capture 9c** — `screenshots/09c_dcr_syslog.png`
> Les 7 facilities Syslog avec le niveau minimum `Warning` doivent être visibles.

> **📸 Capture 9d** — `screenshots/09d_dcr_associations.png`
> Les deux machines `admin-lab-local` et `server-lab-local` doivent apparaître sous la DCR.

---

## 🔍 Chapitre 10 — Analyse des journaux KQL

### Accès à Log Analytics

Portail Azure → **`law-finsecure-prod` → Journaux**

> ⏱️ **Important :** Attendre **15 à 30 minutes** après la configuration de la DCR avant d'exécuter les requêtes. Les premières données mettent quelques minutes à arriver dans le workspace.

---

### Requête 1 — Heartbeat et disponibilité des assets hybrides

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

> **📸 Capture 10a** — `screenshots/10a_kql_heartbeat.png`
> Un tableau avec les **deux serveurs**, leur OS, version d'agent, dernière connexion et nombre de heartbeats doit apparaître.

---

### Requête 2 — Graphique de charge CPU (Timechart)

```kql
// Moyenne d'utilisation CPU par serveur sur les dernières 2h
InsightsMetrics
| where TimeGenerated > ago(2h)
| where Namespace == "Processor"
| where Name == "utilization"
| summarize AvgCPU = avg(Val) by bin(TimeGenerated, 5m), Computer
| render timechart
```

> **📸 Capture 10b** — `screenshots/10b_kql_cpu_chart.png`
> Un graphique linéaire avec **deux courbes** (une par serveur) montrant l'évolution du % CPU sur 2 heures.

---

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

---

### Requête 4 — Journalisation des flux d'accès SSH

```kql
// Détecter les tentatives de connexion SSH (réussies et échouées)
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "sshd"
| project TimeGenerated, Computer, SyslogMessage
| order by TimeGenerated desc
```

> **📸 Capture 10c** — `screenshots/10c_kql_ssh_logins.png`
> Des événements `sshd` avec les messages `Accepted publickey`, `Failed password`, etc. doivent être visibles.

---

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

---

### Requête 6 — Redémarrages système

```kql
// Détecter les redémarrages des serveurs sur les 7 derniers jours
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage contains "reboot" or SyslogMessage contains "shutdown"
| project TimeGenerated, Computer, SyslogMessage
| order by TimeGenerated desc
```

---

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

---

### Requête 8 — Traçabilité des élévations de privilèges (Audit PCI-DSS)

```kql
// Auditer les commandes exécutées avec sudo
Syslog
| where TimeGenerated > ago(7d)
| where SyslogMessage has "sudo" and SyslogMessage has "COMMAND"
| extend
    User = extract(@"(\w+) : TTY", 1, SyslogMessage),
    Command = extract(@"COMMAND=(.+)$", 1, SyslogMessage)
| project TimeGenerated, Computer, User, Command
| order by TimeGenerated desc
```

> **📸 Capture 10d** — `screenshots/10d_kql_sudo_audit.png`
> Un tableau avec les colonnes `TimeGenerated`, `Computer`, `User`, `Command` doit afficher les commandes sudo exécutées pendant le lab.

---

## 🚨 Chapitre 11 — Alertes Azure

### Étape 1 — Déploiement du Groupe d'actions

> Le canal de notification est provisionné **avant** les règles d'évaluation pour respecter les dépendances de déploiement.

```bash
az monitor action-group create \
  --name "ag-finsecure-ops" \
  --resource-group "rg-finsecure-arc" \
  --short-name "FinSecureOps" \
  --action email sysadmin-alerts arc-alerts@finsecure-sa.com
```

> **📸 Capture 11b** — `screenshots/11b_action_group.png`
> Chemin portail : `Monitor → Groupes d'actions → ag-finsecure-ops`
> L'action Email doit être configurée avec l'adresse destinataire visible et le statut activé.

---

### Étape 2 — Création des alertes de seuils critiques

**Alerte 1 — CPU > 80%**

```bash
az monitor metrics alert create \
  --name "alert-cpu-finsecure" \
  --resource-group rg-finsecure-arc \
  --description "CPU > 80% sur les serveurs FinSecure SA" \
  --condition "avg Percentage CPU > 80" \
  --window-size 5m \
  --evaluation-frequency 1m \
  --severity 2 \
  --auto-mitigate true \
  --action "ag-finsecure-ops"
```

**Alerte 2 — Serveur indisponible (Heartbeat)**

```kql
// Signal Log Analytics — Requête personnalisée
// Seuil : Résultats > 0 → le serveur ne répond plus
Heartbeat
| where TimeGenerated > ago(5m)
| summarize LastHeartbeat = max(TimeGenerated) by Computer
| where LastHeartbeat < ago(5m)
```

**Alerte 3 — Espace disque faible (< 20% libre)**

```kql
InsightsMetrics
| where Namespace == "LogicalDisk"
| where Name == "FreeSpacePercentage"
| where Val < 20
| summarize count() by Computer
```

**Alerte 4 — Mémoire > 85%**

```kql
InsightsMetrics
| where Namespace == "Memory"
| where Name == "utilization"
| where Val > 85
| summarize AvgMem = avg(Val) by Computer
```

> **📸 Capture 11a** — `screenshots/11a_alert_cpu_created.png`
> Chemin portail : `Monitor → Alertes → Règles d'alerte`
> Les 4 règles d'alerte doivent être listées avec leur **sévérité** et leur statut **"Activé"**.

### Bonnes pratiques d'alerting

| Bonne pratique | Détail |
|---|---|
| Seuils progressifs | Warning à 70%, Critical à 85% |
| Fenêtre d'évaluation | 5 min minimum pour éviter les faux positifs |
| Auto-résolution | Activer `auto-mitigate` pour clore automatiquement |
| Groupement d'alertes | Regrouper les alertes similaires dans le même groupe d'actions |

---

## 🔄 Chapitre 12 — Azure Update Manager

### Rôle d'Update Manager

Azure Update Manager permet de **gérer les mises à jour Linux directement depuis Azure**, sans accès direct aux serveurs. Il offre :
- Inventaire des mises à jour disponibles par criticité
- Évaluation de la conformité PCI-DSS
- Déploiement planifié ou immédiat via `dnf update`
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

Ou depuis le portail : **Azure Update Manager → Machines → [sélectionner les VMs] → Vérifier les mises à jour**

> **📸 Capture 12a** — `screenshots/12a_update_manager_overview.png`
> Chemin portail : `Azure Update Manager → Vue d'ensemble`
> Le tableau de bord doit afficher le nombre de machines évaluées (2) et les catégories de mises à jour disponibles (Critical, Security, Other).

> **📸 Capture 12b** — `screenshots/12b_updates_available.png`
> La liste des paquets avec mises à jour disponibles doit être classée par criticité (Critical en rouge, Security en orange, Other en gris).

---

### Planification du déploiement

1. Portail Azure → **Update Manager → Déploiements → + Créer**
2. Nom : `deploy-finsecure-monthly`
3. Machines cibles : `admin-lab-local` + `server-lab-local`
4. Planification : Premier dimanche du mois à 02h00
5. Fenêtre de maintenance : 2 heures
6. Reboot : Si nécessaire uniquement

> **📸 Capture 12c** — `screenshots/12c_deployment_schedule.png`
> La configuration doit afficher les deux machines cibles, la planification mensuelle, la fenêtre de 2 heures et l'option de reboot.

---

## 📋 Chapitre 13 — Validation des mises à jour

### Comparaison avant / après déploiement

```bash
# AVANT — Enregistrer l'état initial (sur chaque VM)
sudo rpm -qa | sort > /tmp/packages_before.txt
uname -r > /tmp/kernel_before.txt
sudo dnf check-update > /tmp/updates_before.txt 2>&1

# APRÈS — Enregistrer l'état post-déploiement
sudo rpm -qa | sort > /tmp/packages_after.txt
uname -r > /tmp/kernel_after.txt

# Comparer les deux états
diff /tmp/packages_before.txt /tmp/packages_after.txt

# Lister uniquement les paquets mis à jour
echo "=== Paquets mis à jour ==="
diff /tmp/packages_before.txt /tmp/packages_after.txt | grep "^>"

# Vérifier les paquets installés récemment
sudo rpm -qa --last | head -20
```

> **📸 Capture 13a** — `screenshots/13a_update_history.png`
> Chemin portail : `Update Manager → Historique des mises à jour`
> L'entrée `deploy-finsecure-monthly` doit afficher le statut **"Réussi"** ✅, le nombre de paquets installés et la durée d'exécution.

> **📸 Capture 13b** — `screenshots/13b_diff_packages.png`
> La commande `diff /tmp/packages_before.txt /tmp/packages_after.txt | grep "^>"` doit lister les paquets mis à jour (nom + version).

---

## 📊 Chapitre 14 — Azure Dashboards

### Création du tableau de bord opérationnel

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
| Disponibilité 24h | Heartbeat | % uptime |

### Requête KQL pour la tuile de disponibilité

```kql
Heartbeat
| where TimeGenerated > ago(24h)
| summarize
    Availability = round(countif(TimeGenerated > ago(24h)) * 100.0 / 1440, 1)
    by Computer
| project Computer, Availability
```

> **📸 Capture 14a** — `screenshots/14a_dashboard_overview.png`
> Chemin portail : `Tableaux de bord → dashboard-finsecure-ops`
> Le tableau de bord doit afficher **au minimum 4 tuiles actives** avec des données réelles (état Arc, graphique CPU, alertes, disponibilité). Aucune tuile ne doit afficher "Aucune donnée".

---

## 🛡️ Chapitre 15 — Audit de conformité

### Inventaire des ressources via Azure CLI

```bash
# Lister toutes les ressources du projet
az resource list \
  --resource-group rg-finsecure-arc \
  --output table

# Statut des machines Arc
az connectedmachine list \
  --resource-group rg-finsecure-arc \
  --query "[].{Nom:name, Statut:status, OS:osName, Version:agentVersion}" \
  --output table

# Extensions installées
az connectedmachine extension list \
  --machine-name admin-lab-local \
  --resource-group rg-finsecure-arc \
  --output table
```

### Requête KQL — Rapport de conformité global

```kql
// Résumé de conformité sur les 24 dernières heures
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

> **📸 Capture 15a** — `screenshots/15a_compliance_report.png`
> Chemin portail : `law-finsecure-prod → Journaux`
> Les deux serveurs doivent afficher le statut **"✅ En ligne"**, avec leur score de disponibilité (ex : 99.8%) et leur version d'agent.

---

## 🔧 Chapitre 16 — Dépannage

### Cas 1 — Agent Arc déconnecté

```bash
# Vérifier le service et les logs
systemctl status himdsd
journalctl -u himdsd -n 50

# Tester la connectivité réseau vers Azure
curl -v https://management.azure.com/
curl -v https://guestnotificationservice.azure.com/

# Redémarrer ou reconnecter l'agent
systemctl restart himdsd
# Si nécessaire :
sudo azcmagent disconnect
sudo azcmagent connect [options]
```

### Cas 2 — Logs non collectés dans Log Analytics

```bash
# Vérifier le service AMA
systemctl status azuremonitoragent
journalctl -u azuremonitoragent -n 100

# Vérifier l'association DCR → machine
az monitor data-collection rule association list \
  --resource-group rg-finsecure-arc \
  --output table

# Redémarrer l'agent AMA
systemctl restart azuremonitoragent

# Tester l'envoi de logs manuellement
logger -p auth.warning "TEST AMA - FinSecure SA diagnostics"
# Attendre 2-3 min puis vérifier dans Log Analytics :
# Syslog | where SyslogMessage contains "TEST AMA"
```

### Cas 3 — Mises à jour bloquées

```bash
# Vérifier les dépôts actifs et la connectivité
sudo dnf repolist
sudo dnf check-update

# Vider le cache DNF
sudo dnf clean all && sudo dnf makecache

# Consulter les logs DNF
sudo tail -50 /var/log/dnf.log
```

### Cas 4 — Port 443 bloqué (problème réseau)

```bash
# Tester les endpoints Azure Arc
curl -v https://management.azure.com/ 2>&1 | grep -E "Connected|SSL|TLS"
curl -v https://login.microsoftonline.com/ 2>&1 | grep -E "Connected|SSL"

# Vérifier et corriger Firewalld
firewall-cmd --list-all
firewall-cmd --permanent --add-port=443/tcp
firewall-cmd --reload

# Diagnostiquer un éventuel blocage SELinux
ausearch -m avc -ts recent | grep azcmagent
sealert -a /var/log/audit/audit.log
```

---

## ✅ Chapitre 17 — Validation finale

### Checklist complète du projet

#### Linux — admin.lab.local & server.lab.local
- [ ] Hostname FQDN configuré (`admin.lab.local` / `server.lab.local`)
- [ ] IP statique configurée et persistante
- [ ] Connectivité Internet confirmée (port 443 vers Azure)
- [ ] Utilisateur `arcadmin` avec sudo sans mot de passe créé
- [ ] Authentification SSH par clé Ed25519 configurée
- [ ] Authentification par mot de passe SSH désactivée
- [ ] Banner légal SSH configuré
- [ ] Firewalld actif — seul le service SSH autorisé
- [ ] SELinux en mode **Enforcing** persistant

#### Azure Arc
- [ ] `admin-lab-local` → statut **Connected**
- [ ] `server-lab-local` → statut **Connected**
- [ ] Inventaire automatique collecté (OS, IP, version agent)
- [ ] Tags de ressources corrects (Environment, Project, Owner, HostRoleType)

#### Azure Monitor Agent
- [ ] AMA installé sur `admin-lab-local` → statut **Succeeded**
- [ ] AMA installé sur `server-lab-local` → statut **Succeeded**
- [ ] Service `azuremonitoragent` **active (running)** sur les deux VMs

#### Data Collection Rules
- [ ] DCR `dcr-finsecure-linux` créée
- [ ] 8 compteurs de performance configurés (CPU, RAM, Disque, Réseau)
- [ ] 7 facilities Syslog configurées (niveau Warning)
- [ ] DCR associée aux deux machines Arc

#### Log Analytics
- [ ] Table `Heartbeat` → données des deux serveurs visibles
- [ ] Table `InsightsMetrics` → métriques CPU et mémoire visibles
- [ ] Table `Syslog` → journaux Linux collectés
- [ ] Requêtes KQL (1 à 8) fonctionnelles

#### Alertes
- [ ] Alerte CPU > 80% — créée et activée
- [ ] Alerte mémoire > 85% — créée et activée
- [ ] Alerte serveur indisponible (Heartbeat) — créée et activée
- [ ] Alerte espace disque < 20% — créée et activée
- [ ] Groupe d'action email `ag-finsecure-ops` configuré

#### Update Manager
- [ ] Évaluation de conformité effectuée sur les deux machines
- [ ] Inventaire des mises à jour disponibles visible (par criticité)
- [ ] Planification mensuelle `deploy-finsecure-monthly` configurée
- [ ] Historique de déploiement documenté (statut Réussi)

---

## 🎓 Compétences démontrées

### Administration Linux (RHCSA)

| Compétence | Implémentation dans ce projet |
|---|---|
| Gestion des utilisateurs | Création de `arcadmin`, isolation sudo, groupes dédiés |
| Configuration réseau | IP statique avec `nmcli`, résolution DNS locale |
| SSH sécurisé | Clés Ed25519, désactivation mot de passe, banner légal |
| Firewalld | Règles entrantes minimales, port 443 autorisé |
| SELinux | Mode Enforcing permanent, audit des contextes |
| Systemd | Gestion des services Arc (`himds`) et AMA |
| Administration RHEL 9 | DNF, RPM, journald, `/var/log/*` |

### Administration Azure (AZ-104)

| Compétence | Implémentation |
|---|---|
| Resource Management | Resource Group avec 5 tags, convention de nommage rigoureuse |
| Azure Arc | Connexion et gestion de serveurs Linux on-premises |
| Azure Monitor | DCR, métriques, alertes multi-seuils |
| Log Analytics | Tables, requêtes KQL (8 requêtes), rétention 90 jours |
| Update Manager | Inventaire, conformité, déploiement planifié |
| Governance | Inventaire centralisé, audit de conformité PCI-DSS |

### Hybrid Cloud

| Compétence | Implémentation |
|---|---|
| Connectivity | HTTPS 443, agents Arc et AMA sous SELinux Enforcing |
| Unified Management | Un seul portail Azure pour l'on-premises et le cloud |
| Security | SELinux + Firewalld + SSH hardening + Azure RBAC |
| Observability | Supervision unifiée : métriques, logs, alertes, dashboards |

---

## 🔗 Ressources

- [Documentation Azure Arc — Serveurs](https://learn.microsoft.com/azure/azure-arc/servers/overview)
- [Azure Monitor Agent — Vue d'ensemble](https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-overview)
- [Data Collection Rules](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-rule-overview)
- [Azure Update Manager](https://learn.microsoft.com/azure/update-manager/overview)
- [Référence KQL](https://learn.microsoft.com/azure/data-explorer/kusto/query/)
- [Objectifs d'examen RHCSA (EX200)](https://www.redhat.com/en/services/training/ex200-red-hat-certified-system-administrator-rhcsa-exam)

---

*Réalisé par **Serge TOGNON** — Administrateur Cloud Azure Certifié (AZ-104) | Candidat RHCSA*
*LinkedIn : [linkedin.com/in/serge-tognon](www.linkedin.com/in/serge-tognon-a63443187)*
