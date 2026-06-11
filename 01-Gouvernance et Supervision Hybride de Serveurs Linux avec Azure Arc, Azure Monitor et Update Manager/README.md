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
18. [Architecture cible Production](#-Chapitre-18-Architecture-cible-Production)                
19. [Compétences démontrées](#-compétences-démontrées)

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

### Architecture du projet (architecture actuelle utilise les endpoints publics sécurisés (HTTPS 443))

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


# Restreindre les flux entrants au seul trafic SSH légitime (sur les DEUX VMs)
## Sur admin.lab.local
# Supprimer la règle SSH générique
sudo firewall-cmd --permanent --remove-service=ssh

# Autoriser SSH uniquement depuis server (192.168.10.2)
# Restreindre SSH au strict nécessaire , principe du moindre privilège 
# /32 = adresse hôte unique : seule la VM partenaire est autorisée, aucune autre machine
# du réseau 192.168.10.0/24 ne peut initier une connexion SSH, même en cas de compromission
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.10.2/32" service name="ssh" accept'

# Autoriser HTTPS sortant (Azure Arc + AMA)
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="0.0.0.0/0" port port="443" protocol="tcp" accept'
sudo firewall-cmd --reload
sudo firewall-cmd --list-all

<img width="956" height="459" alt="3a" src="https://github.com/user-attachments/assets/d63ee253-c043-4496-be87-cd929b796181" />


## Sur server.lab.local

# Supprimer la règle SSH générique
sudo firewall-cmd --permanent --remove-service=ssh

# Autoriser SSH uniquement depuis admin (192.168.10.1)
#  seul le bastion admin (192.168.10.1) peut SSH
# /32 garantit qu'aucune autre VM future ajoutée au réseau n'hérite automatiquement
# d'un accès SSH non désiré vers le serveur métier

sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.10.1/32" service name="ssh" accept'

# Autoriser HTTPS sortant (Azure Arc + AMA)
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" destination address="0.0.0.0/0" port port="443" protocol="tcp" accept'

sudo firewall-cmd --reload
sudo firewall-cmd --list-all


<img width="679" height="416" alt="3a&#39;" src="https://github.com/user-attachments/assets/bdd5f1f4-944e-4a11-984f-baaf3131ccfe" />


---
> 💡 **Règle adaptée au contexte** : Ce lab utilise `/32` (adresse hôte
> unique) car seules 2 VMs aux IPs fixes communiquent entre elles.
> Dans un déploiement Ansible à grande échelle ,
> la règle `/24` est justifiée par la nécessité du nœud de contrôle
> d'atteindre toutes les VMs cibles, compensée par l'authentification
> par clé Ed25519 et l'audit Syslog.
> *sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.10.0/24" service name="ssh" accept'*

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
  --tenant-id "TENANT-ID" \
  --subscription-id "SUBSCRIPTION-ID" \
  --resource-group "rg-finsecure-arc" \
  --location "francecentral" \
  --resource-name "admin-lab-local" \
  --cloud "AzureCloud" \
  --tags "Environment=Production,Project=Hybrid Governance,Owner=Serge TOGNON,HostRoleType=LinuxAdminServer"
```
<img width="652" height="406" alt="6d" src="https://github.com/user-attachments/assets/5722c9ea-d99f-40e6-a3dd-5d46aa518fb7" />


---

### Étape 3 — Installation sur server.lab.local

""bash
# Télécharger et installer le binaire de l'agent hybride
wget https://gbl.his.arc.azure.com/azcmagent-linux -O install_linux_azcmagent.sh
# Exécuter l'installation
sudo bash install_linux_azcmagent.sh

<img width="651" height="196" alt="6e" src="https://github.com/user-attachments/assets/1e5652af-5c44-4536-a0ec-7aaa92ba91e5" />

# Connecter le serveur à Azure Arc
sudo azcmagent connect \
  --tenant-id "<TENANT_ID>" \
  --subscription-id "<SUBSCRIPTION_ID>" \
  --resource-group "rg-finsecure-arc" \
  --location "francecentral" \
  --resource-name "server-lab-local" \
  --cloud "AzureCloud" \
  --tags "Environment=Production,Project=Hybrid Governance,Owner=Serge TOGNON,HostRoleType=LinuxApplicationServer"

<img width="668" height="265" alt="6f" src="https://github.com/user-attachments/assets/cc877a62-dd73-4307-8e03-43995a6aab89" />


---

### Diagnostic local de l'agent

```bash
# Vérifier le statut des démons Arc sous SELinux Enforcing
sudo azcmagent show

# Vérifier les services
systemctl status himdsd
systemctl status gcad
```

Résultat attendu de `azcmagent show` :

<img width="650" height="288" alt="6g" src="https://github.com/user-attachments/assets/cd80843d-584b-4f5e-a97e-95bbab5082f3" />

<img width="631" height="158" alt="6g&#39;" src="https://github.com/user-attachments/assets/48a3cc8a-181a-4427-92bf-a8e909ba6e82" />

---

### 🔄 Déploiement à grande échelle — Service Principal & Ansible

> 💡 **Contexte** : Le lab FinSecure SA repose sur 2 VMs locales onboardées
> manuellement aux Étapes 2 et 3. Cette section documente l'approche
> **Service Principal + Ansible** pour un déploiement à grande échelle,
> applicable en contexte entreprise (50+ machines). Elle n'a pas été exécutée
> dans ce lab mais constitue une compétence opérationnelle documentée en
> prévision de scénarios réels.


#### Pourquoi un Service Principal ?

L'onboarding des Étapes 2 et 3 utilise une authentification **interactive** :
`azcmagent connect` ouvre un navigateur pour valider l'identité de l'utilisateur.
Cette approche est impossible à automatiser sur 50 VMs simultanément.

Le **Service Principal** est une identité applicative Azure AD qui permet à
`azcmagent connect` de s'authentifier **sans intervention humaine**, prérequis
indispensable pour tout déploiement Ansible à grande échelle.

---

#### 6.1 — Créer le Service Principal d'onboarding

Le rôle minimal requis est **Azure Connected Machine Onboarding** ,il ne donne
aucun accès aux ressources Azure existantes.

```bash
az ad sp create-for-rbac \
  --name "sp-arc-onboarding-finsecure" \
  --role "Azure Connected Machine Onboarding" \
  --scopes "/subscriptions/<SUBSCRIPTION_ID>/resourceGroups/rg-finsecure-arc"
```

**Résultat à conserver:**

```json
{
  "appId":    "<CLIENT_ID>",
  "password": "<CLIENT_SECRET>",
  "tenant":   "<TENANT_ID>"
}
```

Vérifier le rôle assigné :

```bash
az role assignment list \
  --assignee "<CLIENT_ID>" \
  --query "[].{Role:roleDefinitionName, Scope:scope}" \
  --output table
```

Résultat attendu :

```
Role                                    Scope
--------------------------------------  ------------------------------------------------
Azure Connected Machine Onboarding      /subscriptions/.../rg-finsecure-arc
```



---

#### 6.2 — Inventaire Ansible

Fichier `inventory/hosts.ini` :

```ini
[arc_servers]
vm-01.lab.local
vm-02.lab.local
vm-03.lab.local
# ... jusqu'à vm-50.lab.local

[arc_servers:vars]
ansible_user=arcadmin
ansible_ssh_private_key_file=~/.ssh/id_ed25519
```

Tester la connectivité SSH sur toutes les VMs :

```bash
ansible arc_servers -i inventory/hosts.ini -m ping
```

Résultat attendu : toutes les VMs répondent **pong** en vert.

---

#### 6.3 — Chiffrer les secrets avec Ansible Vault

```bash
# Créer le fichier de secrets chiffré
ansible-vault create group_vars/all/vault.yml
```

Contenu de `vault.yml` :

```yaml
vault_arc_client_id:       "<appId>"
vault_arc_client_secret:   "<password>"
vault_arc_tenant_id:       "<tenant-id>"
vault_arc_subscription_id: "<subscription-id>"
```

---

#### 6.4 — Playbook d'onboarding Arc

Fichier `playbooks/arc_onboarding.yml` :

```yaml
---
- name: Déploiement Azure Arc — FinSecure SA (50 VMs)
  hosts: arc_servers
  become: true
  vars_files:
    - group_vars/all/vault.yml
  vars:
    arc_resource_group: "rg-finsecure-arc"
    arc_location:       "francecentral"
    arc_cloud:          "AzureCloud"

  tasks:

    - name: Vérifier si azcmagent est déjà installé
      command: azcmagent version
      register: agent_check
      ignore_errors: true
      changed_when: false

    - name: Télécharger le binaire azcmagent
      get_url:
        url:  "https://gbl.his.arc.azure.com/azcmagent-linux"
        dest: /tmp/install_linux_azcmagent.sh
        mode: '0440'
      when: agent_check.rc != 0

    - name: Installer azcmagent
      shell: bash /tmp/install_linux_azcmagent.sh
      when: agent_check.rc != 0

    - name: Vérifier le statut de connexion actuel
      command: azcmagent show
      register: arc_status
      ignore_errors: true
      changed_when: false

    - name: Connecter la VM à Azure Arc via Service Principal
      command: >
        azcmagent connect
        --resource-group           "{{ arc_resource_group }}"
        --tenant-id                "{{ vault_arc_tenant_id }}"
        --location                 "{{ arc_location }}"
        --subscription-id          "{{ vault_arc_subscription_id }}"
        --service-principal-id     "{{ vault_arc_client_id }}"
        --service-principal-secret "{{ vault_arc_client_secret }}"
        --resource-name  "{{ inventory_hostname | regex_replace('\\..*', '') }}"
        --cloud                    "{{ arc_cloud }}"
        --tags "Environment=Production,Project=Hybrid Governance,Owner=Serge TOGNON"
      when: "'Connected' not in arc_status.stdout"

    - name: Vérifier le statut final
      command: azcmagent show
      register: final_status
      changed_when: false

    - name: Afficher le statut par VM
      debug:
        msg: "{{ inventory_hostname }} — {{ final_status.stdout_lines }}"
```

---

#### 6.5 — Exécution

```bash
# Dry-run — simulation sans modification
ansible-playbook -i inventory/hosts.ini playbooks/arc_onboarding.yml \
  --ask-vault-pass \
  --check

# Exécution réelle , 10 VMs en parallèle
ansible-playbook -i inventory/hosts.ini playbooks/arc_onboarding.yml \
  --ask-vault-pass \
  --forks 10
```

---

#### 6.6 — Vérification post-déploiement

```bash
# Lister toutes les machines Arc enregistrées
az connectedmachine list \
  --resource-group rg-finsecure-arc \
  --query "[].{Nom:name, Statut:status, OS:osName}" \
  --output table

# Compter les machines effectivement connectées
az connectedmachine list \
  --resource-group rg-finsecure-arc \
  --query "[?status=='Connected'] | length(@)"
```




## ✅ Chapitre 7 — Validation Azure Arc

### Vérification via Azure CLI

```bash
# Lister les machines Arc connectées
az connectedmachine list \
  --resource-group rg-finsecure-arc \
  --query "[].{Nom:name,Status:status,OS:osName,Version:osVersion, Region:location}" \
  --output table
```

**Résultat attendu :**
<img width="960" height="152" alt="7a" src="https://github.com/user-attachments/assets/b18d6dfe-e7a9-45fb-89b5-c16c93cfbd6b" />

<img width="778" height="304" alt="7b" src="https://github.com/user-attachments/assets/124a53b9-cf6f-4196-8e87-89295adf73e9" />

<img width="914" height="305" alt="7c" src="https://github.com/user-attachments/assets/63d64f07-3b5e-4981-88a5-3be20718fc7a" />



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
  --location francecentral
  --no-wait

# Déploiement sur server-lab-local
az connectedmachine extension create \
  --name AzureMonitorLinuxAgent \
  --machine-name server-lab-local \
  --resource-group rg-finsecure-arc \
  --type AzureMonitorLinuxAgent \
  --publisher Microsoft.Azure.Monitor \
  --location francecentral
  --no-wait
```
<img width="920" height="374" alt="8a" src="https://github.com/user-attachments/assets/0799963b-b363-4e5b-8407-97146cc5cd36" />

<img width="857" height="356" alt="8b" src="https://github.com/user-attachments/assets/fb9be511-c9b7-433d-9d64-0ed467fa5ee0" />





---

### Vérification locale du service AMA

```bash
# Vérifier le service sur chaque VM(admin-lab-local et server-lab-local)
sudo systemctl status azuremonitoragent

# Consulter les logs de l'agent
journalctl -u azuremonitoragent -n 50

# Vérifier les processus actifs
ps aux | grep -i azure
```
<img width="649" height="405" alt="8c" src="https://github.com/user-attachments/assets/d12a7a46-7f15-4f7c-b1e1-4c7e05fd5b0e" />

<img width="650" height="265" alt="8d" src="https://github.com/user-attachments/assets/e6b74da1-4b25-49a1-97d5-9b4193ce72dd" />



---



## 📐 Chapitre 9 — Data Collection Rules (DCR)

### Rôle des DCR

Les DCR définissent **quoi collecter** et **où envoyer** les données. Elles associent des sources (métriques système, journaux Syslog) à des destinations (Log Analytics Workspace), avec un contrôle granulaire de la fréquence et du niveau de sévérité.

### Compteurs de performance (fréquence : 60s)

| Compteur | Fréquence | Description |
|---|---|---|
| `Processor/% Processor Time` | 60 s | Utilisation CPU |
| `Memory/% Used Memory` | 60 s | Utilisation RAM |
| `Memory/% Available Memory` | 60 s | RAM disponible |
| `LogicalDisk/% Used Space` | 300 s | Espace disque utilisé |
| `LogicalDisk/Disk Read Bytes/sec` | 60 s | Lectures disque |
| `LogicalDisk/Disk Write Bytes/sec` | 60 s | Écritures disque |
| `Network/Total Bytes Received` | 60 s | Trafic réseau entrant |
| `Network/Total Bytes Transmitted` | 60 s | Trafic réseau sortant |

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

bash
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

  **Etapes Portail Azure**

**Méthode** : Depuis la DCR 

Azure Portal → recherche Data collection rules → dcr-finsecure-linux
Resources (menu gauche)
+ Add → sélectionne les deux machines :

admin-lab-local
server-lab-local


Save


<img width="922" height="403" alt="9a" src="https://github.com/user-attachments/assets/3d9a8924-3ce3-4582-aa29-a0f26ff1b53b" />

<img width="911" height="377" alt="9b" src="https://github.com/user-attachments/assets/d4b5267f-dc42-47e2-96ec-734ad0dbaecf" />

<img width="901" height="372" alt="9c" src="https://github.com/user-attachments/assets/77674148-2283-45a5-bb04-a966ea7e2248" />

<img width="847" height="368" alt="9d" src="https://github.com/user-attachments/assets/7f4ead1a-b2d4-4ef3-9371-442d0c5f1418" />


<img width="920" height="401" alt="9e" src="https://github.com/user-attachments/assets/04ec9365-ff2b-4939-9bd5-9111480ea73b" />

---



## 🔍 Chapitre 10 — Analyse des journaux KQL

### Accès à Log Analytics
Portail Azure → **`law-finsecure-prod` → Journaux**

> ⏱️ **Important :** Attendre **15 à 30 minutes** après la configuration de la DCR
> avant d'exécuter les requêtes. Les premières données mettent quelques minutes
> à arriver dans le workspace.

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

<img width="918" height="389" alt="10a" src="https://github.com/user-attachments/assets/7216292b-fa7b-45f8-b28a-15364950cee6" />

---

### Requête 2 — Graphique de charge CPU (Timechart)

```kql
// Moyenne d'utilisation CPU par serveur sur les dernières 2h
Perf
| where TimeGenerated > ago(2h)
| where ObjectName == "Processor"
| where CounterName == "% Processor Time"
| where InstanceName == "total"
| summarize AvgCPU = avg(CounterValue) by bin(TimeGenerated, 5m), Computer
| render timechart
```

<img width="881" height="407" alt="10b" src="https://github.com/user-attachments/assets/ea50de27-2508-46bb-9457-b60dbc83a99f" />


---

### Requête 3 — Utilisation mémoire

```kql
// Pourcentage de mémoire utilisée par serveur
Perf
| where TimeGenerated > ago(2h)
| where ObjectName == "Memory"
| where CounterName == "% Used Memory"
| summarize AvgMem = avg(CounterValue) by bin(TimeGenerated, 5m), Computer
| render timechart
```

<img width="886" height="396" alt="10c" src="https://github.com/user-attachments/assets/8f3b4a9f-1d58-4771-a593-b0ccd535e8a8" />


---

### Requête 4 — Journalisation des flux d'accès SSH
//Détecter les tentatives de connexion SSH (réussies et échouées)
```kql
Syslog
| where TimeGenerated > ago(48h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "sshd"
| project TimeGenerated, Computer, Facility, SyslogMessage
| order by TimeGenerated desc
```

<img width="919" height="406" alt="10d" src="https://github.com/user-attachments/assets/77cf87d1-3288-43ef-837e-1094a527d4ec" />


---

### Requête 5 — Échecs d'authentification (sécurité)

```kql
// Compter les échecs de connexion par IP source
Syslog
| where TimeGenerated > ago(24h)
| where Facility in ("auth", "authpriv")
| where SyslogMessage contains "Failed"
    or SyslogMessage contains "Invalid"
    or SyslogMessage contains "error"
| summarize FailedAttempts = count() by Computer, Facility
| order by FailedAttempts desc
```

> **📸 Capture 10e** — `screenshots/10e_kql_failed_auth.png`
> Tableau des IPs avec tentatives d'authentification échouées > 3.

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
<img width="918" height="371" alt="10f" src="https://github.com/user-attachments/assets/cf9d397f-5be9-4ef3-8e75-9701d3750486" />



---

### Requête 7 — Activité disque I/O

```kql
// Débit disque lecture/écriture par serveur
Perf
| where TimeGenerated > ago(2h)
| where ObjectName == "Logical Disk"
| where CounterName in ("Disk Read Bytes/sec", "Disk Write Bytes/sec")
| summarize AvgBytes = avg(CounterValue) by bin(TimeGenerated, 5m), Computer, CounterName
| render timechart
```

<img width="909" height="410" alt="10g" src="https://github.com/user-attachments/assets/67012cb3-98fc-477d-9c27-9e9dde93482f" />


---

### Requête 8 — Traçabilité des élévations de privilèges (Audit PCI-DSS)

```kql
// Auditer les commandes exécutées avec sudo
Syslog
| where TimeGenerated > ago(7d)
| where Facility == "authpriv"
| where SyslogMessage contains "sudo"
| extend
    User    = extract(@"(\w+) : TTY", 1, SyslogMessage),
    Command = extract(@"COMMAND=(.+)$", 1, SyslogMessage)
| where isnotempty(Command)
| project TimeGenerated, Computer, User, Command
| order by TimeGenerated desc
```

> **📸 Capture 10h** — `screenshots/10h_kql_sudo_audit.png`
> Tableau avec les colonnes `TimeGenerated`, `Computer`, `User`, `Command`
> affichant les commandes sudo exécutées pendant le lab.


## 🚨 Chapitre 11 — Alertes Azure

##  Étape 1 — Déploiement du Groupe d'actions
Un groupe d'actions est le mécanisme Azure qui définit qui prévenir et comment lorsqu'une alerte se déclenche. Il centralise les canaux de notification (email, SMS, webhook, ticket ITSM) et peut être partagé entre plusieurs règles d'alerte , modifier le groupe suffit pour mettre à jour toutes les alertes qui l'utilisent.
Dans le contexte FinSecure SA, ag-finsecure-ops est le groupe qui reçoit toutes les alertes d'infrastructure hybride : il est créé avant les règles d'alerte car celles-ci en dépendent au moment du déploiement.
bash
az monitor action-group create \
  --name "ag-finsecure-ops" \
  --resource-group "rg-finsecure-arc" \
  --short-name "FinSecureOps" \
  --action email sysadmin-alerts arc-alerts@finsecure-sa.com


<img width="920" height="395" alt="11a" src="https://github.com/user-attachments/assets/937f6ee7-a984-4bae-9327-8499e462b971" />

---
### Étape 2 — Création des règles d'alerte

Une **règle d'alerte** surveille en continu une métrique ou une requête KQL
et déclenche une notification vers le groupe d'actions `ag-finsecure-ops`
dès qu'un seuil critique est franchi.

> **Chemin portail :** Surveillance → Alertes → + Créer → Règle d'alerte

---

#### Alerte 1 — CPU > 80%

**Pourquoi cette alerte ?**
Le CPU est la première ressource à saturer lors d'une surcharge applicative.
Dans un contexte financier (FinSecure SA), un CPU saturé peut impacter les
traitements de transactions, les jobs batch ou les APIs critiques. Le seuil
de 80% laisse une marge d'intervention avant la saturation totale à 100%.

**Comment ça fonctionne ?**
La requête interroge la table `Perf` toutes les **1 minute** sur une fenêtre
de **5 minutes**. Elle calcule la moyenne CPU par serveur. Si cette moyenne
dépasse 80%, la requête retourne au moins 1 résultat → l'alerte se déclenche
et envoie un email via `ag-finsecure-ops`.

**Pourquoi seuil = 0 ?**
La requête KQL filtre déjà `where AvgCPU > 80`  elle ne retourne des lignes
que si le seuil est dépassé. "Résultats > 0" signifie donc "la condition est
vraie sur au moins un serveur".

| Champ | Valeur |
|-------|--------|
| Scope | `law-finsecure-prod` |
| Type de signal | Recherche de journaux personnalisée |
| Opérateur | Supérieur à |
| Valeur seuil | `0` |
| Granularité d'agrégation | `5 minutes` |
| Fréquence d'évaluation | `1 minute` |
| Groupe d'actions | `ag-finsecure-ops` |
| Nom de la règle | `alert-cpu-finsecure` |
| Description | `CPU > 80% sur les serveurs FinSecure SA` |
| Sévérité | `2 - Avertissement` |
| Région | `France Central` |

```kql
Perf
| where ObjectName == "Processor"
| where CounterName == "% Processor Time"
| where InstanceName == "total"
| summarize AvgCPU = avg(CounterValue) by Computer
| where AvgCPU > 80
```

#### Alerte 2 — Serveur indisponible (Heartbeat)

**Pourquoi cette alerte ?**
C'est l'alerte la plus critique du lab. Le heartbeat est le "pouls" de la VM ,
Azure Monitor le reçoit toutes les minutes. Une absence depuis 5 minutes indique
que le serveur est éteint, que le réseau est coupé, ou que l'agent Arc a planté.
Dans un environnement financier, une indisponibilité non détectée peut avoir des
conséquences graves sur la continuité de service , alignement direct avec les
exigences **PCI-DSS** et **ISO 27001**.

**Comment ça fonctionne ?**
La requête cherche les serveurs dont le dernier heartbeat date de plus de
5 minutes. Si elle retourne des résultats → un ou plusieurs serveurs sont
silencieux → alerte **Critique** déclenchée immédiatement.

**Pourquoi sévérité 1 et pas 2 ?**
Une indisponibilité serveur est plus grave qu'une surcharge CPU , le serveur
est complètement inaccessible, pas juste lent.

| Champ | Valeur |
|-------|--------|
| Scope | `law-finsecure-prod` |
| Type de signal | Recherche de journaux personnalisée |
| Opérateur | Supérieur à |
| Valeur seuil | `0` |
| Granularité d'agrégation | `5 minutes` |
| Fréquence d'évaluation | `1 minute` |
| Groupe d'actions | `ag-finsecure-ops` |
| Nom de la règle | `alert-heartbeat-finsecure` |
| Description | `Serveur indisponible depuis 5 min` |
| Sévérité | `0 - Critique` |
| Région | `France Central` |

```kql
Heartbeat
| where TimeGenerated > ago(5m)
| summarize LastHeartbeat = max(TimeGenerated) by Computer
| where LastHeartbeat < ago(5m)
```

#### Alerte 3 — Espace disque < 20%

**Pourquoi cette alerte ?**
Un disque plein est une panne silencieuse et dévastatrice ,les logs s'arrêtent
d'écrire, les bases de données corrompent leurs fichiers, les applications
crashent sans message d'erreur clair. Le seuil de 20% est le standard en
production pour anticiper le problème avant qu'il devienne critique.

**Comment ça fonctionne ?**
La requête surveille le compteur `% Free Space` sur toutes les partitions
individuelles. Si une partition passe sous 20% d'espace libre → alerte
déclenchée avec le nom du serveur et de la partition concernés.

**Pourquoi `InstanceName != "total"` ?**
`total` est une valeur agrégée artificielle. Surveiller les partitions
individuelles (`/`, `/var`, `/home`) est plus précis et actionnable qu'une
moyenne globale qui peut masquer une partition saturée.

| Champ | Valeur |
|-------|--------|
| Scope | `law-finsecure-prod` |
| Type de signal | Recherche de journaux personnalisée |
| Opérateur | Supérieur à |
| Valeur seuil | `0` |
| Granularité d'agrégation | `5 minutes` |
| Fréquence d'évaluation | `5 minutes` |
| Groupe d'actions | `ag-finsecure-ops` |
| Nom de la règle | `alert-disk-finsecure` |
| Description | `Espace disque libre < 20% sur les serveurs FinSecure SA` |
| Sévérité | `2 - Avertissement` |
| Région | `France Central` |

```kql
Perf
| where TimeGenerated > ago(15m)
| where ObjectName == "Logical Disk"
| where CounterName == "% Free Space"
| where InstanceName != "total"
| summarize AvgFree = avg(CounterValue) by Computer, InstanceName
| where AvgFree < 20
```


#### Alerte 4 — Mémoire > 85%

**Pourquoi cette alerte ?**
La saturation mémoire provoque du swap intensif (écriture sur disque à la
place de la RAM), ce qui dégrade drastiquement les performances. À 85%, le
système commence à swapper activement , le serveur est encore fonctionnel
mais ses performances chutent. C'est le moment d'intervenir avant d'atteindre
100% et le crash.

**Comment ça fonctionne ?**
La requête calcule la moyenne de `% Used Memory` sur 15 minutes par serveur.
Une fenêtre de 15 minutes évite les faux positifs liés aux pics mémoire courts
et normaux lors du démarrage de processus.

**Pourquoi 15 minutes et pas 5 ?**
La mémoire est moins volatile que le CPU , un pic CPU de 2 minutes peut être
normal (compilation, batch), mais une mémoire > 85% sur 15 minutes consécutives
est un signal réel de problème structurel.

| Champ | Valeur |
|-------|--------|
| Scope | `law-finsecure-prod` |
| Type de signal | Recherche de journaux personnalisée |
| Opérateur | Supérieur à |
| Valeur seuil | `0` |
| Granularité d'agrégation | `15 minutes` |
| Fréquence d'évaluation | `5 minutes` |
| Groupe d'actions | `ag-finsecure-ops` |
| Nom de la règle | `alert-memory-finsecure` |
| Description | `Mémoire > 85% utilisée sur les serveurs FinSecure SA` |
| Sévérité | `2 - Avertissement` |
| Région | `France Central` |

```kql
Perf
| where TimeGenerated > ago(15m)
| where ObjectName == "Memory"
| where CounterName == "% Used Memory"
| summarize AvgMem = avg(CounterValue) by Computer
| where AvgMem > 85
```
<img width="920" height="361" alt="11b" src="https://github.com/user-attachments/assets/c3268de9-f82d-4fd9-9b6d-35c10fd832dc" />



### Bonnes pratiques d'alerting

| Bonne pratique | Détail |
|----------------|--------|
| Seuils progressifs | Warning à 70%, Critical à 85% |
| Fenêtre d'évaluation | 5 min minimum pour éviter les faux positifs |
| Auto-résolution | Activer `auto-mitigate` pour clore automatiquement |
| Groupement d'alertes | Un seul groupe d'actions `ag-finsecure-ops` pour toutes les règles |
| Requêtes basées sur `Perf` | Adapté à une DCR standard sans VM Insights |

## 🔄 Chapitre 12 — Azure Update Manager

### Rôle d'Update Manager

Azure Update Manager permet de **gérer les mises à jour Linux directement
depuis Azure**, sans accès direct aux serveurs. Il offre :

| Fonctionnalité | Détail |
|----------------|--------|
| Inventaire | Mises à jour disponibles classées par criticité |
| Évaluation | Conformité PCI-DSS par machine |
| Déploiement | Planifié ou immédiat via `dnf update` |
| Rapport | Historique et statut post-déploiement |

> 💡 **Prérequis** : Les machines doivent être connectées à Azure Arc
> et l'agent `azcmagent` doit être en statut **Connected**.

---

### Étape 1 — Évaluation de la conformité

#### Via le portail Azure 

**Azure Update Manager → Machines → Sélectionner les VMs → Vérifier les mises à jour**

> **📸 Capture 12a** — `screenshots/12a_update_manager_overview.png`
> Chemin portail : `Azure Update Manager → Vue d'ensemble`
> Le tableau de bord doit afficher les 2 machines évaluées et les
> catégories de mises à jour disponibles (Critical, Security, Other).

> **📸 Capture 12b** — `screenshots/12b_updates_available.png`
> Chemin portail : `Azure Update Manager → Machines → admin-lab-local → Mises à jour`
> La liste des paquets classée par criticité doit être visible.

#### Via Azure CLI

```bash
# Déclencher une évaluation sur admin-lab-local
az connectedmachine assess-patches \
  --resource-group rg-finsecure-arc \
  --name admin-lab-local

# Déclencher une évaluation sur server-lab-local
az connectedmachine assess-patches \
  --resource-group rg-finsecure-arc \
  --name server-lab-local

# Lister les mises à jour disponibles
az connectedmachine list-patches \
  --resource-group rg-finsecure-arc \
  --name admin-lab-local \
  --query "[].{Paquet:patchName, Criticite:classifications, KB:kbId}" \
  --output table
```

> ⚠️ **Note** : La commande `az maintenance update list` ne fonctionne
> pas sur les machines Arc — utiliser `az connectedmachine assess-patches`
> à la place.

---

### Étape 2 — Planification du déploiement

#### Via le portail Azure

1. **Azure Update Manager → Planifications de maintenance → + Créer**
2. Remplir les champs :

| Champ | Valeur |
|-------|--------|
| Nom | `deploy-finsecure-monthly` |
| Région | `France Central` |
| OS | `Linux` |
| Planification | Premier dimanche du mois à **02h00** |
| Fenêtre de maintenance | **2 heures** |
| Reboot | Si nécessaire uniquement |
| Machines cibles | `admin-lab-local` + `server-lab-local` |
| Classifications | Critical + Security + Other |

> **📸 Capture 12c** — `screenshots/12c_deployment_schedule.png`
> Chemin portail : `Update Manager → Planifications de maintenance → deploy-finsecure-monthly`
> La configuration doit afficher les deux machines cibles, la planification
> mensuelle, la fenêtre de 2 heures et l'option de reboot.

---

### Étape 3 — Déploiement immédiat (one-shot)

Pour appliquer les mises à jour immédiatement sans attendre la planification :

```bash
# Installer les mises à jour critiques et de sécurité maintenant
az connectedmachine install-patches \
  --resource-group rg-finsecure-arc \
  --name admin-lab-local \
  --maximum-duration PT2H \
  --reboot-setting IfRequired \
  --windows-parameters "{'classificationsToInclude': []}" \
  --linux-parameters "{'classificationsToInclude': ['Critical','Security']}"
```

Ou depuis le portail :
**Azure Update Manager → Machines → Sélectionner les VMs → Mettre à jour maintenant**

> **📸 Capture 12d** — `screenshots/12d_install_now.png`
> Chemin portail : `Update Manager → Machines`
> Le bouton **Mettre à jour maintenant** sélectionné avec les 2 machines cochées.

---

### Bonnes pratiques Update Manager

| Bonne pratique | Détail |
|----------------|--------|
| Évaluer avant de déployer | Toujours lancer `assess-patches` avant `install-patches` |
| Fenêtre de maintenance | 2h minimum pour éviter les timeouts |
| Reboot | `IfRequired` — ne redémarre que si nécessaire |
| Criticité | Prioriser Critical + Security en production financière |
| Planification | Hors heures ouvrées (02h00 dimanche) — conformité PCI-DSS |


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




## 🔐 Chapitre 18 — Architecture cible Production



> ### 💬 Retour d'expert — Architecture cible Production
>
> Suite à la publication de ce projet sur LinkedIn, **Bryan Bernet**,
> Architecte technique chez ITS, a soulevé une remarque pertinente :
>
> *"Et en utilisant Arc Private Link et Monitor Private Link pour les flux
> Monitor et VM hybrides ?"*
>
> Cette observation pointe exactement la limite de l'architecture précédente :
> les endpoints publics Azure sont acceptables en environnement de test,
> mais insuffisants pour une mise en production soumise à des exigences
> de sécurité strictes (**PCI-DSS**, **ISO 27001**).
>
> Ce chapitre documente l'évolution naturelle vers une architecture
> **zéro exposition publique**, où tous les flux Arc et Azure Monitor
> transitent exclusivement via le **backbone Microsoft** grâce à
> **Arc Private Link** et **AMPLS** (Azure Monitor Private Link Scope).

<img width="546" height="413" alt="Capture d’écran 2026-06-11 061148" src="https://github.com/user-attachments/assets/9a74d31b-466f-4051-bcc0-4f39a9cf3b68" />


### (Arc Private Link + AMPLS — Zéro exposition publique)

> 💡 **Contexte** : Ce chapitre fait suite à un échange avec **Bryan Bernet**,
> Architecte technique, qui a soulevé la pertinence d'Arc Private Link et
> d'AMPLS pour les flux Monitor en environnement hybride. Il documente
> l'évolution naturelle de l'architecture lab vers un modèle **zéro exposition
> publique**, conforme **PCI-DSS** et **ISO 27001**.
>
> L'architecture  précédente (Chapitres 1-17) utilise les endpoints publics
> Azure sécurisés via HTTPS 443 , valide pour un environnement de test, **insuffisant pour une
> production financière stricte**.

---

### 18.1 — Limites de l'architecture précédente

| Composant | Architecture  | Risque en production |
|-----------|-----------------|---------------------|
| `azcmagent connect` | Endpoints publics Azure Arc | Trafic exposé sur internet public |
| AMA → Log Analytics | Endpoints publics Monitor | Données de supervision en clair sur internet |
| DNS | Résolution publique | Pas de contrôle sur la résolution des endpoints |
| Firewall | Port 443 ouvert vers `*.azure.com` | Surface d'attaque large |

---

### 18.2 — Arc Private Link

**Principe** : Arc Private Link supprime toute exposition publique de
`azcmagent`. Le trafic entre les VMs locales et Azure Arc transite
exclusivement via le **backbone Microsoft**, à travers un Private Endpoint
dans le VNet Azure.

**Composants à déployer** :

```bash
# 1. Créer l'Arc Private Link Scope
az connectedmachine private-link-scope create \
  --name "apls-finsecure-prod" \
  --resource-group rg-finsecure-arc \
  --location francecentral \
  --public-network-access Disabled

# 2. Créer le Private Endpoint pour Arc
az network private-endpoint create \
  --name "pe-arc-finsecure" \
  --resource-group rg-finsecure-arc \
  --vnet-name vnet-finsecure-prod \
  --subnet snet-private-endpoints \
  --private-connection-resource-id "<ID_APLS>" \
  --group-id hybridcompute \
  --connection-name "pec-arc-finsecure"

# 3. Associer les machines Arc au scope
az connectedmachine private-link-scope machine add \
  --scope-name "apls-finsecure-prod" \
  --resource-group rg-finsecure-arc \
  --machine-name admin-lab-local

az connectedmachine private-link-scope machine add \
  --scope-name "apls-finsecure-prod" \
  --resource-group rg-finsecure-arc \
  --machine-name server-lab-local
```

---

### 18.3 — AMPLS (Azure Monitor Private Link Scope)

**Principe** : AMPLS sécurise tous les flux AMA → Log Analytics → Azure Monitor
via des Private Endpoints dédiés. Les données de supervision ne transitent
plus par internet public.

```bash
# 1. Créer l'AMPLS
az monitor private-link-scope create \
  --name "ampls-finsecure-prod" \
  --resource-group rg-finsecure-arc

# 2. Lier le Log Analytics Workspace à l'AMPLS
az monitor private-link-scope scoped-resource create \
  --linked-resource "/subscriptions/<SUB_ID>/resourceGroups/rg-finsecure-arc/providers/microsoft.operationalinsights/workspaces/law-finsecure-prod" \
  --name "law-finsecure-prod" \
  --scope-name "ampls-finsecure-prod" \
  --resource-group rg-finsecure-arc

# 3. Créer le Private Endpoint pour AMPLS
az network private-endpoint create \
  --name "pe-ampls-finsecure" \
  --resource-group rg-finsecure-arc \
  --vnet-name vnet-finsecure-prod \
  --subnet snet-private-endpoints \
  --private-connection-resource-id "<ID_AMPLS>" \
  --group-id azuremonitor \
  --connection-name "pec-ampls-finsecure"
```

---

### 18.4 — Configuration DNS on-premise

Le DNS forwarder local doit résoudre les noms privés Azure vers
`168.63.129.16` (Azure DNS interne) pour que `azcmagent` et AMA
atteignent les Private Endpoints et non les endpoints publics.

```bash
# Zones DNS privées à créer dans Azure
privatelink.his.arc.azure.com         # Arc
privatelink.guestconfiguration.azure.com
privatelink.monitor.azure.com         # AMPLS
privatelink.ods.opinsights.azure.com
privatelink.oms.opinsights.azure.com
privatelink.agentsvc.azure-automation.net
privatelink.blob.core.windows.net
```

---

### 18.5 — Comparaison test vs Production

| Critère | Architecture test | Architecture production |
|---------|-----------------|------------------------|
| Flux Arc | Internet public (HTTPS 443) | Private Link (backbone Microsoft) |
| Flux AMA | Internet public (HTTPS 443) | AMPLS (Private Endpoint) |
| DNS | Résolution publique | DNS Private Zones + Forwarder |
| Firewall | `*.azure.com` ouvert | VPN GW only, internet bloqué |
| Conformité | Lab acceptable | PCI-DSS / ISO 27001 ✅ |


---

### 18.6 — Roadmap d'implémentation

```
Phase 1 — Réseau
  └── Créer VNet + Subnet private-endpoints
  └── Déployer VPN Gateway ou ExpressRoute
  └── Configurer DNS Forwarder on-premise

Phase 2 — Private Link Arc
  └── Créer Arc Private Link Scope (apls-finsecure-prod)
  └── Créer Private Endpoint pe-arc-finsecure
  └── Associer admin-lab-local + server-lab-local

Phase 3 — AMPLS
  └── Créer AMPLS (ampls-finsecure-prod)
  └── Lier law-finsecure-prod à l'AMPLS
  └── Créer Private Endpoint pe-ampls-finsecure

Phase 4 — Durcissement
  └── NSG : bloquer tout trafic internet sortant
  └── Route table : forcer tout trafic vers VPN GW
  └── Valider résolution DNS privée depuis les VMs
```


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

*Réalisé par **Serge TOGNON**  Administrateur Cloud Azure Certifié (AZ-104) | Candidat RHCSA*
*LinkedIn : [linkedin.com/in/serge-tognon](www.linkedin.com/in/serge-tognon-a63443187)*
