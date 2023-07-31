function PrAd {
    $Title = "Menu de sélection Pré AD"
    $Prompt = "Faire choix"
    $IP = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration des &IP","Attribution d'IP Statique ou DHCP, setup du DNS, etc..")
    $WorkStation = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration des &Postes","Modification du nom du poste, Initialisation d'un disque, création des 3 disques pour AD (Sysvol, BDD, Logs)")
    $Domain = [System.Management.Automation.Host.ChoiceDescription]::New("Cofiguration du &Domaine","Ajout du poste en tant qu'utilisateur ou contrôleur du Domaine")
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($IP, $WorkStation, $Domain)
    $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
    Switch ($Choice) {
        0 { $Title = "Configuration des IP"
            $Prompt = "Faire choix"
            $DHCP = [System.Management.Automation.Host.ChoiceDescription]::New("Mode &DHCP","Attribution d'IP par le DHCP")
            $Static = [System.Management.Automation.Host.ChoiceDescription]::New("Mode &Statique","Attribution d'une IP en Statique")
            $DNS = [System.Management.Automation.Host.ChoiceDescription]::New("Modification du D&NS","Modification du DNS par défaut sur lequel la machine pointe")
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($DHCP, $Static, $DNS)
            $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
            Switch ($Choice) {
                0 { Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4AddressNetIP
                    [int]$SelectNIC = Read-Host "Index NIC ?"
                    Remove-NetRoute -InterfaceIndex $SelectNIC -Confirm:$false; Remove-NetIPAddress -InterfaceIndex $SelectNIC -Confirm:$false -ErrorAction SilentlyContinue
                    Set-NetIPInterface -InterfaceIndex $SelectNIC -DHCP Enabled;console
                }
                1 { Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4AddressNetIP
                    [int]$SelectNIC = Read-Host "Index NIC ?"
                    $IPAdress = Read-Host "IP Souhaitée ?"
                    Remove-NetRoute -InterfaceIndex $SelectNIC -Confirm:$false -ErrorAction SilentlyContinue
                    Remove-NetIPAddress -InterfaceIndex $SelectNIC -Confirm:$false -ErrorAction SilentlyContinue
                    $CIDR = Read-Host "Choisir le CIDR"
                    $choix = Read-Host "Appliquer un masque sous réseau ? (Y/N)"
                    if ($choix -eq "oui" -or $choix -eq "yes" -or $choix -eq "y") {
                    $Mask = Read-Host "Choisir le masque sous-reseau"
                    New-NetIPAddress -InterfaceIndex $SelectNIC -IPAddress $IPAdress -AddressFamily IPv4 -PrefixLength $CIDR -DefaultGateway $Mask;console
                    }
                    elseif ($choix -eq "no" -or $choix -eq "non" -or $choix -eq "n") {
                    New-NetIPAddress -InterfaceIndex $SelectNIC -IPAddress $IPAdress -AddressFamily IPv4 -PrefixLength $CIDR;console
                    }
                }
                2 { Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4AddressNetIP
                    [int]$SelectNIC = Read-Host "Choisir le numero NIC souhaitee"
                    $DNSIP = Read-Host "Choisir les IP souhaitees"
                    Set-DnsClientServerAddress -InterfaceIndex $SelectNIC -Addresses $DNSIP;console
                }
            }
        }
        1 { $Title = "Configuration des postes"
            $Prompt = "Faire choix"
            $Rename = [System.Management.Automation.Host.ChoiceDescription]::New("&Renommer le poste","Change l'ID du poste et le redémarre pour appliquer le changement")
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Rename)
            $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
            Switch ($Choice) {
                0 { Write-Host "Nom actuel du poste: $env:COMPUTERNAME" -ForegroundColor blue
                    $NewName = Read-Host -Prompt "Indiquer le nouveau nom du poste"
                    Rename-Computer -NewName $NewName.ToUpper()
                    Write-Warning "Le poste va maintenant redémarrer"
                    Restart-Computer -Force
                }
            }
        }
        2 { $Title = "Configuration du Domaine"
            $Prompt = "Faire choix"
            $ADUser = [System.Management.Automation.Host.ChoiceDescription]::New("Rejoindre le domaine en tant qu'&Utilisateur","Permet d'ajouter le poste de travail dans le domaine en tant qu'Ordinateur Standard")
            $ADDC = [System.Management.Automation.Host.ChoiceDescription]::New("Rejoindre le domaine en tant que &Contrôleur de Domaine","Permet d'ajouter le poste de travail dans le domaine en tant que Contrôleur de Domaine numéro 2")
            $ADMainDC = [System.Management.Automation.Host.ChoiceDescription]::New("Créer la Forêt &Active Directory","Création de la Forêt Active Directory et configuration du poste en tant que Contrôleur Principal du domaine")
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($ADUser, $ADDC, $ADMainDC)
            $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
            Switch ($Choice) {
                0 { $DNSIP = Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses | Select-Object -First 1
                    $FQDN = (Resolve-DnsName -Name $DNSIP).NameHost
                    $DomainRaw = $FQDN -Split "\." | Select-Object -Last 2
                    $DomainName = $DomainRaw -Join "."
                    $DomainNETBIOSRaw = $DomainRaw | Select-Object -SkipLast 1
                    $DomainNETIBIOS = "$DomainNETBIOSRaw\".ToUpper()
                    $DomainAdmin = "$($DomainNETIBIOS)Administrateur"
                    Add-Computer -Domain $DomainName -Restart -Credential $DomainAdmin
                }
                1 { $Disk = Get-Disk -Number 3 -ErrorAction SilentlyContinue
                    if ($Null -eq $Disk) {
                        Write-Host "Disques SYSVOL BDD & LOGS absents de la VM"
                    }
                    else {
                    Initialize-Disk -Number 1
                    New-Partition -DiskNumber 1 -DriveLetter B -UseMaximumSize
                    Format-Volume -DriveLetter B -FileSystem NTFS -Confirm:$false -NewFileSystemLabel BDD
                    Initialize-Disk -Number 2
                    New-Partition -DiskNumber 2 -DriveLetter L -UseMaximumSize
                    Format-Volume -DriveLetter L -FileSystem NTFS -Confirm:$false -NewFileSystemLabel LOGS
                    Initialize-Disk -Number 3
                    New-Partition -DiskNumber 3 -DriveLetter S -UseMaximumSize
                    Format-Volume -DriveLetter S -FileSystem NTFS -Confirm:$false -NewFileSystemLabel SYSVOL

                    Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
                    Import-Module ADDSDeployment
                    $DNSIP = Get-DnsClientServerAddress | Select-Object -ExpandProperty ServerAddresses | Select-Object -First 1
                    $FQDN = (Resolve-DnsName -Name $DNSIP).NameHost
                    $DomainRaw = $FQDN -Split "\." | Select-Object -Last 2
                    $DomainName = $DomainRaw -Join "."
                    $DomainNETBIOSRaw = $DomainRaw | Select-Object -SkipLast 1 
                    $DomainNETIBIOS = "$DomainNETBIOSRaw\".ToUpper()
                    $DomainAdmin = "$($DomainNETIBIOS)Administrateur"
                    $ForestConfiguration = @{
                        '-DatabasePath'           = 'B:\NTDS';
                        '-DomainName'             = $DomainName;
                        '-InstallDns'             = $true;
                        '-LogPath'                = 'L:\NTDS';
                        '-NoRebootOnCompletion'   = $false;
                        '-SysvolPath'             = 'S:\SYSVOL';
                        '-Force'                  = $true;
                        '-CreateDnsDelegation'    = $false;
                        '-NoGlobalCatalog'        = $false;
                        '-ReplicationSourceDC'    = $FQDN;
                        '-CriticalReplicationOnly'= $false;
                        '-SiteName'               = "Default-First-Site-Name";
                        '-Credential'             =  (Get-Credential $DomainAdmin)
                        }
                        Install-ADDSDomainController @ForestConfiguration
                    }
                }
                2 { $Disk = Get-Disk -Number 3 -ErrorAction SilentlyContinue
                    if ($Null -eq $Disk) {
                        Write-Host "Disques SYSVOL BDD & LOGS absents de la VM"
                    }
                    else {
                    Initialize-Disk -Number 1
                    New-Partition -DiskNumber 1 -DriveLetter B -UseMaximumSize
                    Format-Volume -DriveLetter B -FileSystem NTFS -Confirm:$false -NewFileSystemLabel BDD
                    Initialize-Disk -Number 2
                    New-Partition -DiskNumber 2 -DriveLetter L -UseMaximumSize
                    Format-Volume -DriveLetter L -FileSystem NTFS -Confirm:$false -NewFileSystemLabel LOGS
                    Initialize-Disk -Number 3
                    New-Partition -DiskNumber 3 -DriveLetter S -UseMaximumSize
                    Format-Volume -DriveLetter S -FileSystem NTFS -Confirm:$false -NewFileSystemLabel SYSVOL

                    $NameNetBIOS = Read-Host "Nommez le NETBIOS"
                    $NameDomain = Read-Host "Nommez le domaine"
                    Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
                    Import-Module ADDSDeployment
                    Install-ADDSForest `
                    -CreateDnsDelegation:$false `
                    -DatabasePath "B:\NTDS" `
                    -DomainMode "WinThreshold" `
                    -DomainName: $NameDomain `
                    -DomainNetbiosName: $NameNetBIOS `
                    -ForestMode "WinThreshold" `
                    -InstallDns: $true `
                    -LogPath "L:\NTDS" `
                    -NoRebootOnCompletion:$false `
                    -SysvolPath "S:\SYSVOL" `
                    -Force:$true
                    }
                }
            }
        }
    }
}
function ProAd {
    $Title = "Menu de sélection Post AD"
    $Prompt = "Faire choix"
    $SDC = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration des Serveurs Contrôleur de &Domaine","Zone inversée DNS")
    $SMB = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration des &Serveurs","Ajout de fonctionnalitées")
    $AD = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration &Active Directory","Création de groupes, d'utilisateurs et d'OU")
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($SDC, $SMB, $AD)
    $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
    Switch ($Choice) {
        0 { $Title = "Configuration des Serveurs Contrôleur de Domaine"
            $Prompt = "Faire choix"
            $ReverseDNS = [System.Management.Automation.Host.ChoiceDescription]::New("Zone inversée &DNS","Création de la Zone Inversée pour les Contrôleurs de Domaine")
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($ReverseDNS)
            $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
            Switch ($Choice) {
                0 { Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4Address | Out-Host
                    $DNSInterface = Read-Host "Choisir le numero d`'interface"
                    $DNSIP = (Get-NetIPAddress -InterfaceIndex $DNSInterface -AddressFamily IPv4).IPAddress
                    Get-DNSClientServerAddress -InterfaceIndex $DNSInterface -AddressFamily IPv6 | Set-DnsClientserveraddress -ResetServerAddresses
                    Set-DnsClientServerAddress -InterfaceIndex $DNSInterface -ServerAddresses $DNSIP
                    $NetworkIP = Read-Host "Saisissez l`'adresse du reseau au format IP/CIDR"
                    Add-DNSServerPrimaryZone -NetworkId $NetworkIP -ReplicationScope Domain -DynamicUpdate Secure
                    ipconfig /registerdns }
            }
        }
    }
}
function console {
    [CmdletBinding()]
    param(
        [Parameter()]
        [String]$TitleP1 = (Write-Output "1: Setup des machines Pré Domaine"),
        [Parameter()]
        [String]$TitleP2 = (Write-Output "2: Setup des machines Post Domaine")
    )
    Clear-Host
    $TitleP1
    $TitleP2
    $Choice = Read-Host -Prompt "Faire choix"
    Switch ($Choice) {
        1 {PrAd}
        2 {ProAd}
        Q {Exit}
        default {console}
    }
}
console