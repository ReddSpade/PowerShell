function PrAd {
    $Title = "Menu de sélection Pré AD"
    $Prompt = "Faire choix"
    $IP = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration des &IP","Attribution d'IP Statique ou DHCP, setup du DNS, etc..")
    $WorkStation = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration des &Postes","Modification du nom du poste, Initialisation d'un disque, création des 3 disques pour AD (Sysvol, BDD, Logs)")
    $Domain = [System.Management.Automation.Host.ChoiceDescription]::New("Rejoindre le &Domaine","Ajout du poste en tant qu'utilisateur ou contrôleur du Domaine")
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
                    Set-NetIPInterface -InterfaceIndex $SelectNIC -DHCP Enabled
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
                    New-NetIPAddress -InterfaceIndex $SelectNIC -IPAddress $IPAdress -AddressFamily IPv4 -PrefixLength $CIDR -DefaultGateway $Mask
                    }
                    elseif ($choix -eq "no" -or $choix -eq "non" -or $choix -eq "n") {
                    New-NetIPAddress -InterfaceIndex $SelectNIC -IPAddress $IPAdress -AddressFamily IPv4 -PrefixLength $CIDR
                    }
                }
                2 { Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4AddressNetIP
                    [int]$SelectNIC = Read-Host "Choisir le numero NIC souhaitee"
                    $DNSIP = Read-Host "Choisir les IP souhaitees"
                    Set-DnsClientServerAddress -InterfaceIndex $SelectNIC -Addresses $DNSIP
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
                    Write-Warning "Le poste va maintenant redémarrer."
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
                0 { $DomainName = Read-Host "Nommer le domaine"
                    $Credentials = "Administrateur"
                    Add-Computer -Domain $DomainName -Restart -Credential $Credentials
                }
                1 { #Todo Créer une boucle pour les 3 disques
                    Get-Disk | Out-Host
                    $DiskBDD = Read-Host "Sélectionner un disque pour la BDD"
                    Initialize-Disk -Number $DiskBDD
                    New-Partition -DiskNumber $DiskBDD -DriveLetter B -UseMaximumSize
                    Format-Volume -DriveLetter B -FileSystem NTFS -Confirm:$false -NewFileSystemLabel BDD
                    Get-Disk | Out-Host
                    $DiskLOGS = Read-Host "Sélectionner un disque pour les Logs"
                    Initialize-Disk -Number $DiskLOGS
                    New-Partition -DiskNumber $DiskLOGS -DriveLetter L -UseMaximumSize
                    Format-Volume -DriveLetter L -FileSystem NTFS -Confirm:$false -NewFileSystemLabel LOGS
                    Get-Disk | Out-Host
                    $DiskSYSVOL = Read-Host "Sélectionner un disque pour le SYSVOL"
                    Initialize-Disk -Number $DiskSYSVOL
                    New-Partition -DiskNumber $DiskSYSVOL -DriveLetter S -UseMaximumSize
                    Format-Volume -DriveLetter S -FileSystem NTFS -Confirm:$false -NewFileSystemLabel SYSVOL

                    Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
                    Import-Module ADDSDeployment
                    $DomainName = Read-Host "Nommer le domaine"
                    Install-ADDSDomainController `
                    -NoGlobalCatalog:$false `
                    -CreateDnsDelegation:$false `
                    -Credential (Get-Credential) `
                    -CriticalReplicationOnly:$false `
                    -DatabasePath "B:\NTDS" `
                    -DomainName $DomainName `
                    -InstallDns:$true `
                    -LogPath "L:\NTDS" `
                    -NoRebootOnCompletion:$false `
                    -SiteName "Default-First-Site-Name" `
                    -SysvolPath "S:\SYSVOL" `
                    -Force:$true `
                }
                2 { #Todo Créer une boucle pour les 3 disques
                    Get-Disk | Out-Host
                    $DiskBDD = Read-Host "Sélectionner un disque pour la BDD"
                    Initialize-Disk -Number $DiskBDD
                    New-Partition -DiskNumber $DiskBDD -DriveLetter B -UseMaximumSize
                    Format-Volume -DriveLetter B -FileSystem NTFS -Confirm:$false -NewFileSystemLabel BDD
                    Get-Disk | Out-Host
                    $DiskLOGS = Read-Host "Sélectionner un disque pour les Logs"
                    Initialize-Disk -Number $DiskLOGS
                    New-Partition -DiskNumber $DiskLOGS -DriveLetter L -UseMaximumSize
                    Format-Volume -DriveLetter L -FileSystem NTFS -Confirm:$false -NewFileSystemLabel LOGS
                    Get-Disk | Out-Host
                    $DiskSYSVOL = Read-Host "Sélectionner un disque pour le SYSVOL"
                    Initialize-Disk -Number $DiskSYSVOL
                    New-Partition -DiskNumber $DiskSYSVOL -DriveLetter S -UseMaximumSize
                    Format-Volume -DriveLetter S -FileSystem NTFS -Confirm:$false -NewFileSystemLabel SYSVOL
                    Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
                    $NameNetBIOS = Read-Host "Nommez le NETBIOS"
                    $NameDomain = Read-Host "Nommez le domaine"

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
function ProAd {

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