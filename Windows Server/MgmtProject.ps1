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
            $ADMainDC = [System.Management.Automation.Host.ChoiceDescription]::New("Créer la Forêt &Active Directory","Création de la Forêt Active Directory, promotion en tant que Contrôleur de Domaine + Configuration DNS")
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($ADUser, $ADDC, $ADMainDC)
            $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
            Switch ($Choice) {
                0 { $DNSIP = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses | Select-Object -First 1
                    $FQDN = (Resolve-DnsName -Name $DNSIP).NameHost
                    $DomainRaw = $FQDN -Split "\." | Select-Object -Last 2
                    $DomainName = $DomainRaw -Join "."
                    $DomainNETBIOSRaw = $DomainRaw | Select-Object -SkipLast 1
                    $DomainNETIBIOS = "$DomainNETBIOSRaw\".ToUpper()
                    $DomainAdmin = "$($DomainNETIBIOS)Administrateur"
                    Add-Computer -Domain $DomainName -Restart -Credential $DomainAdmin
                }
                1 { Import-Module -Name PSScheduledJob
                    Register-ScheduledJob -Name "ReverseDNSSetup" -ScriptBlock {
                    $NIC = (Get-NetAdapter).ifIndex
                    $DomainMainDC = (Get-ADDomain).DNSRoot
                    $DomainMainDCIP = (Resolve-DNSName -Name $DomainMainDC | Where-Object -Property Type -eq A).IPAddress
                    Get-DNSClientServerAddress -InterfaceIndex $NIC -AddressFamily IPv6,IPv4 | Set-DnsClientserveraddress -ResetServerAddresses
                    Set-DnsClientServerAddress -InterfaceIndex $NIC -ServerAddresses $DomainMainDCIP
                    ipconfig /registerdns
                    Unregister-ScheduledJob *
                    Remove-Job *
                    }
                    $Disk = Get-Disk -Number 3 -ErrorAction SilentlyContinue
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
                    $DomainNETIBIOS = "$DomainNETBIOSRaw".ToUpper()
                    $DomainAdmin = "$DomainNETIBIOS\Administrateur"
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
                        if ($DomainNETIBIOS.Length -le 1 ) {
                            Write-Error "Erreur DNS, regarder le Contrôleur Principal du Domaine..." -ErrorAction Break
                        }
                        else {
                        Install-ADDSDomainController @ForestConfiguration
                        }
                    }
                }
                2 { Import-Module -Name PSScheduledJob
                    Register-ScheduledJob -Name "ReverseDNSSetup" -ScriptBlock {
                    $NIC = (Get-NetAdapter).ifIndex
                    $FQDNDC01IP = (Get-NetIPAddress -InterfaceIndex $NIC -AddressFamily IPv4).IPAddress
                    Get-DNSClientServerAddress -InterfaceIndex $NIC -AddressFamily IPv6,IPv4 | Set-DnsClientserveraddress -ResetServerAddresses
                    Set-DnsClientServerAddress -InterfaceIndex $NIC -ServerAddresses $FQDNDC01IP
                    $NetworkIP = $FQDNDC01IP -Split "\."; $NetworkIP[3] = 0; $NetworkIP = $NetworkIP -Join "."; $NetworkIP += "/24"
                    Add-DNSServerPrimaryZone -NetworkId $NetworkIP -ReplicationScope Domain -DynamicUpdate Secure
                    ipconfig /registerdns
                    Unregister-ScheduledJob *
                    Remove-Job *
                    } -Trigger (New-JobTrigger -AtStartup) -ScheduledJobOption (New-ScheduledJobOption -RunElevated)

                    $Disk = Get-Disk -Number 3 -ErrorAction SilentlyContinue
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

                    $NameDomain = Read-Host "Nommez le domaine"
                    $NameNetBIOS = $NameDomain -Split "\."; $NameNetBIOS = $NameNetBIOS[0].ToUpper()
                    Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature
                    Import-Module ADDSDeployment
                    $NewForestConfiguration = @{
                        '-CreateDnsDelegation'     = $false;
                        '-DatabasePath'            = 'B:\NTDS';
                        '-DomainMode'              = 'WinThreshold';
                        '-DomainName'              = $NameDomain;
                        '-DomainNetbiosName'       = $NameNetBIOS;
                        '-ForestMode'              = 'WinThreshold';
                        '-InstallDns'              = $true;
                        '-LogPath'                 = 'L:\NTDS';
                        '-NoRebootOnCompletion'    = $false;
                        '-SysvolPath'              = 'S:\SYSVOL';
                        '-Force'                   = $true;
                    }
                    Install-ADDSForest @NewForestConfiguration
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
    $SDM = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration des &Serveurs","Ajout de fonctionnalitées")
    $AD = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration &Active Directory","Création de groupes, d'utilisateurs et d'OU")
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($SDC, $SDM, $AD)
    $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
    Switch ($Choice) {
        0 { $Title = "Configuration des Serveurs Contrôleur de Domaine"
            $Prompt = "Faire choix"
            $ReverseDNS = [System.Management.Automation.Host.ChoiceDescription]::New("Zone inversée &DNS","Création de la Zone Inversée")
            $DHCP = [System.Management.Automation.Host.ChoiceDescription]::New("Installation D&HCP + Failover (Exécuter sur DC01)","Installation du DHCP sur le DC01 et Failover sur le DC02")
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($ReverseDNS, $DHCP)
            $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
            Switch ($Choice) {
                0 { $global:OwnFQDN = [System.Net.Dns]::GetHostByName($env:computerName).HostName
                    $DCCheck = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
                    if ($DCCheck.Count -lt 2) {
                        Write-Warning "Il n'y a qu'un Contrôleur de doamine. Merci de rajouter le DC02."
                    }
                    else {
                        $FQDNDC01 = (Get-ADDomain).InfrastructureMaster
                        $FQDNDC01IP = (Resolve-DNSName -Name $FQDNDC01 | Where-Object -Property Type -eq A).IPAddress
                        $FQDNDC02 = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName | Where-Object {$_ -notlike $FQDNDC01}
                        $FQDNDC02IP = (Resolve-DNSName -Name $FQDNDC02 | Where-Object -Property Type -eq A).IPAddress
                        $NIC = (Get-NetAdapter).ifIndex
                        if ($FQDNDC01 -eq $OwnFQDN) {
                            Write-Host "Contrôleur Principal identifié... Configuration" -ForegroundColor Blue; Start-Sleep -Seconds 1
                            Get-DNSClientServerAddress -InterfaceIndex $NIC -AddressFamily IPv6 | Set-DnsClientserveraddress -ResetServerAddresses
                            Set-DnsClientServerAddress -InterfaceIndex $NIC -ServerAddresses $FQDNDC01IP,$FQDNDC02IP
                            ipconfig /registerdns
                            Restart-Service DNS -Force
                            Unregister-ScheduledJob *
                            Remove-Job *
                            console
                        }
                        else {
                            Write-Host "Contrôleur Secondaire identifié... Configuration" -ForegroundColor Blue; Start-Sleep -Seconds 1
                            Get-DNSClientServerAddress -InterfaceIndex $NIC -AddressFamily IPv6 | Set-DnsClientserveraddress -ResetServerAddresses
                            Set-DnsClientServerAddress -InterfaceIndex $NIC -ServerAddresses $FQDNDC02IP,$FQDNDC01IP
                            ipconfig /registerdns
                            Unregister-ScheduledJob *
                            Remove-Job *
                            Restart-Service DNS -Force
                            console
                        }
                    }
                }
                1 { $DCCheck = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName
                    if ($DCCheck.Count -lt 2) {
                    Write-Warning "Il n'y a qu'un Contrôleur de doamine. Merci de rajouter le DC02."; Start-Sleep -Seconds 1; console
                }
                    else {
                        Install-WindowsFeature DHCP -IncludeManagementTools

                        $Pool = Read-Host "Saisir le nom de l`'etendue"
                        $FirstIP = Read-Host "Saisir la première IP attribuable de l`'étendue"
                        $LastIP = Read-Host "Saisir la IP dernière attribuable de l`'étendue"
                        $PoolMask = Read-Host "Saisir le masque sous-réseau de l`'étendue"
                        $DHCPGateway = Read-Host "Saisir la passerelle de l`'étendue"
                        $NetworkIP = $FirstIP -Split "\."; $NetworkIP[3] = 0; $NetworkIP = $NetworkIP -Join "."
                        $Domain = (Get-ADDomain).DNSRoot
                        $FQDNDC01 = (Get-ADDomain).InfrastructureMaster
                        $FQDNDC01IP = Get-NetIPAddress -AddressFamily IPv4 | Select-Object -ExpandProperty IPaddress -First 1
                        $FQDNDC02 = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName | Where-Object {$_ -notlike $FQDNDC01}
                        $FQDNDC02IP = (Resolve-DNSName -Name $FQDNDC02 | Where-Object -Property Type -eq A).IPAddress

                        Add-DHCPServerInDC -DNSName $FQDNDC01
                        Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2 #?Fait disparaitre le message post installation DHCP
                        Add-DHCPServerv4Scope -Name $Pool -StartRange $FirstIP -EndRange $LastIP -SubnetMask $PoolMask -State Active
                        Set-DHCPServerv4OptionValue -ScopeID $NetworkIP -DnsDomain $Domain -DnsServer $FQDNDC01IP,$FQDNDC02IP -Router $DHCPGateway

                        Invoke-Command -ComputerName $FQDNDC02 -ScriptBlock {
                            Install-WindowsFeature DHCP -IncludeManagementTools
                            Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2
                            Restart-Service DhcpServer
                        }
                        Add-DHCPServerInDC -DNSName $FQDNDC02
                        $Scope = Get-DhcpServerv4Scope -ComputerName $FQDNDC01 | Select-Object -ExpandProperty ScopeId
                        $FailOverName = Read-Host -Prompt "Nommer le Basculement"
                        $Secret = Read-Host -Prompt "Créer le mot de passe du Failover" -AsSecureString

                        Add-DhcpServerv4Failover -Name $FailOverName -ComputerName $FQDNDC01 -PartnerServer $FQDNDC02 -ServerRole Standby -ScopeId $Scope -SharedSecret $Secret
                    }
                }
            }
        }
        1 { $Title = "Configuration des Serveurs Membre du Domaine"
            $Prompt = "Faire choix"
            $FSDFS = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration du Serveur de &Fichier et réplique DFS","Nécessite 2 Contrôleurs de Domaine et 2 Serveurs de Fichier")
            $RAID = [System.Management.Automation.Host.ChoiceDescription]::New("Ajout d'un Système &RAID","Configuration d'un système RAID 1 ou 5")
            $LUN = [System.Management.Automation.Host.ChoiceDescription]::New("Configuration d'une &LUN avec cible iSCSI","Création d'un pool LUN et d'une Cible iSCSI associée")
            $WDS = [System.Management.Automation.Host.ChoiceDescription]::New("Installation du &WDS","Installe le rôle Windows Deployment Services")
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($FSDFS, $WDS, $LUN, $RAID)
            $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
            Switch ($Choice) {
                0 { $FQDNDC01 = (Get-ADDomain).InfrastructureMaster
                    $OwnFQDN = [System.Net.Dns]::GetHostByName($env:computerName).HostName
                    if ($OwnFQDN -ne $FQDNDC01) {
                        Write-Error "A executer sur le DC01, ceci n'est pas le DC01" -ErrorAction Stop
                    }
                    else {
                    $DomainName = (Get-ADDomain).dnsroot
                    $DomainRootOU = (Get-ADDomain).DistinguishedName
                    $FQDNDC02 = Get-ADDomainController -Filter * | Select-Object -ExpandProperty HostName | Where-Object {$_ -notlike $FQDNDC01}
                    $AllFS =  Get-ADComputer -Filter * | Select-Object -Property DNSHostName,DistinguishedName | Where-Object {$_ -like "*FS*" -or $_ -like "*SF*"}
                    New-ADOrganizationalUnit -Name "Serveurs" -Path $DomainRootOU
                    $AllFS.DistinguishedName | Foreach-Object { Move-ADObject -Identity $_ -TargetPath "OU=Serveurs,DC=$DomainOU01,DC=$DomainOU02"}
                    $FQDNFS01 = $AllFS[0].DNSHostName
                    $FQDNFS02 = $AllFS[1].DNSHostName
                    $NameSpace = Read-Host "Saisir le nom du partage"
                    $PathDC01 = "\\$FQDNDC01\$NameSpace"
                    $PathDC02 = "\\$FQDNDC02\$NameSpace"
                    $PathFS01 = "\\$FQDNFS01\$NameSpace"
                    $PathFS02 = "\\$FQDNFS02\$NameSpace"
                    $DFSRoot = "\\$DomainName\$NameSpace"
                    Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
                    Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools
                    New-Item -ItemType Directory -Path "C:\DFSRoot\$NameSpace"
                    $ESID = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                    $EName = $ESID.Translate([System.Security.Principal.NTAccount]).Value
                    New-SmbShare -Name $NameSpace -Path "C:\DFSRoot\$NameSpace" -FullAccess $EName | Out-Host

                    Invoke-Command -ComputerName $FQDNDC02 -ScriptBlock {
                        Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
                        Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools
                        $NameSpace = Read-Host "Saisir le nom du partage"
                        New-Item -ItemType Directory -Path "C:\DFSRoot\$NameSpace"

                        $ESID = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                        $EName = $ESID.Translate([System.Security.Principal.NTAccount]).Value
                        New-SmbShare -Name $NameSpace -Path "C:\DFSRoot\$NameSpace" -FullAccess $EName | Out-Host
                    }

                    $CaptureLetterFS01 = Invoke-Command -ComputerName $FQDNFS01 -ScriptBlock {

                        Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
                        Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools

                        Get-Disk | Out-Host

                        $Disk = Read-Host "Selectionnner un disque a initialiser"
                        Initialize-Disk -Number $Disk | Out-Host

                        Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name = 'Size(GB)'; Expression = {{'{0:N2}' -f ($_.Size / 1GB) } }} | Out-Host
                        $Letter = Read-Host "Selectionner la lettre a attribuer"

                        New-Partition -DiskNumber $Disk -DriveLetter $Letter -UseMaximumSize | Out-Host
                        Format-Volume -DriveLetter $Letter -FileSystem NTFS -Confirm:$false -NewFileSystemLabel "Files" | Out-Host

                        Get-Volume $Letter | Select-Object -Property DriveLetter

                         $Compteur = 0
                        do {
                            $Compteur++

                            if ($Compteur -eq 1) {
                                $Loop = Read-Host "Voulez-vous créer un dossier pour le partage ? (Y/N)"
                            }
                            else {
                                $Loop = "yes"
                            }
                            if ($Loop -eq "yes" -or $Loop -eq "y" -or $Loop -eq "oui") {
                                $NewFolderName = Read-Host "Nommer le nouveau dossier"
                                New-Item -ItemType Directory -Path "$($Letter):\Files\$NewFolderName" | Out-Host
                                $Loop2 = Read-Host "Voulez-vous créer autre dossier pour le partage ? (Y/N)"
                            }
                            elseif ($Loop -eq "no" -or $Loop -eq "n" -or $Loop -eq "non") {
                                Write-Host "Fin de la création"

                            }
                        } until ($Loop2 -eq "no" -or $Loop2 -eq "n" -or $Loop2 -eq "non" -or $Loop -eq "no" -or $Loop -eq "n" -or $Loop -eq "non")

                        $ESID = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                        $EName = $ESID.Translate([System.Security.Principal.NTAccount]).Value
                        $ShareName = Read-Host "Nommer le partage"
                        New-SmbShare -Name $ShareName -Path "$($Letter):\Files\" -FullAccess $EName | Out-Host
                    }

                    $CaptureLetterFS02 = Invoke-Command -ComputerName $FQDNFS02 -ScriptBlock {

                        Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
                        Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools

                        Get-Disk | Out-Host

                        $Disk = Read-Host "Selectionnner un disque a initialiser"
                        Initialize-Disk -Number $Disk | Out-Host

                        Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name = 'Size(GB)'; Expression = {($_.Size / 1GB)}} | Out-Host
                        $Letter = Read-Host "Selectionner la lettre a attribuer"

                        New-Partition -DiskNumber $Disk -DriveLetter $Letter -UseMaximumSize | Out-Host
                        Format-Volume -DriveLetter $Letter -FileSystem NTFS -Confirm:$false -NewFileSystemLabel "Files" | Out-Host

                        Get-Volume $Letter | Select-Object -Property DriveLetter

                        $ESID = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
                        $EName = $ESID.Translate([System.Security.Principal.NTAccount]).Value
                        $ShareName = Read-Host "Nommer le partage"
                        New-Item -ItemType Directory -Path "$($Letter):\Files\" | Out-Host
                        New-SmbShare -Name $ShareName -Path "$($Letter):\Files\" -FullAccess $EName | Out-Host
                    }

                    New-DfsnRoot -Path $DFSRoot -Type DomainV2 -TargetPath $PathDC01
                    New-DfsnRoot -Path $DFSRoot -Type DomainV2 -TargetPath $PathDC02
                    $Folders = @(Get-ChildItem -Path "\\$FQDNFS01\Partage\")
                    $Folders.Name | ForEach-Object {
                    New-DfsnFolder -Path "$DFSRoot\$_" -TargetPath "$PathFS01\$_" -EnableTargetFailback $true -Description 'Folder for legacy software.'
                    New-DfsnFolderTarget -Path "$DFSRoot\$_" -TargetPath "$PathFS02\$_"}
                    $Folders.Name | ForEach-Object {
                        New-DfsReplicationGroup -GroupName $_ -Confirm:$false | New-DFSReplicatedFolder -Foldername $_
                        Add-DfsrMember -GroupName $_ -ComputerName $FQDNFS01,$FQDNFS02 -Confirm:$false
                        Add-DfsrConnection -GroupName $_ -SourceComputerName $FQDNFS01 -DestinationComputerName $FQDNFS02 -Confirm:$false
                        Set-DfsrMembership -GroupName $_ -FolderName $_ -ContentPath "$($CaptureLetterFS01.DriveLetter):\Files\$_" -ComputerName $FQDNFS01 -PrimaryMember $True -Confirm:$false -Force
                        Set-DfsrMembership -GroupName $_ -FolderName $_ -ContentPath "$($CaptureLetterFS02.DriveLetter):\Files\$_" -ComputerName $FQDNFS02 $True -Confirm:$false -Force
                    }
                }
                }
                1 { $Disks = Get-Disk -Number 4 -ErrorAction SilentlyContinue
                    if (-not $Disks) {
                        throw "Le disque n'existe pas"
                    }
                    $CD = Get-Volume | Where-Object DriveType -eq 'CD-ROM'
                    if (-not $CD) {
                        throw "Il n'y aucune ISO"
                    }
                    Get-WindowsFeature -Name *WDS* | Install-WindowsFeature -IncludeManagementTools
                    Get-Disk | Out-Host

                    $Disk = Read-Host "Selectionnner un disque a initialiser"
                    Initialize-Disk -Number $Disk | Out-Host

                    Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name = 'Size(GB)'; Expression = {{'{0:N2}' -f ($_.Size / 1GB) } }} | Out-Host
                    $DiskLetter = Read-Host "Selectionner la lettre a attribuer"

                    New-Partition -DiskNumber $Disk -DriveLetter $DiskLetter -UseMaximumSize | Out-Host
                    Format-Volume -DriveLetter $DiskLetter -FileSystem NTFS -Confirm:$false -NewFileSystemLabel "Files" | Out-Host

                    New-Item -ItemType Directory -Path "$($DiskLetter):\RemoteInstall"
                    Invoke-Expression -Command "wdsutil /initialize-server /remInst:$($DiskLetter):\RemoteInstall"
                    Invoke-Expression -Command "wdsutil /set-server /AnswerClients:All /Authorize:Yes  /Transport /ObtainIpv4From:Dhcp"
                    Invoke-Expression -Command "wdsutil /start-server"
                    $CDLetter = $CD.DriveLetter
                    $Index = Get-WindowsImage -ImagePath "$($CDLetter):\Sources\install.esd" | Where-Object {$_.ImageName -like "*Professionnel"} | Select-Object -ExpandProperty ImageIndex
                    Export-WindowsImage -SourceImagePath "$($CDLetter):\Sources\install.esd" -SourceIndex $Index -DestinationImagePath "$($DiskLetter):\install.wim" -CompressionType Max -CheckIntegrity
                    Import-WDSbootimage -Path "$($CDLetter):\Sources\boot.wim" -NewImageName "Microsoft Windows Setup (x64)"
                    New-WDSInstallImageGroup -Name "Windows 10"
                    Import-WdsInstallImage -Path "$($DiskLetter):\install.wim" -ImageGroup "Windows 10" -ImageName "Windows 10 Pro"
                }
                2 {Write-Host "Work-In-Progress !" -ForegroundColor Green; Start-Sleep -Seconds 1; console}
                3 {Write-Host "Work-In-Progress !" -ForegroundColor Green; Start-Sleep -Seconds 1; console}
            }
        }
        2 {
            $Title = "Configuration Active Directory"
            $Prompt = "Faire choix"
            $NewOU = [System.Management.Automation.Host.ChoiceDescription]::New("Nouvelle Unité d'&Organisation","Nécessite 2 Contrôleurs de Domaine et 2 Serveurs de Fichier")
            $NewGroup = [System.Management.Automation.Host.ChoiceDescription]::New("Nouveau &Groupe","Configuration d'un système RAID 1 ou 5")
            $NewUser = [System.Management.Automation.Host.ChoiceDescription]::New("Nouvel &Utilisateur","Création d'un pool LUN et d'une Cible iSCSI associée")
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($NewOU, $NewGroup, $NewUser)
            $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
            Switch ($Choice) {
                1 {}
                2 {}
                3 { $DomainRootOU = (Get-ADDomain).DistinguishedName
                    $DefaultUserOU = "OU=Utilisateurs,$(Get-ADDomain)"
                    $User
                }
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