function PostAd {
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
                            Write-Host "Contrôleur Principal identifié... Configuration" -ForegroundColor DarkCyan; Start-Sleep -Seconds 1
                            Get-DNSClientServerAddress -InterfaceIndex $NIC -AddressFamily IPv6 | Set-DnsClientserveraddress -ResetServerAddresses
                            Set-DnsClientServerAddress -InterfaceIndex $NIC -ServerAddresses $FQDNDC01IP,$FQDNDC02IP
                            ipconfig /registerdns
                            Restart-Service DNS -Force
                            Unregister-ScheduledJob *
                            Remove-Job *
                            console
                        }
                        else {
                            Write-Host "Contrôleur Secondaire identifié... Configuration" -ForegroundColor DarkCyan; Start-Sleep -Seconds 1
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

                        Add-DhcpServerv4Failover -Name $FailOverName -ComputerName $FQDNDC01 -PartnerServer $FQDNDC02 -ServerRole Primary -ScopeId $Scope -SharedSecret $Secret
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
                    New-ADOrganizationalUnit -Name "Serveurs" -Path $DomainRootOU -ProtectedFromAccidentalDeletion:$false
                    $AllFS.DistinguishedName | Foreach-Object { Move-ADObject -Identity $_ -TargetPath "OU=Serveurs,$(Get-ADDomain)"}
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
                    Invoke-Expression -Command "wdsutil /set-server /AnswerClients:All /Authorize:Yes  /UseDHCPPorts:No /DHCPOption60:Yes /Transport /ObtainIpv4From:Dhcp"
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
        2 { $DomainRootOU = "$(Get-ADDomain)"
            $RootLayerA = "Service"
            $RootLayerB = "Direction"
            $RootLayerC = "Commun"
            $GeneralOU = @("Utilisateurs","Groupes","Ordinateurs","Imprimantes")
            $Title = "Configuration Active Directory"
            $Prompt = "Faire choix"
            $NewOU = [System.Management.Automation.Host.ChoiceDescription]::New("Nouvelle Unité d'&Organisation","Nécessite 2 Contrôleurs de Domaine et 2 Serveurs de Fichier")
            $NewGroup = [System.Management.Automation.Host.ChoiceDescription]::New("Nouveau &Groupe","Configuration d'un système RAID 1 ou 5")
            $NewUser = [System.Management.Automation.Host.ChoiceDescription]::New("Nouvel &Utilisateur","Création d'un pool LUN et d'une Cible iSCSI associée")
            $AddGroup = [System.Management.Automation.Host.ChoiceDescription]::New("&Ajout d'utilisateurs aux groupes","Reprend le CSV créé pour les utilisateurs et les ajoutes aux groupes")
            $Options = [System.Management.Automation.Host.ChoiceDescription[]]($NewOU, $NewGroup, $NewUser)
            $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
            Switch ($Choice) {
                0 { #Layer1, Racine
                    Write-Host -ForegroundColor DarkCyan "Pensez à modifier dans le script les OU afin que ça ressemble ce que vous voulez"
                    $RootLayer1 = Read-Host -Prompt "Nom de l'OU racine qui contiendra le reste des OU?"
                    New-ADOrganizationalUnit -Name $RootLayer1 -Path "$DomainRootOU" -ProtectedFromAccidentalDeletion:$false
                    Get-ADOrganizationalUnit -Identity "OU=Serveurs,$DomainRootOU)" | Move-ADObject -TargetPath "$RootLayer1,$DomainRootOU" -ErrorAction SilentlyContinue

                    #LayerA, en dessous du Layer1
                    New-ADOrganizationalUnit -Name $RootLayerA -Path "OU=$RootLayer1,$DomainRootOU" -ProtectedFromAccidentalDeletion:$false
                    $GeneralOU | Foreach-Object {
                        New-ADOrganizationalUnit -Name $_ -Path "OU=$RootLayerA,OU=$RootLayer1,$DomainRootOU" -ProtectedFromAccidentalDeletion:$false
                    }

                    #LayerB, en dessous du Layer1
                    New-ADOrganizationalUnit -Name $RootLayerB -Path "OU=$RootLayer1,$DomainRootOU" -ProtectedFromAccidentalDeletion:$false
                    $GeneralOU | Foreach-Object {
                        New-ADOrganizationalUnit -Name $_ -Path "OU=$RootLayerB,OU=$RootLayer1,$DomainRootOU" -ProtectedFromAccidentalDeletion:$false
                        }

                    #LayerC, en dessous du Layer1
                    New-ADOrganizationalUnit -Name $RootLayerC -Path "OU=$RootLayer1,$DomainRootOU" -ProtectedFromAccidentalDeletion:$false
                    $GeneralOU | Foreach-Object {
                        New-ADOrganizationalUnit -Name $_ -Path "OU=$RootLayerC,OU=$RootLayer1,$DomainRootOU" -ProtectedFromAccidentalDeletion:$false
                        }
                }
                1 { $Layers = @($RootLayerA, $RootLayerB, $RootLayerC)
                       $Layers | Foreach-Object {

                        $GlobalGroup = "GG_$_"
                        $UniversalGroup = "GU_$_"
                        $DomainLocalGroup = "GDL_$($_)_RW"

                        $Path = "OU=$($GeneralOU[1]),OU=$_,OU=$(Get-ADOrganizationalUnit -Filter * -SearchBase $(Get-ADDomain) -SearchScope OneLevel | Where-Object -Property Name -NotLike *Domain* | Select-Object -ExpandProperty Name),$DomainRootOU"
                        New-ADGroup -GroupCategory Security -GroupScope Global -Name $GlobalGroup -Path $Path
                        New-ADGroup -GroupCategory Security -GroupScope Universal -Name $UniversalGroup -Path $Path
                        New-ADGroup -GroupCategory Security -GroupScope DomainLocal -Name $DomainLocalGroup -Path $Path
                        Add-ADGroupMember -Identity $UniversalGroup -Members $GlobalGroup
                        Add-ADGroupMember -Identity $DomainLocalGroup -Members $UniversalGroup
                    }
                }
                2 { $Layers = @($RootLayerA, $RootLayerB, $RootLayerC)
                    Import-Module -Name NameIT
                    $Layers | ForEach-Object {
                        $LayerName = $_
                        [int]$UserNumber = Read-Host -Prompt "Combien d'utilisateurs créer dans $LayerName ?"
                        $PreCSV = Invoke-Generate "[Person] $LayerName GDL_$($LayerName)_RW" -Count $UserNumber
                        $CSVData = $PreCSV | Foreach-Object {
                            $Headers = $_ -Split " "
                            [PSCustomObject]@{
                                GivenName = $Headers[0]
                                Surname = $Headers[1]
                                OU = $Headers[2]
                                Group = $Headers[3]
                            }
                        }
                        $CSVData | Export-CSV -Path "$env:USERPROFILE\Documents\ADUser$LayerName.csv" -Delimiter ";" -Encoding utf8 -NoTypeInformation
                    }
                    Get-ChildItem -Path "$env:USERPROFILE\Documents" | Where-Object -Property Extension -eq ".csv" | Select-Object -ExpandProperty FullName | Foreach-Object {
                        Import-Csv -Path $_ -Delimiter ";" -Encoding utf8 | Foreach-Object {
                            $UserSurname = $_.Surname
                            $UserGivenName = $_.GivenName
                            $UserDisplayName = "$($_.Surname.ToUpper()) $($_.GivenName)"
                            $UserCommonName = "$($_.Surname.ToUpper()) $($_.GivenName)"
                            $SamAccountName = $_.GivenName.Substring(0,1).ToLower() + $_.Surname.Substring(0).ToLower()
                            $UserPrincipalName = "$($_.GivenName.ToLower()).$($_.Surname.ToLower())@$((Get-ADDomain).DNSRoot)"
                            $Mail = $UserPrincipalName
                            $AccountPassword = ConvertTo-SecureString "Lapinou33+" -AsPlainText -Force
                            $ADGroup = $_.Group
                            $Path = "OU=$($GeneralOU[0]),OU=$($_.OU),OU=$(Get-ADOrganizationalUnit -Filter * -SearchBase $(Get-ADDomain) -SearchScope OneLevel | Where-Object -Property Name -NotLike *Domain* | Select-Object -ExpandProperty Name),$DomainRootOU"
                            New-ADUser -Name $UserCommonName -Surname $UserSurname -GivenName $UserGivenName -SamAccountName  $SamAccountName -UserPrincipalName $UserPrincipalName -DisplayName $UserDisplayName -EmailAddress $Mail -AccountPassword $AccountPassword -Path $Path  -ChangePasswordAtLogon:$true -Enabled:$true
                            Add-ADGroupMember -Identity $ADGroup -Members $SamAccountName
                        }
                    }
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
        2 {PostAd}
        Q {Exit}
        default {console}
    }
}
console