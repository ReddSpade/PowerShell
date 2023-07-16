function 3disksup #? Suite de commande pour définir les 3 disques pour les emplacements nécessaires à la création un contrôleur de domaine (SYSVOL, NTDS BDD, NTDS LOGS)
{
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
}


function AD
{
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

function ReverseZone
{
    Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4Address | Format-Table #?Liste les cartes réseaux et formate la liste pour montrer la description, le numéro de l'index et l'IP associée
    $DNSInterface = Read-Host "Choisir le numero d`'interface"
    $DNSIP = (Get-NetIPAddress -InterfaceIndex $DNSInterface -AddressFamily IPv4).IPAddress
    Get-DNSClientServerAddress -InterfaceIndex $DNSInterface -AddressFamily IPv6 | Set-DnsClientserveraddress -ResetServerAddresses
    Set-DnsClientServerAddress -InterfaceIndex $DNSInterface -ServerAddresses $DNSIP
    $NetworkIP = Read-Host "Saisissez l`'adresse du reseau au format IP/CIDR" #Exemple: 192.168.1.1/24

    Add-DNSServerPrimaryZone -NetworkId $NetworkIP -ReplicationScope Domain -DynamicUpdate Secure
    ipconfig /registerdns
}

function DHCP #? Installation de la feature DHCP
{
    Install-WindowsFeature DHCP -IncludeManagementTools
    #Declaration des variables
    $Pool = Read-Host "Saisir le nom de l`'etendue"
    $FirstIP = Read-Host "Saisir la premiere adresse attribuable de l`'etendue"
    $LastIP = Read-Host "Saisir la derniere adresse attribuable de l`'etendue"
    $PoolMask = Read-Host "Saisir le masque sous-reseau de l`'etendue"
    $DHCPGateway = Read-Host "Saisir la passerelle de l`'etendue"
    $NetworkID = Read-Host "Saisir l`'IP du reseau de l`'etendue" #Finit par 0
    Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4Address | Format-Table
    $SelectNIC = Read-Host "Saisir le numéro de l`'interface"
    #$DNSIP = Get-DnsClientServerAddress -InterfaceIndex $SelectNIC -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses
    $DomainID = (Get-ADDomain).DNSRoot
    $FQDN = (Get-ADDomain).InfrastructureMaster
    #Commandes
    Add-DHCPServerInDC -DNSName $FQDN
    Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2
    Add-DHCPServerv4Scope -Name $Pool -StartRange $FirstIP -EndRange $LastIP -SubnetMask $PoolMask -State Active
    Set-DHCPServerv4OptionValue $NetworkID -DnsDomain $DomainID -DnsServer $SelectNIC -Router $DHCPGateway

}

function JoinAsDC
{
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

function JoinADAsUser #? Fonction pour rejoindre le domaine en tant qu'utilisateur
{
    $DomainName = Read-Host "Nommer le domaine"
    $Credentials = "Administrateur"

    Add-Computer -Domain $DomainName -Restart -Credential $Credentials
}
function FSDFS #? Fonction pour installer les rôles Serveur de Fichier + DFS sur les 4 Serveurs (DC1, DC2, FS1, FS2), crée les DFS Root sur les DC et les partage, les dossiers à répliquer et les partages sur les SF, et crée la réplication entre les deux SF
{
    #!Requiert 2 contrôleurs de domaine et deux serveurs de fichier pour fonctionner
    $FirstDC = Read-Host "Veuillez entrer le nom du premier DC"
    $SecondDC = Read-Host "Veuillez entrer le nom du second DC"
    $FirstFS = Read-Host "Veuillez entrer le nom du premier FS"
    $SecondFS = Read-Host "Veuillez entrer le nom du second FS"
    $DomainName = (Get-ADDomain).dnsroot
    $NameSpace = Read-Host "Saisir le nom du partage"
    $PathDC1 = "\\$FirstDC\$NameSpace"
    $PathDC2 = "\\$SecondDC\$NameSpace"
    $PathFS1 = "\\$FirstFS\$NameSpace"
    $PathFS2 = "\\$SecondFS\$NameSpace"
    $DFSRoot = "\\$DomainName\$NameSpace"
    Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
    Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools
    New-Item -ItemType Directory -Path "C:\DFSRoot\$NameSpace"
    New-SmbShare -Name $NameSpace -Path "C:\DFSRoot\$NameSpace"

    Invoke-Command -ComputerName $SecondDC -ScriptBlock {
        Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
        Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools
        $NameSpace = Read-Host "Saisir le nom du partage"
        New-Item -ItemType Directory -Path "C:\DFSRoot\$NameSpace"
        New-SmbShare -Name $NameSpace -Path "C:\DFSRoot\$NameSpace"
    }

    $CaptureLetterFS2 = Invoke-Command -ComputerName $FirstFS -ScriptBlock {

        Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
        Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools

        Get-Disk | Out-Host

        $Disk = Read-Host "Selectionnner un disque a initialiser"
        Initialize-Disk -Number $Disk | Out-Host

        Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name = 'Size(GB)'; Expression = {'{0:N2}' -f ($_.Size / 1GB) } } | Out-Host
        $Letter = Read-Host "Selectionner la lettre a attribuer"

        New-Partition -DiskNumber $Disk -DriveLetter $Letter -UseMaximumSize | Out-Host
        Format-Volume -DriveLetter $Letter -FileSystem NTFS -Confirm:$false -NewFileSystemLabel "Files" | Out-Host

        Get-Volume $Letter | Select-Object -Property DriveLetter

        $Compteur = 0

        do {
            $Compteur++

            if ($Compteur -eq 1) {
                $NewFolder = Read-Host "Voulez-vous créer un dossier pour le partage ? (Y/N)"
            }
            else {
                $NewFolder = "yes"
            }
            if ($NewFolder -eq "yes" -or $NewFolder -eq "y" -or $NewFolder -eq "oui") {
                $NewFolderName = Read-Host "Nommer le nouveau dossier"
                New-Item -ItemType Directory -Path "$($Letter):\Files\$NewFolderName" | Out-Host
                $Loop = Read-Host "Voulez-vous créer d'autres dossiers ?"
            }
            elseif ($NewFolder -eq "no" -or $NewFolder -eq "n") {
                Write-Host "Fin de la création"
            }
        } until ($Loop -eq "no" -or $Loop -eq "n" -or $Loop -eq "non")

        $ShareName = Read-Host "Nommer le partage"
        New-SmbShare -Name $ShareName -Path "$($Letter):\Files\" | Out-Host
    }

    $CaptureLetterFS2 = Invoke-Command -ComputerName $SecondFS -ScriptBlock {

        Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
        Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools

        Get-Disk | Out-Host

        $Disk = Read-Host "Selectionnner un disque a initialiser"
        Initialize-Disk -Number $Disk | Out-Host

        Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name = 'Size(GB)'; Expression = {'{0:N2}' -f ($_.Size / 1GB) } } | Out-Host
        $Letter = Read-Host "Selectionner la lettre a attribuer"

        New-Partition -DiskNumber $Disk -DriveLetter $Letter -UseMaximumSize | Out-Host
        Format-Volume -DriveLetter $Letter -FileSystem NTFS -Confirm:$false -NewFileSystemLabel "Files" | Out-Host

        Get-Volume $Letter | Select-Object -Property DriveLetter

        $Compteur = 0

        do {
            $Compteur++

            if ($Compteur -eq 1) {
                $NewFolder = Read-Host "Voulez-vous créer un dossier pour le partage ? (Y/N)"
            }
            else {
                $NewFolder = "yes"
            }
            if ($NewFolder -eq "yes" -or $NewFolder -eq "y" -or $NewFolder -eq "oui") {
                $NewFolderName = Read-Host "Nommer le nouveau dossier"
                New-Item -ItemType Directory -Path "$($Letter):\Files\$NewFolderName" | Out-Host
                $Loop = Read-Host "Voulez-vous créer d'autres dossiers ?"
            }
            elseif ($NewFolder -eq "no" -or $NewFolder -eq "n") {
                Write-Host "Fin de la création"
            }
        } until ($Loop -eq "no" -or $Loop -eq "n" -or $Loop -eq "non")

        $ShareName = Read-Host "Nommer le partage"
        New-SmbShare -Name $ShareName -Path "$($Letter):\Files\" | Out-Host
    }

    New-DfsnRoot -Path $DFSRoot -Type DomainV2 -TargetPath $PathDC1
    New-DfsnRoot -Path $DFSRoot -Type DomainV2 -TargetPath $PathDC2
    $Folders = @(Get-ChildItem -Path "\\$FirstFS\Files\" | Select-Object -Property Name)
    $Folders | ForEach-Object {
    New-DfsnFolder -Path "$DFSRoot\$_" -TargetPath "$PathFS1\$_" -EnableTargetFailback $true -Description 'Folder for legacy software.'
    New-DfsnFolderTarget -Path "$DFSRoot\$_" -TargetPath "$PathFS2\$_"
    }
    $Folders | ForEach-Object {
        New-DfsReplicationGroup -GroupName $_ -Confirm:$false | New-DFSReplicatedFolder -Foldername $_
        Add-DfsrMember -GroupName $_ -ComputerName $FirstFS,$SecondFS -Confirm:$false
        Add-DfsrConnection -GroupName $_ -SourceComputerName $FirstFS -DestinationComputerName $SecondFS -Confirm:$false
        Set-DfsrMembership -GroupName $_ -FolderName $_ -ContentPath "$($CaptureLetterFS1.DriveLetter)\Files\$_" -ComputerName $FirstFS -PrimaryMember $True -Confirm:$false -Force
        Set-DfsrMembership -GroupName $_ -FolderName $_ -ContentPath "$($CaptureLetterFS2.DriveLetter)\Files\$_" -ComputerName $SecondFS $True -Confirm:$false -Force
    }
}




function DiskInit
{
    Get-Disk
    $Disk = Read-Host "Sélectionner le disque à initialiser"
    $Letter = Read-Host "Entrer une lettre pour votre la partition"
    $NewFileLabel = Read-Host "Quel sera le nom du disque ?"
    Initialize-Disk -Number $Disk
    New-Partition -DiskNumber $Disk -DriveLetter $Letter -UseMaximumSize
    Format-Volume -DriveLetter $Letter -FileSystem NTFS -Confirm:$false -NewFileSystemLabel $NewFileLabel
}

<#function UserAD
{
    New-Item -ItemType Directory -Name UserAD -Path C:\Scripts\

    $EmplacementCSV = Read-Host "Mettre le .csv comprenant les prenom;nom;service;fonction;description (dans la même nomentlature) dans C:\Scripts et le nommer UserAD.csv "

        function pause($message="Appuyer sur une touche pour continuer")
    {
        Write-Host -NoNewline $message
        $null = $Host.UI.RawUI.ReadKey("noecho,includeKeyDown")
        Write-Host ""
    }

    $NomOU = Read-Host "Saisir Nom d'OU"
    $NomDC = (Get-ADDomain).DistinguishedName
    Write-Output $NomDC

    New-ADOrganizationalUnit -Name "$NomOU" -Path "$NomDC"

    $CSVFile = "C:\Scripts\UserAD.csv"
    $CSVData = Import-CSV -Path $CSVFile -Delimiter ";" -Encoding UTF8

    Foreach($Utilisateur in $CSVData)
    {
        $UtilisateurPrenom = $Utilisateur.Prenom
        $UtilisateurNom = $Utilisateur.Nom
        $UtilisateurLogin = $UtilisateurPrenom.Substring(0,1) + "." + $UtilisateurNom
        $UtilisateurLogin = $UtilisateurLogin.ToLower()
        Write-Host $UtilisateurLogin
        $UtilisateurFonction = $Utilisateur.Fonction

        New-ADUser -Name "$UtilisateurNom $UtilisateurPrenom" `
        -DisplayName "$UtilisateurNom $UtilisateurPrenom" `
        -GivenName $UtilisateurPrenom `
        -Surname $UtilisateurNom `
        -SamAccountName $UtilisateurLogin `
        -Title $UtilisateurFonction `
        -Path "OU=$NomOU,DC=SWORD,DC=LOCAL" `
        -AccountPassword (ConvertTo-SecureString -String "P@ssword2023!" -AsPlainText -Force) `
        -Enabled:$True

         Set-ADAccountPassword -Identity $UtilisateurLogin -Reset -NewPassword (ConvertTo-SecureString -AsPlainText "P@ssword2023!" -Force)
         Get-ADUser -Filter * -SearchBase "OU=$NomOU,DC=SWORD,DC=LOCAL" | Set-ADUser -ChangePasswordAtLogon $True

    }#>

<#function RAID ()
{
    Get-PhysicalDisk
    Get-PhysicalDisk -CanPool $true
    Get-StorageSubSystem
    $s = Get-StorageSubSystem
    $disk = (Get-PhysicalDisk -CanPool $true)
    New-StoragePool -FriendlyName "MyPool" -StorageSubSystemUniqueId $s.UniqueId -PhysicalDisks $disk -ResiliencySettingNameDefault Parity
    New-VirtualDisk -FriendlyName "RAIDS" -StoragePoolFriendlyName "MyPool" -UseMaximumSize -ResiliencySettingName Parity
    Initialize-Disk -FriendlyName "RAIDS"
    Get-Disk
    (Get-Disk | Where-Object FriendlyName -eq "RAIDS").Number
    New-Partition -DiskNumber 4 -DriveLetter R -UseMaximumSize
    Format-Volume -DriveLetter R -FileSystem NTFS -Confirm:$false -NewFileSystemLabel DATA
}#>

<#function ISCI
{
    Get-Volume
    Get-IscsiServerTarget | Format-Table TargetName,LunMappings,InitiatorIds,-MemoryStartupBytes

    $VHDXVolChoix = Read-Host "Selectionnner le volume pour le disque virtuel ISCSI"
    $VHDXNomChoix = Read-Host "Saisir le nom du disque virtuel ISCSI"
    $VHDXTailleChoix = Read-Host "Saisir la taille du disque dur virtuel ISCSI en GB"
    $VHDXPath = "$VHDXVolChoix"+"\iSCIVritualDisks\"+"$VHDXNomChoix"+".vhdx"
    $VHDXTaille = Invoke-Expression $VHDXTailleChoix

    New-IscsiVirtualDisk -Path $VHDXPath -Size $VHDXTaille

    $NameTarget = Read-Host "Selectionner le nom de la cible"
    $InitiateurIP = Read-Host "Selectionner l'IP de l'Initiateur"

    New-IscsiServerTarget -TargetPath $NameTarget -InitiatorIds IPAddress:$InitiateurIP

    Add-IscsiVritualDiskTargetMapping $NameTarget $VHDXPath -Lun 0
}#>

function console
{
    Clear-Host
    Write-Host "########################################################" -ForegroundColor Blue
    Write-Host "#                                                      #" -ForegroundColor Blue
    Write-Host "#         ↓ Menu de Gestion Active Directory ↓         #" -ForegroundColor Blue
    Write-Host "#                                                      #" -ForegroundColor Blue
    Write-Host "########################################################" -ForegroundColor Blue


    Write-Host "1: Connexion des 3 disques"
    Write-Host "2: Installation AD"
    Write-Host "3: Zone inversee DNS"
    Write-Host "4: Installation DHCP"
    Write-Host "5: Rejoindre le domain en tant que controleur de domaine"
    Write-Host "6: Rejoindre le domaine en tant qu'utilisateur"
    Write-Host "7: Initialiser un disque"
    Write-Host "8: Installer et déployer le DFS"
    Write-Host "9: Ajout des users AD"
    $choix = Read-Host "Choisissez votre destin"
    switch ($choix)
        {
            1 {3disksup;Pause;console}
            2 {AD;Pause;console}
            3 {ReverseZone;pause;console}
            4 {DHCP;pause;console}
            5 {JoinAsDC;pause;console}
            6 {JoinADAsUser;pause;console}
            7 {DiskInit;pause;console}
            8 {FSDFS;pause;console}
            9 {UserAD;pause;console}
            Q {exit}
            default {console}
        }
}
console