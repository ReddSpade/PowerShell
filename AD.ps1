function 3disksup ()
{
    Get-Disk
    $DiskBDD = Read-Host "Sélectionner un disque pour la BDD"
    Initialize-Disk -Number $DiskBDD
    New-Partition -DiskNumber $DiskBDD -DriveLetter B -Size 4GB
    Format-Volume -DriveLetter B -FileSystem NTFS -Confirm:$false -NewFileSystemLabel BDD
    Get-Disk
    $DiskLOGS = Read-Host "Sélectionner un disque pour les Logs"
    Initialize-Disk -Number $DiskLOGS
    New-Partition -DiskNumber $DiskLOGS -DriveLetter L -Size 4GB
    Format-Volume -DriveLetter L -FileSystem NTFS -Confirm:$false -NewFileSystemLabel LOGS
    Get-Disk
    $DiskSYSVOL = Read-Host "Sélectionner un disque pour le SYSVOL"
    Initialize-Disk -Number $DiskSYSVOL
    New-Partition -DiskNumber $DiskSYSVOL -DriveLetter S -Size 4GB
    Format-Volume -DriveLetter S -FileSystem NTFS -Confirm:$false -NewFileSystemLabel SYSVOL
}


function AD ()
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

function ReverseZone ()
{
    Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4Address | Format-Table
    $DNSInterface = Read-Host "Choisir le numero d`'interface"
    $DNSIP = (Get-NetIPAddress -InterfaceIndex $DNSInterface -AddressFamily IPv4).IPAddress
    Get-DNSClientServerAddress -InterfaceIndex $DNSInterface -AddressFamily IPv6 | Set-DnsClientserveraddress -ResetServerAddresses
    Set-DnsClientServerAddress -InterfaceIndex $DNSInterface -ServerAddresses $DNSIP
    $NetworkIP = Read-Host "Saisissez l`'adresse du reseau au format IP/CIDR" #Exemple: 192.168.1.1/24

    Add-DNSServerPrimaryZone -NetworkId $NetworkIP -ReplicationScope Domain -DynamicUpdate Secure
    ipconfig /registerdns
}

function DHCP ()
{
    #Installation de la feature DHCP
    Install-WindowsFeature DHCP -IncludeManagementTools
    #Declaration des variables
    $Pool = Read-Host "Saisir le nom de l"etendue"
    $FirstIP = Read-Host "Saisir la premiere adresse attribuable de l"etendue"
    $LastIP = Read-Host "Saisir la derniere adresse attribuable de l"etendue"
    $PoolMask = Read-Host "Saisir le masque sous-reseau de l"etendue"
    $DHCPGateway = Read-Host "Saisir la passerelle de l"etendue"
    $NetworkID = Read-Host "Saisir l"IP du reseau de l"etendue" #Finit par 0
    Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4Address | Format-Table 
    $SelectNIC = Read-Host "Saisir le numéro de l"interface"
    #$DNSIP = Get-DnsClientServerAddress -InterfaceIndex $SelectNIC -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses
    $DomainID = (Get-ADDomain).DNSRoot
    $FQDN = (Get-ADDomain).InfrastructureMaster
    #Commandes
    Add-DHCPServerInDC -DNSName $FQDN
    Set-ItemProperty -Path registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2
    Add-DHCPServerv4Scope -Name $Pool -StartRange $FirstIP -EndRange $LastIP -SubnetMask $PoolMask -State Active
    Set-DHCPServerv4OptionValue $NetworkID -DnsDomain $DomainID -DnsServer $SelectNIC -Router $DHCPGateway

}

function JoinAsDC ()
{
    $DomainName = (Resolve-dnsname -name redlabs.fr).name

    Add-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -IncludeAllSubFeature

    Import-Module ADDSDeployment
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

function JoinADAsUser ()
{
    $DomainName = Read-Host "Veuillez nommer le domaine"
    $Rename = Read-Host "Indiquez un nouveau nom pour le poste"
    $DomainDNS = (Resolve-dnsname -name $DomainName).name | Sort-object -Unique
    Rename-Computer -NewName $Rename
    Add-Computer -Domain $DomainDNS -Restart
}

function FSDFS ()
{

    Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
    Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools
    $SecondDC = Read-Host "Veuillez entrer le nom du second DC"
    $FirstFS = Read-Host "Veuillez entrer le nom du premier FS"
    $SecondFS = Read-Host "Veuillez entrer le nom du second FS"

    Invoke-Command -ComputerName $SecondDC -ScriptBlock {
        Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
        Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools
    }

    Invoke-Command -ComputerName $FirstFS -ScriptBlock {

        Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
        Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools

        Get-Disk | Format-Table
        $Disk = Read-host "Selectionnner un disque a initialiser"

        Initialize-Disk -Number $Disk

        Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name="Size(GB)"; Expression={"{0:N2}" -f ($_.Size / 1GB)}}
        $lecteur = Read-Host "Selectionner la lettre a attribuer"

        New-Partition -DiskNumber $Disk -DriveLetter $lecteur -UseMaximumSize
        Format-Volume -DriveLetter $lecteur -FileSystem NTFS -Confirm:$false -NewFileSystemLabel DATA

        'COMMUN','SERVICES','PERSO' | Foreach-Object {New-Item -path "$($lecteur):\DATA\$_" -ItemType 'Directory'}

        New-SmbShare -Name 'Partage$' -Path $lecteur':\DATA'
        }


    Invoke-Command -ComputerName $SecondFS -ScriptBlock {

        Get-WindowsFeature FS-DFS* | Install-WindowsFeature -IncludeManagementTools
        Get-WindowsFeature FS-BranchCache | Install-WindowsFeature -IncludeManagementTools

        Get-Disk | Format-Table
        $Disk = Read-host "Selectionnner un disque a initialiser"

        Initialize-Disk -Number $Disk

        Get-Volume | Select-Object DriveLetter, FileSystemLabel, @{Name="Size(GB)"; Expression={"{0:N2}" -f ($_.Size / 1GB)}}
        $lecteur = Read-Host "Selectionner la lettre a attribuer"

        New-Partition -DiskNumber $Disk -DriveLetter $lecteur -UseMaximumSize
        Format-Volume -DriveLetter $lecteur -FileSystem NTFS -Confirm:$false -NewFileSystemLabel DATA

        'COMMUN','SERVICES','PERSO' | Foreach-Object {New-Item -path "$($lecteur):\DATA\$_" -ItemType 'Directory'}

        New-SmbShare -Name 'Partage$' -Path $lecteur':\DATA' 
    }


    $ShareRoot = Read-Host "Saisir le nom du domaine" #? Ici on renseigne le domaine, ça fait partie de l'espace de nom
    $NameSpace = Read-Host "Saisir le nom du partage" #? Exemple: Partage$, Share$, etc..
    $Path1 = "\\$($FirstFS)\$($NameSpace)" #? Combinaison des deux variable 
    $Path2 = "\\$($SecondFS)\$($NameSpace)" #? Combinaison des deux variable
    $DFSRoot = "\\$($ShareRoot)\$($NameSpace)" #?

    New-DfsnRoot -Path $DFSRoot -Type DomainV2 -TargetPath $Path1
    New-DfsnRoot -Path $DFSRoot -Type DomainV2 -TargetPath $Path2

    New-DfsnFolder -Path $DFSRoot'\COMMUN' -TargetPath $Path1'\COMMUN' -EnableTargetFailback $true -Description 'Folder for legacy software.'
    New-DfsnFolderTarget -Path $DFSRoot'\COMMUN' -TargetPath $Path2'\COMMUN'
    New-DfsnFolder -Path $DFSRoot'\PERSO' -TargetPath $Path1'\PERSO' -EnableTargetFailback $true -Description 'Folder for legacy software.'
    New-DfsnFolderTarget -Path $DFSRoot'\PERSO' -TargetPath $Path2'\PERSO'
    New-DfsnFolder -Path $DFSRoot'\SERVICES' -TargetPath $Path1'\SERVICES' -EnableTargetFailback $true -Description 'Folder for legacy software.'
    New-DfsnFolderTarget -Path $DFSRoot'\SERVICES' -TargetPath $Path2'\SERVICES'


    #New-DfsReplicationGroup -GroupName "COMMUN" -Confirm:$false
    #Add-DfsrMember -GroupName "COMMUN" -ComputerName $serv1,$serv2 -Confirm:$false
    #Add-DfsrConnection -GroupName "COMMUN" -SourceComputerName $serv1 -DestinationComputerName $serv2 -Confirm:$false
    #New-DfsReplicatedFolder -GroupName "COMMUN" -FolderName "COMMUN" -Confirm:$false
    #Set-DfsrMembership -GroupName "COMMUN" -FolderName "COMMUN" -ContentPath "$($lettre1):\COMMUN" -ComputerName $serv1 -PrimaryMember $True -Confirm:$false -Force
    #Set-DfsrMembership -GroupName "COMMUN" -FolderName "COMMUN" -ContentPath "$($lettre2):\COMMUN" -ComputerName $serv2 -Confirm:$false -Force



    #New-DfsReplicationGroup -GroupName "PERSO" -Confirm:$false
    #Add-DfsrMember -GroupName "PERSO" -ComputerName $serv1,$serv2 -Confirm:$false
    #Add-DfsrConnection -GroupName "PERSO" -SourceComputerName $serv1 -DestinationComputerName $serv2 -Confirm:$false
    #New-DfsReplicatedFolder -GroupName "PERSO" -FolderName "PERSO" -Confirm:$false
    #Set-DfsrMembership -GroupName "PERSO" -FolderName "PERSO" -ContentPath "$($lettre1):\PERSO" -ComputerName $serv1 -PrimaryMember $True -Confirm:$false -Force
    #Set-DfsrMembership -GroupName "PERSO" -FolderName "PERSO" -ContentPath "$($lettre2):\PERSO" -ComputerName $serv2 -Confirm:$false -Force



    #New-DfsReplicationGroup -GroupName "SERVICES" -Confirm:$false
    #Add-DfsrMember -GroupName "SERVICES" -ComputerName $serv1,$serv2 -Confirm:$false
    #Add-DfsrConnection -GroupName "SERVICES" -SourceComputerName $serv1 -DestinationComputerName $serv2 -Confirm:$false
    #New-DfsReplicatedFolder -GroupName "SERVICES" -FolderName "SERVICES" -Confirm:$false
    #Set-DfsrMembership -GroupName "SERVICES" -FolderName "SERVICES" -ContentPath "$($lettre1):\SERVICES" -ComputerName $serv1 -PrimaryMember $True -Confirm:$false -Force
    #Set-DfsrMembership -GroupName "SERVICES" -FolderName "SERVICES" -ContentPath "$($lettre2):\SERVICES" -ComputerName $serv2 -Confirm:$false -Force

}

function DFSReplic ()
{

}
function DiskInit ()
{
    Get-Disk
    $Disk = Read-Host "Sélectionner un disque pour la BDD"
    $Letter = Read-Host "Entrer une lettre pour votre la partition"
    $NewFileLabel = Read-Host "Quel sera le nom du disque ?"
    Initialize-Disk -Number $Disk
    New-Partition -DiskNumber $Disk -DriveLetter M -UseMaximumSize
    Format-Volume -DriveLetter $Letter -FileSystem NTFS -Confirm:$false -NewFileSystemLabel $NewFileLabel
}

function UserAD()
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

    }

}

function ISCI ()
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
}

function console ()
{
    Clear-Host
    Write-Host "Menu Script"

    Write-Host "1: Connexion des 3 disques"
    Write-Host "2: Installation AD"
    Write-Host "3: Zone inversee DNS"
    Write-Host "5: Installation DHCP"
    Write-Host "6: Rejoindre le domain en tant que controleur de domaine"
    Write-Host "7: Rejoindre le domaine en tant qu'utilisateur"
    Write-Host "8: Initialiser un disque"
    Write-Host "9: Installer et déployer le DFS"
    Write-Host "10: Ajout des users AD"
    Write-Host "11: LUN"
    $choix = Read-Host "Choisissez votre destin"
    switch ($choix)
        {
            1 {3disksup;Pause;console}
            2 {AD;Pause;console}
            3 {ReverseZone;pause;console}
            4 {DHCP;pause;console}
            5 {JoinAsDC;pause;console}
            6 {JoinADAsUser;pause;console}
            7 {JoinADAsUser;pause;console}
            8 {DiskInit;pause;console}
            9 {FSDFS;pause;console}
            10 {UserAD;pause;console}
            11 {ISCI;pause;console}
            Q {exit}
            default {console}
        }
}
console