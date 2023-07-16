#!TODO Ajouter la création des groupes, attribution des utilisateurs aux groupes, les droits des groupes sur les partages
Import-Module Hyper-V
$global:VMPath = (Get-VMHost).VirtualMachinePath
function WIN22ORE
{
    #Variables d'information
$VMName = Read-Host "Quel sera le nom de la VM ?"
$VMRAM = Read-Host "Quel sera la quantité de RAM de la VM ?"
$GB = Invoke-Expression $VMRAM
#$VMVHD = Read-Host "Où sera localisé le disque dur VHD ?"
#$VMVHDSPACE = Read-Host "De combien de GB sera le disque dur ?"
#$GB2 = Invoke-Expression  $VMVHDSPACE
[int32]$Gen = Read-Host "Génération 1 ou 2 ?"
[int32]$CoreNumber = Read-Host  "Combien de coeur pour la VM ?"

New-Item -ItemType Directory -Name $VMName -Path $VMPath

Copy-Item -Path "$VMPath\Sysprep\WIN22CORESYSPREP.vhdx" -Destination $VMPath\$VMName\$vmname.vhdx
New-VM -Name $VMName -MemoryStartupBytes "$($GB)GB" -Path $VMPath -Generation $Gen
Add-VMHardDiskDrive -VMName $VMName -path $VMPath\$VMName\$VMName.vhdx
Set-VM -name $VMName -ProcessorCount $CoreNumber -CheckpointType Disabled
}
function WIN22GUI
{
    #Variables d'information
$VMName = Read-Host "Quel sera le nom de la VM ?"
$VMRAM = Read-Host "Quel sera la quantité de RAM de la VM ?"
$GB = Invoke-Expression $VMRAM
#$VMVHD = Read-Host "Où sera localisé le disque dur VHD ?"
#$VMVHDSPACE = Read-Host "De combien de GB sera le disque dur ?"
#$GB2 = Invoke-Expression  $VMVHDSPACE
[int32]$Gen = Read-Host "Génération 1 ou 2 ?"
[int32]$CoreNumber = Read-Host  "Combien de coeur pour la VM ?"

New-Item -ItemType Directory -Name $VMName -Path $VMPath

Copy-Item -Path "$VMPath\Sysprep\WIN22GUISYSPREP.vhdx" -Destination $VMPath\$VMName\$vmname.vhdx
New-VM -Name $VMName -MemoryStartupBytes "$($GB)GB" -Path $VMPath -Generation $Gen
Add-VMHardDiskDrive -VMName $VMName -path $VMPath\$VMName\$VMName.vhdx
Set-VM -name $VMName -ProcessorCount $CoreNumber -CheckpointType Disabled
}

function W10RSAT
{
    #Variables d'information
$VMName = Read-Host "Quel sera le nom de la VM ?"
$VMRAM = Read-Host "Quel sera la quantité de RAM de la VM ?"
$GB = Invoke-Expression $VMRAM
#$VMVHD = Read-Host "Où sera localisé le disque dur VHD ?"
#$VMVHDSPACE = Read-Host "De combien de GB sera le disque dur ?"
#$GB2 = Invoke-Expression  $VMVHDSPACE
[int32]$Gen = Read-Host "Génération 1 ou 2 ?"
[int32]$CoreNumber = Read-Host  "Combien de coeur pour la VM ?"

New-Item -ItemType Directory -Name $VMName -Path $VMPath

Copy-Item -Path "$VMPath\Sysprep\WIN10SYSPREP.vhdx" -Destination $VMPath\$VMName\$vmname.vhdx
New-VM -Name $VMName -MemoryStartupBytes "$($GB)GB" -Path $VMPath -Generation $Gen
Add-VMHardDiskDrive -VMName $VMName -path $VMPath\$VMName\$VMName.vhdx
Set-VM -name $VMName -ProcessorCount $CoreNumber -CheckpointType Disabled
}
function DCDisk{
    Get-VM | Select-Object Name | Format-Table
    Pause
    $VMNameAdd = Read-Host "Choisir la VM pour rajout des disques durs"
    $VMFullPath = "$VMPath\$VMNameAdd"

    New-VHD -Path $VMFullPath"\bdd.vhdx" -SizeBytes 4196MB
    New-VHD -Path $VMFullPath"\logs.vhdx" -SizeBytes 4196MB
    New-VHD -Path $VMFullPath"\sysvol.vhdx" -SizeBytes 4196MB

    Add-VMHardDiskDrive -VMName $VMNameAdd -ControllerType SCSI -ControllerNumber 0 -Path $VMFullPath"\bdd.vhdx"
    Add-VMHardDiskDrive -VMName $VMNameAdd -ControllerType SCSI -ControllerNumber 0 -Path $VMFullPath"\logs.vhdx"
    Add-VMHardDiskDrive -VMName $VMNameAdd -ControllerType SCSI -ControllerNumber 0 -Path $VMFullPath"\sysvol.vhdx"
}
function DiskAD
{
    Get-VM | Select-Object Name |Format-Table
    Pause
    $VMNameAdd = Read-Host "Choisir la VM pour rajout des disques durs"
    $VHDSize = Read-Host "Veuillez entrer une taille en GB"
    $VHDName = Read-Host "Veuillez nommer votre disque"
    $GB = Invoke-Expression $VHDSize
    New-VHD -Path "$VMPath$VMNameAdd\$VHDName.vhdx" -SizeBytes "$($GB)GB"
    Add-VMHardDiskDrive -VMName $VMNameAdd -ControllerType SCSI -ControllerNumber 0 -Path "$VMPath$VMNameAdd\$VHDName.vhdx"
}

function shutdown
{
    Get-VM | Select-Object Name,State | Format-Table
    $VMSelect = Read-Host "Choisir la VM a eteindre"
    Stop-VM -name $VMSelect -Force
}

function startup
{
    Get-VM | Select-Object Name,State | Format-Table
    $VMSelect = Read-Host "Choisir la VM a demarrer"
    Start-VM -name $VMSelect
}
function delete
{
    Get-VM | Select-Object Name | Format-Table
    $VMSelect = Read-Host "Choisir la VM a supprimer"
    $VMLitteralPath = Get-VM | Where-Object -Property name -eq $VMSelect | Select-Object -Property Path
    Stop-VM -name $VMSelect -Force -WarningAction Ignore
    Remove-VM -name $VMSelect -Force
    Remove-Item -path ($VMLitteralPath).Path -Recurse -Force
}
function ConnectSwitch
{
    Get-VM | Select-Object Name, @{Name="SwitchName"; Expression={$_.NetworkAdapters | Select-Object -ExpandProperty SwitchName}} | Format-Table #Liste les machines virtuelles et les éventuels Switchs sur lesquelles elle sont connectées, [Get-VMNetworkAdapter * | Select-Object VMname,switchname | Format-Table] Serait une alterative, mais cette dernière fait une nouvelle ligne à chaque carte réseau présente sur une vm
    $VMSelect = Read-Host "Choisir la VM à connecter au Switch"
    Get-VMSwitch | Format-Table
    $VMSwitch = Read-Host "Choisir le Switch cible"
    Add-VMNetworkAdapter -Name "Carte Réseau" -SwitchName $VMSwitch -VMName $VMSelect
}
function NewSwitch
{
    Get-VMSwitch | Format-Table
    $choix = Read-Host "Switch Interne (Permet de communiquer avec l'hôte) Privé (Isolation complète) ou Externe (Accès WAN) ?"
    $SwitchName = Read-Host "Nommer le Switch"
    if ($choix -eq "Interne" -or $choix -eq "Internal") {
        New-VMSwitch -Name $SwitchName -switchtype Internal
    }
    elseif ($choix -eq "Privé" -or $choix -eq "Private" -or $choix -eq "Prive"){
        New-VMSwitch -Name $SwitchName -switchtype Private
    }
    elseif ($choix -eq "External" -or $choix -eq "Externe") {
        Get-NetAdapter | Format-Table -Property Name,InterfaceDescription,Status
        $NICName = Read-Host "Veuillez choisir dans la colonne `"Name`" votre carte réseau"
        New-VMSwitch -Name $SwitchName -NetAdapterName $NICName
    }
}
function EPSIC {
    function Creds {
            Write-Host "Ne peut être défini qu'une fois, si une erreur a été faite, faire Remove-Variable -nom [nom] -Force" -ForegroundColor Red
            $LabUserComp = Read-Host "Nom de l'utilisateur Local"
            New-Variable -Name LabUser -Option AllScope,ReadOnly -Value $LabUserComp
            $LabDomainUserComp = Read-Host "Nom de l'utilisateur du domaine (domaine.x\user ou user@domaine.x)"
            New-Variable -Name LabDomainUser -Option AllScope,ReadOnly -Value $LabDomainUserComp
            $LabPwdComp = Read-Host "Mot de passe de l'utilisateur"
            New-Variable -Name LabPwd -Option AllScope,ReadOnly -Value $LabPwdComp
            $LabPwdSecureComp = ConvertTo-SecureString $LabPwd -AsPlainText -Force
            New-Variable -Name LabPwdSecure -Option AllScope,ReadOnly -Value $LabPwdSecureComp
            $LabDomainCredentialsComp = New-Object System.Management.Automation.PSCredential($LabDomainUser,$LabPwdSecure)
            New-Variable -Name LabDomainCredentials -Option AllScope,ReadOnly -Value $LabDomainCredentialsComp
            $LabLocalCredentialsComp = New-Object System.Management.Automation.PSCredential($LabUser,$LabPwdSecure)
            New-Variable -Name LabLocalCredentials -Option AllScope,ReadOnly -Value $LabLocalCredentialsComp
            Remove-Variable -Name LabUserComp,LabDomainUserComp,LabPwdComp,LabDomainCredentialsComp,LabLocalCredentialsComp
    }
    function EPS{
        Get-VM | Select-Object Name | Format-Table
        $VM = Read-Host = "Choisir la VM pour la session PowerShell Direct"
        $LabSession = Read-Host "Ouvrir la session locale ou domaine (L/D) ?"
        if ($LabSession -eq "L" -or $LabSession -eq "Local" -or $LabSession -eq "Locale"){
            Enter-PSSession -VMName $VM -Credential $LabCredentials
        }
        elseif ($LabSession -eq "D" -or $LabSession -eq "Domain" -or $LabSession -eq "Domaine"){
            Enter-PSSession -VMName $VM -Credential $LabDomainCredentials
        }
    }
    function IC {
        Get-VM | Select-Object Name | Format-Table
        $VM = Read-Host "Choisir la VM pour la session PowerShell Direct"
        $LabSession = Read-Host "Ouvrir la session locale ou domaine (L/D) ?"
        if ($LabSession -eq "L" -or $LabSession -eq "Local" -or $LabSession -eq "Locale"){
            $Location = Read-Host "Ecrire chemin complet des Scripts à executer sur VM (Ex: C:\Script\...)"
            Get-ChildItem -Path $Location | Select-Object -Property Name | Out-Host
            $Script = Read-Host "Choisir le script à éxecuter.."
            Invoke-Command -VMName $VM -FilePath "$Location\$Script" -Credential $LabLocalCredentials
        }
        elseif ($LabSession -eq "D" -or $LabSession -eq "Domain" -or $LabSession -eq "Domaine"){
            $Location = Read-Host "Ecrire chemin complet des Scripts à executer sur VM (Ex: C:\Script\...)"
            Get-ChildItem -Path $Location | Select-Object -Property Name | Out-Host
            $Script = Read-Host "Choisir le script à éxecuter.."
            Invoke-Command -VMName $VM -FilePath "$Location\$Script" -Credential $LabDomainCredentials
        }
    }
    Write-Host "1: Setup des credentials"
    Write-Host "2: Enter-PSSession"
    Write-Host "3: Invoke-Command"
    $EPSIC = Read-Host "Faire votre choix"
    switch ($EPSIC) {
        1 {Creds}
        2 {EPS}
        3 {IC}
    }
}

function pause($message="Appuyez sur une touche pour continuer...")
{
    Write-Host -NoNewLine $message
    $null = $Host.UI.RawUI.ReadKey("noecho,includeKeydown")
    Write-Host ""
}
function console
{
    Clear-Host
    Write-Host "#######################################################" -ForegroundColor Blue
    Write-Host "#                                                     #" -ForegroundColor Blue
    Write-Host "#          ↓ Menu de management VM Hyper-V ↓          #" -ForegroundColor Blue
    Write-Host "#                                                     #" -ForegroundColor Blue
    Write-Host "#######################################################" -ForegroundColor Blue


    Write-Host "1: Création VM Windows Server Core 2022"
    Write-Host "2: Création VM Windows Server Graphique 2022"
    Write-Host "3: Création VM Windows 10 avec rôles RSAT"
    Write-Host "4: Créer et connecter un disque"
    Write-Host "5: Ajouter BDD/LOGS/SYSVOL"
    Write-Host "6: Eteindre VM"
    Write-Host "7: Demarrer une VM"
    Write-Host "8: Supprimer une VM"
    Write-Host "9: Connecter un Switch à une VM"
    Write-Host "10: Créer un Switch"
    Write-Host "11: EPSIC" -ForegroundColor DarkMagenta
    Write-Host "Q: Quitter le Script"

    $choix = Read-Host "Choisissez votre destin"
    switch ($choix)
        {
            1 {WIN22ORE;pause;console}
            2 {WIN22GUI;pause;console}
            3 {W10RSAT;pause;console}
            4 {DiskAD;pause;console}
            5 {DCDisk;pause;console}
            6 {shutdown;pause;console}
            7 {startup;pause;console}
            8 {delete;pause;console}
            9 {ConnectSwitch;pause;console}
            10 {NewSwitch;pause;console}
            11 {EPSIC;pause;exit}
            Q {exit}
            default {console}
        }
}
console