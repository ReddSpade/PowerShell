#!TODO Ajouter la création des groupes, attribution des utilisateurs aux groupes, les droits des groupes sur les partages
#Requires -Modules Hyper-V
$script:VMPath = (Get-VMHost).VirtualMachinePath

function NewVM
{
    function WS22ORE
    {
        #Variables d'information
    $VMName = Read-Host "Quel sera le nom de la VM ?"
    $VMRAM = Read-Host "Quel sera la quantité de RAM de la VM ?"
    $GB = Invoke-Expression $VMRAM
    [int32]$Gen = Read-Host "Génération 1 ou 2 ?"
    [int32]$CoreNumber = Read-Host  "Combien de coeur pour la VM ?"

    New-Item -ItemType Directory -Name $VMName -Path $VMPath


    Copy-Item -Path "$VMPath\Sysprep\WIN22CORESYSPREP.vhdx" -Destination $VMPath\$VMName\$vmname.vhdx
    New-VM -Name $VMName -MemoryStartupBytes "$($GB)GB" -Path $VMPath -Generation $Gen
    Add-VMHardDiskDrive -VMName $VMName -path $VMPath\$VMName\$VMName.vhdx
    Set-VM -name $VMName -ProcessorCount $CoreNumber -CheckpointType Disabled
    }
    function WS22GUI
    {
        #Variables d'information
    $VMName = Read-Host "Quel sera le nom de la VM ?"
    $VMRAM = Read-Host "Quel sera la quantité de RAM de la VM ?"
    $GB = Invoke-Expression $VMRAM
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
    [int32]$Gen = Read-Host "Génération 1 ou 2 ?"
    [int32]$CoreNumber = Read-Host  "Combien de coeur pour la VM ?"

    New-Item -ItemType Directory -Name $VMName -Path $VMPath

    Copy-Item -Path "$VMPath\Sysprep\WIN10SYSPREP.vhdx" -Destination $VMPath\$VMName\$vmname.vhdx
    New-VM -Name $VMName -MemoryStartupBytes "$($GB)GB" -Path $VMPath -Generation $Gen
    Add-VMHardDiskDrive -VMName $VMName -path $VMPath\$VMName\$VMName.vhdx
    Set-VM -Name $VMName -ProcessorCount $CoreNumber -CheckpointType Disabled
    }

    Get-VM | Select-Object Name,State | Out-Host
    $Title = "Menu de création de VM"
    $Prompt = "Faire choix"
    $WS2022SRV = New-Object System.Management.Automation.Host.ChoiceDescription "Windows Server 2022 &Core","Crée une VM qui contient Windows Server 2022 (Core)"
    $WS2022GUI = New-Object System.Management.Automation.Host.ChoiceDescription "Windows Server 2022 &Graphique","Crée une VM qui contient Windows Server 2022 Experience de Bureau (GUI)"
    $W10RSAT = New-Object System.Management.Automation.Host.ChoiceDescription "Windows 10 &RSAT", "Crée une VM qui contient Windows 10 avec les outils RSAT pour le management de Serveurs"
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($WS2022SRV, $WS2022GUI, $W10RSAT)

    $Choice = $host.UI.PromptForChoice($Title, $Prompt, $options, 0)
    Switch ($Choice)
    {
        0 {WS22ORE}
        1 {WS22GUI}
        2 {W10RSAT}
    }
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
function StateManagement
{
    function On
    {
        Get-VM | Select-Object Name,State | Out-Host
        $Title = "Démarrer toute les VM ou une seule ?"
        $Prompt = "Faire choix"
        $All = New-Object System.Management.Automation.Host.ChoiceDescription "&Toutes","Lance le démarrage de chaque VM"
        $Select = New-Object System.Management.Automation.Host.ChoiceDescription "&Selection","Sélection de la VM à démarrer"

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $Select)

        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $options, 1)
        Switch ($Choice)
        {
            0 {Start-VM -VMName *}
            1 {$VMSelect = Read-Host "Choisir la VM à démarrer"
            Start-VM -name $VMSelect}
        }
    }
    function Off
    {
        Get-VM | Select-Object Name,State | Out-Host
        $Title = "Démarrer toute les VM ou une seule ?"
        $Prompt = "Faire choix"
        $All = New-Object System.Management.Automation.Host.ChoiceDescription "&Toutes","Arrêter toutes les VM"
        $Select = New-Object System.Management.Automation.Host.ChoiceDescription "&Selection","Sélection de la VM à arrêter"

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $Select)

        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $options, 1)
        Switch ($Choice)
        {
            0 {Stop-VM -VMName *}
            1 {$VMSelect = Read-Host "Choisir la VM à arrêter"
            Stop-VM -name $VMSelect}
        }
    }

    function Remove
    {
        Get-VM | Select-Object Name | Format-Table
        $Title = "Démarrer toute les VM ou une seule ?"
        $Prompt = "Faire choix"
        $All = New-Object System.Management.Automation.Host.ChoiceDescription "&Toutes","Lance la suppression de chaque VM"
        $Select = New-Object System.Management.Automation.Host.ChoiceDescription "&Selection","Sélection de la VM à supprimer"

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $Select)

        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $options, 1)
        Switch ($Choice)
        {
            0 { $VMLitteralPath = Get-VM | Select-Object -Property Path
                Stop-VM -VMName * -Force -WarningAction Ignore
                Remove-VM -Name * -Force
                Remove-Item -Path ($VMLitteralPath).Path -Recurse -Force
                Write-Host "Les VM ont toute étées supprimées"
            }
            1 { $VMSelect = Read-Host "Choisir la VM a supprimer"
                $VMLitteralPath = Get-VM | Where-Object -Property name -eq $VMSelect | Select-Object -Property Path
                Stop-VM -Name $VMSelect -Force -WarningAction Ignore
                Remove-VM -Name $VMSelect -Force
                Remove-Item -Path ($VMLitteralPath).Path -Recurse -Force
            }
        }
    }
    Get-VM | Select-Object Name | Format-Table
        $Title = "Menu de management de l'état des VM"
        $Prompt = "Faire choix"
        $On = New-Object System.Management.Automation.Host.ChoiceDescription "&Démarrage","Menu de démarrage des VM"
        $Off = New-Object System.Management.Automation.Host.ChoiceDescription "&Arrêt","Menu d'arrêt des VM"
        $Remove = New-Object System.Management.Automation.Host.ChoiceDescription "&Suppression","Menu de suppression des VM"

        $options = [System.Management.Automation.Host.ChoiceDescription[]]($On, $Off, $Remove)

        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $options, 1)
        Switch ($Choice)
        {
        0 {On}
        1 {Off}
        2 {Remove}
        }
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
        Write-Host 'Ne peut être défini qu''une fois, si une erreur a été faite, faire Remove-Variable -Name LLC,LDC' -ForegroundColor Red
            $LabLocalUserTemp = Read-Host "Utilisateur Local"
            $LabDomainUserTemp = Read-Host "Utilisateur du domaine (domaine.x\user or user@domaine.x)"
            $LabPwdTemp = Read-Host "Mot de passe utilisateur"
            $LabPwdSecureTemp = ConvertTo-SecureString $LabPwdTemp -AsPlainText -Force
            $global:LLC = New-Object System.Management.Automation.PSCredential($LabLocalUserTemp,$LabPwdSecureTemp)
            $global:LDC = New-Object System.Management.Automation.PSCredential($LabDomainUserTemp,$LabPwdSecureTemp)
            Remove-Variable -Name *Temp*
    }
   function EPS
    {
        Get-VM | Select-Object Name | Format-Table
        $VM = Read-Host "Choisir la VM pour la session PowerShell Direct"
        $LabSession = Read-Host "Ouvrir la session locale ou domaine (L/D) ?"
        if ($LabSession -eq "L" -or $LabSession -eq "Local" -or $LabSession -eq "Locale"){
            Enter-PSSession -VMName $VM -Credential $LLC
        }
        elseif ($LabSession -eq "D" -or $LabSession -eq "Domain" -or $LabSession -eq "Domaine"){
            Enter-PSSession -VMName $VM -Credential $LDC
        }
    }
    function IC
    {
        Get-VM | Select-Object Name | Format-Table
        $VM = Read-Host "Choisir la VM pour la session PowerShell Direct"
        $LabSession = Read-Host "Ouvrir la session locale ou domaine (L/D) ?"
        if ($LabSession -eq "L" -or $LabSession -eq "Local" -or $LabSession -eq "Locale"){
            $Location = Read-Host "Ecrire chemin complet des Scripts à executer sur VM (Ex: C:\Script\...)"
            Get-ChildItem -Path $Location | Select-Object -Property Name | Out-Host
            $Script = Read-Host "Choisir le script à éxecuter.."
            Invoke-Command -VMName $VM -FilePath "$Location\$Script" -Credential $LLC
        }
        elseif ($LabSession -eq "D" -or $LabSession -eq "Domain" -or $LabSession -eq "Domaine"){
            $Location = Read-Host "Ecrire chemin complet des Scripts à executer sur VM (Ex: C:\Script\...)"
            Get-ChildItem -Path $Location | Select-Object -Property Name | Out-Host
            $Script = Read-Host "Choisir le script à éxecuter.."
            Invoke-Command -VMName $VM -FilePath "$Location\$Script" -Credential $LDC
        }
    }
    Write-Host "1: Setup des credentials"
    Write-Host "2: Enter-PSSession"
    Write-Host "3: Invoke-Command"
    $EPSIC = Read-Host "Faire votre choix"
    switch ($EPSIC) {
        1 {Creds;return}
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


    Write-Host "1: Menu de création de VM"
    Write-Host "2: Créer et connecter un disque"
    Write-Host "3: Ajouter BDD/LOGS/SYSVOL"
    Write-Host "4: Menu de Management de l'état des VM"
    Write-Host "5: Connecter un Switch à une VM"
    Write-Host "6: Créer un Switch"
    Write-Host "7: EPSIC" -ForegroundColor DarkMagenta
    Write-Host "Q: Quitter le Script"

    $choix = Read-Host "Choisissez votre destin"
    switch ($choix)
        {
            1 {NewVM;pause;console}
            2 {DiskAD;pause;console}
            3 {DCDisk;pause;console}
            4 {StateManagement;pause;console}
            5 {ConnectSwitch;pause;console}
            6 {NewSwitch;pause;console}
            7 {EPSIC;pause;break}
            Q {exit}
            default {console}
        }
}

console
