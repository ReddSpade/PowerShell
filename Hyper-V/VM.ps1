#!TODO Ajouter la création des groupes, attribution des utilisateurs aux groupes, les droits des groupes sur les partages
#Requires -Modules Hyper-V
function NewVM {
    function WS22CORE {
        [CmdletBinding()]
        param(
        [System.Object]$VMPath = ((Get-VMHost).VirtualMachinePath),
        [String]$VMName = (Read-Host "Nom de la VM ?"),
        [Int]$VMRAM = (Read-Host "Quantité de ram de la VM ?"),
        [ValidateSet(1,2)][Int]$VMGen = (Read-Host "Génération 1 ou 2 ?"),
        [int]$VMCoreNumber = (Read-Host  "Combien de coeur pour la VM ?")
        )
        New-Item -ItemType Directory -Name $VMName -Path $VMPath

        Copy-Item -Path "$HVMPath\Sysprep\WIN22CORESYSPREP.vhdx" -Destination $HVMPath\$VMName\$VMName.vhdx
        New-VM -Name $VMName -MemoryStartupBytes "$($VMRAM)GB" -Path $VMPath -Generation $VMGen
        Add-VMHardDiskDrive -VMName $VMName -path $HVMPath\$VMName\$VMName.vhdx
        Set-VM -Name $VMName -ProcessorCount $VMCoreNumber -CheckpointType Disabled
    }
    function WS22GUI {
        [CmdletBinding()]
        param(
        [System.Object]$HVMPath = ((Get-VMHost).VirtualMachinePath),
        [String]$VMName = (Read-Host "Nom de la VM ?"),
        [Int]$VMRAM = (Read-Host "Quantité de ram de la VM ?"),
        [ValidateSet(1,2)][Int]$VMGen = (Read-Host "Génération 1 ou 2 ?"),
        [int]$VMCoreNumber = (Read-Host  "Combien de coeur pour la VM ?")
        )
        New-Item -ItemType Directory -Name $VMName -Path $VMPath

        Copy-Item -Path "$HVMPath\Sysprep\WIN22GUISYSPREP.vhdx" -Destination $HVMPath\$VMName\$VMName.vhdx
        New-VM -Name $VMName -MemoryStartupBytes "$($VMRAM)GB" -Path $VMPath -Generation $VMGen
        Add-VMHardDiskDrive -VMName $VMName -path $HVMPath\$VMName\$VMName.vhdx
        Set-VM -name $VMName -ProcessorCount $VMCoreNumber -CheckpointType Disabled
    }

    function W10RSAT {
        [CmdletBinding()]
        param(
        [System.Object]$HVMPath = ((Get-VMHost).VirtualMachinePath),
        [String]$VMName = (Read-Host "Nom de la VM ?"),
        [Int]$VMRAM = (Read-Host "Quantité de ram de la VM ?"),
        [ValidateSet(1,2)][Int]$VMGen = (Read-Host "Génération 1 ou 2 ?"),
        [Int]$VMCoreNumber = (Read-Host  "Combien de coeur pour la VM ?")
        )
        New-Item -ItemType Directory -Name $VMName -Path $VMPath

        Copy-Item -Path "$HVMPath\Sysprep\WIN10SYSPREP.vhdx" -Destination $HVMPath\$VMName\$VMName.vhdx
        New-VM -Name $VMName -MemoryStartupBytes "$($VMRAM)GB" -Path $VMPath -Generation $Gen
        Add-VMHardDiskDrive -VMName $VMName -path $HVMPath\$VMName\$VMName.vhdx
        Set-VM -Name $VMName -ProcessorCount $VMCoreNumber -CheckpointType Disabled
    }

    Get-VM | Select-Object Name,State | Out-Host
    $Title = "Menu de création de VM"
    $Prompt = "Faire choix"
    $WS2022SRV = [System.Management.Automation.Host.ChoiceDescription]::New("Windows Server 2022 &Core","Crée une VM qui contient Windows Server 2022 (Core)")
    $WS2022GUI = [System.Management.Automation.Host.ChoiceDescription]::New("Windows Server 2022 &Graphique","Crée une VM qui contient Windows Server 2022 Experience de Bureau (GUI)")
    $W10RSAT = [System.Management.Automation.Host.ChoiceDescription]::New("Windows 10 &RSAT", "Crée une VM qui contient Windows 10 avec les outils RSAT pour le management de Serveurs")
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($WS2022SRV, $WS2022GUI, $W10RSAT)

    $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
    Switch ($Choice) {
        0 {WS22CORE}
        1 {WS22GUI}
        2 {W10RSAT}
    }
}


function DCDisk {
    Get-VM | Select-Object Name | Format-Table
    $HVMPath = (Get-vmhost).VirtualMachinePath
    $VMNameAdd = Read-Host "Choisir la VM pour rajout des disques durs"
    $VMFullPath = "$HVMPath$VMNameAdd"
    $VHDName = @("\bdd.vhdx","\logs.vhdx","\sysvol.vhdx")
    $VHDName | ForEach-Object { New-VHD -Path $VMFullPath$_ -SizeBytes 4196MB }
    $VHDName | Foreach-Object { Add-VMHardDiskDrive -VMName $VMNameAdd -Path $VMFullPath$_ -ControllerType SCSI -ControllerNumber 0 }
}
function DiskAD {
    Get-VM | Select-Object Name |Format-Table
    $VMNameAdd = Read-Host "Choisir la VM pour rajout des disques durs"
    $VHDSize = Read-Host "Veuillez entrer une taille en GB"
    $VHDName = Read-Host "Veuillez nommer votre disque"
    New-VHD -Path "$VMPath$VMNameAdd\$VHDName.vhdx" -SizeBytes "$($VHDSize)GB"
    Add-VMHardDiskDrive -VMName $VMNameAdd -ControllerType SCSI -ControllerNumber 0 -Path "$VMPath$VMNameAdd\$VHDName.vhdx"
}
function StateManagement {
    function On {
        Get-VM | Select-Object Name,State | Out-Host
        $Title = "Démarrer toute les VM ou une seule ?"
        $Prompt = "Faire choix"
        $All = [System.Management.Automation.Host.ChoiceDescription]::New("&Toutes","Lance le démarrage de chaque VM")
        $Select = [System.Management.Automation.Host.ChoiceDescription]::New("&Selection","Sélection de la VM à démarrer")
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $Select)
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 1)
        Switch ($Choice) {
            0 {Start-VM -VMName *}
            1 {$VMSelect = Get-VM | Select-Object Name | Out-GridView -PassThru
               Start-VM -Name $VMSelect.Name}
        }
    }
    function Off {
        Get-VM | Select-Object Name,State | Out-Host
        $Title = "Démarrer toute les VM ou une seule ?"
        $Prompt = "Faire choix"
        $All = [System.Management.Automation.Host.ChoiceDescription]::New("&Toutes","Arrêter toutes les VM")
        $Select = [System.Management.Automation.Host.ChoiceDescription]::New("&Selection","Sélection de la VM à arrêter")
        $Options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $Select)
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 1)
        Switch ($Choice) {
            0 {Stop-VM -VMName *}
            1 {$VMSelect = Read-Host "Choisir la VM à arrêter"
            Stop-VM -name $VMSelect}
        }
    }

    function Remove {
        Get-VM | Select-Object Name | Format-Table
        $Title = "Démarrer toute les VM ou une seule ?"
        $Prompt = "Faire choix"
        $All = [System.Management.Automation.Host.ChoiceDescription]::New("&Toutes","Lance la suppression de chaque VM")
        $Select = [System.Management.Automation.Host.ChoiceDescription]::New("&Selection","Sélection de la VM à supprimer")
        $Options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $Select)
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 1)
        Switch ($Choice) {
            0 { $VMLitteralPath = Get-VM | Select-Object -Property Path
                Stop-VM -VMName * -Force -WarningAction Ignore
                Remove-VM -Name * -Force
                Remove-Item -Path ($VMLitteralPath).Path -Recurse -Force
                Write-Host "Les VM ont toutes étées supprimées"
            }
            1 { $VMName = Get-VM | Where-Object -Property name -eq $VMSelect | Select-Object -Property Path | Out-GridView -PassThru
                Stop-VM -Name $VMName.Name -Force -WarningAction Ignore
                Remove-VM -Name $VMSelect.Name -Force
                Remove-Item -Path ($VMLitteralPath).Path -Recurse -Force
            }
        }
    }
    Get-VM | Select-Object Name | Format-Table
    $Title = "Menu de management de l'état des VM"
    $Prompt = "Faire choix"
    $On = [System.Management.Automation.Host.ChoiceDescription]::New("&Démarrage","Menu de démarrage des VM")
    $Off = [System.Management.Automation.Host.ChoiceDescription]::New("&Arrêt","Menu d'arrêt des VM")
    $Remove = [System.Management.Automation.Host.ChoiceDescription]::New("&Suppression","Menu de suppression des VM")
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($On, $Off, $Remove)
    $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 1)
    Switch ($Choice) {
    0 {On}
    1 {Off}
    2 {Remove}
    }
}
function ConnectSwitch {
    $VMSelect = Get-VM | Select-Object Name, @{Name="SwitchName"; Expression={$_.NetworkAdapters | Select-Object -ExpandProperty SwitchName}} | Out-Gridview -PassThru
    $VMSwitch = Get-VMSwitch | Out-Gridview -PassThru
    Add-VMNetworkAdapter -Name "Carte Réseau" -SwitchName $VMSwitch.Name -VMName $VMSelect.Name
}
function NewSwitch {
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
            $Script:LLC = [PSCredential]::new($LabLocalUserTemp,$LabPwdSecureTemp)
            $Script:LDC = [PSCredential]::new($LabDomainUserTemp,$LabPwdSecureTemp)
    }
    function EPS {
        Get-VM | Select-Object Name | Format-Table
        $VM = Get-VM | Select-Object Name | Out-GridView -PassThru
        $LabSession = Read-Host "Ouvrir la session locale ou domaine (L/D) ?"
        if ($LabSession -eq "L" -or $LabSession -eq "Local" -or $LabSession -eq "Locale"){
            Enter-PSSession -VMName $VM.Name -Credential $LLC
        }
        elseif ($LabSession -eq "D" -or $LabSession -eq "Domain" -or $LabSession -eq "Domaine"){
            Enter-PSSession -VMName $VM.Name -Credential $LDC
        }
    }
    function IC {
        $VM = Get-VM | Select-Object Name | Out-GridView -PassThru
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
        1 {Creds}
        2 {EPS}
        3 {IC}
    }
}

function pause ($message="Appuyez sur une touche pour continuer...") {
    Write-Host -NoNewLine $message
    $null = $Host.UI.RawUI.ReadKey("noecho,includeKeydown")
    Write-Host ""
}
function console {
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
    switch ($choix) {
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