#!TODO Ajouter la création des groupes, attribution des utilisateurs aux groupes, les droits des groupes sur les partages
#Requires -Modules Hyper-V
function VMMgmt {
    function WS22CORE {
        [CmdletBinding()]
        param(
        [System.Object]$HVMPath = ((Get-VMHost).VirtualMachinePath),
        [String]$VMName = (Read-Host "Nom de la VM ?"),
        [Int]$VMRAM = (Read-Host "Quantité de ram de la VM ?"),
        [ValidateSet(1,2)][Int]$VMGen = (Read-Host "Génération 1 ou 2 ?"),
        [int]$VMCoreNumber = (Read-Host  "Combien de coeur pour la VM ?")
        )
        New-Item -ItemType Directory -Name $VMName -Path $HVMPath

        Copy-Item -Path "$HVMPath\Sysprep\WIN22CORESYSPREP.vhdx" -Destination $HVMPath\$VMName\$VMName.vhdx
        New-VM -Name $VMName -MemoryStartupBytes "$($VMRAM)GB" -Path $HVMPath -Generation $VMGen -noswitch
        Add-VMHardDiskDrive -VMName $VMName -Path $HVMPath\$VMName\$VMName.vhdx
        Set-VM -Name $VMName -ProcessorCount $VMCoreNumber -CheckpointType Disabled
        Remove-VMNetworkAdapter -VMName $VMName
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
        New-Item -ItemType Directory -Name $VMName -Path $HVMPath

        Copy-Item -Path "$HVMPath\Sysprep\WIN22GUISYSPREP.vhdx" -Destination $HVMPath\$VMName\$VMName.vhdx
        New-VM -Name $VMName -MemoryStartupBytes "$($VMRAM)GB" -Path $HVMPath -Generation $VMGen
        Add-VMHardDiskDrive -VMName $VMName -Path $HVMPath\$VMName\$VMName.vhdx
        Set-VM -name $VMName -ProcessorCount $VMCoreNumber -CheckpointType Disabled
        Remove-VMNetworkAdapter -VMName $VMName
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
        New-Item -ItemType Directory -Name $VMName -Path $HVMPath

        Copy-Item -Path "$HVMPath\Sysprep\WIN10SYSPREP.vhdx" -Destination $HVMPath\$VMName\$VMName.vhdx
        New-VM -Name $VMName -MemoryStartupBytes "$($VMRAM)GB" -Path $HVMPath -Generation $VMGen
        Add-VMHardDiskDrive -VMName $VMName -Path $HVMPath\$VMName\$VMName.vhdx
        Set-VM -Name $VMName -ProcessorCount $VMCoreNumber -CheckpointType Disabled
        Remove-VMNetworkAdapter -VMName $VMName
    }
    function Ubuntu {
        $TPM = Test-Path "C:\Program Files\Multipass"
        if ($TPM -eq $false) {
            Write-Error "Multipass n'est pas installé, Uri Multipass-> https://multipass.run/" -ErrorAction Break
        }
        else {
            [String]$VMName = Read-Host "Nom de la VM ?"
            [Int]$VMRAM = Read-Host "Quantité de ram de la VM ?"
            [Int]$VMCoreNumber = Read-Host  "Combien de coeur pour la VM ?"
            [Int]$VMDisk = Read-Host "Combien d'espace pour le disque ?"
            multipass launch --name $VMName --cpus $VMCoreNumber --memory "$($VMRAM)G" --disk "$($VMDisk)G" --cloud-init "D:\Github\Bash\user-data.yaml"
            Set-VM -Name $VMName -CheckpointType Disabled
            Remove-VMSnapshot -VMName $VMName -IncludeAllChildSnapshots:$true
            Remove-VMNetworkAdapter -VMName $VMName
        }
    }

    Get-VM | Select-Object Name,State | Out-Host
    $Title = "Création de VM"
    $Prompt = "Faire choix"
    $WS2022SRV = [System.Management.Automation.Host.ChoiceDescription]::New("Windows Server 2022 &Core","Crée une VM qui contient Windows Server 2022 (Core)")
    $WS2022GUI = [System.Management.Automation.Host.ChoiceDescription]::New("Windows Server 2022 &Graphique","Crée une VM qui contient Windows Server 2022 Experience de Bureau (GUI)")
    $W10RSAT = [System.Management.Automation.Host.ChoiceDescription]::New("Windows 10 &RSAT", "Crée une VM qui contient Windows 10 avec les outils RSAT pour le management de Serveurs")
    $Ubuntu = [System.Management.Automation.Host.ChoiceDescription]::New("&Ubuntu Server", "Crée une VM avec multipass qui Ubuntu Server")
    $Options = [System.Management.Automation.Host.ChoiceDescription[]]($WS2022SRV, $WS2022GUI, $W10RSAT,$Ubuntu)

    $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
    Switch ($Choice) {
        0 {WS22CORE}
        1 {WS22GUI}
        2 {W10RSAT}
        3 {Ubuntu}
    }
}
function DiskMgmt {
    function BLSDisk {
        $HVMPath = (Get-VMHost).VirtualMachinePath
        Get-VM | Select-Object -Property Name | Out-Host
        $VMNameAdd = Read-Host "Choisir la VM pour rajout des disques durs"
        $VMFullPath = "$HVMPath$VMNameAdd"
        $VHDName = @("\bdd.vhdx","\logs.vhdx","\sysvol.vhdx")
        $VHDName | ForEach-Object { New-VHD -Path $VMFullPath$_ -SizeBytes 4196MB }
        $VHDName | Foreach-Object { Add-VMHardDiskDrive -VMName $VMNameAdd -Path $VMFullPath$_ -ControllerType SCSI -ControllerNumber 0 }
    }
    function NewVHD {
        $HVMPath =  (Get-VMHost).VirtualMachinePath
        Get-VM | Select-Object -Property Name | Out-Host
        $VMNameAdd = Read-Host "Choisir la VM pour rajout des disques durs"
        $VHDSize = Read-Host "Veuillez entrer une taille en GB"
        $VHDName = Read-Host "Veuillez nommer votre disque"
        New-VHD -Path "$HVMPath$VMNameAdd\$VHDName.vhdx" -SizeBytes "$($VHDSize)GB"
        Add-VMHardDiskDrive -VMName $VMNameAdd -ControllerType SCSI -ControllerNumber 0 -Path "$HVMPath$VMNameAdd\$VHDName.vhdx"
    }
    $Title = "Démarrer toute les VM ou une seule ?"
        $Prompt = "Faire choix"
        $All = [System.Management.Automation.Host.ChoiceDescription]::New("Nouveau VHD pour Contrôleur de &Domaine","Crée 3 disques de 4Go nommés sysvol logs et bdd et les connectes à la VM souhaitée")
        $Select = [System.Management.Automation.Host.ChoiceDescription]::New("&Nouveau VHD","Crée un nouveau VHD puis le connecte à la VM souhaitée")
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $Select)
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 1)
        Switch ($Choice) {
            0 {BLSDisk}
            1 {NewVHD}
        }

}
function VMStateMgmt {
    function On {
        Get-VM | Select-Object Name,State | Out-Host
        $Title = "Démarrer toutes les VM ou une seule ?"
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
        $Title = "Éteindre toutes les VM ou une seule ?"
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
        $Title = "Supprimer toutes les VM ou une seule ?"
        $Prompt = "Faire choix"
        $All = [System.Management.Automation.Host.ChoiceDescription]::New("&Toutes","Lance la suppression de chaque VM")
        $Select = [System.Management.Automation.Host.ChoiceDescription]::New("&Selection","Sélection de la VM à supprimer")
        $Ubuntu = [System.Management.Automation.Host.ChoiceDescription]::New("&Ubuntu","Sous Menu dédié aux VM Ubuntu")
        $Options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $Select, $Ubuntu)
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 1)
        Switch ($Choice) {
            0 { $HVMPath = ((Get-VMHost).VirtualMachinePath)
                $VMLitteralPath = Get-VM | Select-Object -Property Name
                Stop-VM -VMName * -Force -WarningAction Ignore
                Remove-VM -Name * -Force
                $VMLitteralPath | Foreach-Object { Remove-Item -Path "$HVMPath$($_.Name)" -Recurse -Force }
                Write-Host "Les VM ont toutes étées supprimées"
            }
            1 { $VMName = Get-VM | Select-Object -Property Name,Path | Out-GridView -PassThru
                Stop-VM -Name $VMName.Name -Force -WarningAction Ignore
                Remove-VM -Name $VMName.Name -Force
                Remove-Item -Path $VMName.Path -Recurse -Force
            }
            2{  multipass list | Out-Host
                $Title = "Supprimer toutes les VM ou une seule ?"
                $Prompt = "Faire choix"
                $All = [System.Management.Automation.Host.ChoiceDescription]::New("&Toutes","Lance la suppression de chaque VM Ubuntu")
                $Select = [System.Management.Automation.Host.ChoiceDescription]::New("&Selection","Sélection de la VM Ubuntu à supprimer")
                $Options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $Select)
                $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 1)
                Switch ($Choice) {
                    0 { multipass delete --all
                        multipass purge }
                    1 { $VMName = Read-Host -Prompt "Choisir la VM Ubuntu à supprimer"
                        multipass delete $VMName
                        multipass purge }
                }
            }
        }
    }
    Get-VM | Select-Object VMName | Format-Table
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
function SwitchMgmt {
    function ConnectSwitch {
        $Title = "Connexion unique ou multiple ?"
        $Prompt = "Faire choix"
        $All = [System.Management.Automation.Host.ChoiceDescription]::New("&Toutes","Connecter le Switch sur chaque VM")
        $Select = [System.Management.Automation.Host.ChoiceDescription]::New("&Selection","Sélection de la VM cible")
        $Options = [System.Management.Automation.Host.ChoiceDescription[]]($All, $Select)
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
        Switch ($Choice) {
            0 { Write-Host "Liste des VM existantes et leur Switch déjà connectés" -ForegroundColor Blue
                Get-VM | Select-Object Name, @{Name="SwitchName"; Expression={$_.NetworkAdapters.SwitchName}} | Out-Host
                $VMSwitch = Get-VMSwitch | Out-Gridview -PassThru
                Add-VMNetworkAdapter -Name "Carte Réseau" -SwitchName $VMSwitch.Name -VMName * }
            1 { $VMSelect = Get-VM | Select-Object VMName, @{Name="SwitchName"; Expression={$_.NetworkAdapters.SwitchName}} | Out-GridView -PassThru
                $VMSwitch = Get-VMSwitch | Out-Gridview -PassThru
                Add-VMNetworkAdapter -Name "Carte Réseau" -SwitchName $VMSwitch.Name -VMName $VMSelect.VMName }
            }
        }
    function NewSwitch {
        $Title = "Quel type de Switch créer ?"
        $Prompt = "Faire choix"
        $Internal = [System.Management.Automation.Host.ChoiceDescription]::New("&Interne","Pas d'accès Internet sans Port Forward, permet de communiquer avec l'hôte")
        $Private = [System.Management.Automation.Host.ChoiceDescription]::New("&Privé","Pas d'accès Internet sans Port Forward, Isolation complète")
        $External = [System.Management.Automation.Host.ChoiceDescription]::New("&Externe","Accès Internet, utilise une Carte Réseau de l'hôte")
        $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Internal, $Private, $External)
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
        Switch ($Choice) {
            0 { $SwitchName = Read-Host -Prompt "Nommer le Switch"
                New-VMSwitch -Name $SwitchName -SwitchType Internal }
            1 { $SwitchName = Read-Host -Prompt "Nommer le Switch"
                New-VMSwitch -Name $SwitchName -SwitchType Private }
            2 { Get-VMSwitch | Format-Table
                $SwitchName = Read-Host "Nommer le Switch"
                $NIC = Get-NetAdapter | Select-Object -Property Name,InterfaceDescription,Status | Out-GridView -PassThru
                New-VMSwitch -Name $SwitchName -NetAdapterName $NIC.Name }
            }
        }
        $Title = "Démarrer toute les VM ou une seule ?"
        $Prompt = "Faire choix"
        $Connection = [System.Management.Automation.Host.ChoiceDescription]::New("&Connecter Switch","Connexion d'un Switch à la Carte Réseau d'une ou de toutes les VM")
        $New = [System.Management.Automation.Host.ChoiceDescription]::New("&Nouveau Switch","Création d'un nouveau Switch")
        $Options = [System.Management.Automation.Host.ChoiceDescription[]]($Connection, $New)
        $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Options, 0)
        Switch ($Choice) {
            0 {ConnectSwitch}
            1 {NewSwitch}
        }
}
function EPSIC {
    function Creds {
        Write-Host 'Ne peut être défini qu''une fois, si une erreur a été faite, faire Remove-Variable -Name LLC,LDC' -ForegroundColor Red
            $LabLocalUserTemp = Read-Host "Utilisateur Local"
            $LabDomainUserTemp = Read-Host "Utilisateur du domaine (domaine.x\user or user@domaine.x)"
            $LabPwdSecureTemp = Read-Host -Prompt "Mot de passe utilisateur" -AsSecureString
            $Script:LLC = New-Object System.Management.Automation.PSCredential($LabLocalUserTemp,$LabPwdSecureTemp)
            $Script:LDC = New-Object System.Management.Automation.PSCredential($LabDomainUserTemp,$LabPwdSecureTemp)
            Remove-Variable -Name *Temp*
    }
    function EPS {
        Get-VM | Select-Object Name | Format-Table
        $VM = Get-VM | Select-Object Name | Out-GridView -PassThru
        $LabSession = Read-Host "Ouvrir la session locale ou domaine (L/D) ?"
        if ($LabSession -eq "L" -or $LabSession -eq "Local" -or $LabSession -eq "Locale") {
            Enter-PSSession -VMName $VM.Name -Credential $LLC
        }
        elseif ($LabSession -eq "D" -or $LabSession -eq "Domain" -or $LabSession -eq "Domaine") {
            Enter-PSSession -VMName $VM.Name -Credential $LDC
        }
    }
    function IC {
        $VM = Get-VM | Select-Object Name | Out-ConsoleGridView -OutputMode Single
        $LabSession = Read-Host "Ouvrir la session locale ou domaine (L/D) ?"
        if ($LabSession -eq "L" -or $LabSession -eq "Local" -or $LabSession -eq "Locale") {
            $Location = Read-Host "Ecrire chemin complet des Scripts à executer sur VM (Ex: C:\Script\...)"
            Get-ChildItem -Path $Location | Select-Object -Property Name | Out-Host
            $Script = Read-Host "Choisir le script à éxecuter.."
            Invoke-Command -VMName $VM.Name -FilePath "$Location\$Script" -Credential $LLC
        }
        elseif ($LabSession -eq "D" -or $LabSession -eq "Domain" -or $LabSession -eq "Domaine") {
            $Location = Read-Host "Ecrire chemin complet des Scripts à executer sur VM (Ex: C:\Script\...)"
            Get-ChildItem -Path $Location | Select-Object -Property Name | Out-Host
            $Script = Read-Host "Choisir le script à éxecuter.."
            Invoke-Command -VMName $VM.Name -FilePath "$Location\$Script" -Credential $LDC
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
function pause ($message="Appuyez sur une touche pour continuer...") {
    Write-Host -NoNewLine $message
    $null = $Host.UI.RawUI.ReadKey("noecho,includeKeydown")
    Write-Host ""
}
function console {
    Clear-Host
    Write-Host "######################################################" -ForegroundColor DarkMagenta
    Write-Host "#                                                    #" -ForegroundColor DarkMagenta
    Write-Host "#           ↓ Menu de management Hyper-V ↓           #" -ForegroundColor DarkMagenta
    Write-Host "#                                                    #" -ForegroundColor DarkMagenta
    Write-Host "######################################################" -ForegroundColor DarkMagenta
    Write-Host "1: Menu de création des VM"
    Write-Host "2: Menu de management des Disques Virtuels"
    Write-Host "3: Menu de management de l'état des VM"
    Write-Host "4: Menu de management des Switchs"
    Write-Host "5: EPSIC" -ForegroundColor DarkMagenta
    Write-Host "Q: Quitter le Script"
    $Choice = Read-Host "Faire choix"
    switch ($Choice) {
            1 {VMMgmt;pause;console}
            2 {DiskMgmt;pause;console}
            3 {VMStateMgmt;pause;console}
            4 {SwitchMgmt;pause;console}
            5 {EPSIC;pause;break}
            Q {exit}
            default {console}
        }
}
console