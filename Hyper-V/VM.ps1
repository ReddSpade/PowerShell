#!TODO Ajouter la création des groupes, attribution des utilisateurs aux groupes, les droits des groupes sur les partagesSYSPREP Machine RSAT
Import-Module Hyper-V
$global:VMPath = (Get-VMHost).VirtualMachinePath
{
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

function WS22ORE{
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

Copy-Item -Path "C:\Users\Administrateur\Desktop\WIN22CORESYSPREP.vhdx" -Destination $VMPath\$VMName\$vmname.vhdx
New-VM -Name $VMName -MemoryStartupBytes "$($GB)GB" -Path $VMPath -Generation $Gen
Add-VMHardDiskDrive -VMName $VMName -path $VMPath\$VMName\$VMName.vhdx
Set-VM -name $VMName -ProcessorCount $CoreNumber -CheckpointType Disabled
}

function WS22GUI{
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

Copy-Item -Path "C:\Users\Administrateur\Desktop\WIN22GUISYSPREP.vhdx" -Destination $VMPath\$VMName\$vmname.vhdx
New-VM -Name $VMName -MemoryStartupBytes "$($GB)GB" -Path $VMPath -Generation $Gen
Add-VMHardDiskDrive -VMName $VMName -path $VMPath\$VMName\$VMName.vhdx
Set-VM -name $VMName -ProcessorCount $CoreNumber -CheckpointType Disabled
}

function W10RSAT{
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

Copy-Item -Path "E:\VM_Hyper-V\Sysprep\WIN10SYSPREP.vhdx" -Destination $VMPath\$VMName\$vmname.vhdx
New-VM -Name $VMName -MemoryStartupBytes "$($GB)GB" -Path $VMPath -Generation $Gen
Add-VMHardDiskDrive -VMName $VMName -path $VMPath\$VMName\$VMName.vhdx
Set-VM -name $VMName -ProcessorCount $CoreNumber -CheckpointType Disabled
}

function shutdown ()
{
    Get-VM | Select-Object Name,State | Format-Table
    $VMSelect = Read-Host "Choisir la VM a eteindre"
    Stop-VM -name $VMSelect -Force
}

function startup ()
{
    Get-VM | Select-Object Name,State | Format-Table
    $VMSelect = Read-Host "Choisir la VM a demarrer"
    Start-VM -name $VMSelect
}

function delete ()
{
    Get-VM | Select-Object Name | Format-Table
    $VMSelect = Read-Host "Choisir la VM a supprimer"
    $VMLitteralPath = Get-VM | Where-Object -Property name -eq $VMSelect | Select-Object -Property Path
    Stop-VM -name $VMSelect -Force -WarningAction Ignore
    Remove-VM -name $VMSelect -Force
    Remove-Item -path ($VMLitteralPath).Path -Recurse -Force
}

function DiskAD ()
{
    Get-VM | Select-Object Name |Format-Table
    Pause
    $VMNameAdd = Read-Host "Choisir la VM pour rajout des disques durs"
    $VHDSize = Read-Host "Veuillez entrer une taille en GB"
    $VHDName = Read-Host "Veuillez nommer votre disque"
    $GB = Invoke-Expression $VHDSize
    New-VHD -Path $VMPath"\$VHDName" -SizeBytes "$($GB)GB"
    Add-VMHardDiskDrive -VMName $VMNameAdd -ControllerType SCSI -ControllerNumber 0 -Path $VMPath\$VHDSize
}

function RAID ()
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
}

function pause($message="Appuyez sur une touche pour continuer...")
{
    Write-Host -NoNewLine $message
    $null = $Host.UI.RawUI.ReadKey("noecho,includeKeydown")
    Write-Host ""
}

function console ()
{
    Clear-Host
    Write-Host "#####################################################" -ForegroundColor Blue
    Write-Host "#                                                   #" -ForegroundColor Blue
    Write-Host "#          ↓ Menu de management VM Hyper-V ↓        #" -ForegroundColor Blue
    Write-Host "#                                                   #" -ForegroundColor Blue
    Write-Host "#####################################################" -ForegroundColor Blue


    Write-Host "1: Création VM Windows Server Core 2022"
    Write-Host "2: Création VM Windows Server Graphique 2022"
    Write-Host "3: Création VM Windows 10 avec rôles RSAT"
    Write-Host "4: Créer et connecter un disque"
    Write-Host "5: Ajouter BDD/LOGS/SYSVOL"
    Write-Host "6: Eteindre VM"
    Write-Host "7: Demarrer une VM"
    Write-Host "8: Supprimer une VM"
    Write-Host "Q: Quitter le Script"
    $choix = Read-Host "Choisissez votre destin"
    switch ($choix)
        {
            1 {WS22ORE;pause;console}
            2 {WS22GUI;pause;console}
            3 {W10RSAT;pause;console}
            4 {DiskAD;pause;console}
            5 {DCDisk;pause;console}
            6 {shutdown;pause;console}
            7 {startup;pause;console}
            8 {delete;pause;console}
            Q {exit}
            default {console}
        }
}
console