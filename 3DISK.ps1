function 3disksup
{
    Get-VM | Select-Object Name | Format-Table
    Pause
    $VMNameAdd = Read-Host "Choisir la VM pour rajout des disques durs"
    $VMPath = "C:\VM\$VMNameAdd"

    New-VHD -Path $VMPath"\bdd.vhdx" -SizeBytes 4196MB
    New-VHD -Path $VMPath"\logs.vhdx" -SizeBytes 4196MB
    New-VHD -Path $VMPath"\sysvol.vhdx" -SizeBytes 4196MB

    Add-VMHardDiskDrive -VMName $VMNameAdd -ControllerType SCSI -ControllerNumber 0 -Path $VMPath"\bdd.vhdx"
    Add-VMHardDiskDrive -VMName $VMNameAdd -ControllerType SCSI -ControllerNumber 0 -Path $VMPath"\logs.vhdx"
    Add-VMHardDiskDrive -VMName $VMNameAdd -ControllerType SCSI -ControllerNumber 0 -Path $VMPath"\sysvol.vhdx"
}

#Sl "C:\Windows\System32\Sysprep"
#.\sysprep.exe /oobe /generalize /shutdown
#   -NewVHDPath "C:\VM\VM-TEST\VM-TEST-C.vhdx" -NewVHDSizeBytes 30GB -Generation 2 -Switch "LAB_RDR" -BootDevice NetworkAdapter

function WS22ORE{
    #Variables d'information
$VMName = Read-Host "Quel sera le nom de la VM ?"
$VMRAM = Read-Host "Quel sera la quantité de RAM de la VM ?"
$GB = Invoke-Expression $VMRAM 
$VMPlace = "C:\VM"
#$VMVHD = Read-Host "Où sera localisé le disque dur VHD ?"
#$VMVHDSPACE = Read-Host "De combien de GB sera le disque dur ?"
#$GB2 = Invoke-Expression  $VMVHDSPACE
[int32]$Gen = Read-Host "Génération 1 ou 2 ?"
[int32]$CoreNumber = Read-Host  "Combien de coeur pour la VM ?"

New-Item -ItemType Directory -Name $VMName -Path $VMPlace

Copy-Item -Path "C:\Users\Administrateur\Desktop\WIN22CORESYSPREP.vhdx" -Destination $VMPlace\$VMName\$vmname.vhdx
New-VM -Name $VMName -MemoryStartupBytes $GB -Path $VMPlace -Generation $Gen
Add-VMHardDiskDrive -VMName $VMName -path $VMPlace\$VMName\$VMName.vhdx
Set-VM -name $VMName -ProcessorCount $CoreNumber -CheckpointType Disabled
}

function WS22GUI{
    #Variables d'information
$VMName = Read-Host "Quel sera le nom de la VM ?"
$VMRAM = Read-Host "Quel sera la quantité de RAM de la VM ?"
$GB = Invoke-Expression $VMRAM 
$VMPlace = "C:\VM"
#$VMVHD = Read-Host "Où sera localisé le disque dur VHD ?"
#$VMVHDSPACE = Read-Host "De combien de GB sera le disque dur ?"
#$GB2 = Invoke-Expression  $VMVHDSPACE
[int32]$Gen = Read-Host "Génération 1 ou 2 ?"
[int32]$CoreNumber = Read-Host  "Combien de coeur pour la VM ?"

New-Item -ItemType Directory -Name $VMName -Path $VMPlace

Copy-Item -Path "C:\Users\Administrateur\Desktop\WIN22GUISYSPREP.vhdx" -Destination $VMPlace\$VMName\$vmname.vhdx
New-VM -Name $VMName -MemoryStartupBytes $GB -Path $VMPlace -Generation $Gen
Add-VMHardDiskDrive -VMName $VMName -path $VMPlace\$VMName\$VMName.vhdx
Set-VM -name $VMName -ProcessorCount $CoreNumber -CheckpointType Disabled
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
    Write-Host "Menu Script"

    Write-Host "1: Création VM Windows Server Core 2022"
    Write-Host "2: Création VM Windows Server Graphique 2022"
    Write-Host "3: Ajouter BDD/LOGS/SYSVOL"
    Write-Host "Q: Quitter le Script"
    $choix = Read-Host "Choisissez votre destin"
    switch ($choix)
        {
            1 {WS22CORE;pause;console}
            2 {WS22GUI;pause;console}
            3 {3disksup;pause;console}
            Q {exit}
            default {console}
        } 
}
console