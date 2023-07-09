$Global:NetIP = Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4Address | Format-Table
function GetIP
{
    $NetIP
}

function SetIP
{
    Write-Host "Souhaitez-vous..."
    Write-Host "1: Activer le DCHP"
    Write-Host "2: Définir une IP Statique"
    $choix = Read-Host "Veuillez choisir"
    switch ($choix)
    {
        1
        {
            $NetIP
            [int32]$SelectNIC = Read-Host "Choisir le numero NIC souhaitee"
            Remove-NetRoute -InterfaceIndex $SelectNIC -Confirm:$false; Remove-NetIPAddress -InterfaceIndex $SelectNIC -Confirm:$false
            Set-NetIPInterface -InterfaceIndex $SelectNIC -DHCP Enabled
        }
        2
        {
            $NetIP
            [int32]$SelectNIC = Read-Host "Choisir le numero NIC souhaitee"
            $IPAdress = Read-Host "Veuillez entrer l'IP souhaitee"
            Remove-NetRoute -InterfaceIndex $SelectNIC -Confirm:$false; Remove-NetIPAddress -InterfaceIndex $SelectNIC -Confirm:$false
            #$Mask = Read-Host "Choisir le masque sous-reseau"
            $CIDR = Read-Host "Choisir le CIDR"
            New-NetIPAddress -InterfaceIndex $SelectNIC -IPAddress $IPAdress -AddressFamily IPv4 -PrefixLength $CIDR
        }
        default {console}

    }
}
function DNS
{
    $NetIP
    [int32]$SelectNIC = Read-Host "Choisir le numero NIC souhaitee"
    $DNSIP = Read-Host "Choisir les IP souhaitees"
    Set-DnsClientServerAddress -InterfaceIndex $SelectNIC -Addresses $DNSIP
}
function RemoveIP
{
    $NetIP
    [int32]$SelectNIC = Read-Host "Choisir le numero NIC souhaitee"
    Remove-NetRoute -InterfaceIndex $SelectNIC -Confirm:$false
    Remove-NetIPAddress -InterfaceIndex $SelectNIC -Confirm:$false
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
    Write-Host "Menu Script"

    Write-Host "1: Voir les NIC"
    Write-Host "2: Modifier l'IPv4"
    Write-Host "3: Modifier le DNS"
    Write-Host "4: Retirer les IP et routes"
    Write-Host "Q: Quitter le Script"
    $choix = Read-Host "Choisissez votre destin"
    switch ($choix)
        {
            1 {GetIP;Pause;console}
            2 {SetIP;pause;console}
            3 {DNS;pause;console}
            4 {RemoveIP;pause;console}
            Q {exit}
            default {console}
        }
}
console


