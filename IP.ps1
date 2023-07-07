function GetIP ()
{
    Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4Address | Format-Table
}

function SetIP ()
{
    Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4Address | Format-Table
    Write-Host "Souhaitez-vous.."
    Write-Host "1: Ajouter une nouvelle IP"
    Write-Host "2: Modifier l'IP existante"
    $choix = Read-Host "Choisissez votre destin..."
    switch($choix)
        {
            1{
                [int32]$SelectNIC = Read-Host "Choisir le numero NIC souhaitee"
                $IPAdress = Read-Host "Veuillez entrer l'IP souhaitee"
                #$Mask = Read-Host "Choisir le masque sous-reseau"
                $CIDR = Read-Host "Choisir le CIDR"
                New-NetIPAddress -InterfaceIndex $SelectNIC -IPAddress $IPAdress -AddressFamily IPv4 -PrefixLength $CIDR 
            }
            
            2{
                [int32]$SelectNIC = Read-Host "Choisir le numero NIC souhaitee"
                $IPAdress = Read-Host "Veuillez entrer l'IP souhaitee"
                [int32]$CIDR = Read-Host "Choisir le CIDR"
                Set-NetIPAddress -InterfaceIndex $SelectNIC -IPAddress $IPAdress -AddressFamily IPv4 -PrefixLength $CIDR
            }
            Q {default}
        }
}
function DNS ()
{
    [int32]$SelectNIC = Read-Host "Choisir le numero NIC souhaitee"
    $DNSIP = Read-Host "Choisir les IP souhaitees"
    Set-DnsClientServerAddress -InterfaceIndex $SelectNIC -Addresses $DNSIP
}

function ReverseZone ()
{
    Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4Address | Format-Table
    $DNSInterface = Read-Host "Choisir le numero d'interface"
    $DNSIP = (Get-NetIPAddress -InterfaceIndex $DNSInterface -AddressFamily IPv4).IPAddress
    Get-DNSClientServerAddress -InterfaceIndex $DNSInterface -AddressFamily IPv6 | Set-DnsClientserveraddress -ResetServerAddresses
    Set-DnsClientServerAddress -InterfaceIndex $DNSInterface -ServerAddresses $DNSIP
    $NetworkIP = Read-Host "Saisissez l'adresse du reseau au format IP/CIDR"

    Add-DNSServerPrimaryZone -NetworkId $NetworkIP -ReplicationScope Domain -DynamicUpdate Secure
    ipconfig /registerdns
}
function RemoveIP ()
{
    Get-NetIPConfiguration | Select-Object -Property InterfaceDescription,InterfaceIndex,IPv4Address | Format-Table
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
function console ()
{
    Clear-Host
    Write-Host "Menu Script"

    Write-Host "1: Voir les NIC"
    Write-Host "2: Modifier l'IPv4"
    Write-Host "3: Modifier le DNS"
    Write-Host "4: Zone DNS inversee"
    Write-Host "5: Retirer les IP et routes"
    Write-Host "Q: Quitter le Script"
    $choix = Read-Host "Choisissez votre destin"
    switch ($choix)
        {
            1 {GetIP;Pause;console}
            2 {SetIP;pause;console}
            3 {DNS;pause;console}
            4 {DNSIPv4;pause;console}
            5 {RemoveIP;pause;console}
            Q {exit}
            default {console}
        } 
}
console


