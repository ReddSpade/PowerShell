function 3DISK ()
{
    Clear-Host
    Write-Host "Menu Script"

    Write-Host "1: Liste des VM"
    Write-Host "Q: Quitter le Script"
    $choix = Read-Hefefost "Choisissez votre destin"
    switch ($choix)
        {
            1 {Get-VM | select-object name,state |fl }
            2 {$Title = "Choissisez votre VM"
            $Prompt = ":"
            $Choices = [System.Management.Automation.Host.ChoiceDescription[]] @("&TEST2", "&test3", "&test4")
            $Default = 1
            
            # Prompt for the choice
            $Choice = $host.UI.PromptForChoice($Title, $Prompt, $Choices, $Default)
            
            # Action based on the choice
            switch($Choice)
            {
                0 { Write-Host "Yes - Write your code"}
                1 { Write-Host "No - Write your code"}
                2 { Write-Host "Cancel - Write your code"}
            }}
            default {menu}
        } 
}
console