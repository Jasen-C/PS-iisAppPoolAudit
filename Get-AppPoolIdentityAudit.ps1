###
# Author Jasen C
# Date 2/20/2022
# Description: Find all IIS AppPools running as a service account for audit purposes
#
# Warning The following code block might trigger alerts in EDR/AV/SIEM software for potential credential theft.
#   AppPool service account passwords are stored in plain text on the system and quering the AppPool info
#   may trigger alerts. The code below does not access or report the passwords for the accounts
#   If possible any standard service accounts in this report should be migrated to Managed service accounts if possible
###

# Promt for admin credentials to use in the remote connections
$Cred = $host.ui.PromptForCredential("Need Admin credentials.", "Please enter your user name and password.", "", "NetBiosUserName")

# Codeblock run remotely to query AppPool config and return the server name, AppPool name, and configured username 
$CODE = {
    $AppPools = Get-WebConfiguration -Filter '/system.applicationHost/applicationPools/add'
    
    foreach($AppPool in $AppPools){
        if($AppPool.ProcessModel.identityType -eq "SpecificUser"){
            $object = new-object psobject -Property @{
                Servername = $env:computername
                AppPool = $AppPool.name
                UserAccount = $AppPool.ProcessModel.UserName
                }
                write-output $object  
        }
    }
}

# Get all servers from AD filter to only enabled objects
$Servers = Get-ADComputer -Filter {(OperatingSystem -Like '*Windows Server*') -and (Enabled -eq $true)} | Select-Object dnshostname | Sort-Object dnshostname

# Connects to each server and returns the hostname of the server, I find this fist initial connection reduces errors running the actual audit codeblock
Invoke-Command -Credential $Cred -ComputerName $Servers.dnshostname -ScriptBlock {$env:COMPUTERNAME} -erroraction SilentlyContinue

# Run our codeblock specified at the top, throttle to 20 servers at a time
$AppPoolAudit = Invoke-Command -Credential $Cred -ComputerName $Servers.dnshostname -ThrottleLimit 20 -ScriptBlock $CODE -erroraction SilentlyContinue

# Output audit details to the console
$AppPoolAudit | Format-Table

# Output audit details to a csv file
$AppPoolAudit | Export-Csv "C:\temp\ServerAppPoolAudit.csv" -NoTypeInformation

# Clear our credentials
$Cred = ""