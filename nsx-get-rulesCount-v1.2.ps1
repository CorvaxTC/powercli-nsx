<#

    .SYNOPSIS
        This script uses powercli and posh-shh to retrieve the list of nsx dfw rules applied to vms on esxi hosts and counts the total of rules per host.
        This mainly helps identify any hosts that are reaching the 10 000 dfw rule count.

    .Required Module
        vmware powercli
        Posh-Ssh module. - command to install : Install-Module -Name Posh-SSH 

     .DESCRIPTION
        Connects to a vCenter server, finds the list of hosts.  
        Starts the ssh service and opens a session to the hosts, executes the commands to retrieve the dfw rules and adds them to an array.
        Calculates the sum of the rules per hosts and generates and table per host with total and all vm objects with dfw rules and their count.
    
    .PARAMATERS

        Required : 
            $vcenter = the fqdn of the vCenter Server you want to connect too.

        Optional : 
            $filter = Select between "Cluster" or "Single-Host"
            $filterValue = ** Required if filter has been selected. Contains the name of the resource (Cluster or Host) to search for.
            $logfile = set the path of the log file.  Defaults too current script directory.

    .INPUTS
        Prompts :
           
           $vcenterCreds = The script will prompted for vcenter creds **only if no current connection is opened on the vCenter.
           $esxiCreds = The script will prompted for root creds and assumes that all root credentials are the same.
    .EXAMPLE

        Retrieve that rules count on all the hosts of the vCenter myvcenter.local
        .\nsx-get-rulesCount-v1.1.ps1 -vcenter myvcenter.local

    .EXAMPLE

        Retrieve that rules count on all the hosts of the vCenter myvcenter.local and log to the file 'D:\VMware\testLog.txt'
        .\nsx-get-rulesCount-v1.1.ps1 -vcenter myvcenter.local -logFile D:\VMware\testLog.txt 

    .EXAMPLE

        Retrieve that rules count on all the hosts in the cluster "MyCluster> on the vCenter myvcenter.local    
        .\nsx-get-rulesCount-v1.1.ps1 -vcenter myvcenter.local -filter cluster -filterValue "myclusterName"

    .EXAMPLE

        Retrieve that rules count on the host 'esx01.local' on the vCenter myvcenter.local    
        .\nsx-get-rulesCount-v1.1.ps1 -vcenter myvcenter.local -filter single-host -filterValue "esx01.local"   

    .NOTES
        Created by : Steve Ottavi, Technical Account Manager, VMware

        Disclaimer : This script/function is provided AS IS without warranty of any kind. 
        Author(s) disclaim all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. 
        The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. 
        In no event shall author(s) be held liable for any damages whatsoever (including, without limitation, damages for loss of business profits, 
        business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the script or documentation. 
        Neither this script/function, nor any part of it other than those parts that are explicitly copied from others, 
        may be republished without author(s) express written permission. Author(s) retain the right to alter this disclaimer at any time
        
        Version 1.2    

#>

[CmdletBinding(DefaultParameterSetName='DefaultConfiguration')]

Param(
      [Parameter(Mandatory=$true)][String]$vcenter,
      [Parameter(Mandatory=$false)][String]$logFile="",
      [Parameter(Mandatory=$false)][ValidateSet("Cluster","Single-Host")][string]$filter
)

DynamicParam
{
    $paramDictionary = New-Object -Type System.Management.Automation.RuntimeDefinedParameterDictionary
    $attributes = New-Object System.Management.Automation.ParameterAttribute
    $attributes.ParameterSetName = "__AllParameterSets"
    $attributes.Mandatory = $true
    $attributeCollection = New-Object -Type System.Collections.ObjectModel.Collection[System.Attribute]
    $attributeCollection.Add($attributes)
    if($filter)
    {
        # Create a mandatory string parameter called "filterValue"
        $filterValue = New-Object -Type System.Management.Automation.RuntimeDefinedParameter("filterValue", [String], $attributeCollection)   
        # Add the new parameter to the dictionary
        $paramDictionary.Add("filterValue", $filterValue)
    }
    return $paramDictionary
}


Process{                
    
    function Get-TimeStamp {
    
        return "[{0:MM/dd/yy} {0:HH:mm:ss}]" -f (Get-Date)
    
    }

    function write-ToLog{
        Param(
            [Parameter(Mandatory)][string]$logText,
            [boolean]$append = $true,
            [ValidateSet("INFO","WARNING","ERROR","SUCCESS")][string]$entryType="INFO"
        )

        $log = "$(Get-TimeStamp): $($entryType) $($logText)"

        Switch($entryType){
            "WARNING"{Write-Host $log -ForegroundColor Yellow}
            "ERROR" {Write-Host $log -ForegroundColor Red}
            "SUCCESS" {Write-Host $log -ForegroundColor Green}

            Default{
                Write-Host $log
            }

        } 
    
        if($append -eq $false){
            Write-Output $log |Out-File -FilePath $logfile
        }else{
            Write-Output $log |Out-File -FilePath $logfile -Append
        }
    }

    function Get-ScriptDirectory{
        $Invocation = (Get-Variable MyInvocation -Scope 1).Value
        Split-Path $Invocation.MyCommand.Path
    }


    #Test and set the logfile location.
    If([string]::IsNullOrEmpty($logFile)){    
        write-host "No Logfile path specified. Reverting to current directory."
        $logfile = "$(get-ScriptDirectory)\nsxGetDfWRulesCount.txt"
        
    }   
    
    Write-Host "The logfile has been set to '$($logfile)'" -ForegroundColor Green

    write-ToLog "***********************************************" -append $false
    write-ToLog "Started processing script"
    write-ToLog "vCenter fqdn: $($vcenter)"
    write-ToLog "***********************************************"

    if(($($global:DefaultVIServer).IsConnected -eq $true -and $($global:DefaultVIServer).Name -eq $vcenter)  -or ($($global:DefaultVIServers).IsConnected -eq $true -and $($global:DefaultVIServers).Name -eq $vcenter)){
    
      #Disable the disconnection to vCenter
      $disableDisconnect = $true
    
      if($global:DefaultVIServers.Count -gt 1){
    
        write-ToLog "Found Existing connection to multiple vCenters."  

        $global:DefaultVIServers |foreach{write-ToLog "Found Existing connection open on vCenter '$($_.Name)'"}
         
      }else{
        write-ToLog "Found Existing connection open on vCenter '$($global:DefaultVIServer.Name)'"
      }

  
    }else{

        #vcenter information required. 
        #$vcenter = "vcs01.foggynorth.local"  - Included in Parameters in v1.1

        #prompted for vc credentials
        $vcenterCreds = Get-Credential -Message "Provide vCenter Credentials for $vcenter"

        #open a connection on the vcenter server
        $vc = Connect-VIServer $vcenter -Credential $vcenterCreds

    
        #Validate we have a connection. if failed, exit script.
        if($vc -eq $null){
            write-ToLog "Unable to connect to vCenter '$($vc)'.  The script will now quit." -entryType ERROR
            Exit
        }else{
            write-ToLog "Successfully opened a connection on vCenter '$($vc)'"
        }

    }



    #Prompted for the esxi root password.  Not that this assumes that all root passwords are the same....
    $esxiCreds = Get-Credential -Message "Provide ESXi root Password" -UserName root

    #List the hosts on the vCenter. You can limit to clusters or hosts here, if needed...
    if(!([string]::IsNullOrEmpty($filter) -and [string]::IsNullOrEmpty($filterValue))){
        
        #write-ToLog "Filter = $filter, filterValue = $($PSBoundParameters.filterValue)" #For debug

        $filterValue = $($PSBoundParameters.filterValue) #Retrieve the Dynamique Parameter.

        switch($filter.ToLower()){
            {$_ -eq "cluster"}{
                write-ToLog "Filter applied to retrieve hosts from cluster '$($filterValue)'" -entryType INFO
                $vmHosts = Get-Cluster -Name $filterValue |Get-VMHost
                }
            {$_ -eq "single-host"}{
                write-ToLog "filter applied to retrieve a single host '$($filterValue)'" -entryType SUCCESS
                $vmHosts = Get-VMHost -Name $filterValue
            }
        }

    }else{
        write-ToLog "No Filter on Host or Cluster requested.  Falling back to default and retrieving all hosts." -entryType INFO
        $vmHosts = Get-VMHost
    }


    if($vmHosts.Count -le 0){
        write-ToLog "No hosts located with current filter. The script will now quit." -entryType ERROR
        Exit
    }else{
        write-ToLog "Located '$($vmHosts.Count)' hosts that match the filter requested." -entryType SUCCESS
    }

    #array with all the dfw rules defined...
    $dfwRulesPerVM= @()

    #loop through the hosts
    foreach($vmHost in $vmHosts){
    
        write-ToLog "`r`n-----------------------------------------------------------"

        write-ToLog "Starting processing for Host '$($vmHost)'"

        $sshServiceOriginalState = $($vmHost | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"})

        if($sshServiceOriginalState.Running -eq $false){
              #enable ssh on the host
            write-ToLog "SSH Service is currently stopped and will be started." -entryType WARNING
            $startSSH = Start-VMHostService -HostService ($vmHost | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"} )
        }else{
            write-ToLog "SSH Service is already running.  No need to start the service."
        }
    
        #Validate the ssh service is started. Otherwise skip the session and log
        if($sshServiceOriginalState.Running -eq $true -or $startSSH.Running -eq $true){     
        
            write-ToLog "Successfully started SSH or service already available on host" -entryType SUCCESS
        
            try{
                #start a new ssh session with the provided creds
               $ssh = New-SSHSession -ComputerName $vmHost.Name -Credential $esxiCreds -Port 22 -AcceptKey:$true -ErrorAction Stop

               #write a quick output to indicate that the session is open...
               $return = Invoke-SSHCommand -SSHSession $ssh -Command "uname -a"
               write-ToLog "$($return.Output)" -entryType SUCCESS

               # Retrieve summarize-dvfilter
               write-ToLog "Retrieving host dvfilters and processing the information..."
               $dvflist = Invoke-SSHCommand -SSHSession $ssh -Command "summarize-dvfilter"
    
               if($dvflist.Output.Count -ge 1){
              
                   write-ToLog "Found '$($dvflist.Output.Count)' dvfilters on host '$($vmHost.Name)' that need to be processed."

                   # Parse each line in the summarize-dvfilter output
                   ForEach ($item in $dvflist.Output) {
                
              

                        # If we see a new VM identifier, update our current VMName setting:
                        if ($item -match '(?<=vmm0:)(.*)(?= vcUuid:)') {
                            $vmName = $matches[0]
                        }

                        # If we see a line that looks like a fw export, grab that and run vsipioctl on it:
                        if ($item -match '(?<=name:\s+)(.*\.([2,4-9]|1[0-5]))$') {

                            $vmNic = $matches[0]
                            write-ToLog "Found dfw ruleset on VM $vmName via vnic '$($vmNic)'" -entryType SUCCESS
                    
                            #run the command to retrieve the number of rules applied to the vmnic
                            $getRules = Invoke-SSHCommand -SSHSession $ssh -Command "vsipioctl getrules -f $($vmNic) | grep -i '\sat\s' | wc -l"
            
                            #convert to integer
                            $rulesCount = [int32]$($getRules.Output)
            
                            write-ToLog "Rule count on VM '$($vmName)' = '$($rulesCount)'" -entryType SUCCESS

                            #validate the rulecount is greater then 0
                            if($rulesCount -gt 0){
                                #Create a new row with the required information
                                $row =  New-Object PSObject -Property @{
                                    vmname = $vmName
                                    vnic = $vmNic
                                    rulesCount = $rulesCount
                                    vmHost = $($vmHost.Name)
                                }

                                #add the row to the array.
                                $dfwRulesPerVM+= $row
                            }  
                    } 
                }#End for
            }else{
                write-ToLog "Found no dvfilters on host '$($vmHost.Name)', the host will be skipped."
            }

               #Test to see if ssh service was currently running.  if not, stop the service.
               if($sshServiceOriginalState.Running -eq $false){
                    #Stoping  ssh on the host
                   write-ToLog "Stoping SSH on Host" -entryType WARNING
                   $stop = Stop-VMHostService -HostService ($vmHost | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"} ) -Confirm:$false
               }else{
                   write-ToLog "Leaving SSH service in its started state, since it was already started on the host." -entryType WARNING
            
               }

           }catch{ 

                write-ToLog "Unable to establish an ssh session on host '$($vmHost)'" -entryType ERROR
                write-ToLog $_.ScriptStackTrace -entryType ERROR
                write-ToLog $_.Exception -entryType ERROR

           }
        }

    }#end for each host


    write-ToLog "-----------------------------------------------------------"

    if($disableDisconnect -ne $true){
        #Disconnect from vCenter
        write-ToLog "Closing connection on vCenter '$($vc)'" -entryType WARNING
        Disconnect-VIServer -Server $vcenter -Force -Confirm:$false
    
    }else{
        write-ToLog "Connection on vCenter '$($vc)' will be left open."
    }

    #Retrieve the list of unique host entries
    $hostsWithRules =  $dfwRulesPerVM|Select-Object -Property  vmhost -Unique |Select -ExpandProperty vmhost

    #Array to sum everything up.
    $dfwRulesPerHost = @()

    write-ToLog "-----------------------------------------------------------"
    write-ToLog "--          Calculating rules for hosts                  --"
    write-ToLog "-----------------------------------------------------------`r`n"


    #Loop through the hosts with rules and count the number of rules.
    foreach($esxHost in $hostsWithRules){

       #Count the rules based off unique server name
       $rulesCount = $($dfwRulesPerVM|Where{$_.vmhost -eq $esxHost}|Measure-Object -Sum -Property rulesCount).Sum
   
       #Create a Row to add to the array
       $row = New-Object PSObject -Property @{
            host = $esxHost
            totalRules = $rulesCount
            dfwRuleSet = $($dfwRulesPerVM|Where{$_.vmhost -eq $esxHost}) #add the vm entries that are related to the host
       }

       #add the row to the array
       $dfwRulesPerHost += $row
   
    #Display a message based on the total rules count of the host.
      Switch($rulesCount){
           {$_ -le 9000} {write-ToLog "Found '$($rulesCount)' dfw rules on host '$($esxHost)'" -entryType SUCCESS }
           {$_ -gt 9000 -and $_ -lt 10000} {write-ToLog "Found '$($rulesCount)' dfw rules on host '$($esxHost)'. This is closed to the cap of '10 000'" -entryType WARNING}
           {$_ -ge 10000} {write-ToLog "WARNING : Found $($rulesCount) dfw rules on host '$($esxHost)'. This over the cap of '10 000'. Please adjust." -entryType ERROR}
      }

   
    }

    write-ToLog "-----------------------------------------------------------`r`n"

    # write-host "$($dfwRulesPerHost |Format-Table -Property host,totalRules,dfwRuleSet)" # for debug or use if you want to break it down.

}#End process
