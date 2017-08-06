#############################################################################################
#
#   Script: AWS-SSO-KeyHelper.ps1
#
#   Author: Martin Sustaric
#
#     Date: 19/10/2016
#
#    About: This script is used to request temporary access keys using SAML intergration.
#
#
#    Usage: The script requires SAML pre configured and the user executing script has been added to the nessary 
#           AD security groups. This will then allow federated API access in Windows PowerShell for use with
#           the AWS Tools for Windows PowerShell and AWS CLI for Windows.
#
# Requirements: PowerShell V3.0 and or AWS PowerShell Module Version 3.1.31.0 or later or AWS CLI
#
#
# Versions:
# 19/10/2016 - 1.0 - Initial release creation by Martin Sustaric
# 18/11/2016 - 1.1 - Modified to support non-MFA auth, and externalised account config
# 03/08/2017 - 1.2 - Added support for custom realm but removed MFA, Clear-AWSCredentials command updated
#					 to Remove-AWSCredentialProfile, realm in config file added.
#
#
#############################################################################################


<#
.SYNOPSIS
    This script was creatd by Martin Sustaric.


.DESCRIPTION
    The script requires SAML pre configured and the user executing script has been added to the nessary 
    AD security groups. This will then allow federated API access.



.NOTES
    Author: Martin Sustaric
    Date:   19/10/2016
    Version: 1.0 - Initial release
#>

#Requires -Version 3


Param(
    [Parameter(Mandatory=$true,HelpMessage="Enter in User Name ")][string]$username,
    [Parameter(Mandatory=$true,HelpMessage="Enter in password ")][string]$password,
    [Parameter(Mandatory=$false,HelpMessage="Enter in default region (default=ap-southeast-2)")][string]$region = "ap-southeast-2",
    [Parameter(Mandatory=$false,HelpMessage="Enter in MFA code ")][string]$mfacode,
    [Parameter(Mandatory=$false,HelpMessage="Enter in Session type 'CLI' or 'PS' Powershell (default=CLI)")][string]$type = 'CLI',
    [Parameter(Mandatory=$true,HelpMessage="Enter in ADFS Server")][string]$ADFSServer
    )


#AWS Account ID mappings Variables - Add any mapping here otherwise the account ID will be displayed.  (File format:  each line contains account number and name: "12345678912=Account Name")
$accountMappingFilename = "awsAccounts-$ADFSServer.txt"
if (! (Test-Path $accountMappingFilename) ) {
    write-host "Error - Account mapping file '$accountMappingFilename' could not be found" -ForegroundColor Red -BackgroundColor Black
    break
}
$accountmap = {}
$accountmap = Get-Content -raw $accountMappingFilename | ConvertFrom-StringData
$realmsupplied = $null

#Check for a realm paramiter and extract it
if ($accountmap['realm']) {
    $realm = $accountmap['realm']
    $accountmap.Remove('realm')
    $realmsupplied = $true
} else {
     $realm = $ADFSServer
     $realmsupplied = $false
}

#build urls
$url = "https://$ADFSServer/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices&RedirectToIdentityProvider=http%3a%2f%2f$realm%2fadfs%2fservices%2ftrust"
$url3 = "https://$ADFSServer/adfs/ls/"


#Load AWS PowerShell module if not CLI creds needed
$type = $type.ToLower()
if($type -ne 'cli'){
    #Import AWS PS Module
    try {
        #Import-Module "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.dll" 
        Import-Module AWSPowerShell
    }
    catch {
        $ErrorMessage = $_.Exception.Message
        write-host "Error - There was an error: $ErrorMessage" -ForegroundColor Red -BackgroundColor Black
        break
    }
}

# 1.  Obtain inital cookies

Add-Type -AssemblyName System.Web

#Create Inital Cookie container
$CookieContainerInital = New-Object System.Net.CookieContainer

#GET inital request to obtain cookies
$reqinital = [System.Net.WebRequest]::Create($url)
$reqinital.method = "GET"
$reqinital.AllowAutoRedirect = $true
$reqinital.CookieContainer = $CookieContainerInital
[net.httpWebResponse] $reqinital = $reqinital.getResponse()
$resstinital = $reqinital.getResponseStream()
$srinital = new-object IO.StreamReader($resstinital)
$resultinital = $srinital.ReadToEnd()
$reqinital.close()

#obtain redirect url
#$urlredirect = $reqinital.Headers.Get("Location")
$urlredirect = $reqinital.ResponseUri

#Remove-Variable reqinital
#Remove-Variable CookieContainerInital


# 2.  Submit username/password

#Create Cookie container
$CookieContainer = New-Object System.Net.CookieContainer
#Create post data
$postData = "UserName=$username&Password=$password&AuthMethod=FormsAuthentication"
#encode post data
$buffer = [text.encoding]::ascii.getbytes($postData)
#generate inital post request to inpot the user name and password
$req = [System.Net.WebRequest]::Create($urlredirect)
$req.method = "POST"
$req.AllowAutoRedirect = $false
$req.ContentType = "application/x-www-form-urlencoded"
$req.ContentLength = $buffer.length
$req.CookieContainer = $CookieContainer
try {
    $reqst = $req.getRequestStream()
} catch {
    $ErrorMessage = $_.Exception.Message
    write-host "Error - Unable to connect to ADFS: $ErrorMessage" -ForegroundColor Red -BackgroundColor Black
    break
}
$reqst.write($buffer, 0, $buffer.length)
$reqst.flush()
$reqst.close()
[net.httpWebResponse] $res = $req.getResponse()
$resst = $res.getResponseStream()
$sr = new-object IO.StreamReader($resst)
$result = $sr.ReadToEnd()
$res.close()


# 3.  Submit MFA tokin

#If MFA specified submit tokin
if ($mfacode) {

    # 3.1  If doing MFA, perform a GET to capture the context to be able to do a post to page with MFA

    $req2 = [System.Net.WebRequest]::Create($url)
    $req2.method = "GET"
    $req2.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    $req2.AllowAutoRedirect = $false
    $req2.CookieContainer = $CookieContainer
    [net.httpWebResponse] $res2 = $req2.getResponse()
    $resst2 = $res2.getResponseStream()
    $sr2 = new-object IO.StreamReader($resst2)
    $result2 = $sr2.ReadToEnd()
    $res2.close()

    #Scrape the response for the context
    $Context = (($result2 -split '<input id="context" type="hidden" name="Context" value="')[1] -split '" />')[0]
    #Html decode the string and then urlencode it
    $Context = [System.Web.HttpUtility]::HtmlDecode($Context)
    $Context = [System.Web.HttpUtility]::UrlEncode($Context)

    #Create post data containing mfacode and Context
    $postData = "username=&password=&security_code=$mfacode&AuthMethod=VIPAuthenticationProviderWindowsAccountName&Continue=Continue&Context=$Context"


    # 3.2  If doing MFA, perform a POST to enter in the mfa code

    $buffer = [text.encoding]::ascii.getbytes($postData)
    $req3 = [System.Net.WebRequest]::Create($url)
    $req3.method = "POST"
    $req3.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    $req3.AllowAutoRedirect = $false
    $req3.ContentType = "application/x-www-form-urlencoded"
    $req3.ContentLength = $buffer.length
    $req3.KeepAlive = $true
    $req3.CookieContainer = $CookieContainer
    $reqst3 = $req3.getRequestStream()
    $reqst3.write($buffer, 0, $buffer.length)
    $reqst3.flush()
    $reqst3.close()
    [net.httpWebResponse] $res3 = $req3.getResponse()
    $resst3 = $res3.getResponseStream()
    $sr3 = new-object IO.StreamReader($resst3)
    $result3 = $sr3.ReadToEnd()
    $res3.close()

}


# 4.  Perform a GET on the page (this is the role selection page)

$req4 = [System.Net.WebRequest]::Create($urlredirect)
$req4.method = "GET"
$req4.AllowAutoRedirect = $false
$req4.CookieContainer = $CookieContainer
[net.httpWebResponse] $res4 = $req4.getResponse()
$resst4 = $res4.getResponseStream()
$sr4 = new-object IO.StreamReader($resst4)
$result4 = $sr4.ReadToEnd()
$res4.close()

#Scrape the html from the GET to determing the SAML response that is needed to do the assume and RelayState
$SAMLResp = ((($result4 -split "value=")[1]) -split " ")[0]
$SAMLResp = $SAMLResp.Substring(1,$SAMLResp.Length-2)


#Peform a post if realm is specified in adfs file
if($realmsupplied) {
    #url encode the SAMLResponse
    $SAMLResp = [System.Web.HttpUtility]::HtmlDecode($SAMLResp)
    $SAMLResp = [System.Web.HttpUtility]::UrlEncode($SAMLResp)

    $RelayState = ((($result4 -split "value=")[2]) -split " ")[0]
    $RelayState = $RelayState.Substring(1,$RelayState.Length-2)
    $postData2 = "SAMLResponse=$SAMLResp&RelayState=$RelayState"

    #encode post data
    $buffer = [text.encoding]::ascii.getbytes($postData2)

    $req5 = [System.Net.WebRequest]::Create($url3)
    $req5.method = "POST"
    $req5.AllowAutoRedirect = $false
    $req5.ContentType = "application/x-www-form-urlencoded"
    $req5.ContentLength = $buffer.length
    $req5.CookieContainer = $CookieContainerInital
    try {
        $reqst5 = $req5.getRequestStream()
    } catch {
        $ErrorMessage = $_.Exception.Message
        write-host "Error - Unable to connect to ADFS: $ErrorMessage" -ForegroundColor Red -BackgroundColor Black
        break
    }
    $reqst5.write($buffer, 0, $buffer.length)
    $reqst5.flush()
    $reqst5.close()
    [net.httpWebResponse] $res5 = $req5.getResponse()
    $resst5 = $res5.getResponseStream()
    $sr5 = new-object IO.StreamReader($resst5)
    $result5 = $sr5.ReadToEnd()
    $res5.close()

    $SAMLResp = (($result5 -split 'name="SAMLResponse" value="')[1] -split '" />')[0]

} 


# 5.  Handle role selection

try {
    #Determine the Roles list that the user has access to
    [xml]$temp = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($SAMLResp))
} catch {
    write-host "Error - Authentication failed (unable to parse SAML from ADFS response)" -ForegroundColor Red -BackgroundColor Black
    break
}
$AssersionRoles = ($temp.Response.Assertion.AttributeStatement.Attribute | ?{$_.Name -eq "https://aws.amazon.com/SAML/Attributes/Role"}).AttributeValue

#Create powershell object to help parse and list roles for user creation
$Target= @()
$i=1
foreach($_ in $AssersionRoles){
    $object = $_ -split ","
    $TargetProperties = @{SAMLProvider=$object[0];RoleARN=$object[1];ItemNumber=$i}  
    $TargetObject = New-Object PSObject -Property $TargetProperties
    $Target +=  $TargetObject
    $i++

}

#remove variable so when rerunning for new powershell credentials does not cause error
Remove-Variable reqinital


#Prompt user to select what role thay want to assume
Write-Host "***************************************************************" -ForegroundColor Green -BackgroundColor Black
Write-Host "----------------- AWS SSO Key Helper Script -------------------" -ForegroundColor Green -BackgroundColor Black
Write-Host "---------- List of AWS Accounts and Roles avaliable -----------" -ForegroundColor Green -BackgroundColor Black
Write-Host "***************************************************************" -ForegroundColor Green -BackgroundColor Black
foreach($_ in $Target){
    [string]$accountid = $_.SAMLProvider.Split(":")[4]
    $accountname = $accountmap[$accountid]
    if($accountname -eq $null){
        $accountname = $accountid
    }
    $rolename = (($_.RoleARN.Split(":")[5]) -split "role/")[2,-1]
    
    Write-Host "  ["$_.ItemNumber"] -- " "Accout:"$accountname "-- Role:"$rolename -ForegroundColor Green -BackgroundColor Black
}
Write-Host "Please select Account/Role (enter in number): " -ForegroundColor Green -BackgroundColor Black
$selection = Read-Host


# 6.  Create session / request temp credentials

$principal = ($Target | ? {$_.ItemNumber -eq $selection}).SAMLProvider
$role = ($Target | ? {$_.ItemNumber -eq $selection}).RoleARN

#Load PowerShell session if not CLI else load CLI Credentails
$goodstuff=$null
$type = $type.ToLower();
if($type -ne 'cli'){
    #obtain network credentails of having to auth agains proxy 
    #$creds = [System.Net.CredentialCache]::DefaultNetworkCredentials
    #Set proxy if AWS Powershell needs to use proxy
    #Set-AWSProxy -Hostname $proxy -Port $port -Credential $creds

    ##call AWS sts to assume the role and get access keys and tokin
    $goodstuff = Use-STSRoleWithSAML -PrincipalArn $principal -RoleArn $role -SAMLAssertion $SAMLResp -Region $region 
    
    #Set Default region and credentials for AWS PowerShell session
    Set-DefaultAWSRegion -Region $region

    #Clear AWS default profile as commands seem to default to it rather than set credentials
    #Clear-AWSCredentials -ProfileName default
    try{
        Remove-AWSCredentialProfile -ProfileName default -force
    } 
    catch {
        #suppress error if no default profile found
        #write-host "Info: No default profile"
    }

    #Set default credentails in current PowerShell session
    #Note: http://docs.aws.amazon.com/powershell/latest/reference/items/Set-AWSCredential.html
    #Sets the temporary session-based credentials as active in the current shell. Note that temporary credentials cannot be saved as a profile.
    Set-AWSCredentials -AccessKey $goodstuff.Credentials.AccessKeyId -SecretKey $goodstuff.Credentials.SecretAccessKey -SessionToken $goodstuff.Credentials.SessionToken 

    #Note: When setting AWS PowerShell credentails the scope that the keys are exported to is not "AllScope" thus when calling this script you need to include ". .\AWS-SSO-KeyHelper.ps1"
    #The extra . expands the scipt to the calling script or PowerShell session.
}
else {
    #Note: if aws cli has a connection error make sure you configure a proxy in environemnt variables at this point.
     #$env:HTTP_PROXY = 'http://x.x.x.x:8080'
     #$env:HTTPS_PROXY = 'http://x.x.x.x:8080'

	#call AWS sts to assume the role and get access keys and tokin
    [string]$goodstuff = aws sts assume-role-with-saml --principal-arn $principal --role-arn $role --saml-assertion $SAMLResp
    $vgoodstuff = $goodstuff | ConvertFrom-Json

    #Set Default region and credentials for AWS CLI session
    aws configure set aws_access_key_id $vgoodstuff.Credentials.AccessKeyId --profile default
    aws configure set aws_secret_access_key $vgoodstuff.Credentials.SecretAccessKey --profile default
    aws configure set aws_session_token $vgoodstuff.Credentials.SessionToken --profile default
    aws configure set default.region $region --profile default
}

#Note: http://docs.aws.amazon.com/cli/latest/reference/sts/assume-role-with-saml.html
#The temporary security credentials are valid for the duration that you specified when calling assume-role , or until
#the time specified in the SAML authentication response's SessionNotOnOrAfter value, whichever is shorter. The duration
#can be from 900 seconds (15 minutes) to a maximum of 3600 seconds (1 hour). The default is 1 hour.

$expdate = get-date -Format g ([DateTime]::Now.AddHours(1)) 
Write-Host "---------------------------------------------------------------" -ForegroundColor Green -BackgroundColor Black
Write-Host "---------------- Default AWS Credentials Set ------------------" -ForegroundColor Green -BackgroundColor Black
Write-Host "---------------- Default Region" $region "----------------" -ForegroundColor Green -BackgroundColor Black
Write-Host "------- Credentials will expire on: $expdate --------" -ForegroundColor Green -BackgroundColor Black
Write-Host "***************************************************************" -ForegroundColor Green -BackgroundColor Black



#------------------------------------------- End of Script-------------------------------------------