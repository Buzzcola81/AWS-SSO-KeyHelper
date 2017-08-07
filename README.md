# AWS-SSO-KeyHelper
PowerShell script to generate temporary access keys for AWS PowerShell or AWS CLI using ADFS SSO integration.
This script supports ADFS servers that prompt for MFA codes, and support ADFS servers that intergrate with multiple domains.
Temporary credentials are valid for 1 hour.

## Usage
By default when executing the script is uses CLI and the default region is ap-southeast-2 (Sydney).

### AWS CLI
Examples:
* .\AWS-SSO-KeyHelper.ps1 -username example\username -password xxxxxxxx -ADFSServer adfs.example.com
* .\AWS-SSO-KeyHelper.ps1 -username example\username -password xxxxxxxx -ADFSServer adfs.example.com -type cli
* .\AWS-SSO-KeyHelper.ps1 -username example\username -password xxxxxxxx -ADFSServer adfs.example.com -mfacode 012345

![AWS CLI Example with Realm specified in config file](https://raw.githubusercontent.com/Buzzcola81/AWS-SSO-KeyHelper/master/images/AWS-SSO-HelperScript-CLI.png "AWS CLI Example with Realm specified in config file")

### AWS PowerShell
Examples:
* . .\AWS-SSO-KeyHelper.ps1 -username example\username -password xxxxxxxx -ADFSServer adfs.example.com -type ps
* . .\AWS-SSO-KeyHelper.ps1 -username example\username -password xxxxxxxx -ADFSServer adfs.example.com -type ps -mfacode 012345

Note: Inorder to expose the default credentials you must specify the ". .\" before the script as tokins can not be saved into AWS PowerShell credentials profile file. 

![AWS PowerShell Example with MFA](https://raw.githubusercontent.com/Buzzcola81/AWS-SSO-KeyHelper/master/images/AWS-SSO-HelperScript-PowerShell.png "AWS PoweShell Example with MFA")

## Switches

### -username
[Mandatory=true]

Provide username that your ADFS server requests (domain\username, username@domain.com and username are all posssible options depending on ADFS configuration)

### -password
[Mandatory=true]

Your account password.

### -ADFSServer
[Mandatory=true]

FQND of the ADFS server or alias used.

### -type
[Mandatory=false]

Store crdentails for use with AWS CLI or AWS PowerShell default profile.

### -region
[Mandatory=false]
[Default=ap-southeast-2]

Set the default AWS region.

### -mfacode
[Mandatory=false]

Note: Required if MFA challenged.

If ADFS server logon process requires MFA specify the code.


## AWSAccounts config file
Contains the realm if ADFS authenticats against multiple dimains and the AWS account name mappings.

See example files:
* awsAccounts-asfsrealm.example.com.txt
* awsAccounts-adfs.example2.com.txt

### Filename and ADFS server mappings
Naming convention: awsAccounts-{ADFSServer}.txt

Example: 
* awsAccounts-asfs.domain.com.txt
File location should be in the same directory as the script invocation.  

### Realm
If the ADFS server authenticats against different domains specify a realm in the AWSAccounts file

Example:
```
realm=adfs.domain2.com
```

### AWS Account ID to Account Name Mapping
To convert AWS AccountID to an AWS Account Name for display in role selection.
For each AWS account enter in the AWS Account ID and Name in the following format:
* {AWSAccountId}={AWSAccount Name}

Example:
```
012345678901=Production
012345678902=Development
012345678903=Sandpit
```


## Notes 
http://docs.aws.amazon.com/powershell/latest/reference/items/Set-AWSCredential.html

Sets the temporary session-based credentials as active in the current shell. Note that temporary credentials cannot be saved as a profile. 
When setting AWS PowerShell credentails the scope that the keys are exported to is not "AllScope" thus when calling this script you need to include ". .\AWS-SSO-KeyHelper.ps1"
The extra . expands the scipt variables to the calling script or PowerShell session.


#Note: http://docs.aws.amazon.com/cli/latest/reference/sts/assume-role-with-saml.html

The temporary security credentials are valid for the duration that you specified when calling assume-role , or until
the time specified in the SAML authentication response's SessionNotOnOrAfter value, whichever is shorter. The duration
can be from 900 seconds (15 minutes) to a maximum of 3600 seconds (1 hour). The default is 1 hour.



 