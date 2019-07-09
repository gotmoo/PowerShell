<#
Resolve domain group memberships for a user in any domain (even outside forrest)
=======================
Script resolves the current user in the local domain by searching for the SID using ADSI. 
It will then locate all groups matching the SearchFilter and enumerate them to locate 
the user.

Each group with the user as a direct member is returned in the $MemberOf variable. This 
works for local users, but also for ForeignSecurityPrincipals.

Limit the groups enumerated by setting a search filter and the search root in AD.
I've seen this enumerate 100K+ groups, but that also takes a long time.

I'm using this method running as the user after logon, to determine the resources a user
can see.

07/09/2019 Johan Greefkes
#>

Function Translate-UserToSid() {
    param(
        $UserDomain = $env:USERDOMAIN,
        $UserName = $env:USERNAME
    )
    $ObjUSER = New-Object System.Security.Principal.NTAccount ($UserDomain, $UserName)
    $ObjSID = $ObjUSER.Translate([System.Security.Principal.SecurityIdentifier])
    return $ObjSID.Value.ToString()
}


$sid = Translate-UserToSid 

$SearchFilter = "*"
$SearchRoot = "LDAP://OU=MyGroups,DC=domain,DC=com"

$AdUser = ([System.DirectoryServices.DirectorySearcher]"objectsid=$sid").FindOne().Properties

$searcher = New-Object System.DirectoryServices.DirectorySearcher
$searcher.Filter = "(&(ObjectClass=group)(name=$SearchFilter))"
$searcher.PropertiesToLoad.Clear()
[void]$searcher.PropertiesToLoad.Add("member") 
[void]$searcher.PropertiesToLoad.Add("distinguishedname") 
[void]$searcher.PropertiesToLoad.Add("name") 
$searcher.PageSize = 3
#$searcher.SearchRoot = [adsi]$SearchRoot
$result = $searcher.FindAll()

$MemberOf = @()
foreach ($group in $result) {
    if ($group.Properties.member -icontains ($AdUser.distinguishedname)) { $MemberOf += $group.Properties.name }
}

$MemberOf