<#
.SYNOPSIS
Author: Dump-GUY (@vinopaljiri)
Get-PDInvokeImports is tool which is able to detect P/Invoke, Dynamic P/Invoke and D/Invoke used in assembly.
It uses dnlib to parse assembly and .NET reflection to load dnlib.
This PS module could be useful and helpful during reversing .NET assemblies for fast revealing calls to unmanaged API functions used in assembly.
Sometimes malware assemblies are full of junk code where the main functionality is implemeted by direct WIN API or NTAPI calls.

.DESCRIPTION
Get-PDInvokeImports enables you to get fast overview what P/Invoke, Dynamic P/Invoke and D/Invoke are used in assembly.
It will show you what functions are used + MDTokens, where are declared, and all location where are used from code.
This PS module enables you to export all locations where are detected P/Invoke, Dynamic P/Invoke and D/Invokereferenced from code to DnSpy Bookmarks.xml
Example: Imagine 1MB assembly full of junk code + CF obfuscation where main functionality is reached via unmanaged WinAPI\NTAPI calls.

.PARAMETER PathToAssembly
Mandatory parameter.
Specifies the Assembly path to scan.

.PARAMETER PathToDnlib
Optional parameter.
System Path to dnlib.dll.
If powershell is running from the location of dnlib.dll - this parameter could be ignored otherwise specify this parameter.

.PARAMETER ExportDnSpyBookmarks
Optional parameter.
Used to export all detected P/Invoke, Dynamic P/Invoke and D/Invoke locations referenced from code to DnSpy Bookmarks XML file (DnSpy_Bookmarks.xml)
Similar to DnSpy-Analyze-UsedBy (Nice overview where all PInvoke and DInvoke are used in whole code)
So it is possible to import it to DnSpy via Bookmarks Window

.EXAMPLE
PS> Import-Module .\Get-PDInvokeImports.ps1
PS> Get-PDInvokeImports -PathToAssembly 'C:\testfiles\malware.exe' -PathToDnlib "C:\dnlib.dll" -ExportDnSpyBookmarks
PS> Get-PDInvokeImports -PathToAssembly 'C:\testfiles\malware.exe'
PS> Get-PDInvokeImports -PathToAssembly .\malware.exe -ExportDnSpyBookmarks

.LINK
https://github.com/Dump-GUY/Get-PDInvokeImports
https://docs.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke
https://github.com/TheWover/DInvoke
https://bohops.com/2022/04/02/unmanaged-code-execution-with-net-dynamic-pinvoke/
https://docs.microsoft.com/en-us/dotnet/api/system.reflection.emit.typebuilder.definepinvokemethod?view=netframework-4.6.1
#>
function Get-PDInvokeImports
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$PathToAssembly,

        [Parameter(Mandatory = $false)]
        [string]$PathToDnlib = [System.Environment]::CurrentDirectory + "\dnlib.dll",

        [Parameter(Mandatory = $false)]
        [switch]$ExportDnSpyBookmarks = $false
    )

    #DInvoke imports reveal - type filter
    function Get_DInvoke_Types($AllTypes)
    {
        foreach($type in $AllTypes)
        {   
            #get only types which have CustomAttribute = UnmanagedFunctionPointerAttribute and are defined as CallingConvention.StdCall or CallingConvention.Winapi or also possible CallingConvention.Cdecl
            if(("UnmanagedFunctionPointerAttribute" -in $type.CustomAttributes.AttributeType.Name.String) -and ("CallingConvention" -in $type.CustomAttributes.ConstructorArguments.type.TypeName) -and ($type.CustomAttributes.ConstructorArguments.Value -in @(1,2,3)))
            {   
                [System.Object[]]$DInvoke_Types += $type
            }
        }
        return $DInvoke_Types
    }
    #DInvoke imports - add all Used by methods
    function Get_DInvoke_ALL($DInvoke_Types, $All_Types)
    {
        foreach($DinvokeType in $DInvoke_Types)
        {     
            foreach($type in $All_Types)
            {
                foreach($method in $type.Methods)
                {
                    if($DinvokeType.FullName -in $method.MethodBody.Instructions.operand.fullname)
                    {
                        [System.Object[]]$DInvoke_UsedBy += $method
                    }
                }
            }
            Add-Member -InputObject $DinvokeType -NotePropertyName "Used By Methods MDTokens" -NotePropertyValue $DInvoke_UsedBy.MDToken 
            Add-Member -InputObject $DinvokeType -NotePropertyName "Used By Methods" -NotePropertyValue $DInvoke_UsedBy.FullName
            [System.Object[]]$DInvoke_All += $DinvokeType
            if($DInvoke_UsedBy)
            {
                Clear-Variable -Name DInvoke_UsedBy
            }       
        }
        return $DInvoke_All
    }
    #PInvoke imports reveal - Methods filter
    function Get_PInvoke_Methods($AllTypes)
    {
        foreach($type in $AllTypes)
        {   
            foreach($method in $type.Methods)
            {   #get only Methods with PinvokeImpl attribute
                if($method.Attributes.value__ -band [dnlib.DotNet.MethodAttributes]::PinvokeImpl.value__)
                {   
                    [System.Object[]]$PInvoke_Methods += $method
                }
            }
        }
        return $PInvoke_Methods
    }
    #PInvoke imports - add all Used by methods
    function Get_PInvoke_ALL($PInvoke_methods, $All_Types)
    {
        foreach($PinvokeMethod in $PInvoke_methods)
        {     
            foreach($type in $All_Types)
            {
                foreach($method in $type.Methods)
                {
                    if($PinvokeMethod.FullName -in $method.MethodBody.Instructions.operand.fullname)
                    {
                        [System.Object[]]$PInvoke_UsedBy += $method
                    }
                }
            }
            Add-Member -InputObject $PinvokeMethod -NotePropertyName "Used By Methods MDTokens" -NotePropertyValue $PInvoke_UsedBy.MDToken 
            Add-Member -InputObject $PinvokeMethod -NotePropertyName "Used By Methods" -NotePropertyValue $PInvoke_UsedBy.FullName
            [System.Object[]]$PInvoke_All += $PinvokeMethod
            if($PInvoke_UsedBy)
            {
                Clear-Variable -Name PInvoke_UsedBy
            }     
        }
        return $PInvoke_All
    }

    #Dynamic PInvoke imports reveal - Methods filter which are implementing DefinePInvokeMethod
    function Get_PInvoke_Dynamic_Methods($AllTypes)
    {    
        foreach($type in $AllTypes)
        {
            foreach($method in $type.Methods)
            {
                if($method.MethodBody.Instructions.operand.fullname -match 'DefinePInvokeMethod')
                {
                    [System.Object[]]$PInvokeDynamic_methods += $method
                }
            }
        }
        return $PInvokeDynamic_methods
    }
    
   #Dynamic PInvoke imports - add all Used by methods
   function Get_PInvoke_Dynamic_ALL($PInvokeDynamic_Methods, $All_Types)
   {
       foreach($PinvokeDynamicMethod in $PInvokeDynamic_Methods)
       {     
           foreach($type in $All_Types)
           {
               foreach($method in $type.Methods)
               {
                   if($PinvokeDynamicMethod.FullName -in $method.MethodBody.Instructions.operand.fullname)
                   {
                       [System.Object[]]$PInvokeDynamic_UsedBy += $method
                   }
               }
           }
           Add-Member -InputObject $PinvokeDynamicMethod -NotePropertyName "Used By Methods MDTokens" -NotePropertyValue $PInvokeDynamic_UsedBy.MDToken 
           Add-Member -InputObject $PinvokeDynamicMethod -NotePropertyName "Used By Methods" -NotePropertyValue $PInvokeDynamic_UsedBy.FullName
           [System.Object[]]$PInvokeDynamic_ALL += $PinvokeDynamicMethod
           if($PInvokeDynamic_UsedBy)
           {
               Clear-Variable -Name PInvokeDynamic_UsedBy
           }     
       }
       return $PInvokeDynamic_ALL
   }

#Export detected PInvoke, Dynamic PInvoke and Dinvoke to DnSpy bookmarks XML file - all location where they are referenced (similar to DnSpy-Analyze-UsedBy)
    function Get_DnSpy_BookmarksXML($PInvoke_ALL, $PInvokeDynamic_ALL, $DInvoke_ALL, $All_Types)
    {
        $xmltemplate_start = @"
<?xml version="1.0" encoding="utf-8"?>
<settings>
    <section _="eaa1be38-7a55-44af-ad93-5b7ee2327edd">

"@
        $xmltemplate_end = @"
    </section>
</settings>
"@
        #PInvoke part
        $counter = 1
        foreach($PInvoke in $PInvoke_ALL)
        {
            foreach($type in $All_Types)
            {
                foreach($method in $type.Methods)
                {
                    if($PInvoke.FullName -in $method.MethodBody.Instructions.operand.fullname)
                    {
                        for($i = 0; $i -lt $method.MethodBody.Instructions.count; $i++)
                        {
                            if($PInvoke.FullName -in $method.MethodBody.Instructions[$i].operand.fullname)
                            {
                                $xmltemplate_body += @"
        <section _="Bookmark" IsEnabled="True" Name="PInvoke$($counter)_$($PInvoke.Name.String)">
          <section _="BML" __BMT="DotNetBody" AssemblyFullName="$($method.Module.Assembly.FullName)" ModuleName="$($method.Module.Location)" Offset="$($method.MethodBody.Instructions[$i].offset)" Token="$($method.MDToken.Raw)" TokenString="$([System.Net.WebUtility]::HtmlEncode($method.FullName))" />
        </section>

"@
                                $counter++
                            }
                        }
                    }
                }
            }
        }
        #Dynamic PInvoke part
        $counter = 1
        foreach($PInvokeDynamic in $PInvokeDynamic_ALL)
        {
            foreach($type in $All_Types)
            {
                foreach($method in $type.Methods)
                {
                    if($PInvokeDynamic.FullName -in $method.MethodBody.Instructions.operand.fullname)
                    {
                        for($i = 0; $i -lt $method.MethodBody.Instructions.count; $i++)
                        {
                            if($PInvokeDynamic.FullName -in $method.MethodBody.Instructions[$i].operand.fullname)
                            {
                                $xmltemplate_body += @"
        <section _="Bookmark" IsEnabled="True" Name="DynamicPInvoke$($counter)_$($PInvokeDynamic.Name.String)">
          <section _="BML" __BMT="DotNetBody" AssemblyFullName="$($method.Module.Assembly.FullName)" ModuleName="$($method.Module.Location)" Offset="$($method.MethodBody.Instructions[$i].offset)" Token="$($method.MDToken.Raw)" TokenString="$([System.Net.WebUtility]::HtmlEncode($method.FullName))" />
        </section>

"@
                                $counter++
                            }
                        }
                    }
                }
            }
        }
        #DInvoke part
        $counter = 1
        foreach($DInvoke in $DInvoke_ALL)
        {
            foreach($type in $All_Types)
            {
                foreach($method in $type.Methods)
                {
                    if($DInvoke.FullName -in $method.MethodBody.Instructions.operand.fullname)
                    {
                        for($i = 0; $i -lt $method.MethodBody.Instructions.count; $i++)
                        {
                            if($DInvoke.FullName -in $method.MethodBody.Instructions[$i].operand.fullname)
                            {
                                $xmltemplate_body += @"
        <section _="Bookmark" IsEnabled="True" Name="DInvoke$($counter)_$($DInvoke.Name.String)">
          <section _="BML" __BMT="DotNetBody" AssemblyFullName="$($method.Module.Assembly.FullName)" ModuleName="$($method.Module.Location)" Offset="$($method.MethodBody.Instructions[$i].offset)" Token="$($method.MDToken.Raw)" TokenString="$([System.Net.WebUtility]::HtmlEncode($method.FullName))" />
        </section>

"@
                                $counter++
                            }
                        }
                    }
                }
            }
        }
        return ($xmltemplate_start + $xmltemplate_body + $xmltemplate_end)
    }

    ##################################### MAIN PART #####################################
    #loading dnlib.dll via reflection
    if(Test-Path -Path $PathToDnlib -PathType Leaf)
    {
        [System.Reflection.Assembly]::LoadFile($PathToDnlib) | Out-Null
    }
    else
    {
        Write-Host "'dnlib.dll' not found in current or specified directory !!!`n" -ForegroundColor Red
        Break
    }

    #creating moduledef for sepcified assembly path
    if(Test-Path -Path $PathToAssembly -PathType Leaf)
    {
        $ModuleDefMD = [dnlib.DotNet.ModuleDefMD]::Load($PathToAssembly)
    }
    else
    {
        Write-Host "'PathToAssembly' error!!! Assembly not found in specified directory !!!`n" -ForegroundColor Red
        Break
    }
    #getting ALL Types
    #warning - $ModuleDefMD.Types - doesnt give all nested -> use $ModuleDefMD.GetTypes() -gives ALL
    $All_Types = $ModuleDefMD.GetTypes()
    ##################################### MAIN PART #####################################

    ##################################### PINVOKE PART ##################################### 

    Write-Host "Found PInvoke Imports:" -ForegroundColor Green
    #getting only potential Methods used for PInvoke - filtering
    [System.Object[]]$PInvoke_Methods = Get_PInvoke_Methods -AllTypes $All_Types
    if($PInvoke_Methods)
    {
        #getting all methods where PInvoke is used add them as property
        [System.Object[]]$PInvoke_ALL = Get_PInvoke_ALL -PInvoke_methods $PInvoke_Methods -All_Types $All_Types
        #result -> potential PInvoke imports
        $PInvoke_ALL | Select-Object -Property Name, MDToken, DeclaringType, "Used By Methods", "Used By Methods MDTokens"
    }
    else
    {
        Write-Host "NONE`n" -ForegroundColor Red
    }

    ##################################### PINVOKE PART ##################################### 

    ##################################### DYNAMIC PINVOKE PART ##################################### 

    Write-Host "Found Dynamic PInvoke Imports:" -ForegroundColor Green
    #getting only potential Methods using Dynamic PInvoke (DefinePInvokeMethod) - filtering
    [System.Object[]]$PInvokeDynamic_Methods = Get_PInvoke_Dynamic_Methods -AllTypes $All_Types
    if($PInvokeDynamic_Methods)
    {
        #getting all methods where Dynamic PInvoke is used add them as property
        [System.Object[]]$PInvokeDynamic_ALL = Get_PInvoke_Dynamic_ALL -PInvokeDynamic_Methods $PInvokeDynamic_Methods -All_Types $All_Types
        #result -> potential Dynamic PInvoke imports
        $PInvokeDynamic_ALL | Select-Object -Property Name, MDToken, DeclaringType, "Used By Methods", "Used By Methods MDTokens"
    }
    else
    {
        Write-Host "NONE`n" -ForegroundColor Red
    }

    ##################################### DYNAMIC PINVOKE PART ##################################### 

    ##################################### DINVOKE PART ##################################### 
    Write-Host "Found DInvoke Imports:" -ForegroundColor Green
    #getting only potential types used for DInvoke - filtering
    [System.Object[]]$DInvoke_Types = Get_DInvoke_Types -AllTypes $All_Types
    if($DInvoke_Types)
    {
        #getting all methods where DInvoke is used add them as property
        [System.Object[]]$DInvoke_ALL = Get_DInvoke_ALL -DInvoke_Types $DInvoke_Types -All_Types $All_Types
        #result -> potential DInvoke imports
        $DInvoke_ALL | Select-Object -Property Name, MDToken, DeclaringType, "Used By Methods", "Used By Methods MDTokens"
    }
    else
    {
        Write-Host "NONE`n" -ForegroundColor Red
    }
    ##################################### DINVOKE PART ##################################### 
    #Export all used PInvoke, Dynamic PInvoke and DInvoke to DnSpy bookmarks XML file - contains all methods location where they are used
    if($ExportDnSpyBookmarks)
    {
        $BookmarksXML = Get_DnSpy_BookmarksXML -PInvoke_ALL $PInvoke_ALL -PInvokeDynamic_ALL $PInvokeDynamic_ALL -DInvoke_ALL $DInvoke_ALL -All_Types $All_Types
        Set-Content -Path .\DnSpy_Bookmarks.xml -Value $BookmarksXML -Encoding UTF8
    }
    #Cleanup Vars
    if($PInvoke_Methods)
    {
        Clear-Variable -Name PInvoke_Methods, PInvoke_ALL
    }
    if($PInvokeDynamic_Methods)
    {
        Clear-Variable -Name PInvokeDynamic_Methods, PInvokeDynamic_ALL
    }
    if($DInvoke_Types)
    {
        Clear-Variable -Name DInvoke_Types, DInvoke_ALL
    }
    
}