

rule Insidefile_String_Test
{
    meta: 
	description = "This is an example"
	thread_level = 3
	in_the_wild = true

    strings:
	$a = "xenophon" nocase

    condition:
	$a
}

rule Win_Trojan_APT_Calc_AWS96 : APT
{
meta:
    author = "Chris Clark"
    date = "2013-06-04"
    description = "APT Trojan Numbered Panda"
    hash0 = "0d32078128468047bcbb686fb30067aa"
    hash1 = "34d8e89afdb9a6055da04cccb7456739"
    hash2 = "8a04e37abb317f1f0b7dcff5b0a08414"
    yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
    $string0 = "QRSTUVWXj"
    $string1 = "QRSTUVWX"
    $string2 = "LR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648)" wide
    $string3 = "QRSTUVWX3"
    $string4 = "www.google.com.tw" wide
    $string5 = "jjjjjj" wide
condition:
    5 of them
}

rule Win_Trojan_APT1_CookieBag : APT
{
meta:
    author = "Chris Clark"
    date = "2013-06-04"
    description = "APT Trojan Comment Panda"
    hash0 = "0c28ad34f90950bc784339ec9f50d288"
    hash1 = "321d75c9990408db812e5a248a74f8c8"
    hash2 = "543e03cc5872e9ed870b2d64363f518b"
    yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
    $string0 = "Y21kLmV4ZQ"
    $string1 = " upfile over"
    $string2 = "sleep:"
    $string3 = "<html>" wide
    $string4 = "Runtime Error"
    $string5 = " .NET CLR 3.5.21022; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)" wide
    $string6 = "ttHHtd"
    $string7 = "Microsoft Visual C"
    $string8 = "download"
    $string9 = "DSUVWh"
    $string10 = "t$$VSS"
    $string11 = "Program: "
    $string12 = "AVout_of_range@std@@"
    $string13 = "D$,RSP"
    $string14 = "AVlogic_error@std@@"
    $string15 = "WSSSSj"
condition:
    15 of them
}
rule Win_Trojan_APT_APT1_Greencat : APT
{
meta:
    author = "Chris Clark"
    date = "2013-06-04"
    description = "APT Trojan Comment Crew Greencat"
    hash0 = "57e79f7df13c0cb01910d0c688fcd296"
    hash1 = "871cc547feb9dbec0285321068e392b8"
    hash2 = "6570163cd34454b3d1476c134d44b9d9"
    yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
    $string0 = "Cache-Control:max-age"
    $string1 = "getf/putf FileName <N>"
    $string2 = "Service started"
    $string3 = "Comments" wide
    $string4 = "Service stop pending"
    $string5 = "Usage:"
    $string6 = "OpenT failed with %d"
    $string7 = "SpecialBuild" wide
    $string8 = "Analog Devices, Inc." wide
    $string9 = "Failed"
    $string10 = "Totally %d volumes found."
    $string11 = "CreateProcess failed"
    $string12 = "Content-Length: %d"
    $string13 = "QVVVPVV"
    $string14 = "Program started"
    $string15 = "Removeable"
    $string16 = "ControlService failed"
    $string17 = "Translation" wide
condition:
    17 of them
}

rule Win_Exploit_OLE_APT_Weaponizer : EXPLOIT APT
{
meta:
    author = "Chris Clark"
    date = "2013-06-07"
    description = "Yara Rule To Detect The MSComctlLib.Toolbar.2 Exploit with Tran Duy Weaponizer"
    hash0 = "bfc96694731f3cf39bcad6e0716c5746"
    hash1 = "770a5a1683caa26caaa1531c2ed5e626"
    hash2 = "d2a2ffc54ad7b591c7e0a62249ff8fe9"
    yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
    $string0 = "<a:clrMap xmlns:a"
    $string1 = "H00000002"
    $string2 = "Tran Duy Linh" wide
    $string3 = "\\system3"
    $string4 = "OCXNAME" wide
    $string5 = "omation"
    $string6 = "OFFICE12"
    $string7 = "{000209F2-0000-0000-C000-000000000046};Word8.0;"
    $string8 = "DDDDDDDDD"
    $string9 = "_Evaluate"
    $string10 = "m Files\\@Common"
    $string11 = " CONTROL MSComctlLib.Toolbar.2 \\s "
    $string12 = "1Normal"
    $string13 = "LLDDLD"
    $string14 = "Root Entry" wide
    $string15 = "T[XF64"
    $string16 = "Attribut"
condition:
    16 of them
}
