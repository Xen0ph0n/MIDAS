rule MetaData_PDF_Test
{
    meta:                                        
        description = "This is just an example"
        thread_level = 3
        in_the_wild = true

    strings: 
        $a = "'File:MIMEType': u'application/pdf'" nocase 
        $b = "'File:FileType': u'PDF'" 

    condition:
        $a or $b
}

rule MetaData_Author_OracleReports_Test
{
    meta:                                        
        description = "This is just an example"
        thread_level = 3
        in_the_wild = true

    strings: 
        $a = "'PDF:Author': u'Oracle Reports'" nocase  

    condition:
        $a
}
