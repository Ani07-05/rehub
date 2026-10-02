rule REHUB_S7_PLC_Stop_Request
{
    meta:
        description = "S7comm job request carrying a PLC stop (function 0x29, P_PROGRAM)"
    strings:
        $header = { 03 00 00 ?? 02 F0 80 32 01 }
        $stop = "P_PROGRAM"
    condition:
        $header at 0 and $stop
}

rule REHUB_Triton_Filenames
{
    meta:
        description = "Two or more file names publicly reported for the TRITON framework"
    strings:
        $a = "inject.bin" ascii wide
        $b = "imain.bin" ascii wide
        $c = "library.zip" ascii wide
        $d = "trilog.exe" ascii wide
    condition:
        2 of them
}

rule REHUB_Modbus_Write_Multiple_Registers
{
    meta:
        description = "Modbus/TCP ADU with function code 16 (write multiple registers)"
    strings:
        $adu = { 00 00 00 ?? 01 10 }
    condition:
        $adu at 2
}
