(* Boiler temperature control *)
PROGRAM Boiler
VAR
    Setpoint : INT := 80;
    HighLimit : INT := 95;
END_VAR
IF Temp > Setpoint THEN
    Valve := FALSE;
END_IF;
END_PROGRAM
