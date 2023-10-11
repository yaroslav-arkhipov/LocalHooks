unit HookProcesses;

interface

uses
  System.SysUtils,
  Winapi.Windows,
  WinApi.CommCtrl,
  Vcl.StdCtrls,
  WinApi.Messages;

type
  TJumpOfs = Integer;
  PPointer = ^Pointer;

  PXRedirCode = ^TXRedirCode;
  TXRedirCode = packed record
    Jump: Byte;
    Offset: TJumpOfs;
  end;

  TBaseHook = class
    private
      class function GetActualAddr(Proc: Pointer): Pointer;
    public
      class function HookProc(Proc, Dest: Pointer): TXRedirCode;
      class procedure UnhookProc(Proc: Pointer; var BackupCode: TXRedirCode);
      class procedure ReplaceProcedure(ASource, ADestination: Pointer);
  end;

implementation

{ TBaseHook }
//begin HookProcesses
class function TBaseHook.GetActualAddr(Proc: Pointer): Pointer;

type
  PAbsoluteIndirectJmp = ^TAbsoluteIndirectJmp;
  TAbsoluteIndirectJmp = packed record
    OpCode: Word;
    Addr: PPointer;
  end;

begin
  if Proc <> nil then
  begin
    if (PAbsoluteIndirectJmp(Proc).OpCode = $25FF) then
      {$IFDEF Win32}Result := PPointer(PAbsoluteIndirectJmp(Proc).Addr)^{$ENDIF}
      {$IFDEF Win64}Result := PPointer(TNativeUInt(Proc) + PAbsoluteIndirectJmp(Proc).Addr + 6{Instruction Size})^{$ENDIF}
    else
      Result := Proc;
  end
  else
    Result := nil;
end;

class function TBaseHook.HookProc(Proc, Dest: Pointer): TXRedirCode;
var
  n: NativeUInt;
  Code: TXRedirCode;
begin
  Proc := GetActualAddr(Proc);
  Assert(Proc <> nil);
  if ReadProcessMemory(GetCurrentProcess, Proc, @Result, SizeOf(Result), n) then
  begin
    Code.Jump := $E9;
    Code.Offset := PAnsiChar(Dest) - PAnsiChar(Proc) - SizeOf(Code);
    WriteProcessMemory(GetCurrentProcess, Proc, @Code, SizeOf(Code), n);
  end;
end;

class procedure TBaseHook.UnhookProc(Proc: Pointer; var BackupCode: TXRedirCode);
var
  n: NativeUInt;
begin
  if (BackupCode.Jump <> 0) and (Proc <> nil) then
  begin
    Proc := GetActualAddr(Proc);
    Assert(Proc <> nil);
    WriteProcessMemory(GetCurrentProcess, Proc, @BackupCode, SizeOf(BackupCode), n);
    BackupCode.Jump := 0;
  end;
end;
//end HookProcesses

//begin function of replace method
class procedure TBaseHook.ReplaceProcedure(ASource, ADestination: Pointer);

type
  PJump = ^TJump;
  TJump = packed record
    OpCode: Byte;
    Distance: Pointer;
  end;

const
  SIZE = SizeOf(TJump);
var
  NewJump: PJump;
  OldProtect: NativeUInt;
begin
  if VirtualProtect(ASource, SIZE, PAGE_EXECUTE_READWRITE, @OldProtect) then
  try
    NewJump := PJump(ASource);
    NewJump.OpCode := $E9;
    NewJump.Distance := Pointer(Integer(ADestination) - Integer(ASource) - 5);

    FlushInstructionCache(GetCurrentProcess, ASource, SIZE);
  finally
    VirtualProtect(ASource, SIZE, OldProtect, @OldProtect);
  end;
end;
//end function of replace method

end.
