"""Run a CI command in a Windows Job Object and stream combined output."""

import ctypes
import os
import subprocess
import sys
from ctypes import wintypes


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class _ProcessInformation(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


def _launch(arguments):
    if os.name != "nt":
        raise OSError("The CI Windows launcher can only run on Windows.")
    if not arguments or arguments[0] not in ("--shell", "--exec"):
        raise ValueError("Expected --shell or --exec")

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
    kernel.SetInformationJobObject.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    kernel.CreatePipe.argtypes = (
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
    )
    kernel.SetHandleInformation.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    kernel.GetStdHandle.argtypes = (wintypes.DWORD,)
    kernel.GetStdHandle.restype = wintypes.HANDLE
    kernel.CreateProcessW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfo),
        ctypes.POINTER(_ProcessInformation),
    )
    kernel.CreateProcessW.restype = wintypes.BOOL
    kernel.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
    kernel.ResumeThread.argtypes = (wintypes.HANDLE,)
    kernel.ResumeThread.restype = wintypes.DWORD
    kernel.ReadFile.argtypes = (
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    )
    kernel.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel.GetExitCodeProcess.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    )
    kernel.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)

    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    read_pipe = write_pipe = None
    process_info = _ProcessInformation()
    process_assigned = False
    try:
        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = (
            0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        if not kernel.SetInformationJobObject(
            job, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        security = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), None, True)
        read_pipe, write_pipe = wintypes.HANDLE(), wintypes.HANDLE()
        if not kernel.CreatePipe(
            ctypes.byref(read_pipe), ctypes.byref(write_pipe), ctypes.byref(security), 0
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        if not kernel.SetHandleInformation(read_pipe, 1, 0):  # HANDLE_FLAG_INHERIT
            raise ctypes.WinError(ctypes.get_last_error())

        if arguments[0] == "--shell":
            executable = os.environ.get("COMSPEC", "cmd.exe")
            command_line = subprocess.list2cmdline(
                [executable, "/d", "/s", "/c", arguments[1]]
            )
        else:
            if len(arguments) < 2:
                raise ValueError("--exec requires a command")
            executable = arguments[1]
            command_line = subprocess.list2cmdline(arguments[1:])

        startup = _StartupInfo()
        startup.cb = ctypes.sizeof(startup)
        startup.dwFlags = 0x100  # STARTF_USESTDHANDLES
        startup.hStdInput = kernel.GetStdHandle(0xFFFFFFF6)  # STD_INPUT_HANDLE
        startup.hStdOutput = write_pipe
        startup.hStdError = write_pipe
        command_buffer = ctypes.create_unicode_buffer(command_line)
        if not kernel.CreateProcessW(
            executable,
            command_buffer,
            None,
            None,
            True,
            0x4,
            None,
            None,
            ctypes.byref(startup),
            ctypes.byref(process_info),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        kernel.CloseHandle(write_pipe)
        write_pipe = None

        # Keep the initial thread suspended until the process belongs to the job.
        if not kernel.AssignProcessToJobObject(job, process_info.hProcess):
            raise ctypes.WinError(ctypes.get_last_error())
        process_assigned = True
        if kernel.ResumeThread(process_info.hThread) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())

        buffer = ctypes.create_string_buffer(65536)
        while True:
            count = wintypes.DWORD()
            if not kernel.ReadFile(
                read_pipe, buffer, len(buffer), ctypes.byref(count), None
            ):
                error = ctypes.get_last_error()
                if error == 109:  # ERROR_BROKEN_PIPE
                    break
                raise ctypes.WinError(error)
            if count.value == 0:
                break
            sys.stdout.buffer.write(buffer.raw[: count.value])
            sys.stdout.buffer.flush()

        kernel.WaitForSingleObject(process_info.hProcess, 0xFFFFFFFF)
        exit_code = wintypes.DWORD()
        if not kernel.GetExitCodeProcess(
            process_info.hProcess, ctypes.byref(exit_code)
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return exit_code.value
    finally:
        if process_info.hProcess:
            if process_assigned:
                # Closing the job also terminates any surviving descendants.
                kernel.CloseHandle(job)
                job = None
            else:
                kernel.TerminateProcess(process_info.hProcess, 1)
            kernel.CloseHandle(process_info.hThread)
            kernel.CloseHandle(process_info.hProcess)
        if read_pipe and read_pipe.value:
            kernel.CloseHandle(read_pipe)
        if write_pipe and write_pipe.value:
            kernel.CloseHandle(write_pipe)
        if job:
            kernel.CloseHandle(job)


if __name__ == "__main__":
    try:
        raise SystemExit(_launch(sys.argv[1:]))
    except Exception as exc:
        print(f"CI process launcher failed: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(127)
