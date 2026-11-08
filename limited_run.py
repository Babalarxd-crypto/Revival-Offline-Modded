"""Windows-only aggregate process-tree limits: 75% CPU, 80% physical RAM.

Usage: python limited_run.py python some_analysis.py
RAM is a hard job commit limit, not a guarantee about total system usage.
"""
import ctypes as c
from ctypes import wintypes as w
import subprocess
import sys


class IO(c.Structure):
    _fields_ = [(name, c.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


class Basic(c.Structure):
    _fields_ = [("ProcessTime", c.c_longlong), ("JobTime", c.c_longlong),
                ("Flags", w.DWORD), ("MinWorkingSet", c.c_size_t),
                ("MaxWorkingSet", c.c_size_t), ("ActiveProcesses", w.DWORD),
                ("Affinity", c.c_size_t), ("Priority", w.DWORD), ("Scheduling", w.DWORD)]


class Extended(c.Structure):
    _fields_ = [("Basic", Basic), ("IO", IO), ("ProcessMemory", c.c_size_t),
                ("JobMemory", c.c_size_t), ("PeakProcess", c.c_size_t),
                ("PeakJob", c.c_size_t)]


class Cpu(c.Structure):
    _fields_ = [("Flags", w.DWORD), ("Rate", w.DWORD)]


class Memory(c.Structure):
    _fields_ = [("Length", w.DWORD), ("Load", w.DWORD)] + [
        (name, c.c_ulonglong) for name in (
            "TotalPhys", "AvailPhys", "TotalPageFile", "AvailPageFile",
            "TotalVirtual", "AvailVirtual", "AvailExtendedVirtual")]


def run(argv):
    kernel = c.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [c.c_void_p, w.LPCWSTR]
    kernel.CreateJobObjectW.restype = w.HANDLE
    kernel.SetInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]
    kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
    kernel.CloseHandle.argtypes = [w.HANDLE]
    kernel.GlobalMemoryStatusEx.argtypes = [c.POINTER(Memory)]
    nt = c.WinDLL("ntdll")
    nt.NtResumeProcess.argtypes = [w.HANDLE]
    nt.NtResumeProcess.restype = c.c_long

    def check(value):
        if not value:
            raise c.WinError(c.get_last_error())

    job = kernel.CreateJobObjectW(None, None)
    check(job)
    process = None
    try:
        memory = Memory()
        memory.Length = c.sizeof(memory)
        check(kernel.GlobalMemoryStatusEx(c.byref(memory)))
        limits = Extended()
        limits.Basic.Flags = 0x2000 | 0x200  # kill-on-close + aggregate job memory
        limits.JobMemory = memory.TotalPhys * 80 // 100
        cpu = Cpu(0x1 | 0x4, 7500)  # enabled + hard cap, rate in hundredths of %
        check(kernel.SetInformationJobObject(job, 9, c.byref(limits), c.sizeof(limits)))
        check(kernel.SetInformationJobObject(job, 15, c.byref(cpu), c.sizeof(cpu)))
        print(f"Limits: CPU 75%, job RAM commit {limits.JobMemory // (1024**2)} MiB", flush=True)
        process = subprocess.Popen(argv, creationflags=0x4 | 0x4000)  # suspended, below-normal priority
        check(kernel.AssignProcessToJobObject(job, w.HANDLE(process._handle)))
        if nt.NtResumeProcess(w.HANDLE(process._handle)) < 0:
            raise RuntimeError("Unable to resume limited process")
        return process.wait()
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        kernel.CloseHandle(job)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python limited_run.py <command> [arguments...]")
    raise SystemExit(run(sys.argv[1:]))
