Windows Kernel Exploits: WRMSR (Model Specific Registers)

Model Specific Registers (MSR) are CPU control registers that are specific for a CPU family. Their original purpose was to introduce experimental new features and functionality, but some of them proved useful enough to be retained across CPU models and are not expected to change in future processors. Intel refers to these as Architectural MSRs.

One example of such a register is the Long-mode System call Target Address Register (LSTAR) MSR. This register provides support to the operating system for handling system calls. The OS can store the address of the system call handler in the LSTAR MSR. When the syscall assembly instruction is executed, it switches the CPU to ring 0 mode (kernel mode) and sets the instruction pointer (RIP) to the value stored in the LSTAR register. As a result, the CPU effectively jumps to the system call handler, enabling the OS to process the system call.

If you can write to IA32_LSTAR (via WRMSR), you effectively control the syscall entry point: Redirect every syscall to your own code or a ROP gadget.

That gives arbitrary kernel execution the next time a Syscall runs. In a nutshell, abusing a vulnerable driver through WRMSR you can: 

Save original IA32_LSTAR.,
Write gadget address into IA32_LSTAR.,
Trigger a syscall (NtYieldExecution, etc.).,
CPU jumps to gadget and exploit code executes with kernel privileges.,
Restore original IA32_LSTAR for stability and avoid BSOD,
I have extended the msrexec project with an improved Syscall Wrapper and added automation to execute the ROP gadgets and the Kernel functions as Payloads with a wrapper.

KVA Shadowing detection and bypass,
SMEP bypass using ROP gadgets,
Sycall wrapper pointing to LSTAR ROP gadget,
Arguments instead of hardcoded driver,
Arguments for IOCTLs,
Library Injection into Kernel (ring0),
System 4 token shellcode (Implemented in C++)

![alt text]([http://url/to/img.png](https://i.ibb.co/Mxb3xMWT/Screenshot-from-2025-09-29-20-49-57.png))
