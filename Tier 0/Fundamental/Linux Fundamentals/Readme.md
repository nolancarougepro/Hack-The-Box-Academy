## Linux Structure : 

![[LinuxStructure.png]]
## Prompt Description : 

![[PromptDescription.png]]
## Navigation : 

![[ls-l.png]]
## File Descriptors and Redirections :

- `STDIN – 0`
- `STDOUT – 1`
- `STDERR – 2

```shell-session
find /etc/ -name shadow 2> stderr.txt 1> stdout.txt
```
## Regular Expressions : 

![[RegularExp.png]]
## Permission Management : 

Owner (u), Group (g), Others (o) et All Users (a).
- (`r`) - Read
- (`w`) - Write
- (`x`) - Execute
## User Management : 

![[UserManagement.png]]
## Package Management : 

![[PackageManagement.png]]
## Service and Process Management : 

A process can be in the following states:
- Running
- Waiting (waiting for an event or system resource)
- Stopped
- Zombie (stopped but still has an entry in the process table).

![[SignalProcess.png]]