## Linux Structure : 
![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Linux%20Fundamentals/Images/LinuxStructure.png)
## Prompt Description : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Linux%20Fundamentals/Images/PromptDescription.png)
## Navigation : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Linux%20Fundamentals/Images/ls-l.png)
## File Descriptors and Redirections :

- `STDIN – 0`
- `STDOUT – 1`
- `STDERR – 2`

```shell-session
find /etc/ -name shadow 2> stderr.txt 1> stdout.txt
```
## Regular Expressions : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Linux%20Fundamentals/Images/RegularExp.png)
## Permission Management : 

Owner (u), Group (g), Others (o) et All Users (a).
- (`r`) - Read
- (`w`) - Write
- (`x`) - Execute
## User Management : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Linux%20Fundamentals/Images/UserManagement.png)
## Package Management : 

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Linux%20Fundamentals/Images/PackageManagement.png)
## Service and Process Management : 

A process can be in the following states:
- Running
- Waiting (waiting for an event or system resource)
- Stopped
- Zombie (stopped but still has an entry in the process table).

![](https://github.com/nolancarougepro/Hack-The-Box-Academy/blob/main/Tier%200/Fundamental/Linux%20Fundamentals/Images/SignalProcess.png)
