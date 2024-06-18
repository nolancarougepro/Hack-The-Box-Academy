## Bourne Again Shell : 

[Bash](https://en.wikipedia.org/wiki/Bash_(Unix_shell)) is the scripting language we use to communicate with Unix-based OS and give commands to the system. The main difference between scripting and programming languages is that we don't need to compile the code to execute the scripting language, as opposed to programming languages.

Like a programming language, a scripting language has almost the same structure, which can be divided into :

- `Input` & `Output`
- `Arguments`, `Variables` & `Arrays`
- `Conditional execution`
- `Arithmetic`
- `Loops`
- `Comparison operators`
- `Functions`

To execute a script, we have to specify the interpreter and tell it which script it should process. Such a call looks like this :


```shell
NolanCarougeHTB@htb[/htb]$ bash script.sh <optional arguments>
NolanCarougeHTB@htb[/htb]$ sh script.sh <optional arguments>
NolanCarougeHTB@htb[/htb]$ ./script.sh <optional arguments>
```

Let us look at such a script and see how they can be created to get specific results. If we execute this script and specify a domain, we see what information this script provides.

```shell
NolanCarougeHTB@htb[/htb]$ ./CIDR.sh inlanefreight.com

Discovered IP address(es):
165.22.119.202

Additional options available:
	1) Identify the corresponding network range of target domain.
	2) Ping discovered hosts.
	3) All checks.
	*) Exit.

Select your option: 3

NetRange for 165.22.119.202:
NetRange:       165.22.0.0 - 165.22.255.255
CIDR:           165.22.0.0/16

Pinging host(s):
165.22.119.202 is up.

1 out of 1 hosts are up.
```

```bash
#!/bin/bash

# Check for given arguments
if [ $# -eq 0 ]
then
	echo -e "You need to specify the target domain.\n"
	echo -e "Usage:"
	echo -e "\t$0 <domain>"
	exit 1
else
	domain=$1
fi

# Identify Network range for the specified IP address(es)
function network_range {
	for ip in $ipaddr
	do
		netrange=$(whois $ip | grep "NetRange\|CIDR" | tee -a CIDR.txt)
		cidr=$(whois $ip | grep "CIDR" | awk '{print $2}')
		cidr_ips=$(prips $cidr)
		echo -e "\nNetRange for $ip:"
		echo -e "$netrange"
	done
}

# Ping discovered IP address(es)
function ping_host {
	hosts_up=0
	hosts_total=0
	
	echo -e "\nPinging host(s):"
	for host in $cidr_ips
	do
		stat=1
		while [ $stat -eq 1 ]
		do
			ping -c 2 $host > /dev/null 2>&1
			if [ $? -eq 0 ]
			then
				echo "$host is up."
				((stat--))
				((hosts_up++))
				((hosts_total++))
			else
				echo "$host is down."
				((stat--))
				((hosts_total++))
			fi
		done
	done
	
	echo -e "\n$hosts_up out of $hosts_total hosts are up."
}

# Identify IP address of the specified domain
hosts=$(host $domain | grep "has address" | cut -d" " -f4 | tee discovered_hosts.txt)

echo -e "Discovered IP address:\n$hosts\n"
ipaddr=$(host $domain | grep "has address" | cut -d" " -f4 | tr "\n" " ")

# Available options
echo -e "Additional options available:"
echo -e "\t1) Identify the corresponding network range of target domain."
echo -e "\t2) Ping discovered hosts."
echo -e "\t3) All checks."
echo -e "\t*) Exit.\n"

read -p "Select your option: " opt

case $opt in
	"1") network_range ;;
	"2") ping_host ;;
	"3") network_range && ping_host ;;
	"*") exit 0 ;;
esac
```

As we can see, we have commented here several parts of the script into which we can split it.

1. Check for given arguments
2. Identify network range for the specified IP address(es)
3. Ping discovered IP address(es)
4. Identify IP address(es) of the specified domain
5. Available options

## Conditional Execution : 

Conditional execution allows us to control the flow of our script by reaching different conditions. 
Let us look at the first part of the script again and analyze it.

```bash
#!/bin/bash

# Check for given argument
if [ $# -eq 0 ]
then
	echo -e "You need to specify the target domain.\n"
	echo -e "Usage:"
	echo -e "\t$0 <domain>"
	exit 1
else
	domain=$1
fi

<SNIP>
```

In summary, this code section works with the following components :

- `#!/bin/bash` - Shebang.
- `if-else-fi` - Conditional execution.
- `echo` - Prints specific output.
- `$#` / `$0` / `$1` - Special variables.
- `domain` - Variables.

The shebang line is always at the top of each script and always starts with "`#!`". This line contains the path to the specified interpreter (`/bin/bash`) with which the script is executed.

In pseudo-code, the if condition means the following : 

```bash
if [ the number of given arguments equals 0 ]
then
	Print: "You need to specify the target domain."
	Print: "<empty line>"
	Print: "Usage:"
	Print: "   <name of the script> <domain>"
	Exit the script with an error
else
	The "domain" variable serves as the alias for the given argument 
finish the if-condition
```

By default, an `If-Else` condition can contain only a single "`If`", as shown in the next example.

When adding `Elif` or `Else`, we add alternatives to treat specific values or statuses. If a particular value does not apply to the first case, it will be caught by others.

```bash
#!/bin/bash

value=$1

if [ $value -gt "10" ]
then
	echo "Given argument is greater than 10."
elif [ $value -lt "10" ]
then
	echo "Given argument is less than 10."
else
	echo "Given argument is not a number."
fi
```

## Arguments, Variables, and Arrays : 

The advantage of bash scripts is that we can always pass up to 9 arguments (`$0`-`$9`) to the script without assigning them to variables or setting the corresponding requirements for these. `9 arguments` because the first argument `$0` is reserved for the script.

```shell
NolanCarougeHTB@htb[/htb]$ ./script.sh ARG1 ARG2 ARG3 ... ARG9
       ASSIGNMENTS:       $0      $1   $2   $3 ...   $9
```

This means that we have automatically assigned the corresponding arguments to the predefined variables in this place. These variables are called special variables.

Special variables use the [Internal Field Separator](https://bash.cyberciti.biz/guide/$IFS) (`IFS`) to identify when an argument ends and the next begins.

![[special_var.png]]

In contrast to other programming languages, there is no direct differentiation and recognition between the types of variables in Bash like "`strings`," "`integers`," and "`boolean`." All contents of the variables are treated as string characters. It is important to note when declaring variables that they do `not` contain a `space`. Otherwise, the actual variable name will be interpreted as an internal function or a command.

There is also the possibility of assigning several values to a single variable in Bash. `Arrays` identify each stored entry with an `index` starting with `0`. The declaration for `arrays` looks like this in Bash :

```bash
#!/bin/bash

domains=(www.inlanefreight.com ftp.inlanefreight.com vpn.inlanefreight.com www2.inlanefreight.com)

echo ${domains[0]}
```

It is important to note that single quotes (`'` ... `'`) and double quotes (`"` ... `"`) prevent the separation by a space of the individual values in the array. This means that all spaces between the single and double quotes are ignored and handled as a single value assigned to the array.

## Comparison Operators : 

To compare specific values with each other, we need elements that are called [comparison operators](https://www.tldp.org/LDP/abs/html/comparison-ops.html). The `comparison operators` are used to determine how the defined values will be compared. For these operators, we differentiate between:

- `string` operators
- `integer` operators
- `file` operators
- `boolean` operators

If we compare strings, then we know what we would like to have in the corresponding value.

![[string_op.png]]

String comparison operators "`<` / `>`" works only within the double square brackets `[[ <condition> ]]`.

Comparing integer numbers can be very useful for us if we know what values we want to compare.

![[integer_op.png]]

The file operators are useful if we want to find out specific permissions or if they exist.

![[file_op.png]]

We get a boolean value "`false`" or "`true`" as a result with logical operators. Bash gives us the possibility to compare strings by using double square brackets `[[ <condition> ]]`. To get these boolean values, we can use the string operators.

With logical operators, we can define several conditions within one.

![[logical_op.png]]

## Arithmetic : 

In Bash, we have seven different `arithmetic operators` we can work with. These are used to perform different mathematical operations or to modify certain integers.

![[arithm_op.png]]

We can also calculate the length of the variable. Using this function `${#variable}`, every character gets counted, and we get the total number of characters in the variable.

## Input and Output :

```bash
read -p "Select your option: " opt
```

With the `read` command, the line with "`Select your option:`" is displayed, and the additional option `-p` ensures that our input remains on the same line. Our input is stored in the variable `opt`.

If our scripts become more complicated later, they can take much more time than just a few seconds. To avoid sitting inactively and waiting for our script's results, we can use the [tee](https://man7.org/linux/man-pages/man1/tee.1.html) utility. It ensures that we see the results we get immediately and that they are stored in the corresponding files.

## Flow Control - Loops : 

ach control structure is either a `branch` or a `loop`. Logical expressions of boolean values usually control the execution of a control structure. These control structures include:

- Branches:
    
    - `If-Else` Conditions
    - `Case` Statements

- Loops:
    
    - `For` Loops
    - `While` Loops
    - `Until` Loops


The `For` loop is executed on each pass for precisely one parameter, which the shell takes from a list, calculates from an increment, or takes from another data source.

```bash
for variable in 1 2 3 4
do
	echo $variable
done

for variable in file1 file2 file3
do
	echo $variable
done

for ip in "10.10.10.170 10.10.10.174 10.10.10.175"
do
	ping -c 1 $ip
done
```

The `while` loop is conceptually simple and follows the following principle:

- A statement is executed as long as a condition is fulfilled (`true`).

```bash
while [ $stat -eq 1 ]
do
<SNIP>
done
```

There is also the `until` loop, which is relatively rare. Nevertheless, the `until` loop works precisely like the `while` loop, but with the difference:

- The code inside a `until` loop is executed as long as the particular condition is `false`.

```bash
#!/bin/bash

counter=0

until [ $counter -eq 10 ]
do
  # Increase $counter by 1
  ((counter++))
  echo "Counter: $counter"
done
```

## Flow Control - Branches :

`Case` statements are also known as `switch-case` statements in other languages, such as C/C++ and C#. The main difference between `if-else` and `switch-case` is that `if-else` constructs allow us to check any boolean expression, while `switch-case` always compares only the variable with the exact value.

```bash
case <expression> in
	pattern_1 ) statements ;;
	pattern_2 ) statements ;;
	pattern_3 ) statements ;;
esac
```

## Functions : 

In such cases, `functions` are the solution that improves both the size and the clarity of the script many times.

```bash
function name {
	<commands>
}

name() {
	<commands>
}
```

```bash
#!/bin/bash

function print_pars {
	echo $1 $2 $3
}

one="First parameter"
two="Second parameter"
three="Third parameter"

print_pars "$one" "$two" "$three"
```

```shell
NolanCarougeHTB@htb[/htb]$ ./PrintPars.sh

First parameter Second parameter Third parameter
```

When we start a new process, each `child process` (for example, a `function` in the executed script) returns a `return code` to the `parent process` (`bash shell` through which we executed the script) at its termination, informing it of the status of the execution.

![[return_values.png]]

To get the value of a function back, we can use several methods like `return`, `echo`, or a `variable`. In the next example, we will see how to use "`$?`" to read the "`return code`," how to pass the arguments to the function and how to assign the result to a variable.

## Debugging :

The term `debugging` can have many different meanings. Nevertheless, [Bash debugging](https://tldp.org/LDP/Bash-Beginners-Guide/html/sect_02_03.html) is the process of removing errors (bugs) from our code.

Bash allows us to debug our code by using the "`-x`" (`xtrace`) and "`-v`" options. 

