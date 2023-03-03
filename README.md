
# Spine lang

This is a stack-based *compiled* **golfing** programming language. Or at least this is what this project is to become (for now it is just a very small stack-based language that compiles to Linux x86-64 ELF binary (that works on my machine xd)).

More comming soon, come back in a few units of time!

## Current state

The Spine compiler can be invoked with arguments `-c` and in-command-line source code, or `-f` and path to source file (multiple pieces of source code can be passed to the compiler, it will read the concatenation of them). The `run.sh` script compiles the Spine compiler, calls the Spine compiler to compile the Spine program, then runs the Spine program. For example, `sh run.sh -c "31 [d127-][dp 1+]w 10p"` should work. The `run.sh` also adds the Spine standard library to the beginning of the source code (see `src/stdlib.spn`)

The Spine compiler is currently a C program (not bootstrapped yet), and the Spine compiler can compile some very basic stuff into Linux x86-64 ELF binaries. It accepts pieces of Spice source code (the "specification" of the Spine programming language is just below).

## Spine "specification"

Instructions in Spine are often one character long and often operate on the data stack (a stack of 64-bits unsigned integers). There is an other stack - the call stack - that is used by calls, returns and a few other instructions. The fact that the data stack is not structred in function stack frames means that functions can freely pop values from the data stack without worrying about popping return addresses or something. There are also two local<sup>1</sup> variables: `h` and `v`.

Currently accepted instructions are:

syntax | behavior
------ | --------
*base 10 unsigned integer* | push constant
`'` *followed by a character* | push character ascii value
`p` | pop ascii code from data stack and print
`+`, `-`, `*`, `/`, `%` | pop b, pop a, push (a op b)
`d`, `s` and `g` | duplicate, swap 2 and discard
`[...]` | push address of anonymous function that does `...`, it can have local variables<sup>1</sup>
`c` | pop function address and call it
`@F[...]` | at compile-time, define (or redefine) a function named `F` that does `...` (the allowed names are all the uppercase letters that are not `H` or `V`), it can have local variables<sup>1</sup>
`F` | call the function named `F`
`w` | pop function address b, pop function address c, while(call c, pop != 0){call b}
`i` | pop b, pop a, pop c, if c != 0 then push a else push b
`H`, `V`, `h`, `v` | pop to set *h*, pop to set *v*, get *h* to push, get *v* to push, these are local<sup>1</sup> variables
`r` | return from the current function
`t` | halt execution
`n` | pop index and push copy of stack's index cell
`o` | pop value, pop index and overwrite stack's index cell with value
`"` *some characters* `"` | push address to string, push size of string
`?`, `?b` and `?q` | pop address a, read at it and push *a byte(`b`)/64-bits-int(`q`)<sup>2</sup>
`!`, `!b` and `!q` | pop value, pop address a, write the byte(`b`)/64-bits(`q`)<sup>2</sup> value to a
`_d` | push address of data segment
`k` | pop 6 args, pop n, perform syscall number n with the 6 args, push syscall result

<sup>1</sup>: The `h` and `v` local variables can be made local by starting a function by the `.` suffix to `[` (doing this is like declaring `h` and `v` again, "run-time shadowing" the previous ones until the function returns; not doing this will allow to access the variables from the previous "run-time scope"). For example, `'aV['bV]cvp` will print `b` (because the function does not suffixes `[` with `.` which means that it uses the variables of the caller), whereas `'aV[.'bV]cvp` will print `a` (because the function suffixes `[` with `.` which means it uses local variables that do not affect the variables of the caller it).

<sup>2</sup>: For `?` and `!`, if neither `b` nor `q` is specified then the last one in the function is used (default to `q` if none are ever specified).

Some whitespace is ignored. Line comments are started with `#!` and end at a new-line character (note how it will allow for she-bang stuff), block comments are started with `#[` and end with `]` (they handle nested brackets, ignore string and character literals and stuff, which allows to use block comments to disable pieces of code easily).

*Example:* `31 [d127-][dp 1+]w 10p` prints all the ascii characters from space (code 31) to `~` (code 126).

This is not practical or even golfed at all for now, but this is still very young, give it some time.

## Notes

- There is rudimentary Sublime Text syntax support, see the `Spine.sublime-syntax` file (put it in some Sublime Text folder somewhere to use (or put a symlink instead to keep it automatically updated when git pulling (but note that the simlink trick seem to require closing+reopening Sublime Text to apply any change to the syntax file))).
- There is two stacks: the data stack and the call stack. The data stack is the one used by the instructions ot push and pop data to and from. The call stack is used by function calling and returning, as well as some other instructions (like the `w` loop).
