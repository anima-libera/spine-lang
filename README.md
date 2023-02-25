
# Spine lang

This is a *compiled* **golfing** programming language. Or at least this is what this project is to become (for now it is just a quick and dirty C program that can generate a minimal Linux x86-64 ELF binary (that at least does not crash on my machine xd)).

More comming soon, come back in a few units of time!

## Current state

A C compiler can compile the Spine compiler, and the Spine compiler can compile some very basic stuff into Linux x86-64 ELF binaries.

The Spine compiler takes source code in its first command line argument. To compile everything in one go from compiling the Spine compiler to running the compiled version of the source code given to the Spine compiler, `run.sh <args...>` makes things easier.

Invoke the Spine compiler with arguments `-c` and in-command-line source code, or `-f` and path to source file.

For example, `sh run.sh -c "31 [d127-][dp 1+]w 10p"` should work.

Currently accepted instructions are:

syntax | behavior
------ | --------
*base 10 unsigned integer* | push constant
`'` *followed by a character* | push character ascii value
`p` | pop ascii code from data stack and print
`+`, `-`, `*`, `/`, `%` | pop b, pop a, push (a op b)
`d`, `s` and `g` | duplicate, swap 2 and discard
`[...]` where `...` is some code | push address of anonymous function that does `...`
`@F[...]` | define (at compile-time) a function named `F` that does `...`
`F` | call the function named `F`
`c` | pop function address and call it
`w` | pop function address b, pop function address c, while(call c, pop != 0){call b}
`i` | pop b, pop a, pop c, if c != 0 then push a else push b
`r` | return from the current function
`h` | halt execution
`n` | pop index and push copy of stack's index cell
`o` | pop value, pop index and overwrite stack's index cell with value
`"` *some characters* `"` | push address to string, push size of string
`?`, `?b` and `?q` | pop address a, read at it and push *a byte(`b`)/64-bits-int(`q`)
`!`, `!b` and `!q` | pop value, pop address a, write the byte(`b`)/64-bits(`q`) value to a
`_d` | push address of data segment
`k` | pop 6 args, pop n, perform syscall number n with the 6 args, push syscall result

For `?` and `!`, if neither `b` nor `q` is specified then the last one in the function is used (default to `q` if none are ever specified).

Some whitespace is ignored.

*Example:* `31 [d127-][dp 1+]w 10p` prints all the ascii characters from space (code 31) to `~` (code 126).

This is not practical or even golfed at all for now, but this is still very young, give it some time.

## Notes

- There is rudimentary Sublime Text syntax support, see the `Spine.sublime-syntax` file (put it in some Sublime Text folder somewhere to use (or put a symlink instead to keep it automatically updated when git pulling (but note that the simlink trick seem to require closing+reopening Sublime Text to apply any change to the syntax file))).
- There is two stacks: the data stack and the call stack. The data stack is the one used by the instructions ot push and pop data to and from. The call stack is used by function calling and returning, as well as some other instructions (like the `w` loop).
