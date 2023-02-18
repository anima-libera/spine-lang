
# Spine lang

This is a *compiled* **golfing** programming language. Or at least this is what this project is to become (for now it is just a quick and dirty C program that can generate a minimal Linux x86-64 ELF binary (that at least does not crash on my machine xd)).

More comming soon, come back in a few units of time!

## Current state

A C compiler can compile the Spine compiler, and the Spine compiler can compile some very basic stuff into Linux x86-64 ELF binaries.

The Spine compiler takes source code in its first command line argument. To compile everything in one go from compiling the Spine compiler to running the compiled version of the source code given to the Spine compiler, `run_test.sh <src_code>` makes things easier.

Currently accepted instructions are:

syntax | behavior
------ | --------
*base 10 unsigned integers* | push constant to data stack
`p` | pop ascii code from data stack and print
`+` and `-` | pop a, pop b, push (a op b)
`d` and `g` | duplicate and discard
`d` and `g` | duplicate and discard
`[...]` where `...` is some code | push address of anonymous function that does `...`
`i` | pop b, pop a, pop c, if c != 0 then push a else push b
`c` | pop function address and call it
`w` | pop function address b, pop function address c, while(call c, pop != 0){call b}

Spaces are ignored.

*Example:* `31 [d127-][dp 1+]w 10p` prints all the ascii characters from space (code 31) to `~` (code 126).

This is not practical or even golfed at all for now, but this is still very young, give it some time.
