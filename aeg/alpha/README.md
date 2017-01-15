# AEG/Alpha puzzle
> Solved by 張力

`CTF{5YW25a+m5pq05Yqb6Kej5aW95YOP5Lmf6Kej55qE5Ye65L6G}`

We get base64 encoded elf from server.

Every time sever send us different elf files, but there is always a function called `catflag` 

use angr to find out the address of catflag function and set it as target address.

Let angr run and get flag!