Pwn/Start
=========

## 題目描述
這是一題純assembly寫成的程式，這支程式一開始將`_exit`的位置push到stack上以方便到時候return至那個function。接著再將某些內容push到stack上，使用write印出來後，使用read讀取一段資料放到stack上。

## Exoloit
由於程式read的size限制給得太大，因此讀取時超過20 bytes以後的資料都是**stack overflow**，而在read值時輸入的第24~27 bytes將會覆蓋掉原先的return address。解題時需有兩步驟：

### 取得stack address
只需把return address覆寫指向原始碼16行即可，如此一來便可透過程式中自己的write將stack上的資訊印出來，並藉此得到stack pointer。程式write完以後，會再次進入read，因此攻擊者便可再塞入第二段shellcode。

### 塞入shellcode(**execve**)並執行
在已知shellcode將被寫入何處的狀況下，將shellcode透過程式的read將程式寫在stack上後，再將return address覆寫為剛剛塞入之shellcode的address。

## Solver
```bash
$ python solver.py
```

## Flag
`CTF{Z3r0_1s_st4rt}`
