Pwn/Alivenote
=============
> Solved by 梁智湧

## 漏洞描述
此題類似作業的*deathnote*，可利用`add_note`時對`idx`的錯誤檢查：在把字串寫入memory後，將該字串的address寫到任意memory位置中。這題程式亦未啟動NX，因此可以如作業將shellcode的address寫到got中，促使程式自己去執行shellcode。但此題與作業不同的地方有兩處：

1. 對於輸入字串的檢查更加嚴格，只能有英文字、數字、以及空格。
2. 一次輸入的字串最多只能有8 bytes。

## Exploit
由於上述漏洞，我們得以控制程式行為，但須解決上述的兩個多出來的問題：

### Shellcode內容限制
由於shellcode的要求較作業中嚴格，必須撰寫符合條件的shellcode，並且如作業中因為使用system call時必定要執行`int 0x80`(0xcd 0x80)，該段shellcode必須被encode且在shellcode中要再加decoder。在shellcode開始執行時，shellcode的起頭address會被存放在*edx*中，可利用此特點算出需decode的shellcode將其decode。

此為本題中所使用的Shellcode（已encode）：
`jhhnnn2X5AAAAPhnbinX4APhpZAAX5 PAATYjAQRQTUPWa4AH0D20HHHHH0D21jAX4APYPZjAX4J2z`

### 一次只能8 bytes
這邊必須利用*glibc*中`malloc`的以下性質以將每段短短的shellcode串在一起：

1. 若如同此程式每次都使用`malloc`分配8 bytes時，所得到的address將每次差16 bytes。
2. 在使用`free`釋放掉某個空間後，若下次再使用`malloc`分配一樣大的空間時，將得到與被釋放的那段空間一樣的address。

利用以上性質，我們撰寫好符合內容限制的shellcode後，每段字串只放入一個指令。接著使用`inc edi`（1 byte的指令）作為padding將該字串填到6 bytes後，最後再加上`jne eip+0x38`（2 bytes的指令），如此我們便可將shellcode的每個指令組成一小段段的code片段。

接著將這些小片段使用程式的`add_name`功能放入heap中，並在每個小片段間多加上3個padding用的小片段（因為`jne`時亦必須符合shellcode的內容限制）。在寫入heap時，除了第一段的address要分開儲存在`note`的不同欄位外，其他段小片段的address都可以隨便存在`note`的其他欄位（可以覆蓋）。

最後要將第一段小片段`free`掉，再將第一段重新寫到heap中，而由於上述第二點的性質，該段shellcode會被放回原先的位置。在此次寫入heap時，要透過前述`idx`檢查錯誤的漏洞把該片段的address寫到got當中（寫在`puts@got`）。如此當程式接著執行`puts`時便可觸發執行我們串好的shellcode，進而拿到shell。

下圖描繪shellcode串接的概念：

```
------------- ------- ------- ------- ------------- ------- ------- ------- ------------- ------- ------- ------- -------------
|   i   i j | |     | |     | |     | |   i   i j | |     | |     | |     | |   i   i j | |     | |     | |     | |   i   i j |
|   n   n n | |     | |     | |     | |   n   n n | |     | |     | |     | |   n   n n | |     | |     | |     | |   n   n n |
| C c   c e | |     | |     | |     | | C c   c e | |     | |     | |     | | C c   c e | |     | |     | |     | | C c   c e |
| O   .     | | ... | | ... | | ... | | O   .     | | ... | | ... | | ... | | O   .     | | ... | | ... | | ... | | O   .     | ...
| D e . e 0 | |     | |     | |     | | D e . e 0 | |     | |     | |     | | D e . e 0 | |     | |     | |     | | D e . e 0 |
| E d . d x | |     | |     | |     | | E d . d x | |     | |     | |     | | E d . d x | |     | |     | |     | | E d . d x |
|   i   i 3 | |     | |     | |     | |   i   i 3 | |     | |     | |     | |   i   i 3 | |     | |     | |     | |   i   i 3 |
|         8 | |     | |     | |     | |         8 | |     | |     | |     | |         8 | |     | |     | |     | |         8 |
------------- ------- ------- ------- ------------- ------- ------- ------- ------------- ------- ------- ------- -------------
          |                             ^       |                             ^       |                             ^       |
          |_____________________________|       |_____________________________|       |_____________________________|       |----->
```

## Solver
```bash
$ python solver.py
```

## Flag
`CTF{Sh3llcoding_in_th3_n0t3_ch4in}`
