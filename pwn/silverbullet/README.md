Pwn/SilverBullet
================
> Solved by 梁智湧

## 漏洞描述
由於題目程式中的`power_up`在使用`strncat`時用了**錯誤的上限值**，造成在寫滿`bullet->desc`這個buffer時會**overflow**該buffer，使得`bullet->power`的**least significant byte被歸零**。被歸零後，`power_up`又可再讓使用者輸入更多的input而造成`main`的**stack buffer overflow**，甚至覆寫`main` frame的*return address*。

## Exploit
因為前述漏洞，我們得以覆寫`main` frame的*return address*。由於程式本身有**NX保護**，必須使用**ROP**控制程式行為。但許多address因包含*null byte*，這些address無法被`strncat`複製到buffer上，因此覆寫`main` frame的return address時最多只能使用ROP執行某些gadgets。於是在exploit此題時我們使用了三段ROP chains：

### 第一段ROP Chain
此段ROP chain的目的是為了避免*gadget address*不能有null byte的限制。Chain中使用程式本身的`read_input`**將第二段ROP chain讀到memory當中**某段可讀寫的位置上（*bss區段上*）後，將stack pointer migrate到該區段。此Chain共兩個gadgets，使用了7格stack（28 bytes）。

### 第二段ROP Chain
此段ROP chain的目的是**為得知libc的address**以得到更多的gadgets來組成可spawn shell的指令。其做法**使用plt上的`puts`dump出got上的address**後，再度使用程式本身的`read_input`將第三段ROP chain讀入memory以及migrate。此Chain共三個gadgets，使用了10格stack（40 bytes）。

### 第三段ROP Chain
在生成此段ROP chain時由於已知道libc的address，因此可以使用libc中的所有gadget，直接將程式換成shell。

## Solver
```bash
$ python solver.py
```

## Flag
`CTF{Using_the_silv3r_bull3t_to_pwn_th3_w0rld}`
