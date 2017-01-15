# Crypto/Simple
> Solved by 張力

`CTF{$!mi14r_7o_th3_h0@0m3w@rk5?}`
This problem use AES OFB mode to encrypt flag and more then one message.
![](https://i.imgur.com/sR5h6Ur.png)
As the diagram shown above, if one use same key, IV and OFB mode to encrypt more than one message, It will be a many-time pad vulnerability.

Every corresponding block in each message is xor-ed with same text and we know that each message is consisted of `string.letters + string.digits`

With these two knowledge, We can decrypt the flag.

unfortunately, in this particular problem we can many combination of flag that is possible answer. Therefore I list out all the possible answer and choose the right one. (Obviously, you should know which homework is similar to this one)