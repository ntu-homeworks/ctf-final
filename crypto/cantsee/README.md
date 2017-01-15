# Crypto/Can'tsee
> Solved by 張力

`CTF{F4c70rdb_m4j_h3!p_y@u_4_lo00o@ot!!*-}`
After using Wireshart to examine the pcap file, we found out that this is an https connection.
But as the man in the middle we need to found out a way to know the private key to decrpyt the packet exchanged between host and client.

After digging around we can see the public key's modulus in Server's certificate is 
```
127695381845955305314119044175645367156893292110941161321719077107414888263779759519500867671046267055721787076353868121513439039348957932492225653101963485405262827994314048491225833005496251590380473976841337081508617693635868822061224787961384029283522108969557388784422275961911498737751836833726011661611
```
search it in factordb and it is factorized!

I followed the step on [this site]( https://blog.didierstevens.com/2008/09/07/mister-p-and-qs-excellent-solution/) to generate a private certificate.

Now import the generated private certificate to Wireshark and we can view the encrypted data!
![](https://i.imgur.com/ibfhSIr.png)