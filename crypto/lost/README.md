# Crypto/Lost
> Solved by 張力

`CTF{0x52fec4c0afd8ffaebc93cbaa6}`

Examine the pcap file and we can find out it is exchanging some messages but some digit in it is missing.

After assemble it looks like this:

```
KEY = KeyAd5xBvZR1HVhE6**
Plaintext = Thi5 i$ 7he p!4int3x7 0f AES-CBC
AES-CBC(KEY, Plaintext) =  1f****************************8452fe2ad18a9e5e26887d133a13d7b818
AES-CBC(KEY, FLAG) = 9c2ea756ed9ca3c05d541f7df961b3569e5f85a3387a818ed4c23db57aeeb1e4
```
`key` is missing last two digits and `AES-CBC(KEY, Plaintext)` is missing first block except fist and last digits

We also need to know Initial Vector to decrypt AES-CBC(KEY, FLAG)

First, I find out the first block of `AES-CBC(KEY, Plaintext)` by trying all possible `KEY` and use it to decrypt second block of plain text, and find out all possible (key, first block) pair.

Then I use all (key, first block) to generate IV and then decrypt the flag and see which one is correct!