from pwn import *
import angr
r=remote('133.130.124.59',9991)
for i in range(3):
    if i == 0:
        a=r.recvlines(3)
        print a
    else :
        r.recvuntil('GJ!\n')
    b=r.recvuntil('\n\n')[:-2]
    bb=b64d(b)

    file_ = open('elf', 'w')
    file_.write(bb)
    file_.close()

    p= angr.Project("elf", load_options={'auto_load_libs':False})
    cfg = p.analyses.CFG(fail_fast=True)

    def getFuncAddress( funcName, plt=None ):
        found = [
            addr for addr,func in cfg.kb.functions.iteritems()
            if funcName == func.name and (plt is None or func.is_plt == plt)
            ]
        if len( found ) > 0:
            print "Found "+funcName+"'s address at "+hex(found[0])+"!"
            return found[0]
        else:
            raise Exception("No address found for function : "+funcName)

    addrcat = getFuncAddress('catflag')
    pg = p.factory.path_group()
    found = pg.explore(find=addrcat).found[0]
    ans1=found.state.posix.dumps(0)
    print ans1
    r.send(ans1)
r.interactive()

