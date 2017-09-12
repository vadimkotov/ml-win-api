import sys
from core import database
from core import radare
from core import analysis
from core import winapi

CACHE = 'cache'



if len(sys.argv) != 3:
    print 'Usage: me.py <file> <db_name>'
    sys.exit()
    
path = sys.argv[1]
db_path = sys.argv[2]

r2 = radare.Radare(path, CACHE)
r2.analyze()

exe = analysis.Executable(r2)

emu = winapi.WinAPIEmulator(exe, db_path)
emu.run()

r2.quit()
