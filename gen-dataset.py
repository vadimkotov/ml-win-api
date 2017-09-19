import sys
import os
from core import database
from core import radare
from core import analysis
from core import winapi
from core import util

import logging
util.init_logging(logging.DEBUG)

CACHE = 'cache'


def analyze(file_, db_path):
    logging.info(file_)

    db = database.Database(db_path)
    file_info = {'path': file_}
    
    if db.file_exists(file_info):
        logging.info('File exists... skipping')
        db.close()
        return
    
    r2 = radare.Radare(file_, CACHE)
    r2.analyze()
    
    try:
        exe = analysis.Executable(r2)
    except analysis.ExecutableInitError as e:
        logging.error(e)
        return
    emu = winapi.WinAPIEmulator(exe, db_path)
    emu.run()
    r2.quit()


if len(sys.argv) != 3:
    print 'Usage: me.py <file or path> <db_name>'
    sys.exit()
    
source = sys.argv[1]
db_path = sys.argv[2]

if os.path.isfile(source):
    analyze(source, db_path)

elif os.path.isdir(source):
    for root, dirs, files in os.walk(source):
        for f in files:
            path = os.path.join(root, f)

            size = os.stat(path).st_size
            
            if size / 1024.0 / 1024.0 > 5:
                logging.info('File too large, skipping')
                continue

            
            analyze(path, db_path)

