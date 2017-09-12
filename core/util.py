import logging
import sqlite3
import hashlib
import zlib
import simplejson
import logging

def init_logging(level):
    logging.basicConfig(level=level)
    
def read_file(path):
    fd = open(path, 'rb')
    data = fd.read()
    fd.close()
    return data

def write_file(path, data):
    fd = open(path, 'wb')
    fd.write(data)
    fd.close()

def get_sha256(bytes_):
    return hashlib.sha256(bytes_).hexdigest()

def get_file_sha256(path):
    data = read_file(path)
    return get_sha256(data)

def compress(data):
    compressed = zlib.compress(data, 9)
    """
    b = io.BytesIO()
    b.write(compressed)
    b.seek(0)
    """
    return sqlite3.Binary(compressed)

def pack_json(json):    
    return compress(simplejson.dumps(json)) if json else ''

def decompress(data):
    try:
        decomp = zlib.decompress(data)
    except zlib.error as e:
        return
    return decomp

def unpack_json(data):
    if not data:
        return ''
    data = decompress(data)
    return simplejson.loads(data) if data else ''

def print_json(json):
    print simplejson.dumps(json, indent=2)

def print_disassembly(ops):
    for op in ops:
        print '%-16x %-32s\t%-32s' % (op['offset'], op['opcode'], op['esil'])

def print_sym_path(ops):
    for op in ops:
        # if op['type'] in ['acmp', 'cmp', 'cjmp', 'jmp', 'ucall', 'call', 'ret']:
        #     continue

        if op['type'] in ['mov', 'push', 'pop']:
            
            print "vm.execute('{0}') # {1}".format(op['esil'], op['opcode'])

