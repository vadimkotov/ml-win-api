import esil
import database
import logging

import sys
import simplejson
import z3
import re

def get_ops(path, func):
    ops = []
    for block_addr in path:
        for addr in func.blocks[block_addr]:
            ops.append( func.addr_map[addr] )
    return ops


SUPPORTED_TYPES = ['mov', 'push', 'upush', 'pop', 'upop', 'xor']

def is_supported(op):
    if op['type'] not in SUPPORTED_TYPES \
       or op['opcode'].startswith('rep ') \
       or op['family'] == 'priv':
        return False

    return True

# 'push' - push imm
# 'upush' - push reg/mem
def is_push(op):
    return op['type'] in ['push', 'upush']
    

class WinAPIEmulator:
    def __init__(self, exe, db_path):
        self.db = database.Database(db_path)
        self.db.create_tables()
        self.exe_path = exe.r2.exe_path
        self.exe = exe
        # self.file_id = self.db.add_file({'path': self.exe_path})

    def analyze_path(self, function, path):
        print '[ %x ]' % function.offset
        vm = esil.ESILVM()
        ops = get_ops(path, function)

        conseq_push = 0
        prev = None

        for op in ops:
            if is_supported(op):
                logging.debug('{0}\t// {1}'.format(op['esil'], op['opcode']))

                if is_push(op): 
                    if prev and is_push(prev):
                        conseq_push += 1
                    else:
                        conseq_push = 1
                else:
                    conseq_push = 0
                
                try:
                    vm.execute(op['esil'])
                except RuntimeError as e:
                    print str(e)
                    print simplejson.dumps(op, indent=2)
                    sys.exit()

            # 'ucall' is either a call to IAT or to reg or to memory
            # we don't know the value (vars, args, indexed offsets etc.)
            # 'call' - are normal calls between functions, 
            elif op['type'] in ['ucall', 'call']:
                # print simplejson.dumps(op, indent=2)
                # print
                target = op.get('ptr')

                if not target:
                    continue

                iat_entry = None
                if target in self.exe.import_table:
                    # should be in 'ucall' case
                    iat_entry = self.exe.import_table[target]
                else:
                    # should be in some 'call' cases
                    function = self.exe.functions.get(target)
                    if function and function.jmp_to_iat:
                        iat_entry = function.jmp_to_iat

                if iat_entry:
                    # print iat_entry
                    name = iat_entry['name']
                    args = []
                
                    for i in xrange(conseq_push):
                        if vm.x86_stack:
                            arg = z3.simplify(vm.x86_stack.pop())
                            if hasattr(arg, 'as_long'):
                                arg = '0x%x' % arg.as_long()
                                # print arg
                            else:
                                arg = str(arg)#re.sub(r'', '', str(arg))
                        else:
                            arg = '*'
                        args.append(arg)
                    # print op['opcode']
                    
                    print '{0} ({1})'.format(name, ', '.join(args))
                
            
            prev = op

    def process_function(self, f):
        logging.debug("\tn_edges = {0}".format(f.n_edges))

        if f.n_edges > 100:
            logging.debug('\ttoo many edges, doing random walk')
            max_path = f.get_longest_path_random_walk()

            # print 'PATH:'
            # for addr in max_path:
            #     print hex(addr)
            
        else:
            max_path = f.get_longest_path()


        if not max_path:
            logging.debug('\n\nmax_path not defined!')
            print
            print 'Exit blocks:', map(hex, f.exit_blocks)
            print 'Nodes:', map(hex, f.cfg.nodes())
            print
            print 'Edges:'
            for from_, to_ in f.cfg.edges():
                print hex(from_), '->', hex(to_)
            print f.ops[-1]
            print
            for op in f.ops:
                print '%-8.8x %s ; %s, J:0x%x, F:0x%x' % (op['offset'], op['opcode'], op['type'], op.get('jump', 0), op.get('fail', 0))
            print
            print
            sys.exit()
            
        max_path_len = len(max_path)
        
        # This is a temporary workaround, we'll be checking multiple
        # paths in the future
        for path in [max_path]:
            call_seq = self.analyze_path(f, path)
            if call_seq:
                seq_info = {
                    'file_id': self.file_id,
                    'function_offset': addr,
                    'sequence': ','.join(map(lambda x: str(x), call_seq))
                }
                # print seq_info
                # self.db.add_sequence(seq_info)                

        
    def run(self):
        logging.debug('RUNNING EMULATOR')

        # f = self.exe.functions[0x1018e30]
        # self.process_function(f)

        # print 'Exit blocks:'
        # for addr in f.exit_blocks:
        #     print hex(addr)
        
        for addr, f in self.exe.functions.iteritems():
            logging.debug(hex(addr))
            self.process_function(f)
        
