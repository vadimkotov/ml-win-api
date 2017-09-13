import esil
import database
import logging

import sys
import simplejson
import z3
import re




DB_ENABLED = False
WINAPI_DB = 'winapi.sqlite'


class WinAPI:
    def __init__(self):
        self.db = database.Database(WINAPI_DB)
        

    def __get_n_args(self, api_name):
        sql_str = """
        SELECT n_arguments
        FROM winapi
        WHERE name = '{0}'
        """.format(api_name)

        res = self.db.query(sql_str)
        if res:
            return res[0]['n_arguments']
        
    def get_n_args(self, api_name):
        # Mind A and W versions:
        # if api_name.endswith('A') or api_name.endswith('W'):
        #    api_name = api_name[:-1]
        res = self.__get_n_args(api_name)
        if not res and (api_name.endswith('A') or api_name.endswith('W')):
            res = self.__get_n_args(api_name[:-1])
            if not res:
                res = self.__get_n_args(api_name.replace('Nt','Zw'))
                                        
        return res






def get_ops(path, func):
    ops = []
    for block_addr in path:
        for addr in func.blocks[block_addr]:
            ops.append( func.addr_map[addr] )
    return ops


SUPPORTED_TYPES = ['mov', 'push', 'upush', 'pop', 'upop', 'xor', 'lea']

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
    
def find_mem_address(memory, n):
    for addr, value in memory.iteritems():
        if value == n:
            addr = addr.split(':')[-1]
            if esil.INT_REGEX.match(addr):
                return int(addr)



class WinAPIEmulator:
    def __init__(self, exe, db_path):
        self.db = database.Database(db_path)
        self.db.create_tables()
        self.exe_path = exe.r2.exe_path
        self.exe = exe
        self.winapi = WinAPI()
        if DB_ENABLED:
            self.file_id = self.db.add_file({'path': self.exe_path})

    def analyze_path(self, function, path):
        print '[ %x ]' % function.offset
        vm = esil.ESILVM()
        ops = get_ops(path, function)
        call_seq = []
        # conseq_push = 0
        prev = None

        for op in ops:

            if is_supported(op):
                logging.debug('{0}\t// {1}'.format(op['esil'], op['opcode']))

                
                # if is_push(op): 
                #     if prev and is_push(prev):
                #         conseq_push += 1
                #     else:
                #         conseq_push = 1
                
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
                # approximate number of args by the number of
                # consequetive pushes
                # n_args = conseq_push
                # reset the conuter for consequtive PUSH'es
                # conseq_push = 0

                
                
                # print simplejson.dumps(op, indent=2)
                # print
                # target = op.get('ptr')
                target = None
                if 'ptr' in op:
                    target = op['ptr']
                    # print 'ptr:', target, ',', op['opcode']
                else:
                    # check if it's a poiner to API passed via reg32
                    ptr = op['opcode'].split(' ')[-1].strip()

                    if ptr in vm.registers:
                        val = vm.get_reg(ptr)
                        if isinstance(val, z3.BitVecRef) and str(val).startswith('mem'):
                            mem_addr = find_mem_address(vm.memory, val)
                            
                            if mem_addr:
                                target = mem_addr

                # continue
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

                    n_args = self.winapi.get_n_args(name)
                    if not n_args:
                        continue
                    
                    args = []
                
                    for i in xrange(n_args):
                        if vm.x86_stack:
                            arg = z3.simplify(vm.x86_stack.pop())
                            # arg = z3.simplify(vm.x86_stack[-1])
                            if hasattr(arg, 'as_long'):
                                arg = '0x%x' % arg.as_long()
                            else:
                                arg = str(arg)
                        else:
                            arg = '*'
                        args.append(arg)
                    # print op['opcode']
                    # arguments = ','.join(map(lambda s: '"%s"' % s, args))
                    print '{0} ({1})'.format(name, ', '.join(args))

                    if DB_ENABLED:
                        seq_id = self.db.add_call({'name': name, 'arguments': simplejson.dumps(args)})
                        call_seq.append(seq_id)
                
                
            prev = op
        return call_seq    

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

                if DB_ENABLED:
                    seq_info = {
                        'file_id': self.file_id,
                        'function_offset': f.offset,
                        'sequence': simplejson.dumps(call_seq)
                    }

                    self.db.add_sequence(seq_info)                

        
    def run(self):
        logging.debug('RUNNING EMULATOR')

        # f = self.exe.functions[0x42615d9]
        # self.process_function(f)

        # print 'Exit blocks:'
        # for addr in f.exit_blocks:
        #     print hex(addr)
        
        for addr, f in self.exe.functions.iteritems():
            logging.debug(hex(addr))
            self.process_function(f)
                    
