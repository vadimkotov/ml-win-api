import esil
import database
import logging

import sys
import simplejson
import z3
import re


DB_ENABLED = True
WINAPI_DB = 'core/winapi.sqlite'


def print_op(op):
    print simplejson.dumps(op, indent=2)

    
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


SUPPORTED_TYPES = [
    'mov', 'push', 'upush', 'pop', 'upop', 'xor', 'lea',
    'add', 'sub'
]

# TODO: implement sse support
def is_supported(op):
    if op['type'] not in SUPPORTED_TYPES \
       or op['opcode'].startswith('rep ') \
       or op['family'] in ['priv', 'sse', 'mmx']:
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

# Abstract names:
MEM = 'mem'
VAR = 'var'

def abstract_val_str(s):
        
    if re.search(r'^mem\d+$', s):
        return MEM

    # Check if it's arg or var
    name = esil.get_name_from_addr_str(s)
    if name:
        s = name

    # In this representation we don't distiguish
    # between var and arg
    if re.search(r'^var_.+?h$|^arg_.+?h$', s):
        return VAR

    
    # Fix negation
    # Examples: 4294967295*ret, 4294967295*ret
    s = re.sub(r'4294967295\*([a-zA-F0-9_]+)', lambda x: '-%s'%x.group(1), s)
    return s


class WinAPIEmulator:
    def __init__(self, exe, db_path):
        self.db = database.Database(db_path)
        self.db.create_tables()
        self.exe_path = exe.r2.exe_path
        self.exe = exe
        self.winapi = WinAPI()
        # self.__skip = False
        if DB_ENABLED:
            file_info = {'path': self.exe_path}
            file_id = self.db.file_exists(file_info)
            if file_id:
                # self.__skip = True
                self.file_id = file_id
            else:
                self.file_id = self.db.add_file(file_info)


    def get_call_target(self, op, vm):
        if 'ptr' in op:
            return op['ptr']
        else:
            # check if it's a poiner to API passed via reg32
            ptr = op['opcode'].split(' ')[-1].strip()
            if ptr in vm.registers:
                val = vm.get_reg(ptr)
                if isinstance(val, z3.BitVecRef) and str(val).startswith('mem'):
                    mem_addr = find_mem_address(vm.memory, val)
                            
                    if mem_addr:
                        return mem_addr

        
    def get_iat_entry(self, target):
        if target in self.exe.import_table:
            # should be in 'ucall' case
            return self.exe.import_table[target]
        else:
            # should be in some 'call' cases
            function = self.exe.functions.get(target)
            if function and function.jmp_to_iat:
                return function.jmp_to_iat

    def check_pointer(self, addr):
        for sect in self.exe.sections:
            start = sect['vaddr']
            end = start  + sect['vsize']
            if addr >= start and addr < end:                
                # flags = sect['flags']
                # if flags[4] == 'x':
                #     return 'PTR_CODE'
                # else:
                #     return 'PTR_DATA'
                return 'PTR'

    def get_args(self, n_args, vm):
        args = []
                
        for i in xrange(n_args):
            if vm.x86_stack:
                arg = z3.simplify(vm.x86_stack.pop())
                # arg = z3.simplify(vm.x86_stack[-1])
                if hasattr(arg, 'as_long'):
                    ptr_ = self.check_pointer(arg.as_long())
                    if ptr_:
                        arg = ptr_
                    else:
                        arg = '0x%x' % arg.as_long()
                else:
                    arg = str(arg)
                    name = abstract_val_str(arg)#
                    if name:
                        arg = name

            else:
                arg = '*'
                
            args.append(arg)
        return args
            
    def analyze_path(self, function, path):
        # print '[ %x ]' % function.offset
        vm = esil.ESILVM()
        ops = get_ops(path, function)
        call_seq = []
        # conseq_push = 0
        prev = None

        for op in ops:                
            if is_supported(op):
                logging.debug('{0}\t// {1}'.format(op['esil'], op['opcode']))

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
                target = self.get_call_target(op, vm)
                
                if target:
                    iat_entry = self.get_iat_entry(target)

                    if iat_entry:
                        name = iat_entry['name']
                        n_args = self.winapi.get_n_args(name)
                        
                        
                        if n_args:
                            args = self.get_args(n_args, vm)
                            # print '{0} ({1})'.format(name, ', '.join(args))

                            if DB_ENABLED:
                                api_entry = {
                                    'api_id': self.db.add_api({'name': name}),
                                    'arguments': simplejson.dumps(args)
                                }
                                seq_id = self.db.add_call(api_entry)
                                call_seq.append(seq_id)
                # we need to set some dummy return value to eax
                vm.set_reg('eax', z3.BitVec('ret', 32))
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
            self.print_max_path_error_info(f)
            
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
        logging.info(self.exe_path)
        # if self.__skip:
        #     logging.info("Skipping...")
        #     self.db.close()
        #     return
        
        logging.debug('RUNNING EMULATOR')


        # f = self.exe.functions[0x42615d9]
        # self.process_function(f)

        # print 'Exit blocks:'
        # for addr in f.exit_blocks:
        #     print hex(addr)

        if self.exe.functions:
        
            for addr, f in self.exe.functions.iteritems():
                logging.info(hex(addr))
                self.process_function(f)

            self.db.commit()
            
        self.db.close()
        
                
    def print_max_path_error_info(self, f):
        print
        print 'File:', self.exe_path
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
