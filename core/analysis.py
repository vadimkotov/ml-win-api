import sys
import re
import networkx as nx
import random


class FunctionAnalysisError(Exception):pass
class Function:
    def __init__(self, offset, name, ops):
        if not ops:
            raise FunctionAnalysisError("Error analyzing function")

        for op in ops:
            if op['type'] == 'invalid':
                raise FunctionAnalysisError("Function starts with invalid instruction")

        self.offset = offset
        self.name = name
        self.ops = ops
        self.end = ops[-1].get('offset')
        
        self.cfg = nx.DiGraph()
        self.addr_map = {}
        self.blocks = {}
        self.exit_blocks = []

        self.n_edges = 0
        self.analyze()

        self.jmp_to_iat = None
        self.sym_info = self.__check_if_iat()

        
        
    def __check_if_iat(self):
        st = SYM_IMP_REGEX.match(self.name)
        if st:
            return  {
                'lib': st.group('lib'),
                'name': st.group('name')
            }

    def __inside(self, addr):
        return addr >= self.offset and addr <= self.end
        
    def add_node(self, address):        
        if address not in self.cfg.nodes():
            # logging.debug('Adding node: 0x%x' % address)
            self.cfg.add_node(address)
            self.blocks[address] = []

    def add_edge(self, from_, to_):
        # logging.debug('Adding edge: 0x%x -> 0x%x' % (from_, to_))
        self.n_edges += 1
        self.cfg.add_edge(from_, to_)


    def analyze(self):
        last_op_n = len(self.ops) - 1
        for i in xrange(len(self.ops)):
            op = self.ops[i]
            offset = op['offset']
            
            if i == last_op_n:
                op['next_addr'] = None
            else:
                op['next_addr'] = self.ops[i+1].get('offset')

            self.addr_map[offset] = op
            # Adding information about next address
            self.ops[i] = op

            # Identifying nodes
            if op['type'] in ['cjmp', 'jmp']:
                jmp_target = op.get('jump')
                if jmp_target: 
                    self.add_node(jmp_target)
                if 'fail' in op:
                    self.add_node(op['fail'])

        self.__visited = []
        start_addr = self.offset

        self.add_node(start_addr)
        self.traverse(start_addr)

        # Check for tail calls
        if not self.exit_blocks:
            if self.ops[-1].get('type') == 'jmp':
                self.exit_blocks.append(sorted(self.blocks.keys())[-1])

        # Some functions may share bytes and it can result in unreacheable
        # nodes, let's get rid of unreacheable nodes
        #
        for node, degree in self.cfg.degree(self.cfg.nodes()).iteritems():
            if node != self.offset and degree == 0:
                self.cfg.remove_node(node)
            

    def traverse(self, start_):
        if start_ in self.__visited:
            return
        self.__visited.append(start_)

        
        def new_edge_and_traverse(from_, to_):
            # print '0x%x -> 0x%x' % (from_, to_)
            # self.add_node(to_)
            self.add_edge(from_, to_)
            self.traverse(to_)

        # def is_valid_target(addr):
        #     return addr >= self.offset and addr <= self.end
        
        # print hex(start_)
        addr = start_
        while True:
            if addr not in self.addr_map:
                if addr:
                    msg = "0x%x is not in addr_map. Bad disassembly?" % addr
                else:
                    msg = 'address is None. Bad disassembly?'                    
                raise FunctionAnalysisError(msg)
                
            op = self.addr_map[addr]
            
            self.blocks[start_].append(addr)
            if op['type'] == 'ret':
                self.exit_blocks.append(start_)
                return
                
            if op['type'] in ['cjmp', 'jmp']:
                jmp_target = op.get('jump')
                if jmp_target: #and is_valid_target(jmp_target):
                    new_edge_and_traverse(start_, jmp_target)
                if 'fail' in op:
                    # if is_valid_target(op['fail']):
                    new_edge_and_traverse(start_, op['fail'])
                return

            addr = op['next_addr']
            if addr in self.blocks:
                 # self.add_edge(start_, addr)
                 new_edge_and_traverse(start_, addr)
                 return
        
    
    def get_longest_path(self):
        if len(self.cfg.nodes()) == 1:
            return [self.offset]
        
        longest_len = 0
        longest_path = None
        
        for addr in self.exit_blocks:
            for path in nx.all_simple_paths(self.cfg, self.offset, addr):
                if len(path) >= longest_len:
                    longest_len = len(path)
                    longest_path = path
                    
        return longest_path

    def get_longest_path_random_walk(self):
        if len(self.cfg.nodes()) == 1:
            return [self.offset]
        
        longest_len = 0
        longest_path = None
        
        for i in xrange(30):
            path = self.random_walk()
            if len(path) >= longest_len:
                longest_len = len(path)
                longest_path = path
        return longest_path
            
    def get_paths(self):
        paths = []
        for addr in self.exit_blocks:
            paths.extend(nx.all_simple_paths(self.cfg, self.offset, addr))

        if not paths:
            paths = [[self.offset]]            
        return paths

    # TODO: ignore loops!
    def random_walk(self):
        path = [self.offset]
        block = self.offset

        while True:
            block_addr_list = self.blocks.get(block)
            if not block_addr_list:
                return
            op_addr = block_addr_list[-1]
            op = self.addr_map[op_addr]
            if op['type'] == 'jmp':
                target = op['jump']
            elif op['type'] == 'cjmp':
                target = random.choice([op.get('jump'), op.get('fail')])
            else:
                target = op['next_addr']#self.next_addr(op_addr)

            path.append(target)
            block = target
            
            if target in self.exit_blocks:
                break

        return path

    """
    def next_addr(self, addr):
        all_ = sorted(self.addr_map.keys())
        idx = all_.index(addr) + 1
        if idx >= len(all_):
            return None
        return all_[idx]
    """

SYM_IMP_REGEX = re.compile(r'sym\.imp\.(?P<lib>.+?)_(?P<name>.+)')
# IMPORT_REGEX = re.compile(r'(?P<lib>.+?)_(?P<name>.+)')
IMPORT_REGEX = re.compile(r'(?P<lib>.+?\.(?:dll|drv|exe|sys|cpl))_(?P<name>.+)', re.I)

class Executable:
    def __init__(self, r2):
        self.r2 = r2
        self.file_info = r2.get_file_info()
        self.entry_point = r2.get_entry_point()
        self.import_table = self.init_import_table()
        self.functions = self.init_functions()

    def init_import_table(self):
        import_table = {}
        for imp in self.r2.get_import_table():
            ir = IMPORT_REGEX.match(imp['name'])
            import_table[imp.get('plt')] = {
                'lib': ir.group('lib'),
                'name': ir.group('name')
            }
        return import_table
            
    def is_jmp_to_iat(self, ops):
        if len(ops) == 1:
            op = ops[0]
            
            if  op.get('type') == 'jmp' and\
                op.get('ptr') in self.import_table:
                return self.import_table[op.get('ptr')]
        
    def init_functions(self):
        functions = {}
        r2_func_list = self.r2.get_functions()
        # func_addresses = [f['offset'] for f in r2_func_list]
        
        for i in xrange(len(r2_func_list)):
            f = r2_func_list[i]
            if f['offset'] in self.import_table:
                continue

            func_size = f['size']
            # Let's skip ridiculous functions for now
            if func_size > 10000:
                continue

            ops = self.r2.get_disassembly(f['offset'], func_size)

            try:
                function_ = Function(f['offset'], f['name'], ops)
            except FunctionAnalysisError as e:
                # logging.error(e)
                print str(e)
                continue
                
            function_.jmp_to_iat = self.is_jmp_to_iat(ops)
            functions[f.get('offset')] = function_
        return functions












