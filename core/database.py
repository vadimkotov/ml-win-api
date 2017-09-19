import sqlite3

BATCH_SIZE = 1000

def dict_factory(cursor, row):
    d = {}
    for idx,col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

class Database:
    def __init__(self, filename):
        self.__conn = sqlite3.connect(filename)
        self.__conn.row_factory = dict_factory
        self.__cursor = self.__conn.cursor()
        
    def commit(self):
        self.__conn.commit()

    def close(self):
        self.__cursor.close()
        self.__conn.close()

    def create_tables(self):
        self.__cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
        path TEXT UNIQUE
        )""")

        self.__cursor.execute("""
        CREATE TABLE IF NOT EXISTS api (
        name TEXT
        )""")

        self.__cursor.execute("""
        CREATE TABLE IF NOT EXISTS calls (
        api_id INT,
        arguments TEXT
        )""")
        
        self.__cursor.execute("""
        CREATE TABLE IF NOT EXISTS sequences (
        file_id INT,
        function_offset INT,
        sequence TEXT
        )""")
        
        self.commit()

    def add_dict(self, dict_, table):
        keys = ', '.join(dict_.keys())
        keyrefs = ', '.join(map(lambda k: ':' + k, dict_.keys()))
        
        sql_str = """
        INSERT OR IGNORE INTO 
        {0} ({1})
        VALUES ({2})
        """.format(table, keys, keyrefs)
        
        self.__cursor.execute(sql_str, dict_)
        # self.commit()
        return self.__cursor.lastrowid

    def check_entry(self, table, dict_):
        sql_str = """
        SELECT rowid FROM {0} 
        WHERE
        """.format(table)
        
        res = []
        for col, val in dict_.iteritems():
            res.append("{0} = '{1}'".format(col, val))

        sql_str += ' AND '.join(res)
        # print sql_str
        self.__cursor.execute(sql_str)
        res = self.__cursor.fetchone()
        if res:
            return res['rowid']

    def __add_obj(self, obj_, table):
        res = self.check_entry(table, obj_)
        if not res:
            return self.add_dict(obj_, table)
        return res

    def file_exists(self, file_info):
        return self.check_entry('files', file_info)
    
    def add_file(self, file_info):
        return self.add_dict(file_info, 'files')
        

    def add_api(self, api_info):
        return self.__add_obj(api_info, 'api')
        
    def add_call(self, call_info):
        # res = self.check_entry('calls', call_info)
        # if not res:
        #     return self.add_dict(call_info, 'calls')
        # return res
        return self.__add_obj(call_info, 'calls')
    
    def add_sequence(self, seq_info):
        # res = self.check_entry('sequences', seq_info)
        # if not res:
        #     return self.add_dict(seq_info, 'sequences')
        # return res
        return self.__add_obj(seq_info, 'sequences')

    def query(self, sql_query):
        self.__cursor.execute(sql_query)
        return self.__cursor.fetchall()

    def __generator(self, query):
        self.__cursor.execute(query)
        while True:
            res = self.__cursor.fetchmany(BATCH_SIZE)
            if not res:
                break

            for row in res:
                yield row    
        
    def sequence_generator(self):
        return self.__generator("SELECT * FROM sequences")

    def call_generator(self):
        return self.__generator("""
        SELECT 
        api.name, calls.arguments 
        FROM calls, api 
        WHERE api.rowid = calls.api_id
        """)

