import mysql.connector
import collections
from . import readconfig
from ..models import path


class SqlExcute:
    def __init__(self, db_connector):
        self.db_info = readconfig.readConfigFile(path + 'mysql_config.cfg',
                                                 db_connector)[db_connector]
        self.cnx = mysql.connector.connect(connection_timeout=20, **self.db_info)
        self.cursor = self.cnx.cursor(buffered=True)
        print("connected")

    def cursor_excute(self, sql_mission, sql_data, sql_join=''):
        if not sql_join:
            sql_join = ''
        sql_cmd = readconfig.readConfigFile(path + 'sql.cfg',
                                            sql_mission)[sql_mission]
        print(sql_cmd)
        print(type(sql_join), sql_join)
        sql_cmd['query'] += sql_join
        print(sql_cmd)
        self.cursor.execute(sql_cmd['query'], sql_data)
        return self.cursor

    def print_result(self):
        for line in self.cursor:
            for value in line:
                print(value, end='')
                print(' ', end='')
            print()

    def cursor_close(self):
        self.cursor.close()

    def connect_close(self):
        self.cnx.close()


if __name__ == '__main__':
    # for self test
    dict_user = {}
    data = {}
    t = SqlExcute('172.16.1.200_api')
    t.cursor_excute('user_account', data)
    sql_result = t.cursor

    for line in sql_result:
        if line[4] == 1:
            if line[1] in dict_user.keys():
                dict_user[line[1]]['sent'] += line[7]
            else:
                dict_user[line[1]] = {}
                dict_user[line[1]] = collections.defaultdict(int)
                dict_user[line[1]]['sent'] += line[7]

    for usernumber in dict_user:
        print(usernumber, dict_user[usernumber]['sent'])

    t.cursor_close()
    t.connect_close()