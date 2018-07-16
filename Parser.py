import mysql.connector
from mysql.connector import errorcode
import time

user = 'root'
password = 'P@ssw0rd'
host = '10.0.0.16'
database = 'siem'

#Firewall log file parser
# 1
def logtodic(line):
    line_dic={}
    line_s=line.split(" ")
    line_dic["SRC_IP"]=line_s[2]
    line_dic["ACTION"]=line_s[5]
    line_dic["DATE"] =line_s[0]+" "+line_s[1]
    line_dic["DST_IP"] =line_s[3]
    line_dic["PORT"] =line_s[4]
    return line_dic
#2
def PortToProtocol(port):
    PORTS = {'21': 'FTP', '22': 'SSH', '23': 'TELNET', '25': 'SMTP', '67': 'DHCP', '53': 'DNS', '80': 'HTTP', '445': 'SMB', '443': 'HTTPS'}
    if port in PORTS:
        return PORTS[port]
    else:
        return "UNKNOWN"
#3
def AddProtocol(dic):
    protocol=PortToProtocol(dic["PORT"])
    dic["PROTOCOL"]=protocol
    return dic

#DB Check Connection
def ConnectToDB():
    try:
        cnx = mysql.connector.connect(user=user, password=password,
                                      host=host, database=database)
        return cnx, cnx.cursor(buffered=True)
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("Something is wrong with your user name or password")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("Database does not exist")
        else:
            print(err)
        return None


def LogToDB(path,cnx,cursor):
    with open (path,'r') as opened_file:
        while True:
            line=opened_file.readline()
            if line:
                dic_line=AddProtocol(logtodic(line))
                InsertToDB(dic_line,cnx,cursor)
            else:
                time.sleep(0.1)

#Insert to DB
def InsertToDB(line, cnx, cursor):
    add_log =("""INSERT INTO fwlogs
                (ID, date, SRC_IP, DST_IP, PORT, PROTOCOL, ACTION)
                VALUES (NULL, %(DATE)s, %(SRC_IP)s, %(DST_IP)s, %(PORT)s, %(PROTOCOL)s, %(ACTION)s)""")
    cursor.execute(add_log, line)
    cnx.commit()



def main():
    cnx, cursor = ConnectToDB()
    query = ("SELECT * FROM fwlogs")
    cursor.execute(query)
    LogToDB("log_file.txt",cnx,cursor)
    cursor.close()
    cnx.close()
if __name__ == '__main__':
    main()