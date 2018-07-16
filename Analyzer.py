import datetime
import mysql.connector
import  time

user = 'root'
password = 'P@ssw0rd'
host = '10.0.0.16'
database = 'siem'

def Specific_Port(cnx,cursor):
    query=("""SELECT SRC_IP FROM fwlogs WHERE PORT=444 OR PORT=4445""")
    cursor.execute(query)
    cnx.commit()
    result=cursor.fetchall()
    lst_ip=set(result)
    if len(result)>1:
        return '{} {} {}'.format('Alert',lst_ip,'tried to connect to 444 and/or 4445')



def PortScan(cnx,cursor):
     query = ("""SELECT DISTINCT SRC_IP,DST_IP,PORT FROM fwlogs""")
     cursor.execute(query)
     cnx.commit()
     result = cursor.fetchall()
     ips_dic={}
     for line in result:
         src_dst=line[0]+ " " +line[1]
         if src_dst in ips_dic:
             ips_dic[src_dst] +=1
         else:
             ips_dic[src_dst]=1
     alerts=""
     for key,value in ips_dic.iteritems():
         if value >=10:
             alerts+="{} {} {} {} {}\n".format('Alert:' ,key.split()[0] ,'did port scan',value, 'time')
     return alerts

def PingSweep(cnx,cursor):
    query = ("""SELECT DISTINCT SRC_IP,DST_IP FROM fwlogs WHERE PORT=0""")
    cursor.execute(query)
    cnx.commit()
    result = cursor.fetchall()
    ip_dic={}
    for line in result:
        if line[0] in ip_dic:
            ip_dic[line[0]]+=1
        else:
            ip_dic[line[0]]=1
    alerts=" "
    for key,value in ip_dic.iteritems():
        if value>=10:
            alerts+= "{} {} {} {} {}\n".format('Alert:' ,key ,'did ping sweep',value, 'time')


def PingSweep_Time(cnx,cursor):
    query = ("""SELECT DISTINCT SRC_IP,DST_IP,DATE FROM fwlogs WHERE PORT=0""")
    cursor.execute(query)
    cnx.commit()
    result = cursor.fetchall()
    ip_dic = {}
    date_dic={}
    for line in result:
        if line[0] in ip_dic:
            #ip_dic[line[0]] += 1
            date_dic[line[0]].append(line[2])
        else:
            #ip_dic[line[0]] = 1
            date_dic[line[0]]=[line[2]]
    alerts=" "
    for key, value in date_dic.iteritems():
        if len(value) >= 10:
            #for key1,value1 in date_dic.iteritems():
                #if key==key1:
                    date=GetTimeDiffreneces(value[0],value[9])
                    if date[1] <=10:
                        alerts += "{} {} {} {} {}\n".format('Alert:', key, 'did ping sweep', value, 'time')


def GetTimeDiffreneces(start,end):
    c=end-start
    return divmod(c.days * 86400+c.seconds, 60)

def main():
    old_alerts=set()
    cnx = mysql.connector.connect(user=user, password=password, host=host, database=database)
    cursor = cnx.cursor(buffered=True)
    while True:
        new_alerts=set()
        new_alerts.add(Specific_Port(cnx, cursor))
        new_alerts.add(PortScan(cnx, cursor))
        new_alerts.add(PingSweep(cnx, cursor))
        new_alerts.add(PingSweep_Time(cnx, cursor))
        for alert in new_alerts.difference(old_alerts):
            print alert
        old_alerts=old_alerts.union(new_alerts)
        time.sleep(5)

if __name__ == '__main__':
    main()