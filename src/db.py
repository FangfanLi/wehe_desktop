'''
#######################################################################################################
#######################################################################################################
Copyright 2018 Northeastern University

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

#######################################################################################################
#######################################################################################################
'''

import MySQLdb, MySQLdb.cursors
import datetime, json, time
from python_lib import Singleton
from python_lib import Configs
import traceback

class DB(object):
    __metaclass__ = Singleton
    
    def __init__(self):
        
        self.dbLocation = Configs().get('dbLocation')
        
        if self.dbLocation == 'local':
            self.host   = 'localhost'
            self.user   = 'root'
            self.pw     = 'password'
            self.dbName = 'yourdatabase'
        
        self._connect()

    def _connect(self):
        self.conn = MySQLdb.connect(self.host, self.user, self.pw, self.dbName, 
                                    cursorclass=MySQLdb.cursors.DictCursor, 
                                    local_infile = 1,connect_timeout = 2,)
        self.cursor = self.conn.cursor()

    def execute_wrapper(self, query):
        attempts = 0
        while attempts < 3:
            try:
                return self.execute(query)
            except Exception as e:
                code = e.args[0]
                if attempts == 2 or code != 2013:
                    raise e
                attempts += 1
                time.sleep(0.2 * attempts)

    def execute(self, query):
        #The following ping reconnects if connection has timed out 
        #(i.e. idle for more than wait_timeout which is a system variable of MySQL)
        self.conn.ping(True)
        time.sleep(1)
        # with open('SQL_LOG.txt','a') as sl:
        #     sl.writelines('\n' + query)
        self.cursor.execute(query)
        self.conn.commit()

    # (userID,historyCount,testID) should be the Primary Key in the table
    def insertResult(self, resObj, table= 'testResults', updateOnDup=True):
        columns = '(userID, historyCount, testID, extraString, date, replayName, xput_avg_original, xput_avg_test, area_test, ks2_ratio_test, ks2dVal, ks2pVal)'
        
        if updateOnDup:
            onDup = 'ON DUPLICATE KEY UPDATE area_test={}, ks2_ratio_test={}, xput_avg_original={}, xput_avg_test={}'.format(resObj.area_test, resObj.ks2_ratio_test, resObj.xput_avg_original, resObj.xput_avg_test)
        else:
            onDup = ''

        query   = ' '.join(['INSERT INTO', table, columns, 'VALUES', resObj.tuplify(), onDup, ';'])
        
        try:
            self.execute_wrapper(query)
        except Exception as e:
            print 'Exception in insertResult:', e
    
    def insertReplay(self, to_write, instanceID, table='testReplays'):
        tmp          = to_write.split('\t')
        incomingTime = str(datetime.datetime.strptime(tmp[0], "%Y-%m-%d %H:%M:%S"))
        # Get rid of the timestamps of the replayName
        if tmp[4] == 'AmazonAug8':
            tmp[4] = 'Amazon-Aug8'
        elif tmp[4] == 'AmazonAug8Random':
            tmp[4] = 'AmazonRandom-Aug8'
        elif tmp[4] == 'NetflixSep22':
            tmp[4] = 'Netflix-Sep22'
        elif tmp[4] == 'NetflixSep22Random':
            tmp[4] = 'NetflixRandom-Sep22'
        toInsert     = [incomingTime] + tmp[1:9]
        exceptions   = tmp[8]
        
        if exceptions in ['NoPermission', 'UnknownReplayName']:
            columns = '(instanceID, incomingTime, userID, id, clientIP, replayName, extraString, historyCount, testID, exceptions)'
        
        else:
            # toInsert += tmp[9:14]
             
            try:
                mobileStats = json.loads(tmp[14])
            except Exception as e:
                mobileStats = None
             
            if mobileStats is not None:
                # Get the country name via lat,lon

                lat = str(mobileStats['locationInfo']['latitude'])
                lon = str(mobileStats['locationInfo']['longitude'])
                if lat != '0.0' and lon != '0.0' and lat != 'nil':
                    country = mobileStats['locationInfo']['geoinfo']['country']
                    toInsert += map(str,
                                [mobileStats['locationInfo']['latitude'],
                                 mobileStats['locationInfo']['longitude'],
                                 country,
                                 mobileStats['carrierName'],
                                 mobileStats['cellInfo'],
                                 mobileStats['networkType'],
                                 mobileStats['model'],
                                 mobileStats['os']['RELEASE'],
                                 mobileStats['os']['SDK_INT'],
                                 mobileStats['os']['INCREMENTAL'],
                                 mobileStats['manufacturer'],
                                 ])
                    columns = '(instanceID, incomingTime, userID, id, clientIP, replayName, extraString, historyCount, testID, exceptions, lat, lon, country, carrierName, cellInfo, networkType, model, rel, sdkInt, incremental, manufacturer)'
                else:
                    toInsert += map(str,
                                [mobileStats['locationInfo']['latitude'],
                                 mobileStats['locationInfo']['longitude'],
                                 mobileStats['carrierName'],
                                 mobileStats['cellInfo'],
                                 mobileStats['networkType'],
                                 mobileStats['model'],
                                 mobileStats['os']['RELEASE'],
                                 mobileStats['os']['SDK_INT'],
                                 mobileStats['os']['INCREMENTAL'],
                                 mobileStats['manufacturer'],
                                 ])
                    columns = '(instanceID, incomingTime, userID, id, clientIP, replayName, extraString, historyCount, testID, exceptions, lat, lon, carrierName, cellInfo, networkType, model, rel, sdkInt, incremental, manufacturer)'

            else:
                columns = '(instanceID, incomingTime, userID, id, clientIP, replayName, extraString, historyCount, testID, exceptions)'
        
        toInsert = [instanceID] + toInsert
        
        query = ' '.join(['INSERT INTO', table, columns, 'VALUES', str(tuple(toInsert)), ';'])


        try:
            self.execute_wrapper(query)
            return True
        except Exception as e:
            print 'Exception in insertReplays:', e
            return (e, query)
            # with open('SQL_EXC.txt','a') as sl:
            #     sl.writelines('\n' + str(e) + ':\n' + query)

    #  (userID,historyCount,testID) as Primary Key, should uniquely identify a replay
    def getSingleResult(self, userID, historyCount, testID, table = 'testResults'):
        query = "SELECT * FROM " + table + " WHERE userID='{}' ".format(userID)

        query += 'AND historyCount = {} AND testID = {}'.format(historyCount, testID)
        try:
            self.execute_wrapper(query)
            results = self.cursor.fetchall()
        except Exception as e:
            print '\r\n ERROR in getting result', e
            results = ()
        return results

    def getCurrTest(self, userID, replayName, carrierName, table = 'currDPITests'):
        query = "SELECT * FROM " + table + " WHERE userID = '{}' AND replayName = '{}' AND carrierName = '{}';".format(userID, replayName, carrierName)
        try:
            self.execute_wrapper(query)
            results = self.cursor.fetchall()
        except Exception as e:
            traceback.print_exc()
            print '\r\n ERROR in getCurrTest', e
            results = None
        return results

    def insertCurrTest(self, userID, replayName, carrierName, timestamp, currTestPacket, currTestLeft, currTestRight, numTests, numTestedPackets, BAque_id, mr_id, table = 'currDPITests'):
        columns = '(userID, carrierName, replayName, timestamp, currTestPacket, currTestLeft, currTestRight, numTests, numTestedPackets, BAque_id, mr_id)'
        toInsert = (userID, carrierName, replayName, timestamp, currTestPacket, int(currTestLeft), int(currTestRight), int(numTests), int(numTestedPackets), int(BAque_id), int(mr_id))
        query = ' '.join(['INSERT INTO', table, columns, 'VALUES', str(toInsert), ';'])

        try:
            self.execute_wrapper(query)
            return True
        except Exception as e:
            traceback.print_exc()
            print 'Exception in insertCurrTest:', e
            return (e, query)

    def delCurrTest(self, userID, replayName, carrierName, table = 'currDPITests'):
        query = ' '.join(['DELETE FROM', table, "WHERE userID='{}' AND replayName = '{}' AND carrierName = '{}' ;".format(userID, replayName, carrierName)])
        try:
            self.execute_wrapper(query)
            return True
        except Exception as e:
            traceback.print_exc()
            print 'Exception in delCurrTest:', e
            return (e, query)

    def updateCurrTest(self, userID, replayName, carrierName, timestamp, currTestPacket, currTestLeft, currTestRight,
                       numTests, numTestedPackets, table='currDPITests'):
        query = ' '.join(["UPDATE ", table,
                          "SET timestamp = '{}', currTestPacket = '{}', currTestLeft = {}, currTestRight = {}, numTests = {}, numTestedPackets = {} "
                                            "WHERE userID = '{}' AND carrierName = '{}' AND replayName = '{}';".format(
                              timestamp, currTestPacket, int(currTestLeft), int(currTestRight), int(numTests), int(numTestedPackets), userID, carrierName, replayName)])
        try:
            self.execute_wrapper(query)
            return True
        except Exception as e:
            traceback.print_exc()
            print 'Exception in updateCurrTest:', e
            return (e, query)

    def insertBAque(self, BAque_id, testPacket, testLeft, testRight, table = 'testQueues'):
        print '\r\n DB BAQUE'
        columns = '(testq_id, testPacket, testLeft, testRight)'
        toInsert = (int(BAque_id), testPacket, int(testLeft), int(testRight))
        query = ' '.join(['INSERT INTO', table, columns, 'VALUES', str(toInsert), ';'])

        print '\r\n INSERT BAQUE', query

        try:
            self.execute_wrapper(query)
            return True
        except Exception as e:
            traceback.print_exc()
            print 'Exception in insertBAque:', e
            return (e, query)

    def getTestBAque(self, BAque_id, table = 'testQueues'):
        query = "SELECT * FROM " + table + " WHERE testq_id = {} LIMIT 1;".format(int(BAque_id))
        print '\r\n DB GET NEXT BAQUE',query
        try:
            self.execute_wrapper(query)
            results = self.cursor.fetchall()
        except Exception as e:
            traceback.print_exc()
            print '\r\n ERROR in getTestBAque', e
            results = None
        return results

    def delTestBAque(self, uniqtest_id, table = 'testQueues'):
        query = ' '.join(['DELETE FROM', table,
                          "WHERE uniqtest_id={};".format(uniqtest_id)])
        try:
            self.execute_wrapper(query)
            return True
        except Exception as e:
            traceback.print_exc()
            print 'Exception in delTestBAque:', e
            return (e, query)

    def insertRegion(self, mr_id, packetNum, byteNum, table = 'matchingRegion'):
        columns = '(mr_id, packetNum, byteNum)'
        toInsert = (int(mr_id), packetNum, int(byteNum))
        query = ' '.join(['INSERT INTO', table, columns, 'VALUES', str(toInsert), ';'])

        try:
            self.execute_wrapper(query)
            return True
        except Exception as e:
            traceback.print_exc()
            print 'Exception in insertRegion:', e
            return (e, query)

    def getMatchingRegion(self, mr_id, table = 'matchingRegion'):
        query = "SELECT * FROM " + table + " WHERE mr_id = {};".format(int(mr_id))
        try:
            self.execute_wrapper(query)
            results = self.cursor.fetchall()
        except Exception as e:
            traceback.print_exc()
            print '\r\n ERROR in getPreTest', e
            results = None
        return results


    def getPreTest(self, userID, replayName, carrierName, table = 'preDPITests'):
        query = "SELECT * FROM " + table + " WHERE userID = '{}' AND replayName = '{}' AND carrierName = '{}' ORDER BY timestamp DESC LIMIT 1;".format(userID, replayName, carrierName)
        try:
            self.execute_wrapper(query)
            results = self.cursor.fetchall()
        except Exception as e:
            traceback.print_exc()
            print '\r\n ERROR in getPreTest', e
            results = None
        return results


    def insertPreTest(self, userID, replayName, carrierName, timestamp, numTests, matchingContent, mr_id, table = 'preDPITests'):
        columns = '(userID, replayName, carrierName, timestamp, numTests, matchingContent, mr_id)'
        toInsert = (userID, replayName, carrierName, timestamp, int(numTests), matchingContent, int(mr_id))
        query = ' '.join(['INSERT INTO', table, columns, 'VALUES', str(toInsert), ';'])

        try:
            self.execute_wrapper(query)
            return True
        except Exception as e:
            traceback.print_exc()
            print 'Exception in insertPreTest:', e
            return (e, query)


    def insertRawTest(self, userID, replayName, carrierName, timestamp, testedPacket, testedLeft, testedRight, historyCount, testID, diffDetected, table = 'rawDPITests'):
        columns = '(userID, replayName, carrierName, timestamp, testedPacket, testedLeft, testedRight, historyCount, testID, diffDetected)'
        toInsert = (userID, replayName, carrierName, timestamp, testedPacket, int(testedLeft), int(testedRight), int(historyCount), int(testID), diffDetected)
        query = ' '.join(['INSERT INTO', table, columns, 'VALUES', str(toInsert), ';'])


        try:
            self.execute_wrapper(query)
            return True
        except Exception as e:
            traceback.print_exc()
            print 'Exception in insertRaw:', e
            return (e, query)

    def close(self):
        self.conn.close()
    
def main():
    db = DB()


if __name__=="__main__":
    main()
