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

import subprocess, numpy, datetime,json,logging, traceback
import copy
import sys, glob, pickle, os, time
sys.path.append('testHypothesis')
import testHypothesis as TH

DEBUG = 0
# elogger = logging.getLogger('errorLogger')

# def convertDate(date):
#     '''
#     converts '%Y-%b-%d-%H-%M-%S' to '%Y-%m-%d %H:%M:%S'
#     '''
#
#     date = datetime.datetime.strptime(date, "%Y-%b-%d-%H-%M-%S")
#     date = date.strftime('%Y-%m-%d %H:%M:%S')
#     return date

class ResultObj(object):
    def __init__(self, userID, historyCount, testID, replayName, extraString, date=None):
        self.userID             = str(userID)
        self.historyCount       = int(historyCount)
        self.testID             = int(testID)
        self.replayName         = replayName
        self.extraString        = extraString
        self.xput_avg_original  = -1
        self.xput_avg_test    = -1
        self.area_test        = -1
        self.ks2_ratio_test   = -1
        self.ks2dVal          = -1
        self.ks2pVal          = -1
        if not date:
            self.date = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        else:
            self.date = date
    
    def tuplify(self):
        dTuple = str(tuple(map(str, [self.userID, self.historyCount, self.testID, self.extraString, self.date, self.replayName,
                                     self.xput_avg_original, self.xput_avg_test,
                                     self.area_test, self.ks2_ratio_test, self.ks2dVal, self.ks2pVal])))
        return dTuple

def finalAnalyzer(userID, historyCount, testID, path, xputBuckets, alpha, side='Client'):
    replayInfodir = path + '/' + userID + '/replayInfo/'
    regexOriginal = '*_' + str(historyCount) + '_' + str(0) + '.json'
    replayOriginal = glob.glob(replayInfodir + regexOriginal)
    replayInfo = json.load(open(replayOriginal[0], 'r'))

    realID = replayInfo[2]
    replayName = replayInfo[4]
    extraString = replayInfo[5]
    incomingTime = replayInfo[0]


    if side == 'Client':
        folder          = path + '/' + userID + '/clientXputs/'
        regexOriginal   = '*_' + str(historyCount) + '_' + str(0) + '.json'
        regexRandom    = '*_' + str(historyCount) + '_' + str(testID) + '.json'
        fileOriginal    = glob.glob(folder+regexOriginal)
        fileRandom     = glob.glob(folder+regexRandom)
        try:
            (xputO, durO) = json.load(open(fileOriginal[0], 'r'))
            (xputR, durR) = json.load(open(fileRandom[0], 'r'))
        except Exception as e:
            # elogger.error('FAIL at loading the client xputs', e)
            print 'FAIL at loading client side throughputs', e
            return None
    # Do server side analysis
    # After the analysis is done, scp the pcap file back to achtung immediately
    # KNOWN ISSUE: sometimes the pcap file does not get scp/rm
    # --- Temporal Solution: run dataCleaning.py periodically on the server to backup data as well as pcaps that are left on the replay servers
    else:
        try:
            dumpDir          = path + '/' + userID + '/tcpdumpsResults/'
            regexRandom     = '*_' + str(historyCount) + '_' + str(testID) + '*.pcap'
            regexOriginal   = '*_' + str(historyCount) + '_' + str(0) + '*.pcap'
            fileRandom      = glob.glob(dumpDir + regexRandom)
            fileOriginal    = glob.glob(dumpDir + regexOriginal)
            (xputO, durO) = TH.adjustedXput(fileOriginal[0], xputBuckets)
            (xputR, durR) = TH.adjustedXput(fileRandom[0], xputBuckets)
        except Exception as e:
            traceback.print_exc(file=sys.stdout)
            print 'FAIL at loading server side throughputs', e
            return None

    try:
       resultFile = (path + '/' + userID + '/decisions/'+'results_{}_{}_{}_{}.json').format(userID, side, historyCount, testID)
       xputO = [x for x in xputO if x > 0]
       xputR = [x for x in xputR if x > 0]
       # Only use none-zero throughputs for test
       forPlot, results        = testIt(xputO, xputR, resultFile, alpha)
    except Exception as e:
        # elogger.error('FAIL at testing the result for '.format(userID, historyCount, testID))
        print 'FAIL at loading result', e
        return None

    resultObj = ResultObj(realID, historyCount, testID, replayName, extraString, incomingTime)

    resultObj.area_test      = results['areaTest']
    resultObj.ks2_ratio_test = results['ks2ratio']
    resultObj.xput_avg_original = results['xputAvg1']
    resultObj.xput_avg_test   = results['xputAvg2']
    resultObj.ks2dVal = results['ks2dVal']
    resultObj.ks2pVal   = results['ks2pVal']


    return resultObj

def testIt(xputO, xputR, resultFile, alpha, doRTT=True):
    forPlot         = {}

    if os.path.isfile(resultFile):
        results = json.load(open(resultFile, 'r'))
    else:
        # print '\r\n CREATING RESULT FILE',resultFile
        results = TH.doTests(xputO, xputR, alpha)
        # print '\r\n RESULTS FROM DOTESTS',results
        json.dump(results, open(resultFile, 'w'))

    forPlot['Original'] = xputO
    forPlot['Random'] = xputR


    areaTest = results[0]
    ks2ratio = results[1]
    xputAvg1 = results[4][2]
    xputAvg2 = results[5][2]
    ks2dVal = results[9]
    ks2pVal = results[10]
    return forPlot, {'areaTest':areaTest, 'ks2ratio':ks2ratio, 'xputAvg1':xputAvg1, 
                     'xputAvg2':xputAvg2, 'ks2dVal':ks2dVal, 'ks2pVal':ks2pVal}

            
def parseTsharkTransferOutput(output):
    '''
    ************ WORKS WITH tshark 1.12.1 ONLY ************
    '''
    x = []
    y = []
    lines       = output.splitlines()
    
    total = 0
    
    for l in lines:
        if '<>' not in l:
            continue
        
        l      = l.replace('|', '')
        l      = l.replace('<>', '')
        parsed = map(float, l.split())
        end    = parsed[1]
        bytes  = parsed[-1]
        
        total += bytes 
        
        x.append(end)
        y.append(total)
        
    #converting to Mbits/sec
    y = map(lambda z: z/1000000.0, y)
    
    return x, y 
