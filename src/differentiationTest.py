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

import pickle, replay_client, urllib2, urllib
from python_lib import *

'''
This is the main script for Classifiers Unclassified
1. Run original replay
2. Run random/bit inverted replay
3. If differentation detected, perform binary search to identify the matching rule
'''


logger = logging.getLogger('classifierUnclassified')
formatter = logging.Formatter('%(asctime)s--%(levelname)s\t%(message)s', datefmt='%m/%d/%Y--%H:%M:%S')
handler = logging.handlers.TimedRotatingFileHandler('unclassify.log', backupCount=200, when="midnight")
# handler = logging.FileHandler('unclassify.log')
handler.setFormatter(formatter)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

class AnalyzerI(object):
    '''
    This class contains all the methods to interact with the analyzerServer
    '''
    def __init__(self, ip, port):
        self.path = ('http://'
                     + ip
                     + ':'
                     + str(port)
                     + '/Results')


    def ask4analysis(self, id, historyCount, testID):
        '''
        Send a POST request to tell analyzer server to analyze results for a (userID, historyCount)

        server will send back 'True' if it could successfully schedule the job. It will
        return 'False' otherwise.

        This is how and example request look like:
            method: POST
            url:    http://54.160.198.73:56565/Results
            data:   userID=KSiZr4RAqA&command=analyze&historyCount=9
        '''
        # testID specifies the test number in this series of tests
        # testID = 0 is the first replay in this series of tests, thus it is the baseline (original) to be compared with
        data = {'userID':id, 'command':'analyze', 'historyCount':historyCount, 'testID':testID}
        res = self.sendRequest('POST', data=data)
        return res

    def getSingleResult(self, id, historyCount, testID):
        '''
        Send a GET request to get result for a historyCount and testID

        This is how an example url looks like:
            method: GET
            http://54.160.198.73:56565/Results?userID=KSiZr4RAqA&command=singleResult&historyCount=9
        '''
        # testID specifies the test number in this series of tests
        data = {'userID':id, 'command':'singleResult', 'testID':testID}

        if isinstance(historyCount,int):
            data['historyCount'] = historyCount

        res = self.sendRequest('GET', data=data)
        return res

    def sendRequest(self, method, data=''):
        '''
        Sends a single request to analyzer server
        '''
        data = urllib.urlencode(data)

        if method.upper() == 'GET':
            req = urllib2.Request(self.path + '?' + data)

        elif method.upper() == 'POST':
            req  = urllib2.Request(self.path, data)

        res = urllib2.urlopen(req).read()
        print '\r\n RESULTS',res
        return json.loads(res)

def processResult(result):
    # Only if ks2ratio > ks2Beta (this is the confidence interval) the ks2 result is trusted, otherwise only the area test is used
    # Default suggestion: areaThreshold 0.1, ks2Beta 95%, ks2Threshold 0.05
    # KS2:
    # ks2Threshold is the threshold for p value in the KS2 test, if p greater than it, then we cannot
    # reject the hypothesis that the distributions of the two samples are the same
    # If ks2pvalue suggests rejection (i.e., p < ks2Threshold), where accept rate < (1 - ks2Beta), the two distributions are not the same (i.e., differentiation)
    # Else, the two distributions are the same, i.e., no differentiation
    # Area:
    # if area_test > areaThreshold, the two distributions are not the same (i.e., Differentiation)
    # Else, the two distributions are the same, i.e., no differentiation
    # Return result score, 0  : both suggests no differentiation
    #                      1  : inconclusive conclusion from two methods (Considered as no differentiation so far)
    #                      2  : both suggests differentiation
    #                      if target trace has less throughput, return negative value respectively, e.g., -1 means target trace is throttled
    #        result rate: differentiated rate = (normal - throttled)/throttled

    areaT = Configs().get('areaThreshold')
    ks2Beta  = Configs().get('ks2Beta')
    ks2T  = Configs().get('ks2Threshold')

    ks2Ratio = float(result['ks2_ratio_test'])
    ks2Result = float(result['ks2pVal'])
    areaResult = float(result['area_test'])

    # Trust the KS2 result:
    if ks2Ratio > ks2Beta:
        # 1. The CDFs have less than areaT difference in area test and 2.With confidence level ks2T that the two distributions are the same
        # Then there is no differentiation
        if (areaResult < areaT) and (ks2Result > ks2T):
            outres = 'NOT Different from Original replay'
        # 1. The CDFs have more than areaT difference in area test and 2.With confidence level ks2T that the two distributions are not the same
        # Then there is differentiation
        elif (areaResult > areaT) and (ks2Result < ks2T):
            outres = 'Different from Original replay'
            # rate = (result['xput_avg_test'] - result['xput_avg_original'])/min(result['xput_avg_original'], result['xput_avg_test'])
        # Else inconclusive, but consider as no diff
        else:
            outres = 'NOT Different from Original replay'
            PRINT_ACTION('##### INConclusive Result, area test is' + str(areaResult) + 'ks2 test is ' + str(ks2Result), 0)
            # rate = (result['xput_avg_test'] - result['xput_avg_original'])/min(result['xput_avg_original'], result['xput_avg_test'])
    # The KS2 result is not trusted
    else:
        if areaResult > areaT:
            outres = 'Different from Original replay'
        else:
            outres = 'NOT Different from Original replay'

    return outres

# This function would run replay client against the replay server for one time
# The tricky part is to get the classification result, the method now is to write into the 'Result.txt' file

def runReplay(pcapDir, pacmodify, analyzerI):

    classification = None

    cmpacNum = -1
    caction = None
    cspec = None
    smpacNum = -1
    saction = None
    sspec = None

    # Check whether modification needed for this replay
    Side, Num, Action, Mspec = pickle.loads(pacmodify)

    if Side == 'Client':
        cmpacNum = Num
        caction = Action
        cspec = Mspec
    elif Side == 'Server':
        smpacNum = Num
        saction = Action
        sspec = Mspec

    configs = Configs()
    testID = int(configs.get('testID'))
    configs.set('testID', str(testID + 1))

    try:
        replayResult = replay_client.run(configs = configs, pcapdir = pcapDir, cmpacNum = cmpacNum, caction = caction, cspec = cspec,
                          smpacNum = smpacNum, saction = saction, sspec = sspec, testID=configs.get('testID'), byExternal=True)
    except:
        print '\r\n Error when running replay'
        replayResult = None

    time.sleep(2)
    permaData = PermaData()
    try:
        PRINT_ACTION(str(analyzerI.ask4analysis(permaData.id, permaData.historyCount, configs.get('testID'))), 0 )
    except Exception as e:
        PRINT_ACTION('\n\n\n####### COULD NOT ASK FOR ANALYSIS!!!!! #######\n\n\n' + str(e),0)

    # ASK the replay analyzer for differentiation test

    ori_avg_xputs = 0
    ran_avg_xputs = 0
    # 3 trials for getting the result, 5 * i seconds for the server to process the result each time
    for i in xrange(3):
        time.sleep(5)
        PRINT_ACTION('Fetching analysis result from the analyzer server',0)
        res = analyzerI.getSingleResult(permaData.id, permaData.historyCount, configs.get('testID'))

        # Check whether results are successfully fetched


        if res['success'] == True:
            # Process result here
            classification = processResult(res['response'])
            ori_avg_xputs = res['response']['xput_avg_original']
            ran_avg_xputs = res['response']['xput_avg_test']
            break
        else:
            # Only use whether the replayResult as classification
            PRINT_ACTION('\r\n Failed at fetching result ' + res['error'], 0)
            classification = replayResult

    # Supplement YOUR OWN method to get the classification result here

    # OR Manually type what this traffic is classified as
    # classification = raw_input('Is it classified the same as original replay? "YES" or "NO"?')

    return classification, ori_avg_xputs, ran_avg_xputs


# Run a replay with the recorded trace in pcapDir
# return classification result
def Replay(pcapDir, pacmodify, AnalyzerI):
    # Repeat the experiment for 10 times, until getting a classification result, otherwise  exit
    classification = None
    needConfirm = True
    ori_avg_xputs = ran_avg_xputs = 0
    for i in xrange(10):
        classification, ori_avg_xputs, ran_avg_xputs = runReplay(pcapDir, pacmodify, AnalyzerI)
        time.sleep(10)
        if classification:
            if classification == 'Different from Original replay' and needConfirm:
                needConfirm = False
                continue
            elif classification == 'Different from Original replay':
                break
            else:
                break
        if i == 9:
            PRINT_ACTION("\r\n Can not get the classification result after the 10th trial, exiting", 0)
            sys.exit()

    return classification, ori_avg_xputs, ran_avg_xputs



def setUpConfig(configs):
    configs.set('ask4analysis'     , False)
    configs.set('analyzerPort'     , 56565)
    configs.set('testID', '-1')
    configs.set('areaThreshold', 0.1)
    configs.set('ks2Threshold', 0.05)
    configs.set('ks2Beta', 0.95)

    configs.read_args(sys.argv)
    return configs

def main(args):

    # All the configurations used
    configs = Configs()
    configs = setUpConfig(configs)

    if args == []:
        configs.read_args(sys.argv)
    else:
        configs.read_args(args)

    configs.check_for(['pcap_folder'])

    #The following does a DNS lookup and resolves server's IP address
    try:
        configs.get('serverInstanceIP')
    except KeyError:
        configs.check_for(['serverInstance'])
        configs.set('serverInstanceIP', Instance().getIP(configs.get('serverInstance')))

    pcapDir = configs.get('pcap_folder')

    if not pcapDir.endswith('/'):
        pcapDir= pcapDir + '/'

    replayName = pcapDir.split('/')[-2]
    mainDir = pcapDir.split(replayName)[0]

    permaData = PermaData()
    permaData.updateHistoryCount()
    analyzerI = AnalyzerI(configs.get('serverInstanceIP'), configs.get('analyzerPort'))

    # Check whether there is differentiation
    # No modification, get original Classification
    nomodify = pickle.dumps(('Client', -1, None, None))
    PRINT_ACTION('Start to replay Original trace',0)
    Classi_Origin, ori_avg_xputs, ran_avg_xputs = Replay(pcapDir, nomodify, analyzerI)

    PRINT_ACTION('JUST FINISHED ORIGINAL REPLAY', 0)
    time.sleep(10)
    # Load the randomized trace and perform a replay to check whether DPI based classification
    PRINT_ACTION('Start to replay Randomized trace',0)


    # The random replay should be in the same directory as the original replay
    if '_' in replayName:
        Classi_Random, ori_avg_xputs, ran_avg_xputs = Replay(mainDir + replayName.split('_')[0] + 'Random_' + replayName.split('_')[1], nomodify, analyzerI)
    else:
        Classi_Random, ori_avg_xputs, ran_avg_xputs = Replay(pcapDir[:-1] + 'Random/', nomodify, analyzerI)

    if Classi_Origin == Classi_Random:
        PRINT_ACTION('NO DPI based differentiation detected. Average throughput for original replay is {} Mbps, '
                     'and average throughput for randomized replay is {} Mbps'.format(ori_avg_xputs, ran_avg_xputs),0)
    else:
        PRINT_ACTION('DPI based differentiation detected. Average throughput for original replay is {} Mbps, '
                     'and average throughput for randomized replay is {} Mbps'.format(ori_avg_xputs, ran_avg_xputs), 0)


if __name__=="__main__":
    main(sys.argv)
