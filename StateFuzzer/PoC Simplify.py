"""
Author: Chen Zhang (@demi6od) <demi6d@gmail.com>
Date: 2014 June 4th
"""

from pydbg import *
from pydbg.defines import *

import argparse
import socket
import re
import os
import shutil
import threading
import copy
import signal
import utils
import webbrowser
import time
from win32com.client import GetObject


class Style:
    """One style block (e.g. tag1, tag2... {val1, val2...})"""

    def __init__(self):
        self.elems = []
        self.vals = []

    def parseStyle(self, string):
        searchObj = re.search(r'([^{]+){([^}]+)}', string)
        elemStr = searchObj.group(1)
        self.elems = re.findall(r"[^, ]+[, ]", elemStr)

        valStr = searchObj.group(2)
        self.vals = re.findall(r"[^;]+;", valStr)

        self.elems[len(self.elems) - 1] = self.elems[len(self.elems) - 1] + ","

    def getStr(self):
        styleStr = ""
        for elem in self.elems:
            styleStr = styleStr + elem

        # Delete comma in the end
        styleStr = re.sub(r"[ ,]+$", "", styleStr)

        styleStr = styleStr + "{"
        for val in self.vals:
            styleStr = styleStr + val
        styleStr = styleStr + "}"

        return styleStr

    def copy(self, style):
        self.elems = copy.deepcopy(style.elems)
        self.vals = copy.deepcopy(style.vals)

    def printf(self):
        print (self.elems)
        print (self.vals)

    def filterEmp(self):
        elems = []
        for elem in self.elems:
            if elem != "":
                elems.append(elem)

        vals = []
        for val in self.vals:
            if val != "":
                vals.append(val)

        self.elems = elems
        self.vals = vals


class Styles:
    """Style block list"""

    def __init__(self):
        self.styles = []

    def parseStyles(self, string):
        # Get style string
        searchObj = re.search(r'"([^"]+)"', string)
        styleStr = searchObj.group(1)

        # Get style string block: tag1, tag2... {style1, style2...} 
        styleStrs = re.findall(r"[^}]+}", styleStr)
        for string in styleStrs:
            style = Style()
            style.parseStyle(string)
            self.styles.append(style)

    def getStr(self):
        styleStat = '\t\t\t\tid_2006.innerText = "'

        for style in self.styles:
            styleStat = styleStat + style.getStr() 

        styleStat = styleStat + '";\n'
        return styleStat

    def copy(self, stylesObj):
        self.styles = []
        for idx in range(len(stylesObj.styles)):
            self.styles.append(Style())
            self.styles[idx].copy(stylesObj.styles[idx])

    def printf(self):
        for style in self.styles:
            style.printf()

    def filterEmp(self):
        for style in self.styles:
            style.filterEmp()


class Poc:
    """Poc code list and statement list"""

    def __init__(self):
        self.codes = []
        self.stats = []

        # Statement pattern
        self.inPat = ""
        self.outPat = ""

    def printf(self):
        for line in self.codes:
            print (line)

    def updatePat(self, inPat, outPat):
        self.inPat = inPat
        self.outPat = outPat

    def read(self, fileName):
        fo = open(fileName, "r+")
        self.codes = fo.readlines()
        fo.close()

        self.parseStats(self.inPat, self.outPat)

    def replace(self, oldStr, newStr):
        for idx, line in enumerate(self.codes):
            self.codes[idx] = line.replace(oldStr, newStr)

    def find(self, pat):
        isFound = False
        for line in self.codes:
            if line.find(pat) != -1:
                isFound = True

        return isFound

    def write(self, fileName):
        fo = open(fileName, "w+")
        fo.writelines(self.codes)
        fo.close()

    def parseStats(self, inPat, outPat):
        self.stats = []
        for idx, line in enumerate(self.codes):
            if re.search(inPat, line) and not re.search(outPat, line):
                self.stats.append(idx)

    def copy(self, poc):
        self.codes = copy.deepcopy(poc.codes)
        self.stats = copy.deepcopy(poc.stats)

    def filterPat(self, pat):
        newCodes = []

        for line in self.codes:
            if not re.search(pat, line):
                newCodes.append(line)

        self.codes = newCodes
        self.parseStats(self.inPat, self.outPat)


class PocManager:
    """Poc manager can minimize and simplify poc"""

    def __init__(self, fileDirPath, urlPath):
        self.poc = Poc()
        self.pocType = ""
        self.stylesObj = Styles()
        self.styleStatIdx = 0
        self.hasFrame = False
        self.fileDirPath = fileDirPath
        self.urlPath = urlPath
        self.checkUrl = ""
        self.testFile = ""
        self.mainFileName = ""
        self.verifier = CrashVerifier() 

    def minimize(self, inFile, outFile, inPat, outPat, pocType, isFinal, isFrame):
        print ("[+] minimize " + inFile + " " + pocType)

        self.pocType = pocType
        self.poc.read(self.fileDirPath + inFile)

        if pocType == "main":
            self.mainFileName = outFile
            self.checkUrl = self.urlPath + "testPoc.html" 
            self.testFile = self.fileDirPath + "testPoc.html" 

            # Set javascript timeout to ensure attach renderer before crash
            self.poc.replace("<body onload='testcase();'>", "<body onload='setTimeout(\"testcase();\",500)'>") 

            # Calculate appropriate timeout
            while True:
                self.poc.write(self.testFile)
                if self.verifier.verify(self.checkUrl):
                    ensureTick = 1
                    self.verifier.timeout = self.verifier.timeout + ensureTick
                    print ("[+] Get Timeout: %d" % (self.verifier.timeout))
                    break
                else:
                    print ("[+] Timeout is %d" % (self.verifier.timeout))
                    self.verifier.timeout = self.verifier.timeout + 1
        elif self.pocType == "frame":
            if not self.hasFrame:
                print ("[+] There is no frame")
                return

            self.checkUrl = self.urlPath + self.mainFileName 
            self.testFile = self.fileDirPath + inFile 
        else:
            print ("[*] Warning: minimize else")

        self.poc.updatePat(inPat, outPat)
        self.poc.filterPat(r"^\t\t\t\t//")
        self.poc.filterPat(r"^\s*$")

        if not (pocType == "main" and isFrame):
            self.simplifyPoc()

        if self.pocType == "main":
            if isFinal:
                self.filterToken(["try { ", " } catch(e){}"])
            self.simplifyStyles()
            self.checkFrame()
        elif self.pocType == "frame":
            if self.poc.codes[3].find("style") != -1:
                self.filterLines([3])
            self.simplifyFrameJs()
        else:
            print ("[*] Warning: minimize else")

        self.poc.write(self.fileDirPath + outFile)

    def checkFrame(self):
        self.poc.replace("demicmFrameIE.html", "demiFrame.html");
        self.hasFrame = self.poc.find("demiFrame.html");

    def filterToken(self, tokens):
        cachePoc = Poc()
        cachePoc.copy(self.poc)

        for token in tokens:
            cachePoc.replace(token, "")

        if self.verify(cachePoc):
            self.poc.copy(cachePoc)

    def filterLines(self, lines):
        cachePoc = Poc()

        for idx, line in enumerate(self.poc.codes):
            if idx not in lines:
                cachePoc.codes.append(line)

        if self.verify(cachePoc):
            self.poc.copy(cachePoc)

    def simplifyFrameJs(self):
        """Simplify frame js code."""
        startIdx = 0
        endIdx = 0
        isMan = False
        for idx, line in enumerate(self.poc.codes):
            if line.find("setTimeout('selfMan();', 1);") != -1:
                isMan = True
            if line.find("demiFront") != -1:
                startIdx = idx + 2
            if line.find("</script>") != -1:
                endIdx = idx - 1

        if not isMan:
            cachePoc = Poc()
            for idx, line in enumerate(self.poc.codes):
                if idx < startIdx or idx > endIdx:
                    cachePoc.codes.append(line)

            self.poc.copy(cachePoc)

    def simplifyStyles(self):
        #self.poc.printf()
        print ("[+] Start simplifying styles")
        self.styleStatIdx = -1
        for idx, line in enumerate(self.poc.codes):
            if line.find('\t\t\t\tid_2006.innerText = "') != -1:
                line = line.replace("{}", "")
                self.stylesObj.parseStyles(line)
                self.styleStatIdx = idx

        if self.styleStatIdx == -1:
            print ("[+] Style statement is not found!")
            return

        #self.stylesObj.printf()
        for styleIdx in range(len(self.stylesObj.styles)):
            self.simplifyStyle("elem", styleIdx)
            self.simplifyStyle("val", styleIdx)

    def simplifyStyle(self, styleType, styleIdx):
        if styleType == "elem":
            blockSize = len(self.stylesObj.styles[styleIdx].elems)
        elif styleType == "val":
            blockSize = len(self.stylesObj.styles[styleIdx].vals)
        else:
            print ("[*] Warning: simplifyStyle else")

        while blockSize != 0:
            self.simplifyStyleStr(blockSize, styleType, styleIdx)
            blockSize = blockSize / 2 

    def simplifyStyleStr(self, blockSize, styleType, styleIdx):
        print ("[+] simplify style string: %s, with blockSize %d" % (styleType, blockSize))
        cacheStyles = Styles()
        cacheStyles.copy(self.stylesObj)

        if styleType == "elem":
            length = len(self.stylesObj.styles[styleIdx].elems)
        elif styleType == "val":
            length = len(self.stylesObj.styles[styleIdx].vals)
        else:
            print ("[*] Warning: simplifyStyleStr else")

        while length >= blockSize:
            startIdx = length - blockSize

            for idx in range(startIdx, length):
                if styleType == "elem":
                    cacheStyles.styles[styleIdx].elems[idx] = "" 
                elif styleType == "val":
                    cacheStyles.styles[styleIdx].vals[idx] = "" 
                else:
                    print ("[*] Warning: simplifyStyleStr else")

            self.poc.codes[self.styleStatIdx] = cacheStyles.getStr()
            if self.verify(self.poc):
                self.stylesObj.copy(cacheStyles)
            else:
                cacheStyles.copy(self.stylesObj)

            length = length - blockSize
            self.stylesObj.filterEmp()

    def simplifyPoc(self):
        blockSize = len(self.poc.stats) / 2
        while blockSize != 0:
            self.simplify(blockSize)
            blockSize = blockSize / 2 

    def simplify(self, blockSize):
        print ("[+] --------------Simplify with blockSize: %d" % (blockSize))
        print ("[+] --------------Statement count: %d" % (len(self.poc.stats)))

        cachePoc = Poc()
        cachePoc.copy(self.poc)

        length = len(self.poc.stats)
        if self.pocType == "main":
            length = length - 1

        # Verify for every block
        while length >= blockSize:
            startIdx = length - blockSize

            for idx in range(startIdx, length):
                cachePoc.codes[cachePoc.stats[idx]] = "" 

            if self.verify(cachePoc):
                self.poc.copy(cachePoc)
            else:
                cachePoc.copy(self.poc)

            length = length - blockSize

        self.poc.filterPat("^$")

    def verify(self, poc):
        poc.write(self.testFile)
        isVul = self.verifier.verify(self.checkUrl)
        return isVul


class CrashVerifier:
    """Verify whether poc will crash"""

    def __init__(self):
        self.pids = []
        self.dbg = pydbg()
        self.isAccessv = False
        self.isVul = False
        self.isMon = False
        self.isInAv = False
        self.timeout = 1
        self.nullPtrThr = -1
        self.avBlackList = [r"cmp byte \[0x70\],0x0 from"]

    def verify(self, url):
        self.isAccessv = False
        self.isVul = False

        self.startBrowser(url)
        self.verifyUrl()

        print ("[+] isAv: %r" % (self.isAccessv))
        print ("[+] isVul: %r" % (self.isVul))
        return self.isVul

    def checkVul(self, crashLog):
        # Check null point dereference
        match = re.search(r'EIP: .+\[.*(eax|ebx|ecx|edx|esi|edi|ebp|esp|eip).*\]', crashLog)
        if match:
            keyReg = match.group(1)
            match = re.search(keyReg.upper() + r': (\w{8}) ', crashLog)
            regVal = match.group(1)
            if int(regVal, 16) > self.nullPtrThr:
                self.isVul = True
            else:
                self.isVul = False
        else:
            self.isVul = True
            # Check no vul
            for pat in self.avBlackList:
                if re.search(pat, crashLog):
                    self.isVul = False

    def checkAccessv(self, dbg):
        self.isInAv = True

        if dbg.dbg.u.Exception.dwFirstChance:
            return DBG_EXCEPTION_NOT_HANDLED

        crashBin = utils.crash_binning.crash_binning()
        crashBin.record_crash(dbg)

        #print (crashBin.crash_synopsis())

        print ("[+] Crash pid %d" % (self.pids[1]))
        dbg.terminate_process()

        self.checkVul(crashBin.crash_synopsis())
        self.isAccessv = True

        self.isInAv = False
        return DBG_EXCEPTION_NOT_HANDLED

    def verifyUrl(self):
        # Attach pydbg to renderer process
        self.dbg = pydbg()
        self.dbg.attach(self.pids[1])
        self.dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.checkAccessv)
        print ("[+] Attach pid: %d" % (self.pids[1]))

        # Start monitor thread for no crash url
        monitorThread = threading.Thread(target = self.monitorDebugger)
        monitorThread.setDaemon(0)
        monitorThread.start()

        # Continue to run url
        self.dbg.run()

        time.sleep(1)
        self.getPid("iexplore.exe")
        for pid in self.pids:
            print ("[+] Kill all ie processes: pid %d" % (pid))
            os.kill(pid, signal.SIGTERM)

        # Wait monitor thread exit
        while self.isMon:
            time.sleep(1)

    def startBrowser(self, url):
        ie = webbrowser.get(webbrowser.iexplore)
        ie.open(url)

        # Ensure ie renderer process started
        self.pids = []
        while len(self.pids) != 2:
            self.getPid("iexplore.exe")

    def getPid(self, procName):
        self.pids = []

        WMI = GetObject("winmgmts:")
        processes = WMI.InstancesOf("Win32_Process")
        for p in processes:
            if p.Properties_("Name").Value == procName:
                self.pids.append(p.Properties_("ProcessID").Value)

    def monitorDebugger(self):
        self.isMon = True
        counter = 0
        while counter < self.timeout:
            time.sleep(1)
            #print ("[+] counter: %d" % (counter))
            counter += 1

            # Wait for accessv analyzing
            while self.isInAv:
                time.sleep(1)

            if self.isAccessv == True:
                self.isMon = False
                return

        print ("[+] Kill renderer pid %d" % (self.pids[1]))
        self.dbg.terminate_process()
        self.isAccessv = False
        self.isMon = False


def main():
    fileDirPath = "c:\\www\\fuzz test\\"

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', help = '1 - Simplify with initial demiFrame.html'
        + '  2 - Common simplify  3 - Final simplify  4 - Only frame')
    args = parser.parse_args()

    isFinal = False
    isFrame = False
    if args.i == "1":
        print ("[+] Simplify with initial demiFrame.html")
        shutil.copy(fileDirPath + "demicmFrameIE.html", fileDirPath + "demiFrame.html")
    elif args.i == "2":
        print ("[+] Common simplify")
    elif args.i == "3":
        print ("[+] Final simplify")
        isFinal = True
    elif args.i == "4":
        print ("[+] Frame simplify")
        isFrame = True
    else:
        print ("[+] Make sure the demiPoc.html, demiFrame.html and demicmFrameIE.html")
        return

    localIp = socket.gethostbyname(socket.gethostname())
    urlPath = "http://" + localIp + "/fuzz%20test/"
    pocMan = PocManager(fileDirPath, urlPath)

    # Simplify main page
    inFile = "demiPoc.html"
    outFile = "demiPoc.html"

    # Add suffix for multiple times simplify
    for suffix in range(100):
        if os.path.exists(fileDirPath + outFile):
            inFile = outFile
            outFile = outFile[0: -5] + str(suffix) + ".html"
        else:
            break
        
    inPat = "^\t\t\t\t(try {|var )|doctype html|<title>|style>|logging\.js"
    outPat = "^$|CollectGarbage"
    pocMan.minimize(inFile, outFile, inPat, outPat, "main", isFinal, isFrame)

    # Simplify frame page
    inFile = "demiFrame.html"
    outFile = "demiFrame.html"
    inPat = ";|<"
    outPat = "<body|</body>|<html>|</html>|<head>|</head>|<meta |<script>|</script>|{|}|demiFront"
    pocMan.minimize(inFile, outFile, inPat, outPat, "frame", isFinal, isFrame)


if __name__ == "__main__":
    main()
