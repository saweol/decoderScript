import struct
import idaapi
import idautils
import idc


#Make Key Table From Encrypted Data
#Split by 2bytes
def makeKeyTable(encStr):
    keyTable = []
    for x in range(0,32,2):
        keyTable.append(int(encStr[x:x+2],16))
    
    return keyTable

#Decrypting Encrypted String
def decrypt(encStr):
    keyTable = makeKeyTable(encStr)
    encStr = encStr[32:]

    idx = 0
    decStr = ''
    xorBuf = 0
    privKey = 0

    for x in range(0, len(encStr),2):
        xorBuf = privKey ^ keyTable[idx]
        encData = int(encStr[x:x+2],16)
        decStr = decStr +  chr(xorBuf ^ encData)
        privKey = encData

        if idx >= 15:
            idx = idx - 15
        else:
            idx = idx + 1
    
    return decStr

#Find Decrypt Function Reference
def getXref(addr):
    xref = []
    for ref in CodeRefsTo(addr,1):
        xref.append(ref)
    
    return xref

#Find Encrypted String From Address
# Check lea and rcx
def FindEncodedStr(addrList):
    encodedStr = []

    for addr in addrList:
        while True:
            addr = idc.prev_head(addr)
            disasm = idc.GetDisasm(addr)
            print disasm
            if disasm[:3] == 'lea' and 'rcx' in disasm:
                break
        strAddr = idc.get_operand_value(addr,1)
        encStr = idc.get_strlit_contents(strAddr)
        encodedStr.append({'addr': addr,'encStr' : encStr})
    
    return encodedStr

def setComments(info,decStr):
    #Set Comment for Decompile (hexray) 
    cfunc = idaapi.decompile(info['addr'])
    tl = idaapi.treeloc_t()
    tl.ea = info['addr'] + 7
    tl.itp = idaapi.ITP_SEMI
    cfunc.set_user_cmt(tl, decStr)
    cfunc.save_user_cmts()
    
    #Set Comment for Disasemble (IDA)
    idaapi.set_cmt(info['addr'],decStr,None)
    

def run(addr):
    #Get Encrypted String Address From Function
    data = getXref(addr)
    
    #Get Encrypted String From Address
    encData = FindEncodedStr(data)

    for x in encData:
        
        if x['encStr'] == None:
            continue
        else:
            decStr = decrypt(x['encStr'])
            print ("{0} : {1} -> {2}".format(hex(x['addr']).rstrip("L"), x['encStr'], decStr))
        
        setComments(x,decStr)



