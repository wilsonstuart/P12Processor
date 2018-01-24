#=============================================================================== 
# FILE: OutputProcessor #
# USAGE: #
# DESCRIPTION:
# OPTIONS: 
# REQUIREMENTS: Parse xkms response file and create p12 output files
# BUGS: ---
# NOTES: --- 
# AUTHOR: Stuart Wilson 
# COMPANY: --- 
# VERSION: 1.0 
# CREATED: 15-Apr-2015 11:30:40 CET 
# REVISION: --- 
#=============================================================================== 

import etree.ElementTree as ET
from StringIO import StringIO
from xml.dom import minidom
from xml.dom.minidom import Node
import sys, getopt, re, time
from datetime import date
from subprocess import Popen, PIPE, STDOUT, call
from OpenSSL import crypto, SSL
from sys import stdout
import os
from os.path import basename, splitext
from __builtin__ import True
import shutil


date=time.strftime("%Y/%m/%d")
testing = False
generateCertFiles = False
generateP12Files = False
cafile=''
# Read command line args
try:
    myopts, args = getopt.getopt(sys.argv[1:], "i:cp:T")
except getopt.GetoptError as e:
    print(str(e))
    print("Usage: %s -i <input_file> -c -p <CA_FILE>" % sys.argv[0] % sys.argv[0])
    sys.exit(2)
    
    
#0==Option, a==argument passed to o    
for o, a in myopts:

    if o == '-i':
        inputFile=a
    elif o == '-c':
        generateCertFiles = True
    elif o == '-p':
        generateP12Files = True
        cafile = a
        print cafile
    elif o == '-T':
        testing = True
        

ET.register_namespace('xbulk',"http://www.w3.org/2002/03/xkms-xbulk")
ET.register_namespace('ogcm','http://xkms.ubizen.com/kitoshi')
ET.register_namespace('xkms','http://www.w3.org/2002/03/xkms#')
ET.register_namespace("ds","http://www.w3.org/2000/09/xmldsig#")



# Function to parse certificate from XKMS response file and create PEM certificate file
def parseCertfromXKMS(inputFile):
    
    try:
        # 1. Parse Input File
        tree = ET.parse(inputFile)
        root = tree.getroot()
        namespaces = {
        'dsig':'http://www.w3.org/2000/09/xmldsig#',
        'xkms': 'http://www.w3.org/2002/03/xkms#'
        }
        
        # 2. Open output file
        #RESFILEHANDLE = open(outputFile, "w")
        
        # 3. Iterate over required content and write to files
        
        
        for xkmsAnswer in tree.findall('.//xkms:Answer', namespaces):
            keyID = xkmsAnswer.find('.//xkms:KeyID', namespaces)
            print "######### Printing Details ##########"
            print keyID.text
            certFile = './Certs/' + os.path.basename(keyID.text) + '.crt'
            RESFILEHANDLE = open(certFile, "w")
            subjectCert = xkmsAnswer.find('.//dsig:X509Certificate',namespaces)
            print subjectCert.text
            RESFILEHANDLE.write(subjectCert.text)
            RESFILEHANDLE.close()
            print "Closed File" +certFile
            formatPEMCert(certFile)	

    except Exception, err:
        print('Exception raised in parseCertfromXKMS: ')
        print err
        return False
    
    return True


#Function to create PKCS12 file based on private keys and corresponding certificates
def createPKCS12():
    
    #1. Obtain private Key that corresponds to certificate
    print "In createPKCS12 Function"	
    privateKeyArray = []    
    keysDir = "./keys"
    
    if testing:
        #cafile = "../test/00/cafile.cer"
        keysDir = "../test/00"
    
    for file in os.listdir(keysDir):
        if os.path.isdir(os.path.join(keysDir, file)):
            newdir = os.path.join(keysDir, file)
            for protfile in os.listdir(newdir):
                if protfile.endswith(".prot"):
                    #Found Private Key add to array
                    privateKeyArray.append(os.path.join(newdir, protfile)) 
            
    #Iterate over the privateKeyArray and identify the correct private key and certificate to include in the p12
   #Sort the array - workaround to fix a problem in the XKMS Responder - Fixed in MCS 2.7 Version D     
    privateKeyArray.sort()
    print "Lenght of priateKeyArray is : " + str(len(privateKeyArray)) 
    for key in privateKeyArray:
        #Find corresponding certificate file
        privkey=os.path.basename(key)
        eeCert = './Certs/'+ privkey.replace(".pvt.prot",".crt")
        print privkey
        print eeCert
        outputP12 = './P12/'+ privkey.replace(".pvt.prot",".p12")
        if testing:
            eeCert = '../test/00/'+ key.replace(".pvt.prot",".crt")
            outputP12 = '../test/00/'+ key.replace(".pvt.prot",".p12")
        # Check it exists
        try:    
            #2. Create pkcs12 using openssl
            print("openssl" + "pkcs12" + "-keypbe" + "PBE-SHA1-3DES" + "-certpbe" + "PBE-SHA1-3DES" + "-export" + "-certfile" + cafile + "-in" + eeCert + "-inkey" + key + "-out" + outputP12)
            pipe = Popen(["openssl", "pkcs12", "-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-export", "-certfile", cafile, "-in", eeCert, "-inkey", key, "-out", outputP12, "-password", "pass:Verizon1!"],stdout=PIPE, stderr=PIPE)
            print "PIPE return code: "+str(pipe.returncode)
            pipe.communicate(PIPE)
            print "PIPE return code: "+str(pipe.returncode)
            if pipe.returncode != 0:
                print "Failure in OpenSSL when creating P12 for " +privKey
		return False
            #Move private key and cert to backup locations after successful creation of P12
            processedCert = './Certs/processed/'+privkey.replace(".pvt.prot",".crt")
            processedPrivKey = './keys/processed/'+privkey
            os.rename(eeCert, processedCert)
            #shutil.move(eeCert, processedCert)
            os.rename(key, processedPrivKey)
            #shutil.move (key, processedPrivKey)
            
        except Exception, e:
            print('Exception raised in createPKCS12:%s' % e)
            return False
    
    return True

# Function to Format xkms certificate to PEM format for Openssl consumtion into P12.    
def formatPEMCert(inputFile):
    try:
        print "Open File: "+inputFile
        RESFILEHANDLE = open(inputFile, "r")
        cert = RESFILEHANDLE.read()
        RESFILEHANDLE.close()

        pemCert = re.sub("(.{64})", "\\1\n", cert)
        newFile = inputFile + ".new"

        NEWFILEHANDLE = open(newFile, "w")
        NEWFILEHANDLE.write("-----BEGIN CERTIFICATE-----\n")
        if pemCert[-1:] == "\n":
            pemCert = pemCert[:-1]
        NEWFILEHANDLE.write(pemCert)
        NEWFILEHANDLE.write("\n-----END CERTIFICATE-----")
        NEWFILEHANDLE.close()

        os.rename(newFile, inputFile)        
    except Exception, e:
        print('Exception raised in formatPEMCert: %s' % e)
        return False
    
    return True    

if generateCertFiles:
    #Create Certificate Files
    parseCertfromXKMS(inputFile)
    
if generateP12Files:
    #Create Certificate Files
    parseCertfromXKMS(inputFile)
    #Creater PKCS12 File
    createPKCS12()
    
if testing:
    
    #parseCertfromXKMS()
    createPKCS12()
