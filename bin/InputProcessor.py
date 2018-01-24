#=============================================================================== 
# FILE: InputProcessor #
# USAGE: #
# DESCRIPTION:
# OPTIONS: 
# REQUIREMENTS: 
#  1. Generate Key pair for each DN request
#  2. Generate PKCS10 request for each key
#  3. Create XKMS request from DN bulk request file
# BUGS: ---
# NOTES: --- 
# AUTHOR: Stuart Wilson 
# COMPANY: --- 
# VERSION: 1.0 
# CREATED: 15-Mar-2015 11:30:40 CET 
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


parseInputFile = False
createXMLFile = False
inputFile = ''
outputFile= ''
bulk_id='0'
buc_id=''
adminCert=''
batchTime=''
testing=False
batchTime = '2015:03:02T12:00:00'

# Read command line args
try:
    myopts, args = getopt.getopt(sys.argv[1:], "Tpi:b:x:c:t:o:")
except getopt.GetoptError as e:
    print(str(e))
    print("Usage: %s -p -i <input_file> OR %s -b <bulk_id> -x <buc_id> -c <adminCert> -t <batchTime>-o <output_file>" % sys.argv[0] % sys.argv[0])
    sys.exit(2)
    
    
#0==Option, a==argument passed to o    
for o, a in myopts:
    if o == '-p':
        parseInputFile=True
    if o == '-i':
        inputFile=a
    if o == '-c':
        adminCertFile=a
        f = open(adminCertFile, 'r')
        adminCert = f.read()
        adminCert = adminCert.rstrip('\r\n')
    if o == '-b':
        bulk_id=a
    if o == '-x':
        buc_id=a
    if o == '-t':
        batchTime=a
    if o == '-T':
        testing=True
    elif o == '-o':
        createXMLFile=True
        outputFile=a
        

#Register Namespace - this is used when creating the 
ET.register_namespace('xbulk',"http://www.w3.org/2002/03/xkms-xbulk")
ET.register_namespace('ogcm','http://xkms.ubizen.com/kitoshi')
ET.register_namespace('xkms','http://www.xkms.org/schema/xkms-2001-01-20')
ET.register_namespace("ds","http://www.w3.org/2000/09/xmldsig#")
  


# Function used to extract cert from XKMS
def parseCertfromXKMS(inputFile,outputFile):
    
    try:
        # 1. Parse Input File
        tree = ET.parse(inputFile)
        root = tree.getroot()
        namespaces = {'dsig':'http://www.w3.org/2000/09/xmldsig#'}
        
        # 2. Open output file
        RESFILEHANDLE = open(outputFile, "w")
        
        # 3. Iterate over required content and write to file
        subjectName = tree.findall('.//dsig:X509SubjectName', namespaces)
        for child in subjectName:
            print child.text
        subjectCert = tree.findall('.//dsig:X509Certificate',namespaces)
        for child in subjectCert:
            print child.text
            RESFILEHANDLE.write(child.text + '\n')
    
        # 4. Close output  file
        RESFILEHANDLE.close()
        return True
    except:
        print('Exception raised in parseCertfromXKMS')
        return False         



# Test Function used to extract DN from file - please note that DN is in openssl subject format as outlined below.
# The template has to reflect this.
def parseDNfromFile(reqFile):
    
    try:
        REQFILEHANDLE = open(reqFile, "r")
        flag = 1
        DNLine=''
        #1 Build DN using key values
        #=======================================================================
        # So Values could be like this:
        # DN:/CN=Stuart Wilson/emailAddress=stuart.wilson@uk.verizon.com/OU=PM/O=Verizon/C=GB
        #=======================================================================     
        
        for line in REQFILEHANDLE:
            if line.startswith("DN:"):
                #Found DN extract and create
                subject = re.sub("DN:", "", line)
                key = "00269859-0001-000001.pvt.prot"
                key = basename(key)
                print key
                #newline = line.rstrip('DN:')
                print subject
                #Create CSR
                #===============================================================
                # call(["openssl", "version",])
                #=============================================================
                pipe = Popen(["openssl", "req", "-new", "-key", key, "-batch","-x509","-subj", subject],stdout=PIPE, stderr=PIPE)
                removeHeader = pipe.communicate()[0].__str__().replace("-----BEGIN CERTIFICATE-----", "")
                removeNewLine = removeHeader.replace("\n","")
                removeFooter = removeNewLine.replace("-----END CERTIFICATE-----","")
                print removeFooter
                #call(["openssl", "req", "-new", "-key","00269859-0001-000001.pvt.prot", "-batch","-x509","-subj", "/C=GB/ST=London/L=London/O=Global Security/OU=IT Department/CN=example.com"])
        REQFILEHANDLE.close()
        return True        
    except:
        print('Exception raised in parsePKCS10fromFile')
        return False            

def countOccurrence(reqFile, desired):
    
    try:
        hit_count=0
        with open(reqFile) as f:
            for line in f:
                if re.match('DN:', line):
                    hit_count = hit_count + 1                    
        return hit_count
    except:
        return False

# Function used to extract DN from file and generate XKMS Request - please note that DN is in openssl subject format as outlined below.
# The template has to reflect this.
def buildPKCS10XKMSReq(reqFile, xkmsReqOutput):
    
    numberOfRequests=str(countOccurrence(reqFile, 'DN:'))
    #date=time.strftime("%Y-%m-%dT%H:%M:%S")
    date=batchTime
    #1. Build header for xml output
    header = buildXKMSHeader(bulk_id,date,numberOfRequests)
    
    #2. Build Request Header
    reqHeader = buildXKMSReqHeader(numberOfRequests)
    
    #3. Main section - build pkcs10 requests
    
    #Put private key files into an array for use later
    privateKeyArray = []
    keysDir = "./keys"
    for file in os.listdir(keysDir):
        if os.path.isdir(os.path.join(keysDir, file)):
	    newdir = os.path.join(keysDir, file)
            for protfile in os.listdir(newdir):
                if protfile.endswith(".prot"):
                    #Found Private Key add to array
                    privateKeyArray.append(os.path.join(newdir, protfile))
 
    # Build DN from Request File - used in generation of CSR using system openssl binaries
    #=======================================================================
    # So Values could be like this:
    # DN:/CN=Stuart Wilson/emailAddress=stuart.wilson@uk.verizon.com/OU=PM/O=Verizon/C=GB
    #=======================================================================      
    REQFILEHANDLE = open(reqFile, "r")
    flag = 1
    pkcs10Line=''
    reqBody=''
    counter=0
    #Sort the array due to bug in XKMS Responder (Fixed in MCS 2.7 Version D)
    privateKeyArray.sort()    
    print len(privateKeyArray)
    for line in REQFILEHANDLE:
        if line.startswith("DN:"):
	    pkcs10Line=''
            subject = re.sub("DN:", "", line)
            subject = subject.replace("\n","")
            print "openssl"+ "req"+ "-new"+ "-key"+privateKeyArray[counter]+ "-batch"+"-subj"+ subject
            pipe = Popen(["openssl", "req", "-new", "-key",privateKeyArray[counter], "-batch","-subj", subject],stdout=PIPE, stderr=PIPE)
	    print "PIPE return code: "+str(pipe.returncode)
            removeHeader = pipe.communicate()[0].__str__().replace("-----BEGIN CERTIFICATE REQUEST-----", "")
	    print "PIPE return code: "+str(pipe.returncode)
            removeNewLine = removeHeader.replace("\n","")
            pkcs10Line = removeNewLine.replace("-----END CERTIFICATE REQUEST-----","")
            print pkcs10Line
	    pipe.stdout.close()
	    pipe.stderr.close()
            print privateKeyArray[counter].replace(".pvt.prot","")
            reqBody = reqBody + buildXKMSReq(privateKeyArray[counter].replace(".pvt.prot",""),str(buc_id),pkcs10Line)
            counter += 1

    xkmsReqOutputString = header + reqHeader + reqBody + buildXKMSReqFooter() + buildXKMSSignedPart(adminCert)    
    
    namespaces = {
    'xbulk': 'http://www.w3.org/2002/03/xkms-xbulk',
    'xkms': 'http://www.xkms.org/schema/xkms-2001-01-20',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}
    #print xkmsReqOutputString
    xkmsReq = ET.fromstring(xkmsReqOutputString)
    xkmsTree = ET.ElementTree(xkmsReq)
    xkmsTree.write(xkmsReqOutput,encoding="us-ascii",xml_declaration=True)
    #print ET.tostring(xkmsReq)        

    

# Function to create XKMS Header Section            
def buildXKMSHeader(bulk_id,date,numberOfRequests):
        xkmsHeader ='''<?xml version="1.0" encoding="UTF-8"?>
<xbulk:BulkRegister xmlns:xbulk="http://www.w3.org/2002/03/xkms-xbulk"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:xkms="http://www.xkms.org/schema/xkms-2001-01-20">
    <xbulk:SignedPart Id="refId_1">
        <xbulk:BatchHeader>
            <xbulk:BatchID>mcp_bulk_'''+bulk_id+'''</xbulk:BatchID>
            <xbulk:BatchTime>'''+date+'''</xbulk:BatchTime>
            <xbulk:NumberOfRequests>'''+numberOfRequests+'''</xbulk:NumberOfRequests>
            <xbulk:ProcessInfo>
                <ogcm:Reason xmlns:ogcm="http://xkms.ubizen.com/kitoshi">some stuff here</ogcm:Reason>
            </xbulk:ProcessInfo>
        </xbulk:BatchHeader>
        <xkms:Respond>
            <xkms:string>KeyName</xkms:string>
            <xkms:string>RetrievalMethod</xkms:string>
            <xkms:string>X509Cert</xkms:string>
        </xkms:Respond>
        '''
        return xkmsHeader


# Function to XKMS Request Header Section 
def buildXKMSReqHeader(numberOfRequests):
        xkmsRequestHeader='''<xbulk:Requests number="'''+numberOfRequests+'''">
    '''
        return xkmsRequestHeader
    

# Function to create XKMS Request Section             
def buildXKMSReq(keyID,buc_id,pkcs10):
    #1. Create XKMS Header:        
    xkmsRequest='''
        <xbulk:Request>
                <xkms:Status>Valid</xkms:Status>
                <xkms:KeyID>'''+keyID+'''</xkms:KeyID>
                <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:KeyName>http://xkms.ubizen.com/keyname?buc_id='''+buc_id+'''&amp;</ds:KeyName>
                    <xbulk:PKCS10>'''+pkcs10+'''</xbulk:PKCS10>
                </ds:KeyInfo>
            </xbulk:Request>
        '''
    return xkmsRequest

# Function to create XKMS Request Footer Section 
def buildXKMSReqFooter():
        xkmsRequestFooter='''</xbulk:Requests>
        '''
        return xkmsRequestFooter

# Function to create XKMS Signature Section - Currently provides no signature and therefore validate XKMS signature needs to be disabled in SAdmin.
def buildXKMSSignedPart(adminCert):
    xkmsSignedPart = '''</xbulk:SignedPart>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:SignedInfo>
            <ds:CanonicalizationMethod
                Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
            <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
            <ds:Reference URI="#refId_2">
                <ds:Transforms>
                    <ds:Transform Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315" />
                </ds:Transforms>
                <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                <ds:DigestValue />
            </ds:Reference>
        </ds:SignedInfo>
        <ds:SignatureValue />
        <ds:KeyInfo>
            <ds:X509Data>
                <ds:X509Certificate>'''+adminCert+'''</ds:X509Certificate>
            </ds:X509Data>
        </ds:KeyInfo>
    </ds:Signature>
</xbulk:BulkRegister>'''
    
    return xkmsSignedPart

    

namespaces = {
    'xbulk': 'http://www.w3.org/2002/03/xkms-xbulk',
    'xkms': 'http://www.xkms.org/schema/xkms-2001-01-20',
    'ds': 'http://www.w3.org/2000/09/xmldsig#',
}


# Test Function
def testScript():
    #Read Sample Input of pkcs10 request and create XKMS output
    #buildPKCS10XKMSReq('sampleCSR.txt','sampleOutTest.xml')
    #Extract Cert from XKMS Response and create response file.
    #parseCertfromXKMS('mcp_bulk_xx_response.xml', 'sampleOutRes.txt')
    parseDNfromFile("../test/DN.out")
    bulk_id="10"
    batchTime = "2015:03:02T12:00:00"
    inputFile = "../test/DN.out"
    outputFile = "../test/output.xml"
    buildPKCS10XKMSReq(inputFile,outputFile)
    
    
if parseInputFile:
    #Read Sample Input of pkcs10 request and create XKMS output
    buildPKCS10XKMSReq(inputFile,outputFile)
    
if testing:
    testScript()
