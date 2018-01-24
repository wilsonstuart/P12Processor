#!/bin/bash
#=============================================================================== 
# FILE: InputProcessor.sh #
# USAGE: Called by BulkProcessor#
# DESCRIPTION:
# 1. Calculates how many certificates are required by the submitted bulk request file
# 2. Generates Private Keys using PKReservoir
# 3. Generate XKMS request files containing cert request for each private key
# OPTIONS: 
# REQUIREMENTS: Create XKMS request from DName bulk request file
# Direcotries:
#   /opt/bulkprocessorclient/Custom/ProcessP12/conf/
#   /opt/bulkprocessorclient/Custom/ProcessP12/bin/
# BUGS: ---
# NOTES: --- 
# AUTHOR: Stuart Wilson 
# COMPANY: --- 
# VERSION: 1.0 
# CREATED: 23-Mar-2015 11:30:40 CET
# REVISION: --- 
#=============================================================================== 

#---------- # Set up VARIABLES #----------
# Current directory
CURRENT_DIR=`pwd`

# Custom Conf directory
CONF_DIR=/opt/bulkprocessorclient/PM/P12/conf
# Bin directory from where script is executed
BIN_DIR=/opt/bulkprocessorclient/PM/P12/bin
# Custom Config file - Contains Batch Size - request files will be based on this number
# buc_id  - XML business Context Identifier - used to populate XKMS request
# cafile - Used to store CA files to add to P12 when creating output.
CONFIG_FILE=ProcessP12.conf


FILESUFFIX=$(date '+%Y%m%d%H%M%S')

# Log file of actions
LOGFILE=InputProcessor_$FILESUFFIX.log

# Obtain Input variables from params.ini for Processing
BULK_ID=`echo $(grep "BULK_REQUEST_ID=" params.ini ) |  sed -e 's/\\r//g;s/BULK_REQUEST_ID=//g'`
INPUT_FILE=`echo $(grep "bulk_request_filepath=" params.ini ) |  sed -e 's/\\r//g;s/bulk_request_filepath=//g'`
ADMIN_CERT=admin.cert
#Format of batchtime is important as this is used to process the request through the components.
# This should be the same for every chunk in a multi request.
XKMS_BATCHTIME=`date +%Y-%m-%d"T"%H:%M:%S`

#---------- # Functions #----------

#Function to create the directories used in processing
func_create_dirs() {

    if [ ! -d "request" ]; then
        mkdir request
        func_log_if_error "mkdir request failed"
    fi

    if [ ! -d "unzip" ]; then
        mkdir unzip
        func_log_if_error "mkdir unzip failed"
    fi

    if [ ! -d "keys" ]; then
        mkdir keys
	mkdir keys/processed
        func_log_if_error "mkdir keys failed"
    fi

    if [ ! -d "Certs" ]; then
        mkdir Certs/
	mkdir Certs/processed
        func_log_if_error "mkdir Certs failed"
    fi
    if [ ! -d "P12" ]; then
        mkdir P12/
        func_log_if_error "mkdir P12 failed"
    fi

    return 0;
}

#Function to create a request file for updating with new parameters that will finally be copied into params.ini
func_make_config_file() {
    xkms_bulk_request_id=`echo $(grep "BULK_REQUEST_ID=" params.ini ) |  sed -e 's/\\r//g;s/BULK_REQUEST_ID=//g'`
    cat $CONF_DIR/$CONFIG_FILE > request_config.txt
    func_log_if_error " make config file failed"
    echo "xkms_bulk_request_id="$xkms_bulk_request_id >> request_config.txt
    func_log_if_error " make config file failed"
}


# Function to create log file
func_log() {

		echo "`date '+%Y-%m-%d %H:%M:%S'`	: $1" | tee -a $LOGFILE
	
}



func_find_error()
{
    error_string=$(grep "Exit on Error:" $1*.txt )
    leftString=${error_string##*"Exit on Error:"}
    finalString=${leftString%": exiting"*}

    echo "ERROR_MESSAGE=$finalString" >> params.ini

}


# Function to find error in text of log file.
func_find_error()
{
    error_string=$(grep "Exit on Error:" $1*.txt )
    leftString=${error_string##*"Exit on Error:"}
    finalString=${leftString%": exiting"*}

    echo "ERROR_MESSAGE=$finalString" >> params.ini

}

# Function to log error messages
func_log_if_error() {

    result=${PIPESTATUS[0]}
    if [ "$result" != "0" ]; then
        echo "log_if_error :"$1
        echo "ERROR_MESSAGE="$1  >> params.ini
        exit 1;
    fi


}

# Function to log PKReservoir execution errors
func_log_pkClientError()
{
	
	#Arg 1: Result
	#Arg 2: Order ID
	
   errorCode=$1 
   errorString="PKReservoirAPIClient: Fatal unknown error."

    if [ "$errorCode" = "1" ];
    then
 	errorString="PKReservoirAPIClient: command line parameter error."
    elif [ "$errorCode" = "2" ];
    then
 	errorString="PKReservoirAPIClient: Properties parameter error."

    elif [ "$errorCode" = "3" ];
    then
 	errorString="PKReservoirAPIClient: Local output path error."
    elif [ "$errorCode" = "4" ];
    then
 	errorString="PKReservoirAPIClient: Fatal client error."
    elif [ "$errorCode" = "10" ];
    then
 	errorString="PKReservoirAPIClient: Fatal Rest Error"
    elif [ "$errorCode" = "20" ];
    then
 	errorString="PKReservoirAPIClient: File delivery request timeout error."
    elif [ "$errorCode" = "30" ];
    then
 	errorString="PKReservoirAPIClient: FTP server unable to connect."
    elif [ "$errorCode" = "31" ];
    then
 	errorString="PKReservoirAPIClient: FTP server unable to disconnect"
    elif [ "$errorCode" = "32" ];
    then
 	errorString="PKReservoirAPIClient: FTP server initial connection timeout."
    elif [ "$errorCode" = "33" ];
    then
 	errorString="PKReservoirAPIClient: FTP server max retry limit."
    elif [ "$errorCode" = "34" ];
    then
 	errorString="PKReservoirAPIClient: FTP server bad credentials"
    else
 	errorString="PKReservoirAPIClient: Fatal unknown error."

    fi

    if  [ "$2" = "" ];
    then
     echo "ERROR_MESSAGE="$errorString  >> params.ini
    else
     echo "ERROR_MESSAGE="$errorString" order id :"$2   >> params.ini
    fi



}

# Function which calls pkreservoirClient.sh and obtains the key pairs. Currently only supports RSA.
func_getkeys()
{
	
	#Arg1: Number of keys required
	#Arg2: Specified if reorder is required. This takes an oderid

	keys_needed=$1
	func_log "KEYS NEEDED: $1"
	
	#First Check if this is a reorder, if $2 = x then this is not a re order.
	if [ "x" = "$2" ]
	then
	  id_string=" "
	else
	  id_string="-id "$2

	fi

	if [ "$keys_needed" = "0" ];
	then

		return 0;

	fi
	# Execute the PKReservoir script to obtain required keys.
        /opt/bulkprocessorclient/pkreservoirClient/pkreservoirClient.sh -n $keys_needed -a 1.2.840.113549.1.1.1 -s 2048 -o ./unzip -p "bash -c \"cat %privatekeyfile% > %privatekeyfile%.prot\" " $id_string 2> pkreservoirClient_output.txt

        result=${PIPESTATUS[0]}
        if [ "$result" = "0" ];
        then


		var=$(grep "mcs-pkreservoir:order_id"  pkreservoirClient_output.txt )
		var2=${var%"</mcs-pkreservoir:order_id"*}
		order_id=${var2##*"mcs-pkreservoir:order_id>"}

		# Unzip the resulting keys to the keys directory.
		for i in $( ls unzip/$order_id/*.zip); do
        		unzip -o  $i   -d  keys/
		func_log_if_error " unzip failed"
                        if [ "$result" = "0" ];
                        then
                                func_log "Decompressed $order_id to keys"
                                rm  $i
			        func_log_if_error "rm $1 failed"
                        fi

		done
        else
                var=$(grep "mcs-pkreservoir:order_id"  pkreservoirClient_output.txt )
                var2=${var%"</mcs-pkreservoir:order_id"*}
                order_id=${var2##*"mcs-pkreservoir:order_id>"}

		func_log_pkClientError $result $order_id

          return 1;
        fi

	return 0 ;
}


# This is the function that creates the XKMS request
# Calls python script to generate pkcs10 file using the public keys in the directory
func_create_request() {

# Account for multi requests.
if [ $1 == 0 ];then
    BULK_ID=`echo $(grep "BULK_REQUEST_ID=" params.ini ) |  sed -e 's/\\r//g;s/BULK_REQUEST_ID=//g'`
else
    BULK_ID=$BULK_ID_$1
fi

OUTPUT_FILE=`dirname $INPUT_FILE`/mcp_bulk_$BULK_ID.xml
func_log "Running InputProcessor.py"
func_log "python InputProcessor.py -p -i $INPUT_FILE -b $BULK_ID -x $BUC_ID -c $ADMIN_CERT -t $XKMS_BATCHTIME -o $OUTPUT_FILE"
python $BIN_DIR/InputProcessor.py -p -i $INPUT_FILE -b $BULK_ID -x $BUC_ID -c $ADMIN_CERT -t $XKMS_BATCHTIME -o $OUTPUT_FILE

result=${PIPESTATUS[0]}
    if [ "$result" != "0" ]; then
        func_log "InputProcessor Failed to create request file in func_create_request using : $INPUT_FILE"
        echo "ERROR_MESSAGE="$1  >> params.ini
    exit 1;
    fi

}


#---------- # Begin Main #----------



# 1. Check Directories Exist
func_create_dirs


# 2. Make Config File

func_make_config_file


# Obtain Extra Variables from config file
BATCH_SIZE=`echo $(grep "batch_size=" request_config.txt ) |  sed -e 's/\\r//g;s/batch_size=//g'`
BUC_ID=`echo $(grep "buc_id=" request_config.txt ) |  sed -e 's/\\r//g;s/buc_id=//g'`

# 3. Validate input File
# Check number of requests in the file
XKMS_NUMBEROFREQUESTS=`grep -c "DN:" $INPUT_FILE`

if [ $XKMS_NUMBEROFREQUESTS -gt $BATCH_SIZE ]; then
    #Calculate the number of batches
    func_log "Num of Requests = $XKMS_NUMBEROFREQUESTS and Batch Size = $BATCH_SIZE"
    NUMBER_OF_CHUNKS=$(( ($XKMS_NUMBEROFREQUESTS + ($XKMS_NUMBEROFREQUESTS - 1)) / $BATCH_SIZE))

else
    NUMBER_OF_CHUNKS=1

fi


# 4. Generate ALL Private and Public Keys

result="x"

func_getkeys $XKMS_NUMBEROFREQUESTS $result
result=${PIPESTATUS[0]}
if [ "$result" != "0" ]; 
then
	exit 1;
fi

# Now we have the private and public keys located in keys directory and labaled for example 00269859-0001-000001.pvt.prot and 0269859-0001-000001.pub
# 4. Create XKMS Request File/s using .pub files

for ((i=0 ; i < $NUMBER_OF_CHUNKS; i++));
do
func_create_request $i
done

# 5. Update params.ini and exit process returning control to Bulk Processor
# Add :
# xkms_batchid - should be mcp_bulk_<BULK_REQUEST_ID>
# xkms_batchtime - Should be the same for every chunk in the multi-request
# number_of_chunks - number of bulk request files
# xkms_numberofrequests - indicates the total number of requests
# batch_size - maximum number of requests per chunk

echo "xkms_batchid=mcp_bulk_$BULK_ID" >> params.ini
echo "xkms_batchtime=$XKMS_BATCHTIME" >> params.ini
echo "number_of_chunks=$NUMBER_OF_CHUNKS" >> params.ini
echo "xkms_numberofrequests=$XKMS_NUMBEROFREQUESTS" >> params.ini
echo "batch_size=$BATCH_SIZE" >> params.ini

# 6 Exit code if successful should be 0

exit 0
