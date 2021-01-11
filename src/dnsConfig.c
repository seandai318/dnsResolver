#include "string.h"
#include <arpa/inet.h>
#include <endian.h>
#include <stdlib.h>

#include "osPL.h"
#include "osMemory.h"
#include "osTypes.h"
#include "osSockAddr.h"
#include "osMBuf.h"
#include "osXmlParserIntf.h"
#include "osConfig.h"

#include "dnsConfig.h"



//the order must be sorted based on the data name length.  for the data name with the same len, their orders do not matter
osXmlData_t dnsConfig_xmlData[DNS_XML_MAX_DATA_NAME_NUM] = {
    {DNS_XML_SERVER_IP,         {"DNS_SERVER_IP", sizeof("DNS_SERVER_IP")-1},             OS_XML_DATA_TYPE_XS_STRING},
    {DNS_XML_SERVER_SET,        {"DNS_SERVER_SET", sizeof("DNS_SERVER_SET")-1},           OS_XML_DATA_TYPE_XS_SHORT, true},
    {DNS_XML_SERVER_PORT,       {"DNS_SERVER_PORT", sizeof("DNS_SERVER_PORT")-1},         OS_XML_DATA_TYPE_XS_SHORT},
	{DNS_XML_RESOLVER_IP,		{"DNS_RESOLVER_IP", sizeof("DNS_RESOLVER_IP")-1},		  OS_XML_DATA_TYPE_XS_STRING},
    {DNS_XML_Q_HASH_SIZE,       {"DNS_Q_HASH_SIZE", sizeof("DNS_Q_HASH_SIZE")-1},         OS_XML_DATA_TYPE_XS_LONG},
    {DNS_XML_RR_HASH_SIZE,      {"DNS_RR_HASH_SIZE", sizeof("DNS_RR_HASH_SIZE")-1},       OS_XML_DATA_TYPE_XS_LONG},
    {DNS_XML_MAX_SERVER_NUM,    {"DNS_MAX_SERVER_NUM", sizeof("DNS_MAX_SERVER_NUM")-1},   OS_XML_DATA_TYPE_XS_SHORT},
    {DNS_XML_WAIT_RSP_TIMER,    {"DNS_WAIT_RSP_TIMER", sizeof("DNS_WAIT_RSP_TIMER")-1},   OS_XML_DATA_TYPE_XS_LONG},
    {DNS_XML_SERVER_PRIORITY,   {"DNS_SERVER_PRIORITY", sizeof("DNS_SERVER_PRIORITY")-1}, OS_XML_DATA_TYPE_XS_SHORT},
	{DNS_XML_SERVER_SEL_MODE,   {"DNS_SERVER_SEL_MODE", sizeof("DNS_SERVER_SEL_MODE")-1}, OS_XML_DATA_TYPE_XS_SHORT},
    {DNS_XML_QUARANTINE_TIMER,      {"DNS_QUARANTINE_TIMER", sizeof("DNS_QUARANTINE_TIMER")-1}, OS_XML_DATA_TYPE_XS_LONG},
    {DNS_XML_QUARANTINE_THRESHOLD,  {"DNS_QUARANTINE_THRESHOLD", sizeof("DNS_QUARANTINE_THRESHOLD")-1}, OS_XML_DATA_TYPE_XS_SHORT},
    {DNS_XML_MAX_ALLOWED_SERVER_PER_QUERY,  {"DNS_MAX_ALLOWED_SERVER_PER_QUERY", sizeof("DNS_MAX_ALLOWED_SERVER_PER_QUERY")-1}, OS_XML_DATA_TYPE_XS_SHORT}};



static void dnsConfig_xmlParseCB(osXmlData_t* pXmlValue, void* nsInfo, void* appData);
static void dnsConfig_dbgList();


static dnsConfig_t gDnsConfig;
static int gMaxAllowedServerPerQuery, gWaitRspTimeout, gQuarantineTimeout, gQuarantineThreshold;



osStatus_e dnsConfig_init(char* dnsFileFolder, char* dnsXsdFileName, char* dnsXmlFileName)
{
    osStatus_e status = OS_STATUS_OK;
    osMBuf_t* dnsXsdBuf = NULL;

    if(!dnsXsdFileName || !dnsXmlFileName)
    {
        logError("null pointer, dnsXsdFileName=%p, dnsXmlFileName=%p.", dnsXsdFileName, dnsXmlFileName);
        status = OS_ERROR_NULL_POINTER;
        goto EXIT;
    }

    osMBuf_t* xsdMBuf = osXsd_initNS(dnsFileFolder, dnsXsdFileName);
    if(!xsdMBuf)
    {
        logError("fails to osXsd_initNS from %s/%s for dns xsd", dnsFileFolder, dnsXsdFileName);
        status = OS_ERROR_SYSTEM_FAILURE;
		goto EXIT;
    }

    char dnsXmlFile[OS_MAX_FILE_NAME_SIZE];
    if(snprintf(dnsXmlFile, OS_MAX_FILE_NAME_SIZE, "%s/%s", dnsFileFolder ? dnsFileFolder : ".", dnsXmlFileName) >= OS_MAX_FILE_NAME_SIZE)
    {
        logError("dnsXmlFile name is truncated.");
        status = OS_ERROR_INVALID_VALUE;
    }

    //8000 is the initial mBuf size.  If the reading needs more than 8000, the function will realloc new memory
    osMBuf_t* pDnsOrigXmlBuf = osMBuf_readFile(dnsXmlFile, 8000);
    if(!pDnsOrigXmlBuf)
    {
        logError("read dns xml file fails, dnsXmlFile=%s", dnsXmlFile);
        status = OS_ERROR_INVALID_VALUE;
        goto EXIT;
    }

    osPointerLen_t xsdName = {dnsXsdFileName, strlen(dnsXsdFileName)};
    osXmlDataCallbackInfo_t cbInfo={true, true, false, dnsConfig_xmlParseCB, &gDnsConfig, dnsConfig_xmlData, DNS_XML_MAX_DATA_NAME_NUM};
    osXml_getElemValue(&xsdName, NULL, pDnsOrigXmlBuf, true, &cbInfo);

	dnsConfig_dbgList();

EXIT:
	osMBuf_dealloc(pDnsOrigXmlBuf);
    return status;
}


static void dnsConfig_xmlParseCB(osXmlData_t* pXmlValue, void* nsInfo, void* appData)
{
    if(!pXmlValue)
    {
        logError("null pointer, pXmlValue.");
        return;
    }

	dnsConfig_t* pDnsConfig = appData;

	static __thread osIpPort_t* fpServerIpPort = NULL;
    static __thread int fServerSetNum = 0;

    switch(pXmlValue->eDataName)
	{
		case DNS_XML_RR_HASH_SIZE:
			pDnsConfig->rrHashSize = pXmlValue->xmlInt;

            mdebug(LM_DNS, "dataName=%r, value=%d", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, pXmlValue->xmlInt);
			break;
        case DNS_XML_Q_HASH_SIZE:
            pDnsConfig->qHashSize = pXmlValue->xmlInt;

            mdebug(LM_DNS, "dataName=%r, value=%d", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, pXmlValue->xmlInt);
            break;
    	case DNS_XML_SERVER_IP:
            osIPPort_staticInit(&pDnsConfig->dnsServer[fServerSetNum].ipPort, false, true);
			osVPL_copyPL(&fpServerIpPort->ip, &pXmlValue->xmlStr);

            mdebug(LM_DNS, "dataName=%r, value=%r", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, &pXmlValue->xmlStr);
debug("to-remove, fpServerIpPort->ip=%r", &fpServerIpPort->ip);
			break;
    	case DNS_XML_SERVER_SET:
            if(pXmlValue->isEOT)
            {
                pDnsConfig->serverNum = ++fServerSetNum;
            }
			else
			{
				if(fServerSetNum >= DNS_MAX_SERVER_NUM)
				{
					logError("the dns configuration has more server set(%d) than DNS_MAX_SERVER_NUM(%d).", fServerSetNum+1, DNS_MAX_SERVER_NUM);
					return;
				}

				fpServerIpPort = &pDnsConfig->dnsServer[fServerSetNum].ipPort;
				fpServerIpPort->ip.pl.p = fpServerIpPort->ipMem;
				fpServerIpPort->ip.pl.l = INET_ADDRSTRLEN;
				fpServerIpPort->ip.isPDynamic = false;
				fpServerIpPort->ip.isVPLDynamic = false;
			}

			mdebug(LM_DNS, "dataName=%r, isEOT=%d", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, pXmlValue->isEOT);
            break;
    	case DNS_XML_SERVER_PORT:
			fpServerIpPort->port = pXmlValue->xmlInt;

            mdebug(LM_DNS, "dataName=%r, value=%d", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, pXmlValue->xmlInt);
			break;		
		case DNS_XML_RESOLVER_IP:
		{
			osIpPort_t ipPort = {{pXmlValue->xmlStr}};
			osConvertPLton(&ipPort, false, &pDnsConfig->localSockAddr);

            mdebug(LM_DNS, "dataName=%r, value=%r", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, &pXmlValue->xmlStr);
			break;		
		}
		case DNS_XML_MAX_SERVER_NUM:
			mdebug(LM_DNS, "dataName=%r, value=%d", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, pXmlValue->xmlInt);
			if(pXmlValue->xmlInt != DNS_MAX_SERVER_NUM)
			{
				logError("DNS_MAX_SERVER_NUM is defined in dnsConfig.h, not configurable.  The current value is %d.", DNS_MAX_SERVER_NUM);
			}
            break;
		case DNS_XML_WAIT_RSP_TIMER:
            gWaitRspTimeout = pXmlValue->xmlInt;

            mdebug(LM_DNS, "dataName=%r, value=%d", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, pXmlValue->xmlInt);
            break;		
    	case DNS_XML_SERVER_PRIORITY:
			pDnsConfig->dnsServer[fServerSetNum].priority = pXmlValue->xmlInt;
		
			mdebug(LM_DNS, "dataName=%r, ServerSetIdx=%d, value=%d", &dnsConfig_xmlData[DNS_XML_SERVER_PRIORITY].dataName, fServerSetNum, pDnsConfig->dnsServer[fServerSetNum].priority);
			break;			
    	case DNS_XML_SERVER_SEL_MODE:
			pDnsConfig->serverSelMode = pXmlValue->xmlInt;

            mdebug(LM_DNS, "dataName=%r, value=%d", &dnsConfig_xmlData[DNS_XML_SERVER_SEL_MODE].dataName, pDnsConfig->serverSelMode);
			break;
		case DNS_XML_QUARANTINE_TIMER:
            gQuarantineTimeout = pXmlValue->xmlInt;

            mdebug(LM_DNS, "dataName=%r, value=%d", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, pXmlValue->xmlInt);
            break;
		case DNS_XML_QUARANTINE_THRESHOLD:
            gQuarantineThreshold = pXmlValue->xmlInt;

            mdebug(LM_DNS, "dataName=%r, value=%d", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, pXmlValue->xmlInt);
            break;
		case DNS_XML_MAX_ALLOWED_SERVER_PER_QUERY:
			gMaxAllowedServerPerQuery = pXmlValue->xmlInt;

            mdebug(LM_DNS, "dataName=%r, value=%d", &dnsConfig_xmlData[pXmlValue->eDataName].dataName, pXmlValue->xmlInt);
            break;
		default:
            mlogInfo(LM_DNS, "pXmlValue->eDataName(%d) is not processed.", pXmlValue->eDataName);
            break;
	}
}


const dnsConfig_t* dns_getConfig()
{
	return &gDnsConfig;
}


const int dnsConfig_getMaxAllowedServerPerQuery()
{
	return gMaxAllowedServerPerQuery;
}


const int dnsConfig_getWaitRspTimeout()
{
	return gWaitRspTimeout;
}


const int dnsConfig_getQuarantineTimeout()
{
	return gQuarantineTimeout;
}


const int dnsConfig_getQuarantineThreshold()
{
	return gQuarantineThreshold;
}

struct sockaddr_in dnsConfig_getLocalSockAddr()
{
	return gDnsConfig.localSockAddr;
}


static void dnsConfig_dbgList()
{
	mdebug(LM_DNS, "DNS resolver configuration:");
	mdebug1(LM_DNS, "local address=%A\n", &gDnsConfig.localSockAddr);
	mdebug1(LM_DNS, "rr hash size=%d\nq hash size=%d.\n", gDnsConfig.rrHashSize, gDnsConfig.qHashSize);
	mdebug1(LM_DNS, "the max number of server the dns resolver will try for a query=%d.\n", gMaxAllowedServerPerQuery);
	mdebug1(LM_DNS, "wait response timeout=%d msec\n", gWaitRspTimeout);
	mdebug1(LM_DNS, "server into quarantine threshold=%d\nquarantine timeout=%d sec\n", gQuarantineThreshold, gQuarantineTimeout); 	 
	mdebug1(LM_DNS, "server selection mode=%d\nserver Num=%d\n", gDnsConfig.serverSelMode, gDnsConfig.serverNum);
	for(int i=0; i<gDnsConfig.serverNum; i++)
	{
		mdebug1(LM_DNS, "    i=%d, server IP=%r, port=%d\n", i, &gDnsConfig.dnsServer[i].ipPort.ip.pl, gDnsConfig.dnsServer[i].ipPort.port);
	}
}			
