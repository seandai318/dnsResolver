/* copyright (c) 2020, Sean Dai
 *
 * implement DNS resolver functionalities, support three query types: A, SRV, NAPTR
 * For A query, support IPv4 only. For other queries, raw DNS rr will be returned,
 * it is up to the application to continue decoding the raw rr
 */


#include <endian.h>
#include <string.h>

#include "osSockAddr.h"
#include "osHash.h"
#include "osList.h"
#include "osMemory.h"
#include "osMBuf.h"
#include "osPL.h"
#include "osDebug.h"
#include "osMisc.h"
#include "osTimer.h"

#include "transportIntf.h"

#include "dnsResolver.h"
#include "dnsResolverIntf.h"


static __thread osHash_t* rrCache;	//cached rr records
static __thread osHash_t* qCache;	//ongoing queries, each element contains dnsQCacheInfo_t, multiple requests with the same qName and qType are combined into one element with each request's appData is appended in appDataList
static __thread osList_t serverFd;	//each element contains dnsUdpActiveFdInfo_t.
static dnsServerSelInfo_t serverSelInfo;
static __thread uint16_t dnsTrId;

static osStatus_e dnsHashLookup(osHash_t* pHash, osPointerLen_t* qName, dnsQType_e qType, void** pHashData);
static dnsQCacheInfo_t* dnsRRMatchQCacheAndNotifyApp(osPointerLen_t* qName, dnsQType_e qType, dnsResStatus_e rrStatus, dnsMessage_t* pDnsMsg);
static bool dnsIsQueryOngoing(osPointerLen_t* qName, dnsQType_e qType, bool isCacheRR, dnsResolver_callback_h rrCallback, void* pData, dnsQCacheInfo_t** ppQCache);
static osStatus_e dnsPerformQuery(osVPointerLen_t* qName, dnsQType_e qType, bool isCacheRR, dnsResolver_callback_h rrCallback, void* pData, dnsQCacheInfo_t** ppQCache);
static void dnsTpCallback(transportStatus_e tStatus, int fd, osMBuf_t* pBuf);
static dnsMessage_t* dnsParseMessage(osMBuf_t* pBuf, dnsRcode_e* replyCode);
static osStatus_e dnsParseDomainName(osMBuf_t* pBuf, char* pUri);
static osStatus_e dnsParseQuestion(osMBuf_t* pBuf, dnsQuestion_t* pQuery);
static dnsRR_t* dnsParseRR(osMBuf_t* pBuf);
static void dns_onQCacheTimeout(uint64_t timerId, void* ptr);
static void dns_onRRCacheTimeout(uint64_t timerId, void* ptr);
static void dns_onServerQuarantineTimeout(uint64_t timerId, void* ptr);
static dnsServerInfo_t* dnsGetServer();
static uint16_t dnsCreateTrId();
static void dnsMessage_cleanup(void* data);
static void dnsQCacheInfo_cleanup(void* data);
static void dnsRRCacheInfo_cleanup(void* data);


osStatus_e dnsResolverInit(uint32_t rrBucketSize, uint32_t qBucketSize, dnsServerConfig_t* pDnsServerConfig)
{
	osStatus_e status = OS_STATUS_OK;

	if(!pDnsServerConfig)
	{
		logError("null pointer, pDnsServerConfig.");
		status = OS_ERROR_NULL_POINTER;
		goto EXIT;
	}

	if(pDnsServerConfig->serverNum > DNS_MAX_SERVER_NUM)
	{
		logError("the number of DNS server num(%d) > DNS_MAX_SERVER_NUM(%d)", pDnsServerConfig->serverNum, DNS_MAX_SERVER_NUM);
		status = OS_ERROR_INVALID_VALUE;
		goto EXIT;
	}

	rrCache = osHash_create(rrBucketSize);
	if(!rrCache)
    {
        logError("fails to create qCache");
        status = OS_ERROR_MEMORY_ALLOC_FAILURE;
        goto EXIT;
    }

	qCache = osHash_create(qBucketSize);
    if(!qCache)
    {
        logError("fails to create qCache");
        status = OS_ERROR_MEMORY_ALLOC_FAILURE;
        goto EXIT;
    }

	//build serverSelInfo.  the serverSelInfo.serverInfo is sorted with least priority first
	int color[DNS_MAX_SERVER_NUM] = {};
	for(int i=0; i<pDnsServerConfig->serverNum; i++)
	{
		//sort to find the smallest value of priority
		uint8_t curPriority = 255;
		int curNode = -1;
		for(int j=0; j<pDnsServerConfig->serverNum; j++)
		{
			if(color[j])
			{
				continue;
			}

			if(pDnsServerConfig->dnsServer[j].priority <= curPriority)
			{
				curPriority = pDnsServerConfig->dnsServer[j].priority;
				curNode = j;
			}
		}

		if(curNode != -1)
		{
			color[curNode] = 1;
		}

		status = osConvertPLton(&pDnsServerConfig->dnsServer[curNode].ipPort, true, &serverSelInfo.serverInfo[i].socketAddr);
		if(status != OS_STATUS_OK)
		{
			logError("fails to osConvertPLton for ipPortNum=%d", i);
			goto EXIT;
		}

		serverSelInfo.serverInfo[i].priority = pDnsServerConfig->dnsServer[curNode].priority;
		serverSelInfo.serverInfo[i].quarantineTimerId = 0;
	}

	serverSelInfo.serverSelMode = pDnsServerConfig->serverSelMode;
	serverSelInfo.serverNum = pDnsServerConfig->serverNum;
	serverSelInfo.curNodeSelIdx = 0;	

	transport_localRegApp(TRANSPORT_APP_TYPE_DNS, dnsTpCallback);
EXIT:
    return status;
}


/* if isCacheRR == true, caller indicates cache the RR if possible, otherwise, the resolver would not cache the rr.  The resolver also uses this flag to check if it needs to check the rrCache first before performing dns query.  It is expected that user may not want to set this flag to true for NSAPR u query (enum query) as each call may require a enum query and the same E164 number may not re-occur for long time, it will be waste of resources to store its rr
*/
dnsQueryStatus_e dnsQueryInternal(osVPointerLen_t* qName, dnsQType_e qType, bool isCacheRR, dnsMessage_t** qResponse, dnsQCacheInfo_t** ppQCache, dnsResolver_callback_h rrCallback, void* pData)
{
	DEBUG_BEGIN
	dnsQueryStatus_e qStatus = DNS_QUERY_STATUS_ONGOING;
	osStatus_e status = OS_STATUS_OK;

	if(!qName || !qResponse || !rrCallback || !ppQCache)
	{
		logError("null pointer, qName=%p, qResponse=%p, rrCallback=%p, ppQCache=%p.", qName, qResponse, rrCallback, ppQCache);
		status = OS_ERROR_NULL_POINTER;
		goto EXIT;
	}

	*qResponse = NULL;
	*ppQCache = NULL;

	debug("qName=%r, qType=%d, isCacheRR=%d", &qName->pl, qType, isCacheRR);
	if(isCacheRR)
	{
		//check if there is cached response
		dnsRRCacheInfo_t* pRRCache = NULL;
		status = dnsHashLookup(rrCache, &qName->pl, qType, (void**)&pRRCache);
		if(status != OS_STATUS_OK)
		{
			logError("fails to dnsHashLookup for qName(%r), qType(%d).", &qName->pl, qType);
			goto EXIT;
		}

		if(pRRCache)
		{
			*qResponse = pRRCache->pDnsMsg;
			if(!*qResponse)
			{
				logError("a dnsMsg is cached in rrCache, but is empty.");
				status = OS_ERROR_INVALID_VALUE;
				goto EXIT;
			}
			logInfo("find a cached DNS query response for qName(%r), qType(%d).", &qName->pl, qType);
			osVPL_free(qName, true);
			qStatus = DNS_QUERY_STATUS_DONE;
			goto EXIT;
		}
	}
 	
	//check if a query is ongoing for the same qName
	if(dnsIsQueryOngoing(&qName->pl, qType, isCacheRR, rrCallback, pData, ppQCache))
	{
		logInfo("there is a query ongoing for qName(%r), qType(%d).", &qName->pl, qType);

		osVPL_free(qName, true);
		goto EXIT;
	}

	//do not find a cached query response, neither there is a ongoing query, perform a brand new query		
	status = dnsPerformQuery(qName, qType, isCacheRR, rrCallback, pData, ppQCache);

EXIT:
	if(status != OS_STATUS_OK)
	{
		osVPL_free(qName, true);
		qStatus = DNS_QUERY_STATUS_FAIL;
	}
	DEBUG_END
	return qStatus;
}	



static osStatus_e dnsHashLookup(osHash_t* pHash, osPointerLen_t* qName, dnsQType_e qType, void** pHashData)
{
	osStatus_e status = OS_STATUS_OK;
	*pHashData = NULL;

	uint32_t hashKeyInt = osHash_getKeyPL_extraKey(qName, false, qType);

	osListElement_t* pHashElement = osHash_lookupByKey(pHash, &hashKeyInt, OSHASHKEY_INT);
	if(pHashElement)
	{
		osHashData_t* pHashNode = pHashElement->data;
		if(!pHashNode)
		{
			logError("pHashData is NULL for qName(%r), qType(%d).", qName, qType);
			status = OS_ERROR_INVALID_VALUE;
		}
		else
		{
			*pHashData = pHashNode->pData;
		}
	}

	return status;
}
	

static dnsQCacheInfo_t* dnsRRMatchQCacheAndNotifyApp(osPointerLen_t* qName, dnsQType_e qType, dnsResStatus_e rrStatus, dnsMessage_t* pDnsMsg)
{
	osStatus_e status = OS_STATUS_OK;
    dnsQCacheInfo_t* pQCache = NULL;
 
    /* find the request owners and forward the result. */
    if(dnsHashLookup(qCache, qName, qType, (void**)&pQCache) != OS_STATUS_OK)
    {
        logError("fails to dnsHashLookup in qCache for qName(%r), qType(%d).", qName, qType);
        status = OS_ERROR_INVALID_VALUE;
        goto EXIT;
    }

    if(!pQCache)
    {
        logInfo("find an entry in qCache hash for qName(%r), qType(%d), but pQCache is NULL.", qName, qType);
        status = OS_ERROR_INVALID_VALUE;
        goto EXIT;
    }

    //remove from hash.  Intentionally put before the notifying of pDnsMsg to app to allow app to add the same entry (may not be necessary though)
    osHash_deleteNode(pQCache->pHashElement, OS_HASH_DEL_NODE_TYPE_KEEP_USER_DATA);

	//in this function, rrType can only take either DNS_RR_DATA_TYPE_MSG or DNS_RR_DATA_TYPE_STATUS
	dnsResResponse_t rr = {};
	if(rrStatus == DNS_RES_STATUS_OK)
	{
		rr.rrType = DNS_RR_DATA_TYPE_MSG;
		rr.pDnsRsp = pDnsMsg;
	}
	else
	{
        rr.rrType = DNS_RR_DATA_TYPE_STATUS;
        rr.status = rrStatus;
    }

    //notify the request owners one after another
    osListElement_t* pLE = pQCache->appDataList.head;
    while(pLE)
    {
        dnsQAppInfo_t* pApp = pLE->data;
        pApp->rrCallback(&rr, pApp->pAppData);
        pLE = pLE->next;
    }

EXIT:
	if(status != OS_STATUS_OK)
	{
		pQCache = NULL;
	}

	return pQCache;
}


static bool dnsIsQueryOngoing(osPointerLen_t* qName, dnsQType_e qType, bool isCacheRR, dnsResolver_callback_h rrCallback, void* pData, dnsQCacheInfo_t** ppQCache)
{
	osStatus_e status = OS_STATUS_OK;
	bool isQOngoing = false;
	dnsQCacheInfo_t* pQuery = NULL;

	uint32_t hashKeyInt = osHash_getKeyPL_extraKey(qName, false, qType);
	osListElement_t* pHashElement = osHash_lookupByKey(qCache, &hashKeyInt, OSHASHKEY_INT);
	if(!pHashElement)
	{
		goto EXIT;
	}

	osHashData_t* pHashData = pHashElement->data;
    if(!pHashData)
    {
        logError("pHashData is NULL for qName(%r), qType(%d), unexpected.", qName, qType);
		status = OS_ERROR_INVALID_VALUE;
		goto EXIT;
    }
			
	pQuery = pHashData->pData;
	if(!pQuery)
	{
		logError("qName(%r), qType(%d) has an entry in qCache hash, but pQueryInfo is NULL, unexpected.", qName, qType);
		status = OS_ERROR_INVALID_VALUE;
		goto EXIT;
	}

	//only store isCacheRR if it is true, this is for case that for the same query, some request set isCacheRR to true, some set to false
	if(isCacheRR)
    {
        pQuery->isCacheRR = true;
	}
	
	dnsQAppInfo_t* pQAppInfo = osmalloc(sizeof(dnsQAppInfo_t), NULL);
	if(!pQAppInfo)
	{
		logError("fails to osmalloc for pQAppInfo.");
		status = OS_ERROR_MEMORY_ALLOC_FAILURE;
		goto EXIT;
	}

	pQAppInfo->rrCallback = rrCallback;
	pQAppInfo->pAppData = pData;				
	osList_append(&pQuery->appDataList, pQAppInfo);
    isQOngoing = true;

EXIT:
	*ppQCache = pQuery;
	return isQOngoing;
}


static osStatus_e dnsPerformQuery(osVPointerLen_t* qName, dnsQType_e qType, bool isCacheRR, dnsResolver_callback_h rrCallback, void* pData, dnsQCacheInfo_t** ppQCache)
{
	osStatus_e status = OS_STATUS_OK;

	osMBuf_t* pBuf = NULL;
	dnsQCacheInfo_t* pQCache = NULL;
	dnsQAppInfo_t* pQAppInfo = NULL;

	pQCache = oszalloc(sizeof(dnsQCacheInfo_t), dnsQCacheInfo_cleanup);
	if(!pQCache)
	{
		logError("fails to osmalloc for pQCache.");
		status = OS_ERROR_MEMORY_ALLOC_FAILURE;
		goto EXIT;
	}

	pBuf = osMBuf_alloc_r(DNS_MAX_MSG_SIZE);
    if(!pBuf)
    {
        logError("fails to osMBuf_alloc_r.");
        status = OS_ERROR_MEMORY_ALLOC_FAILURE;
        goto EXIT;
    }

	pQCache->pBuf = pBuf;

    pQAppInfo = osmalloc(sizeof(dnsQAppInfo_t), NULL);
	if(!pQAppInfo)
	{
        logError("fails to osmalloc for pQAppInfo.");

        status = OS_ERROR_MEMORY_ALLOC_FAILURE;
        goto EXIT;
    }

	pQCache->qName = qName;
	pQCache->qType = qType;
	pQCache->isCacheRR = isCacheRR;
	pQAppInfo->rrCallback = rrCallback;
	pQAppInfo->pAppData = pData;
	osList_append(&pQCache->appDataList, pQAppInfo);

	//fill the query header
	osMBuf_writeU16(pBuf, dnsCreateTrId(), true);			//transaction ID
	osMBuf_writeU16(pBuf, htobe16(1<<DNS_RD_POS), true);	//flags
	osMBuf_writeU16(pBuf, htobe16(1), true);				//qustions
	osMBuf_writeU32(pBuf, 0, true);					//answer, authority RRs
	osMBuf_writeU16(pBuf, 0, true);					//additional RRs

	//fill uri
	size_t labelPos = pBuf->pos++;
	uint8_t labelCount = 0;
	for(int i=0; i<qName->pl.l; i++)
	{
		if(qName->pl.p[i] == '.')
		{
			pBuf->buf[labelPos] = labelCount;
			labelCount = 0;
			labelPos = pBuf->pos++;
		}
		else
		{
			labelCount++;
 			osMBuf_writeU8(pBuf, qName->pl.p[i], true);
		}
	}
	pBuf->buf[labelPos] = labelCount;
	osMBuf_writeU8(pBuf, 0, true);

	osMBuf_writeU16(pBuf, htobe16(qType), true);
	osMBuf_writeU16(pBuf, htobe16(DNS_CLASS_IN), true);

	//send message to tp to be transmitted.  support UDP only.  true is for persistent
	transportInfo_t tpInfo;
	tpInfo.isCom = false;
	tpInfo.tpType = TRANSPORT_TYPE_UDP;
    dnsServerInfo_t* pServerInfo = dnsGetServer();
	if(!pServerInfo)
	{
        logError("no dns server available.");
		status = OS_ERROR_NETWORK_FAILURE;
		goto EXIT;
	}
	pQCache->pServerInfo = pServerInfo;

	tpInfo.local.sin_addr.s_addr = 0;	//use the default ip in the tp layer
    tpInfo.peer = pServerInfo->socketAddr;
	tpInfo.udpInfo.isUdpWaitResponse = true;
	tpInfo.udpInfo.isEphemeralPort = true;
	tpInfo.udpInfo.fd = -1;
	tpInfo.protocolUpdatePos = 0;
	transportStatus_e tStatus = transport_localSend(TRANSPORT_APP_TYPE_DNS, &tpInfo, pBuf, NULL); 
	if(tStatus != TRANSPORT_STATUS_UDP)
	{
		logError("fails to transport_localSend.");
		status = OS_ERROR_NETWORK_FAILURE;
		goto EXIT;
	}

	//start wait for response timer
	pQCache->waitForRespTimerId = osStartTimer(DNS_WAIT_RESPONSE_TIMEOUT, dns_onQCacheTimeout, pQCache); 

	osHashData_t* pHashData = oszalloc(sizeof(osHashData_t), NULL);
    if(!pHashData)
    {
        logError("fails to allocate pHashData.");

		//keep fd.  the rr response will be dropped eventually since pQCache will be removed 
        status = OS_ERROR_MEMORY_ALLOC_FAILURE;
        goto EXIT;
    }

    pHashData->hashKeyType = OSHASHKEY_INT;
	pHashData->hashKeyInt = osHash_getKeyPL_extraKey(&qName->pl, false, qType);
	pHashData->pData = pQCache;
	pQCache->pHashElement = osHash_add(qCache, pHashData);

EXIT:
	if(status != OS_STATUS_OK)
	{
		pQCache = osfree(pQCache);
	}

	*ppQCache = pQCache;
	return status;
}


static void dnsTpCallback(transportStatus_e tStatus, int fd, osMBuf_t* pBuf)
{
	DEBUG_BEGIN

	osStatus_e status = OS_STATUS_OK;
	dnsRcode_e replyCode = 0;
	dnsMessage_t* pDnsMsg = NULL;
    dnsQCacheInfo_t* pQCache = NULL;
	dnsRRCacheInfo_t* pRRCache = NULL;

	//some thing is wrong with a udp fd.  For query waiting on the fd, the timeout will take care of it
	if(tStatus != TRANSPORT_STATUS_UDP)
	{
		//to-do, need to check replycode, try to match qcache and notify app
		logInfo("tStatus(%d) != TRANSPORT_STATUS_UDP, ignore.");
		goto EXIT;
	}

	pDnsMsg = dnsParseMessage(pBuf, &replyCode);
	if(!pDnsMsg)
	{
		logError("fails to dnsParseMessage.");
		status = OS_ERROR_INVALID_VALUE;
		goto EXIT;
	}

	if(!(pDnsMsg->hdr.flags & DNS_QR_MASK))
	{
		logError("received a DNS request, drop.");
        status = OS_ERROR_INVALID_VALUE;
		goto EXIT;
	}

	osPointerLen_t qName = {pDnsMsg->query.qName, strlen(pDnsMsg->query.qName)};
    debug("query response, qName=%r, qType=%d, replyCode=%d", &qName, pDnsMsg->query.qType, replyCode);
	pQCache = dnsRRMatchQCacheAndNotifyApp(&qName, pDnsMsg->query.qType, DNS_RES_STATUS_OK, pDnsMsg);

	if(!pQCache)
	{
		logError("dnsRRMatchQCacheAndNotifyApp returns null pQCache, unexpected.");
		goto EXIT;
	}

	pQCache->pServerInfo->noRspCount = 0;

	//app does not want this RR to cache
	if(!pQCache->isCacheRR || replyCode != DNS_RCODE_NO_ERROR )
	{
		logInfo("do not cache rr for qName(%r), qType=%d", &qName, pDnsMsg->query.qType);
		goto EXIT;
	}

	//use the first answer if there is more than one answer
	uint32_t ttl = ((dnsRR_t*)pDnsMsg->answerList.head->data)->ttl;
	if(!ttl)
	{
		debug("ttl=0, do not cache");
		goto EXIT;
	}

	debug("qName=%r, ttl=%d(sec)", &qName, ttl);
	//cache the response in the rrCache, create a rrCache data structure
	pRRCache = oszalloc(sizeof(dnsRRCacheInfo_t), dnsRRCacheInfo_cleanup);
//	pRRCache->pDnsMsg = osmemref(pDnsMsg);
	pRRCache->pDnsMsg = pDnsMsg;
    osHashData_t* pHashData = oszalloc(sizeof(osHashData_t), NULL);
    if(!pHashData)
    {
        logError("fails to allocate pHashData.");
        status = OS_ERROR_MEMORY_ALLOC_FAILURE;
        goto EXIT;
    }

    pHashData->hashKeyType = OSHASHKEY_INT;
    pHashData->hashKeyInt = osHash_getKeyPL_extraKey(&qName, false, pQCache->qType);
    pHashData->pData = pRRCache;
    pRRCache->pHashElement = osHash_add(rrCache, pHashData);

    //start the ttl timer
    pRRCache->ttlTimerId = osStartTimer(ttl*1000, dns_onRRCacheTimeout, pRRCache);

EXIT:
	osfree(pQCache);
	osMBuf_dealloc(pBuf);
	if(status != OS_STATUS_OK)
	{
		osfree(pRRCache);
	}

	DEBUG_END
	return;
}



static dnsMessage_t* dnsParseMessage(osMBuf_t* pBuf, dnsRcode_e* replyCode)
{
	DEBUG_BEGIN
	osStatus_e status = OS_STATUS_OK;
	dnsMessage_t* pDnsMsg = NULL;

	uint16_t trId = htobe16(*(uint16_t*)pBuf->buf);
	pBuf->pos += 2;
	uint16_t flags = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
	pBuf->pos += 2;
	*replyCode = flags & DNS_RCODE_MASK;
	if(*replyCode == DNS_RCODE_FORMAT_ERROR)
	{
		logInfo("dns server returns format error for the query, trId=%d", trId);
		status = OS_ERROR_INVALID_VALUE;
		goto EXIT;
	}

	pDnsMsg = oszalloc(sizeof(dnsMessage_t), dnsMessage_cleanup);
	if(!pDnsMsg)
	{
		logError("fails to osmalloc for dnsMessage_t.");
		status = OS_ERROR_MEMORY_ALLOC_FAILURE;
		goto EXIT;
	}

	pDnsMsg->hdr.flags = flags;
	pDnsMsg->hdr.qdCount = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
	pBuf->pos += 2;
	if(pDnsMsg->hdr.qdCount != 1)
	{
		logError("only support pDnsMsg->hdr.qdCount = 1, but the received pDnsMsg->hdr.qdCount=%d.", pDnsMsg->hdr.qdCount);
		status = OS_ERROR_INVALID_VALUE;
		goto EXIT;
	}

	//only parse the maximum DNS_MAX_RR_NUM records.
    pDnsMsg->hdr.anCount = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
    pBuf->pos += 2;

    pDnsMsg->hdr.nsCount = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
    pBuf->pos += 2;

    pDnsMsg->hdr.arCount = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
    pBuf->pos += 2;

	status = dnsParseQuestion(pBuf, &pDnsMsg->query);
	if(status != OS_STATUS_OK)
	{
		logError("fails to dnsParseQuestion.");
		goto EXIT;
	}

	dnsRR_t* pRR = NULL;
	for(int i=0; i<pDnsMsg->hdr.anCount; i++)
	{
		pRR = dnsParseRR(pBuf);
    	if(!pRR)
    	{
        	logError("fails to dnsParseRR for pDnsMsg->answer[%d].", i);
        	goto EXIT;
    	}

		osList_append(&pDnsMsg->answerList, pRR);
	}

    for(int i=0; i<pDnsMsg->hdr.nsCount; i++)
    {
        pRR = dnsParseRR(pBuf);
        if(!pRR)
        {
            logError("fails to dnsParseRR for pDnsMsg->auth[%d].", i);
            goto EXIT;
        }

		osList_append(&pDnsMsg->authList, pRR);
    }

    for(int i=0; i<pDnsMsg->hdr.arCount; i++)
    {
        pRR = dnsParseRR(pBuf);
        if(!pRR)
        {
            logError("fails to dnsParseRR for pDnsMsg->addtlAnswer[%d].", i);
            goto EXIT;
        }

		osList_append(&pDnsMsg->addtlAnswerList, pRR);
    }

EXIT:
	if(status != OS_STATUS_OK)
	{
		pDnsMsg = osfree(pDnsMsg);
	}

	DEBUG_END
	return pDnsMsg;
}


/* handle three scenarios: the domainName is
	1. a sequence of labels ending in a zero octet
	2. a pointer
	3. a sequence of labels ending with a pointer
*/
static osStatus_e dnsParseDomainName(osMBuf_t* pBuf, char* pUri)
{
    DEBUG_BEGIN
	osStatus_e status = OS_STATUS_OK;

    //it is possible labelSize=0, indicating the domain name is <Root>
	if(pBuf->buf[pBuf->pos] == 0)
	{
        pUri[0] = 0;
		pBuf->pos++;
        goto EXIT;
    }

	//starts from the first char after the first label
	uint8_t labelSize;
	size_t origPos = pBuf->pos;	//points to the first label of the domain name
	while(pBuf->buf[pBuf->pos] != 0 && pBuf->pos < pBuf->size)
	{
		labelSize = pBuf->buf[pBuf->pos];
		//add +1 because the last char of the domain name must end with 0x00, which is extra of what is pointed by the labelSize
		if(pBuf->pos + labelSize + 1 >= pBuf->size)
		{
			logError("domain name pBuf->pos(%ld) + labelSize(%d) exceed the pBuf->size(%ld).", pBuf->pos, labelSize, pBuf->size);
			status = OS_ERROR_INVALID_VALUE;
			goto EXIT;
		}

		 //0xc0 = the first 2 bits of a 16 bits field are 1, per rfc1035 section 4.1.4, it indicates the domain name is a pointer
		if(labelSize >= 0xc0)
	    {
        	uint16_t origUriPos = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]) & 0x3fff;
			//copy the uri before this label, note the label has been replace with '.' in earlier iteration
			if(pBuf->pos > origPos+1)
			{
                //the char in origPos shall be a label, the uri starts right after the first label
				memcpy(pUri, &pBuf->buf[origPos+1], pBuf->pos-origPos-1);
                strcpy(&pUri[pBuf->pos-origPos-1], &pBuf->buf[origUriPos]);
			}
            else
            {
                //the new URI completely points to a subset of a previous URI, remove the pointed top label in the previous URI 
                strcpy(pUri, &pBuf->buf[++origUriPos]);
            }
			//copy the remaining uri since the offset label is used, per rfc1035, this must be the last label.  note the earlier occurance of the domain name's label must have been replaced by '.' too
			pBuf->pos += 2;

            debug("domain name=%s, using pointer", pUri);
        	goto EXIT;
    	}

		if(labelSize > DNS_MAX_DOMAIN_NAME_LABEL_SIZE)
		{
			logError("a domain name label size(0x%x) in pos(0x%lx) is bigger than maximum allowed(%d).", labelSize, pBuf->pos, DNS_MAX_DOMAIN_NAME_LABEL_SIZE);
			pBuf->pos = origPos;
			status = OS_ERROR_INVALID_VALUE;
			goto EXIT;
		}
		pBuf->buf[pBuf->pos] = '.';
		pBuf->pos += labelSize + 1;
	}

	//combined with the previous while() check, the following check also implicitly verified the pBuf->buf[pBuf->pos] == 0
	if(pBuf->pos >= pBuf->size)
	{
        logError("the parsing of domain name crosses pBuf->size(%ld).", pBuf->size);
		pBuf->pos = origPos;
        status = OS_ERROR_INVALID_VALUE;
        goto EXIT;
    }

	if(pBuf->pos - origPos > DNS_MAX_NAME_SIZE)
	{
		logError("domain name size(%ld) is larger than DNS_MAX_NAME_SIZE(%d).", pBuf->pos - origPos, DNS_MAX_NAME_SIZE);
		pBuf->pos = origPos;
		status = OS_ERROR_INVALID_VALUE;
		goto EXIT;
	}

	//the URI in mBuf starts 1 char after origPos (the 1st har is a label), and ends with 0, i.e., pBuf->buf[pBuf->pos] = 0
	strcpy(pUri, &pBuf->buf[origPos+1]);

	//point the pos to the first char after the uri, including the terminating 00
	pBuf->pos++;

	debug("domain name=%s", pUri);

EXIT:
    DEBUG_END
	return status;
}	
	

static osStatus_e dnsParseQuestion(osMBuf_t* pBuf, dnsQuestion_t* pQName)
{
	osStatus_e status = dnsParseDomainName(pBuf, pQName->qName);
	if(status != OS_STATUS_OK)
	{
		goto EXIT;
	}

	pQName->qType = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
	pBuf->pos += 2;
	pQName->qClass = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
    pBuf->pos += 2;

	if(pBuf->pos >= pBuf->size)
	{
        logError("when parsing QName, pBuf->pos crosses pBuf->size(%ld).", pBuf->size);
        status = OS_ERROR_INVALID_VALUE;
        goto EXIT;
    }

EXIT:
	return status;
}


static dnsRR_t* dnsParseRR(osMBuf_t* pBuf)
{
DEBUG_BEGIN
	osStatus_e status = OS_STATUS_OK;
	dnsRR_t* pRR = osmalloc(sizeof(dnsRR_t), NULL);
	if(!pRR)
	{
		logError("fails to osmalloc pRR.");
		status = OS_ERROR_MEMORY_ALLOC_FAILURE;
		goto EXIT;
	}

	status = dnsParseDomainName(pBuf, pRR->name);
    if(status != OS_STATUS_OK)
    {
        goto EXIT;
    }

	pRR->type = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
    debug("domain name=%s, dns rr type=%d, pos=0x%x", pRR->name, pRR->type, pBuf->pos);
    pBuf->pos += 2;
	pRR->rrClass = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
    pBuf->pos += 2;
	pRR->ttl = htobe32(*(uint32_t*)&pBuf->buf[pBuf->pos]);
    pBuf->pos += 4;
	pRR->rDataLen = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
    pBuf->pos += 2;

	switch(pRR->type)
	{
		case DNS_QTYPE_A:
			if(pRR->rDataLen != 4)
			{
				logError("rr class is A, but (pRR->rDataLen=%d.", pRR->rDataLen);
				status = OS_ERROR_INVALID_VALUE;
				goto EXIT;
			}

			//no need to do htobe for network address
			pRR->ipAddr.s_addr = *(uint32_t*)&pBuf->buf[pBuf->pos];	
			pBuf->pos += 4;
			break;
		case DNS_QTYPE_SRV:
			//based on rfc 2782
            pRR->srv.priority = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
            pBuf->pos += 2;
            pRR->srv.weight = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
            pBuf->pos += 2;
            pRR->srv.port = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
            pBuf->pos += 2;

            //process target
		    status = dnsParseDomainName(pBuf, pRR->srv.target);
			break;
		case DNS_QTYPE_NAPTR:
			//based on rfc 2915
			pRR->naptr.order = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
		    pBuf->pos += 2;
			pRR->naptr.pref = htobe16(*(uint16_t*)&pBuf->buf[pBuf->pos]);
            pBuf->pos += 2;

			//process flags
			if(pBuf->buf[pBuf->pos] != 1)
			{
				logError("naptr flags size(%d) is not 1, unexpected.", pBuf->buf[pBuf->pos]);
				pRR->naptr.flags = DNS_NAPTR_FLAGS_OTHER;
			}
			else
			{
				switch (pBuf->buf[++pBuf->pos])
				{
					case 's':
					case 'S':
						pRR->naptr.flags = DNS_NAPTR_FLAGS_S;
						break;
					case 'a':
					case 'A':
						pRR->naptr.flags = DNS_NAPTR_FLAGS_A;
						break;
					case 'u':
					case 'U':
						pRR->naptr.flags = DNS_NAPTR_FLAGS_U;
						break;
					case 'p':
					case 'P':
						pRR->naptr.flags = DNS_NAPTR_FLAGS_P;
						break;
					default:
						pRR->naptr.flags = DNS_NAPTR_FLAGS_OTHER;
						break;
				}
			}
			++pBuf->pos;

			//process service
			pRR->naptr.service.l = pBuf->buf[pBuf->pos++];
			pRR->naptr.service.p = &pBuf->buf[pBuf->pos];
			pBuf->pos += pRR->naptr.service.l;

            //process regexp
            pRR->naptr.regexp.l = pBuf->buf[pBuf->pos++];
            pRR->naptr.regexp.p = &pBuf->buf[pBuf->pos];
            pBuf->pos += pRR->naptr.regexp.l;

            //process replacement
		    status = dnsParseDomainName(pBuf, pRR->naptr.replacement);
    		if(status != OS_STATUS_OK)
    		{
        		goto EXIT;
    		}
			break;
		default:
			logInfo("pRR->type=%d is unhandled.", pRR->type);
			pRR->other.l = pRR->rDataLen;
			pRR->other.p = &pBuf->buf[pBuf->pos];
			pBuf->pos += pRR->other.l;
			break;
	}

EXIT:
	if(status != OS_STATUS_OK)
	{
		pRR = osfree(pRR);
	}

DEBUG_END
	return pRR;
}



static void dns_onQCacheTimeout(uint64_t timerId, void* ptr)
{
    if(!ptr)
    {
        logError("null pointer, ptr.");
        return;
    }

    dnsQCacheInfo_t* pQCache = ptr;
    if(pQCache->waitForRespTimerId != timerId)
    {
        logError("pQCache->waitForRespTimerId(%d) does not match with timerId(%d), unexpected.", pQCache->waitForRespTimerId, timerId);
        return;
    }

	pQCache->waitForRespTimerId = 0;
	if(++pQCache->pServerInfo->noRspCount > DNS_MAX_SERVER_QUARANTINE_NO_RESPONSE_NUM)
	{
		pQCache->pServerInfo->quarantineTimerId = osStartTimer(DNS_QUARANTINE_TIMEOUT, dns_onServerQuarantineTimeout, pQCache->pServerInfo);
	}

	//if there is multiple servers, and the query is allowed to try other servers
	if(++pQCache->serverQueried < DNS_MAX_ALLOWED_SERVER_NUM_PER_QUERY)
	{
	    //send message to tp to be transmitted.  support UDP only.  true is for persistent
    	transportInfo_t tpInfo;
    	tpInfo.isCom = false;
    	tpInfo.tpType = TRANSPORT_TYPE_UDP;
    	dnsServerInfo_t* pServerInfo = dnsGetServer();
		if(!pServerInfo)
		{
			logError("no dns server available.");
			goto EXIT;
		}

    	tpInfo.local.sin_addr.s_addr = 0;   //use the default ip in the tp layer
    	tpInfo.peer = pServerInfo->socketAddr;
    	tpInfo.udpInfo.isUdpWaitResponse = true;
    	tpInfo.udpInfo.isEphemeralPort = true;
    	tpInfo.udpInfo.fd = -1;
    	tpInfo.protocolUpdatePos = 0;
    	transportStatus_e tStatus = transport_localSend(TRANSPORT_APP_TYPE_DNS, &tpInfo, pQCache->pBuf, NULL);
    	if(tStatus != TRANSPORT_STATUS_UDP)
    	{
        	logError("fails to transport_localSend.");
        	goto EXIT;
    	}

    	//start wait for response timer
    	pQCache->waitForRespTimerId = osStartTimer(DNS_WAIT_RESPONSE_TIMEOUT, dns_onQCacheTimeout, pQCache);
		return;
	}

EXIT:
	//notify all Query listeners
	dnsRRMatchQCacheAndNotifyApp(&pQCache->qName->pl, pQCache->qType, DNS_RES_ERROR_NO_RESPONSE, NULL);

    osfree(pQCache);
}


static void dns_onServerQuarantineTimeout(uint64_t timerId, void* ptr)
{
    if(!ptr)
    {
        logError("null pointer, ptr.");
        return;
    }

	dnsServerInfo_t* pServerInfo = ptr;
	if(pServerInfo->quarantineTimerId != timerId)
    {
        logError("pServerInfo->quarantineTimerId(%d) does not match with timerId(%d), unexpected.", pServerInfo->quarantineTimerId, timerId);
        return;
    }
	pServerInfo->quarantineTimerId = 0;
}


static void dns_onRRCacheTimeout(uint64_t timerId, void* ptr)
{
	if(!ptr)
	{
		logError("null pointer, ptr.");
		return;
	}

	dnsRRCacheInfo_t* pRRCache = ptr;
	if(pRRCache->ttlTimerId != timerId)
	{
		logError("pRRCache->ttlTimerId(0x%lx) does not match with timerId(0x%lx), unexpected.", pRRCache->ttlTimerId, timerId);
		return;
	}
	pRRCache->ttlTimerId = 0;

	osfree(pRRCache);
}	
		

static dnsServerInfo_t* dnsGetServer()
{
	dnsServerInfo_t* pServer = NULL;

	if(serverSelInfo.serverSelMode == OS_NODE_SELECT_MODE_PRIORITY)
	{
		for(int i=0; i<serverSelInfo.serverNum; i++)
		{
			if(serverSelInfo.serverInfo[i].quarantineTimerId)
			{
				continue;
			}

			pServer = &serverSelInfo.serverInfo[i];
			break;
		}
	}
	else
	{
		int nodeIdx = serverSelInfo.curNodeSelIdx++ % serverSelInfo.serverNum;
		for(int i=nodeIdx; i < serverSelInfo.serverNum; i++)
		{
            if(serverSelInfo.serverInfo[i].quarantineTimerId)
            {
                continue;
            }

            pServer = &serverSelInfo.serverInfo[i];
            break;
        }

		if(!pServer)
		{
			for(int i=0; i<nodeIdx; i++)
			{
	            if(serverSelInfo.serverInfo[i].quarantineTimerId)
    	        {
        	        continue;
            	}

            	pServer = &serverSelInfo.serverInfo[i];
            	break;
        	}
		}
	}
	
	return pServer;
}


static uint16_t dnsCreateTrId()
{
	return dnsTrId++;
}


static void dnsMessage_cleanup(void* data)
{
	dnsMessage_t* pMsg = data;
	if(!pMsg)
	{
		return;
	}

	osList_delete(&pMsg->answerList);
	osList_delete(&pMsg->authList);
	osList_delete(&pMsg->addtlAnswerList);
}


static void dnsQCacheInfo_cleanup(void* data)
{
	dnsQCacheInfo_t* pQCache = data;
	if(!pQCache)
	{
		return;
	}

	osVPL_free(pQCache->qName, true);
	osMBuf_dealloc(pQCache->pBuf);
	//keep the user data, as the user data is actually pQCache.
    osHash_deleteNode(pQCache->pHashElement, OS_HASH_DEL_NODE_TYPE_KEEP_USER_DATA);
	osList_delete(&pQCache->appDataList);
	if(pQCache->waitForRespTimerId)
	{
		pQCache->waitForRespTimerId = osStopTimer(pQCache->waitForRespTimerId);
	}
}


static void dnsRRCacheInfo_cleanup(void* data)
{
	dnsRRCacheInfo_t* pRRCache = data;
    if(!pRRCache)
    {
        return;
    }

	osfree(pRRCache->pDnsMsg);
	//keep the user data, as the user data is actually pQCache.
    osHash_deleteNode(pRRCache->pHashElement, OS_HASH_DEL_NODE_TYPE_KEEP_USER_DATA);
	if(pRRCache->ttlTimerId)
	{
		pRRCache->ttlTimerId = osStopTimer(pRRCache->ttlTimerId);
	}
}
