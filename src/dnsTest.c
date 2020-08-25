#include <string.h>
#include <arpa/inet.h>

#include "osSockAddr.h"
#include "osMisc.h"
#include "osPL.h"
#include "osList.h"
#include "osMemory.h"
#include "osSockAddr.h"
#include "osTimer.h"

#include "dnsResolverIntf.h"


static void printOutcome(dnsMessage_t* pDnsRsp, bool isUntilA);
static void dnsTestCallback(dnsResResponse_t* pRR, void* pData);
static void startTest();
static void dnsTest_onTimeout(uint64_t timerId, void* ptr);


#define QUERY_A 1
#define QUERY_SRV 0

dnsServerConfig_t dnsServerConfig;


bool isResolveAll = true;

void dnsTest()
{
//    dnsServerConfig_t dnsServerConfig;
    dnsServerConfig.serverNum = 1;
    dnsServerConfig.serverSelMode = OS_NODE_SELECT_MODE_PRIORITY;
    dnsServerConfig.dnsServer[0].ipPort.ip.pl.p = "192.168.1.254";
    dnsServerConfig.dnsServer[0].ipPort.ip.pl.l = strlen("192.168.1.254");
    dnsServerConfig.dnsServer[0].ipPort.port = 53;
    dnsServerConfig.dnsServer[0].ipPort.ip.isVPLDynamic = false;
    dnsServerConfig.dnsServer[0].ipPort.ip.isPDynamic = false;
    dnsServerConfig.dnsServer[0].priority = 10;

    dnsInit(64, 64, &dnsServerConfig);

	debug("dnsResolver is initialized");

	startTest();

	uint64_t timerId = osStartTimer(10000, dnsTest_onTimeout, NULL);
	debug("start timer=0x%lx", timerId);
}


static void dnsTest_onTimeout(uint64_t timerId, void* ptr)
{
	debug("timeout.  timerId=0x%lx", timerId); 
	startTest();
}

static void startTest()
{
    //perform dns testing
//    osVPointerLen_t qName = {{"ims.globalstar.com.mnc970.mcc310.gprs", strlen("ims.globalstar.com.mnc970.mcc310.gprs")}, false, false};
    osVPointerLen_t* qName = osmalloc(sizeof(osVPointerLen_t), NULL);
	dnsResResponse_t* pDnsRR = NULL;
#if QUERY_A
	qName->pl.p ="example.com";
	qName->pl.l = strlen("example.com");
	qName->isPDynamic = false;
	qName->isVPLDynamic = true;
    dnsQueryStatus_e qStatus = dnsQuery(qName, DNS_QTYPE_A, isResolveAll, true, &pDnsRR, dnsTestCallback, NULL);
#endif
#if QUERY_SRV
    qName->pl.p ="_sip._udp.sip.voice.google.com";
    qName->pl.l = strlen("_sip._udp.sip.voice.google.com");
    qName->isPDynamic = false;
    qName->isVPLDynamic = true;
    dnsMessage_t* pDnsMsg = NULL;
    dnsQueryStatus_e qStatus = dnsQuery(qName, DNS_QTYPE_SRV, isResolveAll, true, &pDnsRR, dnsTestCallback, NULL);
#endif

	switch(qStatus)
	{
		case DNS_QUERY_STATUS_ONGOING:
			debug("dnsQuery(%r) is ongoing", qName);
			break;
		case DNS_QUERY_STATUS_DONE:
			debug("dnsQuery(%r) is done.", qName);
			if(pDnsRR->rrType == DNS_RR_DATA_TYPE_STATUS)
			{
				debug("rr status = %d", pDnsRR->status);
			}
			else if(pDnsRR->rrType == DNS_RR_DATA_TYPE_MSG)
			{
				printOutcome(pDnsRR->pDnsRsp, false);
				//debug("qName=%s, qType=%d, query done.", pDnsRR->pDnsRsp->query.qName, pDnsRR->pDnsRsp->query.qType);
			}
			else
			{
	            osListElement_t* pRRLE = pDnsRR->dnsRspList.head;
    	        while(pRRLE)
        	    {
            	    dnsMessage_t* pDnsRsp = pRRLE->data;
                	debug("qName=%s, qType=%d", pDnsRsp->query.qName, pDnsRsp->query.qType);

                	if(pDnsRsp->hdr.flags & DNS_RCODE_MASK != DNS_RCODE_NO_ERROR)
                	{
                    	debug("query response error=%d", pDnsRsp->hdr.flags & DNS_RCODE_MASK);
                    	return;
                	}

                	printOutcome(pDnsRsp, false);
                	pRRLE = pRRLE->next;
            	}
			}
			break;
		case DNS_QUERY_STATUS_FAIL:
			logError("fails to dnsQuery, qName=%r, status = %d.", qName, qStatus);
			goto EXIT;
			break;
	}

EXIT:
	return;
};


static void dnsTestCallback(dnsResResponse_t* pRR, void* pData)
{
	if(!pRR)
	{
		logError("null pointer, pRR");
		return;
	}

	switch(pRR->rrType)
	{
		case DNS_RR_DATA_TYPE_STATUS:
			debug("query response is status, status=%d", pRR->status);
			break;
    	case DNS_RR_DATA_TYPE_MSG:
		{
			debug("query response is DNS_RR_DATA_TYPE_MSG");

			debug("qName=%s, qType=%d, pData=%p", pRR->pDnsRsp->query.qName, pRR->pDnsRsp->query.qType, pData);

			if(pRR->pDnsRsp->hdr.flags & DNS_RCODE_MASK != DNS_RCODE_NO_ERROR)
			{
				debug("query response error=%d", pRR->pDnsRsp->hdr.flags & DNS_RCODE_MASK);
				return;
			}

			printOutcome(pRR->pDnsRsp, true);
			break;
		}
		case DNS_RR_DATA_TYPE_MSGLIST:
		{
            debug("query response is DNS_RR_DATA_TYPE_MSGLIST");

			osListElement_t* pRRLE = pRR->dnsRspList.head;
			while(pRRLE)
			{
				dnsMessage_t* pDnsRsp = pRRLE->data;
	            debug("qName=%s, qType=%d, pData=%p", pDnsRsp->query.qName, pDnsRsp->query.qType, pData);

	            if(pDnsRsp->hdr.flags & DNS_RCODE_MASK != DNS_RCODE_NO_ERROR)
    	        {
        	        debug("query response error=%d", pDnsRsp->hdr.flags & DNS_RCODE_MASK);
            	    return;
            	}

				printOutcome(pDnsRsp, false);
				pRRLE = pRRLE->next;
			}
			break;
		}
	}

	return;
}


static void printOutcome(dnsMessage_t* pDnsRsp, bool isUntilA)
{
	switch(pDnsRsp->query.qType)
	{
		case DNS_QTYPE_A:
		{
#if 0
			osIpPort_t ipPort={{"93.184.216.34", strlen("93.184.216.34")}, 0};
			struct sockaddr_in sockAddr;
			osConvertPLton(&ipPort, false, &sockAddr);
			debug("sockAddr.sin_addr.s_addr=0x%x for 93.184.216.34", sockAddr.sin_addr.s_addr);
#endif
			debug("DNS_QTYPE_A, anCount=%d", pDnsRsp->hdr.anCount);
			osListElement_t* pLE = pDnsRsp->answerList.head;
			int i=0;
			while(pLE)
			{
				dnsRR_t* pDnsRR = pLE->data;
				struct sockaddr_in rxSockAddr;
				rxSockAddr.sin_addr = pDnsRR->ipAddr;
				rxSockAddr.sin_port=0;
				rxSockAddr.sin_family = AF_INET;
				debug("i=%d, ttl=%d, ipAddr.sin_addr.s_addr=0x%x, ip=%A", i++, pDnsRR->ttl, pDnsRR->ipAddr.s_addr, &rxSockAddr);
				pLE = pLE->next;
			}
			break;
		}
		case DNS_QTYPE_SRV:
		{
			osListElement_t* pLE = pDnsRsp->answerList.head;
			int i=0;
          	while(pLE)
          	{
				int isAFound = false;
				dnsRR_t* pDnsRR = pLE->data;
				debug("SRV, i=%d, type=%d, rrClase=%d, ttl=%d, priority=%d, weight=%d, port=%d, target=%s", i++, pDnsRR->type, pDnsRR->rrClass, pDnsRR->ttl, pDnsRR->srv.priority, pDnsRR->srv.weight, pDnsRR->srv.port, pDnsRR->srv.target);
				
				if(!isUntilA)
				{				
	                pLE = pLE->next;
					continue;
				}

				osListElement_t* pARLE = pDnsRsp->addtlAnswerList.head;
				int j=0;
				while(pARLE)
				{
					dnsRR_t* pARDnsRR = pARLE->data;
					if(pARDnsRR->type != DNS_QTYPE_A)
					{
						continue;
					}

					if(strcasecmp(pARDnsRR->name, pARDnsRR->srv.target) == 0)
					{
						debug("A record, in addtlAnswer[%d], uri=%s", j, pARDnsRR->name);
						struct sockaddr_in rxSockAddr;
						rxSockAddr.sin_addr = pARDnsRR->ipAddr;
						rxSockAddr.sin_port=0;
						rxSockAddr.sin_family = AF_INET;
						debug("addtlAnswer[%d], ttl=%d, ipAddr.sin_addr.s_addr=0x%x, ip=%A", j, pARDnsRR->ttl, pARDnsRR->ipAddr.s_addr, &rxSockAddr);
						isAFound = true;
						break;
					}
					pARLE = pARLE->next;
				}

				if(!isAFound)
				{
					osVPointerLen_t* qName = osmalloc(sizeof(osVPointerLen_t), NULL);
    				qName->pl.p = pDnsRR->srv.target;
    				qName->pl.l = strlen(qName->pl.p);
    				qName->isPDynamic = false;
    				qName->isVPLDynamic = true;
					dnsResResponse_t* pDnsRR;
					dnsQueryStatus_e qStatus = dnsQuery(qName, DNS_QTYPE_A, false, true, &pDnsRR, dnsTestCallback, NULL);

				    switch(qStatus)
    				{
        				case DNS_QUERY_STATUS_ONGOING:
				            debug("dnsQuery(%r) is ongoing", qName);
            				break;
        				case DNS_QUERY_STATUS_DONE:
            				debug("dnsQuery(%r) is done.", qName);
            				if(pDnsRR->rrType == DNS_RR_DATA_TYPE_STATUS)
            				{
                				debug("rr status = %d", pDnsRR->status);
            				}
            				else if(pDnsRR->rrType == DNS_RR_DATA_TYPE_MSG)
            				{
                				debug("qName=%s, qType=%d, query done.", pDnsRR->pDnsRsp->query.qName, pDnsRR->pDnsRsp->query.qType);
            				}
            				else
            				{
                				osListElement_t* pLE = pDnsRR->dnsRspList.head;
                				while(pLE)
                				{
                    				dnsMessage_t* pDnsMsg = pLE->data;
                    				debug("qName=%s, qType=%d, query done.", pDnsMsg->query.qName, pDnsMsg->query.qType);
                    				pLE = pLE->next;
                				}
            				}
            				break;
        				case DNS_QUERY_STATUS_FAIL:
            				logError("fails to dnsQuery, qName=%r, status = %d.", qName, qStatus);
            				return;
            				break;
    				}
				}

				pLE = pLE->next;
			} 
			break;
		}
		case DNS_QTYPE_NAPTR:
		default:
			debug("query type=%d", pDnsRsp->query.qType);
			break;
	}					
}
