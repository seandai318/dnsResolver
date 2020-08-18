#include <string.h>
#include <arpa/inet.h>

#include "osSockAddr.h"
#include "osMisc.h"
#include "osPL.h"
#include "osMemory.h"
#include "osSockAddr.h"

#include "dnsResolver.h"


static void dnsTestCallback(osPointerLen_t* qName, dnsQType_e qType, const dnsResResponse_t rr, void* pData);


void dnsTest()
{
    dnsServerConfig_t dnsServerConfig;
    dnsServerConfig.serverNum = 1;
    dnsServerConfig.serverSelMode = OS_NODE_SELECT_MODE_PRIORITY;
    dnsServerConfig.dnsServer[0].ipPort.ip.pl.p = "192.168.1.254";
    dnsServerConfig.dnsServer[0].ipPort.ip.pl.l = strlen("192.168.1.254");
    dnsServerConfig.dnsServer[0].ipPort.port = 53;
    dnsServerConfig.dnsServer[0].ipPort.ip.isVPLDynamic = false;
    dnsServerConfig.dnsServer[0].ipPort.ip.isPDynamic = false;
    dnsServerConfig.dnsServer[0].priority = 10;

    dnsResolverInit(64, 64, &dnsServerConfig);

	debug("dnsResolver is initialized");

    //perform dns testing
//    osVPointerLen_t qName = {{"ims.globalstar.com.mnc970.mcc310.gprs", strlen("ims.globalstar.com.mnc970.mcc310.gprs")}, false, false};
    osVPointerLen_t* qName = osmalloc(sizeof(osVPointerLen_t), NULL);
	qName->pl.p ="example.com";
	qName->pl.l = strlen("example.com");
	qName->isPDynamic = false;
	qName->isVPLDynamic = true;
    dnsMessage_t* pDnsMsg = NULL;
    osStatus_e status = dnsQuery(qName, DNS_QTYPE_A, true, &pDnsMsg, dnsTestCallback, NULL);
	if(status != OS_STATUS_OK)
	{
		logError("fails to dnsQuery, status = %d.", status);
		goto EXIT;
	}

	if(pDnsMsg)
	{
		logInfo("received pDnsMsg.");
		goto EXIT;
	}

EXIT:
	return;
};


static void dnsTestCallback(osPointerLen_t* qName, dnsQType_e qType, const dnsResResponse_t rr, void* pData)
{
	debug("qName=%r, qType=%d, pData=%p", qName, qType, pData);
	debug("rr.isStatus=%d, rr.status=%d, rr.dnsMsg=%p", rr.isStatus, rr.status, rr.pDnsMsg);
	if(rr.isStatus)
	{
		debug("query error status = %d", rr.status);
		return;
	}

	if(rr.pDnsMsg->hdr.flags & DNS_RCODE_MASK != DNS_RCODE_NO_ERROR)
	{
		debug("query response error=%d", rr.pDnsMsg->hdr.flags & DNS_RCODE_MASK);
		return;
	}

	switch(rr.pDnsMsg->query.qType)
	{
		case DNS_QTYPE_A:
		{
			osIpPort_t ipPort={{"93.184.216.34", strlen("93.184.216.34")}, 0};
			struct sockaddr_in sockAddr;
			osConvertPLton(&ipPort, false, &sockAddr);
			debug("sockAddr.sin_addr.s_addr=0x%x for 93.184.216.34", sockAddr.sin_addr.s_addr);

			debug("DNS_QTYPE_A, anCount=%d", rr.pDnsMsg->hdr.anCount);
			for(int i=0; i<rr.pDnsMsg->hdr.anCount; i++)
			{
				struct sockaddr_in rxSockAddr;
				rxSockAddr.sin_addr = rr.pDnsMsg->answer[i].ipAddr;
				rxSockAddr.sin_port=0;
				rxSockAddr.sin_family = AF_INET;
				debug("i=%d, ttl=%d, ipAddr.sin_addr.s_addr=0x%x, ip=%A", i, rr.pDnsMsg->answer[i].ttl, rr.pDnsMsg->answer[i].ipAddr.s_addr, &rxSockAddr);
			}
			break;
		}
		case DNS_QTYPE_SRV:
		case DNS_QTYPE_NAPTR:
		default:
			debug("query type=%d", rr.pDnsMsg->query.qType);
			break;
	}				
}

