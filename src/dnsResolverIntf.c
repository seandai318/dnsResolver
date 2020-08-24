/* Copyright 2020, 2019, Sean Dai
 */


#include <string.h>

#include "osMemory.h"
#include "osList.h"

#include "dnsResolverIntf.h"
#include "dnsResolver.h"
#include "dnsRecurQuery.h"



osStatus_e dnsInit(uint32_t rrBucketSize, uint32_t qBucketSize, dnsServerConfig_t* pDnsServerConfig)
{
	return dnsResolverInit(rrBucketSize, qBucketSize, pDnsServerConfig);
}


dnsQueryStatus_e dnsQuery(osVPointerLen_t* qName, dnsQType_e qType, bool isResolveAll, bool isCacheRR, dnsResResponse_t** ppResResponse, dnsResolver_callback_h rrCallback, void* pData)
{
	dnsQueryStatus_e qStatus = DNS_QUERY_STATUS_DONE;
	dnsMessage_t* pDnsRspMsg = NULL;

	if(!qName || !ppResResponse)
	{
		logError("null pointer, qName=%p, ppResResponse=%p", qName, ppResResponse);
		qStatus = DNS_QUERY_STATUS_FAIL;
		goto EXIT;
	}

	*ppResResponse = NULL;
	dnsQCacheInfo_t* pQCache = NULL;
	dnsNextQCallbackData_t* pCbData = NULL;
	if(qType == DNS_QTYPE_A || !isResolveAll)
	{
		qStatus = dnsQueryInternal(qName, qType, isCacheRR, &pDnsRspMsg, &pQCache, rrCallback, pData);
	}
	else
	{
		pCbData = oszalloc(sizeof(dnsNextQCallbackData_t), dnsNextQCallbackData_cleanup);
	
		qStatus = dnsQueryInternal(qName, qType, isCacheRR, &pDnsRspMsg, &pQCache, dnsInternalCallback, pCbData);
	}

	switch(qStatus)
	{
		case DNS_QUERY_STATUS_ONGOING:
			if(isResolveAll)
			{
        		pCbData->pQNextInfo = osmalloc(sizeof(dnsNextQInfo_t), dnsNextQInfo_cleanup);
        		pCbData->pQNextInfo->pResResponse = oszalloc(sizeof(dnsResResponse_t), dnsResResponse_cleanup);
        		pCbData->pQNextInfo->pResResponse->rrType = DNS_RR_DATA_TYPE_MSGLIST;

				pCbData->pQNextInfo->origAppData.rrCallback = rrCallback;
				pCbData->pQNextInfo->origAppData.pAppData = pData;

				pCbData->pQCache = pQCache;
				osList_append(&pCbData->pQNextInfo->qCacheList, pQCache);
			}
			break;
		case DNS_QUERY_STATUS_DONE:
			if(pDnsRspMsg->query.qType == DNS_QTYPE_A || !isResolveAll)
			{
		        *ppResResponse = oszalloc(sizeof(dnsResResponse_t), dnsResResponse_cleanup);
        		(*ppResResponse)->rrType = DNS_RR_DATA_TYPE_MSG;
				(*ppResResponse)->pDnsRsp = pDnsRspMsg;
    		}
			else
			{
	            pCbData->pQNextInfo = osmalloc(sizeof(dnsNextQInfo_t), dnsNextQInfo_cleanup);
    	        pCbData->pQNextInfo->pResResponse = oszalloc(sizeof(dnsResResponse_t), dnsResResponse_cleanup);
     	        pCbData->pQNextInfo->pResResponse->rrType = DNS_RR_DATA_TYPE_MSGLIST;

          	    pCbData->pQNextInfo->origAppData.rrCallback = rrCallback;
               	pCbData->pQNextInfo->origAppData.pAppData = pData;

        		qStatus = dnsQueryNextLayer(pDnsRspMsg, pCbData);
		        switch(qStatus)
        		{
            		case DNS_QUERY_STATUS_ONGOING:
                		break;
            		case DNS_QUERY_STATUS_FAIL:
                		osList_delete(&pCbData->pQNextInfo->pResResponse->dnsRspList);
                		pCbData->pQNextInfo->pResResponse->rrType = DNS_RR_DATA_TYPE_STATUS;
                		pCbData->pQNextInfo->pResResponse->status = DNS_RES_ERROR_RECURSIVE;
                		*ppResResponse = pCbData->pQNextInfo->pResResponse;
						pCbData->pQNextInfo->pResResponse = NULL;

                		//if !pCbData->pQNextInfo->qCacheList), the last query response will free
                		if(osList_isEmpty(&pCbData->pQNextInfo->qCacheList))
                		{
                    		osfree(pCbData);
                		}
                		break;
            		case DNS_QUERY_STATUS_DONE:
                		*ppResResponse = pCbData->pQNextInfo->pResResponse;
                		pCbData->pQNextInfo->pResResponse = NULL;
                		osfree(pCbData);
                		break;
					default:
						break;
				}
			}
			break;
		case DNS_QUERY_STATUS_FAIL:
			if(isResolveAll)
			{
				osfree(pCbData);
			}
			break;
		default:
			break;
	}	

EXIT:
	return qStatus;
}
