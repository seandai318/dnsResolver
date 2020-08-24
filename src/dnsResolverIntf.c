/* Copyright 2020, 2019, Sean Dai
 */


#include <string.h>

#include "osMemory.h"
#include "osList.h"

#include "dnsResolverIntf.h"
#include "dnsResolver.h"


typedef struct {
	dnsResResponse_t* pResResponse;
	dnsQAppInfo_t origAppData;
	osList_t qCacheList;	//each list contains dnsQCacheInfo_t
} dnsNextQInfo_t;


typedef struct {
	dnsNextQInfo_t* pQNextInfo;
	dnsQCacheInfo_t* pQCache;
} dnsNextQCallbackData_t;


static dnsQueryStatus_e dnsQueryNextLayer(dnsMessage_t* pDnsRespMsg, dnsNextQCallbackData_t* pCbData);
static void dnsInternalCallback(dnsResResponse_t* pRR, void* pData);
static bool isRspHasNextLayerQ(char* qName, dnsQType_e qType, osList_t* pAddtlAnswerList, osList_t* qNameList);
static void dnsNextQCallbackData_cleanup(void* pData);
static void dnsNextQInfo_cleanup(void* pData);
static void dnsResResponse_cleanup(void* pData);



dnsQueryStatus_e dnsQuery(osVPointerLen_t* qName, dnsQType_e qType, bool isResolveAll, bool isCacheRR, dnsResResponse_t** ppResResponse, dnsResolver_callback_h rrCallback, void* pData)
{
	dnsQueryStatus_e qStatus = DNS_QUERY_STATUS_DONE;
	dnsMessage_t* pDnsRspMsg = NULL;

	if(!qName || ppResResponse)
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



/* this function shall be called after receiving a query response.
 * when starting next layer of query, create a list that contains all qCaches of next layer query. 
 * that list is stores as a pData for dnsQueryIntyernal(). when query response comes, remove the qCache
 * from the list.  If next layer of query is required, add new query's qCache into the list.  So on so
 * forth, until the list size is 0, call back to the application
 *
 * pDnsRespMsg: the dns response from the previous query
 * pQCache: the dns qCache for the previous query
 */
static dnsQueryStatus_e dnsQueryNextLayer(dnsMessage_t* pDnsRspMsg, dnsNextQCallbackData_t* pCbData)
{
	dnsQueryStatus_e qStatus = DNS_QUERY_STATUS_DONE;

    switch(pDnsRspMsg->query.qType)
    {
        case DNS_QTYPE_A:
			//no need to handle DNS_QTYPE_A
            goto EXIT;
            break;
        case DNS_QTYPE_SRV:
		case DNS_QTYPE_NAPTR:
        {
            osListElement_t* pAnLE = pDnsRspMsg->answerList.head;
            while(pAnLE)
            {
				dnsRR_t* pAnDnsRR = pAnLE->data;
				char* qName = pDnsRspMsg->query.qType == DNS_QTYPE_SRV ? pAnDnsRR->srv.target : pAnDnsRR->naptr.replacement;
				dnsQType_e qType = pDnsRspMsg->query.qType == DNS_QTYPE_SRV ? DNS_QTYPE_A : DNS_QTYPE_SRV;
				osList_t aQNameList;
				bool isFound = isRspHasNextLayerQ(qName, qType, &pDnsRspMsg->addtlAnswerList, &aQNameList);

                if(!isFound)
                {
                    dnsMessage_t* pDnsMsg = NULL;
                    dnsQCacheInfo_t* pQCache = NULL;
					osVPointerLen_t* nextQName = NULL;

					//the next layer qName can be qName, or a element inside aQNameList (when aQNameList is not empty).  The qType
					//for aQNameList is always DNS_QTYPE_A
					if(!osList_isEmpty(&aQNameList))
					{
						osListElement_t* pLE = aQNameList.head;
						while(pLE)
						{
	                        nextQName = osmalloc(sizeof(osVPointerLen_t), NULL);
    	                    nextQName->pl.p = pLE->data;
        	                nextQName->pl.l = strlen(nextQName->pl.p);
            	            nextQName->isPDynamic = false;
                	        nextQName->isVPLDynamic = true;

                    		qStatus = dnsQueryInternal(nextQName, DNS_QTYPE_A, true, &pDnsMsg, &pQCache, dnsInternalCallback, pCbData);
							switch(qStatus)
                    		{
								case DNS_QUERY_STATUS_FAIL:
									//do nothing, dnsInternalCallback() will notify app and free memory
									goto EXIT;
								case DNS_QUERY_STATUS_DONE:
								{
									osList_append(&pCbData->pQNextInfo->pResResponse->dnsRspList, pDnsRspMsg);
									if(pDnsMsg->query.qType == DNS_QTYPE_SRV)
									{
										qStatus = dnsQueryNextLayer(pDnsMsg, pCbData);
									}
                    				break;
								}
								case DNS_QUERY_STATUS_ONGOING:
									//no need to ref pQCache, as if dnsResolver times out for pQCache, it will have to do callback first
                        			pCbData->pQCache = pQCache;
                        			osList_append(&pCbData->pQNextInfo->qCacheList, pQCache);
									break;
								default:
									break;
							}

							pLE = pLE->next;
						}
					}
					else
					{
                        nextQName = osmalloc(sizeof(osVPointerLen_t), NULL);
                        nextQName->pl.p = qName;
                        nextQName->pl.l = strlen(nextQName->pl.p);
                        nextQName->isPDynamic = false;
                        nextQName->isVPLDynamic = true;

                       	qStatus = dnsQueryInternal(nextQName, qType, true, &pDnsMsg, &pQCache, dnsInternalCallback, pCbData);
						switch(qStatus)
                        {
                            case DNS_QUERY_STATUS_FAIL:					
                                //do nothing, dnsInternalCallback() will notify app and free memory
								goto EXIT;
							case DNS_QUERY_STATUS_DONE:
                            {
                                osList_append(&pCbData->pQNextInfo->pResResponse->dnsRspList, pDnsRspMsg);
                                if(pDnsMsg->query.qType == DNS_QTYPE_SRV)
                                {
                                    qStatus = dnsQueryNextLayer(pDnsMsg, pCbData);
                                }
                                break;
							}
                            case DNS_QUERY_STATUS_ONGOING:
                                pCbData->pQCache = pQCache;
                                osList_append(&pCbData->pQNextInfo->qCacheList, pQCache);
                                break;
                            default:
                                break;
                        }
                	}
				}

                pAnLE = pAnLE->next;
            }
            break;
        }
        default:
            break;
    }

EXIT:
	return qStatus;
}


static void dnsInternalCallback(dnsResResponse_t* pRR, void* pData)
{
	if(!pData)
	{
		logError("null pointer, pData.");
		return;
	}

	dnsNextQCallbackData_t* pCbData = pData;
	dnsQCacheInfo_t* pQCache = osList_deletePtrElement(&pCbData->pQNextInfo->qCacheList, pCbData->pQCache);	
	if(!pQCache)
	{
		logError("pQNextInfo->qCacheList does not contain pCbData->pQCache(%p), unexpected.", pCbData->pQCache);
		return;
	}

	//rr.rrType can only be DNS_RR_DATA_TYPE_STATUS or DNS_RR_DATA_TYPE_MSG
	switch(pRR->rrType)
	{
		case DNS_RR_DATA_TYPE_STATUS:
			if(pCbData->pQNextInfo->pResResponse->rrType != DNS_RR_DATA_TYPE_STATUS)
			{
				osList_delete(&pCbData->pQNextInfo->pResResponse->dnsRspList);
				pCbData->pQNextInfo->pResResponse->rrType = DNS_RR_DATA_TYPE_STATUS;
				pCbData->pQNextInfo->pResResponse->status = pRR->status;
	
				//expect app to refer pCbData->pQNextInfo->pResResponse if it wants to keep the data response
                pCbData->pQNextInfo->origAppData.rrCallback(pCbData->pQNextInfo->pResResponse, pCbData->pQNextInfo->origAppData.pAppData);

                osfree(pCbData);
			}
			return;	
			break;			
		case DNS_RR_DATA_TYPE_MSG:
			//if there is already error, stop further processing, app has been notified when DNS_RR_DATA_TYPE_STATUS was first set, here no need to notify app any more
			if(pCbData->pQNextInfo->pResResponse->rrType == DNS_RR_DATA_TYPE_STATUS)
			{
		        if(osList_isEmpty(&pCbData->pQNextInfo->qCacheList))
        		{
            		osfree(pCbData);
        		}
				osfree(pRR->pDnsRsp);
				return;
			}
			else
			{
				osList_append(&pCbData->pQNextInfo->pResResponse->dnsRspList, pRR->pDnsRsp);
			}
			break;
		case DNS_RR_DATA_TYPE_MSGLIST:
		default:
			logError("rr.rrType(%d) = DNS_RR_DATA_TYPE_MSGLIST or other unexpect value, this shall never happen.", pRR->rrType);
			return;
			break;
	}

	//here we only handle rr.rrType == DNS_RR_DATA_TYPE_MSG && pCbData->pQNextInfo->pResResponse->rrType != DNS_RR_DATA_TYPE_STATUS case	
    dnsQueryStatus_e qStatus = DNS_QUERY_STATUS_DONE;
	if(pRR->pDnsRsp->query.qType != DNS_QTYPE_A)
	{
		qStatus = dnsQueryNextLayer(pRR->pDnsRsp, pCbData);
    }

	switch(qStatus)
	{
		case DNS_QUERY_STATUS_ONGOING:
			break;
    	case DNS_QUERY_STATUS_DONE:
			if(osList_isEmpty(&pCbData->pQNextInfo->qCacheList))
			{
                //expect app to refer pCbData->pQNextInfo->pResResponse if it wants to keep the data response
				pCbData->pQNextInfo->origAppData.rrCallback(pCbData->pQNextInfo->pResResponse, pCbData->pQNextInfo->origAppData.pAppData);

				osfree(pCbData);
			}
			break;
    	case DNS_QUERY_STATUS_FAIL:
			osList_delete(&pCbData->pQNextInfo->pResResponse->dnsRspList);

 			pCbData->pQNextInfo->pResResponse->rrType = DNS_RR_DATA_TYPE_STATUS;
			pCbData->pQNextInfo->pResResponse->status = DNS_RES_ERROR_RECURSIVE;	
		
            if(osList_isEmpty(&pCbData->pQNextInfo->qCacheList))
            {
                //expect app to refer pCbData->pQNextInfo->pResResponse if it wants to keep the data response
                pCbData->pQNextInfo->origAppData.rrCallback(pCbData->pQNextInfo->pResResponse, pCbData->pQNextInfo->origAppData.pAppData);

                osfree(pCbData);
            }
            break;
	}

EXIT:
	return;
}


/* This function try to find the next layer query answer in the additonal answer rr.  if the next layer query is found, then this 
 * function will continue to search for next next layer until either the query is a DNS_QTYPE_A or query answer does not find.  
 * If the function returns FALSE, and qNameList is not empty, all qname in the qNameList need to be queried, the future query type 
 * shall be DNS_QTYPE_A (given we only support NAPTR, SRV and A queries.  If in the future this function supports a query type that
 * is more than 3 layers deeper, or if the deepest query type is not DNS_QTYPE_A, then qNameList shall contain qType info, together 
 * with qName.).  if the function returns FALSE, and qNameList is empty, then the future query is qName and query type is qType
 * as appear in the function prototype. 
 * 
 * qName: the qName for next layer query.  For example, if a naptr query resonse calls this function, qName will be the replacement
 *        of the naptr query response.  if a SRV query reponse calls this function, qname is the target of the srv query response.
 * qType: the query type for next layer query.  for example, if SRV query calls this function, the query type will be DNS_QTYPE_A.
 * pAddtlAnswerList: the additional answer RR of the query response that calls this function
 * qNameList: list of next next layer query name.  For example, a naptr query calls this function, and passes in a SRV qname.  If
 * the attitonl answer does not contain the SRV qname, then the qNameList will be empty, the return value will be FALSE.  But if
 * the additional answer rr has one or more answers for the SRV qname, this function will continue to search the DNS_QTYPE_A  
 * answer for the corresponding SRV targets.  If not found, the unfound target will be put into the qNameList, and the return value
 * will be FALSE, even though SRV answer was found
 */
static bool isRspHasNextLayerQ(char* qName, dnsQType_e qType, osList_t* pAddtlAnswerList, osList_t* qNameList)
{
	if(qType == DNS_QTYPE_SRV && !qNameList)
	{
		logError("qNameList is NULL for qType = DNS_QTYPE_SRV.");
		return false;
	}

	int isFound = false;
	osListElement_t* pArLE = pAddtlAnswerList->head;
    while(pArLE)
    {
    	dnsRR_t* pArDnsRR = pArLE->data;
        if(pArDnsRR->type != qType)
        {
	        continue;
		}

		//found the match for qName in the additional answer.  be noted for some qType, like SRV, there may have more than one match 
		//for qName, so need to continue search until the additional answer is completely searched
        if(strcasecmp(pArDnsRR->name, qName) == 0)
        {
debug("A record, in addtlAnswer, uri=%s", pArDnsRR->name);

			//for A query, assume only one answer per qName, so as soon as one match is found, return 
			if(qType == DNS_QTYPE_A)
			{
				return true;
			}

			//for SRV, needs to check next layer, which is A query layer.  note the whole additional answer rr is to be searched until one is found
			if(qType == DNS_QTYPE_SRV)
			{
				isFound = isRspHasNextLayerQ(pArDnsRR->srv.target, DNS_QTYPE_A, pAddtlAnswerList, NULL);
				if(!isFound)
				{
					osList_append(qNameList, pArDnsRR->srv.target);
				}
			}
        }
        pArLE = pArLE->next;
    }

	//if there are multiple qname entries, some are in the additional answer rr, some are not, mark isFound = false
	if(isFound && !osList_isEmpty(qNameList))
	{
		isFound = false;
	}

	return isFound;
}


static void dnsNextQCallbackData_cleanup(void* pData)
{
	if(!pData)
	{
		logError("null pointer, pData");
		return;
	}

	dnsNextQCallbackData_t* pCbData = pData;
	osfree(pCbData->pQNextInfo);
}


static void dnsNextQInfo_cleanup(void* pData)
{
    if(!pData)
    {
        logError("null pointer, pData");
        return;
    }

	dnsNextQInfo_t* pNQInfo = pData;
	osList_clear(&pNQInfo->qCacheList);
	//if app needs pNQInfo->pResResponse, they shall refer the data structure
    osfree(pNQInfo->pResResponse);
}


static void dnsResResponse_cleanup(void* pData)
{
	if(!pData)
	{
		return;
	}

    /* there was consideration to let app to free pDnsMsg.  But realize there may have multiple requests for a pDnsMsg, 
	 * to make thing easier just let this function to free pDnsMsg.  if app wants to keep pDnsMsg, it has to save by 
	 * itself.  With this approach, the pDnsMsg also does not need to refer the raw DNS response (osMBuf_t) in its data 
	 * structure for query typyes like NAPTR (it has osPointerLen_t parameters that points to bytes in osMBuf.
	 */
	dnsResResponse_t* pRR = pData;
	switch(pRR->rrType)
	{
		case DNS_RR_DATA_TYPE_MSG:
			osfree(pRR->pDnsRsp);
			break;
		case DNS_RR_DATA_TYPE_MSGLIST:
			osList_delete(&pRR->dnsRspList);
			break;
		case DNS_RR_DATA_TYPE_STATUS:
		default:
			break;
	}
}
