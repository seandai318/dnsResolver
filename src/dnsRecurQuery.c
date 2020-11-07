/* Copyright (c) 2019, 2020, Sean Dai
 *
 * This file implements recursive queries until either a A record is received or query error happens.
 * Sometimes when queries SRV or NAPTR, the DNS server just provides RR answer for the query type, does
 * not provide extra next layer information, like SRV/A answer for NAPTR, A answer for SRV, etc., in
 * the extra rr answer section.  In this case, the functions in this file query the dns server for the 
 * next layer query type.
 * A note, recursive query here means action i the dns resolver side, not the DNS server recursive query 
 * as implemented in the dns server side.
 */


#include <string.h>

#include "osMemory.h"
#include "osList.h"

#include "dnsResolverIntf.h"
#include "dnsResolver.h"
#include "dnsRecurQuery.h"



static bool isRspHasNextLayerQ(char* qName, dnsQType_e qType, osList_t* pAddtlAnswerList, osList_t* qNameList);


/* this function shall be called after receiving a query response.
 * when starting next layer of query, create a list that contains all qCaches of next layer query. 
 * that list is stores as a pData for dnsQueryIntyernal(). when query response comes, remove the qCache
 * from the list.  If next layer of query is required, add new query's qCache into the list.  So on so
 * forth, until the list size is 0, call back to the application
 *
 * pDnsRespMsg: the dns response from the previous query
 * pQCache: the dns qCache for the previous query
 */
dnsQueryStatus_e dnsQueryNextLayer(dnsMessage_t* pDnsRspMsg, dnsNextQCallbackData_t* pCbData)
{
	DEBUG_BEGIN
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
				char* qName = NULL;
				dnsQType_e qType = DNS_QTYPE_A;
				if(pDnsRspMsg->query.qType == DNS_QTYPE_SRV)
				{
					qName = pAnDnsRR->srv.target;
				}
				else
				{
					switch(pAnDnsRR->naptr.flags)
					{
						case DNS_NAPTR_FLAGS_A:
							qType = DNS_QTYPE_A;
							qName = pAnDnsRR->naptr.replacement;
							break;
						case DNS_NAPTR_FLAGS_S:
							qType = DNS_QTYPE_SRV;
							qName = pAnDnsRR->naptr.replacement;
							break;
                        case DNS_NAPTR_FLAGS_U:
                        case DNS_NAPTR_FLAGS_P:
                        default:
                            pAnLE = pAnLE->next;
                            continue;
                            break;
					}
				}

				osList_t aQNameList = {};
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
									//this must be rrType == DNS_RR_DATA_TYPE_MSGLIST case, as pDnsRspMsg here is the next layer query response
									osList_append(&pCbData->pQNextInfo->pResResponse->dnsRspList, pQCache);
									//osList_append(&pCbData->pQNextInfo->pResResponse->dnsRspList, pDnsRspMsg);
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
                                //free nextQName, dnsInternalCallback() will notify app and free memory
								osVPL_free(nextQName, true);
								goto EXIT;
							case DNS_QUERY_STATUS_DONE:
                            {
								//this must be rrType == DNS_RR_DATA_TYPE_MSGLIST case, as pDnsRspMsg here is the next layer query response
								osList_append(&pCbData->pQNextInfo->pResResponse->dnsRspList, pDnsMsg);
                                //osList_append(&pCbData->pQNextInfo->pResResponse->dnsRspList, pDnsRspMsg);

								//free nextQName
								osVPL_free(nextQName, true);

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
								//free nextQName
								osfree(nextQName);
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
	DEBUG_END
	return qStatus;
}


void dnsInternalCallback(dnsResResponse_t* pRR, void* pData)
{
	DEBUG_BEGIN
	if(!pData)
	{
		logError("null pointer, pData.");
		goto EXIT;
	}

	dnsNextQCallbackData_t* pCbData = pData;
	dnsQCacheInfo_t* pQCache = osList_deletePtrElement(&pCbData->pQNextInfo->qCacheList, pCbData->pQCache);	
	if(!pQCache)
	{
		logError("pQNextInfo->qCacheList does not contain pCbData->pQCache(%p), unexpected.", pCbData->pQCache);
		goto EXIT;
	}

	debug("pRR->rrType=%d", pRR->rrType);
	//rr.rrType can only be DNS_RR_DATA_TYPE_STATUS or DNS_RR_DATA_TYPE_MSG, as this is a callback for single query
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
			goto EXIT;	
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
				goto EXIT;
			}
			else
			{
				osList_append(&pCbData->pQNextInfo->pResResponse->dnsRspList, pRR->pDnsRsp);
			}
			break;
		case DNS_RR_DATA_TYPE_MSGLIST:
		default:
			logError("rr.rrType(%d) = DNS_RR_DATA_TYPE_MSGLIST or other unexpect value, this shall never happen.", pRR->rrType);
			goto EXIT;
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
	DEBUG_END
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
DEBUG_BEGIN
    int isFound = false;

	if(qType == DNS_QTYPE_SRV && !qNameList)
	{
		logError("qNameList is NULL for qType = DNS_QTYPE_SRV.");
		goto EXIT;
	}

	osListElement_t* pArLE = pAddtlAnswerList->head;
    while(pArLE)
    {
    	dnsRR_t* pArDnsRR = pArLE->data;
		debug("qName=%s, pArDnsRR->type=%d, qType=%d", qName, pArDnsRR->type, qType);

		//found the match for qName in the additional answer.  be noted for some qType, like SRV, there may have more than one match 
		//for qName, so need to continue search until the additional answer is completely searched
        if(pArDnsRR->type == qType && strcasecmp(pArDnsRR->name, qName) == 0)
        {
            debug("find a qName match in the addtlAnswer, uri=%s, qType=%d", pArDnsRR->name, qType);

			//for A query, assume only one answer per qName, so as soon as one match is found, return 
			if(qType == DNS_QTYPE_A)
			{
				isFound = true;
				goto EXIT;
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

EXIT:
DEBUG_END
	return isFound;
}


void dnsNextQCallbackData_cleanup(void* pData)
{
	if(!pData)
	{
		logError("null pointer, pData");
		return;
	}

	dnsNextQCallbackData_t* pCbData = pData;
	osfree(pCbData->pQNextInfo);
}


void dnsNextQInfo_cleanup(void* pData)
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


void dnsResResponse_cleanup(void* pData)
{
	if(!pData)
	{
		return;
	}

	/* the dnsMsg will be freed in dnsResolver.c after rrCache is timed out.  For app, it also does not need to 
     * to free the dnsMsg after using it within the call chain.  But a app wants to keep it, it has to refer it.
     */    
	dnsResResponse_t* pRR = pData;
	switch(pRR->rrType)
	{
		case DNS_RR_DATA_TYPE_MSGLIST:
			osList_clear(&pRR->dnsRspList);
			break;
		case DNS_RR_DATA_TYPE_MSG:
		case DNS_RR_DATA_TYPE_STATUS:
		default:
			break;
	}
}
