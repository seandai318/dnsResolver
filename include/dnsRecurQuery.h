/* Copyright 2020, 2019, Sean Dai
 */

#ifndef _DNS_RECUR_QUERY_H
#define _DNS_RECUR_QUERY_H


#include "dnsResolverIntf.h"


typedef struct {
    dnsResResponse_t* pResResponse;
    dnsQAppInfo_t origAppData;
    osList_t qCacheList;    //each list contains dnsQCacheInfo_t
} dnsNextQInfo_t;


typedef struct {
    dnsNextQInfo_t* pQNextInfo;
    dnsQCacheInfo_t* pQCache;
} dnsNextQCallbackData_t;


dnsQueryStatus_e dnsQueryNextLayer(dnsMessage_t* pDnsRespMsg, dnsNextQCallbackData_t* pCbData);
void dnsInternalCallback(dnsResResponse_t* pRR, void* pData);
void dnsNextQCallbackData_cleanup(void* pData);
void dnsNextQInfo_cleanup(void* pData);
void dnsResResponse_cleanup(void* pData);


#endif
