/* Copyright 2020, Sean Dai
 */

#ifndef _DNS_RESOLVER_H
#define _DNS_RESOLVER_H

#include "osMBuf.h"

#include "dnsResolverIntf.h"

typedef struct {
    dnsResolver_callback_h rrCallback;
    void* pAppData;
} dnsQAppInfo_t;


typedef struct {
    struct sockaddr_in socketAddr;
    uint8_t priority;
    uint8_t noRspCount;     //the continuous query no response count, the count will be reset to 0 any time got a response. e.g., if query A, B, C, D, A no response, count=1, B no response, count=2, C response, count=0, D no response, count=1, etc.
    uint64_t quarantineTimerId; //!=0 when the server is quarantined
} dnsServerInfo_t;


typedef struct {
    osVPointerLen_t* qName;
    dnsQType_e qType;
    bool isCacheRR;
    uint16_t qTrId;
    uint8_t serverQueried;      //how many servers has this query used due to earlier query failure
    osMBuf_t* pBuf;             //query mBuf
    dnsServerInfo_t* pServerInfo;
    uint64_t waitForRespTimerId;
    osList_t appDataList;       //each element contains dnsQAppInfo_t, list of app Data received when app requesting dns service, need to pass back in rrCallback. one element per request
    osListElement_t* pHashElement;  //points to the qCache element stores this node
} dnsQCacheInfo_t;


typedef struct {
    dnsMessage_t* pDnsMsg;
    uint64_t ttlTimerId;
    osListElement_t* pHashElement;
} dnsRRCacheInfo_t;


typedef struct {
    osNodeSelMode_e serverSelMode;
    dnsServerInfo_t serverInfo[DNS_MAX_SERVER_NUM];
    int serverNum;
    uint64_t curNodeSelIdx;     //only applicable if serverSelMode=OS_NODE_SELECT_MODE_ROUND_ROBIN
} dnsServerSelInfo_t;


dnsQueryStatus_e dnsQueryInternal(osVPointerLen_t* qName, dnsQType_e qType, bool isCacheRR, dnsMessage_t** qResponse, dnsQCacheInfo_t** ppQCache, dnsResolver_callback_h rrCallback, void* pData);


#endif

