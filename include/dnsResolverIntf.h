/* Copyright 2020, Sean Dai
 */

#ifndef _DNS_RESOLVER_INTF_H
#define _DNS_RESOLVER_INTF_H


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "osMisc.h"
#include "osPL.h"
#include "osSockAddr.h"
#include "osList.h"



//implement RFC1035
//only support DNS_CLASS_IN=1 for CLASS and QCLASS
//support UDP only

#define DNS_QR_POS		15
#define DNS_OPCODE_POS	11
#define DNS_AA_POS		10
#define DNS_TC_POS		9
#define DNS_RD_POS		8
#define DNS_RA_POS		7
#define DNS_Z_POS		4
#define DNS_RCODE_POS	0	

#define DNS_QR_MASK		0x8000
#define DNS_OPCODE_MASK	0x7800
#define DNS_AA_MASK		0x0400
#define DNS_TC_MASK		0x0200
#define DNS_RD_MASK		0x0100
#define DNS_RA_MASK		0X0080
#define DNS_Z_MASK		0x0040
#define DNS_AN_AUTHED_MASK	0x0020
#define DNS_NOAUTH_DATA_MASK	0x0010
#define DNS_RCODE_MASK	0x000f

#define DNS_CLASS_IN  1

#define DNS_MAX_SERVER_NUM	3
#define DNS_MAX_ALLOWED_SERVER_NUM_PER_QUERY 2

#define DNS_WAIT_RESPONSE_TIMEOUT	3000
#define DNS_QUARANTINE_TIMEOUT		300000
#define DNS_MAX_SERVER_QUARANTINE_NO_RESPONSE_NUM	3

#define DNS_MAX_MSG_SIZE	512
#define DNS_MAX_NAME_SIZE    125		//max domain name size
#define DNS_MAX_DOMAIN_NAME_LABEL_SIZE	63
#define DNS_MAX_NAPTR_SERVICE_SIZE	64



typedef enum {
	DNS_RCODE_NO_ERROR = 0,
	DNS_RCODE_FORMAT_ERROR = 1,
	DNS_RCODE_SERVER_FAILURE = 2,
	DNS_RCODE_NAME_ERROR = 3,
	DNS_RCODE_NOT_IMPLEMENTED = 4,
	DNS_RCODE_REFUSED = 5,
	DNS_RCODE_FUTURE_USE = 6,
} dnsRcode_e;

typedef enum {
	DNS_RES_STATUS_OK,
	DNS_RES_ERROR_NO_RESPONSE,
	DNS_RES_ERROR_SOCKET,
	DNS_RES_ERROR_RECURSIVE,
	DNS_RES_ERROR_OTHER,
} dnsResStatus_e;


typedef enum {
    DNS_QUERY_STATUS_ONGOING,
    DNS_QUERY_STATUS_DONE,
    DNS_QUERY_STATUS_FAIL,
} dnsQueryStatus_e;


typedef enum {
    DNS_QTYPE_OTHER = -1,
    DNS_QTYPE_A = 1,
    DNS_QTYPE_SRV = 33,
    DNS_QTYPE_NAPTR = 35,
} dnsQType_e;


typedef enum {
	DNS_NAPTR_FLAGS_S,
	DNS_NAPTR_FLAGS_A,
	DNS_NAPTR_FLAGS_U,
	DNS_NAPTR_FLAGS_P,
	DNS_NAPTR_FLAGS_OTHER,	//not defined in rfc 2915 and not handled
} dnsNaptrFlags_e;


typedef struct {
	osIpPort_t ipPort;
	uint32_t priority;
} dnsServer_t;


typedef struct {
	dnsServer_t dnsServer[DNS_MAX_SERVER_NUM];
	int serverNum;
	osNodeSelMode_e serverSelMode;
} dnsServerConfig_t;


typedef struct {
	uint32_t priority;
	uint32_t weight;
	uint32_t port;
	char target[DNS_MAX_NAME_SIZE];
} dnsSrv_t;


typedef struct {
	uint16_t order;
	uint16_t pref;
	dnsNaptrFlags_e flags;
	osPointerLen_t service;
	osPointerLen_t regexp;
//	osPointerLen_t replacement;
	char replacement[DNS_MAX_NAME_SIZE];
} dnsNaptr_t;


typedef struct {
    uint16_t trId;
    uint16_t flags;
    uint16_t qdCount;
    uint16_t anCount;
    uint16_t nsCount;
    uint16_t arCount;
} dnsHdr_t;


typedef struct dnsQuestion {
	char qName[DNS_MAX_NAME_SIZE];
	uint16_t qType;
	uint16_t qClass;
} dnsQuestion_t;


typedef struct dnsRR {
	char name[DNS_MAX_NAME_SIZE];
	uint16_t type;
	uint16_t rrClass;
	uint32_t ttl;
	uint16_t rDataLen;
	union {
		struct in_addr ipAddr;
		dnsSrv_t srv;
		dnsNaptr_t naptr;
		osPointerLen_t other;
	};
} dnsRR_t;



/*
  dns message per rfc1035
    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+
*/
typedef struct dnsMessage {
    dnsHdr_t hdr;
    dnsQuestion_t query;
    osList_t answerList;        //dnsRR_t, list of answer rr
    osList_t authList;          //dnsRR_t, list of auth rr
    osList_t addtlAnswerList;   //dnsRR_t, list of additional answer rr
} dnsMessage_t;


typedef enum {
	DNS_RR_DATA_TYPE_STATUS,
	DNS_RR_DATA_TYPE_MSG,
	DNS_RR_DATA_TYPE_MSGLIST,
} dnsRRDType_e;


typedef struct {
	dnsRRDType_e rrType;
    union {
		dnsMessage_t* pDnsRsp;
        osList_t dnsRspList;    //each element contains dnsMessage_t*
        dnsResStatus_e status;
    };
} dnsResResponse_t;


//the callback receiver shall not free memory for qName and pDnsMsg
typedef void (*dnsResolver_callback_h)(dnsResResponse_t* pRR, void* pData);


osStatus_e dnsResolverInit(uint32_t rrBucketSize, uint32_t qBucketSize, dnsServerConfig_t* pDnsServerConfig);
dnsQueryStatus_e dnsQuery(osVPointerLen_t* qName, dnsQType_e qType, bool isResolveAll, bool isCacheRR, dnsResResponse_t** ppResResponse, dnsResolver_callback_h rrCallback, void* pData);

	
#endif