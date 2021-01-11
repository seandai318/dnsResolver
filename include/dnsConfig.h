#ifndef __DNS_CONFIG_H
#define __DNS_CONFIG_H


#include "osSockAddr.h"
#include "osMisc.h"


#define DNS_MAX_SERVER_NUM      3


typedef struct {
    osIpPort_t ipPort;
    uint32_t priority;
} dnsServer_t;


typedef struct {
    dnsServer_t dnsServer[DNS_MAX_SERVER_NUM];
    int serverNum;
    osNodeSelMode_e serverSelMode;
	struct sockaddr_in localSockAddr;
	uint32_t rrHashSize;
	uint32_t qHashSize;
} dnsConfig_t;


typedef enum {
    DNS_XML_SERVER_IP,
    DNS_XML_SERVER_SET,
    DNS_XML_SERVER_PORT,
	DNS_XML_RESOLVER_IP,
    DNS_XML_Q_HASH_SIZE,
    DNS_XML_RR_HASH_SIZE,
	DNS_XML_MAX_SERVER_NUM,
	DNS_XML_WAIT_RSP_TIMER,
    DNS_XML_SERVER_PRIORITY,
    DNS_XML_SERVER_SEL_MODE,
	DNS_XML_QUARANTINE_TIMER,	
	DNS_XML_QUARANTINE_THRESHOLD,
	DNS_XML_MAX_ALLOWED_SERVER_PER_QUERY,
	DNS_XML_MAX_DATA_NAME_NUM,
} dnsConfig_xmlDataName_e;


#define DNS_MAX_ALLOWED_SERVER_NUM_PER_QUERY dnsConfig_getMaxAllowedServerPerQuery()	//default 2
#define DNS_WAIT_RESPONSE_TIMEOUT   dnsConfig_getWaitRspTimeout()		//default 3000
#define DNS_QUARANTINE_TIMEOUT      dnsConfig_getQuarantineTimeout()	//default 300000
#define DNS_MAX_SERVER_QUARANTINE_NO_RESPONSE_NUM   dnsConfig_getQuarantineThreshold()	//default 3


const dnsConfig_t* dns_getConfig();

const int dnsConfig_getMaxAllowedServerPerQuery();
const int dnsConfig_getWaitRspTimeout();
const int dnsConfig_getQuarantineTimeout();
const int dnsConfig_getQuarantineThreshold();

struct sockaddr_in dnsConfig_getLocalSockAddr();



#endif
