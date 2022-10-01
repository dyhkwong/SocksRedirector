/**
*	This sample redirects TCP/UDP traffic to the specified SOCKS5 proxy.
**/

#include "stdafx.h"
#include <ws2tcpip.h>
#include <crtdbg.h>
#include <process.h>
#include <map>
#include <queue>
#include "nfapi.h"
#include "sync.h"
#include "UdpProxy.h"
#include "TcpProxy.h"
#include "utf8.h"

using namespace nfapi;

#if defined(_DEBUG) || defined(_RELEASE_LOG)
DBGLogger DBGLogger::dbgLog;
#endif

// Change this string after renaming and registering the driver under different name
#define NFDRIVER_NAME "netfilter2"

typedef std::vector<std::string> tStrings;

unsigned char	g_proxyAddress[NF_MAX_ADDRESS_LENGTH];
unsigned char	g_dnsAddress[NF_MAX_ADDRESS_LENGTH];
tStrings	g_processNamesAllow;
tStrings	g_processNamesFilter;
std::string g_userName;
std::string g_userPassword;

bool redirectDns;

inline bool safe_iswhitespace(int c) { return (c == (int) ' ' || c == (int) '\t' || c == (int) '\r' || c == (int) '\n'); }

std::string trimWhitespace(std::string str)
{
	while (str.length() > 0 && safe_iswhitespace(str[0]))
	{
		str.erase(0, 1);
	}

	while (str.length() > 0 && safe_iswhitespace(str[str.length()-1]))
	{
		str.erase(str.length()-1, 1);
	}

	return str;
}

bool parseValue(const std::string & _s, tStrings & v)
{
	std::string sPart;
	size_t pos;
	std::string s = _s;

	v.clear();

	while (!s.empty()) 
	{
		pos = s.find(",");
	
		if (pos == std::string::npos)
		{
			sPart = trimWhitespace(s);
			s.erase();
		} else
		{
			sPart = trimWhitespace(s.substr(0, pos));
			s.erase(0, pos+1);
		}
		
		if (!sPart.empty())
		{
			v.push_back(sPart);
		}
	}

	return true;
}


static std::string getProcessName(DWORD processId)
{
    wchar_t processName[512] = L"";
    wchar_t fullProcessName[512] = L"";
    BOOL nameAcquired = FALSE;

	if (processId == 4)
	{
		return "system";
	}

    nameAcquired = nf_getProcessNameFromKernel(processId, processName, sizeof(processName)/2);

    if (nameAcquired)
    {
        if (!GetLongPathNameW(processName, 
                fullProcessName, 
                (DWORD)ARRAYSIZE(fullProcessName)))
        {
            wcscpy(fullProcessName, processName);
        }
    }

    return encodeUTF8(fullProcessName);
}

bool checkProcessNameInAllow(DWORD processId)
{
	std::string processName = getProcessName(processId);

	size_t processNameLen = processName.length();

	for (size_t i=0; i<g_processNamesAllow.size(); i++)
	{
		if (g_processNamesAllow[i].length() > processNameLen)
			continue;

		if (stricmp(g_processNamesAllow[i].c_str(), processName.c_str() + processNameLen - g_processNamesAllow[i].length()) == 0)
			return true;
	}

	return false;
}

bool checkProcessNameInFilter(DWORD processId)
{
	std::string processName = getProcessName(processId);

	size_t processNameLen = processName.length();

	for (size_t i=0; i<g_processNamesFilter.size(); i++)
	{
		if (g_processNamesFilter[i].length() > processNameLen)
			continue;

		if (stricmp(g_processNamesFilter[i].c_str(), processName.c_str() + processNameLen - g_processNamesFilter[i].length()) == 0)
			return true;
	}

	return false;
}

struct DNS_REQUEST
{
	DNS_REQUEST(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options)
	{
		m_id = id;

		memcpy(m_remoteAddress, remoteAddress, NF_MAX_ADDRESS_LENGTH);

		if (buf)
		{
			m_buf = new char[len];
			memcpy(m_buf, buf, len);
			m_len = len;
		} else
		{
			m_buf = NULL;
			len = 0;
		}

		if (options)
		{
			m_options = (PNF_UDP_OPTIONS)new char[sizeof(NF_UDP_OPTIONS) + options->optionsLength];
			memcpy(m_options, options, sizeof(NF_UDP_OPTIONS) + options->optionsLength - 1);
		} else
		{
			m_options = NULL;
		}
	}

	~DNS_REQUEST()
	{
		if (m_buf)
			delete[] m_buf;
		if (m_options)
			delete[] m_options;
	}

	ENDPOINT_ID m_id;
	unsigned char m_remoteAddress[NF_MAX_ADDRESS_LENGTH];
	char * m_buf;
	int m_len;
	PNF_UDP_OPTIONS m_options;
};

class DnsResolver
{
public:
	DnsResolver()
	{
		m_stopEvent.Attach(CreateEvent(NULL, TRUE, FALSE, NULL));
	}

	~DnsResolver()
	{
		free();
	}

	bool init(int threadCount)
	{
		HANDLE hThread;
		unsigned threadId;
		int i;

		ResetEvent(m_stopEvent);

		if (threadCount <= 0)
		{
			SYSTEM_INFO sysinfo;
			GetSystemInfo( &sysinfo );

			threadCount = sysinfo.dwNumberOfProcessors;
			if (threadCount == 0)
			{
				threadCount = 1;
			}
		}

		for (i=0; i<threadCount; i++)
		{
			hThread = (HANDLE)_beginthreadex(0, 0,
						 _threadProc,
						 (LPVOID)this,
						 0,
						 &threadId);

			if (hThread != 0 && hThread != (HANDLE)(-1L))
			{
				m_threads.push_back(hThread);
			}
		}

		return true;
	}

	void free()
	{
		SetEvent(m_stopEvent);

		for (tThreads::iterator it = m_threads.begin();
			it != m_threads.end();
			it++)
		{
			WaitForSingleObject(*it, INFINITE);
			CloseHandle(*it);
		}

		m_threads.clear();

		while (!m_dnsRequestQueue.empty())
		{
			DNS_REQUEST * p = m_dnsRequestQueue.front();
			delete p;
			m_dnsRequestQueue.pop();
		}
	}

	void addRequest(DNS_REQUEST * pRequest)
	{
		AutoLock lock(m_cs);
		m_dnsRequestQueue.push(pRequest);
		SetEvent(m_jobAvailableEvent);
	}

protected:

	void handleRequest(DNS_REQUEST * pRequest, SOCKET s)
	{
		int len;
		int size = (((sockaddr*)g_dnsAddress)->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in);

		printf("DnsResolver::handleRequest() id=%I64u\n", pRequest->m_id);

		len = sendto(s, pRequest->m_buf, pRequest->m_len, 0, (sockaddr*)&g_dnsAddress, size);
		if (len != SOCKET_ERROR)
		{
			fd_set fdr, fde;
			timeval tv;

			FD_ZERO(&fdr);
			FD_SET(s, &fdr);
			FD_ZERO(&fde);
			FD_SET(s, &fde);

			tv.tv_sec = 2;
			tv.tv_usec = 0;

			len = select(1, &fdr, NULL, &fde, &tv);
			if (len != SOCKET_ERROR)
			{
				if (FD_ISSET(s, &fdr))
				{
					char result[1024];
					int fromLen;

					fromLen = size;
					len = recvfrom(s, result, (int)sizeof(result), 0, (sockaddr*)&g_dnsAddress, &fromLen);
					if (len != SOCKET_ERROR)
					{
						nf_udpPostReceive(pRequest->m_id,
							pRequest->m_remoteAddress,
							result,
							len,
							pRequest->m_options);

						printf("DnsResolver::handleRequest() id=%I64u succeeded, len=%d\n", pRequest->m_id, len);
					} else
					{
						printf("DnsResolver::handleRequest() id=%I64u recvfrom error=%d\n", pRequest->m_id, GetLastError());
					}
				} else
				{
					printf("DnsResolver::handleRequest() id=%I64u no data\n", pRequest->m_id);
				}
			} else
			{
				printf("DnsResolver::handleRequest() id=%I64u select error=%d\n", pRequest->m_id, GetLastError());
			}
		} else
		{
			printf("DnsResolver::handleRequest() id=%I64u sendto error=%d\n", pRequest->m_id, GetLastError());
		}

	}

	void threadProc()
	{
		HANDLE handles[] = { m_jobAvailableEvent, m_stopEvent };
		DNS_REQUEST * pRequest;

		SOCKET s;

		s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (s == INVALID_SOCKET)
			return;

		for (;;)
		{
			DWORD res = WaitForMultipleObjects(2, handles, FALSE, INFINITE);

			if (res == (WAIT_OBJECT_0+1))
				break;

			for (;;)
			{
				{
					AutoLock lock(m_cs);
					if (m_dnsRequestQueue.empty())
					{
						break;
					}

					pRequest = m_dnsRequestQueue.front();
					m_dnsRequestQueue.pop();
				}

				handleRequest(pRequest, s);

				delete pRequest;
			}
		}

		closesocket(s);
	}

	static unsigned WINAPI _threadProc(void* pData)
	{
		(reinterpret_cast<DnsResolver*>(pData))->threadProc();
		return 0;
	}

private:
	typedef std::vector<HANDLE> tThreads;
	tThreads m_threads;

	typedef std::queue<DNS_REQUEST*> tDnsRequestQueue;
	tDnsRequestQueue m_dnsRequestQueue;

	AutoEventHandle m_jobAvailableEvent;
	AutoHandle m_stopEvent;

	AutoCriticalSection m_cs;
};

DnsResolver g_dnsResolver;

// Forward declarations
void printAddrInfo(bool created, ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo);
void printConnInfo(bool connected, ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo);

struct UDP_CONTEXT
{
	UDP_CONTEXT(PNF_UDP_OPTIONS options)
	{
		if (options)
		{
			m_options = (PNF_UDP_OPTIONS)new char[sizeof(NF_UDP_OPTIONS) + options->optionsLength];
			memcpy(m_options, options, sizeof(NF_UDP_OPTIONS) + options->optionsLength - 1);
		} else
		{
			m_options = NULL;
		}
	}

	~UDP_CONTEXT()
	{
		if (m_options)
			delete[] m_options;
	}
	
	PNF_UDP_OPTIONS m_options;
};



//
//	API events handler
//
class EventHandler : public NF_EventHandler, public UdpProxy::UDPProxyHandler
{
	TcpProxy::LocalTCPProxy m_tcpProxy;

	typedef std::map<unsigned __int64, UDP_CONTEXT*> tUdpCtxMap;
	tUdpCtxMap m_udpCtxMap;

	UdpProxy::UDPProxy	m_udpProxy;

	typedef std::set<unsigned __int64> tIdSet;
	tIdSet m_filteredUdpIds;

	AutoCriticalSection m_cs;


public:

	bool init()
	{
		bool result = false;
		
		for (;;)
		{
			if (!m_udpProxy.init(this, 
				(char*)g_proxyAddress, 
				(((sockaddr*)g_proxyAddress)->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in),
				g_userName.empty()? NULL : g_userName.c_str(),
				g_userPassword.empty()? NULL : g_userPassword.c_str()))
			{
				printf("Unable to start UDP proxy");
				break;
			}

			if (!m_tcpProxy.init(htons(8888)))
			{
				printf("Unable to start TCP proxy");
				break;
			}

			m_tcpProxy.setProxy(0, TcpProxy::PROXY_SOCKS5, 
				(char*)g_proxyAddress, 
				(((sockaddr*)g_proxyAddress)->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in),
				g_userName.empty()? NULL : g_userName.c_str(),
				g_userPassword.empty()? NULL : g_userPassword.c_str());
			
			result = true;

			break;
		}

		if (!result)
		{
			free();
		}

		return result;
	}

	void free()
	{
		m_udpProxy.free();
		m_tcpProxy.free();

		AutoLock lock(m_cs);
		while (!m_udpCtxMap.empty())
		{
			tUdpCtxMap::iterator it = m_udpCtxMap.begin();
			delete it->second;
			m_udpCtxMap.erase(it);
		}
		m_filteredUdpIds.clear();
	}

	virtual void onUdpReceiveComplete(unsigned __int64 id, char * buf, int len, char * remoteAddress, int remoteAddressLen)
	{
		AutoLock lock(m_cs);
		
		tUdpCtxMap::iterator it = m_udpCtxMap.find(id);
		if (it == m_udpCtxMap.end())
			return;

		char remoteAddr[MAX_PATH];
		DWORD dwLen;
		
		dwLen = sizeof(remoteAddr);
		WSAAddressToString((sockaddr*)remoteAddress, 
				(((sockaddr*)remoteAddress)->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				remoteAddr, 
				&dwLen);

		printf("onUdpReceiveComplete id=%I64u len=%d remoteAddress=%s\n", id, len, remoteAddr);
//		fflush(stdout);

		nf_udpPostReceive(id, (const unsigned char*)remoteAddress, buf, len, it->second->m_options);
	}

	virtual void threadStart()
	{
	}

	virtual void threadEnd()
	{
	}
	
	//
	// TCP events
	//
	virtual void tcpConnectRequest(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
	{
		printf("tcpConnectRequest id=%I64u\n", id);

		sockaddr * pAddr = (sockaddr*)pConnInfo->remoteAddress;
		int addrLen = (pAddr->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in);

		// Don't redirect the connection if it is already redirected
		if (memcmp(pAddr, g_proxyAddress, addrLen) == 0)
		{
			printf("tcpConnectRequest id=%I64u bypass already redirected\n", id);
			return;
		}

		if (g_processNamesAllow.size() > 0)
		{
			if (checkProcessNameInAllow(pConnInfo->processId))
			{
				printf("tcpConnectRequest id=%I64u bypass process\n", id);
				return;
			}
		}

		if (g_processNamesFilter.size() > 0)
		{
			if (!checkProcessNameInFilter(pConnInfo->processId))
			{
				printf("tcpConnectRequest id=%I64u bypass process\n", id);
				return;
			}
		}

		if (!m_tcpProxy.isIPFamilyAvailable(pAddr->sa_family))
		{
			printf("tcpConnectRequest id=%I64u bypass ipFamily %d\n", id, pAddr->sa_family);
			return;
		}

		m_tcpProxy.setConnInfo(pConnInfo);

		// Redirect the connection
		if (pAddr->sa_family == AF_INET)
		{
			sockaddr_in addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin_family = AF_INET;

			if (((sockaddr_in*)pConnInfo->localAddress)->sin_addr.S_un.S_addr != 0)
			{
				addr.sin_addr.S_un.S_addr = ((sockaddr_in*)pConnInfo->localAddress)->sin_addr.S_un.S_addr;
			} else
			{
				addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
			}

			addr.sin_port = m_tcpProxy.getPort();

			memcpy(pConnInfo->remoteAddress, &addr, sizeof(addr));
		} else
		{
			sockaddr_in6 addr;
			memset(&addr, 0, sizeof(addr));
			addr.sin6_family = AF_INET6;

			char zero[16] = {0};
			if (memcmp(&((sockaddr_in6*)pConnInfo->localAddress)->sin6_addr, zero, 16) != 0)
			{
				memcpy(&addr.sin6_addr, &((sockaddr_in6*)pConnInfo->localAddress)->sin6_addr, 16);
			} else
			{
				addr.sin6_addr.u.Byte[15] = 1;
			}

			addr.sin6_port = m_tcpProxy.getPort();

			memcpy(pConnInfo->remoteAddress, &addr, sizeof(addr));
		}

		// Specify current process id to avoid blocking connection redirected to local proxy
		pConnInfo->processId = GetCurrentProcessId();
	}

	virtual void tcpConnected(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
	{
		printConnInfo(true, id, pConnInfo);
		fflush(stdout);
	}

	virtual void tcpClosed(ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
	{
		printConnInfo(false, id, pConnInfo);
		fflush(stdout);
	}

	virtual void tcpReceive(ENDPOINT_ID id, const char * buf, int len)
	{	
		printf("tcpReceive id=%I64u len=%d\n", id, len);
		// Send the packet to application
		nf_tcpPostReceive(id, buf, len);
	}

	virtual void tcpSend(ENDPOINT_ID id, const char * buf, int len)
	{
		printf("tcpSend id=%I64u len=%d\n", id, len);
		// Send the packet to server
		nf_tcpPostSend(id, buf, len);
	}

	virtual void tcpCanReceive(ENDPOINT_ID id)
	{
	}

	virtual void tcpCanSend(ENDPOINT_ID id)
	{
	}
	
	//
	// UDP events
	//

	virtual void udpCreated(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
	{
		printAddrInfo(true, id, pConnInfo);
		fflush(stdout);

		if (g_processNamesAllow.size() > 0)
		{
			if (checkProcessNameInAllow(pConnInfo->processId))
			{
				printf("udpCreated id=%I64u bypass process\n", id);
				return;
			}
		}
		if (g_processNamesFilter.size() > 0)
		{
			if (!checkProcessNameInFilter(pConnInfo->processId))
			{
				printf("udpCreated id=%I64u bypass process\n", id);
				return;
			}
		}
		AutoLock lock(m_cs);
		m_filteredUdpIds.insert(id);
	}

	virtual void udpConnectRequest(ENDPOINT_ID id, PNF_UDP_CONN_REQUEST pConnReq)
	{
		printf("udpConnectRequest id=%I64u\n", id);
		fflush(stdout);
	}

	virtual void udpClosed(ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
	{
		printAddrInfo(false, id, pConnInfo);
		fflush(stdout);

		m_udpProxy.deleteProxyConnection(id);

		AutoLock lock(m_cs);

		tUdpCtxMap::iterator it = m_udpCtxMap.find(id);
		if (it != m_udpCtxMap.end())
		{
			delete it->second;
			m_udpCtxMap.erase(it);
		}
	
		m_filteredUdpIds.erase(id);
	}

	virtual void udpReceive(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options)
	{	
		char remoteAddr[MAX_PATH];
		DWORD dwLen;
		
		dwLen = sizeof(remoteAddr);
		WSAAddressToString((sockaddr*)remoteAddress, 
				(((sockaddr*)remoteAddress)->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				remoteAddr, 
				&dwLen);

		printf("udpReceive id=%I64u len=%d remoteAddress=%s\n", id, len, remoteAddr);
//		fflush(stdout);

		// Send the packet to application
		nf_udpPostReceive(id, remoteAddress, buf, len, options);
	}

	virtual void udpSend(ENDPOINT_ID id, const unsigned char * remoteAddress, const char * buf, int len, PNF_UDP_OPTIONS options)
	{
		char remoteAddr[MAX_PATH];
		DWORD dwLen;
		
		dwLen = sizeof(remoteAddr);
		WSAAddressToString((sockaddr*)remoteAddress, 
				(((sockaddr*)remoteAddress)->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				remoteAddr, 
				&dwLen);

		printf("udpSend id=%I64u len=%d remoteAddress=%s\n", id, len, remoteAddr);
//		fflush(stdout);

		if (redirectDns)
		{
			if ((((sockaddr*)remoteAddress)->sa_family == AF_INET6) ? ((sockaddr_in6*)remoteAddress)->sin6_port == htons(53) : ((sockaddr_in*)remoteAddress)->sin_port == htons(53))
			{
				g_dnsResolver.addRequest(new DNS_REQUEST(id, remoteAddress, buf, len, options));
				return;
			}
		}

		{
			AutoLock lock(m_cs);

			tIdSet::iterator itid = m_filteredUdpIds.find(id);
			if (itid == m_filteredUdpIds.end())
			{
				nf_udpPostSend(id, remoteAddress, buf, len, options);
				return;
			}

			tUdpCtxMap::iterator it = m_udpCtxMap.find(id);
			if (it == m_udpCtxMap.end())
			{
				if (!m_udpProxy.createProxyConnection(id))
					return;

				m_udpCtxMap[id] = new UDP_CONTEXT(options);
			}
		}

		{
			int addrLen = (((sockaddr*)remoteAddress)->sa_family == AF_INET)? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
			if (!m_udpProxy.udpSend(id, (char*)buf, len, (char*)remoteAddress, addrLen))
			{
				nf_udpPostSend(id, remoteAddress, buf, len, options);
			}
		}
	}

	virtual void udpCanReceive(ENDPOINT_ID id)
	{
	}

	virtual void udpCanSend(ENDPOINT_ID id)
	{
	}
};

void usage()
{
	printf("Usage: SocksRedirector.exe -r IP:port [-g \"<process names>\"] [-p \"<process names>\"] [-user <proxy user name>] [-password <proxy user password>]  [-dns IP:port]\n" \
		"IP:port : tunnel TCP/UDP traffic via SOCKS proxy using specified IP:port\n" \
		"-g <process names> : (global mode, prior to process mode) redirect the traffic except for those of the specified processes (it is possible to specify multiple names divided by ',')\n" \
		"-p <process names> : (process mode) redirect the traffic of the specified processes (it is possible to specify multiple names divided by ',')\n" \
		"-dns : hijack DNS requests and redirect to specified specified IP:port\n" \
		);
	exit(0);
}

bool stringToIPv6(char * str, char * ipBytes)
{
	int err, addrLen;
	sockaddr_in6 addr;

	addrLen = sizeof(addr);
	err = WSAStringToAddress(str, AF_INET6, NULL, (LPSOCKADDR)&addr, &addrLen);
	if (err < 0)
	{
		return false;
	}

	memcpy(ipBytes, &addr.sin6_addr, NF_MAX_IP_ADDRESS_LENGTH);

	return true;
}

int main(int argc, char* argv[])
{
	EventHandler eh;
	NF_RULE rule;
	NF_RULE_EX ruleEx;
	WSADATA wsaData;

	// This call is required for WSAAddressToString
    ::WSAStartup(MAKEWORD(2, 2), &wsaData);

#ifdef _DEBUG
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_DEBUG);
#endif

#if defined(_DEBUG) || defined(_RELEASE_LOG)
	DBGLogger::instance().init("SocksRedirectorLog.txt");
#endif

	memset(&g_proxyAddress, 0, sizeof(g_proxyAddress));

	if (argc < 2)
		usage();

	for (int i=1; i < argc; i += 2)
	{
		if (stricmp(argv[i], "-r") == 0)
		{
			int err, addrLen;

			addrLen = sizeof(g_proxyAddress);
			err = WSAStringToAddress(argv[i+1], AF_INET, NULL, (LPSOCKADDR)&g_proxyAddress, &addrLen);
			if (err < 0)
			{
				addrLen = sizeof(g_proxyAddress);
				err = WSAStringToAddress(argv[i+1], AF_INET6, NULL, (LPSOCKADDR)&g_proxyAddress, &addrLen);
				if (err < 0)
				{
					printf("WSAStringToAddress failed, err=%d", WSAGetLastError());
					usage();
				}
			}

			printf("Redirect to: %s\n", argv[i+1]);
		} else
		if (stricmp(argv[i], "-g") == 0)
		{
			parseValue(argv[i+1], g_processNamesAllow);
			printf("(Global mode) bypass process name(s): %s\n", argv[i+1]);
		} else
		if (stricmp(argv[i], "-p") == 0)
		{
			parseValue(argv[i+1], g_processNamesFilter);
			printf("(Process mode) proxy process name(s): %s\n", argv[i+1]);
		} else
		if (stricmp(argv[i], "-user") == 0)
		{
			g_userName = argv[i+1];

			printf("User name: %s\n", argv[i+1]);
		} else
		if (stricmp(argv[i], "-password") == 0)
		{
			g_userPassword = argv[i+1];

			printf("User password: %s\n", argv[i+1]);
		} else
		if (stricmp(argv[i], "-dns") == 0)
		{
			redirectDns = true;
			int err, addrLen;

			addrLen = sizeof(g_dnsAddress);
			err = WSAStringToAddress(argv[i+1], AF_INET, NULL, (LPSOCKADDR)&g_dnsAddress, &addrLen);
			if (err < 0)
			{
				addrLen = sizeof(g_dnsAddress);
				err = WSAStringToAddress(argv[i+1], AF_INET6, NULL, (LPSOCKADDR)&g_dnsAddress, &addrLen);
				if (err < 0)
				{
					printf("WSAStringToAddress failed, err=%d", WSAGetLastError());
					usage();
				}
			}

			printf("Redirect DNS to: %s\n", argv[i+1]);
		}
		else
		{
			usage();
		}
	}

	printf("Press enter to stop...\n\n");

	g_dnsResolver.init(10);

	if (!eh.init())
	{
		printf("Failed to initialize the event handler");
		return -1;
	}

	// Initialize the library and start filtering thread
	if (nf_init(NFDRIVER_NAME, &eh) != NF_STATUS_SUCCESS)
	{
		printf("Failed to connect to driver");
		return -1;
	}

	// Bypass local traffic
	memset(&rule, 0, sizeof(rule));
	rule.filteringFlag = NF_ALLOW;
	rule.ip_family = AF_INET;
	*((unsigned long*)rule.remoteIpAddress) = inet_addr("127.0.0.1");
	*((unsigned long*)rule.remoteIpAddressMask) = inet_addr("255.0.0.0");
	nf_addRule(&rule, FALSE);

	memset(&rule, 0, sizeof(rule));
	rule.filteringFlag = NF_ALLOW;
	rule.ip_family = AF_INET6;
	stringToIPv6("::1", (char*)rule.remoteIpAddress);
	nf_addRule(&rule, FALSE);

	memset(&rule, 0, sizeof(rule));
	rule.filteringFlag = NF_ALLOW;
	rule.ip_family = AF_INET6;
	stringToIPv6("0:0:0:0:0:ffff:7f00:001", (char*)rule.remoteIpAddress);
	nf_addRule(&rule, FALSE);

	// Bypass processes
	for (size_t i = 0; i < g_processNamesAllow.size(); i++)
	{
		memset(&ruleEx, 0, sizeof(ruleEx));
		ruleEx.filteringFlag = NF_ALLOW;
		const wchar_t *p = std::wstring(g_processNamesAllow[i].begin(), g_processNamesAllow[i].end()).c_str();
		wcsncpy((wchar_t*)ruleEx.processName, p, MAX_PATH);
		nf_addRuleEx(&ruleEx, FALSE);
	}

	// Filter processes
	for (size_t i = 0; i < g_processNamesFilter.size(); i++)
	{
		memset(&ruleEx, 0, sizeof(ruleEx));
		ruleEx.filteringFlag = NF_FILTER;
		const wchar_t *p = std::wstring(g_processNamesFilter[i].begin(), g_processNamesFilter[i].end()).c_str();
		wcsncpy((wchar_t*)ruleEx.processName, p, MAX_PATH);
		nf_addRuleEx(&ruleEx, FALSE);
	}

	// Filter UDP packets
	memset(&rule, 0, sizeof(rule));
	rule.protocol = IPPROTO_UDP;
	rule.filteringFlag = NF_FILTER;
	nf_addRule(&rule, FALSE);

	// Filter TCP connect requests
	memset(&rule, 0, sizeof(rule));
	rule.protocol = IPPROTO_TCP;
	rule.direction = NF_D_OUT;
	rule.filteringFlag = NF_INDICATE_CONNECT_REQUESTS;
	nf_addRule(&rule, FALSE);

	// Wait for enter
	getchar();

	// Free the library
	nf_free();

	g_dnsResolver.free();

	eh.free();

	::WSACleanup();

	return 0;
}


/**
* Print the address information
**/
void printAddrInfo(bool created, ENDPOINT_ID id, PNF_UDP_CONN_INFO pConnInfo)
{
	char localAddr[MAX_PATH] = "";
	sockaddr * pAddr;
	DWORD dwLen;
	char processName[MAX_PATH] = "";
	
	pAddr = (sockaddr*)pConnInfo->localAddress;
	dwLen = sizeof(localAddr);

	WSAAddressToString((LPSOCKADDR)pAddr, 
				(pAddr->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				localAddr, 
				&dwLen);
		
	if (created)
	{
		if (!nf_getProcessName(pConnInfo->processId, processName, sizeof(processName)/sizeof(processName[0])))
		{
			processName[0] = '\0';
		}

		printf("udpCreated id=%I64u pid=%d local=%s\n\tProcess: %s\n",
			id,
			pConnInfo->processId, 
			localAddr, 
			processName);
	} else
	{
		printf("udpClosed id=%I64u pid=%d local=%s\n",
			id,
			pConnInfo->processId, 
			localAddr);
	}

}

/**
* Print the connection information
**/
void printConnInfo(bool connected, ENDPOINT_ID id, PNF_TCP_CONN_INFO pConnInfo)
{
	char localAddr[MAX_PATH] = "";
	char remoteAddr[MAX_PATH] = "";
	DWORD dwLen;
	sockaddr * pAddr;
	char processName[MAX_PATH] = "";
	
	pAddr = (sockaddr*)pConnInfo->localAddress;
	dwLen = sizeof(localAddr);

	WSAAddressToString((LPSOCKADDR)pAddr, 
				(pAddr->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				localAddr, 
				&dwLen);

	pAddr = (sockaddr*)pConnInfo->remoteAddress;
	dwLen = sizeof(remoteAddr);

	WSAAddressToString((LPSOCKADDR)pAddr, 
				(pAddr->sa_family == AF_INET6)? sizeof(sockaddr_in6) : sizeof(sockaddr_in), 
				NULL, 
				remoteAddr, 
				&dwLen);
	
	if (connected)
	{
		if (!nf_getProcessName(pConnInfo->processId, processName, sizeof(processName)/sizeof(processName[0])))
		{
			processName[0] = '\0';
		}

		printf("tcpConnected id=%I64u flag=%d pid=%d direction=%s local=%s remote=%s (conn.table size %d)\n\tProcess: %s\n",
			id,
			pConnInfo->filteringFlag,
			pConnInfo->processId, 
			(pConnInfo->direction == NF_D_IN)? "in" : ((pConnInfo->direction == NF_D_OUT)? "out" : "none"),
			localAddr, 
			remoteAddr,
			nf_getConnCount(),
			processName);
	} else
	{
		printf("tcpClosed id=%I64u flag=%d pid=%d direction=%s local=%s remote=%s (conn.table size %d)\n",
			id,
			pConnInfo->filteringFlag,
			pConnInfo->processId, 
			(pConnInfo->direction == NF_D_IN)? "in" : ((pConnInfo->direction == NF_D_OUT)? "out" : "none"),
			localAddr, 
			remoteAddr,
			nf_getConnCount());
	}

}

