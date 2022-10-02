#pragma once
#include <chrono>
#include <thread>
#include "nfapi.h"

using namespace nfapi;

DWORD delay;

class IPEventHandler : public NF_IPEventHandler
{
public:
	unsigned short checksum(unsigned char* buf, unsigned int len)
	{
		unsigned int sum = 0;
		unsigned int cnt = len;
		for (unsigned int i = 0; i < len; i += 2)
		{
			sum += (buf[i] << 8) + buf[i + 1];
			cnt -= 2;
		}
		if (cnt == 1)
		{
			sum += buf[len - 1] << 8;
		}
		while (sum >> 16)
		{
			sum = (sum >> 16) + (sum & 0xffff);
		}
		return (unsigned short)~sum;
	}

	virtual void ipSend(const char* buf, int len, PNF_IP_PACKET_OPTIONS options)
	{
		if (options->ip_family == AF_INET && options->ipHeaderSize == 20 && len >= 28 &&
			buf[0] == 69 && buf[9] == 1 && buf[20] == 8 && buf[21] == 0)
		{
			unsigned char* data = new unsigned char[len];
			memcpy(data, buf, len);
			unsigned char src[4];
			memcpy(src, &data[12], 4);
			memcpy(&data[12], &data[16], 4);
			memcpy(&data[16], src, 4);
			unsigned short sum = checksum(data, 20);
			data[10] = (sum >> 8);
			data[11] = sum & 0xff;
			data[20] = 0;
			data[22] += 8;
			if (data[22] < 8) data[23] += 1;
			if (delay > 0) std::this_thread::sleep_for(std::chrono::milliseconds(delay));
			printf("ipSend %d.%d.%d.%d\n", data[12], data[13], data[14], data[15]);
			nf_ipPostReceive((char*)data, len, options);
			return;
		}
		if (options->ip_family == AF_INET6 && options->ipHeaderSize == 40 && len >= 48 &&
			buf[0] >> 4 == 6 && buf[40] == -128 && buf[41] == 0)
		{
			unsigned char* data = new unsigned char[len];
			memcpy(data, buf, len);
			unsigned char src[16];
			memcpy(src, &data[8], 16);
			memcpy(&data[8], &data[24], 16);
			memcpy(&data[24], src, 16);
			data[40] = 129;
			data[42] -= 1;
			if (data[42] == 255) data[43] -= 1;
			if (delay > 0) std::this_thread::sleep_for(std::chrono::milliseconds(delay));
			printf("ipSend %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], 
				data[16], data[17], data[18], data[19], data[20], data[21], data[22], data[23]);
			nf_ipPostReceive((char*)data, len, options);
			return;
		}
		nf_ipPostSend(buf, len, options);
	}
	virtual void ipReceive(const char* buf, int len, PNF_IP_PACKET_OPTIONS options)
	{
		nf_ipPostReceive(buf, len, options);
	}
};
