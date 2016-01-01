#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <pthread.h>

typedef unsigned char u_int8_t;
typedef unsigned short int u_int16_t;
typedef unsigned int u_int32_t;
typedef signed char s_int8_t;
typedef signed short int s_int16_t;
typedef signed int s_int32_t;

#define ICMP_ECHO 8
#define ICMP_ECHOREPLY 0 
#define ICMP_HEADER_SIZE 8
#define IP_HEADER_SIZE 20
#define K 1024

u_int16_t pid;
u_int16_t pack_recv=1, pack_send=1;
static struct sockaddr_in dest;
struct timeval tv_begin,tv_end,tv_internal;
u_int8_t sendbuf[128];
u_int8_t recvbuf[128];
u_int32_t rawsock;
u_int8_t alive;

typedef struct icmp_head
{
	u_int8_t icmp_type;
	u_int8_t icmp_code;
	u_int16_t icmp_cksum;
	u_int16_t icmp_Id;
	u_int16_t icmp_Seq;
	u_int8_t icmp_Data[1];
}ICMP;

typedef struct ip_head
{
	//u_int32_t ip_version:4;
	u_int32_t ip_headlen:4;
	u_int32_t ip_version:4;
	u_int8_t  ip_tos;
	u_int16_t ip_lenth;
	u_int16_t ip_id;
	u_int16_t ip_fragoff;
	u_int8_t ip_tti;
	u_int8_t ip_top;
	u_int16_t ip_cksum;
	struct in_addr ip_src;
	struct in_addr ip_dest;
}IP;

typedef struct ping_packet
{
	struct timeval tv_begin;
	struct timeval tv_end;
	u_int16_t seq;
	u_int8_t flag;
}PINGPACK;

static PINGPACK ping_packets[128];

void init_pingpack(void)
{
	u_int8_t i;
	
	for(i=0;i<128;i++)
	{
		ping_packets[i].seq = 0;
		ping_packets[i].flag = 0;
	}
}

static PINGPACK *ping_findpacket(s_int16_t seq)
{
	u_int8_t i;
	PINGPACK *pack;

	if(-1 == seq)
	{
		for(i=0;i<128;i++)
		{
			if(0 == ping_packets[i].flag)
			{
				pack = &ping_packets[i];
				break;
			}
		}
	}	
	else if(seq >= 0)
	{
		for(i=0;i<128;i++)
		{
			if(seq == ping_packets[i].seq)
			{
				pack = &ping_packets[i];
				break;
			}
		}
	}
	return pack;
}

static u_int16_t icmp_cksumcheck(u_int16_t *data, u_int16_t length)
{
	u_int32_t sum = 0;
	u_int16_t *p = data;

	while(length & 0xfffe)
	{
		sum += *p++;
		length -= 2;
	}
	if(length)
	{
		sum += (*p & 0xff00); 
	}

	while(sum >> 16)
		sum = (sum>>16)	+ (sum & 0xffff);

	return (u_int16_t)(~sum);
}
static u_int16_t icmp_pack(ICMP *icmpptr, u_int16_t seq, u_int16_t length)
{
	u_int8_t i = 0;
	icmpptr->icmp_type = ICMP_ECHO;
	icmpptr->icmp_code = 0;
	icmpptr->icmp_cksum = 0;
	icmpptr->icmp_Id = pid & 0xffff;
	icmpptr->icmp_Seq = seq;
	for(i=0;i<length;i++)
	{
		icmpptr->icmp_Data[i] = i;
	}
		
	icmpptr->icmp_cksum = icmp_cksumcheck((u_int16_t *)icmpptr,(ICMP_HEADER_SIZE + length));
} 
static struct timeval time_calc(struct timeval timv_send, struct timeval timv_recv)
{
	struct timeval tv;

	tv.tv_sec = timv_recv.tv_sec - timv_send.tv_sec;
	tv.tv_usec = timv_recv.tv_usec - timv_send.tv_usec;

	if(tv.tv_usec < 0)
	{
		tv.tv_sec--;
		tv.tv_usec += 1000000;
	}
	return tv;
}
static u_int16_t icmp_unpack(u_int8_t *buf, u_int16_t length)
{
	u_int32_t ipheadlen = 0;
	IP *ip=NULL;
	ICMP *icmp=NULL;

	if(NULL == buf)
		return -1;

	ip = (IP *)buf;
	ipheadlen = ip->ip_headlen*4;
	icmp = (ICMP *)(buf+ipheadlen);

	length -= ipheadlen;
	if(length < 8)
	{
		printf("It's not ICMP packet!\n");
		return -1;
	}
	if((ICMP_ECHOREPLY == icmp->icmp_type) && (icmp->icmp_Id == pid))
	{
		struct timeval timv_send,timv_recv,timv_internal;
		PINGPACK *pack = NULL;
		u_int16_t rtt;
		gettimeofday(&timv_recv,NULL);
		pack = ping_findpacket(icmp->icmp_Seq);
		
		if(NULL == pack)
			return -1;
		
		pack->flag = 0;	
		timv_send = pack->tv_begin;

		timv_internal = time_calc(timv_send, timv_recv);

		rtt = timv_internal.tv_sec*1000+timv_internal.tv_usec/1000;
		
		pack_recv++;
		if(0xffff == pack_recv)
		{
			pack_recv = 0;
		}
		
		printf("%d bytes data from %s: icmp_seq = %d, ttl = %d, rtt = %d ms\n",length, inet_ntoa(ip->ip_src),icmp->icmp_Seq, ip->ip_tti, rtt);
	}
	else
	{
		return -1;
	}
	
}

static void icmp_sigint(s_int32_t signo)
{
	alive = 0;
	gettimeofday(&tv_end,NULL);
	tv_internal = time_calc(tv_end, tv_begin);

	return;
}

static void *icmp_send(void *argv)
{
	gettimeofday(&tv_begin,NULL);
	
	while(alive)
	{
		u_int32_t size;
		
		icmp_pack((ICMP *)sendbuf, pack_send, 64-ICMP_HEADER_SIZE);
		
		size = sendto(rawsock, sendbuf, 64, 0, (struct sockaddr *)&dest, sizeof(dest));
		if(size < 0)
		{
			perror("send error!\n");
			continue;
		}
		else
		{
			PINGPACK *pack;
			pack = ping_findpacket(-1);
			pack->flag = 1;
			pack->seq = pack_send;
			gettimeofday(&pack->tv_begin,NULL); 
			pack_send++;
			if(0xffff == pack_send)
			{
				pack_send = 0;
			}
		}
		sleep(2);
	} 
}

static void *icmp_recv(void *argv)
{
	struct timeval tv;
	fd_set readfd;

	tv.tv_usec = 10;
	tv.tv_sec = 0;
	while(alive)
	{
		s_int16_t ret;
		FD_ZERO(&readfd);
		FD_SET(rawsock,&readfd);
			
		ret = select(rawsock+1, &readfd, NULL,NULL,&tv);
		switch(ret)
		{
			case -1:
				break;
			case 0:
				break;
			default:
				{
					u_int32_t size;
					u_int16_t rett;
					memset(recvbuf,0,sizeof(recvbuf));
					
					size = recv(rawsock, recvbuf, sizeof(recvbuf),0);

					if(size < 0)
					{
						perror("recv error!\n");
						continue;
					}
					else
					{
						rett = icmp_unpack(recvbuf,size);
						if(-1 == rett)
						{
							continue;
						}
					}
				}
				break;	
		}
		//sleep(1);
	}
}

static void icmp_statistics(void)
{
	u_int32_t time = tv_internal.tv_sec*1000+tv_internal.tv_usec/1000;
	printf("----ping statistics-------\n");
	printf("%d packets transmitted, %d recevied, %d%c packets loss, time %d ms\n",pack_send, pack_recv,(pack_send - pack_recv)*100/pack_send,'%',time);
}

int main(int argc, char *argv[])
{
	u_int8_t c;
	struct in_addr inp;
	struct hostent *ht = NULL;
	struct protoent *protocol = NULL;
	char protoname[] = "icmp";
	unsigned long int netaddr = 1;
	pthread_t pthread_recv_id,pthread_send_id;
	u_int32_t size = 128*K;
	in_addr_t inaddr=0;

	if(2 != argc)
	{
		printf("Error parameters configuration!Like as ./ping 192.168.1.1\n");
		return -1;
	}
	
	protocol = getprotobyname(protoname);
	if(NULL == protocol)
	{
		printf("Error protocol type!\n");
		return -1;
	}

	rawsock = socket(AF_INET,SOCK_RAW,protocol->p_proto);
	if(rawsock < 0)
	{
		perror("sock error!\n");
		return -1;	
	}	
	
	setsockopt(rawsock, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));

	bzero(&dest,sizeof(dest));
	dest.sin_family = AF_INET;
	inaddr = inet_addr(argv[1]);
	if(INADDR_NONE == inaddr)
	{
		ht = gethostbyname(argv[1]);
		if(NULL == ht)
		{
			printf("Error get host by name!\n");
			return -1;
		}
		memcpy((char *)&dest.sin_addr,ht->h_addr_list,ht->h_length);
	}
	else
	{
		#if 0
		if((c=inet_aton(argv[1],&(dest.sin_addr))) != 0)
		{
			printf("Error IP address!\n");
			return -1;
		}
		#endif
		memcpy((char *)&dest.sin_addr,&inaddr,sizeof(inaddr));
	}		
	
	alive = 1;
	pid = getuid();
	signal(SIGINT,icmp_sigint);
	init_pingpack();

	pthread_create(&pthread_send_id,NULL,icmp_send,NULL);
	pthread_create(&pthread_recv_id,NULL,icmp_recv,NULL); 

	pthread_join(pthread_recv_id,NULL);
	pthread_join(pthread_send_id,NULL);

	close(rawsock);	
	icmp_statistics();
	return 0;
}
