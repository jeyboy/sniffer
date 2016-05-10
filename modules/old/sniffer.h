#ifndef SNIFFER
#define SNIFFER


//void ColorPacket(const IPHeader *h, const u_long haddr, const u_long whost = 0)
//{
//	if (h->xsum)
//		SetConsoleTextColor(0x17);
//	else
//		SetConsoleTextColor(0x07);

//	if (haddr == h->src)
//	{
//		SetConsoleTextColor(BACKGROUND_BLUE | /*BACKGROUND_INTENSITY |*/
//			FOREGROUND_RED | FOREGROUND_INTENSITY);
//	}
//	else if (haddr == h->dest)
//	{
//		SetConsoleTextColor(BACKGROUND_BLUE | /*BACKGROUND_INTENSITY |*/
//			FOREGROUND_GREEN | FOREGROUND_INTENSITY);
//	}

//	if (h->protocol == PROT_ICMP || h->protocol == PROT_IGMP)
//	{
//		SetConsoleTextColor(0x70);
//	}
//	else if(h->protocol == PROT_IP || h->protocol == 115)
//	{
//		SetConsoleTextColor(0x4F); // IP-in-IP, L2TP
//	}
//	else if(h->protocol == 53 || h->protocol == 56)
//	{
//		SetConsoleTextColor(0x4C); // TLS, IP with Encryption
//	}

//	if(whost == h->dest || whost == h->src)
//	{
//		SetConsoleTextColor(0x0A);
//	}
//}

//void ShowLegend()
//{
//		SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY |
//			BACKGROUND_GREEN | BACKGROUND_BLUE);
//		printf("Legend\t\t\t\n");
//		SetConsoleTextColor(BACKGROUND_BLUE | /*BACKGROUND_INTENSITY |*/
//			FOREGROUND_GREEN | FOREGROUND_INTENSITY);
//		printf("\nPacket FOR this host\t\n");
//		SetConsoleTextColor(BACKGROUND_BLUE | /*BACKGROUND_INTENSITY |*/
//			FOREGROUND_RED | FOREGROUND_INTENSITY);
//		printf("Packet FROM this host\t\n");
//		SetConsoleTextColor(0x17);
//		printf("Any non-empty packet\t\n");
//		SetConsoleTextColor(0x07);
//		printf("Any empty packet\t\n");
//		SetConsoleTextColor(0x70); // ICMP
//		printf("ICMP packet\t\t\n");
//		SetConsoleTextColor(0x4F); // IP-in-IP
//		printf("IP-in-IP packet, L2TP\t\n");
//		SetConsoleTextColor(0x4C); // TLS, IP with Encryption
//		printf("TLS, IP with Encryption\t\n");
//		SetConsoleTextColor(0x0A); // TLS, IP with Encryption
//		printf("Watched host packets\t\n");
//}



//void ShowHelp()
//{
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("IP-datagram structure:\n");
//	printf("ver");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Internet Protocol version. Common Defaults: usually 4 (IPv4) or 6 (IPv6), 4 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("hlen");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": IP header length(in bytes), 4 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("tos");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Type of Service flags controls the priority of the packet. The first 3 bits stand for routing priority, the next 4 bits for the type of service (delay, throughput, reliability and cost), 8 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("len");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Total length must contain the total length of the IP datagram. This includes IP, ICMP, TCP or UDP header and payload size in bytes, 16 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("id");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": The ID sequence number is mainly used for reassembly of fragmented IP datagrams, 16 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("flags");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Flags, 3 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("offset");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Offset, 16 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("ttl");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Time to live, 8 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("prot");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": The transport layer protocol. Can be tcp (6), udp(17), icmp(1), or whatever protocol follows the IP header, 8 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("crc");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": The header checksum. Every time anything in the header changes, it needs to be recalculated, or the packet will be discarded by the next router, 16 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("src");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Source address, 32 bits;\n");
//	//----
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
//	printf("dest");
//	SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE);
//	printf(": Destination address, 32 bits;\n");
//}

#include <qobject.h>
#include <QFutureWatcher>
#include <QtConcurrent/QtConcurrentRun>;

#include <winsock2.h>
#include <windows.h>
#include <process.h>

#include <time.h>

#include <string>

#include "raw_sock.h"
#include "socket.h"

class Sniffer : public QObject {
    Q_OBJECT

    QFutureWatcher<void> * server;
public:
    ~Sniffer() {
        RS_Free();
    }

    Sniffer(int port = 20000) {
        RS_Init();

        if (RS_SSocket == SOCKET_ERROR) {
            // send error
            return -1;
        }

        //	printf("%s> ", STR_HOSTNAME);
        //	printf("%s\n", RS_Hostname);


        //	printf("%s> ", STR_HOST_IP);
        //	printf("%s\n", nethost2str(RS_SocketAddress.sin_addr.s_addr));

        //	// promiscuous mode
        RS_SetPromMode(1);

        server = new QFutureWatcher<void>();
        initiator -> setFuture(QtConcurrent::run(this, &Sniffer::listening, port, server));

        RS_InitStat();

        //	while(true)
        //	{
                IPHeader* hdr = RS_Sniff();
        //		if (hdr)
        //		{
        //			char *packet_str = 0;
        //			packets_count++;
        //			time(&rawtime);
        //			timeinfo = localtime (&rawtime);
        //			packet_str = RS_IPHeaderToStr(hdr);
        //			if (f)
        //				fprintf(f, "%.2d:%.2d:%.2d>%s\n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, packet_str);

        //			SetConsoleTextColor(0x07);
        //			/*ColorPacket(hdr, RS_SocketAddress.sin_addr.s_addr, watch_host);*/
        //			if (console_out == 'y')
        //			{
        //				SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE /*| FOREGROUND_INTENSITY*/);
        //				printf("%.2d:%.2d:%.2d>", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
        //				ColorPacket(hdr, RS_SocketAddress.sin_addr.s_addr, watch_host);
        //				printf("%s", packet_str);
        //				//for(int i = 0; i < CONSOLE_WIDTH - strlen(packet_str)-9; i++) printf(" ");
        //				//printf("\n");
        //			}

        //			sCurrPacket = packet_str;
        //			bNewPacket = true;

        //			free((void*)packet_str);
        //			free((void*)hdr);

        //			if (packet_res > 0)
        //				Sleep(packet_res);
        //		}

        //		SetConsoleTitle(RS_GetNetStat());

        //		if(!PauseAndContinue())
        //			break;
        //	}
        //}
    }

    void listening(int port, QFutureWatcher<void> * initiator) {
        SocketServer in(port, 20);

        while(!initiator -> isCanceled()) {
            Socket * s = in.Accept();

            QFutureWatcher<void> * socket_proc = new QFutureWatcher<void>();
            socket_proc -> setFuture(QtConcurrent::run(this, &Sniffer::procSocket, s, server));

            unsigned ret;
            _beginthreadex(0, 0, Connection, (void *)s, 0, &ret);
        }
    }

    void procSocket(Socket * s, QFutureWatcher<void> * initiator) {
//        if (a == NULL)
//            return SOCKET_ERROR;

        while(!initiator -> isCanceled()) {
            if (bNewPacket)	{
                EnterCriticalSection(&critsect);

                s -> SendLine(sCurrPacket + (char)13 + (char)10);
                bNewPacket = false;

                LeaveCriticalSection(&critsect);
            }
        }

        delete s;
    }

    //int main(int argc, char* argv[])
    //{
    //	char		 console_out = 'y';
    //	char		 buf[64];

    //	FILE*		 f = NULL;
    //	unsigned int ret;

    //	RS_InitStat();

    //	while(true)
    //	{
    //		IPHeader* hdr = RS_Sniff();
    //		if (hdr)
    //		{
    //			char *packet_str = 0;
    //			packets_count++;
    //			time(&rawtime);
    //			timeinfo = localtime (&rawtime);
    //			packet_str = RS_IPHeaderToStr(hdr);
    //			if (f)
    //				fprintf(f, "%.2d:%.2d:%.2d>%s\n", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, packet_str);

    //			SetConsoleTextColor(0x07);
    //			/*ColorPacket(hdr, RS_SocketAddress.sin_addr.s_addr, watch_host);*/
    //			if (console_out == 'y')
    //			{
    //				SetConsoleTextColor(FOREGROUND_GREEN | FOREGROUND_BLUE /*| FOREGROUND_INTENSITY*/);
    //				printf("%.2d:%.2d:%.2d>", timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);
    //				ColorPacket(hdr, RS_SocketAddress.sin_addr.s_addr, watch_host);
    //				printf("%s", packet_str);
    //				//for(int i = 0; i < CONSOLE_WIDTH - strlen(packet_str)-9; i++) printf(" ");
    //				//printf("\n");
    //			}

    //			sCurrPacket = packet_str;
    //			bNewPacket = true;

    //			free((void*)packet_str);
    //			free((void*)hdr);

    //			if (packet_res > 0)
    //				Sleep(packet_res);
    //		}

    //		SetConsoleTitle(RS_GetNetStat());

    //		if(!PauseAndContinue())
    //			break;
    //	}

    //	printf("\r");

    //	RS_Free();
    //	fclose(f);

    //	SetConsoleTextColor(0x0E);
    //	printf("\n\n%s %d\n", STR_END_OF_PROGRAM, packets_count);

    //	WaitForKey();
    //	return 0;
    //}
protected:
    CRITICAL_SECTION critsect;

    static string sCurrPacket = "";
    static bool	bNewPacket = true;

    DWORD		 packet_res = 0;
    u_long		 watch_host = 0;
    DWORD		 packets_count = 0;
};

#endif // SNIFFER
