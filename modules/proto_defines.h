#ifndef PROTOCOLS_DEFINES
#define PROTOCOLS_DEFINES

#define PROT_HOPOPT		 0      //	        IPv6 Hop-by-Hop Option                   [RFC1883]
#define PROT_ICMP		 1		//          Internet Control Message                 [RFC792]
#define PROT_IGMP		 2		//          Internet Group Management                [RFC1112]
#define PROT_GGP		 3		//          Gateway-to-Gateway                       [RFC823]
#define PROT_IP		  	 4		//          IP in IP (encapsulation)                 [RFC2003]
#define PROT_ST			 5		//          Stream                                   [RFC1190][RFC1819]
#define PROT_TCP		 6		//          Transmission Control                     [RFC793]
#define PROT_CBT		 7		//          CBT                                      [Ballardie]
#define PROT_EGP		 8		//          Exterior Gateway Protocol                [RFC888][DLM1]
#define PROT_IGP		 9		//          any private interior gateway             [IANA]
#define PROT_BBN_RCC_MON 10     //			BBN RCC Monitoring                       [SGC]
#define PROT_NVP_II      11     //			Network Voice Protocol                   [RFC741][SC3]
#define PROT_PUP         12     //			PUP                                      [PUP][XEROX]
#define PROT_ARGUS       13     //			ARGUS                                    [RWS4]
#define PROT_EMCON       14     //			EMCON                                    [BN7]
#define PROT_XNET        15     //			Cross Net Debugger                       [IEN158][JFH2]
#define PROT_CHAOS       16     //			Chaos                                    [NC3]
#define PROT_UDP         17     //			User Datagram                            [RFC768][JBP]
#define PROT_MUX         18     //			Multiplexing                             [IEN90][JBP]
#define PROT_DCN_MEAS    19     //			DCN Measurement Subsystems               [DLM1]
//#define HMP         20     Host Monitoring                          [RFC869][RH6]
//#define PRM         21     Packet Radio Measurement                 [ZSU]
//#define XNS-IDP     22     XEROX NS IDP                             [ETHERNET][XEROX]
//#define TRUNK-1     23     Trunk-1                                  [BWB6]
//#define TRUNK-2     24     Trunk-2                                  [BWB6]
//#define LEAF-1      25     Leaf-1                                   [BWB6]
//#define LEAF-2      26     Leaf-2                                   [BWB6]
//#define RDP         27     Reliable Data Protocol                   [RFC908][RH6]
//#define IRTP        28     Internet Reliable Transaction            [RFC938][TXM]
//#define ISO-TP4     29     ISO Transport Protocol Class 4           [RFC905][RC77]
//#define NETBLT      30     Bulk Data Transfer Protocol              [RFC969][DDC1]
//#define MFE-NSP     31     MFE Network Services Protocol            [MFENET][BCH2]
//#define MERIT-INP   32     MERIT Internodal Protocol                [HWB]
//#define DCCP        33     Datagram Congestion Control Protocol     [RFC4340]
//#define 3PC         34     Third Party Connect Protocol             [SAF3]
//#define IDPR        35     Inter-Domain Policy Routing Protocol     [MXS1]
//#define XTP         36     XTP                                      [GXC]
//#define DDP         37     Datagram Delivery Protocol               [WXC]
//#define IDPR-CMTP   38     IDPR Control Message Transport Proto     [MXS1]
//#define TP++        39    TP++ Transport Protocol                  [DXF]
//#define IL          40     IL Transport Protocol                    [Presotto]
//#define IPv6        41     Ipv6                                     [Deering]
//#define SDRP        42    Source Demand Routing Protocol           [DXE1]
//#define IPv6-Route  43     Routing Header for IPv6                  [Deering]
//#define IPv6-Frag   44     Fragment Header for IPv6                 [Deering]
//#define IDRP        45     Inter-Domain Routing Protocol            [Hares]
//#define RSVP        46     Reservation Protocol                     [Braden]
//#define GRE         47     General Routing Encapsulation            [Li]
//#define DSR         48     Dynamic Source Routing Protocol          [RFC4728]
//#define BNA         49     BNA                                      [Salamon]
//#define ESP         50     Encap Security Payload                   [RFC4303]
//#define AH          51     Authentication Header                    [RFC4302]
//#define I-NLSP      52     Integrated Net Layer Security  TUBA      [GLENN]
//#define SWIPE       53     IP with Encryption                       [JI6]
//#define NARP        54     NBMA Address Resolution Protocol         [RFC1735]
//#define MOBILE      55     IP Mobility                              [Perkins]
//#define TLSP        56     Transport Layer Security Protocol        [Oberg]
//									using Kryptonet key management
//57      #define SKIP             SKIP                                     [Markson]
//58      #define IPv6-ICMP        ICMP for IPv6                            [RFC1883]
//59      #define IPv6-NoNxt       No Next Header for IPv6                  [RFC1883]
//60      #define IPv6-Opts        Destination Options for IPv6             [RFC1883]
//61      #define ANY_HOST_INTERNAL_PROTOCOL								[IANA]
//62      #define CFTP             CFTP                                     [CFTP][HCF2]
//63                        any local network                        [IANA]
//64      #define SAT-EXPAK        SATNET and Backroom EXPAK                [SHB]
//65      #define KRYPTOLAN        Kryptolan                                [PXL1]
//66      #define RVD              MIT Remote Virtual Disk Protocol         [MBG]
//67      #define IPPC             Internet Pluribus Packet Core            [SHB]
//68                        any distributed file system              [IANA]
//69      #define SAT-MON          SATNET Monitoring                        [SHB]
//70      #define VISA             VISA Protocol                            [GXT1]
//71      #define IPCV             Internet Packet Core Utility             [SHB]
//72      #define CPNX             Computer Protocol Network Executive      [DXM2]
//73      #define CPHB             Computer Protocol Heart Beat             [DXM2]
//74      #define WSN              Wang Span Network                        [VXD]
//75      #define PVP              Packet Video Protocol                    [SC3]
//76      #define BR-SAT-MON       Backroom SATNET Monitoring               [SHB]
//77      #define SUN-ND           SUN ND PROTOCOL-Temporary                [WM3]
//78      #define WB-MON           WIDEBAND Monitoring                      [SHB]
//79      #define WB-EXPAK         WIDEBAND EXPAK                           [SHB]
//80      #define ISO-IP           ISO Internet Protocol                    [MTR]
//81      #define VMTP             VMTP                                     [DRC3]
//82      #define SECURE-VMTP      SECURE-VMTP                              [DRC3]
//83      #define VINES            VINES                                    [BXH]
//84      #define TTP              TTP                                      [JXS]
//85      #define NSFNET-IGP       NSFNET-IGP                               [HWB]
//86      #define DGP              Dissimilar Gateway Protocol              [DGP][ML109]
//87      #define TCF              TCF                                      [GAL5]
//88      #define EIGRP            EIGRP                                    [CISCO][GXS]
//89      #define OSPFIGP          OSPFIGP                                  [RFC1583][JTM4]
//90      #define Sprite-RPC       Sprite RPC Protocol                      [SPRITE][BXW]
//91      #define LARP             Locus Address Resolution Protocol        [BXH]
//92      #define MTP              Multicast Transport Protocol             [SXA]
//93      #define AX.25            AX.25 Frames                             [BK29]
//94      #define IPIP             IP-within-IP Encapsulation Protocol      [JI6]
//95      #define MICP             Mobile Internetworking Control Pro.      [JI6]
//96      #define SCC-SP           Semaphore Communications Sec. Pro.       [HXH]
//97      #define ETHERIP          Ethernet-within-IP Encapsulation         [RFC3378]
//98      #define ENCAP            Encapsulation Header                     [RFC1241,RXB3]
//99                        any private encryption scheme            [IANA]
//100     #define GMTP             GMTP                                     [RXB5]
//101     #define IFMP             Ipsilon Flow Management Protocol         [Hinden]
//102     #define PNNI             PNNI over IP                             [Callon]
//103     #define PIM              Protocol Independent Multicast           [Farinacci]
//104     #define ARIS             ARIS                                     [Feldman]
//105     #define SCPS             SCPS                                     [Durst]
//106     #define QNX              QNX                                      [Hunter]
//107     #define A/N              Active Networks                          [Braden]
//108     #define IPComp           IP Payload Compression Protocol          [RFC2393]
//109     #define SNP              Sitara Networks Protocol                 [Sridhar]
//110     #define Compaq-Peer      Compaq Peer Protocol                     [Volpe]
//111     #define IPX-in-IP        IPX in IP                                [Lee]
//112     #define VRRP             Virtual Router Redundancy Protocol       [RFC3768]
//113     #define PGM              PGM Reliable Transport Protocol          [Speakman]
//114                       any 0-hop protocol                       [IANA]
//115     #define L2TP             Layer Two Tunneling Protocol             [Aboba]
//116     #define DDX              D-II Data Exchange (DDX)                 [Worley]
//117     #define IATP             Interactive Agent Transfer Protocol      [Murphy]
//118     #define STP              Schedule Transfer Protocol               [JMP]
//119     #define SRP              SpectraLink Radio Protocol               [Hamilton]
//120     #define UTI              UTI                                      [Lothberg]
//121     #define SMP              Simple Message Protocol                  [Ekblad]
//122     #define SM               SM                                       [Crowcroft]
//123     #define PTP              Performance Transparency Protocol        [Welzl]
//124     #define ISIS over IPv4                                            [Przygienda]
//125     #define FIRE                                                      [Partridge]
//126     #define CRTP             Combat Radio Transport Protocol          [Sautter]
//127     #define CRUDP            Combat Radio User Datagram               [Sautter]
//128     #define SSCOPMCE                                                  [Waber]
//129     #define IPLT                                                      [Hollbach]
//130     #define SPS              Secure Packet Shield                     [McIntosh]
//131     #define PIPE             Private IP Encapsulation within IP       [Petri]
//132     #define SCTP             Stream Control Transmission Protocol     [Stewart]
//133     #define FC               Fibre Channel                            [Rajagopal]
//134     #define RSVP-E2E-IGNORE                                           [RFC3175]
//135     #define Mobility Header                                           [RFC3775]
//136     #define UDPLite                                                   [RFC3828]
//137     #define MPLS-in-IP                                                [RFC4023]
//138     #define manet            MANET Protocols                          [RFC5498]
//139     #define HIP              Host Identity Protocol                   [RFC5201]
//140     #define Shim6            Shim6 Protocol                           [RFC5533]
////141-252                   Unassigned                               [IANA]//
////253                       Use for experimentation and testing      [RFC3692]
////254                       Use for experimentation and testing      [RFC3692]
////255      Reserved                                                  [IANA]

#endif // PROTOCOLS_DEFINES
