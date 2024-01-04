//Efrain Robles Pulido
#include <iostream>

#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include<math.h>
#include <cstring>

using namespace std;

FILE* archive;
int opcM, word;
char charBuffer[3];

//fgetc te lo regresa como entero
void LeerCabeceraEthernet();
void LeerARP(int);
void LeerIPv4(int, bool);
void LeerICMPv4(int);
string TYPEofPROTOCOL(const int&);
string typeIcmp(const int&);
string codeIcmp(const int&, const int&);
int Hexa_Decimal(const string&);


/*string LeerArchivoHex(string& nombre){ ///Intento de usar cadenas
    int word;
    string hex;
    if ((archive = fopen(nombre.c_str(), "rb")) == NULL) {
            cout<< "Error en la apertura. Algo salio mal";
            }
        else {
            fseek(archive,0,SEEK_SET);
            while(!feof(archive)){
                word = fgetc(archive);
                sprintf(charBuffer, "%02X", word);
                hex+=charBuffer;
            }
            return hex;
            }//If FIN del Fopen
}*/

int main() {
    string nombre, Hex;
    int opcM=0;

    while(opcM!=2) {
        system("cls");
        cout << "DIME EL NOMBRE DEL FICHERO: ";//ethernet_arp_reply.bin     ethernet_ipv4_icmp.bin
        getline(cin, nombre);//ethernet_1.bin       ethernet_ipv4_tcp.bin
        //ethernet_ipv4_icmp_host_unreachable.bin           ethernet_ipv4_icmp_ping_2.bin       ethernet_ipv4_icmp_pong_2.bin

        //Si logra abrir el fichero
        if ((archive = fopen(nombre.c_str(), "rb")) == NULL) {
            cout<< "Error en la apertura. Algo salio mal";
            }
        else {
            LeerCabeceraEthernet();
            }//If FIN del Fopen
        cout<<endl;
        fclose(archive);

        cout<<endl<<"\tDESEA LEER OTRO ARCHIVO"<<endl<<"\t     1(Si)   2(No):    ";
        cin>>opcM;
        cin.ignore();
        }

    cout<<endl<<endl<<"\tFIN DEL PROGRAMA"<<endl;
    return 0;
    }

int Hexa_Decimal(const string& hex) {
    int p=0, i=0, decimal=0, n = 1;
    for ( i = hex.length() - 1; i >= 0; i--) {
        if (hex[i] >= 'A' && hex[i] <= 'F')
            p = hex[i] - 'A' + 10;
        else
            p = hex[i] - '0';

        decimal += p * n;
        n *= 16;
        }
    return decimal;
    }

string codeIcmp(const int& type, const int& subvalor) {
    string destination_Unreachable[]= { ///type 3
        "Destination Network Unreachable",
		"Destination Host Unreachable",
		"Destination Protocol Unreachable",
		"Destination Port Unreachable",
		"Fragmentation Required, and DF flag set",
		"Source Route Failed",
		"Destination Network Unknown",
		"Destination Host Unknown",
		"Source Host Isolated",
		"Network Administratively Prohibited",
		"Host Administratively Prohibited",
		"Network Unreachable for ToS",
		"Host Unreachable for ToS",
		"Communication Administratively Prohibited",
		"Host Precedence Violation",
		"Precedence Cutoff in Effect"
        };

    string Redirect_Message[]= {    ///type 5
        "Redirect Datagram for the Network",
		"Redirect Datagram for the Host",
		"Redirect Datagram for the ToS & network",
		"Redirect Datagram for the ToS & host"
    };

    string Time_Exceed[]= { ///type 11
        "TTL expired in transit",
        "Fragment reassembly time exceeded"
    };

    string Parameter_Problem[]= {   ///type 12
        "Pointer indicates the error",
		"Missing a required option",
		"Bad length"
    };

    string Extended_Echo_Reply[]{   ///type 43
        "No Error",
		"Malformed Query",
		"No Such Interface",
		"No Such Table Entry",
		"Multiple Interfaces Satisfy Query"
    };

    string codeRest[]= {
        "Echo Reply (Ping)",
		"Reserved",
		"Reserved",
		" ",//3
		"Source quench (congestion control)",
		" ",//5
		"Alternate Host Address",
		"Reserved",
		"Echo request (used to ping)",
		"Router Advertisement",
		"Router discovery/selection/solicitation",
		" ",//11
		" ",//12
		"Timestamp",
		"Timestamp reply",
		"Information Request",
		"Information Reply",
		"Address Mask Request",
		"Address Mask Reply",
		"Reserved for security",
		"Reserved for robustness experiment",
		"Information Request",
		"Datagram Conversion Error",
		"Mobile Host Redirect",
		"Where-Are-You (originally meant for IPv6)",
		"Here-I-Am (originally meant for IPv6)",
		"Mobile Registration Request",
		"Mobile Registration Reply",
        "Domain Name Request",
        "Domain Name Reply",
        "SKIP Algorithm Discovery Protocol, Simple Key-Management for Internet Protocol",
        "Photuris, Security failures",
        "ICMP for experimental mobility protocols such as Seamoby",
        "Request Extended Echo (XPing)",
        " ",//43
        };

        string myStr= "  -> ";
    switch(type){
        case 3:
            return myStr += destination_Unreachable[subvalor];

        case 5:
            return myStr += Redirect_Message[subvalor];

        case 11:
            return myStr += Time_Exceed[subvalor];

        case 12:
            return myStr += Parameter_Problem[subvalor];

        case 43:
            return myStr += Extended_Echo_Reply[subvalor];

        default:
            if (type<44){
                return myStr += codeRest[type];
            }else{
                return myStr += "Reserve";
            }
    }

    }

string typeIcmp(const int& type) {
    string TYPE_icmp[]= {"Echo Reply","Unassigned","Unassigned","Destination Unreachable",
                         "Source Quench (Deprecated)","Redirect","Alternate Host Address (Deprecated)","Unassigned",
                         "Echo Request","Router Advertisement","Router Solicitation","Time Exceeded",
                         "Parameter Problem","Timestamp","Timestamp Reply","Information Request (Deprecated)",
                         "Information Reply (Deprecated)","Address Mask Request (Deprecated)","Address Mask Reply (Deprecated)","Reserved (for Security)",
                         "Reserved (for Robustness Experiment)","Traceroute (Deprecated)","Datagram Conversion Error (Deprecated)","Mobile Host Redirect (Deprecated)",
                         "IPv6 Where-Are-You (Deprecated)","IPv6 I-Am-Here (Deprecated)","Mobile Registration Request (Deprecated)","Mobile Registration Reply (Deprecated)",
                         "Domain Name Request (Deprecated)","Domain Name Reply (Deprecated)","SKIP (Deprecated)","Photuris",
                         "ICMP messages utilized by experimental mobility protocols such as Seamoby","Extended Echo Request","Extended Echo Reply"
                        };
    if((type>=20 && type <= 29) || type>=44) {
        return "  -> Unsigned";
        }
    else {
        return "  -> " + TYPE_icmp[type];
        }
    }

void LeerICMPv4(int POS) { //POS 34
    int i, TYPEicmp, Code;
    string HEADchecksum, IDN, SEQ, redirectIP;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ICMPv4 "<<endl<<endl;

    fseek(archive,POS, SEEK_SET);
    cout<<"Type: ";
    word = fgetc(archive);
    TYPEicmp=word;
    cout<<TYPEicmp<<typeIcmp(TYPEicmp)<<endl;

    fseek(archive, 0, POS+1);
    cout<<"Code: ";
    word = fgetc(archive);
    Code=word;
    cout<<Code<<codeIcmp(TYPEicmp,Code)<<endl;

    fseek(archive,POS+2,SEEK_SET);
    cout<<"Header Checksum: 0x";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        HEADchecksum += charBuffer;
        }
    cout<<HEADchecksum<<endl;

    switch(TYPEicmp){
case 0://ping
case 8://pong
    fseek(archive,0,POS+4);
    cout<<"Identificador: ";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        IDN += charBuffer;
        }
    cout<<Hexa_Decimal(IDN)<<endl;

    fseek(archive,POS+6,SEEK_SET);
    cout<<"Numero de secuencia: ";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        SEQ += charBuffer;
        }
    cout<<Hexa_Decimal(SEQ)<<endl;
    break;
    case 3://unreachable
    case 11://ttl
        /*fseek(archive,0,POS+4);
    cout<<"Identificador: ";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        IDN += charBuffer;
        }
    cout<<Hexa_Decimal(IDN)<<endl;

    fseek(archive,POS+6,SEEK_SET);
    cout<<"Cantidad de datos: ";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        SEQ += charBuffer;
        }
    cout<<Hexa_Decimal(SEQ)<<" bytes"<<endl;*/

        LeerIPv4((POS+8),false);
        break;

    case 5://redirect
        fseek(archive,POS+4,SEEK_SET);
        cout<<endl<<"Direccion IP de Redirect: ";
        for(i=0; i < 4; i++) {
        word = fgetc(archive);
        if(i<3) {
            sprintf(charBuffer, "%i.", word);
            }
        else {
            sprintf(charBuffer, "%i ", word);
            }
        redirectIP += charBuffer;
        }
        cout<<redirectIP<<endl;

        LeerIPv4((POS+8),false);
        break;
    }

    }

string TYPEofPROTOCOL(const int& valor) {
    string TYPEprotocol[]= {"HOPOPT	    IPv6 Hop-by-Hop Option",
                            "ICMP	Internet Control Message Protocol","IGMP	Internet Group Management Protocol",
                            "GGP	Gateway-to-Gateway Protocol",
                            "IP	    IP en IP (encapsulación)",
                            "ST	    Internet Stream Protocol",
                            "TCP	Transmission Control Protocol",
                            "CBT	Core-based trees",
                            "EGP	Exterior Gateway Protocol",
                            "IGP	Interior Gateway Protocol (cualquier gateway privado interior (usado por Cisco para su IGRP))",
                            "BBN-RCC-MON	Monitoreo BBN RCC",
                            "NVP-II	    Network Voice Protocol",
                            "PUP	Xerox PUP",
                            "ARGUS	ARGUS",
                            "EMCON	EMCON",
                            "XNET	Cross Net Debugger",
                            "CHAOS	Chaos",
                            "UDP	User Datagram Protocol",
                            "MUX	Multiplexing",
                            "DCN-MEAS	DCN Measurement Subsystems",
                            "HMP	Host Monitoring Protocol",
                            "PRM	Packet Radio Measurement",
                            "XNS-IDP	XEROX NS IDP",
                            "TRUNK-1	Trunk-1",
                            "TRUNK-2	Trunk-2",
                            "LEAF-1	Leaf-1",
                            "LEAF-2	Leaf-2",
                            "RDP	Reliable Datagram Protocol",
                            "IRTP	Internet Reliable Transaction Protocol",
                            "ISO-TP4	ISO Transport Protocol Class 4",
                            "NETBLT	Bulk Data Transfer Protocol",
                            "MFE-NSP	MFE Network Services Protocol",
                            "MERIT-INP	MERIT Internodal Protocol",
                            "DCCP	Datagram Congestion Control Protocol",
                            "3PC	Third Party Connect Protocol",
                            "IDPR	Inter-Domain Policy Routing Protocol",
                            "XTP	Xpress Transport Protocol",
                            "DDP	Datagram Delivery Protocol",
                            "IDPR-CMTP	IDPR Control Message Transport Protocol",
                            "TP++	TP++ Transport Protocol",
                            "IL	IL Protocolo de Transporte",
                            "IPv6	IPv6",
                            "SDRP	Source Demand Routing Protocol",
                            "IPv6-Route	Cabecera de Ruteo para IPv6",
                            "IPv6-Frag	Cabecera de Fragmento para IPv6",
                            "IDRP	Inter-Domain Routing Protocol",
                            "RSVP	Resource Reservation Protocol",
                            "GRE	Generic Routing Encapsulation",
                            "MHRP	Mobile Host Routing Protocol",
                            "BNA	BNA",
                            "ESP	Encapsulating Security Payload",
                            "AH	Authentication Header",
                            "I-NLSP	Integrated Net Layer Security Protocol",
                            "SWIPE	IP con cifrado",
                            "NARP	NBMA Address Resolution Protocol",
                            "MOBILE	IP Móvil (Min Encap)",
                            "TLSP	Transport Layer Security Protocol (usa felipendo manejo de llaves Kryptonet)",
                            "SKIP	Simple Key-Management for Internet Protocol",
                            "IPv6-ICMP	ICMP para IPv6",
                            "IPv6-NoNxt	No Next Header para IPv6",
                            "IPv6-Opts	Opciones de Destino para IPv6",
                            "Protocolo interno cualquier host",
                            "CFTP	CFTP",
                            "Cualquier red local",
                            "SAT-EXPAK	SATNET y Backroom EXPAK",
                            "KRYPTOLAN	Kryptolan",
                            "RVD	MIT Remote Virtual Disk Protocol",
                            "IPPC	Internet Pluribus Packet Core",
                            "Cualquier sistema distribuido de archivos",
                            "SAT-MON	Monitoreo SATNET",
                            "VISA	Protocolo VISA",
                            "IPCV	Internet Packet Core Utility",
                            "CPNX	Computer Protocol Network Executive",
                            "CPHB	Computer Protocol Heart Beat",
                            "WSN	Wang Span Network",
                            "PVP	Packet Video Protocol",
                            "BR-SAT-MON	    Backroom SATNET Monitoring",
                            "SUN-ND	    SUN ND PROTOCOL-Temporary",
                            "WB-MON	    WIDEBAND Monitoring",
                            "WB-EXPAK	WIDEBAND EXPAK",
                            "ISO-IP	    International Organization for Standardization Internet Protocol",
                            "VMTP	Versatile Message Transaction Protocol",
                            "SECURE-VMTP	Secure Versatile Message Transaction Protocol",
                            "VINES	VINES",
                            "TTP	TTP",
                            "NSFNET-IGP	    NSFNET-IGP",
                            "DGP	Dissimilar Gateway Protocol",
                            "TCF	TCF",
                            "EIGRP	EIGRP",
                            "OSPF	Open Shortest Path First",
                            "Sprite-RPC	    Sprite RPC Protocol",
                            "LARP	Locus Address Resolution Protocol",
                            "MTP	Multicast Transport Protocol",
                            "AX.25	AX.25",
                            "IPIP	Protocolo de Encapsulación IP-en-IP",
                            "MICP	Mobile Internetworking Control Protocol",
                            "SCC-SP	    Semaphore Communications Sec. Pro",
                            "ETHERIP	Ethernet-within-IP Encapsulation",
                            "ENCAP	    Cabecera de Encapsulación",
                            "Cualquier esquema privado de cifrado",
                            "GMTP	GMTP",
                            "IFMP	Ipsilon Flow Management Protocol",
                            "PNNI	PNNI sobre IP",
                            "PIM	Protocol Independent Multicast",
                            "ARIS	ARIS",
                            "SCPS	SCPS (Space Communications Protocol Standards)",
                            "QNX	QNX",
                            "A/N	Active Networks",
                            "IPComp	IP Payload Compression Protocol",
                            "SNP	Sitara Networks Protocol",
                            "Compaq-Peer	Compaq Peer Protocol",
                            "IPX-in-IP	    IPX in IP",
                            "VRRP	Virtual Router Redundancy Protocol",
                            "PGM	PGM Reliable Transport Protocol",
                            "Cualquier protocolo de 0-saltos",
                            "L2TP	Layer Two Tunneling Protocol",
                            "DDX	D-II Data Exchange (DDX)",
                            "IATP	Interactive Agent Transfer Protocol",
                            "STP	Schedule Transfer Protocol",
                            "SRP	SpectraLink Radio Protocol",
                            "UTI	UTI",
                            "SMP	Simple Message Protocol",
                            "SM	SM",
                            "PTP	Performance Transparency Protocol",
                            "IS-IS sobre IPv4",
                            "FIRE",
                            "CRTP	Combat Radio Transport Protocol",
                            "CRUDP	Combat Radio User Datagram",
                            "SSCOPMCE",
                            "IPLT",
                            "SPS	Secure Packet Shield",
                            "PIPE	Private IP Encapsulation within IP (Encapsulación Privada IP en IP)",
                            "SCTP	Stream Control Transmission Protocol",
                            "FC	Fibre Channel",
                            "RSVP-E2E-IGNORE",
                            "Cabecera de Movilidad",
                            "UDP Lite",
                            "MPLS-en-IP",
                            "manet	Protocolos MANET",
                            "HIP	Host Identity Protocol",
                            "Shim6	Site Multihoming by IPv6 Intermediation"
                           };
    return "  -> " + TYPEprotocol[valor];
    }

void LeerIPv4(int POS, bool flag) {//POS 14
    int i=0, binary, bits, bitsProtocol, ToS, VERSION, JUMPOPTION, FLAGS, TIMEtoLIVE, PROTOCOL;
    string TOTAL_LENG, IDENTI, HEADchecksum, SOURCE_IP, DESTINATION_IP;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t IPv4 "<<endl;

    fseek(archive,POS, SEEK_SET);
    cout<<"Version: ";
    word = fgetc(archive);
    binary = word;//recibe expresion decimal para convetirlo a entero
    bits = binary & 240;//obtenemos 4 "ultimos" bits (los mas significantes)
    VERSION = bits>>4;
    if(VERSION == 4) {
        cout<<"IPv4";
        }
    else if(VERSION == 6) {
        cout<<"IPv6";
        }
    cout<<" ("<<VERSION<<")"<<endl;

    cout<<"IHL (Inter Header Length): ";
    bits = binary & 15;//obtenemos 4 "primeros" bits (los menos significantes)
    if((bitsProtocol = bits*4) >= 20) {
        cout<<bitsProtocol<<" bytes ("<<bits<<")"<<endl; //No hay opciones
        }
    else if(bitsProtocol <= 60) {
        cout<<bitsProtocol<<" bytes ("<<bits<<")"<<endl;
        }
    JUMPOPTION = bitsProtocol - 20;

    fseek(archive,0, POS+1);
    cout<<"ToS (Types of Services): ";
    word = fgetc(archive);
    ToS = word;
    cout<<ToS<<endl;

    fseek(archive,0, POS+2);
    cout<<"Total Length: ";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        TOTAL_LENG += charBuffer;
        }
    cout<<Hexa_Decimal(TOTAL_LENG)<<" bytes"<<endl;


    fseek(archive,0, POS+4);
    cout<<"Identification: ";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        IDENTI += charBuffer;
        }
    cout<<Hexa_Decimal(IDENTI)<<endl;

    fseek(archive,POS+6, SEEK_SET);
    cout<<endl<<"Flags:"<<endl;
    word = fgetc(archive);
    binary = word;
    FLAGS = (binary & 240)>>4;//obtenemos 4 "ultimos" bits (los mas significantes) y le hacemos un recorrimiento
    //cout<<FLAGS<<endl;
    cout<<"  + Reservado ("<<(FLAGS&8)/8<<")"<<endl;
    cout<<"  + Don't fragment ("<<(FLAGS&4)/4<<")"<<endl;
    cout<<"  + More fragment ("<<(FLAGS&2)/2<<")"<<endl;
    cout<<"- Fragment offset("<<(FLAGS&1)<<")"<<endl;

    fseek(archive,POS+8,SEEK_SET);
    cout<<endl<<"TTL (Time to Live): ";
    word = fgetc(archive);
    TIMEtoLIVE = word;
    cout<<TIMEtoLIVE<<" brincos"<<endl;

    fseek(archive,POS+9,SEEK_SET);
    cout<<"Protocol: ";
    word = fgetc(archive);
    PROTOCOL = word;
    cout<<PROTOCOL<<TYPEofPROTOCOL(PROTOCOL)<<endl;

    fseek(archive,POS+10,SEEK_SET);
    cout<<"Header Checksum: 0x";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        HEADchecksum += charBuffer;
        }
    cout<<HEADchecksum<<endl;

    fseek(archive,POS+12, SEEK_SET);
    cout<<"IP Source Address: ";
    for(i=0; i < 4; i++) {
        word = fgetc(archive);
        if(i<3) {
            sprintf(charBuffer, "%i.", word);
            }
        else {
            sprintf(charBuffer, "%i ", word);
            }
        SOURCE_IP += charBuffer;
        }
    cout<<SOURCE_IP<<endl;

    fseek(archive,0, POS+16);
    cout<<"IP Destination Address: ";
    for(i=0; i < 4; i++) {
        word = fgetc(archive);
        if(i<3) {
            sprintf(charBuffer, "%i.", word);
            }
        else {
            sprintf(charBuffer, "%i ", word);
            }
        DESTINATION_IP += charBuffer;
        }
    cout<<DESTINATION_IP<<endl;

        if(flag){
            LeerICMPv4((POS+20)+JUMPOPTION);//salto las optiones
        }
    }

void LeerARP(int POS) {//POS 14
    string PROTOCOL_TYPE, SENDER_MAC, SENDER_IP, TARGET_MAC, TARGET_IP;
    int i=0, HARD_TYPE, HARD_ADDRESS_LENG,PROTO_ADDRESS_LENG, OPERATION;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ARP "<<endl;

    fseek(archive,POS, SEEK_SET);
    cout<<endl<<"HardwareType: ";
    for(i=0; i < 2; i++) {
        word = fgetc(archive);
        HARD_TYPE = word;
        }
    cout<<HARD_TYPE;
    if(HARD_TYPE == 1) {
        cout<<" (Ethernet)"<<endl;
        }

    fseek(archive,0, POS+2);
    cout<<"Protocol type: 0x";
    for(i=0; i < 2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        PROTOCOL_TYPE += charBuffer;
        }
    if(PROTOCOL_TYPE == "0800") {
        cout<<PROTOCOL_TYPE+" (IPv4)"<<endl;
        }

    fseek(archive,0, POS+4);
    cout<<"Hardware Address Length: ";
    word = fgetc(archive);
    HARD_ADDRESS_LENG = word;

    cout<<HARD_ADDRESS_LENG<<" bytes"<<endl;

    fseek(archive,0, POS+5);
    cout<<"Protocol Address Length: ";
    word = fgetc(archive);
    PROTO_ADDRESS_LENG = word;

    cout<<PROTO_ADDRESS_LENG<<" bytes"<<endl;

    fseek(archive,0, POS+6);
    cout<<"Operation: ";
    for(i=0; i < 2; i++) {
        word = fgetc(archive);
        OPERATION = word;
        }

    if(OPERATION == 1) {
        cout<<"ARP Request ("<<OPERATION<<")";
        }
    else if(OPERATION == 2) {
        cout<<"ARP Reply ("<<OPERATION<<")";
        }

    fseek(archive,0, POS+8);
    cout<<endl<<"Sender MAC Address: ";
    for(i=0; i < 6; i++) {
        word = fgetc(archive);
        if(i<5) {
            sprintf(charBuffer, "%02X:", word);
            }
        else {
            sprintf(charBuffer, "%02X ", word);
            }
        SENDER_MAC += charBuffer;
        }
    cout<<SENDER_MAC<<endl;

    fseek(archive,0, POS+14);
    cout<<"Sender IP Address: ";
    for(i=0; i < 4; i++) {
        word = fgetc(archive);
        if(i<3) {
            sprintf(charBuffer, "%i.", word);
            }
        else {
            sprintf(charBuffer, "%i ", word);
            }
        SENDER_IP += charBuffer;
        }
    cout<<SENDER_IP<<endl;

    fseek(archive,0, POS+18);
    cout<<"Target Mac Address: ";
    for(i=0; i < 6; i++) {
        word = fgetc(archive);
        if(i<5) {
            sprintf(charBuffer, "%02X:", word);
            }
        else {
            sprintf(charBuffer, "%02X ", word);
            }
        TARGET_MAC += charBuffer;
        }
    cout<<TARGET_MAC<<endl;

    fseek(archive,0, POS+24);
    cout<<"Target IP Address: ";
    for(i=0; i < 4; i++) {
        word = fgetc(archive);
        if(i<3) {
            sprintf(charBuffer, "%i.", word);
            }
        else {
            sprintf(charBuffer, "%i ", word);
            }
        TARGET_IP += charBuffer;
        }
    cout<<TARGET_IP<<endl;
    }

void LeerCabeceraEthernet() {
    string MACd, MACo, ETHER, FCS;
    int i=0, firstBit, secondBit;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";

    cout<<endl<< "\t\t\t ETHERNET "<<endl;


    fseek(archive,0, SEEK_SET);
    cout<<endl<<"Direccion MAC destino: ";
    for(i=0; i<6; i++) {
        word = fgetc(archive);
        if(i==0) {//recibo el primer byte
            firstBit = word & 1;//el primer bit(operacion binaria)
            secondBit = word & 2;//el segundo bit(operacion binaria)
            }
        if(i<5) {
            sprintf(charBuffer, "%02X:", word);
            }
        else {
            sprintf(charBuffer, "%02X ", word);
            }
        MACd += charBuffer;
        }
    cout<<MACd<<endl;


    if("FF:FF:FF:FF:FF:FF " == MACd) {
        cout<<"\tEs una MAC Address Broadcast"<<endl;
        }
    else if(firstBit == 1) {
        cout<<"\tEs una MAC Address Multicast"<<endl;
        }
    else if(firstBit == 0) {
        cout<<"\tEs una MAC Address Unicast"<<endl;
        }

    if(secondBit == 2) {
        cout<<"\tLocally administered"<<endl;
        }
    else if(secondBit == 0){
        cout<<"\tGlobally Unique"<<endl;
        }

    fseek(archive,0, 6);
    cout<<endl<<"Direccion MAC origen: ";
    for(i=0; i<6; i++) {
        word = fgetc(archive);
        if(i==0) {//recibo el primer byte
            firstBit = word & 1;//el primer bit(operacion binaria)
            secondBit = word & 2;//el segundo bit(operacion binaria)
            }
        if(i<5) {
            sprintf(charBuffer, "%02X:", word);
            }
        else {
            sprintf(charBuffer, "%02X ", word);
            }
        MACo += charBuffer;
        }
    cout<<MACo<<endl;

    if(firstBit == 1) {
        cout<<"\tEs una MAC Address Multicast"<<endl;
        }
    else if(firstBit == 0) {
        cout<<"\tEs una MAC Address Unicast"<<endl;
        }

    if(secondBit == 2) {
        cout<<"\tLocally administered"<<endl;
        }
    else if(secondBit == 0){
        cout<<"\tGlobally Unique"<<endl;
        }

    fseek(archive,12, SEEK_SET);
    cout<<endl<<"Ethertype: 0x";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        ETHER += charBuffer;
        }
    cout<<ETHER;
    if(ETHER == "0800") {
        cout<<" (IPv4)"<<endl;
        }
    else if(ETHER == "0806") {
        cout<<" (ARP)"<<endl;
        }
    else if(ETHER == "86DD") {
        cout<<" (IPv6)"<<endl;
        }

    fseek(archive,0,SEEK_END);//Se va al final del archivo   ethernet_ipv6_nd.bin
    long packSize = ftell(archive);//Obtenemos la cantidad total del paquete
    cout<< (packSize - 18)<<" bytes de carga util en Ethernet"<<endl; //Se resta 18, debido a los bytes que se usan para la cabecera (MAC Addres y etc)


    fseek(archive,-4, SEEK_END);
    cout<<"FCS: 0x ";
    for(i=0; i<4; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X ", word);
        FCS += charBuffer;
        }
    cout<<FCS<<endl;

    if(ETHER == "0806") {
        LeerARP(14);
        }
    else if (ETHER == "0800") {
        LeerIPv4(14, true);
        }
    }
