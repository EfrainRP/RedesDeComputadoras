//Efrain Robles Pulido
#include <iostream>

#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include<math.h>
#include <cstring>
#include <cstddef>


using namespace std;

FILE* archive;
int opcM, word;
char charBuffer[3];

//fgetc te lo regresa como entero
void LeerCabeceraEthernet();
void LeerARP(int);
void LeerIPv4(int, bool);
void LeerICMPv4(int);
void LeerIPv6(int, bool);
void LeerICMPv6(int, const int&);
string TYPEofPROTOCOL(const int&);
string typeIcmpv4(const int&);
string codeIcmpv4(const int&, const int&);
string formatIPv6(string&);
string typeICMPV6(const int&);
string codeIcmpv6(const int&, const int&);
void optionsICMPv6(int, const int&);
int Hexa_Decimal(const string&);


int main() {
    string arch = "E:\\Documentos PC\\UDG Materias\\REDES\\ARCHIVOS\\";
    string nombre, Hex;
    int opcM=0;

    while(opcM!=2) {
        system("cls");
        cout << "DIME EL NOMBRE DEL FICHERO: ";//ethernet_arp_reply.bin     ethernet_ipv4_icmp.bin
        getline(cin, nombre);//ethernet_1.bin       ethernet_ipv4_tcp.bin
        nombre = arch + nombre + ".bin";
        //ipv6_nd_sol_1.bin         ethernet_ipv6_nd.bin        //ipv6_icmpv6_igmp.bin

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
void optionsICMPv6(int POS, const int&PAYLOAD) {

    }

string codeIcmpv6(const int& type, const int& subvalor) {
    string destination_Unreachable[]= {     ///type 1
        "no route to destination",
        "communication with destination administratively prohibited",
        "beyond scope of source address",
        "address unreachable",
        "port unreachable",
        "source address failed ingress/egress policy",
        "reject route to destination",
        "Error in Source Routing Header"
        };

    string Time_Exceed[]= {     ///type 3
        "Hop limit exceeded in transit",
        "Fragment reassembly time exceeded"
        };

    string Parameter_Problem[]= {   ///type 4
        "Erroneous header field encountered",
        "Unrecognized Next Header type encountered",
        "Unrecognized IPv6 option encountered"
        };

    string 	Router_Renumbering[]= {        ///type 138
        "Router Renumbering Command",
        "Router Renumbering Result",
        "Sequence Number Reset"
        };

    string ICMP_Node_Information_Query[] {  ///type 139
        "The Data field contains an IPv6 address which is the Subject of this Query",
        "The Data field contains a name which is the Subject of this Query, or is empty, as in the case of a NOOP",
        "	The Data field contains an IPv4 address which is the Subject of this Query"
        };

    string 	ICMP_Node_Information_Response[]= {     ///type 140
        "A successful reply. The Reply Data field may or may not be empty",
        "The Responder refuses to supply the answer. The Reply Data field will be empty",
        "The Qtype of the Query is unknown to the Responder. The Reply Data field will be empty",
        };

    string myStr= "  -> ";
    switch(type) {
        case 1:
            return myStr += destination_Unreachable[subvalor];

        case 3:
            return myStr += Time_Exceed[subvalor];

        case 4:
            return myStr += Parameter_Problem[subvalor];

        case 138:
            if(subvalor == 255) {
                return myStr += Router_Renumbering[3];
                }
            return myStr += Router_Renumbering[subvalor];

        case 139:
            return myStr += ICMP_Node_Information_Query[subvalor];

        case 140:
            return myStr += ICMP_Node_Information_Response[subvalor];

        default:
            return " (Not used)";

        }
    }

string typeICMPV6(const int& info) {
    int i=0, TYPEnum[]= {1,2,3,4,100,101,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,151,152,153,155,200,201,255};
    string TYPEinfo[]= {
        "Destination unreachable",
        "Packet too big",
        "Time exceeded",
        "Parameter problem",
        "Private experimentation",
        "Private experimentation",
        "Reserved for expansion of ICMPv6 error messages",
        "Echo Request",
        "Echo Reply",
        "Multicast Listener Query (MLD)",
        "Multicast Listener Report (MLD)",
        "Multicast Listener Done (MLD)",
        "Router Solicitation (NDP)",
        "Router Advertisement (NDP)",
        "Neighbor Solicitation (NDP)",
        "Neighbor Advertisement (NDP)",
        "Redirect Message (NDP)",
        "Router Renumbering",
        "ICMP Node Information Query",
        "ICMP Node Information Response",
        "Inverse Neighbor Discovery Solicitation Message",
        "Inverse Neighbor Discovery Advertisement Message",
        "Multicast Listener Discovery (MLDv2) reports (RFC 3810)",
        "Home Agent Address Discovery Request Message",
        "Home Agent Address Discovery Reply Message",
        "Mobile Prefix Solicitation",
        "Mobile Prefix Advertisement",
        "Certification Path Solicitation (SEND)",
        "Certification Path Advertisement (SEND)",
        "Multicast Router Advertisement (MRD)",
        "Multicast Router Solicitation (MRD)",
        "Multicast Router Termination (MRD)",
        "RPL Control Message",
        "Private experimentation",
        "Private experimentation",
        "Reserved for expansion of ICMPv6 informational messages"
        };

    while(i<30) {
        if(info==TYPEnum[++i]) {
            break;
            }
        }
    return " -> " + TYPEinfo[i];
    }

void LeerICMPv6(int POS, const int& PAYLOAD) { //40
    int i, TYPEicmp, Code;
    string HEADchecksum, targetAddr, IDN, SEQ;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ICMPv6 "<<endl<<endl;

    fseek(archive,POS, SEEK_SET);
    cout<<"Type: ";
    word = fgetc(archive);
    TYPEicmp=word;
    cout<<TYPEicmp<<typeICMPV6(TYPEicmp)<<endl;

    fseek(archive, POS+1, SEEK_SET);
    cout<<"Code: ";
    word = fgetc(archive);
    Code=word;
    cout<<Code<<codeIcmpv6(TYPEicmp,Code)<<endl;

    fseek(archive,POS+2,SEEK_SET);
    cout<<"Header Checksum: 0x";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        HEADchecksum += charBuffer;
        }
    cout<<HEADchecksum<<endl;

    switch(TYPEicmp) {
    case 1://Unreachable
        /*fseek(archive,POS+8,SEEK_SET);
            cout<<"Target Address: ";
            for(i=0; i < 16; i++) {
                word = fgetc(archive);
                if(i%2!=0 && i<15) {
                    sprintf(charBuffer, "%02X:", word);
                    }
                else {
                    sprintf(charBuffer, "%02X", word);
                    }
                targetAddr += charBuffer;
                }
            ///cout<<targetAddr + " hola"<<endl;
            cout<<formatIPv6(targetAddr)<<endl;*/
        break;

    case 3://hop limit(time exceeded)

        break;

    case 2://packet too big

        break;

    case 128://echo request (ping)
        cout<<"POS "<<POS+8<<endl;
        fseek(archive,POS+8,SEEK_SET);
            cout<<"Identificador: ";
            for(i=0; i<2; i++) {
                word = fgetc(archive);
                sprintf(charBuffer, "%02X", word);
                IDN += charBuffer;
                }
            cout<<Hexa_Decimal(IDN)<<" "<<IDN<<endl;

            fseek(archive,POS+10,SEEK_SET);
            cout<<"Numero de secuencia: ";
            for(i=0; i<2; i++) {
                word = fgetc(archive);
                sprintf(charBuffer, "%02X", word);
                SEQ += charBuffer;
                }
            cout<<Hexa_Decimal(SEQ)<<endl;
        break;

    case 129://echo reply (pong)

        break;

    case 133://router solicitacion

        break;
    case 134://router advertisement

        break;

    case 135://Neighbor Solicitation
        fseek(archive,POS+8,SEEK_SET);
            cout<<"Target Address: ";
            for(i=0; i < 16; i++) {
                word = fgetc(archive);
                if(i%2!=0 && i<15) {
                    sprintf(charBuffer, "%02X:", word);
                    }
                else {
                    sprintf(charBuffer, "%02X", word);
                    }
                targetAddr += charBuffer;
                }
            ///cout<<targetAddr + " hola"<<endl;
            cout<<formatIPv6(targetAddr)<<endl;
        break;

    case 136://Neighbor Advertisement

        break;

    case 137://Redirect

        break;
            /*case 0://ping
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
                cout<<Hexa_Decimal(SEQ)<<" bytes"<<endl;

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
            break;*/
        }
    }


string formatIPv6(string& IPv6) {
    int i,zd=0,zi=0, x1, x2;
    size_t foundFirst=IPv6.find("000"), foundLast;
    string myStr;

    ///Eliminacion de ceros a la izquierda
    while(foundFirst != std::string::npos) {
        IPv6.erase(foundFirst, 3); // != std::string::npos, cuando ya no encuntra el 000
        foundFirst = IPv6.find("000");
        }

    while((foundFirst = IPv6.find(":00")) != std::string::npos) {
        IPv6.erase(foundFirst+1, 2); // != std::string::npos, cuando ya no encuntra el 00
        }
    for(i=0; i<IPv6.size(); i++) {
        if(IPv6[i-1]== ':' && IPv6[i]== '0' && IPv6[i+1]!= ':') { //Elimina si quedo un :0y(otro numero)
            IPv6.erase(i, 1);
            }
        }

    for(i=0; i<IPv6.size(); ++i) {
        if(IPv6[i-1]== ':' && IPv6[i]== '0' && IPv6[i+1]== ':' && IPv6[i+2]== '0' && IPv6[i+3]== ':') {
            zi++;//medio
            x1=i;
            ///cout<<" m"<<i<<" ";

            }
        else if(IPv6[i-3]== ':' && IPv6[i-2]== '0' && IPv6[i-1]== ':' && IPv6[i]== '0') {
            zi++;//fin
            ///x1=i;cout<<" f"<<i<<" ";

            }
        else if(IPv6[i-1]== '\0' && IPv6[i]== '0' && IPv6[i+1]== ':' && IPv6[i+2]== '0' && IPv6[i+3]== ':') {
            zi++;//inicio
            ///x1=i;cout<<" i"<<i<<" ";

            }
        }
    ///cout<<endl<<"zi: "<<zi<<endl;
    ///cout<<"x1: "<<x1<<endl;

    for(i=IPv6.size(); i>=0; i--) {
        if(IPv6[i+1]== ':' && IPv6[i]== '0' && IPv6[i-1]== ':' && IPv6[i-2]== '0' && IPv6[i-3]== ':') {
            zd++;//medio
            //i-=3;
            ///cout<<" m"<<i<<" ";
            x2=i-1;


            }
        else if(IPv6[i-1]== '\0' && IPv6[i]== '0' && IPv6[i+1]== ':' && IPv6[i+2]== '0' && IPv6[i+3]== ':') {
            zd++;//fin
            ///cout<<" f"<<i<<" ";x2=i-1;

            }
        else if(IPv6[i-5]!= '0' && (IPv6[i-4]!= ':' || IPv6[i-3]!= '0') && IPv6[i-2]== ':' && IPv6[i-1]== '0' && IPv6[i]== ':' && IPv6[i+1]== '0') {
            zd++;//inicio
            ///cout<<" i"<<i<<" ";x2=i-1;

            }
        }
    ///cout<<endl<<"zd: "<<zd<<endl;
    ///cout<<"x2: "<<x2<<endl;
    ///cout<<IPv6<<endl;


    ///Eliminacion (compresion)
    if(zd>zi) {
        ///cout<<"der"<<endl;
        IPv6.erase(x1,(zd+(zd-1)));
        }
    else {
        ///cout<<"izq"<<endl;
        IPv6.erase(x2,(zi+(zi-1)));
        }

    for(int i=0; i<IPv6.size(); i++) {
        if(IPv6[i-2]!=':' && IPv6[i-1]==':' && IPv6[i]=='0' && IPv6[i+1]!=':') {
            IPv6.erase(i,1);
            IPv6.insert(i,":");
            }
        }
    return IPv6;
    }

void LeerIPv6(int POS, bool flag) { // POS14
    int i=0,x=0, binary, bitsPart1, bitsPart2, FL, VERSION, TIMEtoLIVE, PROTOCOL, intPayload, longNext, next, nextHeader;
    string Payload, NextH, HEADchecksum, SOURCE_IP, DESTINATION_IP;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t IPv6 "<<endl;

    fseek(archive,POS, SEEK_SET);
    cout<<"Version: ";
    word = fgetc(archive);
    binary = word;//recibe expresion decimal para convetirlo a entero
    bitsPart2 = binary & 240;//obtenemos 4 "ultimos" bits (los mas significantes)
    VERSION = bitsPart2>>4;
    if(VERSION == 6) {
        cout<<"IPv6";
        }
    cout<<" ("<<VERSION<<")"<<endl;

    /*bitsPart1 = binary & 15;//obtenemos 4 "primeros" bits del primer byte(los menos significantes)            Traffic class de 8 bits
    cout<<"Traffic class: ";
    fseek(archive,0, POS+1);
    word = fgetc(archive);
    binary = word;//Obtenemos el "segundo" byte
    bitsPart2 = binary & 240;//obtenemos 4 "ultimos" bits (los mas significantes)
    cout<<bitsPart2+bitsPart2<<endl;*/

    cout<<"Traffic class: ";
    bitsPart1 = binary & 15;//obtenemos 4 "primeros" bits (los menos significantes)
    cout<<(bitsPart1*4)*5<<endl;

    fseek(archive,0, POS+1);
    cout<<"Flow Label: ";
    for(i=0; i<3; i++) {
        word = fgetc(archive);
        FL = word;
        }
    cout<<FL<<endl;

    fseek(archive,0, POS+4);
    cout<<"Payload Lenght: ";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        Payload += charBuffer;
        }
    cout<<(intPayload=Hexa_Decimal(Payload))<<" bytes"<<endl;

    fseek(archive,0, POS+5);
    cout<<"Next Header: ";
    word = fgetc(archive);
    nextHeader= word;
    cout<<word<<TYPEofPROTOCOL(word)<<endl;

    fseek(archive,POS+7,SEEK_SET);
    cout<<endl<<"Hop Limit: ";
    word = fgetc(archive);
    TIMEtoLIVE = word;
    cout<<TIMEtoLIVE<<" brincos"<<endl;

    fseek(archive,POS+8, SEEK_SET);
    cout<<"IP Source Address: ";
    for(i=0; i < 16; i++) {
        word = fgetc(archive);
        if(i%2!=0 && i<15) {
            sprintf(charBuffer, "%02X:", word);
            }
        else {
            sprintf(charBuffer, "%02X", word);
            }

        SOURCE_IP += charBuffer;
        }
    ///cout<<SOURCE_IP<<endl<<endl;
    cout<<formatIPv6(SOURCE_IP)<<endl;

    fseek(archive,0, POS+24);
    cout<<"IP Destination Address: ";
    for(i=0; i < 16; i++) {
        word = fgetc(archive);
        if(i%2!=0 && i<15) {
            sprintf(charBuffer, "%02X:", word);
            }
        else {
            sprintf(charBuffer, "%02X", word);
            }
        DESTINATION_IP += charBuffer;
        }
    ///cout<<DESTINATION_IP<<endl<<endl;
    cout<<formatIPv6(DESTINATION_IP)<<endl;

    if(nextHeader == 58 || nextHeader == 17){
        LeerICMPv6((POS+40),intPayload);
        }
    else {
        fseek(archive,0, POS+40);//otro header
        word = fgetc(archive);
        next=word;

        fseek(archive,0, POS+41);
        word = fgetc(archive);
        longNext=word;
        longNext =(longNext+1)*8;
        //cout<<POS+longNext+40;

        LeerICMPv6((POS+longNext+40),intPayload);
        }
    }

string codeIcmpv4(const int& type, const int& subvalor) {
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

    string Extended_Echo_Reply[] {  ///type 43
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
    switch(type) {
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
            if (type<44) {
                return myStr += codeRest[type];
                }
            else {
                return myStr += "Reserve";
                }
        }

    }

string typeIcmpv4(const int& type) {
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
    cout<<TYPEicmp<<typeIcmpv4(TYPEicmp)<<endl;

    fseek(archive, 0, POS+1);
    cout<<"Code: ";
    word = fgetc(archive);
    Code=word;
    cout<<Code<<codeIcmpv4(TYPEicmp,Code)<<endl;

    fseek(archive,POS+2,SEEK_SET);
    cout<<"Header Checksum: 0x";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        HEADchecksum += charBuffer;
        }
    cout<<HEADchecksum<<endl;

    switch(TYPEicmp) {
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
                            "ICMP	Internet Control Message Protocol",
                            "IGMP	Internet Group Management Protocol",
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

    if(flag && PROTOCOL==1) {
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
    else if(secondBit == 0) {
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
    else if(secondBit == 0) {
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
    else if (ETHER == "86DD") {
        LeerIPv6(14, true);
        }
    }
