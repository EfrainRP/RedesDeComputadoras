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

int Hexa_Decimal(string hex) {
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

void TYPEofPROTOCOL(int valor) {
    switch (valor) {
        case 0:
            cout<<"  (HOPOPT)  - IPv6 Hop-by-Hop Option"<<endl;
            break;
        case 1:
            cout<<"  (ICMP)  - Internet Control Message Protocol"<<endl;
            break;
        case 2:
            cout<<"  (IGMP)  - Internet Group Management Protocol"<<endl;
            break;
        case 3:
            cout<<"  (GGP)  - Gateway-to-Gateway Protocol"<<endl;
            break;
        case 4:
            cout<<"  (IP)  - IP en IP (encapsulación)"<<endl;
            break;
        case 5:
            cout<<"  (ST)  - Internet Stream Protocol"<<endl;
            break;
        case 6:
            cout<<"  (TCP)  - Transmission Control Protocol"<<endl;
            break;
        case 7:
            cout<<"  (CBT)  - Core-based trees"<<endl;
            break;
        case 8:
            cout<<"  (EGP)  - Exterior Gateway Protocol"<<endl;
            break;
        case 9:
            cout<<"  (IGP)  - Interior Gateway Protocol "<<endl;
            break;
        case 10:
            cout<<"  (BBN-RCC-MON)  - Monitoreo BBN RCC"<<endl;
            break;
        case 11:
            cout<<"  (NVP-II)  - Network Voice Protocol"<<endl;
            break;
        case 12:
            cout<<"  (PUP)  - Xerox PUP"<<endl;
            break;
        case 13:
            cout<<"  (ARGUS)"<<endl;
            break;
        case 14:
            cout<<"  (EMCON)"<<endl;
            break;
        case 15:
            cout<<"  (XNET)  - Cross Net Debugger"<<endl;
            break;
        case 16:
            cout<<"  (CHAOS)"<<endl;
            break;
        case 17:
            cout<<"  (UDP)  - User Datagram Protocol"<<endl;
            break;
        case 18:
            cout<<"  (MUX)  - Multiplexing"<<endl;
            break;
        case 19:
            cout<<"  (DCN-MEAS)  - DCN Measurement Subsystems"<<endl;
            break;
        case 20:
            cout<<"  (HMP)  - Host Monitoring Protocol"<<endl;
            break;
        case 21:
            cout<<"  (PRM)  - Packet Radio Measurement"<<endl;
            break;
        case 22:
            cout<<"  (XNS-IDP)  - XEROX NS IDP"<<endl;
            break;
        case 23:
            cout<<"  (TRUNK-1)"<<endl;
            break;
        case 24:
            cout<<"  (TRUNK-2)"<<endl;
            break;
        case 25:
            cout<<"  (LEAF-1)"<<endl;
            break;
        case 26:
            cout<<"  (LEAF-2)"<<endl;
            break;
        case 27:
            cout<<"  (RDP)  - Reliable Datagram Protocol"<<endl;
            break;
        case 28:
            cout<<"  (IRTP)  - Internet Reliable Transaction Protocol"<<endl;
            break;
        case 29:
            cout<<"  (ISO-TP4)  - ISO Transport Protocol Class 4"<<endl;
            break;
        case 30:
            cout<<"  (NETBLT)  - Bulk Data Transfer Protocol"<<endl;
            break;
        }
    }

void LeerIPv4() {
    int i=0, binary, bits, bitsProtocol, ToS, VERSION, JUMPOPTION, FLAGS, TIMEtoLIVE, PROTOCOL;
    string TOTAL_LENG, IDENTI, HEADchecksum, SOURCE_IP, DESTINATION_IP;

    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t IPv4 "<<endl;

    fseek(archive,14, SEEK_SET);
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

    fseek(archive,0, 15);
    cout<<"ToS (Types of Services): ";
    word = fgetc(archive);
    ToS = word;
    cout<<ToS<<endl;

    fseek(archive,0, 16);
    cout<<"Total Length: ";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        TOTAL_LENG += charBuffer;
        }
    cout<<Hexa_Decimal(TOTAL_LENG)<<" bytes"<<endl;


    fseek(archive,0, 18);
    cout<<"Identification: ";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        IDENTI += charBuffer;
        }
    cout<<Hexa_Decimal(IDENTI)<<endl;


    fseek(archive,20, SEEK_SET);
    cout<<endl<<"Flags:"<<endl;
    word = fgetc(archive);
    binary = word;
    FLAGS = (binary & 240)>>4;//obtenemos 4 "ultimos" bits (los mas significantes) y le hacemos un recorrimiento
    //cout<<FLAGS<<endl;
    cout<<"  + Reservado ("<<(FLAGS&8)/8<<")"<<endl;
    cout<<"  + Don't fragment ("<<(FLAGS&4)/4<<")"<<endl;
    cout<<"  + More fragment ("<<(FLAGS&2)/2<<")"<<endl;
    cout<<"- Fragment offset("<<(FLAGS&1)<<")"<<endl;

    fseek(archive,22,SEEK_SET);
    cout<<endl<<"TTL (Time to Live): ";
    word = fgetc(archive);
    TIMEtoLIVE = word;
    cout<<TIMEtoLIVE<<endl;

    fseek(archive,23,SEEK_SET);
    cout<<"Protocol: ";
    word = fgetc(archive);
    PROTOCOL = word;
    cout<<PROTOCOL;
    TYPEofPROTOCOL(PROTOCOL);

    fseek(archive,24,SEEK_SET);
    cout<<"Header Checksum: 0x";
    for(i=0; i<2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        HEADchecksum += charBuffer;
        }
    cout<<HEADchecksum<<endl;

    fseek(archive,26, SEEK_SET);
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

    fseek(archive,0, 30);
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
    }

void LeerARP() {
    string PROTOCOL_TYPE, SENDER_MAC, SENDER_IP, TARGET_MAC, TARGET_IP;
    int i=0, HARD_TYPE, HARD_ADDRESS_LENG,PROTO_ADDRESS_LENG, OPERATION;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ARP "<<endl;

    fseek(archive,14, SEEK_SET);
    cout<<endl<<"HardwareType: ";
    for(i=0; i < 2; i++) {
        word = fgetc(archive);
        HARD_TYPE = word;
        }
    cout<<HARD_TYPE;
    if(HARD_TYPE == 1) {
        cout<<" (Ethernet)"<<endl;
        }

    fseek(archive,0, 16);
    cout<<"Protocol type: 0x";
    for(i=0; i < 2; i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X", word);
        PROTOCOL_TYPE += charBuffer;
        }
    if(PROTOCOL_TYPE == "0800") {
        cout<<PROTOCOL_TYPE+" (IPv4)"<<endl;
        }

    fseek(archive,0, 18);
    cout<<"Hardware Address Length: ";
    word = fgetc(archive);
    HARD_ADDRESS_LENG = word;

    cout<<HARD_ADDRESS_LENG<<" bytes"<<endl;

    fseek(archive,0, 19);
    cout<<"Protocol Address Length: ";
    word = fgetc(archive);
    PROTO_ADDRESS_LENG = word;

    cout<<PROTO_ADDRESS_LENG<<" bytes"<<endl;

    fseek(archive,0, 20);
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

    fseek(archive,0, 22);
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

    fseek(archive,0, 28);
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

    fseek(archive,0, 32);
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

    fseek(archive,0, 38);
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
    for(i=0; i<=70; i++)
        cout<< "-";

    cout<<endl<< "\t\t\t ETHERNET "<<endl;


    fseek(archive,0, SEEK_SET);
    cout<<endl<<"Direccion MAC destino: ";
    for(i=0; i<6; i++) {
        word = fgetc(archive);
        if(i==0) {//recibo el primer byte
            firstBit = word & 1;//el primer bit(operacion binaria)     MULTICAST
            secondBit = word & 2;//el segundo bit(operacion binaria)    GLOBAL/LOCAL
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
            firstBit = word & 1;//el primer bit(operacion binaria)     MULTICAST
            secondBit = word & 2;//el segundo bit(operacion binaria)    GLOBAL/LOCAL
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
/*    switch(ETHER){
    case "0800":
        cout<<" (IPv4)"<<endl;
        break;

        case "0806":
        cout<<" (ARP)"<<endl;
        break;

        case "086DD":
        cout<<" (IPv6)"<<endl;
        break;
    }
*/
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
        LeerARP();
        }
    else if (ETHER == "0800") {
        LeerIPv4();
        }
    }

int main() {
    string nombre;
    int opcM=0;
    string arch = "E:\\Documentos PC\\UDG Materias\\REDES\\ARCHIVOS\\";

    while(opcM!=2){
    system("cls");
    cout << "DIME EL NOMBRE DEL FICHERO: ";//ethernet_arp_reply.bin     ethernet_ipv4_icmp.bin
    getline(cin, nombre);//ethernet_1.bin       ethernet_ipv4_tcp.bin
nombre = arch + nombre + ".bin";
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
