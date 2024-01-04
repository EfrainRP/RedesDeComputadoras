#include "ETHERNET.h"

/*DICCIONARY::DICCIONARY():ptr(-1),link(NULL) {}

void DICCIONARY::setPtr(const int&i) {
    ptr = i;
    }

int DICCIONARY::getPtr() {
    return ptr;
    }

void DICCIONARY::setLink(const string&i) {
    link = i;
    }

string  DICCIONARY::getLink() {
    return link;
    }*/


void Ethernet::setColor(const int k) {
    HANDLE hConsole=GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, k);
    }

Ethernet::Ethernet() {}

Ethernet::Ethernet(List<unsigned char>& _infoPack): infoPack(_infoPack), POS(0) {}

Ethernet::~Ethernet() {
    infoPack.deleteAll();
    }

List<unsigned char>& Ethernet:: operator = (const List<unsigned char>& e) {
    infoPack = e;
    POS=0;
    *this;
}

void Ethernet::LeerCabeceraEthernet() {
    string MACd, MACo, ETHER, FCS;
    int i, firstBit, secondBit;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";

    cout<<endl<< "\t\t\t ETHERNET "<<endl;


    //fseek(archive,0, SEEK_SET);
    cout<<endl<<"Direccion MAC destino: ";
    for(i=0; i<6; i++) {
        if(i<5) {
            sprintf(charBuffer,"%02X:", infoPack[POS++]);
            }
        else {
            sprintf(charBuffer,"%02X", infoPack[POS++]);
            }
        MACd+= charBuffer;
        }
    cout<<MACd<<endl;

    firstBit = infoPack[0] & 1;//el primer bit(operacion binaria)
    secondBit = infoPack[0] & 2;//el segundo bit(operacion binaria)

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

    //fseek(archive,0, 6);
    cout<<endl<<"Direccion MAC origen: ";
    for(i=POS; i<POS+6; i++) {
        if(i<POS+5) {
            sprintf(charBuffer,"%02X:", infoPack[i]);
            }
        else {
            sprintf(charBuffer,"%02X", infoPack[i]);
            }
        MACo+=charBuffer;
        }
    POS+=6;
    cout<<MACo<<endl;

    firstBit = infoPack[6] & 1;//el primer bit(operacion binaria)
    secondBit = infoPack[6] & 2;//el segundo bit(operacion binaria)

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

    //fseek(archive,12, SEEK_SET);
    cout<<endl<<"Ethertype: 0x";
    for(i=POS; i<POS+2; i++) {
        sprintf(charBuffer,"%02X", infoPack[i]);
        ETHER += charBuffer;
        }
    POS+=2;
    cout<<ETHER<<etherType(ETHER)<<endl;
    /*if(ETHER == "0800") {
        cout<<" (IPv4)"<<endl;
        }
    else if(ETHER == "0806") {
        cout<<" (ARP)"<<endl;
        }
    else if(ETHER == "86DD") {
        cout<<" (IPv6)"<<endl;
        }*/

    int Size=infoPack.getListSize();

    if(ETHER == "0806") {//POS = 14
        cout<< (Size - 18)<<" bytes de carga util en Ethernet"<<endl; //Se resta 18, debido a los bytes que se usan para la cabecera (MAC Addres y etc)
        cout<<"FCS: 0x ";
        for(i=Size-4; i<Size; i++) {
            sprintf(charBuffer,"%02X ", infoPack[i]);
            FCS += charBuffer;
            }
        cout<<FCS<<endl;
        LeerARP();
        }
    else if (ETHER == "0800") {
        cout<<"FCS: 0x ";
        for(i=Size-4; i<Size; i++) {
            sprintf(charBuffer,"%02X ", infoPack[i]);
            FCS += charBuffer;
            }
        cout<<FCS<<endl;
        LeerIPv4(true);
        }
    else if (ETHER == "86DD") {
        LeerIPv6(true);
        }
    }

void Ethernet::LeerARP() {
    string PROTOCOL_TYPE, SENDER_MAC, SENDER_IP, TARGET_MAC, TARGET_IP;
    int i=0,HARD_ADDRESS_LENG=0,PROTO_ADDRESS_LENG=0, OPERATION=0,HARD_TYPE=0;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ARP "<<endl;

//    fseek(archive,POS, SEEK_SET);
    cout<<endl<<"HardwareType: ";
    for(i=POS; i < POS+2; i++) {
        HARD_TYPE += infoPack[i];
        }
    POS+=2;
    cout<<HARD_TYPE;
    if(HARD_TYPE == 1) {
        cout<<" (Ethernet)"<<endl;
        }

//    fseek(archive,0, POS+2);
    cout<<"Protocol type: 0x";
    for(i=POS; i < POS+2; i++) {
        sprintf(charBuffer,"%02X", infoPack[i]);
        PROTOCOL_TYPE += charBuffer;
        }
    POS+=2;
    if(PROTOCOL_TYPE == "0800") {
        cout<<PROTOCOL_TYPE+" (IPv4)"<<endl;
        }

//    fseek(archive,0, POS+4);
    cout<<"Hardware Address Length: ";
    HARD_ADDRESS_LENG = infoPack[POS++];

    cout<<HARD_ADDRESS_LENG<<" bytes"<<endl;
//    fseek(archive,0, POS+5);
    cout<<"Protocol Address Length: ";
    PROTO_ADDRESS_LENG = infoPack[POS++];

    cout<<PROTO_ADDRESS_LENG<<" bytes"<<endl;

//    fseek(archive,0, POS+6);
    cout<<"Operation: ";//<<POS;
    for(i=POS; i < POS+2; i++) {
        OPERATION += infoPack[i];
        }
    POS+=2;
    if(OPERATION == 1) {
        cout<<"ARP Request ("<<OPERATION<<")";
        }
    else if(OPERATION == 2) {
        cout<<"ARP Reply ("<<OPERATION<<")";
        }

//    fseek(archive,0, POS+8);
    cout<<endl<<"Sender MAC Address: ";
    for(i=POS; i < POS+6; i++) {
        if(i<POS+5) {
            sprintf(charBuffer,"%02X:", infoPack[i]);
            }
        else {
            sprintf(charBuffer,"%02X ", infoPack[i]);

            }
        SENDER_MAC += charBuffer;
        }
    POS+=6;
    cout<<SENDER_MAC<<endl;

//    fseek(archive,0, POS+14);
    cout<<"Sender IP Address: ";
    for(i=POS; i < POS+4; i++) {
        if(i<3) {
            sprintf(charBuffer,"%i.", infoPack[i]);
            }
        else {
            sprintf(charBuffer,"%i", infoPack[i]);
            }
        SENDER_IP += charBuffer;
        }
    POS+=4;
    cout<<SENDER_IP<<endl;

//    fseek(archive,0, POS+18);
    cout<<"Target Mac Address: ";
    for(i=POS; i < POS+6; i++) {
        if(i<POS+5) {
            sprintf(charBuffer,"%02X:", infoPack[i]);
            }
        else {
            sprintf(charBuffer,"%02X", infoPack[i]);

            }
        TARGET_MAC += charBuffer;
        }
    POS+=6;
    cout<<TARGET_MAC<<endl;

//    fseek(archive,0, POS+24);
    cout<<"Target IP Address: ";
    for(i=POS; i < POS+4; i++) {
        if(i<3) {
            sprintf(charBuffer,"%i.", infoPack[i]);
            }
        else {
            sprintf(charBuffer,"%i", infoPack[i]);
            }
        TARGET_IP+=charBuffer;
        }
    POS+=4;
    cout<<TARGET_IP<<endl;
    }

void Ethernet::LeerIPv4(const bool flag) {
    int i=0, bits, bitsProtocol, ToS, VERSION, JUMPOPTION, FLAGS, TIMEtoLIVE, PROTOCOL;
    string TOTAL_LENG, IDENTI, HEADchecksum, SOURCE_IP, DESTINATION_IP;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t IPv4 "<<endl;

//    fseek(archive,POS, SEEK_SET);
    cout<<"Version: ";
    i=infoPack[POS++];
    bits = i & 240;//obtenemos 4 "ultimos" bits (los mas significantes)
    VERSION = bits>>4;
    if(VERSION == 4) {
        cout<<"IPv4";
        }
    cout<<" ("<<VERSION<<")"<<endl;

    cout<<"IHL (Inter Header Length): ";
    bits = i & 15;//obtenemos 4 "primeros" bits (los menos significantes)
    bitsProtocol = bits*4;

    cout<<bitsProtocol<<" bytes ("<<bits<<")"<<endl; //No hay opciones

    JUMPOPTION = bitsProtocol - 20;

//    fseek(archive,0, POS+1);
    cout<<"ToS (Types of Services): ";
    ToS = infoPack[POS++];
    cout<<ToS<<endl;

//    fseek(archive,0, POS+2);
    cout<<"Total Length: ";
    for(i=POS; i<POS+2; i++) {
        sprintf(charBuffer,"%02X",infoPack[i]);
        TOTAL_LENG += charBuffer;
        }
    POS+=2;
    cout<<Hexa_Decimal(TOTAL_LENG)<<" bytes"<<endl;


//    fseek(archive,0, POS+4);
    cout<<"Identification: ";
    for(i=POS; i<POS+2; i++) {
        sprintf(charBuffer,"%02X",infoPack[i]);
        IDENTI += charBuffer;
        }
    POS+=2;
    cout<<Hexa_Decimal(IDENTI)<<endl;

//    fseek(archive,POS+6, SEEK_SET);
    cout<<endl<<"Flags:"<<endl;
    FLAGS = (infoPack[POS++] & 240)>>4;//obtenemos 4 "ultimos" bits (los mas significantes) y le hacemos un recorrimiento

    //cout<<FLAGS<<endl;
    cout<<"  + Reservado ("<<(FLAGS&8)/8<<")"<<endl;
    cout<<"  + Don't fragment ("<<(FLAGS&4)/4<<")"<<endl;
    cout<<"  + More fragment ("<<(FLAGS&2)/2<<")"<<endl;
    cout<<"- Fragment offset("<<(FLAGS&1)<<")"<<endl;

//    fseek(archive,POS+8,SEEK_SET);
    cout<<endl<<"TTL (Time to Live): ";
    TIMEtoLIVE = infoPack[++POS];
    cout<<TIMEtoLIVE<<" brincos"<<endl;

//    fseek(archive,POS+9,SEEK_SET);
    cout<<"Protocol: ";
    PROTOCOL = infoPack[++POS];
    cout<<PROTOCOL<<TYPEofPROTOCOL(PROTOCOL)<<endl;

//    fseek(archive,POS+10,SEEK_SET);
    POS++;
    cout<<"Header Checksum: 0x";
    for(i=POS; i<POS+2; i++) {
        sprintf(charBuffer,"%02X",infoPack[i]);
        HEADchecksum += charBuffer;
        }
    POS+=2;
    cout<<HEADchecksum<<endl;

//    fseek(archive,POS+12, SEEK_SET);
    cout<<"IP Source Address: ";
    for(i=POS; i < POS+4; i++) {
        if(i<POS+3) {
            sprintf(charBuffer,"%i.",infoPack[i]);;
            }
        else {
            sprintf(charBuffer,"%i",infoPack[i]);
            }
        SOURCE_IP+=charBuffer;
        }
    POS+=4;
    cout<<SOURCE_IP<<endl;

//    fseek(archive,0, POS+16);
    cout<<"IP Destination Address: ";
    for(i=POS; i < POS+4; i++) {
        if(i<POS+3) {
            sprintf(charBuffer,"%i.",infoPack[i]);
            }
        else {
            sprintf(charBuffer,"%i",infoPack[i]);
            }
        DESTINATION_IP+=charBuffer;
        }
    POS+=4;
    cout<<DESTINATION_IP<<endl;

    if(PROTOCOL == 17) { //Protocol de UDP
        LeerUDP();
        }
    else if(flag && PROTOCOL==1) { //Protocol de ICMP
        POS+=JUMPOPTION;
        LeerICMPv4();//salto las optiones
        }
    else if(PROTOCOL==6) {  //Protocol TCP
        LeerTCP(POS);
        }
    }

void Ethernet::LeerICMPv4() {
    int i, TYPEicmp, Code;
    string HEADchecksum, IDN, SEQ, redirectIP;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ICMPv4 "<<endl<<endl;

//    fseek(archive,POS, SEEK_SET);
    cout<<"Type: ";
    TYPEicmp=infoPack[POS++];
    cout<<TYPEicmp<<typeIcmpv4(TYPEicmp)<<endl;

//    fseek(archive, 0, POS+1);
    cout<<"Code: ";
    Code=infoPack[POS++];
    cout<<Code<<codeIcmpv4(TYPEicmp,Code)<<endl;

//    fseek(archive,POS+2,SEEK_SET);
    cout<<"Header Checksum: 0x";
    for(i=POS; i<POS+2; i++) {
        sprintf(charBuffer,"%02X",infoPack[i]);
        HEADchecksum += charBuffer;
        }
    POS+=2;
    cout<<HEADchecksum<<endl;

    switch(TYPEicmp) {
        case 0://ping
        case 8://pong
//            fseek(archive,0,POS+4);
            cout<<"Identificador: ";
            for(i=POS; i<POS+2; i++) {
                IDN += infoPack[i];
                }
            POS+=2;
            cout<<Hexa_Decimal(IDN)<<endl;

//            fseek(archive,POS+6,SEEK_SET);
            cout<<"Numero de secuencia: ";
            for(i=POS; i<POS+2; i++) {
                SEQ += infoPack[i];
                }
            POS+=2;
            cout<<Hexa_Decimal(SEQ)<<endl;
            break;
        case 3://unreachable
        case 11://ttl
            LeerIPv4(false);///POS+8??
            break;

        case 5://redirect
//            fseek(archive,POS+4,SEEK_SET);
            cout<<endl<<"Direccion IP de Redirect: ";
            for(i=POS; i < POS+4; i++) {
                if(i<POS+3) {
                    sprintf(charBuffer,"%i.",infoPack[i]);
                    }
                else {
                    sprintf(charBuffer,"%i",infoPack[i]);

                    }
                redirectIP += charBuffer;
                }
            POS+=4;
            cout<<redirectIP<<endl;

            LeerIPv4(false);
            break;
        }
    }

void Ethernet::LeerIPv6(const bool flag) {
    int i=0, bitsPart1, bitsPart2, FL = 0, VERSION, TIMEtoLIVE;
    int intPayload, longNext, nextHeader;
    string Payload, NextH, HEADchecksum, SOURCE_IP, DESTINATION_IP;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t IPv6 "<<endl;

//    fseek(archive,POS, SEEK_SET);
    cout<<"Version: ";
//    binary = valueArchive;//recibe expresion decimal para convetirlo a entero
    bitsPart2 = infoPack[POS] & 240;//obtenemos 4 "ultimos" bits (los mas significantes)
    VERSION = bitsPart2>>4;
    if(VERSION == 6) {
        cout<<"IPv6";
        }
    cout<<" ("<<VERSION<<")"<<endl;

    cout<<"Traffic class: ";
    bitsPart1 = infoPack[POS++] & 15;//obtenemos 4 "primeros" bits (los menos significantes)
    cout<<(bitsPart1*4)*5<<endl;

//    fseek(archive,0, POS+1);
    cout<<"Flow Label: ";
    for(i=POS; i<POS+3; i++) {
        FL += infoPack[i];
        }
    POS+=3;
    cout<<FL<<endl;

//    fseek(archive,0, POS+4);
    cout<<"Payload Lenght: ";
    for(i=POS; i<POS+2; i++) {
        sprintf(charBuffer,"%02X",infoPack[i]);
        Payload += charBuffer;
        }
    POS+=2;
    cout<<(intPayload = Hexa_Decimal(Payload))<<" bytes"<<endl;

//    fseek(archive,0, POS+5);
    cout<<"Next Header: ";
    nextHeader = infoPack[POS];
    cout<<nextHeader<<TYPEofPROTOCOL(infoPack[POS++])<<endl;

//    fseek(archive,POS+7,SEEK_SET);
    cout<<endl<<"Hop Limit: ";
    TIMEtoLIVE = infoPack[POS++];
    cout<<TIMEtoLIVE<<" brincos"<<endl;

//    fseek(archive,POS+8, SEEK_SET);
    cout<<"IP Source Address: ";
    for(i=POS; i < POS+16; i++) {
        if(i%2!=0 && i<POS+15) {
            sprintf(charBuffer,"%02X:",infoPack[i]);
            }
        else {
            sprintf(charBuffer,"%02X",infoPack[i]);

            }
        SOURCE_IP += charBuffer;
        }
    POS+=16;
    cout<<formatIPv6(SOURCE_IP)<<endl;

//    fseek(archive,0, POS+24);
    cout<<"IP Destination Address: ";
    for(i=POS; i < POS+16; i++) {
        if(i%2!=0 && i<POS+15) {
            sprintf(charBuffer,"%02X:",infoPack[i]);
            }
        else {
            sprintf(charBuffer,"%02X",infoPack[i]);
            }
        DESTINATION_IP+=charBuffer;
        }
    POS+=16;
    cout<<formatIPv6(DESTINATION_IP)<<endl;
    ///cout<<"POS "<<POS<<endl;

    if(nextHeader == 58) {//ICMP
        if(flag) {
            LeerICMPv6(intPayload);
            }
        }
    else if (nextHeader == 17) {//UDP
        LeerUDP();
        }
    else if(nextHeader == 6) {//TCP
        LeerTCP(POS);
        }
    else {
        POS++;///se deberia hacer un analizis del next header
        longNext=infoPack[POS++];
        longNext +=(longNext+1)*8;

        if(flag) {
            POS=(POS-2)+longNext;
            LeerICMPv6(intPayload);
            }
        }
    }

void Ethernet::LeerICMPv6(const int& PAYLOAD) {
    int i=0, TYPEicmp=0, Code=0, LastPos=POS, bits=0, restPOS=0, mov=0;
    string HEADchecksum, targetAddr, IDN, SEQ,tooBigIP,RouterLife,reachableTime, retransTimer,DestAddr;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ICMPv6 "<<endl<<endl;
//pos54
    //fseek(archive,POS, SEEK_SET);

    cout<<"Type: ";
    TYPEicmp=infoPack[POS++];
    cout<<TYPEicmp<<typeICMPV6(TYPEicmp)<<endl;

    //fseek(archive, POS+1, SEEK_SET);
    cout<<"Code: ";
    Code=infoPack[POS++];
    cout<<Code<<codeIcmpv6(TYPEicmp,Code)<<endl;

    //fseek(archive,POS+2,SEEK_SET);
    cout<<"Header Checksum: 0x";
    for(i=POS; i<POS+2; i++) {
        sprintf(charBuffer,"%02X",infoPack[i]);
        HEADchecksum += charBuffer;
        }
    POS+=2;
    cout<<HEADchecksum<<endl;

    ///cout<<"POS "<<POS<<endl;
    switch(TYPEicmp) {
        case 1://Unreachable
            POS+=4;
            LeerIPv6(false);
            break;

        case 2://infoPacket too big
            /*cout<<"Direccion IP de infoPacket too Big: ";
                for(i=POS; i<POS+6; i++) {
                if(i<POS+5){
                    tooBigIP += infoPack[i] + ":";
                    }
                else {
                    tooBigIP += infoPack[i];
                    }
                    }
                    POS+=6;
                cout<<formatIPv6(tooBigIP)<<endl;*/
            POS+=4;
            LeerIPv6(false);
            break;

        case 3://hop limit(time exceeded)
            POS+=4;
            LeerIPv6(false);
            break;

        case 128://echo request (ping)
            //fseek(archive,POS+8,SEEK_SET);
            cout<<"Identificador: ";
            for(i=POS; i<POS+2; i++) {
                sprintf(charBuffer,"%02X",infoPack[i]);
                IDN += charBuffer;
                }
            POS+=2;
            cout<<Hexa_Decimal(IDN)<<endl;

            //fseek(archive,POS+10,SEEK_SET);
            cout<<"Numero de secuencia: ";
            for(i=POS; i<POS+2; i++) {
                sprintf(charBuffer,"%02X",infoPack[i]);
                SEQ += charBuffer;
                }
            POS+=2;
            cout<<Hexa_Decimal(SEQ)<<endl;
            break;

        case 129://echo reply (pong)
            cout<<"Identificador: ";
            for(i=POS; i<POS+2; i++) {
                sprintf(charBuffer,"%02X",infoPack[i]);
                IDN += charBuffer;
                }
            POS+=2;
            cout<<Hexa_Decimal(IDN)<<endl;

            //fseek(archive,POS+10,SEEK_SET);
            cout<<"Numero de secuencia: ";
            for(i=POS; i<POS+2; i++) {
                sprintf(charBuffer,"%02X",infoPack[i]);
                SEQ += charBuffer;
                }
            POS+=2;
            cout<<Hexa_Decimal(SEQ)<<endl;
            break;

        case 133://router solicitacion
            POS+=4;
            while(PAYLOAD>(restPOS=POS-LastPos)) {
                mov = PAYLOAD-restPOS;
                optionsICMPv6(mov);
                }
            break;

        case 134://router advertisement
            sprintf(charBuffer,"%i",infoPack[POS++]);
            cout<<"Cur Hop Limit: "<<charBuffer<<endl;

            bits=(infoPack[POS]>>4)&8;
            cout<<"Bandera de configuracion de direccion administrada: "<<bits<<endl;

            bits=(infoPack[POS++]>>4)&4;
            cout<<"Otra bandera de configuracion: "<<bits<<endl;

            cout<<"Router Lifetime: ";
            for(i=POS; i<POS+2; i++) {
                sprintf(charBuffer,"%02X",infoPack[i]);
                RouterLife += charBuffer;
                }
            POS+=2;
            cout<<Hexa_Decimal(RouterLife)<<endl;

            cout<<"Reachable Time: ";
            for(i=POS; i<POS+4; i++) {
                sprintf(charBuffer,"%02X",infoPack[i]);
                reachableTime += charBuffer;
                }
            POS+=4;
            cout<<Hexa_Decimal(reachableTime)<<endl;

            cout<<"Retrans Timer: ";
            for(i=POS; i<POS+4; i++) {
                sprintf(charBuffer,"%02X",infoPack[i]);
                retransTimer += charBuffer;
                }
            POS+=4;
            cout<<Hexa_Decimal(retransTimer)<<endl;

            while(PAYLOAD>(restPOS=POS-LastPos)) {
                mov = PAYLOAD-restPOS;
                optionsICMPv6(PAYLOAD);
                }
            break;

        case 135://Neighbor Solicitation        ipv6_nd_sol_2
            POS+=4;
            //fseek(archive,POS+8,SEEK_SET);
            cout<<"Target Address: ";
            for(i=POS; i<POS+16; i++) {
                if(i%2!=0 && i<POS+15) {
                    sprintf(charBuffer,"%02X:",infoPack[i]);
                    }
                else {
                    sprintf(charBuffer,"%02X",infoPack[i]);
                    }
                targetAddr += charBuffer;
                }
            POS+=16;
            cout<<formatIPv6(targetAddr)<<endl;
            ///cout<<"POS: "<<POS<<"           restPos: "<<POS-LastPos<<"           payload: "<<PAYLOAD<<"           mov: "<<PAYLOAD-(POS-LastPos);
            while(PAYLOAD>(restPOS=POS-LastPos)) {

                mov = PAYLOAD-restPOS;
                optionsICMPv6(PAYLOAD);
                }
            break;

        case 136://Neighbor Advertisement
            bits=(infoPack[POS]>>4)&8;
            cout<<"\t->(R) Router Flag: "<<bits<<endl;

            bits=((infoPack[POS]>>4)&4)/4;
            cout<<"\t->(S) Solicited flag: "<<bits<<endl;

            bits=((infoPack[POS]>>4)&2)/2;
            cout<<"\t->(O) Override flag: "<<bits<<endl;
            POS+=4;

            cout<<"Target Address: ";
            for(i=POS; i<POS+16; i++) {
                if(i%2!=0 && i<POS+15) {
                    sprintf(charBuffer,"%02X:",infoPack[i]);
                    }
                else {
                    sprintf(charBuffer,"%02X",infoPack[i]);

                    }
                targetAddr += charBuffer;
                }
            POS+=16;

            cout<<formatIPv6(targetAddr)<<endl;

            while(PAYLOAD>(restPOS=POS-LastPos)) {
                mov = PAYLOAD-restPOS;
                optionsICMPv6(PAYLOAD);
                }
            break;

        case 137://Redirect
            POS+=4;
            cout<<"Target Address: ";
            for(i=POS; i<POS+16; i++) {
                if(i%2!=0 && i<POS+15) {
                    sprintf(charBuffer,"%02X:",infoPack[i]);
                    }
                else {
                    sprintf(charBuffer,"%02X",infoPack[i]);
                    }
                targetAddr += charBuffer;
                }
            POS+=16;
            cout<<formatIPv6(targetAddr)<<endl;
            cout<<"Destination Address: ";
            for(i=POS; i<POS+16; i++) {
                if(i%2!=0 && i<POS+15) {
                    sprintf(charBuffer,"%02X:",infoPack[i]);
                    }
                else {
                    sprintf(charBuffer,"%02X",infoPack[i]);
                    }
                DestAddr += charBuffer;
                }
            POS+=16;
            cout<<formatIPv6(DestAddr)<<endl;

            while(PAYLOAD>(restPOS=POS-LastPos)) {
                mov = PAYLOAD-restPOS;
                optionsICMPv6(PAYLOAD);
                }
            break;
        }
    }

void Ethernet::optionsICMPv6(const int&) {
    string SOURCE_LINK, TARGET_LINK, FinalPREFIX;
    int i=0, TYPE=0, LENGTH=0, PreFixLENGTH=0, FLAGS=0;
    int LifeTime=0, PreferLifeTime=0;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ICMPv6 Options "<<endl<<endl;
    //movement=movement+POS;

    //cout<<"Pos "<<POS<<e ndl<<endl;
    TYPE=infoPack[POS++];
    LENGTH=infoPack[POS++];
    //cout<<"Type: "<<TYPE<<endl<<"Length: "<<LENGTH<<endl<<endl;

    if(TYPE==1) {
        cout<<"Source Link-Layer Address: ";
        for(i=0; i<6; i++) {
            if(i < POS+5) {
                sprintf(charBuffer,"%02X:",infoPack[i]);
                }
            else {
                sprintf(charBuffer,"%02X",infoPack[i]);

                }
            SOURCE_LINK += charBuffer;
            }
        POS+=6;
        cout<<SOURCE_LINK<<endl;
        }

    if(TYPE==2) {
        cout<<"Target Link-Layer Address: ";
        for(i=POS; i<POS+6; i++) {
            if(i < POS+5) {
                sprintf(charBuffer,"%02X:",infoPack[i]);
                }
            else {
                sprintf(charBuffer,"%02X",infoPack[i]);

                }
            TARGET_LINK += charBuffer;
            }
        POS+=6;
        cout<<TARGET_LINK<<endl;
        }

    if(TYPE==3) {
        LENGTH=8*LENGTH;
        cout<<"\tType Prefix Info: "<<endl;
        PreFixLENGTH=infoPack[POS++]/8;
        cout<<"Prefix Length: "<<PreFixLENGTH<<" bytes"<<endl;

        cout<<"Flags: "<<endl;

        FLAGS = (infoPack[POS++] & 240)>>4;//obtenemos 4 "ultimos" bits (los mas significantes) y le hacemos un recorrimiento

        cout<<"\t-> L, On-Link Flag ("<<(FLAGS&4)/4<<")"<<endl;
        cout<<"\t-> A, Autonomous Address-Configuration Flag ("<<(FLAGS&2)/2<<")"<<endl;

        cout<<"Valid LifeTime: ";
        for(i=POS; i<POS+4; i++) {
            LifeTime += infoPack[i];
            }
        POS+=4;
        cout<<LifeTime<<endl;

        cout<<"Preferred Lifetime: ";
        for(i=POS; i<POS+4; i++) {
            LifeTime += infoPack[i];
            }
        POS+=4;
        cout<<PreferLifeTime<<endl;
        POS+=4;

        cout<<"Prefix: ";
        for(i=POS; i<POS+16; i++) {
            if(i%2!=0 && i < POS+15) {
                sprintf(charBuffer,"%02X:",infoPack[i]);
                }
            else {
                sprintf(charBuffer,"%02X",infoPack[i]);
                }
            FinalPREFIX += charBuffer;
            }
        POS+=16;
//empieza en 2001

        cout<<formatIPv6(FinalPREFIX)<<"/"<<PreFixLENGTH*8<<endl;
        }

    if(TYPE==4) {
        cout<<"Type: "<<TYPE<<endl<<endl;
        cout<<"Length: "<<LENGTH<<endl;
        POS+=6;
        }
    sprintf(charBuffer,"%i",infoPack[POS]);
    //cout<<"POS: "<<POS<<"   INFOpos: "<<charBuffer<<endl;
    }

void Ethernet::LeerUDP() {
    int i=0, Long=0;
    string Checksum, PortDeOrigen, PortDest;

    ///cout<<"POS: "<<POS<<"   info: "<<(int)infoPack[POS]<<endl;
    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t UDP "<<endl<<endl;

    cout<<"Puerto de origen: ";
    for(i=0; i<2; i++) {
        sprintf(charBuffer,"%02X",infoPack[POS++]);
        PortDeOrigen += charBuffer;
        }
    cout<<Hexa_Decimal(PortDeOrigen)<<endl;

    cout<<"Puerto de destino: ";
    for(i=0; i<2; i++) {
        sprintf(charBuffer,"%02X",infoPack[POS++]);
        PortDest += charBuffer;
        }
    cout<<Hexa_Decimal(PortDest)<<endl;

    cout<<"Longitud: ";
    for(i=0; i<2; i++) {
        Long += infoPack[POS++];
        }
    sprintf(charBuffer,"%i",Long);
    cout<<charBuffer<<endl;

    cout<<"Header Checksum: 0x";
    for(i=0; i<2; i++) {
        sprintf(charBuffer,"%02X",infoPack[POS++]);
        Checksum += charBuffer;
        }
    cout<<Checksum<<endl;
    if(Hexa_Decimal(PortDeOrigen)==53 || Hexa_Decimal(PortDest)==53) {
        LeerDNS();
        }
    }

void Ethernet::LeerDNS() {
    int dnsPOS=POS, FLAGS=0,i=0, questions=0, answers=0, authority=0, additional=0;
    string transitID, flags, PortDest;

    //cout<<"POS: "<<POS<<"   info: "<<(int)infoPack[POS]<<"   info next: "<<(int)infoPack[POS+1]<<endl;
    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t DNS "<<endl<<endl;

    cout<<"Transit ID: 0x";
    for(i=POS; i<POS+2; i++) {
        sprintf(charBuffer,"%02X",infoPack[i]);
        transitID += charBuffer;
        }
    POS+=2;
    cout<<transitID<<endl;

    cout<<"Flags: 0x";
    for(i=POS; i<POS+2; i++) {
        sprintf(charBuffer,"%02X",infoPack[i]);
        flags += charBuffer;
        }
    POS+=2;
    cout<<flags<<endl;
    FLAGS=Hexa_Decimal(flags);

    //bit = (FLAGS & 240);//obtenemos 4 "ultimos" bits (los mas significantes) y le hacemos un recorrimiento

    cout<<"  + Query/Response Flag ("<<(FLAGS&32768)/32768<<")"<<endl;

    cout<<"  + Operation Code ("<<((FLAGS&30720)>>11)<<")   -> "<<OpC_flag(((FLAGS&30720)>>11))<<endl;

    cout<<"  + Authoritative Answer Flag ("<<(FLAGS&1024)/1024<<")"<<endl;
    cout<<"  + Truncation Flag ("<<(FLAGS&512)/512<<")"<<endl;
    cout<<"  + Recursion Desired ("<<(FLAGS&256)/256<<")"<<endl;
    cout<<"  + Recursion Available ("<<(FLAGS&128)/128<<")"<<endl;
    cout<<"  + Zero ("<<((FLAGS&112)>>4)<<")"<<endl;

    cout<<"  + Response Code ("<<(FLAGS&15)<<")  -> "<<RCode_flag((FLAGS&15))<<endl;

    cout<<endl<<"Questions: ";
    for(i=POS; i<POS+2; i++) {
        questions += infoPack[i];
        }
    POS+=2;
    cout<<questions<<endl;

    cout<<"Answer RRS: ";
    for(i=POS; i<POS+2; i++) {
        answers += infoPack[i];
        }
    POS+=2;
    cout<<answers<<endl;

    cout<<"Authority RRS: ";
    for(i=POS; i<POS+2; i++) {
        authority += infoPack[i];
        }
    POS+=2;
    cout<<authority<<endl;

    cout<<"Additional RRS: ";
    for(i=POS; i<POS+2; i++) {
        additional += infoPack[i];
        }
    POS+=2;
    cout<<additional<<endl;

    for(i=0; i<questions; i++) {
        cout<<endl<<"\tQuestions "<<i+1<<":"<<endl;
        parseInfoQuestions();
        }

    for(i=0; i<answers; i++) {
        cout<<endl<<"\tAnswers "<<i+1<<":"<<endl;
        parseAllInfo(dnsPOS);
        }

    for(i=0; i<authority; i++) {
        cout<<endl<<"\tAuthority "<<i+1<<":"<<endl;
        parseAllInfo(dnsPOS);
        }

    for(i=0; i<additional; i++) {
        cout<<endl<<"\tAdditional "<<i+1<<":"<<endl;
        //sprintf(charBuffer, "%02X", infoPack[POS]);
        //cout<<"POS: "<<POS<<"       value: "<<charBuffer<<endl;
        parseAllInfo(dnsPOS);
        }
    }

void Ethernet::LeerTCP(const int& lastPOS) {
    int i=0, bits=0, ACK=0, URG=0, dataOffset=0, firstPOS=lastPOS;
    u_int x=0;
    string Checksum, PortDeOrigen, PortDest, seq;

    ///cout<<"POS: "<<POS<<"   info: "<<(int)infoPack[POS]<<endl;
    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t TCP "<<endl<<endl;

    cout<<"Puerto de origen: ";
    for(i=0; i<2; i++) {
        sprintf(charBuffer,"%02X",infoPack[POS++]);
        PortDeOrigen += charBuffer;
        }
    cout<<Hexa_Decimal(PortDeOrigen)<<endl;

    cout<<"Puerto de destino: ";
    for(i=0; i<2; i++) {
        sprintf(charBuffer,"%02X",infoPack[POS++]);
        PortDest += charBuffer;
        }
    cout<<Hexa_Decimal(PortDest)<<endl;

    cout<<"Numero de Secuencia: ";//ethernet_ipv4_tcp_syn
    for(i=0; i<4; i++) {
        //x+=infoPack[POS++];
        sprintf(charBuffer,"%02X",infoPack[POS++]);
        seq += charBuffer;
        }
    cout<<(unsigned int)Hexa_Decimal(seq)<<endl;

    seq.clear();
    cout<<"Numero de acuse de recibo: ";//es 0
    for(i=0; i<4; i++) {
        sprintf(charBuffer,"%02X",infoPack[POS++]);
        seq += charBuffer;
        }
    cout<<(unsigned int)Hexa_Decimal(seq)<<endl;

    //cout<<"POS: "<<POS<<"   info: "<<(int)infoPack[POS]<<endl;
    cout<<"Data offset: "<<(dataOffset=((infoPack[POS]&0xF0)>>4)*4)<<" bytes"<<endl;

    cout<<"FLAGS: "<<endl;
    cout<<"   +  NS: "<<(int)(infoPack[POS++]&0x01)<<endl;

    /*sprintf(charBuffer, "%02X",infoPack[POS]);
    cout<<charBuffer<<"          POS: "<<POS<<endl;*/

    bits = infoPack[POS++];
    cout<<"   + CWR: "<<(int)(((bits&0x80)>>4)/8)<<endl;
    cout<<"   + ECE: "<<(int)(((bits&0x40)>>4)/4)<<endl;
    cout<<"   + URG: "<<(URG=((bits&0x20)>>4)/4)<<endl;
    cout<<"   + ACK: "<<(ACK=((bits&0x10)>>4))<<endl;
    cout<<"   + PSH: "<<(int)(((bits&0x08))/8)<<endl;
    cout<<"   + RST: "<<(int)(((bits&0x04))/4)<<endl;
    cout<<"   + SYN: "<<(int)(((bits&0x02))/2)<<endl;
    cout<<"   + FIN: "<<(int)((bits&0x01))<<endl;

    seq.clear();
    cout<<"Tamaño de Ventana: ";
    for(i=0; i<2; i++) {
        sprintf(charBuffer,"%02X",infoPack[POS++]);
        seq += charBuffer;
        }
    cout<<Hexa_Decimal(seq)<<endl;

    cout<<"Header Checksum: 0x";
    for(i=0; i<2; i++) {
        sprintf(charBuffer,"%02X",infoPack[POS++]);
        Checksum += charBuffer;
        }
    cout<<Checksum<<endl;

    if(URG==0) {
        seq.clear();
        cout<<"Urgent Pointer: ";
        for(i=0; i<2; i++) {
            sprintf(charBuffer,"%02X",infoPack[POS++]);
            seq += charBuffer;
            }
        cout<<Hexa_Decimal(seq)<<endl;
        }

    int jumpOption=dataOffset-20;
    POS+=jumpOption;
    //cout<<"pos: "<<POS<<endl;

    if(Hexa_Decimal(PortDeOrigen)==53 || Hexa_Decimal(PortDest)==53) {
        LeerDNS();
        }
    }


void Ethernet::parseInfoQuestions() {
    int length(0),i(0);
    string word;

    length=infoPack[POS++];
    do {
        for(i=0; i<length; i++) {
            word+=infoPack[POS++];
            }
        length=infoPack[POS++];
        if(length) {
            word += ".";
            }
        }
    while(length);
    cout<<"Name: "<<word<<endl;

    int TYPEyCLASS(0);
    for(i=0; i<2; i++) {
        TYPEyCLASS+=infoPack[POS++];
        }
    cout<<"Type: "<<"("<<TYPEyCLASS<<")"<<TypeDNS(TYPEyCLASS)<<endl;

    TYPEyCLASS=0;
    for(i=0; i<2; i++) {
        TYPEyCLASS+=infoPack[POS++];
        }
    cout<<"Class: "<<"("<<TYPEyCLASS<<") "<<ClassDNS(TYPEyCLASS)<<endl;

    }
//dns_gatuno_mx
void Ethernet::parseAllInfo(const int& currentPos) {
    cout<<"Name: ";
    parseTheInfo(currentPos);

    int TYPE(0), CLASS(0), LenResp(0), i(0), length(0);
    string TTL;

    for(i=0; i<2; i++) {
        TYPE+=infoPack[POS++];
        }
    cout<<endl<<"Type: "<<"("<<TYPE<<")"<<TypeDNS(TYPE)<<endl;

    for(i=0; i<2; i++) {
        CLASS+=infoPack[POS++];
        }
    cout<<"Class: "<<"("<<CLASS<<")"<<ClassDNS(CLASS)<<endl;

    for(i=0; i<4; i++) {
        sprintf(charBuffer, "%02X",infoPack[POS++]);
        TTL+=charBuffer;
        }
    cout<<"TTL: "<<Hexa_Decimal(TTL)<<endl;


    for(i=0; i<2; i++) {
        LenResp+=infoPack[POS++];
        }
    if(TYPE!=41) {
        cout<<"RData: ";//<<LenResp
        }

    string Addrs, pref, word;

    switch(TYPE) {
        case 1:
            for(i=0; i<LenResp; i++) {
                if(i<LenResp-1) {
                    sprintf(charBuffer, "%i.",infoPack[POS++]);
                    }
                else {
                    sprintf(charBuffer, "%i",infoPack[POS++]);
                    }
                Addrs+=charBuffer;
                }
            cout<<Addrs<<endl;
            break;

        case 2:
            length=infoPack[POS++];
            cout<<endl<<"   ->NSDNAME: ";
            do {
                for(int x=0; x<length; x++) {
                    cout<<infoPack[POS++];
                    }
                length=infoPack[POS++];

                if(length) {
                    cout<<".";
                    }
                if(length==0xC0) {
                    POS--;
                    parseTheInfo(currentPos);
                    break;
                    }
                }
            while(length || length==0xC0);
            cout<<endl;
            break;

        case 5:
            for(i=0; i<LenResp; i++) {
                Addrs+=infoPack[POS++];
                }
            cout<<endl<<"   ->CName: "<<Addrs<<endl;
            break;

        case 15:
            for(i=0; i<2; i++) {
                sprintf(charBuffer, "%02X",infoPack[POS++]);
                pref+=charBuffer;
                }
            cout<<endl<<"   ->Preference: "<<Hexa_Decimal(pref)<<endl;

            length=infoPack[POS++];
            cout<<"   ->Exchanged: ";
            do {
                for(int x=0; x<length; x++) {
                    cout<<infoPack[POS++];
                    }
                length=infoPack[POS++];

                if(length) {
                    cout<<".";
                    }
                }
            while(length!=0xC0);
            POS--;

            parseTheInfo(currentPos);
            cout<<endl;
            break;

        case 28:
            for(i=0; i < LenResp; i++) {
                if(i%2!=0 && i<LenResp-1) {
                    sprintf(charBuffer,"%02X:",infoPack[POS++]);
                    }
                else {
                    sprintf(charBuffer,"%02X",infoPack[POS++]);

                    }
                Addrs += charBuffer;
                }
            cout<<formatIPv6(Addrs)<<endl;
            break;
        }
    }

void Ethernet::parseTheInfo(const int& currentPos) {
    if(infoPack[POS++]==0xC0) {
        int ptrPOSdns(currentPos+infoPack[POS++]);
        //sprintf(charBuffer,"%02X",infoPack[ptrPOSdns]);
        //cout<<endl<<"PARSE THE INFO: POS "<<ptrPOSdns<<"    PARSE THE INFO: valor "<<charBuffer<<endl;
        parseTheInfo(currentPos, ptrPOSdns);//se manda la posicion actualizada del apuntador, directo al tamaño de la palabra (el ptrPOSdns)
        }


    }
void Ethernet::parseTheInfo(const int& currentPos,int DNSpos) {
    int length(infoPack[DNSpos++]);
    if(length==0) {
        return;
        }
    for(int i=0; i<length; i++) {
        cout<<infoPack[DNSpos++];
        }
    if((length=infoPack[DNSpos])==0xC0) {

        int newDNSpos(currentPos+infoPack[++DNSpos]);
        //sprintf(charBuffer,"%02X",infoPack[newDNSpos]);
        //cout<<endl<<"PARSE THE INFO: POS "<<newDNSpos<<"    PARSE THE INFO: valor "<<charBuffer<<endl;
        cout<<".";
        parseTheInfo(currentPos,newDNSpos);
        }
    else if(length) {
        cout<<".";
        parseTheInfo(currentPos,DNSpos);
        }
    }

//dns_gatuno_mx
string Ethernet::etherType(const string& value) {
    string numType[]= {"0800","0806","0842","22F0","22F3","22EA","6002","6003","6004","8035","809B","80F3","8100","8102",
                       "8103","8137","8204","86DD","8808","8809","8819","8847","8848","8863","8864","887B","888E","8892","889A","88A2","88A4",
                       "88A8","88AB","88B8","88B9","88BA","88BF","88CC","88CD","88E1","88E3","88E5","88E7","88F7","88F8","88FB","8902","8906",
                       "8914","8915","891D","893a","892F","9000","F1C1"
                      };

    string type[]= {"Internet Protocol version 4 (IPv4)","Address Resolution Protocol (ARP)","Wake-on-LAN","Audio Video Transport Protocol (AVTP)",
                    "IETF TRILL Protocol","Stream Reservation Protocol","DEC MOP RC","DECnet Phase IV, DNA Routing","DEC LAT","Reverse Address Resolution Protocol (RARP)",
                    "AppleTalk (Ethertalk)","AppleTalk Address Resolution Protocol (AARP)","VLAN-tagged frame (IEEE 802.1Q) and Shortest Path Bridging IEEE 802.1aq with NNI compatibility",
                    "Simple Loop Prevention Protocol (SLPP)","Virtual Link Aggregation Control Protocol (VLACP)","IPX","QNX Qnet","Internet Protocol Version 6 (IPv6)","Ethernet flow control",
                    "Ethernet Slow Protocols[11] such as the Link Aggregation Control Protocol (LACP)","CobraNet","MPLS unicast","MPLS multicast","PPPoE Discovery Stage","PPPoE Session Stage",
                    "HomePlug 1.0 MME","EAP over LAN (IEEE 802.1X)","PROFINET Protocol","HyperSCSI (SCSI over Ethernet)","ATA over Ethernet","EtherCAT Protocol","Service VLAN tag identifier (S-Tag) on Q-in-Q tunnel",
                    "Ethernet Powerlink[citation needed]","GOOSE (Generic Object Oriented Substation event)","GSE (Generic Substation Events) Management Services","SV (Sampled Value Transmission)",
                    "MikroTik RoMON (unofficial)","Link Layer Discovery Protocol (LLDP)","SERCOS III","HomePlug Green PHY","Media Redundancy Protocol (IEC62439-2)",
                    "IEEE 802.1AE MAC security (MACsec)","Provider Backbone Bridges (PBB) (IEEE 802.1ah)","Precision Time Protocol (PTP) over IEEE 802.3 Ethernet","NC-SI",
                    "Parallel Redundancy Protocol (PRP)","IEEE 802.1ag Connectivity Fault Management (CFM) Protocol / ITU-T Recommendation (OAM)","Fibre Channel over Ethernet (FCoE)",
                    "FCoE Initialization Protocol","RDMA over Converged Ethernet (RoCE)","TTEthernet Protocol Control Frame (TTE)","IEEE Protocol","High-availability Seamless Redundancy (HSR)",
                    "Ethernet Configuration Testing Protocol","Redundancy Tag (IEEE 802.1CB Frame Replication and Elimination for Reliability)"
                   };
    int x(0);
    while(x<55) {
        if(numType[x]==value){
            return "    -> " + type[x];
        }
        x++;
        }

    }

string Ethernet::TYPEofPROTOCOL(const int& valor) {
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
                            "IPv6-ICMP (ICMP para IPv6)",
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

string Ethernet::typeIcmpv4(const int& type) {
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

string Ethernet::codeIcmpv4(const int& type, const int& subvalor) {
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

string Ethernet::formatIPv6(string& IPv6) {
    int i,zd=0,zi=0, x1, x2;
    size_t foundFirst=IPv6.find("000");
    string myStr;

    ///Eliminacion de ceros a la izquierda
    while(foundFirst != std::string::npos) {
        IPv6.erase(foundFirst, 3); //  cuando ya no encuntra el 000
        foundFirst = IPv6.find("000");
        }

    while((foundFirst = IPv6.find(":00")) != std::string::npos) {
        IPv6.erase(foundFirst+1, 2); // cuando ya no encuntra el 00
        }
    for(i=0; i<(int)IPv6.size(); i++) {
        if(IPv6[i-1]== ':' && IPv6[i]== '0' && IPv6[i+1]!= ':') { //Elimina si quedo un :0y(otro numero)
            IPv6.erase(i, 1);
            }
        }

    for(i=0; i<(int)IPv6.size(); ++i) {
        if(IPv6[i-1]== ':' && IPv6[i]== '0' && IPv6[i+1]== ':' && IPv6[i+2]== '0' && IPv6[i+3]== ':') {
            zi++;//medio
            x1=i;
            }
        else if(IPv6[i-3]== ':' && IPv6[i-2]== '0' && IPv6[i-1]== ':' && IPv6[i]== '0') {
            zi++;//fin
            }
        else if(IPv6[i-1]== '\0' && IPv6[i]== '0' && IPv6[i+1]== ':' && IPv6[i+2]== '0' && IPv6[i+3]== ':') {
            zi++;//inicio

            }
        }
    ///cout<<endl<<"zi: "<<zi<<endl;
    ///cout<<"x1: "<<x1<<endl;

    for(i=IPv6.size(); i>=0; i--) {
        if(IPv6[i+1]== ':' && IPv6[i]== '0' && IPv6[i-1]== ':' && IPv6[i-2]== '0' && IPv6[i-3]== ':') {
            zd++;//medio
            x2=i-1;
            }
        else if(IPv6[i-1]== '\0' && IPv6[i]== '0' && IPv6[i+1]== ':' && IPv6[i+2]== '0' && IPv6[i+3]== ':') {
            zd++;//fin
            }
        else if(IPv6[i-5]!= '0' && (IPv6[i-4]!= ':' || IPv6[i-3]!= '0') && IPv6[i-2]== ':' && IPv6[i-1]== '0' && IPv6[i]== ':' && IPv6[i+1]== '0') {
            zd++;//inicio
            }
        }

    ///Eliminacion (compresion)
    if(zd>zi) {
        ///cout<<"der"<<endl;
        IPv6.erase(x1,(zd+(zd-1)));
        }
    else {
        ///cout<<"izq"<<endl;
        IPv6.erase(x2,(zi+(zi-1)));
        }

    for(int i=0; i<(int)IPv6.size(); i++) {
        if(IPv6[i-2]!=':' && IPv6[i-1]==':' && IPv6[i]=='0' && IPv6[i+1]!=':') {
            IPv6.erase(i,1);
            IPv6.insert(i,":");
            }
        }
    return IPv6;
    }

string Ethernet::typeICMPV6(const int& info) {
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
        if(info==TYPEnum[i]) {
            break;
            }
        i++;
        }
    return " -> " + TYPEinfo[i];
    }

string Ethernet::codeIcmpv6(const int& type, const int& subvalor) {
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

string Ethernet::OpC_flag(const int i) {
    string OpC[]= {"Query","IQUERY","STATUS","(reserved)","NOTIFY","UPDATE"};

    if(i<=5) {
        return OpC[i];
        }
    else {
        return "Unused";
        }

    }

string Ethernet::RCode_flag(const int i) {
    string RCode[]= {"No Error","Format Error","Server Failure","Name Error","Not Implemented",
                     "Refused", "YX Domain","YX RR Set","NX RR Set","Not Auth","NotZone"
                    };
    if(i<=10) {
        return RCode[i];
        }
    else {
        return "Unused";
        }
    }

string Ethernet::TypeDNS(const int& i) {
    string type[]= {"A","AAAA","AFSDB","APL","CAA","CDNSKEY",
                    "CDS","CERT","CNAME","CSYNC","DHCID","DLV","DNAME","DNSKEY",
                    "DS","EUI48","EUI64","HINFO","HIP","HTTPS","IPSECKEY","KEY",
                    "KX","LOC","MX","NAPTR","NS","NSEC","NSEC3","NSEC3PARAM","OPENPGPKEY",
                    "PTR","RRSIG","RP","SIG","SMIMEA","SOA","SRV","SSHFP","SVCB",
                    "TA","TKEY","TLSA","TSIG","TXT","URI","ZONEMD","*", "AXFR", "IXFR","OPT"
                   };

    int typenum[]= {1,28,18,42,257,60,59,37,5,62,49,32769,39,48,43,108,109,13,55,65,45,25,36,
                    29,15,35,2,47,50,51,61,12,46,17,24,53,6,33,44,64,32768,249,52,250,16,256,63,
                    255,252,251,41
                   };
    int x(0);
    while(x<50) {
        if(i==typenum[x]) {
            break;
            }
        x++;
        }
    return " -> " + type[x];
    }

string Ethernet::ClassDNS(const int& i) {
    string CLASSS[]= {"Reserved","Internet (IN)","Unassigned","Chaos (CH)","Hesiod (HS)"};

    if(i<4) {
        return "-> " + CLASSS[i];
        }
    else if(i>4 && i<254) {
        return "-> Unassigned";
        }
    else if(i==254) {
        return "-> QCLASS NONE";
        }
    else if(i==255) {
        return "-> QCLASS * (ANY)";
        }
    else if(i>255 && i<65280) {
        return "-> Unassigned";
        }
    else if(i>=65280 && i<=65534) {
        return "-> Reserved for Private Use";
        }
    else if(i==65535) {
        return "-> Reserved";
        }
    }
int Ethernet::Hexa_Decimal(const string& hex) {
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
