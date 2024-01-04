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
//const char* Pack, const string* HexPack, const int& Size, int POS

char charBuffer[3];
//fgetc te lo regresa como entero
void LeerCabeceraEthernet(const unsigned char*, const int&, int&);
void LeerARP(const unsigned char*, int&);
void LeerIPv4(const unsigned char*, int&, bool);
void LeerICMPv4(const unsigned char*, const int&, int&);
void LeerIPv6(const unsigned char*, int&, bool);
void LeerICMPv6(const unsigned char*, int&);
void optionsICMPv6(const unsigned char*, int&, const int&);
void LeerUDP(const unsigned char*, int&);
string TYPEofPROTOCOL(const int&);
string typeIcmpv4(const int&);
string codeIcmpv4(const int&, const int&);
string formatIPv6(string&);
string typeICMPV6(const int&);
string codeIcmpv6(const int&, const int&);

int Hexa_Decimal(const string&);


int main(int arg,char*argv[]) {
    //E:\\Documentos PC\\UDG Materias\\REDES\\ARCHIVOS\\
    //C:\\Users\\efrai\\OneDrive\\Documentos\\REDES\\ARCHIVOS\\

    string myArchive, arch = "E:\\Documentos PC\\UDG Materias\\REDES\\ARCHIVOS\\";
    int opcM=0, opc=0, i=0,POS=0;
    //char charBuffer[3];

    FILE* archive;
    int valueArchive;
    long int packSize;

    unsigned char* pack;

    while(opcM!=2) {
        ///system("cls");
        cout<<endl<<"\tINGRESE OPCION A LEER"<<endl<<"\t     1(LOCAL)   2(PCAP):    ";
        cin>>opc;
        switch(opc) {
            case 1:
                cout << "Dime el nombre del fichero: ";
                getline(cin.ignore(), myArchive);
                myArchive = arch + myArchive + ".bin";

                //Si logra abrir el fichero
                if ((archive = fopen(myArchive.c_str(), "rb")) == NULL) {
                    cout<< "Error en la apertura. Algo salio mal";
                    break;
                    }
                else {
                    fseek(archive,0,SEEK_END);//Se va al final del archivo   ethernet_ipv6_nd.bin
                    packSize = ftell(archive);//Obtenemos la cantidad total del paquete
                    rewind(archive);

                    system("pause");
                    pack = new unsigned char[packSize];

                    while (!feof(archive)) {//feof devuelve un 0 cuando leyo todo el archivo
                        valueArchive = fgetc(archive);
                        pack[i++]= valueArchive;
                        }

                    for(int i=0;i<packSize;i++){
                        sprintf(charBuffer,"%02d ",pack[i]);
                        cout<<charBuffer;
                        //cout<<pack[i];
                    }
                    cout<<endl;

                    /*for(int i=0;i<5;i++){
                        pack[i]=0;
                        cout<<pack[i];
                        sprintf(charBuffer,"%02d ",pack[i]);
                        cout<<charBuffer;
                    }
                    cout<<endl<<endl;*/
                }
                LeerCabeceraEthernet(pack, packSize,POS);
                /*for(int i=0;i<packSize;i++){
                        pack[i]=NULL;
                        cout<<pack[i];
                    }*/
                    fclose(archive);
                    //pack=nullptr;
                delete[] pack;
                //pack=nullptr;
                //cout<<"pack  "<<pack[1]<<"     hexPack "<<hexPack[1]<<endl;

                //delete[] pack;
                //delete[] hexPack;
                /*cout<<"delete       pack  "<<pack[1]<<"     hexPack "<<hexPack[1]<<endl;
                if( hexPack==nullptr){
                    cout<<"hexpack VACIO  "<<hexPack<<endl;
                }else{
                    cout<<"hexpack LLENO  "<<hexPack<<endl;
                }

                if(pack==nullptr ){
                    cout<<"pack VACIO  "<<pack<<endl;
                }else{
                    cout<<"pack LLENO  "<<pack<<endl;
                }*/
                break;

                case 2:

                    system("pause");
                break;
            }
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

void LeerUDP(const unsigned char*Pack, int& POS){
    int i=0, PortDeOrigen=0, PortDest=0;
    string Long, Checksum;
    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ICMPv6 "<<endl<<endl;

    cout<<"Puerto de origen: ";
    for(i=POS; i<POS+2; i++) {
        PortDeOrigen += Pack[i];
        }
        POS+=2;
    cout<<PortDeOrigen<<endl;

    cout<<"Puerto de destino: ";
    for(i=POS; i<POS+2; i++) {
        PortDest += Pack[i];
        }
        POS+=2;
    cout<<PortDest<<endl;

    cout<<"Longitud: ";
    for(i=POS; i<POS+2; i++) {
        Long += Pack[i];
        }
        POS+=2;
    cout<<Long<<endl;

    cout<<"Header Checksum: 0x";
    for(i=POS; i<POS+2; i++) {
            sprintf(charBuffer,"%02X ",Pack[i]);
        Checksum += charBuffer;
        }
        POS+=2;
    cout<<Checksum<<endl;
}

void optionsICMPv6(const unsigned char*Pack,int& POS, const int& movement) {
    string SOURCE_LINK, TARGET_LINK, FinalPREFIX;
    int i=0, TYPE=0, LENGTH=0, NONCE=0, PREFIX=0, PreFixLENGTH=0, FLAGS=0, x=0, cont=0;
    int LifeTime=0, PreferLifeTime=0;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ICMPv6 Options "<<endl<<endl;
    //movement=movement+POS;


    //cout<<"Pos "<<POS<<endl<<endl;
    TYPE=Pack[POS++];
    LENGTH=Pack[POS++];
    //cout<<"Type "<<TYPE<<"      Length: "<<LENGTH<<endl<<endl;
    if(TYPE==1){
        cout<<"Source Link Layer Address: ";
        for(i=POS; i<POS+6; i++) {
        if(i < POS+5){
                sprintf(charBuffer,"%02X:",Pack[i]);
        }else{
            sprintf(charBuffer,"%02X",Pack[i]);

        }
        SOURCE_LINK += charBuffer;
        }
        POS+=6;
    cout<<SOURCE_LINK<<endl;
    }

    if(TYPE==2){
        cout<<"Target Link Layer Address: ";
    for(i=POS; i<POS+6; i++) {
        if(i < POS+5){
            sprintf(charBuffer,"%02X:",Pack[i]);
        }else{
            sprintf(charBuffer,"%02X",Pack[i]);

        }
        TARGET_LINK += charBuffer;
        }
        POS+=6;
    cout<<TARGET_LINK<<endl;
    }

    if(TYPE==3){
            LENGTH=8*LENGTH;
            cout<<"\tType Prefix Info: "<<endl;
            PreFixLENGTH=Pack[POS++]/8;
    cout<<"Prefix Length: "<<PreFixLENGTH<<endl;

    cout<<"Flags: "<<endl;

    FLAGS = (Pack[POS++] & 240)>>4;//obtenemos 4 "ultimos" bits (los mas significantes) y le hacemos un recorrimiento

    cout<<" L, On-Link Flag ("<<(FLAGS&1)<<")"<<endl;
    cout<<" A, Autonomous Address-Configuration Flag ("<<(FLAGS&2)/2<<")"<<endl;

    cout<<"Valid LifeTime: ";
    for(i=POS; i<POS+4; i++) {
        LifeTime += Pack[i];
        }
        POS+=4;
    cout<<LifeTime<<endl;

    cout<<"Preferred Lifetime: ";
    for(i=POS; i<POS+4; i++) {
        LifeTime += Pack[i];
        }
        POS+=4;
    cout<<PreferLifeTime<<endl;
    POS+=4;

    cout<<"Prefix: ";
    for(i=POS; i<POS+16; i++) {
        if(i%2!=0 && i < POS+15){
            sprintf(charBuffer,"%02X:",Pack[i]);
        }else{
        sprintf(charBuffer,"%02X",Pack[i]);
        }
        FinalPREFIX += charBuffer;
        }
        POS+=PreFixLENGTH;
//empieza en 2001

    cout<<formatIPv6(FinalPREFIX)<<endl;
    }

    if(TYPE==4){
        cout<<"Type: "<<TYPE<<endl<<endl;
        cout<<"Length: "<<LENGTH<<endl;
    POS+=6;
    }
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

void LeerICMPv6(const unsigned char* Pack, const int& PAYLOAD, int& POS) { //40
    int i=0, TYPEicmp=0, Code=0, LastPos=POS, bits=0, restPOS=0, mov=0;
    string HEADchecksum, targetAddr, IDN, SEQ,tooBigIP,RouterLife,reachableTime, retransTimer,DestAddr;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ICMPv6 "<<endl<<endl;
//pos54
    //fseek(archive,POS, SEEK_SET);
    cout<<"Type: ";
    TYPEicmp=Pack[POS++];
    cout<<TYPEicmp<<typeICMPV6(TYPEicmp)<<endl;

    //fseek(archive, POS+1, SEEK_SET);
    cout<<"Code: ";
    Code=Pack[POS++];
    cout<<Code<<codeIcmpv6(TYPEicmp,Code)<<endl;

    //fseek(archive,POS+2,SEEK_SET);
    cout<<"Header Checksum: 0x";
    for(i=POS; i<POS+2; i++) {
            sprintf(charBuffer,"%02X",Pack[i]);
        HEADchecksum += charBuffer;
        }
        POS+=2;
    cout<<HEADchecksum<<endl;

    ///cout<<"POS "<<POS<<endl;
    switch(TYPEicmp) {
    case 1://Unreachable
        POS+=4;
        LeerIPv6(Pack,POS,false);
        break;

    case 2://packet too big
        /*cout<<"Direccion IP de Packet too Big: ";
            for(i=POS; i<POS+6; i++) {
            if(i<POS+5){
                tooBigIP += Pack[i] + ":";
                }
            else {
                tooBigIP += Pack[i];
                }
                }
                POS+=6;
            cout<<formatIPv6(tooBigIP)<<endl;*/
            POS+=4;
            LeerIPv6(Pack,POS,false);
        break;

    case 3://hop limit(time exceeded)
        POS+=4;
        LeerIPv6(Pack,POS,false);
        break;

    case 128://echo request (ping)
        //fseek(archive,POS+8,SEEK_SET);
            cout<<"Identificador: ";
            for(i=POS; i<POS+2; i++) {
                sprintf(charBuffer,"%02X",Pack[i]);
                IDN += charBuffer;
                }
                POS+=2;
            cout<<Hexa_Decimal(IDN)<<endl;

            //fseek(archive,POS+10,SEEK_SET);
            cout<<"Numero de secuencia: ";
            for(i=POS; i<POS+2; i++) {
                    sprintf(charBuffer,"%02X",Pack[i]);
                SEQ += charBuffer;
                }
                POS+=2;
            cout<<Hexa_Decimal(SEQ)<<endl;
        break;

    case 129://echo reply (pong)
            cout<<"Identificador: ";
            for(i=POS; i<POS+2; i++) {
                    sprintf(charBuffer,"%02X",Pack[i]);
                IDN += charBuffer;
                }
                POS+=2;
            cout<<Hexa_Decimal(IDN)<<endl;

            //fseek(archive,POS+10,SEEK_SET);
            cout<<"Numero de secuencia: ";
            for(i=POS; i<POS+2; i++) {
                sprintf(charBuffer,"%02X",Pack[i]);
                SEQ += charBuffer;
                }
                POS+=2;
            cout<<Hexa_Decimal(SEQ)<<endl;
        break;

    case 133://router solicitacion
        POS+=4;
        if(PAYLOAD>(restPOS=POS-LastPos)){
        mov = PAYLOAD-restPOS;
        optionsICMPv6(Pack, POS, mov);
        }
        break;

    case 134://router advertisement
        sprintf(charBuffer,"%i",Pack[POS++]);
        cout<<"Cur Hop Limit: "<<charBuffer<<endl;

        bits=(Pack[POS]>>4)&8;
        cout<<"Bandera de configuracion de direccion administrada: "<<bits<<endl;

        bits=(Pack[POS++]>>4)&4;
        cout<<"Otra bandera de configuracion: "<<bits<<endl;

        cout<<"Router Lifetime: ";
        for(i=POS; i<POS+2; i++) {
                sprintf(charBuffer,"%02X",Pack[i]);
            RouterLife += charBuffer;
            }
            POS+=2;
        cout<<Hexa_Decimal(RouterLife)<<endl;

        cout<<"Reachable Time: ";
        for(i=POS; i<POS+4; i++) {
                sprintf(charBuffer,"%02X",Pack[i]);
            reachableTime += charBuffer;
            }
            POS+=4;
        cout<<Hexa_Decimal(reachableTime)<<endl;

        cout<<"Retrans Timer: ";
        for(i=POS; i<POS+4; i++) {
                sprintf(charBuffer,"%02X",Pack[i]);
            retransTimer += charBuffer;
            }
            POS+=4;
        cout<<Hexa_Decimal(retransTimer)<<endl;

        if(PAYLOAD>(restPOS=POS-LastPos)){
                mov = PAYLOAD-restPOS;
        optionsICMPv6(Pack, POS, PAYLOAD);
        }
        break;

    case 135://Neighbor Solicitation        ipv6_nd_sol_2
        POS+=4;
        //fseek(archive,POS+8,SEEK_SET);
            cout<<"Target Address: ";
            for(i=POS; i<POS+16; i++) {
                if(i%2!=0 && i<POS+15) {
                        sprintf(charBuffer,"%02X:",Pack[i]);
                    }
                else {
                    sprintf(charBuffer,"%02X",Pack[i]);
                    }
                targetAddr += charBuffer;
                }
                POS+=16;
            cout<<formatIPv6(targetAddr)<<endl;
            ///cout<<"POS: "<<POS<<"           restPos: "<<POS-LastPos<<"           payload: "<<PAYLOAD<<"           mov: "<<PAYLOAD-(POS-LastPos);
            if(PAYLOAD>(restPOS=POS-LastPos)){

                    mov = PAYLOAD-restPOS;
        optionsICMPv6(Pack, POS, PAYLOAD);
        }
        break;

    case 136://Neighbor Advertisement
        bits=(Pack[POS]>>4)&8;
        cout<<"Router Flag: "<<bits<<endl;

        bits=(Pack[POS]>>4)&4;
        cout<<"Solicited flag: "<<bits<<endl;

        bits=(Pack[POS]>>4)&2;
        cout<<"Override flag: "<<bits<<endl;
        POS+=4;

        cout<<"Target Address: ";
            for(i=POS; i<POS+16; i++) {
                if(i%2!=0 && i<POS+15) {
                        sprintf(charBuffer,"%02X:",Pack[i]);
                    }
                else {
                    sprintf(charBuffer,"%02X",Pack[i]);

                    }
                targetAddr += charBuffer;
                }
                POS+=16;

            cout<<formatIPv6(targetAddr)<<endl;

        if(PAYLOAD>(restPOS=POS-LastPos)){
                mov = PAYLOAD-restPOS;
        optionsICMPv6(Pack, POS, PAYLOAD);
        }
        break;

    case 137://Redirect
        POS+=4;
        cout<<"Target Address: ";
            for(i=POS; i<POS+16; i++) {
                if(i%2!=0 && i<POS+15) {
                    sprintf(charBuffer,"%02X:",Pack[i]);
                    }
                else {
                    sprintf(charBuffer,"%02X",Pack[i]);
                    }
                    targetAddr += charBuffer;
                }
                POS+=16;
            cout<<formatIPv6(targetAddr)<<endl;
        cout<<"Destination Address: ";
            for(i=POS; i<POS+16; i++) {
                if(i%2!=0 && i<POS+15) {
                    sprintf(charBuffer,"%02X:",Pack[i]);
                    }
                else {
                    sprintf(charBuffer,"%02X",Pack[i]);
                    }
                    DestAddr += charBuffer;
                }
                POS+=16;
            cout<<formatIPv6(DestAddr)<<endl;

        if(PAYLOAD>(restPOS=POS-LastPos)){
                mov = PAYLOAD-restPOS;
        optionsICMPv6(Pack, POS, PAYLOAD);
        }
        break;
        }
    }


string formatIPv6(string& IPv6) {
    int i,zd=0,zi=0, x1, x2;
    size_t foundFirst=IPv6.find("000"), foundLast;
    string myStr;

    ///Eliminacion de ceros a la izquierda
    while(foundFirst != std::string::npos) {
        IPv6.erase(foundFirst, 3); //  cuando ya no encuntra el 000
        foundFirst = IPv6.find("000");
        }

    while((foundFirst = IPv6.find(":00")) != std::string::npos) {
        IPv6.erase(foundFirst+1, 2); // cuando ya no encuntra el 00
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

    for(int i=0; i<IPv6.size(); i++) {
        if(IPv6[i-2]!=':' && IPv6[i-1]==':' && IPv6[i]=='0' && IPv6[i+1]!=':') {
            IPv6.erase(i,1);
            IPv6.insert(i,":");
            }
        }
    return IPv6;
    }

void LeerIPv6(const unsigned char* Pack, int& POS, bool flag) { // POS14
    int i=0,x=0, binary, bitsPart1, bitsPart2, FL = 0, VERSION, TIMEtoLIVE;
    int PROTOCOL, intPayload, longNext, next, nextHeader;
    string Payload, NextH, HEADchecksum, SOURCE_IP, DESTINATION_IP;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t IPv6 "<<endl;

//    fseek(archive,POS, SEEK_SET);
    cout<<"Version: ";
//    binary = valueArchive;//recibe expresion decimal para convetirlo a entero
    bitsPart2 = Pack[POS] & 240;//obtenemos 4 "ultimos" bits (los mas significantes)
    VERSION = bitsPart2>>4;
    if(VERSION == 6) {
        cout<<"IPv6";
        }
    cout<<" ("<<VERSION<<")"<<endl;

    cout<<"Traffic class: ";
    bitsPart1 = Pack[POS++] & 15;//obtenemos 4 "primeros" bits (los menos significantes)
    cout<<(bitsPart1*4)*5<<endl;

//    fseek(archive,0, POS+1);
    cout<<"Flow Label: ";
    for(i=POS; i<POS+3; i++) {
        FL += Pack[i];
        }
        POS+=3;
    cout<<FL<<endl;

//    fseek(archive,0, POS+4);
    cout<<"Payload Lenght: ";
    for(i=POS; i<POS+2; i++) {
        sprintf(charBuffer,"%02X",Pack[i]);
        Payload += charBuffer;
        }
        POS+=2;
    cout<<(intPayload = Hexa_Decimal(Payload))<<" bytes"<<endl;

//    fseek(archive,0, POS+5);
    cout<<"Next Header: ";
    nextHeader = Pack[POS];
    cout<<nextHeader<<TYPEofPROTOCOL(Pack[POS++])<<endl;

//    fseek(archive,POS+7,SEEK_SET);
    cout<<endl<<"Hop Limit: ";
    TIMEtoLIVE = Pack[POS++];
    cout<<TIMEtoLIVE<<" brincos"<<endl;

//    fseek(archive,POS+8, SEEK_SET);
    cout<<"IP Source Address: ";
    for(i=POS; i < POS+16; i++) {
        if(i%2!=0 && i<POS+15) {
                sprintf(charBuffer,"%02X:",Pack[i]);
            }
        else {
            sprintf(charBuffer,"%02X",Pack[i]);

            }
        SOURCE_IP += charBuffer;
        }
        POS+=16;
    cout<<formatIPv6(SOURCE_IP)<<endl;

//    fseek(archive,0, POS+24);
    cout<<"IP Destination Address: ";
    for(i=POS; i < POS+16; i++) {
        if(i%2!=0 && i<POS+15) {
                sprintf(charBuffer,"%02X:",Pack[i]);
            }
        else {
            sprintf(charBuffer,"%02X",Pack[i]);
            }
        DESTINATION_IP+=charBuffer;
        }
        POS+=16;
    cout<<formatIPv6(DESTINATION_IP)<<endl;
    ///cout<<"POS "<<POS<<endl;

    if(nextHeader == 58 || nextHeader == 17){
        if(flag) {
            LeerICMPv6(Pack, intPayload, POS);
        }
        }
    else {
        next=Pack[POS++];
        longNext=Pack[POS++];
        longNext =(longNext+1)*8;
        if(flag) {

            LeerICMPv6(Pack,intPayload, POS=(POS-2)+longNext);
        }
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

void LeerICMPv4(const unsigned char* Pack,int& POS) { //POS 34
    int i, TYPEicmp, Code;
    string HEADchecksum, IDN, SEQ, redirectIP;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ICMPv4 "<<endl<<endl;

//    fseek(archive,POS, SEEK_SET);
    cout<<"Type: ";
    TYPEicmp=Pack[POS++];
    cout<<TYPEicmp<<typeIcmpv4(TYPEicmp)<<endl;

//    fseek(archive, 0, POS+1);
    cout<<"Code: ";
    Code=Pack[POS++];
    cout<<Code<<codeIcmpv4(TYPEicmp,Code)<<endl;

//    fseek(archive,POS+2,SEEK_SET);
    cout<<"Header Checksum: 0x";
    for(i=POS; i<POS+2; i++) {
            sprintf(charBuffer,"%02X",Pack[i]);
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
                IDN += Pack[i];
                }
                POS+=2;
            cout<<Hexa_Decimal(IDN)<<endl;

//            fseek(archive,POS+6,SEEK_SET);
            cout<<"Numero de secuencia: ";
            for(i=POS; i<POS+2; i++) {
                SEQ += Pack[i];
                }
                POS+=2;
            cout<<Hexa_Decimal(SEQ)<<endl;
            break;
        case 3://unreachable
        case 11://ttl
            LeerIPv4(Pack,POS,false);///POS+8??
            break;

        case 5://redirect
//            fseek(archive,POS+4,SEEK_SET);
            cout<<endl<<"Direccion IP de Redirect: ";
            for(i=POS; i < POS+4; i++) {
                if(i<POS+3) {
                        sprintf(charBuffer,"%i.",Pack[i]);
                    }
                else {
                    sprintf(charBuffer,"%i",Pack[i]);

                    }
                redirectIP += charBuffer;
                }
                POS+=4;
            cout<<redirectIP<<endl;

            LeerIPv4(Pack,POS,false);
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

void LeerIPv4(const unsigned char* Pack,int& POS, bool flag) {//POS 14
    int i=0, binary, bits, bitsProtocol, ToS, VERSION, JUMPOPTION, FLAGS, TIMEtoLIVE, PROTOCOL;
    string TOTAL_LENG, IDENTI, HEADchecksum, SOURCE_IP, DESTINATION_IP;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t IPv4 "<<endl;

//    fseek(archive,POS, SEEK_SET);
    cout<<"Version: ";
    bits = Pack[POS] & 240;//obtenemos 4 "ultimos" bits (los mas significantes)
    VERSION = bits>>4;
    if(VERSION == 4) {
        cout<<"IPv4";
        }
    cout<<" ("<<VERSION<<")"<<endl;

    cout<<"IHL (Inter Header Length): ";
    bits = Pack[POS] & 15;//obtenemos 4 "primeros" bits (los menos significantes)
    bitsProtocol = bits*4;

    cout<<bitsProtocol<<" bytes ("<<bits<<")"<<endl; //No hay opciones

    JUMPOPTION = bitsProtocol - 20;

//    fseek(archive,0, POS+1);
    cout<<"ToS (Types of Services): ";
    ToS = Pack[++POS];
    cout<<ToS<<endl;

//    fseek(archive,0, POS+2);
    cout<<"Total Length: ";
    for(i=++POS; i<POS+2; i++) {
            sprintf(charBuffer,"%02X",Pack[i]);
        TOTAL_LENG += charBuffer;
        }
        POS+=2;
    cout<<Hexa_Decimal(TOTAL_LENG)<<" bytes"<<endl;


//    fseek(archive,0, POS+4);
    cout<<"Identification: ";
    for(i=POS; i<POS+2; i++) {
            sprintf(charBuffer,"%02X",Pack[i]);
        IDENTI += charBuffer;
        }
        POS+=2;
    cout<<Hexa_Decimal(IDENTI)<<endl;

//    fseek(archive,POS+6, SEEK_SET);
    cout<<endl<<"Flags:"<<endl;
    FLAGS = (Pack[POS++] & 240)>>4;//obtenemos 4 "ultimos" bits (los mas significantes) y le hacemos un recorrimiento

    //cout<<FLAGS<<endl;
    cout<<"  + Reservado ("<<(FLAGS&8)/8<<")"<<endl;
    cout<<"  + Don't fragment ("<<(FLAGS&4)/4<<")"<<endl;
    cout<<"  + More fragment ("<<(FLAGS&2)/2<<")"<<endl;
    cout<<"- Fragment offset("<<(FLAGS&1)<<")"<<endl;

//    fseek(archive,POS+8,SEEK_SET);
    cout<<endl<<"TTL (Time to Live): ";
    TIMEtoLIVE = Pack[++POS];
    cout<<TIMEtoLIVE<<" brincos"<<endl;

//    fseek(archive,POS+9,SEEK_SET);
    cout<<"Protocol: ";
    PROTOCOL = Pack[++POS];
    cout<<PROTOCOL<<TYPEofPROTOCOL(PROTOCOL)<<endl;

//    fseek(archive,POS+10,SEEK_SET);
    cout<<"Header Checksum: 0x";
    for(i=++POS; i<POS+2; i++) {
            sprintf(charBuffer,"%02X",Pack[i]);
        HEADchecksum += charBuffer;
        }
        POS+=2;
    cout<<HEADchecksum<<endl;

//    fseek(archive,POS+12, SEEK_SET);
    cout<<"IP Source Address: ";
    for(i=POS; i < POS+4; i++) {
        if(i<POS+3) {
            SOURCE_IP += sprintf(charBuffer,"%i.",Pack[i]);;
            }
        else {
            sprintf(charBuffer,"%i",Pack[i]);
            }
            SOURCE_IP+=charBuffer;
        }
        POS+=4;
    cout<<SOURCE_IP<<endl;

//    fseek(archive,0, POS+16);
    cout<<"IP Destination Address: ";
    for(i=POS; i < POS+4; i++) {
        if(i<POS+3) {
                sprintf(charBuffer,"%i.",Pack[i]);
            }
        else {
            sprintf(charBuffer,"%i",Pack[i]);
            }
        DESTINATION_IP+=charBuffer;
        }
        POS+=4;
    cout<<DESTINATION_IP<<endl;

    if(PROTOCOL == 17){//Protocol de UDP
        LeerUDP(Pack,POS);
    }

    if(flag && PROTOCOL==1) {//Protocol de ICMP
        LeerICMPv4(Pack,POS+=JUMPOPTION);//salto las optiones
        }
    }

void LeerARP(const unsigned char* Pack, int& POS) {//POS 14
    string PROTOCOL_TYPE, SENDER_MAC, SENDER_IP, TARGET_MAC, TARGET_IP;
    int i=0,HARD_ADDRESS_LENG=0,PROTO_ADDRESS_LENG=0, OPERATION=0,HARD_TYPE=0;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";
    cout<<endl<< "\t\t\t ARP "<<endl;

//    fseek(archive,POS, SEEK_SET);
    cout<<endl<<"HardwareType: ";
    for(i=POS; i < POS+2; i++) {
        HARD_TYPE += Pack[i];
        }
        POS+=2;
    cout<<HARD_TYPE;
    if(HARD_TYPE == 1) {
        cout<<" (Ethernet)"<<endl;
        }

//    fseek(archive,0, POS+2);
    cout<<"Protocol type: 0x";
    for(i=POS; i < POS+2; i++) {
        sprintf(charBuffer,"%02X", Pack[i]);
        PROTOCOL_TYPE += charBuffer;
        }
        POS+=2;
    if(PROTOCOL_TYPE == "0800") {
        cout<<PROTOCOL_TYPE+" (IPv4)"<<endl;
        }

//    fseek(archive,0, POS+4);
    cout<<"Hardware Address Length: ";
    HARD_ADDRESS_LENG = Pack[POS++];

    cout<<HARD_ADDRESS_LENG<<" bytes"<<endl;
//    fseek(archive,0, POS+5);
    cout<<"Protocol Address Length: ";
    PROTO_ADDRESS_LENG = Pack[POS++];

    cout<<PROTO_ADDRESS_LENG<<" bytes"<<endl;

//    fseek(archive,0, POS+6);
    cout<<"Operation: ";//<<POS;
    for(i=POS; i < POS+2; i++) {
        OPERATION += Pack[i];
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
                sprintf(charBuffer,"%02X:", Pack[i]);
            }
        else {
            sprintf(charBuffer,"%02X ", Pack[i]);

            }
        SENDER_MAC += charBuffer;
        }
        POS+=6;
    cout<<SENDER_MAC<<endl;

//    fseek(archive,0, POS+14);
    cout<<"Sender IP Address: ";
    for(i=POS; i < POS+4; i++) {
        if(i<POS+3) {
            sprintf(charBuffer,"%i.", Pack[i]);
            }
        else {
            sprintf(charBuffer,"%i", Pack[i]);
            }
        SENDER_IP += charBuffer;
        }
        POS+=4;
    cout<<SENDER_IP<<endl;

//    fseek(archive,0, POS+18);
    cout<<"Target Mac Address: ";
    for(i=POS; i < POS+6; i++) {
        if(i<POS+5) {
            sprintf(charBuffer,"%02X:", Pack[i]);
            }
        else {
            sprintf(charBuffer,"%02X", Pack[i]);

            }
        TARGET_MAC += charBuffer;
        }
        POS+=6;
    cout<<TARGET_MAC<<endl;

//    fseek(archive,0, POS+24);
    cout<<"Target IP Address: ";
    for(i=POS; i < POS+4; i++) {
        if(i<POS+3) {
            sprintf(charBuffer,"%i.", Pack[i]);
            }
        else {
            sprintf(charBuffer,"%i", Pack[i]);
            }
        TARGET_IP+=charBuffer;
        }
        POS+=4;
    cout<<TARGET_IP<<endl;
    }

void LeerCabeceraEthernet(const unsigned char* Pack, const int& Size, int& POS) {
    string MACd, MACo, ETHER, FCS;
    int i, firstBit, secondBit;

    cout<<endl;
    for(i=0; i<=70; i++)
        cout<< "-";

    cout<<endl<< "\t\t\t ETHERNET "<<endl;


    //fseek(archive,0, SEEK_SET);
    cout<<endl<<"Direccion MAC destino: ";
    for(i=POS; i<POS+6; i++) {
        if(i<POS+5) {
            sprintf(charBuffer,"%02X:", Pack[i]);
            }
        else {
            sprintf(charBuffer,"%02X", Pack[i]);
            }
        MACd+= charBuffer;
        }
        POS+=6;
    cout<<MACd<<endl;

    firstBit = Pack[0] & 1;//el primer bit(operacion binaria)
    secondBit = Pack[0] & 2;//el segundo bit(operacion binaria)

    if("FF:FF:FF:FF:FF:FF " == MACd) {
        cout<<"\tEs una MAC Address Broadcast"<<endl;
        }
    else if(firstBit = Pack[0] & 1 == 1) {
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
                sprintf(charBuffer,"%02X:", Pack[i]);
            }
        else {
            sprintf(charBuffer,"%02X", Pack[i]);
            }
        MACo+=charBuffer;
        }
        POS+=6;
    cout<<MACo<<endl;

    firstBit = Pack[6] & 1;//el primer bit(operacion binaria)
    secondBit = Pack[6] & 2;//el segundo bit(operacion binaria)

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
            sprintf(charBuffer,"%02X", Pack[i]);
        ETHER += charBuffer;
        }
        POS+=2;
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

    cout<< (Size - 18)<<" bytes de carga util en Ethernet"<<endl; //Se resta 18, debido a los bytes que se usan para la cabecera (MAC Addres y etc)

    if(ETHER == "0806") {//POS = 14
        cout<<"FCS: 0x ";
    for(i=Size-4; i<Size; i++) {
        sprintf(charBuffer,"%02X ", Pack[i]);
        FCS += charBuffer;
        }
    cout<<FCS<<endl;
        LeerARP(Pack, POS);
        }
    else if (ETHER == "0800") {
        cout<<"FCS: 0x ";
    for(i=Size-4; i<Size; i++) {
        sprintf(charBuffer,"%02X ", Pack[i]);
        FCS += charBuffer;
        }
    cout<<FCS<<endl;
        LeerIPv4(Pack, POS, true);
        }
    else if (ETHER == "86DD") {
        LeerIPv6(Pack, POS, true);
        }


        //cout<<"FFFFFFFFFIIIIIIIIIIINNNNNNNNNN"<<endl;
    }
