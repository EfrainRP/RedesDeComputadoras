//Efrain Robles Pulido
#include <iostream>

#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <string>

using namespace std;

FILE* archive;
int opcM, word;
char charBuffer[3];

//fgetc te lo regresa como entero

void LeerARP(){
    string PROTOCOL_TYPE, SENDER_MAC, SENDER_IP, TARGET_MAC, TARGET_IP;
    int HARD_TYPE, HARD_ADDRESS_LENG,PROTO_ADDRESS_LENG, OPERATION;
    for(int i=0; i<=70; i++)
            cout<< "-";
        cout<<endl<< "\t\t\t ARP "<<endl;

        fseek(archive,14, SEEK_SET);
        cout<<endl<<"HardwareType: ";
        for(int i=0; i < 2; i++) {
            word = fgetc(archive);
            HARD_TYPE += word;//recibe expresion decimal para convetirlo a entero
            }
        cout<<HARD_TYPE;
        if(HARD_TYPE == 1) {
            cout<<" (Ethernet)"<<endl;
            }

        fseek(archive,0, 16);
        cout<<"Protocol type: 0x";
        for(int i=0; i < 2; i++) {
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
        for(int i=0; i < 2; i++) {
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
        for(int i=0; i < 6; i++) {
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
        for(int i=0; i < 4; i++) {
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
        for(int i=0; i < 6; i++) {
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
        for(int i=0; i < 4; i++) {
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
    int firstBit, secondBit;
    for(int i=0; i<=70; i++)
        cout<< "-";

    cout<<endl<< "\t\t\t ETHERNET "<<endl;


    fseek(archive,0, SEEK_SET);
    cout<<endl<<"Direccion MAC destino: ";
    for(int i=0;i<6;i++) {
        word = fgetc(archive);
        if(i==1) {//recibo el primer byte
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
    }else if(secondBit == 2) {
        cout<<"\tEs una MAC Address Multicast"<<endl;
    }
    if(firstBit == 1) {
        cout<<"\tLocally administered"<<endl;
    } else if(firstBit == 0) {
        cout<<"\tGlobally Unique"<<endl;
    }

    fseek(archive,0, 6);
    cout<<endl<<"Direccion MAC origen: ";
    for(int i=0;i<6;i++) {
        word = fgetc(archive);
        if(i==1) {//recibo el primer byte
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
        cout<<"\tLocally administered"<<endl;
        }
    else if(firstBit == 0) {
        cout<<"\tGlobally Unique"<<endl;
        }

    fseek(archive,12, SEEK_SET);
    cout<<endl<<"Ethertype: 0x";
    for(int i=0;i<2;i++) {
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
    for(int i=0;i<4;i++) {
        word = fgetc(archive);
        sprintf(charBuffer, "%02X ", word);
        FCS += charBuffer;
        }
    cout<<FCS<<endl;

    if(ETHER == "0806"){
            LeerARP();
        }
    }

int main() {
    string nombre;
    //do {
    cout << "Dime el nombre del fichero: ";//ethernet_arp_reply.bin     ethernet_ipv4_icmp.bin
    getline(cin, nombre);//ethernet_1.bin

    //Si logra abrir el fichero
    if ((archive = fopen(nombre.c_str(), "rb")) == NULL) {
        cout<< "Error en la apertura. Algo salio mal";
        }
    else {
        LeerCabeceraEthernet();
        }//If FIN del Fopen
    cout<<endl;
    fclose(archive);

    /*cout<<"Leer otro archivo: 1(Si)   2(No)";
    cin>>opcM;
    }
    while(opcM != 2);*/
    return 0;
    }
