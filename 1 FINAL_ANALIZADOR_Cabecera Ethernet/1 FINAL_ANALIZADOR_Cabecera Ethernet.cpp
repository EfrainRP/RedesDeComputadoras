//Efrain Robles Pulido
#include <iostream>
#include <fstream>
//#include <stdlib.h>
//#include <string.h>
#include <string>

using namespace std;
int firstBit(0), secondBit(0);
char myChar[2], *ptrChar;

void bitAnalize(unsigned char hexa) {
    sprintf(myChar, "%03d", hexa);
    ptrChar = &myChar[0];
    int binary = atoi(ptrChar);//recibe expresion decimal para convetirlo a entero

    //cout<<binary<<"   byte"<<endl;

    firstBit = binary & 2;//el primer bit(operacion binaria)
    //secondBit = binary & 1;//el segundo bit(operacion binaria)

    //cout<<binary<<"   resultado"<<endl;

    /*  sprintf(myChar, "%02X", firstBit);
      cout<<myChar<<endl;

      sprintf(myChar, "%02X", secondBit);
      cout<<myChar<<endl;
    */
    }

int main() {
    
    int i(0), opcM(0);
    string nombre, MACd, MACo, ETHER, FCS;
    unsigned char(word);
    unsigned char(hex);
    char charBuffer[3], charBinary[5];

    //do {
        cout << "Dime el nombre del fichero: ";//ethernet_1.bin
        getline(cin, nombre);

        //Si logra abrir el fichero
        if ((archive = fopen(nombre.c_str(), "rb")) == NULL) {
            cout<< "Error en la apertura. Algo salio mal";
            }
        else {

            fseek(archive,0, SEEK_SET);
            cout<<endl<<"Direccion MAC destino: ";
            while(i <6) {
                word = fgetc(archive);
                if(i==1) {
                    hex = word; //recibo el primer byte
                    }
                if(i<5) {
                    sprintf(charBuffer, "%02X:", word);
                    }
                else {
                    sprintf(charBuffer, "%02X ", word);
                    }
                MACd += charBuffer;
                i++;
                }
            cout<<MACd<<endl;

            bitAnalize(hex);

            if("FF:FF:FF:FF:FF:FF " == MACd) {
                cout<<"\tEs una MAC Address Broadcast"<<endl;
                }/*else if(secondBit == 1) {
                cout<<"\tMulticast"<<endl;
                }else if(secondBit == 0) {
                cout<<"\tUnicast"<<endl;
                }*/

            if(firstBit == 2) {
                cout<<"\tLocally administered"<<endl;
                }
            else if(firstBit == 0) {
                cout<<"\tGlobally Unique"<<endl;
                }

            fseek(archive,0, 6);
            cout<<endl<<"Direccion MAC origen: ";
            i = 0;
            while(i < 6) {
                word = fgetc(archive);
                if(i==1) {
                    hex = word; //recibo el primer byte
                    }
                if(i<5) {
                    sprintf(charBuffer, "%02X:", word);
                    }
                else {
                    sprintf(charBuffer, "%02X ", word);
                    }
                MACo += charBuffer;
                i++;
                }
            cout<<MACo<<endl;

            bitAnalize(hex);

            if(firstBit == 2) {
                cout<<"\tLocally administered"<<endl;
                }
            else if(firstBit == 0) {
                cout<<"\tGlobally Unique"<<endl;
                }/*else if(secondBit == 1) {
                cout<<"\tMulticast"<<endl;
                }else if(secondBit == 0) {
                cout<<"\tUnicast"<<endl;
                }*/

            fseek(archive,2, 12);
            cout<<endl<<"Ethertype: 0x";
            i = 0;
            while(i < 2) {
                word = fgetc(archive);
                sprintf(myChar, "%02X", word);
                ETHER += myChar;
                i++;
                }
            //ETHERetecout<<ETHER;

            if(ETHER == "0800") {
                cout<<ETHER+" (IP)"<<endl;
                }
            else if(ETHER == "0806") {
                cout<<ETHER +" (ARP)"<<endl;
                }

            fseek(archive,0,SEEK_END);//Se va al final del archivo
            long packSize = ftell(archive);//Obtenemos cla cantidad total del paquete
            rewind(archive);//Vuelve al principio
            cout<< (packSize - 18)<<" bytes de carga util en Ethernet"<<endl; //Se resta 18, debido a los bytes que se usan para la cabecera (MAC Addres y etc)

            fseek(archive,-4, SEEK_END);
            cout<<"FCS: 0x ";
            i=0;
            while(i<4) {
                word = fgetc(archive);
                sprintf(charBuffer, "%02X ", word);
                FCS += charBuffer;
                i++;
                }
            cout<<FCS;
            }
        cout<<endl;
        fclose(archive);

        /*cout<<"Leer otro archivo: 1(Si)   2(No)";
        cin>>opcM;
        }
    while(opcM != 2);*/
    return 0;
    }
