//Efrain Robles Pulido

#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <iostream>

#include "List.h"
#include "ETHERNET.h"
#include <windows.h>

//#include <pcap.h>
#define LINE_LEN 16

#include <fstream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include<math.h>
#include <cstring>
#include <cstddef>

using namespace std;
//const char* Pack, const string* HexPack, const int& Size, int POS

int main(int argc,char*argv[]) {
    //E:\\Documentos PC\\UDG Materias\\REDES\\ARCHIVOS\\
    //C:\\Users\\efrai\\OneDrive\\Documentos\\REDES\\ARCHIVOS\\

    string myArchive, arch = "C:\\Users\\efrai\\OneDrive\\Documentos\\REDES\\ARCHIVOS\\";
    int opcM=0, opc=0, i=0,POS=0;
    char charBuffer[3];

    List<unsigned char> pack;
    List<unsigned char>::Position NodePOS(nullptr);

    Ethernet INFOarchive;

    FILE* archive;
    unsigned char valueArchive;
    long int packSize;

    while(opcM<2) {
        ///system("cls");
        cout<<endl<<"\tINGRESE OPCION A LEER"<<endl<<"\t     1(LOCAL)   2(PCAP):    ";
        cin>>opc;
        if (opc == 1) {
            cout << endl<< "Dime el nombre del fichero: ";
            getline(cin.ignore(), myArchive);
            myArchive = arch + myArchive + ".bin";

            //Si logra abrir el fichero
            if ((archive = fopen(myArchive.c_str(), "rb")) == NULL) {
                cout<< "Error en la apertura. Algo salio mal"<<endl;
                break;
                }
            else {
                while (!feof(archive)) {//feof devuelve un 0 cuando leyo todo el archivo
                    valueArchive = fgetc(archive);
                    pack.insertData((NodePOS=pack.getLastPos()),valueArchive);

                    }
                NodePOS=pack.getFirstPos();
                /*int i=0;
                while(i<pack.getListSize()) {
                    sprintf(charBuffer,"%02x ",pack[i]);
                    if(i==74) { //42
                        HANDLE hConsole=GetStdHandle(STD_OUTPUT_HANDLE);
                        SetConsoleTextAttribute(hConsole, 2);

                        }
                    else {
                        HANDLE hConsole=GetStdHandle(STD_OUTPUT_HANDLE);
                        SetConsoleTextAttribute(hConsole, 7);
                        }
                    cout<<charBuffer;
                    i++;
                    }*/
                }
            //Ethernet INFOarchive(pack);
            cout<<pack.toString()<<endl;
            INFOarchive=pack;
            INFOarchive.LeerCabeceraEthernet();
            fclose(archive);
            pack.deleteAll();

            }
        else if(opc==2) {
            pcap_if_t *alldevs, *d;
            pcap_t *fp;
            u_int inum, t=0;
            int i=0, res;
            char errbuf[PCAP_ERRBUF_SIZE];
            struct pcap_pkthdr header;
            unsigned char *pkt_data;

            printf("pktdump_ex: prints the packets of the network using WinPcap.\n");
            printf("   Usage: pktdump_ex [-s source]\n\n"
                   "   Examples:\n"
                   "      pktdump_ex -s file.acp\n"
                   "      pktdump_ex -s \\Device\\NPF_{C8736017-F3C3-4373-94AC-9A34B7DAD998}\n\n");

            if(argc < 3) {
                printf("\nNo adapter selected: printing the device list:\n");
                /* The user didn't provide a packet source: Retrieve the local device list */
                if(pcap_findalldevs(&alldevs, errbuf) == -1) {
                    fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
                    exit(1);
                    }

                /* Print the list */
                for(d=alldevs; d; d=d->next) {
                    printf("%d. %s\n    ", ++t, d->name);

                    if (d->description)
                        printf(" (%s)\n", d->description);
                    else
                        printf(" (No description available)\n");
                    }

                if (t==0) {
                    printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
                    return -1;
                    }

                printf("Enter the interface number (1-%d):",t);
                scanf("%d", &inum);

                if (inum < 1 || inum > t) {
                    printf("\nInterface number out of range.\n");

                    /* Free the device list */
                    pcap_freealldevs(alldevs);
                    return -1;
                    }

                /* Jump to the selected adapter */
                for (d=alldevs, t=0; t< inum-1 ; d=d->next, t++);

                /* Open the adapter */
                if ((fp = pcap_open_live(d->name,	// name of the device
                                         65536,							// portion of the packet to capture.
                                         // 65536 grants that the whole packet will be captured on all the MACs.
                                         1,								// promiscuous mode (nonzero means promiscuous)
                                         1000,							// read timeout
                                         errbuf							// error buffer
                                        )) == NULL) {
                    fprintf(stderr,"\nError opening adapter\n");
                    return -1;
                    }
                }
            else {
                /* Do not check for the switch type ('-s') */
                fp = pcap_open_live(argv[2],	// name of the device
                                    65536,							// portion of the packet to capture.
                                    // 65536 grants that the whole packet will be captured on all the MACs.
                                    1,								// promiscuous mode (nonzero means promiscuous)
                                    0,							// read timeout
                                    errbuf							// error buffer
                                   );
                if ( fp == NULL) {
                    fprintf(stderr,"\nError opening adapter\n");
                    return -1;
                    }
                }

            pkt_data = (unsigned char*) pcap_next(fp, &header);

            if(pkt_data != nullptr) {


                /* Print the packet */
                for (t=0; t < header.len ; t++) {
                    printf("%.2x ", pkt_data[t]);

                    if ( (t % LINE_LEN) == 0) printf("\n");

                    pack.insertData((NodePOS=pack.getLastPos()),pkt_data[t]);

                    }
                ///printf("\n\n");

                }

            int ID,k;
            int j=1, ba=0;
            int flag,banj = 0, bandera;


            /*if ((archivo1 = fopen("File01.txt", "rb+")) == NULL)
            {
            	printf("Error en la apertura. Es posible que el fichero no exista. \n ");
            }
            else
            {
            	while(!feof(archivo1))
            	{
            		archivoEthernet[c]=pkt_data[i-1];
            		c++;
            	}*/

            /*for(int o=0;o<3;o++){
                archivoEthernet[c]=arch;
            	c++;
            }*/
            cout<<pack.toString()<<endl;
            INFOarchive=pack;
            INFOarchive.LeerCabeceraEthernet();
            pack.deleteAll();

            system("pause");
            }
        cout<<endl<<"\tDESEA LEER OTRO ARCHIVO"<<endl<<"\t     1(Si)   2(No):    ";
        cin>>opcM;
        cin.ignore();
        }

    cout<<endl<<endl<<"\tFIN DEL PROGRAMA"<<endl;
    return 0;
    }
