#ifndef ETHERNET_H_INCLUDED
#define ETHERNET_H_INCLUDED

#include "List.h"
#include <iostream>
#include "string"
#include<windows.h>
#include <stdint.h>

/*class DICCIONARY{
private:
    int ptr;
    string link;

public:
    DICCIONARY();

    void setPtr(const int&);
    int getPtr();

    void setLink(const string&);
    string getLink();
};*/

class Ethernet{
private:
    List<unsigned char> infoPack;
    //List<DICCIONARY> dicc;
    int POS;
    char charBuffer[3];

public:
    Ethernet ();
    Ethernet(List<unsigned char>&);
    ~Ethernet();

    List<unsigned char>& operator = (const List<unsigned char>&);
    void LeerCabeceraEthernet();

private:
    void setColor(const int);
    void LeerARP();
    void LeerIPv4(const bool);
    void LeerICMPv4();
    void LeerIPv6(const bool);
    void LeerICMPv6(const int&);
    void optionsICMPv6(const int&);
    void LeerUDP();
    void LeerDNS();
    void LeerTCP(const int&);

    void parseInfoQuestions();
    void parseAllInfo(const int&);
    void parseTheInfo(const int&);//metodo recursivo iniciador
    void parseTheInfo(const int&,int);//metodo recursivo trabajador

    string etherType(const string&);
    string TYPEofPROTOCOL(const int&);
    string typeIcmpv4(const int&);
    string codeIcmpv4(const int&, const int&);
    string formatIPv6(string&);
    string typeICMPV6(const int&);
    string codeIcmpv6(const int&, const int&);
    string OpC_flag(const int);
    string RCode_flag(const int);
    string TypeDNS(const int&);
    string ClassDNS(const int&);

    int Hexa_Decimal(const string&);
};


#endif // ETHERNET_H_INCLUDED
