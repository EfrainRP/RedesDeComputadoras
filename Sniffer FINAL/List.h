#ifndef LIST_H_INCLUDED
#define LIST_H_INCLUDED

#include <string>
#include <exception>
///Definicion de Lista
template <class T>
class List {
    private:
///Definicion del Nodo
        class Node {//Es una clase anidad de la lista aprovechando la plantilla
            private:
                T data;
                Node* next;
            public:
                Node();
                Node(const T&);
                T getData()const;
                Node* getNext()const;
                void setData(const T&);
                void setNext(Node*);
            };
    public:
        typedef Node* Position;//aunque el nodo sea pivado, el nodo sera publico atraves de Position y se inicializa

        ///Definicion de Excepcion
        class ListException : public std::exception {
            private:
                std::string msg;
            public:
                explicit ListException(const char* message): msg(message){}
                explicit ListException(const std::string& message): msg(message) {}
                virtual ~ListException() throw() {}
                virtual const char* what() const throw () {
                    return msg.c_str();
                    }
            };
    private:
        int ListSize;
        Node* anchor;//Se abre esta area para aprovechar e incializar lo que tengo anteriormente

        bool isValidPos(Node*)const;
        void copyAll(const List<T>&);//Guardara el objeto creado a una copia
    public:
        ///Constructores
        List();
        List(const List<T>&);
        ~List(); ///Destructor

        ///Sobrecarga de operador
        List<T>& operator = (const List<T>&);//No es necesario el <T> porque para el compilador ya esta todo esta plantillado asi que ya no es necesario
        T operator [] (const int&);

        ///Metodos para una Lista
        bool isEmpty()const;
        std::string toString()const;
        void insertData(Position, const T&);
        void deleteData(Position);
        void deleteAll();
        T retrieve(Position)const;
        Position getFirstPos()const;
        Position getLastPos()const;
        Position getPrevPos(Position)const;
        Position getNextPos(Position)const;
        Position findDataLinear(const T&, int comp(const T&, const T&))const;

        int getListSize()const;
    };
///Implementacion
using namespace std;
///del Nodo
template <class T>
List<T>::Node::Node():next(nullptr) {}

template <class T>
List<T>::Node::Node(const T& e): next(nullptr), data(e) {}

template <class T>
T List<T>::Node::getData()const {
    return data;
    }

template <class T>
typename List<T>::Position List<T>::Node::getNext()const {
    return next;
    }

template <class T>
void List<T>::Node::setData(const T& e) {
    data = e;
    }

template <class T>
void List<T>::Node::setNext(Node* p) {
    next = p;
    }

///de la Lista
///Metodos privados
template <class T>
bool List<T>::isValidPos(Position p) const {
    Position aux(anchor);
    while (aux != nullptr) {
        if(aux == p) {
            return true;
            }
        aux=aux->getNext();
        }
    return false;
    }

template <class T>
void List<T>::copyAll(const List<T>& l) {
    Position aux(l.anchor);
    Position last(nullptr);
    Position newNode;
    while(aux != nullptr) {
        newNode = new Node(aux->getData());
        if(newNode == nullptr) {
            throw ListException("Memoria no disponible, inserData");
            }
        if(last == nullptr) {
            anchor = newNode;
            }
        else {
            last->setNext(newNode);
            }
        last = newNode;
        aux = aux->getNext();
        ListSize=l.ListSize;
        }
    }

///Constructores
template <class T>
List<T>::List(): anchor(nullptr), ListSize(0) {}

template <class T>
List<T>::List(const List<T>& l):List() {
    copyAll(l);
    }

template <class T>
List<T>::~List() {///Destructor
    deleteAll();
    }

///Sobrecarga de operador
template <class T>
List<T>& List<T>::operator =(const List<T>&l) {
    deleteAll();
    copyAll(l);
    return *this;
    }

template <class T>
T List<T>::operator [](const int& c) {
    if(!isEmpty() and c<ListSize){
        Position aux(anchor);
        int cont(-1);
        while(aux!=nullptr) {
            if(++cont == c){
                return aux->getData();
            }
            aux=aux->getNext();
            }
    }
    throw ListException ("Indice invalido");
    }

///Metodos publicos de la Lista
template <class T>
bool List<T>::isEmpty() const {
    return anchor == nullptr;
    }

template <class T>
std::string List<T>::toString() const {
    string myStr;
    char charBuffer[3];
    Position aux(anchor);

    while(aux!=nullptr){
        sprintf(charBuffer,"%02X ", aux->getData());
        myStr += charBuffer;
        aux = aux->getNext();
        }
    return myStr;
    }

template <class T>
void List<T>::insertData(Position p, const T& e) {
    if(p != nullptr and !isValidPos(p)) {
        throw ListException("Posicion Invalida, insetData");
        }
    Position aux(new Node(e));
    if(aux == nullptr) {
        throw ListException ("Memoria no disponible, inserData");
        }
//Religado
    if(p == nullptr) { //Insertar al principio
        aux->setNext(anchor);
        anchor = aux;
        }
    else { //Insertar en cualquier posicion (despues del punto de interes)
        aux->setNext(p->getNext());
        p->setNext(aux);
        }
        ListSize++;
    }

template <class T>
void List<T>::deleteData(Position p) {
    if(!isValidPos(p)) {
        throw ListException ("Posicion invalida, deleteData");
        }
    if(p == anchor) { //Eliminar el primero
        anchor = anchor->getNext();
        }
    else {//Eliminar cualquier otro
        getPrevPos(p)->setNext(p->getNext());
        }
    delete p;
    ListSize--;
    }

template <class T>
void List<T>::deleteAll() {
    Position aux;
    while(anchor != nullptr) {
        aux = anchor;
        anchor = anchor->getNext();
        delete aux;
        }
        ListSize=0;
    }

template <class T>
T List<T>::retrieve(Position p) const {
    if(!isValidPos(p)) {
        throw ListException ("Posicion invalida, retrieve");
        }
    return p->getData();
    }

template <class T>
typename List<T>::Position List<T>::getFirstPos() const {
    return anchor;
    }

template <class T>
typename List<T>::Position List<T>::getLastPos() const {
    if(isEmpty()) {
        return nullptr;
        }
    Position aux(anchor);
    while(aux->getNext() != nullptr) {
        aux=aux->getNext();
        }
    return aux;
    }

template <class T>
typename List<T>::Position List<T>::getPrevPos(Position p) const {
    if(p == anchor) {
        return nullptr;
        }
    Position aux(anchor);
    while(aux != nullptr and aux->getNext() != p ) {
        aux=aux->getNext();
        }
    return aux;
    }

template <class T>
typename List<T>::Position List<T>::getNextPos(Position p) const {
    if(!isValidPos(p)) {
        return nullptr;
        }
    return p->getNext();
    }

template <class T>
typename List<T>::Position List<T>::findDataLinear(const T& e, int comp(const T&, const T&)) const {
    Position aux(anchor);
    while(aux!=nullptr and comp(aux->getData(),e) != 0) {
        aux=aux->getNext();
        }
    return aux;
    }

 template <class T>
int List<T>::getListSize()const{
    return ListSize;
}

#endif // LIST_H_INCLUDED
