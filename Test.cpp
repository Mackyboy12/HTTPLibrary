#include "NetworkingLibrary.cpp"
#include <iostream>


int main(int argc, char* argv[]){
    try{
        std::cout << argv[1] << "\n";
        Website site(argv[1]);
        site.sendToSite("GET /robots.txt\r\n\r\n");
        char * buf = new char[500]();
        site.recvFromSite(buf, 500);
        std::cout << buf << "\n";
    }catch (char const* error){
            std::cout << "Error: " << error << "\n\n";
            exit(-1);
    }
}
