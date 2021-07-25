#include "NetworkingLibrary.cpp"
#include <iostream>


int main(int argc, char* argv[]){
    if(argc < 2){
        std::cout << "Invalid arguments\n";
        exit(0);
    }
    try{
        Website site(argv[1]);
        std::cout << site.get(argv[2], 1000) << "\n";
    }catch (char const* error){
            std::cout << "Error: " << error << "\n\n";
            exit(-1);
    }
}
