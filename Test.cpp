#include "NetworkingLibrary.cpp"
#include <iostream>


int main(int argc, char* argv[]){
    try{
        Website site(argv[1]);
        std::cout << site.get(argv[2], 1000) << "\n";
    }catch (char const* error){
            std::cout << "Error: " << error << "\n\n";
            exit(-1);
    }
}
