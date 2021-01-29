

#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include <vector>
#include <string>
class Website
{
    int status, sock;
    struct addrinfo hints;
    struct addrinfo *servinfo;
    struct URL
    {
        std::string host;
        std::string port;
        std::string protocol;
    };
    URL url;
    public:
      Website(std::string url){
          parseUrl(url);
          memset(&hints, 0, sizeof hints);
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = SOCK_STREAM;
          if((status = getaddrinfo(Website::url.host.c_str(), Website::url.port.c_str(), &hints, &servinfo)) != 0) throw "Something wrong with getaddrinfo";
          if((sock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1) throw "Something wrong with creating socket";
          if((connect(sock, servinfo->ai_addr, servinfo->ai_addrlen)) != 0) throw "Error in connecting to website";
      }
     
      std::string get(std::string loc, int maxsize){
        std::string request = "GET "+ loc + "\r\n\r\n";
        char * recvBuf = new char[maxsize]();  
        Website::sendToSite(request);
        Website::recvFromSite(recvBuf, maxsize);
        std::string reply(recvBuf);
        return reply;
      }
    ~Website(){
      close(sock);
      freeaddrinfo(servinfo);
     }

    private:
      void sendToSite(std::string request){
        if (send(sock, request.c_str(), strlen(request.c_str()), 0)  == -1){
            throw "Error sending message"; 
        }
      }
      void recvFromSite(char buf[], int maxsize){
        if (recv(sock, buf, maxsize, 0) == -1){
            throw "Error receving message";
        }
      }
   //Filles struct Website::url  with host as first argument and path as second
  void parseUrl(std::string url){
    // Check wether url is http or https
    if(url.rfind("http://", 0) == 0){
        Website::url.port = "80";
        Website::url.host = url.substr(7);
        Website::url.protocol = "http";  
    } else if (url.rfind("https://", 0) == 0){
        Website::url.port = "443";
        Website::url.host = url.substr(8);
        Website::url.protocol = "https";
    } else {
        throw "Invalid url, must start with http:// or https://";
    }
  }
};

