

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
      int sendToSite(std::string request){
        return send(sock, request.c_str(), strlen(request.c_str()), 0);
      }
      int recvFromSite(char buf[], int maxsize){
        return recv(sock, buf, maxsize, 0);
      }
    ~Website(){
      close(sock);
      freeaddrinfo(servinfo);
     }
   //Filles struct Website::url  with host as first argument and path as second
  void parseUrl(std::string url){
    // Check wether url is http or https
    if(url.rfind("http://", 0) == 0){
    	Website::url.port = "80";
	Website::url.host = url.substr(7);	
    } else if (url.rfind("https://", 0) == 0){
    	Website::url.port = "443";
	Website::url.host = url.substr(8);
    } else {
    	throw "Invalid url, must start with http:// or https://";
    }
  }
};

