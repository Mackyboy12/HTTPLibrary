
#include <iostream>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <sstream>
#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include <vector>
#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/conf.h>

class Website
{
    int status, sock, ssl_sock;
    struct addrinfo hints;
    struct addrinfo *servinfo;
    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;
    long res = 1;
 
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
          if(Website::url.protocol == "http"){
            establishConn();
            std::cout << "Err\n";
          } else if(Website::url.protocol == "https"){
            initSSL();
            initCTX();
            /*
            if((web = BIO_new_ssl_connect(ctx)) == NULL) throw "Error in bio ssl";
            if(BIO_set_conn_hostname(web, Website::url.host.c_str()) != 1) throw "BIO hostname error"; 
            if(BIO_set_conn_port(web, Website::url.port.c_str()) != 1) throw "BIO port error";
            if(BIO_set_nbio(web, 1) != 1) throw "Error setting BIO to nonblocking";
            BIO_get_ssl(web, &ssl);
            if(ssl == NULL) throw "Error in ssl";*/
            const char* const PREFERED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
            if(SSL_set_cipher_list(ssl, PREFERED_CIPHERS) != 1) throw "Cipher error";
            if(SSL_set_tlsext_host_name(ssl, Website::url.host.c_str()) != 1) throw "Hostname error";
            /*if(BIO_do_connect(web) == 0) throw "Error connecting";
            //if(BIO_do_handshake(web) == 0) throw "Error handshake";
            X509* cert = SSL_get_peer_certificate(ssl);
            if(cert) X509_free(cert);
            if(cert == NULL) {ERR_print_errors_fp(stderr); throw "Error with cert";}
            if(SSL_get_verify_result(ssl) != X509_V_OK) throw "Error verifying cert";*/
            
            establishConn();
            ssl_sock = SSL_get_fd(ssl);
            if(SSL_set_fd(ssl, sock) == 0) throw "Error setting fd";
            int SSL_status = SSL_connect(ssl);
            switch(SSL_get_error(ssl,SSL_status)){
                case SSL_ERROR_NONE:
                    //No error, do nothing
                    break;
                case SSL_ERROR_ZERO_RETURN:
                    throw "Peer has closed connection";
                    break;
                case SSL_ERROR_SSL:
                    ERR_print_errors_fp(stderr);
                    SSL_shutdown(ssl);

                    throw "Error in SSL library";
                    break;
                    
                default:
                    ERR_print_errors_fp(stderr);
                    throw "Unknown error";
                    break;

            }
            std::cout << "Ssl connection using " << SSL_get_cipher(ssl) << "\n";


          }
      }
     
      std::string get(std::string loc, int maxsize){
        std::string request = "GET "+ loc + "\r\n\r\n";
        char *recvBuf = new char[maxsize];
        memset(recvBuf, 0, strlen(recvBuf));
        Website::sendToSite(request);
        Website::recvFromSite(recvBuf, maxsize);
        std::string reply(recvBuf);
        return reply;
      }
    ~Website(){
      if(Website::url.protocol =="http"){
        close(sock);
        freeaddrinfo(servinfo);
      }else if(Website::url.protocol == "https"){
        SSL_free(ssl);
        SSL_CTX_free(ctx);
      }
     }

    private:
      void sendToSite(std::string request){
        if(Website::url.protocol == "http"){
            if (send(sock, request.c_str(), strlen(request.c_str()), 0)  == -1) throw "Error sending message";
        } else if(Website::url.protocol == "https"){
            int len = SSL_write(ssl, request.c_str(), strlen(request.c_str()));
            if(len < 0) throw "Error sending ssl packet"; 
        }
      }

      void recvFromSite(char buf[], int maxsize){
        if(Website::url.protocol == "http"){
            if (recv(sock, buf, maxsize, 0) == -1) throw "Error receving message";
        } else if(Website::url.protocol == "https"){
            int amountRead = 0;
           while(amountRead < maxsize){
                int readPart = SSL_read(ssl, buf, maxsize - amountRead);
                if(readPart < 0) throw "Error reccieving message";
                amountRead += readPart;
           
           } 
        }
      }
      //Setting up the SSL
      void initSSL(void){
        SSL_library_init();

      }
      void initCTX(){
        const SSL_METHOD* method = TLS_method();
        if((ctx = SSL_CTX_new(method)) == NULL) throw "Could not create CTX";
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        SSL_CTX_set_verify_depth(ctx, 4);
        SSL_CTX_set_options(ctx, SSL_OP_ALL);
        if(SSL_CTX_set_default_verify_paths(ctx) == 0) throw "Couldn't se default verify paths";
        if((ssl = SSL_new(ctx)) == NULL) throw "Couldn't create SSL";

 
  
      }
      void establishConn(){
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        if((status = getaddrinfo(Website::url.host.c_str(), Website::url.port.c_str(), &hints, &servinfo)) != 0) throw "Something wrong with getaddrinfo";
        if((sock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol)) == -1) throw "Something wrong with creating socket";
        if((connect(sock, servinfo->ai_addr, servinfo->ai_addrlen)) != 0) throw "Error in connecting to website";       
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
};/*
int verify_callback(int preverify, X509_STORE_CTX* x509_ctx){
  int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
  int err = X509_STORE_CTX_get_error(x509_ctx);
        
  X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
  X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
        
  std::cout << "Issuer (cn)" << (char *)iname;
  std::cout << "Subject (cn)"<<(char *) sname;
  return preverify;
 }*/
