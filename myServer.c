#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <shadow.h>
#include <crypt.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>

#define PORT_NUMBER 4433
#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define USER_SIZE 200
#define PSW_SIZE 200
int  setupTCPServer();          // Defined in Listing 19.10

//gcc login.c -lcrypt
//public-private key: psw:12345 ； common name： liang.com
//CA psw : 12345
//counrty name:yy state: yy  all of them is yy. except that common name: self 



// using shadow file to check the vpn client
int check_Client(char *user, char *passwd){
 
	struct spwd *pw;
	char *epasswd;
	pw = getspnam(user);
	if(pw == NULL) {
    printf("--------------UserName does not exist--------\n");
    return -1;
  }

	printf("Login Name: %s\n", pw->sp_namp);
	printf("Passwd.   : %s\n", pw->sp_pwdp);
	epasswd = crypt(passwd, pw->sp_pwdp);
	if(strcmp(epasswd, pw->sp_pwdp)){
    printf("-------------Password Wrong!----------");
		return -1; 
	}

	return 1;

}

// create tun Device
int createTunDevice() {
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);

	//--------------------send the packet to vpn server through the tunnel-------------------
    SSL_write(ssl,buff,len);
   
}

void socketSelected (int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
    // get the packet from the tunnel and using ssl to decrypt the packet then saved inbuff
    len = SSL_read(ssl, buff, BUFF_SIZE);
    
    //put the packet to kernel
    write(tunfd, buff, len);

}


int setupTCPServer()
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock= socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset (&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family      = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port        = htons (PORT_NUMBER);
    int err = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}

void process_packet(int tunfd, int sockfd, SSL *ssl){
 while (1) {
     fd_set readFDSet;

     FD_ZERO(&readFDSet);
     FD_SET(sockfd, &readFDSet);
     FD_SET(tunfd, &readFDSet);
     select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
     if (FD_ISSET(tunfd,  &readFDSet)) tunSelected(tunfd, sockfd, ssl);
     if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
    
    // usleep(1000000);
  }

}

int main(){

  SSL_METHOD *meth;
  SSL_CTX* ctx;
  SSL *ssl;
  

   //Step 0: OpenSSL library initialization 
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  
  // -----------------------Create tun device-----------------------------------------
  int tunfd = createTunDevice();

  //----------------------- Step 1: SSL context initialization-------------------------
  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  //------------------------- Step 2: Set up the server certificate and private key-------------------
  SSL_CTX_use_certificate_file(ctx, "./cert_server/server-cert.pem", SSL_FILETYPE_PEM);
  SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/server-key.pem", SSL_FILETYPE_PEM);

  // --------------------------Step 3: Create a new SSL structure for a connection--------------------
  ssl = SSL_new (ctx);

  struct sockaddr_in sa_client;
  size_t client_len;
  int listen_sock = setupTCPServer();

  while(1){
  //after settingup the TCP server, we first need to check the first two packet ,which is the username and password
    int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
    if(fork() == 0){
      close (listen_sock);
      char username[USER_SIZE];
      char password[PSW_SIZE];
      memset(username,0,USER_SIZE);
      memset(password,0,PSW_SIZE);

      SSL_set_fd (ssl, sock);
      int err = SSL_accept (ssl);
      CHK_SSL(err);
      printf ("SSL connection established!\n");
      int index = 1;
      while(1){
  	    fd_set set;
  	    FD_ZERO(&set);
  	     FD_SET(sock,&set);
  	     if (FD_ISSET(sock,  &set)){
  	      	if(index == 1){SSL_read(ssl, username, 200); index++;}
  		      if(index == 2){ SSL_read(ssl,password,200); index++;}
  		      if(index == 3){break;}
  	      }
      }
      if(check_Client(username,password) != 1) {
  	   exit(-1);
      }else{
  	    printf ("Valid User!\n");
  	//---------------------------------packet processing-----------------------
  	   process_packet(tunfd,sock, ssl);
      }
      close(sock);
    }else{
      close(sock);
    }

  }
  
  return 0;

}



















