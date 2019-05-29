#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>
#include <netinet/in.h>

//CA psw : 12345
//counrty name:yy state: yy  all of them is yy. except that common name: self 

#define BUFF_SIZE 2000
#define CHK_SSL(err) if ((err) < 1) { ERR_print_errors_fp(stderr); exit(2); }
#define CA_DIR "ca_client" 
#define USER_SIZE 200
#define PSW_SIZE 200

struct sockaddr_in peerAddr;


//send the user name and password to the VPN Server for authentication
void send_User_PSW(SSL *ssl){
   char UID[USER_SIZE];
   char PSW[PSW_SIZE];
   memset(UID, 0, USER_SIZE);
   memset(PSW, 0, PSW_SIZE);

   printf("Input Account:");
   scanf("%s",UID);
   SSL_write(ssl, UID, strlen(UID));
   printf("Input Passwd:");
   scanf("%s",PSW); 
   SSL_write(ssl, PSW, strlen(PSW));

}

// create TUN/TAP Interface;
int createTunDevice() {
  printf("enter tun device");
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  
   // create a tun device
   tunfd = open("/dev/net/tun", O_RDWR);
   // bind the tun0 to the kernel
   ioctl(tunfd, TUNSETIFF, &ifr);       

   return tunfd;
}

//get a packet from the tun interface and then send the packet to VPN server  through the tunnel
void tunSelected(int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from TUN\n");

    bzero(buff, BUFF_SIZE);
    len = read(tunfd, buff, BUFF_SIZE);
    buff[len]='\0';
    // use SSL encrypt and send the packet.
    printf("%d",len);
    int i = SSL_write(ssl, buff, len);
    if(i > 0 ){printf("write successfully");}else{
      printf("Wrong");
    }
    //sendto(sockfd, buff, len, 0, (struct sockaddr *) &peerAddr,
                   // sizeof(peerAddr));
}

// get a packet from the tunnel and
void socketSelected (int tunfd, int sockfd, SSL *ssl){
    int  len;
    char buff[BUFF_SIZE];

    printf("Got a packet from the tunnel\n");

    bzero(buff, BUFF_SIZE);
   // len = recvfrom(sockfd, buff, BUFF_SIZE, 0, NULL, NULL);
   // use SSL to decrypt the data
   len = SSL_read (ssl, buff, BUFF_SIZE);

   write(tunfd, buff, len);

}
/*
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    char  buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("subject= %s\n", buf);

    if (preverify_ok == 1) {
       printf("Verification passed.\n");
    } else {
       int err = X509_STORE_CTX_get_error(x509_ctx);
       printf("Verification failed: %s.\n",
                    X509_verify_cert_error_string(err));
    }
}
*/


//set up TLS client;
SSL* setupTLSClient(const char* hostname)
{
   // Step 0: OpenSSL library initialization 
   // This step is no longer needed as of version 1.1.0.
   //register available ciphers and digests; second error strings; ssl contains an instance of the context
   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   SSL_METHOD *meth;
   SSL_CTX* ctx;
   SSL* ssl;

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);

   SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
   if(SSL_CTX_load_verify_locations(ctx,NULL, CA_DIR) < 1){
	printf("Error setting the verify locations. \n");
	exit(0);
   }
   ssl = SSL_new (ctx);
   //hostname check
   X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl); 
   X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

   return ssl;
}

int setupTCPClient(const char* hostname, int port)
{
   
   struct sockaddr_in *server_addr;

   // --------------------------------Get the IP address from hostname ----------------------
   // getaddrinfo( const char *hostname, const char *service, const struct addrinfo *hints, struct addrinfo **result );
   struct addrinfo hints;
   struct addrinfo *res;
   int ret;

   hints.ai_family = AF_INET;
   //AI_ADDRCONFIG: 查询配置的地址类型(IPv4或IPv6).
   //AI_V4MAPPED: 如果没有找到IPv6地址, 则返回映射到IPv6格式的IPv6地址.
   hints.ai_flags = AI_ADDRCONFIG | AI_V4MAPPED;
   //常用的有SOCK_STREAM、SOCK_DGRAM、SOCK_RAW, 设置为0表示所有类型都可以。
   hints.ai_socktype = 0;
   
   ret = getaddrinfo(hostname, NULL, &hints,&res);

   if(ret != 0){
   		// 将错误信息输出到 标准输出流stderr 中
   		fprintf(stderr,"Error in SetupTCPClient: %s ",gai_strerror(ret));
        exit(1);
   }
   printf("-----------setupClient---------\n");
   
   server_addr = (struct sockaddr_in *) res->ai_addr;
   
   


   // -----------------------------------Create a TCP socket ----------------------------------
   int sockfd= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

   // Fill in the destination information (IP, port #, and family)
   server_addr->sin_port   = htons (port);
   server_addr->sin_family = AF_INET;

   // Connect to the destination
   connect(sockfd, (struct sockaddr*) server_addr,
           sizeof(*server_addr));

   return sockfd;
}
void sendOrRecData(int sockfd,int tunfd, SSL *ssl){
  printf("Connected to VPN successfully!!!!!\n");
	while(1){
		fd_set set;
		// FD_ZERO(&set); 将set清零使集合中不含任何fd
		FD_ZERO(&set);
		//将 sockfd 加入set集合
		FD_SET(sockfd, &set);
		//将 tunfd 加入set集合
		FD_SET(tunfd, &set);
		//测试指定的fd 是否 可读
		select(FD_SETSIZE,&set, NULL, NULL, NULL);
		//测试tunfd是否在set集合中
		if(FD_ISSET(tunfd, &set)){
			tunSelected(tunfd, sockfd, ssl);

		}
		//测试 sockfd 是否在set集合中
		if(FD_ISSET(sockfd, &set)){
			socketSelected(tunfd, sockfd, ssl);

		}
		//usleep(10000000);
	}



}



int main(int argc, char *argv[])
{
   int tunfd, sockfd;
   //Initialize TUN inferface
   tunfd  = createTunDevice();
   // hard code for the hostname; default hostname and port number
   char *hostname = "liang.com";
   int port = 4433;
   // we can also set the host name from the command line
   if (argc > 1) hostname = argv[1];
   if (argc > 2) port = atoi(argv[2]);

   /*----------------TLS initialization ----------------*/
   SSL *ssl   = setupTLSClient(hostname);

   /*----------------Create a TCP connection ---------------*/
   sockfd = setupTCPClient(hostname, port);

   /*----------------TLS handshake ---------------------*/
   //connect SSL and TCP
   SSL_set_fd(ssl, sockfd);
   int err = SSL_connect(ssl); CHK_SSL(err);
   printf("SSL connection is successful\n");
   printf ("SSL connection using %s\n", SSL_get_cipher(ssl));

   //type user name and password to the server:
   send_User_PSW(ssl);


   /*----------------Send/Receive data --------------------*/

   sendOrRecData(sockfd, tunfd, ssl);


   return 0;
  
}
















