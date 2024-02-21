#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <ctype.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

void handle_https_request(SSL* ssl)
{
	FILE *fp;
    if (SSL_accept(ssl) == -1){
		perror("SSL_accept failed");
		exit(1);
	}
    else{
		char buf[1024] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf));
		if (bytes < 0) {
			perror("SSL_read failed");
			exit(1);
		}
        //
        else{
            char string[1024];
            int i, k = 0;
            for( i = 5; buf[i] != ' ';){
                string[k] = buf[i];
                i++;
                k++;
            }
            string[k] = '\0';
            fp = fopen(string,"rb");
            if(fp == NULL){
                const char* response="HTTP/1.0 404 Not Found\r\n";
                SSL_write(ssl, response, strlen(response));
            }
            else{
                int find = 0;
                int l;
                for(i = 0; buf[i]!='\n';i++);
                i++;
                char lines[1024];
                char buf_206_range[1024];
                while( !(buf[i]=='\r' && buf[i + 1]=='\n' && buf[i + 2]=='\r' && buf[i+ 3] == '\n')){
                    for(k = 0; buf[i]!=':';k++,i++){
                        lines[k] = buf[i];
                    }
                    l = 0;
                    for(; buf[i]!='\r';i++){
                        buf_206_range[l] = buf[i];
                        l++;
                    }
                    buf_206_range[l]='\0';
                    if(strstr(lines,"Range")!=NULL){
                        find = 1;
                        break;
                    }
                }

                if(find == 1){
                    int start,end;
                    for(i = 0; isdigit(buf_206_range[i]) == 0;i++);
                    start = atoi(&buf_206_range[i]);
                    
                    long int len;
                    for(i = 0; buf_206_range[i] !='-';i++);
                    if( isdigit(buf_206_range[i + 1]) != 0){
                        end = atoi(&buf_206_range[i + 1]);
                        len = end - start + 1;
                        
                    }
                    else{
                        fseek(fp,0,SEEK_END);
                        end = ftell(fp);
                        len = end - start + 1;
                    }

                    char* response;
                    response = (char *)malloc(len*sizeof(char) + 1024);
                    sprintf(response,"HTTP/1.0 206 Partial Content\r\nContent-Length: %ld\r\n\r\n",len);
                    
                    fseek(fp,start,SEEK_SET);
                    int compare_len;
                    while(feof(fp)== 0 &&  len > 0){
                        char buf_206[1025]={0};
                        compare_len = len > 1024? 1024 : len;
                        fread(buf_206,1,compare_len,fp); 
                        strcat(response,buf_206);
                        len = len - compare_len;
                    }
                    SSL_write(ssl, response, strlen(response));
                }
                else{
                    char* response;
                    int start,end;
                    long int len;
                    fseek(fp,0,SEEK_END);
                    end = ftell(fp);
                    fseek(fp,0,SEEK_SET);
                    start = ftell(fp);
                    len = end - start;
                    response = (char *)malloc(len*sizeof(char) + 1024);
                    sprintf(response,"HTTP/1.0 200 Partial Content\r\nContent-Length: %ld\r\n\r\n",len);
                    while(feof(fp) == 0){
                        char buf_200[1025] = {0};
                        fread(buf_200,1,1024,fp);
                        strcat(response,buf_200);
                    }
                    SSL_write(ssl, response, strlen(response));
                }
               fclose(fp); 
            } 
        }   
    }
    
    int sock = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sock);
}

void handle_http_request(void)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

    struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(80);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
	listen(sock, 10);
    while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
        // 这里开始添加
        char buf[1024] = {0};
        int bytes = recv(csock, buf, sizeof(buf),0);
        if (bytes < 0) {
            perror("receive failed");
            exit(1);
        }
        else{
            char string[1024];
            int i, k = 0;
            for( i = 5; buf[i] != ' ';){
                string[k] = buf[i];
                i++;
                k++;
            }
            string[k] = '\0';

            char buf_301[1024]="Location: https://10.0.0.1/";
            strcat(buf_301,string);

            char *response;
            response = (char *)malloc(1024*2 + strlen(string));
            char buf_301_format[1024]="\r\n\r\n";
            sprintf(response,"HTTP/1.0 301 Moved Permanently\r\nContent-Length: 0\r\n");
            strcat(response,buf_301);
            strcat(response,buf_301_format);
            int send_http=send(csock,response,strlen(response),0);
            if(send_http < 0){
                perror("send failed");
                exit(1);
            }
        }	
	}
    close(sock);
}

void https(void)
{
	// init SSL Library
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

	// enable TLS method
	const SSL_METHOD *method = TLS_server_method();
	SSL_CTX *ctx = SSL_CTX_new(method);

	// load certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, "./keys/cnlab.cert", SSL_FILETYPE_PEM) <= 0) {
		perror("load cert failed");
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "./keys/cnlab.prikey", SSL_FILETYPE_PEM) <= 0) {
		perror("load prikey failed");
		exit(1);
	}

	// init socket, listening to port 443
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("Opening socket failed");
		exit(1);
	}
	int enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		perror("setsockopt(SO_REUSEADDR) failed");
		exit(1);
	}

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(443);

	if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Bind failed");
		exit(1);
	}
	listen(sock, 10);

	while (1) {
		struct sockaddr_in caddr;
		socklen_t len;
		int csock = accept(sock, (struct sockaddr*)&caddr, &len);
		if (csock < 0) {
			perror("Accept failed");
			exit(1);
		}
		SSL *ssl = SSL_new(ctx); 
		SSL_set_fd(ssl, csock);
		handle_https_request(ssl);
	}

	close(sock);
	SSL_CTX_free(ctx);
}


int main(){
    pthread_t thread443,thread80;
    pthread_create(&thread443,NULL,https,NULL);
    pthread_create(&thread80,NULL,handle_http_request,NULL);
    pthread_join(thread443,NULL);
    pthread_join(thread80,NULL);
    return 0;
}