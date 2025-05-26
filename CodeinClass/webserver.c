#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

int tmp;


int main()
{
struct sockaddr_in addr,remote_addr;
int i,j,k,s,t,s2,len;
int c;
FILE * fin;
int yes=1;
char * method, *path, *ver;
char request[5000],response[10000];
s =  socket(AF_INET, SOCK_STREAM, 0);
if ( s == -1 ){ perror("Socket Failed"); return 1; }
addr.sin_family = AF_INET;
addr.sin_port = htons(8033);
addr.sin_addr.s_addr = 0;
t= setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(int));
if (t==-1){perror("setsockopt Failed"); return 1;}
if ( bind(s,(struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) {perror("bind Failed"); return 1;}
if ( listen(s,5) == -1 ) { perror("Listen Fallita"); return 1; }
len = sizeof(struct sockaddr_in);
while(1){
s2 =  accept(s, (struct sockaddr *)&remote_addr,&len);
if ( s2 == -1 ) { perror("Accept Failed"); return 1;}
t = read(s2,request,4999);
if ( t == -1 ) { perror("Read Failed"); return 1;}
request[t]=0;
printf("%s",request);
method = request;
for(i=0;request[i]!=' ';i++){} request[i]=0; path = request+i+1;
for(i++;request[i]!=' ';i++); request[i]=0; ver = request+i+1;
for(i++;request[i]!='\r';i++); request[i]=0;
printf("method=%s path=%s ver=%s\n",method,path,ver);
if ((fin = fopen(path+1,"rt"))==NULL){
        sprintf(response,"HTTP/1.1 404 Not Found\r\n\r\n");
        write(s2,response,strlen(response));
        }
else {
                        sprintf(response,"HTTP/1.1 200 OK\r\n\r\n");
                        write(s2,response,strlen(response));
                        while ( (c = fgetc(fin)) != EOF )
                                write(s2,&c,1);
                        fclose(fin);
                }
                        close(s2);
}
}