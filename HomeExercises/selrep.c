#include <signal.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>

#define N 5

struct packet{
int is_acked;
int timeout;
} win[2*N];
int winstart;

/* Asynchronous I/O ---> I/O handler and asynchronous Sockets
   Support for timeout ----> Timer setting and Timer handler
   Non blocking I/O ---> polling file descriptors

         main: initialization and runs the application
   myio: handles the packet receving
   mytimer: handles the timeouts

   */
sigset_t mask;
int seconds;
void mytimer(int num)
{
int i;
seconds ++;
printf("Timer Call: %d\n",seconds);
for(i=winstart; i<winstart + N; i++)
        if((!win[i%(2*N)].is_acked) && (win[i%(2*N)].timeout<=seconds)){
                printf("Timer Handler: Send Packet %d\n",i);
                win[i%(2*N)].timeout = seconds + 4;
        }
}

void myio(int num){
int t,i;
int ack_no;
char buffer[101];
struct pollfd fd[1];
fd[0].fd=0;
fd[0].events = POLLIN;
fd[0].revents = 0;
printf("I/O called\n");
if (-1 == poll(fd,1,0)) {perror("poll error"); return ;}
if (fd[0].revents == POLLIN){
        for(i=0;(t=read(fd[0].fd,buffer+i,100-i))>0; i+=t){}
        if (t == -1 && (errno!=EAGAIN) ) perror("read");
        buffer[i]=0;
        sscanf(buffer, "%d",&ack_no);
        printf("Acked: %d\n",ack_no);
        if(ack_no >= winstart && ack_no< winstart + N){
                win[ack_no % ( 2*N )].is_acked=1;
        for(i=winstart; i<winstart + N && win[i%(2*N)].is_acked ; i++){
                        win[(i+N)%(2*N)].is_acked=0;
                        win[(i+N)%(2*N)].timeout = seconds + 4;
                        printf("I/O Handler: sending packet %d\n",i+N);
                        }
                winstart = i;
                }
}
}
struct sigaction sa_io, sa_timer;
int main(){
struct itimerval ti;


int s = 0;
int flags;
flags = fcntl(s,F_SETOWN, getpid());
flags = fcntl(s,F_GETFL);
if (flags==-1) { perror("fcntl-F_GETFL"); return 1;}
flags = fcntl(s,F_SETFL, flags | O_ASYNC | O_NONBLOCK);
if (flags==-1) { perror("fcntl-F_SETFL"); return 1;}
sa_io.sa_handler = myio;

sa_timer.sa_handler = mytimer;

ti.it_interval.tv_sec = 1;
ti.it_interval.tv_usec = 0;
ti.it_value.tv_sec = 1;
ti.it_value.tv_usec = 0;
setitimer(ITIMER_REAL,&ti, NULL);

if (-1 == sigaction(SIGIO, &sa_io, NULL)){perror("Sigaction SIGIO error"); return 1;}
if (-1 == sigaction(SIGALRM, &sa_timer, NULL)){perror("Sigaction SIGALRM error"); return 1;}
if (-1 == sigemptyset(&mask)) {perror("Sigemptyset error"); return 1;}
if (-1 == sigaddset(&mask,SIGIO)){perror("Sigaddset SIGIO error"); return 1;}
if (-1 == sigaddset(&mask,SIGALRM)){perror("Sigaddset SIGALRM error"); return 1;}
if (-1 == sigprocmask(SIG_UNBLOCK,&mask,NULL)){perror("Sigprocmask err"); return 1;}

while (1) { sleep(1000);}

}