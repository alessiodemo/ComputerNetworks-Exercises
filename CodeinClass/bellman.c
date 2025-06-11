#include<stdio.h>
#define N 6
#define INF 255
#define TBP 1
int adj[N][N]={  
	0,4,6,0,0,0, 
	4,0,8,6,8,0,
	6,8,0,0,1,0,
	0,6,0,0,7,1,
	0,8,1,7,0,3,
	0,0,0,1,3,0 };

struct node_data {
	unsigned char ctg[N];
	unsigned char nxt[N];
	unsigned char st;
} ;

struct  node_data node[N];
int iterations = 0;
int main()
{
unsigned char i,j, improvement, dest,min,pivot;
for(dest=0;dest<N;dest++){ // For each destination
	printf("==== dest %d ====\n",dest);
	for(i=0;i<N;i++){ // Inizialization
		node[i].ctg[dest]=(i==dest)?0:INF;
		node[i].nxt[dest]= i;
		node[i].st = TBP;
		}
	improvement= 1;
	while(improvement){
		improvement = 0;
		for(i=0;i<N;i++) // For each node
			for(j=0;j<N;j++) if(adj[i][j]){ // For each adjacent node
					iterations ++;
					if (node[i].ctg[dest]>adj[i][j]+node[j].ctg[dest]){
						node[i].ctg[dest] = adj[i][j]+node[j].ctg[dest];
						node[i].nxt[dest] = j;
					  printf("    Improving Cost to go of node %d = %d\n",i,node[i].ctg[dest]);
						improvement = 1;
			}
		}
	}
}	
for(i=0;i<N;i++){ // Printing routing tables
	printf("\nRouting Table of node %d\n",i);
	for(dest=0;dest<N;dest++)
		printf("	to %d: %d (ctg=%d)\n",dest,node[i].nxt[dest],node[i].ctg[dest]);
}				
printf("Iterations = %d\n",iterations);
}
