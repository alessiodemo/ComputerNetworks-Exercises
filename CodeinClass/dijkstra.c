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

int iterations =0;
int main()
{
unsigned char i,dest,min,pivot;
for(dest=0;dest<N;dest++){ // Fore each destination
	printf("==== dest %d ====\n",dest);
	for(i=0;i<N;i++){ // Inizialization
		node[i].ctg[dest]=(i==dest)?0:INF;
		node[i].nxt[dest]= i;
		node[i].st = TBP;
		}
	pivot = 0;
	while(pivot!=INF){
		min = pivot = INF;
		for(i=0;i<N;i++) if(node[i].st) // For each node to be processed
				if (node[i].ctg[dest]<min){ 
					min = node[i].ctg[dest]; // Find the minimum cost to go
					pivot = i;
					}
		printf("Selected Pivot: %d\n",pivot);
		node[pivot].st = !TBP; // Remove the pivot from the nodes to be processed
		for(i=0;i<N;i++) if(node[i].st==TBP) // For each node to be processed
			if(adj[i][pivot]){ // if adjacent to the Pivot
				iterations ++;
				if (node[i].ctg[dest]>adj[i][pivot]+node[pivot].ctg[dest]){
					node[i].ctg[dest]=adj[i][pivot]+node[pivot].ctg[dest];
					node[i].nxt[dest]=pivot;
					printf("    Improving Cost to go of node %d = %d\n",i,node[i].ctg[dest]);
					}
		}
		}
}
for(i=0;i<N;i++){
	printf("\nRouting Table of node %d\n",i);
	for(dest=0;dest<N;dest++)
		printf("	to %d: %d (ctg=%d)\n",dest,node[i].nxt[dest],node[i].ctg[dest]);
}				
printf("Iterations: %d\n", iterations);
}
