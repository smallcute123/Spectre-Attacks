/*

Calibrate L1 hit and L1 miss latency distribution

Usage: see README (step 1.1) in the top level 
Authors: Wenjie Xiong (wenjie.xiong@yale.edu) and Jakub Szefer (jakub.szefer@yale.edu)

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <immintrin.h>
#include <x86intrin.h>
#include <dlfcn.h>

const int line_size=64; // bytes
const int way_size=64*64/8; // in cache lines
int g_stride=8;//next set


char** probe;
char* chain_array[256*1024];//for pointer chasing chain
int perm[32]; //random permutation
void *gadget_module = NULL;

int histogram[2][200]={0};

int para_d=8;
int para_e=9;
void create_permutation(int size){
//  create random permutation of probe size in perm[]
//  To avoid prefetcher
	for(int i=0; i < size; i++){
		perm[i]=i;
	}

	for(int i=0; i < size; i++){
		int j = i + (rand()%(size-i));
		if(i!=j){
			int tmp=perm[i];
			perm[i]=perm[j];
			perm[j]=tmp;
		}
	
	}
}


char* create_chain(int stride, int offset, char* last){
//create pointer chasing chain in probe array with stride
// offset decides which set to start
	char** start = &chain_array[perm[0]*stride + offset];
    
	for(int i=0; i < 6; i++){
		chain_array[perm[i]*stride + offset]= (char*) (& chain_array[perm[i+1]*stride + offset]);
        printf("%p\t",&chain_array[perm[i+1]*stride + offset]);
	}
	chain_array[perm[6]*stride + offset] = last;
    
    printf("\n");
    void* temp=start, *temp2;
    for(int i=0; i < 8; i++){
        temp2 = (void*) *(void**)temp;
        printf("%llx, %llx\n",temp, temp2);
        temp=temp2;
    }
    printf("\n");
	return start;
}

unsigned long test_delay_1_set(char* start[], char* chain, int sec) {

  unsigned long t=0;
    
  //put the set into a random init LRU state
    
 for(int i = 0; i <20;i++)
  {
       asm __volatile__ (
       "movq (%%rcx),  %%rax     \n"
       "lfence              \n"
       "rdtsc               \n"
       : "=a" (t)
       : "c" (start[rand() %8+16]));
      
  }
    
    
  for(int i=0;i<para_d;i++){         
     asm __volatile__ (
       "movq (%%rcx),  %%rax     \n"
       "lfence              \n"
       "rdtsc               \n"
       : "=a" (t)
       : "c" (start[i]));
   }

   //sec = 1 will result in L1 hit, otherwise, L1 miss
   if(sec){ 
     asm __volatile__ (
       "movq (%%rcx),  %%rax     \n"
       "lfence              \n"
       "rdtsc               \n"
       : "=a" (t)
       : "c" (start[0]));
   }
        
   //load another line into the same set to evict the LRU line
    for(int i=para_d;i<para_e;i++){
     asm __volatile__ (
       "movq (%%rcx),  %%rax     \n"
       "lfence              \n"
       "rdtsc               \n"
       : "=a" (t)
       : "c" (start[i]));
    }
              

      //load the first 7 of the chain to L1
     asm __volatile__ (
       "movq (%%rcx),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "lfence              \n"
       "rdtsc               \n"
       : "=a" (t)
       : "c" (chain));
    
    //measure latency
         asm __volatile__ (
       "lfence              \n" 
       "rdtsc               \n"
       "movl %%eax, %%esi   \n"
       "movq (%%rcx),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "movq (%%rax),  %%rax     \n"
       "lfence              \n"
       "rdtsc               \n"
       "subl %%esi, %%eax   \n"
       : "=a" (t)
       : "c" (chain)
       : "%esi", "%edx");

    return t;
}



int main(int argc, char *argv[]) {
    
    
  if(argc >= 2){
          para_d=strtol(argv[1], NULL, 10);
          printf("parameter d=%d\n",para_d);
  }
  if(argc >= 3){
          para_e=strtol(argv[2], NULL, 10);
          printf("parameter e=%d\n",para_e);
      }   
  int test_cnt=10000;
  srand(1234);

  create_permutation(8);

  //dynamic load lib for probe array
  gadget_module = dlopen("/usr/lib/x86_64-linux-gnu/liblruattack.so.1.0.1",  RTLD_LAZY);
  probe= (char**)(dlsym(gadget_module,"_binary_pi_txt_start"));
  printf("%s",dlerror());
   
  probe = probe + 1024*sizeof(void*);
   
  char* start[24];
  for(int i=0;i< 8;i++){// 8 way cache
    start[perm[i]]=&probe[ i*way_size];
  }
  for(int i=8;i< 24;i++){
    start[i]=&probe[ i*way_size];
  }
  char * chain;
  chain = create_chain(g_stride, g_stride, start[0]);
    
    
  unsigned int t;
  //add dummy computation to make sure the data load into L1/L2 from memory
  for(int j= 0;j <100;j++){
      t=test_delay_1_set(start,chain,1);
      for (int i = 0; i < 100000; ++i){
            t+=i;
      } 
  }
  
  //calibration
  for(int i=0;i<test_cnt;i++){
    t=test_delay_1_set(start,chain,1);
    if(t<200){
        histogram[1][t]++;
    }
    else
        histogram[1][199]++; 
      
    t=test_delay_1_set(start,chain,0);
    if(t<200){
        histogram[0][t]++;
    }
    else
        histogram[0][199]++; 
  }
  
  printf("cycles\thit\tmiss\n");
  for(int i=0;i<200;i++){
        printf("%d\t%d\t%d\n", i, histogram[1][i], histogram[0][i]);   
  }
    
    
  return 0;
}
