
// Copyright Antonio Barbalace, SSRG, VT, 2012
//#include <linux/if.h>
#include <net/if.h>
#include <linux/if_tun.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sched.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>
/* 
 * Allocate TUN device, returns opened fd. 
 * Stores dev name in the first arg(must be large enough).
 */  
static int tun_open_common0(char *dev, int istun)
{
    char tunname[14];
    int i, fd, err;

    if( *dev ) {
       sprintf(tunname, "/dev/%s", dev);
       printf("Opening /dev/%s\n", tunname);
       return open(tunname, O_RDWR);
    }

    sprintf(tunname, "/dev/%s", istun ? "tun" : "tap");
    err = 0;
    for(i=0; i < 255; i++){
       sprintf(tunname + 8, "%d", i);
       /* Open device */
       if( (fd=open(tunname, O_RDWR)) > 0 ) {
          strcpy(dev, tunname + 5);
          return fd;
       }
       else if (errno != ENOENT)
          err = errno;
       else if (i)	/* don't try all 256 devices */
          break;
    }
    if (err)
	errno = err;
    return -2;
}

//#ifdef HAVE_LINUX_IF_TUN_H /* New driver support */
//#include <linux/if_tun.h>

#ifndef OTUNSETNOCSUM
/* pre 2.4.6 compatibility */
#define OTUNSETNOCSUM  (('T'<< 8) | 200) 
#define OTUNSETDEBUG   (('T'<< 8) | 201) 
#define OTUNSETIFF     (('T'<< 8) | 202) 
#define OTUNSETPERSIST (('T'<< 8) | 203) 
#define OTUNSETOWNER   (('T'<< 8) | 204)
#endif

static int tun_open_common(char *dev, int istun)
{
    struct ifreq ifr;
    int fd;

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
       return tun_open_common0(dev, istun);

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = (istun ? IFF_TUN : IFF_TAP) | IFF_NO_PI;
    if (*dev)
       strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, (void *) &ifr) < 0) {
       if (errno == EBADFD) {
	  /* Try old ioctl */
 	  if (ioctl(fd, OTUNSETIFF, (void *) &ifr) < 0) 
	     goto failed;
       } else
          goto failed;
    } 

    strcpy(dev, ifr.ifr_name);
    return fd;

failed:
    close(fd);
    return -1;
}



#define DEBUGF 
//#define DEBUGF logging

static inline int logging( const char namefmt[], ...) {
//  printf(args);
return 0;
}

#define MAX_IP 64
#define MAX_VERBOSE 0x8000
#define MAX_BUFFER 0x1000
#define MAGIC_NUMBER 0xA5A5C3C3
#define STATUS_CON 0x12345678
#define STATUS_DISCON 0x87654321

typedef struct ip_tunnel {
  int magic;
  int status;
  int lock;
  int i;
  char buffer [MAX_BUFFER];
} ip_tunnel_t;


static ip_tunnel_t * open_shm(void* addr, int me) {
  int mem_fd;
  void* physical;  
  ip_tunnel_t * tun_area;
  
  mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (mem_fd < 0) {
    perror("open /dev/mem error");
    exit(0);
  }

long delta = sysconf(_SC_PAGE_SIZE);
 
printf("mmap(%p, %ld, 0x%x, 0x%x, %d, 0x%lx)\n",
  (void*) 0, (sizeof(ip_tunnel_t) * MAX_IP), PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, (unsigned long)addr); 
  //(void*) 0, (delta * 4), PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, (off_t)addr); 
  physical = mmap(0, (sizeof(ip_tunnel_t) * MAX_IP), PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, (off_t)(unsigned long)addr);
  //physical = mmap(0, delta * 4, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, (off_t)addr);
  printf("base address %p\n", physical);
  if (physical == -1) {
    perror("mmap");
    exit(0);
  }
  
  tun_area = (ip_tunnel_t *)physical;
  tun_area[me].i = 0;
  tun_area[me].magic = MAGIC_NUMBER;
  tun_area[me].lock = 0; // lock is for multi writer
    
  return tun_area;
}

//#else

//# define tun_open_common(dev, type) tun_open_common0(dev, type)

//#endif /* New driver support */

int tun_open(char *dev) { return tun_open_common(dev, 1); }
int tap_open(char *dev) { return tun_open_common(dev, 0); }

int tun_close(int fd, char *dev) { return close(fd); }
int tap_close(int fd, char *dev) { return close(fd); }

/* Read/write frames from TUN device */
int tun_write(int fd, char *buf, int len) { return write(fd, buf, len); }
int tap_write(int fd, char *buf, int len) { return write(fd, buf, len); }

int tun_read(int fd, char *buf, int len) { return read(fd, buf, len); }
int tap_read(int fd, char *buf, int len) { return read(fd, buf, len); }

int stop =0;



typedef struct __tun{
  int recv_from;
  int send_to;
} tunnel;

typedef struct __popcorn{
  int fd;
  int cpu;
  ip_tunnel_t * addr;
} popcorn;

void  * loop(void * arg) {
  int byte = 0; 
  tunnel * tuna = (tunnel *) arg;
  char * buffer = malloc(MAX_BUFFER);
  int  fd_read =tuna->recv_from;
  int  fd_write =tuna->send_to;
  
  printf("BEGIN THREAD read %d write %d\n", fd_read, fd_write);
  
  while(!stop){
    if (byte = tun_read(fd_read, buffer, MAX_BUFFER)) {
	    printf("%d -> %d bytes %d from %d.%d.%d.%d to %d.%d.%d.%d\n",
		   fd_read, fd_write, byte,
		   (int) buffer[12], (int) buffer[13], (int) buffer[14], (int) buffer[15],
		   (int) buffer[16], (int) buffer[17], (int) buffer[18], (int) buffer[19]
		  );
	    tun_write(fd_write, buffer, byte);
    }
  }
}

struct timespec sleep_send = {0, 50000000}; //50ms
void  * pop_send(void * arg) {
  int byte = 0; 
  popcorn * pp =  (popcorn *) arg;
  ip_tunnel_t * my_buf = 0;

  char * buffer = malloc(MAX_BUFFER);
  int  fd =pp->fd;
  int l=0; // verbose suppression code
  
  printf("BEGIN THREAD SEND id %d\n", fd);
  
  while(!stop){
    if (byte = tun_read(fd, buffer, MAX_BUFFER)) {
	    DEBUGF("SEND bytes %d from %d.%d.%d.%d to %d.%d.%d.%d\n",
		   byte,
		   (int) buffer[12], (int) buffer[13], (int) buffer[14], (int) buffer[15],
		   (int) buffer[16], (int) buffer[17], (int) buffer[18], (int) buffer[19]
		  );
           // check IP address - not on this network
           if ( !((buffer[19]-1) < MAX_IP) ) {
             DEBUGF("PACKET DROP ip (.%d) is greater the MAX_IP (%d)\n",
               (buffer[19]), MAX_IP );
            continue;
           }

	   my_buf = &((pp->addr)[(buffer[19]-1)]);
	   
	   // check magic number
/*	   if (my_buf->magic != MAGIC_NUMBER) {
	     DEBUGF("PACKET DROP magic number not present @ %p is 0x%x (remote id is %d)\n",
	       my_buf, my_buf->magic, (buffer[19]-1) );
            continue;
           }*/
	   
	   int i;
_mimmo:
	  for(i = 0; i< 0x1000; i++)
	    if (my_buf->i == 0)
	      break;
	  
	  if (i == 0x1000) {
	    if ( !(l++%MAX_VERBOSE) )
		DEBUGF("remote .%d (%d.%d.%d.%d) id not ready to accept data - i is %d\n",
		   (buffer[19]-1),
		   (int) buffer[16], (int) buffer[17], (int) buffer[18], (int) buffer[19],
		   my_buf->i
		  );
	    sched_yield();
	    //nanosleep(&sleep_send, 0);
	    goto _mimmo;
	  }

	if ( __sync_lock_test_and_set (&(my_buf->lock), 1) == 1 )
	  goto _mimmo;

	   memcpy(my_buf->buffer, buffer, byte);
	   my_buf->i = byte;
           my_buf->lock = 0;
    }
  }
}
struct timespec sleep_recv = {0, 100000000}; // 100ms
void  * pop_recv(void * arg) {
  int byte = 0; 
  popcorn * pp =  (popcorn *) arg;
  ip_tunnel_t * my_buf = &((pp->addr)[pp->cpu]);
  
  char * buffer;
  int  fd =pp->fd;
  int l=0; // verbose suppression code
  
  my_buf->status = STATUS_CON;
  printf("BEGIN THREAD RECV id %d (cpuid %d)\n", fd, pp->cpu);
  
  while(!stop){
        int i;
	for(i = 0; i< 0x1000; i++)
	  if (my_buf->i != 0)
	    break;
	 
	if (i == 0x1000) {
	  if (!(l++%MAX_VERBOSE))
	    DEBUGF("local .%d no data to recv - i is %d\n",
		   (pp->cpu +1),
		   my_buf->i
		  );
	    //nanosleep(&sleep_recv, 0);
	    sched_yield();
	    continue;
	}
	
	// check magic number
	   if (my_buf->magic != MAGIC_NUMBER)
	     DEBUGF("magic number not present @ %p is 0x%x (local id is %d)\n",
	       my_buf, my_buf->magic, pp->cpu
	    );
	
	buffer = my_buf->buffer;
	byte = my_buf->i;
	DEBUGF("RECV bytes %d from %d.%d.%d.%d to %d.%d.%d.%d\n",
		   byte,
		   (int) buffer[12], (int) buffer[13], (int) buffer[14], (int) buffer[15],
		   (int) buffer[16], (int) buffer[17], (int) buffer[18], (int) buffer[19]
		  );
	tun_write(fd, buffer, byte);
	my_buf->i = 0;    
  }
  my_buf->magic = 0; // this is temporary in the meanwhile we will implement status
  my_buf->status = STATUS_DISCON;
}

void dump(ip_tunnel_t *data, int max) {
  int i;
  int mem_fd;
  void* physical;  
  ip_tunnel_t * tun_area;
  
  mem_fd = open("/dev/mem", O_RDWR | O_SYNC);
  if (mem_fd < 0) {
    perror("open /dev/mem error");
    exit(0);
  }

long delta = sysconf(_SC_PAGE_SIZE);

#ifdef HTML
printf("<div><h2 style=\"display:block;margin-left:auto;margin-right:auto;width:50%;text-align:center\">Popcorn Kernel Status</h2>\n");
#endif
 
printf("mmap(%p, %ld, 0x%x, 0x%x, %d, 0x%lx)\n",
  (void*) 0, (sizeof(ip_tunnel_t) * MAX_IP), PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, (unsigned long)data); 
  //(void*) 0, (delta * 4), PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, (off_t)addr); 
  physical = mmap(0, (sizeof(ip_tunnel_t) * MAX_IP), PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, (off_t)data);
  //physical = mmap(0, delta * 4, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd, (off_t)addr);
  printf("base address %p\n", physical);
  if (physical == -1) {
    perror("mmap");
    exit(0);
  }

#ifdef HTML
printf("<table style=\"width:50%;height:50%;margin-left:auto;margin-right:auto\"><tr>\n");
#endif

  data = physical;
  for (i=0; i<max; i++) {
#ifdef HTML
printf("<td><div style=\"background-color:%s;height:70px\">%d</div></td>\n",
	(data[i].magic == 0xa5a5c3c3) ? "green":"red", i);
if ((i != 0) && ((i+1)%8 == 0))
  printf("</tr><tr>\n");
#else
    printf("%d: m:%x s:%s l:%d i:%d\n", i,
	   data[i].magic,
	   (data[i].status == STATUS_CON) ? "conn" : (data[i].status == STATUS_DISCON) ? "deco" : "none",
	   data[i].lock,
	   data[i].i);
#endif
 }
#ifdef HTML
  printf("</table></div>\n");
#endif
}

int main (int argc, char * argv [] ) {
#ifdef TEST 
  pthread_t tun0_thread, tun1_thread;
  char name0[32], name1[32];
  memset(name0, 0, 32);
  memset(name1, 0, 32);
  
  int tun0 = tun_open(name0);
  int tun1 = tun_open(name1);
  
  tunnel tun0_tun = {tun0, tun1};
  tunnel tun1_tun = {tun1, tun0};
#else
  pthread_t tun_send, tun_recv;
  char name[32];
  memset(name, 0, 32);
  
  if (argc == 2) {
  void * phy_addr;
  //sscanf(argv[1], "%x", &phy_addr);
  phy_addr = (void*)strtoul(argv[1], 0, 0);

  dump(phy_addr, MAX_IP);
    return;
  }
  
  int tun = tun_open(name);

  popcorn pp = {.fd = tun, .cpu = -1, .addr= 0};
#endif
  
  if (argc != 3)
    printf("usage: tun physical_addr cpuid\n");
  
  void * phy_addr;
  //sscanf(argv[1], "%x", &phy_addr);
  phy_addr = (void*)strtoul(argv[1], 0, 0);
  int cpuid = atoi(argv[2]);

  if ( !(cpuid < MAX_IP) ) {
    printf("ERROR cpuid (%d) greater then MAX_IP (%d)\n", cpuid, MAX_IP);
    exit(0);
  }

#ifndef TEST  
  printf("phy %p cpuid %d\n", phy_addr, cpuid);
  pp.cpu = cpuid;
  
  ip_tunnel_t * gigi = open_shm(phy_addr, cpuid);
  pp.addr = gigi;
  
  printf("tun %s (fd %d)\n", name, tun);
  
  pthread_create(&tun_send, 0, pop_send, &pp);
  pthread_create(&tun_recv, 0, pop_recv, &pp);
#else
  
  printf("tun 0 %s tun 1 %s\n", name0, name1);
  
  pthread_create(&tun0_thread, 0, loop, &tun0_tun);
  pthread_create(&tun1_thread, 0, loop, &tun1_tun);
#endif
 
while (1) { 
  sleep(1200);
}
  stop = 1;
  
#ifndef TEST
  pthread_join(tun_send, 0);
  pthread_join(tun_recv, 0);
#else
  pthread_join(tun0_thread, 0);
  pthread_join(tun1_thread, 0);
#endif  
  
  printf("threaded tunnel end\n");
  
  return 0;
}
