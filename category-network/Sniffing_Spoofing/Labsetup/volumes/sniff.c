#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define u_char unsigned char

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    printf("got packet\n");
}

int main(){
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  char *dev;
  struct bpf_program fp;
  char filter_exp[] = "icmp";
  bpf_u_int32 net = 0;
  dev = pcap_lookupdev(errbuf);
  if(dev == NULL){
    fprintf(stderr, "Couldn't find default device:%s\n", errbuf);
  }

  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if(handle == NULL){
    fprintf(stderr, "Couldn't open default device %s: %s\n", dev, errbuf);
  }
  
  if(pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
    return 2;
  }

  pcap_compile(handle, &fp, filter_exp, 0, net);

  if(pcap_setfilter(handle, &fp) != 0){
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }

  pcap_loop(handle, -1, got_packet, NULL);
  pcap_close(handle);
  return 0;
}
