/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <pcap/pcap.h>


int main(int argc, char** argv)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  int rc;
  pcap_if_t* dev;

  rc = pcap_findalldevs(&dev, errbuf);
  printf("pcap_findalldevs rc=%d\n", rc);

  while( dev ) {
    printf("%s\n", dev->name);
    dev = dev->next;
  }

  return 0;
}
