/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

pcap_t *sfsc_create(const char *, char *, int *);
int sfsc_findalldevs(pcap_if_t **devlistp, char *errbuf);
