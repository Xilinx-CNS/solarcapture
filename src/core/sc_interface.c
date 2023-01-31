/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"


void sc_interface_get(struct sc_interface** intf_out, struct sc_session* scs,
                      const char* interface_name)
{
  int i;

  for( i = 0; i < scs->tg_interfaces_n; ++i )
    if( ! strcmp(scs->tg_interfaces[i]->if_name, interface_name) ) {
      *intf_out = scs->tg_interfaces[i];
      return;
    }

  struct sc_interface* intf;
  SC_TEST(intf = calloc(1, sizeof(*intf)));
  intf->if_session = scs;
  intf->if_name = strdup(interface_name);
  SC_REALLOC(&scs->tg_interfaces, ++scs->tg_interfaces_n);
  scs->tg_interfaces[scs->tg_interfaces_n - 1] = intf;
  *intf_out = intf;
}


void sc_interface_free(struct sc_interface* intf)
{
  free(intf->if_name);
  free(intf);
}
