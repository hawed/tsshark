/*
    Copyright (C) 2012  hawed

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef _BAT_H_
#define _BAT_H_

#include "si_table.h"

typedef struct
{
  int transport_stream_id;
  int original_network_id;

  int transport_descriptors_length;
  char *pDescriptorDataTransport; //ptr to section buffer -> use descriptor_parser!! TODO

}TS_BAT_TRANSPORT_STREAM;


typedef struct 
{
  TS_SI_TABLE_SECTION stSection;
  
  int bouquet_descriptors_length;
  char *pDescriptorDataBouquet; //ptr to section buffer -> use descriptor_parser!! TODO

  int transport_stream_loop_length;

  int private_iTransportStreamLen; //private var
  TS_BAT_TRANSPORT_STREAM  *pastTransportStream; 

  unsigned long CRC;

}TS_BAT;

#endif
