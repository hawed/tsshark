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

#ifndef _TS_PARSER_H_
#define _TS_PARSER_H_

typedef enum 
{
  eTS_PARSER_OK,
  eTS_PARSER_INCOMPLETE,
  eTS_PARSER_FINISHED,
  eTS_PARSER_ERROR
}TE_TS_PARSER_RC;

typedef struct
{
  int transport_error_indicator;
  int payload_unit_start_indicator;
  int transport_priority;
  int PID;
  int transport_scrambling_control;
  int adaption_field_control;
  int continuity_counter;
}TS_PACKET_HEADER;

typedef struct 
{
  int adaptation_field_len;

  /* adaptation field flags*/
  int discontinuity_indicator;
  int random_access_indicator;
  int elemtary_stream_priority_indicator;
  int PCR_flag;
  int OPCR_flag;
  int splicing_point_flag;
  int transport_private_data_flag;
  int adaptation_field_extension_flag;

  /* if PCR flag == 1 */
  long int program_clock_reference_base;
  int program_clock_reference_extension;
  
  /* if OPCR flag == 1 */
  long int original_program_clock_reference_base;
  int original_program_clock_reference_extension;

  /* if splicing_point_flag == 1 */
  int splice_countdown;
  
  /* if transport_private_data_flag == 1 */
  int transport_private_data_length;
  char *ptr_transport_private_data;

  /* if adaptation_field_extension_flag == 1 */
  int adaptation_field_extension_len;

  /* adaptation_field_extension flags */
  int ltw_flag;
  int piecewise_rate_flag;
  int seamless_splice_flag;

  /* if ltw_flag == 1 */
  int ltw_valid_flag;
  int ltw_offset;

  /* if piecewise_rate_flag == 1 */
  int piecewise_rate;
    
  /* if seamless_splice_flag == 1 */
  int splice_type;
  long int DTS_next_AU;
  
}TS_PACKET_ADAPTATION_FIELD;

typedef struct
{
  TS_PACKET_HEADER stHeader;  
  TS_PACKET_ADAPTATION_FIELD stAdaptation;
  int iValidAdaptation;
  char *pabPayload; //ptr to pabInputBuffer !!except:  the last packet was an incomplete packet -> then it's parser memory !! 
  int iPayloadLen;
}TS_PACKET_DATA;

typedef int T_TS_PARSER_HANDLE;
#define TS_PARSER_INVALID (T_TS_PARSER_HANDLE)-1

#define TS_PACKET_SIZE 188

TE_TS_PARSER_RC  ts_parser_e_create(T_TS_PARSER_HANDLE  *pHandle);
TE_TS_PARSER_RC  ts_parser_e_destroy(T_TS_PARSER_HANDLE  tHandle);


/*
**  returns OK  packet parse successfull
**  returns INCOMPLETE if an uncomplete packet was found at the end of pabInputBuf
**                a following parse call will get the packet data if a new buffer is attached
**  returns FINSIHED if buffer was parsed complete
*/
TE_TS_PARSER_RC  ts_parser_e_parse(T_TS_PARSER_HANDLE  tHandle, 
                                                                      char* pabInputBuffer, 
                                                                      unsigned long uwBufferLen,  
                                                                      int iReset,
                                                                      TS_PACKET_DATA *pstParseResult );


#endif
