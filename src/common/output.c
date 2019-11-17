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

#include <stdio.h>
#include <string.h>

#include "pubh/output.h"
#include "pubh/si_parser.h"
#include "pubh/ts_parser.h"

#define TRACE_IF(x)          printf x         
#define TRACE_CALLS(x) printf x

#if 0 //TODO
#define TRACE_OUTPUT(level, x) {if (level==) nur levek 0 ... } anstelle von printf
#endif

#define TRACE_ERR printf("E: %s: %i\n", __FILE__,__LINE__); 

#define BYTETOBINARYPATTERN "%d%d%d%d%d%d%d%d"
#define BYTETOBINARY(byte)  \
  (byte & 0x80 ? 1 : 0), \
  (byte & 0x40 ? 1 : 0), \
  (byte & 0x20 ? 1 : 0), \
  (byte & 0x10 ? 1 : 0), \
  (byte & 0x08 ? 1 : 0), \
  (byte & 0x04 ? 1 : 0), \
  (byte & 0x02 ? 1 : 0), \
  (byte & 0x01 ? 1 : 0) 

#define COLUMN_1 "  |--"
#define COLUMN_2 "    |--"
#define COLUMN_3 "      |--"
#define CRITICAL "!!critical: "
#define CRITICAL_END "!!\n" 
#define RED "\033[31m"
#define COLOR_END "\033[0m"

static const char* _pidToStr(int pid);
static const char* _tidToStr(int tid);
static const char* _streamtypeToStr(int streamtype);
static void _hexOut(char* buf, int len);
static void _outputTableHeaderAndBody(TS_SI_TABLE_SECTION *pstTableHeader);


static int verbose = 2; //TODO output param - verbose printf MACRO!!

/*
** API
*/
const char* streamtypeToStr(int streamtype)
{
  return _streamtypeToStr(streamtype);
}

const char* pidToStr(int pid)
{
  return _pidToStr(pid);
}

const char* tidToStr(int tid)
{
  return _tidToStr(tid);
}

void hexOut(char* buf, int len)
{
  return _hexOut(buf,len);
}

void outputTs(void *pstParseResult /*,int iInfoLevel*/,  unsigned long uwPacketCount)
{
  TS_PACKET_DATA *pRes = NULL;
  
  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }
  
  pRes = (TS_PACKET_DATA*)pstParseResult; 

  printf("-- TS packet:[%lu] -- \n",uwPacketCount);
  printf(COLUMN_1"header: 4 Byte\n");
  if (verbose > 0)
  {
    printf(COLUMN_2"transport_error_indicator: 0x%x\n",pRes->stHeader.transport_error_indicator);
    printf(COLUMN_2"payload_unit_start_indicator: 0x%x\n",pRes->stHeader.payload_unit_start_indicator);
    printf(COLUMN_2"transport_priority: 0x%x\n",pRes->stHeader.transport_priority);
    printf(COLUMN_2"PID: 0x%x %s\n",pRes->stHeader.PID, _pidToStr(pRes->stHeader.PID));
    printf(COLUMN_2"transport_scrambling_control: 0x%x\n",pRes->stHeader.transport_scrambling_control);
    printf(COLUMN_2"adaption_field_control: 0x%x\n",pRes->stHeader.adaption_field_control);
    printf(COLUMN_2"continuity_counter: 0x%x\n",pRes->stHeader.continuity_counter);
  }

  if (pRes->iValidAdaptation == 1 )
  {
    printf(COLUMN_1"adaptation field: %i Byte\n", pRes->stAdaptation.adaptation_field_len);
    if (verbose > 0)
    {
      printf(COLUMN_2"adaptation_field_len: 0x%x\n",pRes->stAdaptation.adaptation_field_len);

      if (pRes->stAdaptation.adaptation_field_len <=  0)
      {
        printf(RED CRITICAL"adaptation_field_len: <= 0 but valid flag set"CRITICAL_END COLOR_END); 
      }
      else
      {
        printf(COLUMN_2"discontinuity_indicator: 0x%x\n",pRes->stAdaptation.discontinuity_indicator);
        printf(COLUMN_2"random_access_indicator: 0x%x\n",pRes->stAdaptation.random_access_indicator);
        printf(COLUMN_2"elemtary_stream_priority_indicator: 0x%x\n",pRes->stAdaptation.elemtary_stream_priority_indicator);
        printf(COLUMN_2"PCR_flag: 0x%x\n",pRes->stAdaptation.PCR_flag);
        printf(COLUMN_2"OPCR_flag: 0x%x\n",pRes->stAdaptation.OPCR_flag);
        printf(COLUMN_2"splicing_point_flag: 0x%x\n",pRes->stAdaptation.splicing_point_flag);
        printf(COLUMN_2"transport_private_data_flag: 0x%x\n",pRes->stAdaptation.transport_private_data_flag);
        printf(COLUMN_2"adaptation_field_extension_flag: 0x%x\n",pRes->stAdaptation.adaptation_field_extension_flag);

        if (pRes->stAdaptation.PCR_flag == 1)
        {
          printf(COLUMN_2"program_clock_reference_base: 0x%lx\n",pRes->stAdaptation.program_clock_reference_base);
          printf(COLUMN_2"program_clock_reference_extension: 0x%x\n",pRes->stAdaptation.program_clock_reference_extension);
        }

        if (pRes->stAdaptation.OPCR_flag == 1)
        {
          printf(COLUMN_2"original_program_clock_reference_base: 0x%lx\n",pRes->stAdaptation.original_program_clock_reference_base);
          printf(COLUMN_2"original_program_clock_reference_extension: 0x%x\n",pRes->stAdaptation.original_program_clock_reference_extension);
        }

        if (pRes->stAdaptation.splicing_point_flag == 1)
        {
          printf(COLUMN_2"splice_countdown: 0x%x\n",pRes->stAdaptation.splice_countdown);
        }

        if (pRes->stAdaptation.transport_private_data_flag == 1)
        {
          printf(COLUMN_2"transport_private_data_length: 0x%x\n",pRes->stAdaptation.transport_private_data_length);
          
          if((pRes->stAdaptation.ptr_transport_private_data != NULL) && 
             (pRes->stAdaptation.transport_private_data_length > 0))
          {
             //TODO: show payload
             printf(COLUMN_3"transport_private_data:\n");
          }
        }

        if (pRes->stAdaptation.adaptation_field_extension_flag == 1)
        {
          printf(COLUMN_2"adaptation_field_extension_len: 0x%x\n",pRes->stAdaptation.adaptation_field_extension_len);
          printf(COLUMN_2"ltw_flag: 0x%x\n",pRes->stAdaptation.ltw_flag);
          printf(COLUMN_2"piecewise_rate_flag: 0x%x\n",pRes->stAdaptation.piecewise_rate_flag);
          printf(COLUMN_2"seamless_splice_flag: 0x%x\n",pRes->stAdaptation.seamless_splice_flag);
          
          if (pRes->stAdaptation.ltw_flag == 1)
          {
            printf(COLUMN_2"ltw_valid_flag: 0x%x\n",pRes->stAdaptation.ltw_valid_flag);
            printf(COLUMN_2"ltw_offset: 0x%x\n",pRes->stAdaptation.ltw_offset);
          }

          if (pRes->stAdaptation.piecewise_rate_flag == 1)
          { 
            printf(COLUMN_2"piecewise_rate: 0x%x\n",pRes->stAdaptation.piecewise_rate);
          }

          if (pRes->stAdaptation.seamless_splice_flag == 1)
          {
            printf(COLUMN_2"DTS_next_AU: 0x%lx\n",pRes->stAdaptation.DTS_next_AU);
          }
        }//adaptation extension
      }//no error
    }//verbose
  }//adaptation valid

  printf(COLUMN_1"payload: %i Byte\n",(TS_PACKET_SIZE - 4 - pRes->stAdaptation.adaptation_field_len));

  if (verbose > 1)
  {
    if(pRes->iPayloadLen)
    {
      _hexOut(pRes->pabPayload, pRes->iPayloadLen);
    }
  }
}

void outputPAT(void *pstParseResult)
{
  int i = 0;
  TS_PAT *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }
  
  pRes = (TS_PAT*)pstParseResult; 

  printf("-- PAT -- \n" );

  _outputTableHeaderAndBody(&pRes->stSection);

  printf(COLUMN_1"program loop: %i Byte\n",  pRes->private_iProgramLoopLen * 4 /*byte per program*/ );
  for(i = 0; i < pRes->private_iProgramLoopLen;  i++)
  {
    printf(COLUMN_2"program_number: 0x%x (%i)\n",pRes->pastProgram[i].program_number,pRes->pastProgram[i].program_number);
    if(pRes->pastProgram[i].program_number == 0)
    {
      printf(COLUMN_2"network_PID: 0x%x (%i)\n",pRes->pastProgram[i].network_PID,pRes->pastProgram[i].network_PID);
    }
    else
    {
      printf(COLUMN_2"program_map_PID: 0x%x (%i)\n",pRes->pastProgram[i].program_map_PID,pRes->pastProgram[i].program_map_PID);
    }
    printf("\n");
  }
  printf(COLUMN_1"CRC: 0x%08x\n", (int)pRes->CRC);
}

void outputPMT(void *pstParseResult)
{
  int i = 0;
  TS_PMT *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }

  pRes = (TS_PMT*)pstParseResult; 

  printf("-- PMT -- \n" );

   _outputTableHeaderAndBody(&pRes->stSection);

  /*data*/
  printf(COLUMN_1"PCR_PID: 0x%02x (%i)\n",  pRes->PCR_PID,pRes->PCR_PID);
  printf(COLUMN_1"program_info_length: 0x%02x (%i)\n",  pRes->program_info_length, pRes->program_info_length);

  if(pRes->program_info_length != 0)
  {
    printf(COLUMN_2"descriptors:\n");
    _hexOut(pRes->pDescriptorDataProgramInfo, pRes->program_info_length);
  }

  printf(COLUMN_1"stream loop:\n");

  for(i = 0; i < pRes->private_iStreamLoopLen;  i++)
  {
    printf(COLUMN_2"stream_type: 0x%x (%s)\n",pRes->pastStream[i].stream_type , _streamtypeToStr(pRes->pastStream[i].stream_type));
    printf(COLUMN_2"elementary_PID: 0x%02x (%i)\n",pRes->pastStream[i].elementary_PID ,pRes->pastStream[i].elementary_PID);
    printf(COLUMN_2"ES_info_length: 0x%02x (%i)\n",pRes->pastStream[i].ES_info_length ,pRes->pastStream[i].ES_info_length);

    if(pRes->pastStream[i].ES_info_length != 0)
    {
      printf(COLUMN_3"descriptors:\n");
      _hexOut(pRes->pastStream[i].pDescriptorDataEsInfo,  pRes->pastStream[i].ES_info_length);
    }
    printf("\n");
  }
  printf(COLUMN_1"CRC: 0x%08x\n",  (int)pRes->CRC);

}

void outputCAT(void *pstParseResult)
{
  TS_CAT *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }

  pRes = (TS_CAT*)pstParseResult; 

  printf("-- CAT -- \n" );

   _outputTableHeaderAndBody(&pRes->stSection);

   /*data*/
   if(pRes->ca_info_length != 0)
   {
    printf(COLUMN_1"ca_info_descriptor: (%i Byte)\n",  pRes->ca_info_length);

    if(pRes->ca_info_length != 0)
    {
      printf(COLUMN_2"descriptors:\n");
      _hexOut(pRes->pDescriptorDataCA, pRes->ca_info_length);
    }
    printf("\n");
   }
   printf(COLUMN_1"CRC: 0x%08x\n", (int)pRes->CRC);
}

void outputNIT(void *pstParseResult)
{
  int i;
  TS_NIT *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }

  pRes = (TS_NIT*)pstParseResult; 

  printf("-- NIT -- \n" );

   _outputTableHeaderAndBody(&pRes->stSection);

  /*data*/
  printf(COLUMN_1"network_descriptors_length: 0x%03x (%i)\n",  pRes->network_descriptors_length, pRes->network_descriptors_length);
  if(pRes->network_descriptors_length != 0)
  {
     printf(COLUMN_2"descriptors:\n");
     _hexOut(pRes->pDescriptorDataNetwork, pRes->network_descriptors_length);
     printf("\n");
  }
  
  printf(COLUMN_1"transport_stream_loop_length: 0x%03x (%i)\n",  pRes->transport_stream_loop_length , pRes->transport_stream_loop_length);

  if(pRes->transport_stream_loop_length != 0)
  {
    printf(COLUMN_1"transport_stream_loop:\n");

    for(i = 0; i < pRes->private_iTransportStreamLen;  i++)
    {
      printf(COLUMN_2"transport_stream_id: 0x%04x (%i)\n",pRes->pastTransportStream[i].transport_stream_id , pRes->pastTransportStream[i].transport_stream_id);
      printf(COLUMN_2"original_network_id: 0x%04x (%i)\n",pRes->pastTransportStream[i].original_network_id,pRes->pastTransportStream[i].original_network_id);
      printf(COLUMN_2"transport_descriptors_length: 0x%04x (%i)\n",pRes->pastTransportStream[i].transport_descriptors_length, pRes->pastTransportStream[i].transport_descriptors_length);
    
      if(pRes->pastTransportStream[i].transport_descriptors_length != 0)
      {
        printf(COLUMN_3"descriptors:\n");
        _hexOut(pRes->pastTransportStream[i].pDescriptorDataTransport,  pRes->pastTransportStream[i].transport_descriptors_length);
      }
      printf("\n");
    }
  }

  printf(COLUMN_1"CRC: 0x%08x\n", (int) pRes->CRC);
}

void outputBAT(void *pstParseResult)
{
  int i = 0;
  TS_BAT *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }

  pRes = (TS_BAT*)pstParseResult; 

  printf("-- BAT -- \n" );

   _outputTableHeaderAndBody(&pRes->stSection);

  /*data*/
  printf(COLUMN_1"bouquet_descriptors_length: 0x%03x (%i)\n",  pRes->bouquet_descriptors_length, pRes->bouquet_descriptors_length);
  if(pRes->bouquet_descriptors_length != 0)
  {
     printf(COLUMN_2"descriptors:\n");
     _hexOut(pRes->pDescriptorDataBouquet, pRes->bouquet_descriptors_length);
     printf("\n");
  }
  
  printf(COLUMN_1"transport_stream_loop_length: 0x%03x (%i)\n",  pRes->transport_stream_loop_length , pRes->transport_stream_loop_length);

  if(pRes->transport_stream_loop_length != 0)
  {
    printf(COLUMN_1"transport_stream_loop:\n");

    for(i = 0; i < pRes->private_iTransportStreamLen;  i++)
    {
      printf(COLUMN_2"transport_stream_id: 0x%04x (%i)\n",pRes->pastTransportStream[i].transport_stream_id , pRes->pastTransportStream[i].transport_stream_id);
      printf(COLUMN_2"original_network_id: 0x%04x (%i)\n",pRes->pastTransportStream[i].original_network_id,pRes->pastTransportStream[i].original_network_id);
      printf(COLUMN_2"transport_descriptors_length: 0x%04x (%i)\n",pRes->pastTransportStream[i].transport_descriptors_length, pRes->pastTransportStream[i].transport_descriptors_length);
    
      if(pRes->pastTransportStream[i].transport_descriptors_length != 0)
      {
        printf(COLUMN_3"descriptors:\n");
        _hexOut(pRes->pastTransportStream[i].pDescriptorDataTransport,  pRes->pastTransportStream[i].transport_descriptors_length);
      }
      printf("\n");
    }
  }

  printf(COLUMN_1"CRC: 0x%08x\n",  (int)pRes->CRC);

}

void outputSDT(void *pstParseResult)
{
  int i = 0;
  TS_SDT *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }

  pRes = (TS_SDT*)pstParseResult; 

  printf("-- SDT -- \n" );

   _outputTableHeaderAndBody(&pRes->stSection);

  /*data*/
  printf(COLUMN_1"original_network_id: 0x%04x (%i)\n", pRes->original_network_id,  pRes->original_network_id);

  printf(COLUMN_1"service loop:\n");
  for(i = 0; i < pRes->private_iServiceLen;  i++)
  {
    printf(COLUMN_2"service_id: 0x%x (%i)\n",pRes->pastService[i].service_id, pRes->pastService[i].service_id);
    printf(COLUMN_2"EIT_schedule_flag: 0x%x\n",pRes->pastService[i].EIT_schedule_flag);
    printf(COLUMN_2"EIT_present_following_flag: 0x%x\n",pRes->pastService[i].EIT_present_following_flag);    
    printf(COLUMN_2"running_status: 0x%x\n",pRes->pastService[i].running_status);    
    printf(COLUMN_2"free_CA_mode: 0x%x\n",pRes->pastService[i].free_CA_mode);    
    printf(COLUMN_2"descriptors_loop_length: 0x%x (%i)\n",pRes->pastService[i].descriptors_loop_length, pRes->pastService[i].descriptors_loop_length);    

    if(pRes->pastService[i].descriptors_loop_length != 0)
    {
      printf(COLUMN_3"descriptors:\n");
      _hexOut(pRes->pastService[i].pDescriptorDataService,  pRes->pastService[i].descriptors_loop_length);
    }
    printf("\n");
  }
  printf(COLUMN_1"CRC: 0x%08x\n",  (int)pRes->CRC);
}

void outputEIT(void *pstParseResult)
{
  int i = 0;
  TS_EIT *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }

  pRes = (TS_EIT*)pstParseResult; 

  printf("-- SDT -- \n" );

 _outputTableHeaderAndBody(&pRes->stSection);

  /*data*/
  //...

}

void outputRST(void *pstParseResult)
{
  int i = 0;
  TS_RST *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }

  pRes = (TS_RST*)pstParseResult; 

  printf("-- RST -- \n" );

   _outputTableHeaderAndBody(&pRes->stSection);

   /*data*/
  //...

}

void outputTDT(void *pstParseResult)
{
  int i = 0;
  TS_TDT *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }

  pRes = (TS_TDT*)pstParseResult; 

  printf("-- TDT -- \n" );

   _outputTableHeaderAndBody(&pRes->stSection);

   /*data*/
  //...

}

void outputTOT(void *pstParseResult)
{
  int i = 0;
  TS_TOT *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }

  pRes = (TS_TOT*)pstParseResult; 

  printf("-- TOT -- \n" );

   _outputTableHeaderAndBody(&pRes->stSection);

  /*data*/
  //...

}

void outputST(void *pstParseResult)
{
  int i = 0;
  TS_ST *pRes = NULL;

  if(pstParseResult == NULL)
  {
    TRACE_ERR;
    return;
  }

  pRes = (TS_ST*)pstParseResult; 

  printf("-- ST -- \n" );

 _outputTableHeaderAndBody(&pRes->stSection);

  /*data*/
  //...

}


/*
* private
*/

static void _outputTableHeaderAndBody(TS_SI_TABLE_SECTION *pstSection)
{
  printf(COLUMN_1"ptr field: 1 Byte\n");
  printf(COLUMN_2"ptr: 0x%x\n", pstSection->cPointer);

  printf(COLUMN_1"table header: 4 Byte\n");
  printf(COLUMN_2"table_id: 0x%x %s\n",pstSection->stTableHeader.table_id, tidToStr(pstSection->stTableHeader.table_id));
  printf(COLUMN_2"section_syntax_indicator: 0x%x\n",pstSection->stTableHeader.section_syntax_indicator);
  printf(COLUMN_2"section_length: 0x%x (%i)\n",pstSection->stTableHeader.section_length,
         pstSection->stTableHeader.section_length);

  if(pstSection->stTableHeader.section_syntax_indicator == 1)
  {
    printf(COLUMN_1"table body: 5 Byte\n");
    printf(COLUMN_2"table_id_extension: 0x%x\n",pstSection->stTableBody.st_body_long.table_id_extension);
    printf(COLUMN_2"version_number: 0x%x\n",pstSection->stTableBody.st_body_long.version_number);
    printf(COLUMN_2"current_next_indicator: 0x%x\n",pstSection->stTableBody.st_body_long.current_next_indicator);
    printf(COLUMN_2"section_number: 0x%x\n",pstSection->stTableBody.st_body_long.section_number);
    printf(COLUMN_2"last_section_number: 0x%x\n",pstSection->stTableBody.st_body_long.last_section_number);
  }

}

static const char* _pidToStr(int pid)
{
  switch (pid)
  {
  case 0x0000: return "(PAT)";
  case 0x0001: return "(CAT)";
  case 0x0010: return "(NIT)";
  case 0x0011: return "(BAT,SDT)";
  case 0x0013: return "(RST)";
  case 0x0014: return "(TDT,TOT)";
  default: return "(NISCHT WISCHTCHESS)";
  }
}

static void _hexOut(char* buf, int len)
{
  int i,k;
  int j = 0;

  if((buf != NULL) && (len != 0))
  {
    for(i = 0; i < len ; i++)
    {
      printf("0x%02x ",(buf[i] & 0xff));
      j++;
      if(j == 16)
      {
        for(k = 0; (k < 16); k++ )
        {
          if(((buf[(i - j) + k] & 0xff) > 0x21) && ((buf[(i - j) + k] & 0xff) < 0x7e))
          {
            printf("%c", buf[(i - j) + k]);
          }
          else
          {
            printf("%s", ".");
          }
        }
        printf("\n");
        j = 0;
      }
    }

    printf("\n");
  }
}

static const char* _tidToStr(int tid)
{
  switch (tid)
  {
  case 0x00: return "(PAT)";
  case 0x01: return "(CAT)";
  case 0x02: return "(PMT)";
  case 0x40: return "(NIT)";
  case 0x41: return "(NIT)";
  case 0x4A: return "(BAT)";
  case 0x42: return "(SDT)";
  case 0x46: return "(SDT)";
  case 0x71: return "(RST)";
  case 0x70: return "(TDT)";
  case 0x73: return "(TOT)";
  case 0x72: return "(ST)";
  default: return "(NISCHTE)";
  }
}

static const char* _streamtypeToStr(int streamtype)
{
  switch(streamtype)
  {
case 0x1: return "ISO/IEC 11172 Video (MPEG-1)";
case 0x2: return "ITU-T Rec. H.262 | ISO/IEC 13818-2 (MPEG-2) Video or ISO/IEC 11172-2 (MPEG-1) constrained parameter video stream";
case 0x3: return "ISO/IEC 11172 Audio (MPEG-1)" ;
case 0x4: return "ISO/IEC 13818-3 Audio (MPEG-2)"; 
case 0x5: return "MPEG-2 private table sections";
case 0x6: return "MPEG-2 Packetized Elementary Stream packets containing private data";
case 0x7: return "MHEG Packets";
case 0x8: return "MPEG-2 Annex A DSM CC";
case 0x9: return "ITU-T Rec. H.222.1";
case 0xA: return "ISO/IEC 13818-6 DSM-CC type A";
case 0xB: return "ISO/IEC 13818-6 DSM-CC type B";
case 0xC: return "ISO/IEC 13818-6 DSM-CC type C";
case 0xD: return "ISO/IEC 13818-6 DSM-CC type D";
case 0xE: return "ISO/IEC 13818-1 (MPEG-2) auxiliary";
case 0xF: return "ISO/IEC 13818-7 Audio with ADTS transport syntax";
case 0x10: return "ISO/IEC 14496-2 (MPEG-4) Visual";
case 0x11: return "ISO/IEC 14496-3 Audio with the LATM transport syntax as defined in ISO/IEC 14496-3 / AMD 1";
case 0x12: return "ISO/IEC 14496-1 SL-packetized stream or FlexMux stream carried in PES packets";
case 0x13: return "ISO/IEC 14496-1 SL-packetized stream or FlexMux stream carried in ISO/IEC14496_sections.";
case 0x14: return "ISO/IEC 13818-6 Synchronized Download Protocol";
case 0x15: return "Metadata carried in PES packets";
case 0x16: return "Metadata carried in metadata_sections";
default: return "(unknown)";
  }
}
