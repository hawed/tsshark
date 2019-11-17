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
#include <stdlib.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include <unistd.h>
#include "../common/pubh/ts_parser.h"
#include "../common/pubh/si_parser.h"
#include "../common/pubh/output.h"

#define TRACE_MAIN(x) printf x
#define TRACE_ERR printf("E: %s: %i\n", __FILE__,__LINE__); 

#define USE_TEST_PACKETS (0)

#if USE_TEST_PACKETS
static const char abTestPacket[] = 
"\x47\x00\x31\x17\x68\xD7\xEA\x6C\xA5\xD0\xC2\xD8\x5D\x8B\x4E\x0A\
\xAA\xCB\x0A\x03\xD5\x86\x96\xA6\xE9\xB6\x6D\x85\x5F\x16\xB3\x22\
\x4B\x22\x90\xC0\xE6\xC6\x7A\x00\x0E\x9B\x65\xB2\xAA\x10\xD5\x9B\
\x03\xDA\x9C\xEA\x6A\x33\x4B\x6A\x01\x55\xA8\x1C\x49\x62\x4D\x42\
\x4B\x0C\x35\x22\x92\xDC\x84\x90\x3D\x5A\x88\x7B\x59\x24\xE2\x0D\
\x00\xE5\xA8\x91\x2A\x35\x13\x55\xB3\x39\x1B\x36\x1F\x0A\x6B\x20\
\x7B\x55\x22\xC6\xB6\x26\xAB\x50\xD6\x48\xB6\x63\x98\x13\x16\x31\
\x85\xB5\x76\x24\x68\x66\xD8\x1D\x19\x82\xD8\x13\x55\xA3\x38\x53\
\x0D\xA1\x51\x96\xC1\xC4\x36\x32\xA0\x1E\xD0\xE6\x18\x6C\xB9\x4D\
\xB8\x06\xDA\xCC\xC9\xCD\xAA\x81\x3E\x57\x6C\x21\x56\xA0\x74\x25\
\xB5\xF0\x3E\x8A\x25\x98\x05\xCB\x58\x6D\x09\xAD\x4F\x03\xDA\x0C\
\x02\xD9\x4A\xA5\xCB\xE9\x5A\x44\x85\xD4\xF0\x64\
\x47\x00\x32\x17\x68\xD7\xEA\x6C\xA5\xD0\xC2\xD8\x5D\x8B\x4E\x0A\
\xAA\xCB\x0A\x03\xD5\x86\x96\xA6\xE9\xB6\x6D\x85\x5F\x16\xB3\x22\
\x4B\x22\x90\xC0\xE6\xC6\x7A\x00\x0E\x9B\x65\xB2\xAA\x10\xD5\x9B\
\x03\xDA\x9C\xEA\x6A\x33\x4B\x6A\x01\x55\xA8\x1C\x49\x62\x4D\x42\
\x4B\x0C\x35\x22\x92\xDC\x84\x90\x3D\x5A\x88\x7B\x59\x24\xE2\x0D\
\x00\xE5\xA8\x91\x2A\x35\x13\x55\xB3\x39\x1B\x36\x1F\x0A\x6B\x20\
\x7B\x55\x22\xC6\xB6\x26\xAB\x50\xD6\x48\xB6\x63\x98\x13\x16\x31\
\x85\xB5\x76\x24\x68\x66\xD8\x1D\x19\x82\xD8\x13\x55\xA3\x38\x53\
\x0D\xA1\x51\x96\xC1\xC4\x36\x32\xA0\x1E\xD0\xE6\x18\x6C\xB9\x4D\
\xB8\x06\xDA\xCC\xC9\xCD\xAA\x81\x3E\x57\x6C\x21\x56\xA0\x74\x25\
\xB5\xF0\x3E\x8A\x25\x98\x05\xCB\x58\x6D\x09\xAD\x4F\x03\xDA\x0C\
\x02\xD9\x4A\xA5\xCB\xE9\x5A\x44\x85\xD4\xF0\x64\
\x47\x00\x33\x17\x68\xD7\xEA\x6C\xA5\xD0\xC2\xD8\x5D\x8B\x4E\x0A\
\xAA\xCB\x0A\x03\xD5\x86\x96\xA6\xE9\xB6\x6D\x85\x5F\x16\xB3\x22\
\x4B\x22\x90\xC0\xE6\xC6\x7A\x00\x0E\x9B\x65\xB2\xAA\x10\xD5\x9B\
\x03\xDA\x9C\xEA\x6A\x33\x4B\x6A\x01\x55\xA8\x1C\x49\x62\x4D\x42\
\x4B\x0C\x35\x22\x92\xDC\x84\x90\x3D\x5A\x88\x7B\x59\x24\xE2\x0D\
\x00\xE5\xA8\x91\x2A\x35\x13\x55\xB3\x39\x1B\x36\x1F\x0A\x6B\x20\
\x7B\x55\x22\xC6\xB6\x26\xAB\x50\xD6\x49\xB6\x63\x98\x13\x16\x31\
\x85\xB5\x76\x24\x68\x66\xD8\x1D\x19\x82\xD8\x13\x55\xA3\x38\x53\
\x0D\xA1\x51\x96\xC1\xC4\x36\x32\xA0\x1E\xD0\xE6\x18\x6C\xB9\x4D\
\xB8\x06\xDA\xCC\xC9\xCD\xAA\x81\x3E\x57\x6C\x21\x56\xA0\x74\x25\
\xB5\xF0\x3E\x8A\x25\x98\x05\xCB\x58\x6D\x09\xAD\x4F\x03\xDA\x0C\
\x02\xD9\x4A\xA5\xCB\xE9\x5A\x44\x85\xD4\xF0\x64\
\x47\x00\x34\x17\x68\xD7\xEA\x6C\xA5\xD0\xC2\xD8\x5D\x8B\x4E\x0A\
\xAA\xCB\x0A\x03\xD5\x86\x96\xA6\xE9\xB6\x6D\x85\x5F\x16\xB3\x22\
\x4B\x22\x90\xC0\xE6\xC6\x7A\x00\x0E\x9B\x65\xB2\xAA\x10\xD5\x9B\
\x03\xDA\x9C\xEA\x6A\x33\x4B\x6A\x01\x55\xA8\x1C\x49\x62\x4D\x42\
\x4B\x0C\x35\x22\x92\xDC\x84\x90\x3D\x5A\x88\x7B\x59\x24\xE2\x0D\
\x00\xE5\xA8\x91\x2A\x35\x13\x55\xB3\x39\x1B\x36\x1F\x0A\x6B\x20\
\x7B\x55\x22\xC6\xB6\x26\xAB\x50\xD6\x50\xB6\x63\x98\x13\x16\x31\
\x85\xB5\x76\x24\x68\x66\xD8\x1D\x19\x82\xD8\x13\x55\xA3\x38\x53\
\x0D\xA1\x51\x96\xC1\xC4\x36\x32\xA0\x1E\xD0\xE6\x18\x6C\xB9\x4D\
\xB8\x06\xDA\xCC\xC9\xCD\xAA\x81\x3E\x57\x6C\x21\x56\xA0\x74\x25\
\xB5\xF0\x3E\x8A\x25\x98\x05\xCB\x58\x6D\x09\xAD\x4F\x03\xDA\x0C\
\x02\xD9\x4A\xA5\xCB\xE9\x5A\x44\x85\xD4\xF0\x64\
\x47\x00\x35\x17\x68"
;

static const char abTestPackets2[] = 
"\xD7\xEA\x6C\xA5\xD0\xC2\xD8\x5D\x8B\x4E\x0A\
\xAA\xCB\x0A\x03\xD5\x86\x96\xA6\xE9\xB6\x6D\x85\x5F\x16\xB3\x22\
\x4B\x22\x90\xC0\xE6\xC6\x7A\x00\x0E\x9B\x65\xB2\xAA\x10\xD5\x9B\
\x03\xDA\x9C\xEA\x6A\x33\x4B\x6A\x01\x55\xA8\x1C\x49\x62\x4D\x42\
\x4B\x0C\x35\x22\x92\xDC\x84\x90\x3D\x5A\x88\x7B\x59\x24\xE2\x0D\
\x00\xE5\xA8\x91\x2A\x35\x13\x55\xB3\x39\x1B\x36\x1F\x0A\x6B\x20\
\x7B\x55\x22\xC6\xB6\x26\xAB\x50\xD6\x50\xB6\x63\x98\x13\x16\x31\
\x85\xB5\x76\x24\x68\x66\xD8\x1D\x19\x82\xD8\x13\x55\xA3\x38\x53\
\x0D\xA1\x51\x96\xC1\xC4\x36\x32\xA0\x1E\xD0\xE6\x18\x6C\xB9\x4D\
\xB8\x06\xDA\xCC\xC9\xCD\xAA\x81\x3E\x57\x6C\x21\x56\xA0\x74\x25\
\xB5\xF0\x3E\x8A\x25\x98\x05\xCB\x58\x6D\x09\xAD\x4F\x03\xDA\x0C\
\x02\xD9\x4A\xA5\xCB\xE9\x5A\x44\x85\xD4\xF0\x64\
\x47\x00\x36\x17\x68\xD7\xEA\x6C\xA5\xD0\xC2\xD8\x5D\x8B\x4E\x0A\
\xAA\xCB\x0A\x03\xD5\x86\x96\xA6\xE9\xB6\x6D\x85\x5F\x16\xB3\x22\
\x4B\x22\x90\xC0\xE6\xC6\x7A\x00\x0E\x9B\x65\xB2\xAA\x10\xD5\x9B\
\x03\xDA\x9C\xEA\x6A\x33\x4B\x6A\x01\x55\xA8\x1C\x49\x62\x4D\x42\
\x4B\x0C\x35\x22\x92\xDC\x84\x90\x3D\x5A\x88\x7B\x59\x24\xE2\x0D\
\x00\xE5\xA8\x91\x2A\x35\x13\x55\xB3\x39\x1B\x36\x1F\x0A\x6B\x20\
\x7B\x55\x22\xC6\xB6\x26\xAB\x50\xD6\x48\xB6\x63\x98\x13\x16\x31\
\x85\xB5\x76\x24\x68\x66\xD8\x1D\x19\x82\xD8\x13\x55\xA3\x38\x53\
\x0D\xA1\x51\x96\xC1\xC4\x36\x32\xA0\x1E\xD0\xE6\x18\x6C\xB9\x4D\
\xB8\x06\xDA\xCC\xC9\xCD\xAA\x81\x3E\x57\x6C\x21\x56\xA0\x74\x25\
\xB5\xF0\x3E\x8A\x25\x98\x05\xCB\x58\x6D\x09\xAD\x4F\x03\xDA\x0C\
\x02\xD9\x4A\xA5\xCB\xE9\x5A\x44\x85\xD4\xF0\x64\
\x47\x00\x37\x17\x68\xD7\xEA\x6C\xA5\xD0\xC2\xD8\x5D\x8B\x4E\x0A\
\xAA\xCB\x0A\x03\xD5\x86\x96\xA6\xE9\xB6\x6D\x85\x5F\x16\xB3\x22\
\x4B\x22\x90\xC0\xE6\xC6\x7A\x00\x0E\x9B\x65\xB2\xAA\x10\xD5\x9B\
\x03\xDA\x9C\xEA\x6A\x33\x4B\x6A\x01\x55\xA8\x1C\x49\x62\x4D\x42\
\x4B\x0C\x35\x22\x92\xDC\x84\x90\x3D\x5A\x88\x7B\x59\x24\xE2\x0D\
\x00\xE5\xA8\x91\x2A\x35\x13\x55\xB3\x39\x1B\x36\x1F\x0A\x6B\x20\
\x7B\x55\x22\xC6\xB6\x26\xAB\x50\xD6\x49\xB6\x63\x98\x13\x16\x31\
\x85\xB5\x76\x24\x68\x66\xD8\x1D\x19\x82\xD8\x13\x55\xA3\x38\x53\
\x0D\xA1\x51\x96\xC1\xC4\x36\x32\xA0\x1E\xD0\xE6\x18\x6C\xB9\x4D\
\xB8\x06\xDA\xCC\xC9\xCD\xAA\x81\x3E\x57\x6C\x21\x56\xA0\x74\x25\
\xB5\xF0\x3E\x8A\x25\x98\x05\xCB\x58\x6D\x09\xAD\x4F\x03\xDA\x0C\
\x02\xD9\x4A\xA5\xCB\xE9\x5A\x44\x85\xD4\xF0\x64\
\x47\x00\x38\x17\x68\xD7\xEA\x6C\xA5\xD0\xC2\xD8\x5D\x8B\x4E\x0A\
\xAA\xCB\x0A\x03\xD5\x86\x96\xA6\xE9\xB6\x6D\x85\x5F\x16\xB3\x22\
\x4B\x22\x90\xC0\xE6\xC6\x7A\x00\x0E\x9B\x65\xB2\xAA\x10\xD5\x9B\
\x03\xDA\x9C\xEA\x6A\x33\x4B\x6A\x01\x55\xA8\x1C\x49\x62\x4D\x42\
\x4B\x0C\x35\x22\x92\xDC\x84\x90\x3D\x5A\x88\x7B\x59\x24\xE2\x0D\
\x00\xE5\xA8\x91\x2A\x35\x13\x55\xB3\x39\x1B\x36\x1F\x0A\x6B\x20\
\x7B\x55\x22\xC6\xB6\x26\xAB\x50\xD6\x50\xB6\x63\x98\x13\x16\x31\
\x85\xB5\x76\x24\x68\x66\xD8\x1D\x19\x82\xD8\x13\x55\xA3\x38\x53\
\x0D\xA1\x51\x96\xC1\xC4\x36\x32\xA0\x1E\xD0\xE6\x18\x6C\xB9\x4D\
\xB8\x06\xDA\xCC\xC9\xCD\xAA\x81\x3E\x57\x6C\x21\x56\xA0\x74\x25\
\xB5\xF0\x3E\x8A\x25\x98\x05\xCB\x58\x6D\x09\xAD\x4F\x03\xDA\x0C\
\x02\xD9\x4A\xA5\xCB\xE9\x5A\x44\x85\xD4\xF0\x64\
\x47\x00\x39\x17\x68\xD7\xEA\x6C\xA5\xD0\xC2\xD8\x5D\x8B\x4E\x0A\
\xAA\xCB\x0A\x03\xD5\x86\x96\xA6\xE9\xB6\x6D\x85\x5F\x16\xB3\x22\
\x4B\x22\x90\xC0\xE6\xC6\x7A\x00\x0E\x9B\x65\xB2\xAA\x10\xD5\x9B\
\x03\xDA\x9C\xEA\x6A\x33\x4B\x6A\x01\x55\xA8\x1C\x49\x62\x4D\x42\
\x4B\x0C\x35\x22\x92\xDC\x84\x90\x3D\x5A\x88\x7B\x59\x24\xE2\x0D\
\x00\xE5\xA8\x91\x2A\x35\x13\x55\xB3\x39\x1B\x36\x1F\x0A\x6B\x20\
\x7B\x55\x22\xC6\xB6\x26\xAB\x50\xD6\x50\xB6\x63\x98\x13\x16\x31\
\x85\xB5\x76\x24\x68\x66\xD8\x1D\x19\x82\xD8\x13\x55\xA3\x38\x53\
\x0D\xA1\x51\x96\xC1\xC4\x36\x32\xA0\x1E\xD0\xE6\x18\x6C\xB9\x4D\
\xB8\x06\xDA\xCC\xC9\xCD\xAA\x81\x3E\x57\x6C\x21\x56\xA0\x74\x25\
\xB5\xF0\x3E\x8A\x25\x98\x05\xCB\x58\x6D\x09\xAD\x4F\x03\xDA\x0C\
\x02\xD9\x4A\xA5\xCB\xE9\x5A\x44\x85\xD4\xF0\x64";
#endif

/*
* private
*/
static void usage(void);
#if USE_TEST_PACKETS
static void _parseTestPackets(void);
#endif
static void _parseFile(char* pFile);
static void _parseTables(char* pFile, char* pTable, char* cPid);

static void _getPat(char *pFile);
static void _getPmt(int iPid, char *pFile);
static void _getCat(char *pFile);
static void _getNit(char *pFile);
static void _getBat(char *pFile);
static void _getSdt(char *pFile);
static void _getEit(char *pFile);
static void _getRst(char *pFile);
static void _getTdt(char *pFile);
static void _getTot(char *pFile);
static void _getSt(char *pFile);

//verbose level 0 1 2
static int verbose = 2; // cmd line option!! TODO

int main(int argc, char** argv)
{
  if (argc == 1)
  {
    usage();
    return 0;
  }

  if (argc > 1)
  {
    struct stat stBuf;

    memset(&stBuf, 0, sizeof(stBuf));

    if (stat(argv[1], &stBuf) < 0 )
    {
      TRACE_MAIN(("no such file <%s>\n", argv[1]));
      return 1;
    }
  }

  if (argc > 2)
  {
    if (strcmp("-t", argv[2] ) == 0)
    {
      if (argc > 3)
      {
        if(strcmp("PMT", argv[3]) == 0)
        {
          if(argc > 4)
          {
            _parseTables(argv[1], argv[3], argv[4]);
          }
          else
          {
            usage();
          }
        }
        else
        {
          _parseTables(argv[1], argv[3], 0);
        }
      }
      else
      {
        usage();
      }
    }
    else if (strcmp("-r", argv[2] ) == 0)
    {
#if USE_TEST_PACKETS
      _parseTestPackets();
#else
      _parseFile(argv[1]);
#endif
    }
    else
    {
      usage();
    }
  }

  return 0;
}

static void usage()
{
  printf("tsshark ");
  printf("<tsfile> ");
  printf("-[");
  printf("r(aw),");
  printf("t(able)[PAT,PMT<pid>,CAT,NIT,BAT,SDT,EIT,RST,TDT,TOT,ST],");
  printf("p(ID)<pid>");
  printf("]\n");
  printf("\n");
}

static void _parseTables(char* pFile, char* pTable, char*  pPid)
{
  if (pFile == NULL)
  {
    TRACE_ERR;
    return;
  }

  if (pTable == NULL)
  {
    TRACE_ERR;
    return;
  }

  if (strcmp("PAT", pTable) == 0)
  {
    _getPat(pFile);
  }
  else if(strcmp("PMT", pTable) == 0)
  {
    _getPmt(atoi(pPid), pFile);
  }
  else if (strcmp("CAT", pTable) == 0)
  {
    _getCat(pFile);
  }
  else if (strcmp("NIT", pTable) == 0)
  {
    _getNit(pFile);
  }
  else if (strcmp("BAT", pTable) == 0)
  {
    _getBat(pFile);
  }
  else if (strcmp("SDT", pTable) == 0)
  {
    _getSdt(pFile);
  }
  else if (strcmp("EIT", pTable) == 0)
  {
    _getEit(pFile);
  }
  else if (strcmp("RST", pTable) == 0)
  {
    _getRst(pFile);
  }
  else if (strcmp("TDT", pTable) == 0)
  {
    _getTdt(pFile);
  }
  else if (strcmp("TOT", pTable) == 0)
  {
    _getTot(pFile);
  }
  else if (strcmp("ST", pTable) == 0)
  {
    _getSt(pFile);
  }
  else 
  {
    printf("table not supported so far\n");
  }
}

static void _parseFile(char* pFile)
{
  int iFd = -1;
  char *pabReadBuffer = NULL;
#define CHUNK_SIZE (64 * 1024)

  if (pFile == NULL)
  {
    TRACE_ERR;
    return;
  }

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_TS_PARSER_HANDLE tParserHandle = TS_PARSER_INVALID;
    TE_TS_PARSER_RC eRc = eTS_PARSER_OK;
    TS_PACKET_DATA stResult;
    unsigned long uwCount = 0;

    memset(&stResult, 0, sizeof(TS_PACKET_DATA));

    if (ts_parser_e_create(&tParserHandle))
    {
      TRACE_ERR;
    }
    else
    {
      int n;

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          /* parse buffer*/
          while (1)
          {
            eRc = ts_parser_e_parse(tParserHandle, pabReadBuffer, CHUNK_SIZE, 0, &stResult);

            if (eRc == eTS_PARSER_OK)
            {
              uwCount++;
              outputTs((void*)&stResult,uwCount);
            }
            else
            {
              printf("eRc: %i\n",eRc);
              if (eRc == eTS_PARSER_ERROR)
              {
                TRACE_ERR;
              }
              break;
            }
          }
        }

        if (n <= 0)
        {
          if (n < 0)
          {
            TRACE_ERR;
          }
          break;
        }
      }

      if (ts_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }

    close(iFd);
  }

  free(pabReadBuffer);
}

#if USE_TEST_PACKETS
static void _parseTestPackets()
{
  T_TS_PARSER_HANDLE tParserHandle = TS_PARSER_INVALID;
  TE_TS_PARSER_RC eRc = eTS_PARSER_OK;
  TS_PACKET_DATA stResult;
  char *buf = NULL;
  unsigned long len = 0;
  unsigned long uwCount = 0;

  if (ts_parser_e_create(&tParserHandle))
  {
    TRACE_ERR;
  }
  else
  {
    TRACE_MAIN(("...done\n"));
    memset(&stResult, 0, sizeof(TS_PACKET_DATA));

    TRACE_MAIN(("Parse  test packets (len: %lu)\n",sizeof(abTestPacket)));
    TRACE_MAIN(("Parse  test packets2 (len: %lu)\n",sizeof(abTestPackets2)));

    buf = (char*)abTestPacket;
    len = (unsigned long)(sizeof(abTestPacket) - 1); //\0 ignore -> - 1

    /* packet 1- ok*/
    eRc = ts_parser_e_parse(tParserHandle, buf, len, 0,  &stResult);

    uwCount++;

    printf("eRc: %i\n",eRc);

    if (eRc == eTS_PARSER_OK)
    {
      outputTs((void*)&stResult, uwCount);
    }

    /* packet 2 - ok*/
    eRc = ts_parser_e_parse(tParserHandle, buf, len, 0, &stResult);

    uwCount++;

    printf("eRc: %i\n",eRc);

    if (eRc == eTS_PARSER_OK)
    {
      outputTs((void*)&stResult,uwCount);
    }

    /* packet 3 - ok*/
    eRc = ts_parser_e_parse(tParserHandle, buf, len, 0,  &stResult);

    uwCount++;

    printf("eRc: %i\n",eRc);

    if (eRc == eTS_PARSER_OK)
    {
      outputTs((void*)&stResult, uwCount);
    }

    /* packet 4 - ok*/
    eRc = ts_parser_e_parse(tParserHandle, buf, len, 0,  &stResult);

    uwCount++;

    printf("eRc: %i\n",eRc);

    if (eRc == eTS_PARSER_OK)
    {
      outputTs((void*)&stResult, uwCount);
    }

    /* packet 5 - incomplete*/
    eRc = ts_parser_e_parse(tParserHandle, buf, len, 0,  &stResult);

    printf("eRc: %i\n",eRc);

    if (eRc == eTS_PARSER_INCOMPLETE)
    {
      buf = (char*)abTestPackets2;
      len = (unsigned long)(sizeof(abTestPackets2) - 1); //\0 ignore -> - 1
    }

    /* packet 5 - now complete */
    eRc = ts_parser_e_parse(tParserHandle, buf, len, 0,  &stResult);

    uwCount++;

    printf("eRc: %i\n",eRc);

    if (eRc == eTS_PARSER_OK)
    {
      outputTs((void*)&stResult, uwCount);
    }

    /* packet 6 - ok*/
    eRc = ts_parser_e_parse(tParserHandle, buf, len, 0,  &stResult);

    uwCount++; 

    printf("eRc: %i\n",eRc);

    if (eRc == eTS_PARSER_OK)
    {
      outputTs((void*)&stResult, uwCount);
    }

    /* packet 7 - ok*/
    eRc = ts_parser_e_parse(tParserHandle, buf, len, 0, &stResult);

    uwCount++;

    printf("eRc: %i\n",eRc);

    if (eRc == eTS_PARSER_OK)
    {
      outputTs((void*)&stResult, uwCount);
    }

    /* packet 8 - ok*/
    eRc = ts_parser_e_parse(tParserHandle, buf, len, 0, &stResult);

    uwCount++;

    printf("eRc: %i\n",eRc);

    if (eRc == eTS_PARSER_OK)
    {
      outputTs((void*)&stResult, uwCount);
    }

    /* packet 9 - finsihed*/
    eRc = ts_parser_e_parse(tParserHandle, buf, len, 0, &stResult);

    uwCount++;

    printf("eRc: %i\n",eRc);

    if (eRc == eTS_PARSER_FINISHED)
    {
      outputTs((void*)&stResult, uwCount);
    }


    if (ts_parser_e_destroy(tParserHandle))
    {
      TRACE_ERR;
    }
  }
  return eRc;
}
#endif // testpackets

static void _getPat(char* pFile)
{
  int iFd = -1;
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    //TODO move to an extra code part  PAT  
    if (si_parser_e_create(&tParserHandle, ePARSER_PAT))
    {
      TRACE_ERR;
    }
    else
    {
      TS_PAT stResult;
      memset(&stResult, 0, sizeof(TS_PAT));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_pat(tParserHandle, pabReadBuffer, CHUNK_SIZE, &stResult);

          if (eRc == eSI_PARSER_OK)
          {
            outputPAT(&stResult);

            if(si_parser_e_free_pat(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}


static void _getPmt(int iPid, char *pFile)
{
  int iFd = -1;
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    
    if (si_parser_e_create(&tParserHandle, ePARSER_PMT))
    {
      TRACE_ERR;
    }
    else
    {
      TS_PMT stResult;
      memset(&stResult, 0, sizeof(TS_PMT));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_pmt(tParserHandle, pabReadBuffer, CHUNK_SIZE, iPid, &stResult);

          if (eRc == eSI_PARSER_OK)
          {
            outputPMT(&stResult);

            if(si_parser_e_free_pmt(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}

static void _getCat(char *pFile)
{
  int iFd = -1;
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    
    if (si_parser_e_create(&tParserHandle, ePARSER_CAT))
    {
      TRACE_ERR;
    }
    else
    {
      TS_CAT stResult;
      memset(&stResult, 0, sizeof(TS_CAT));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_cat(tParserHandle, pabReadBuffer, CHUNK_SIZE, &stResult);
          
          if (eRc == eSI_PARSER_OK)
          {
            outputCAT(&stResult);

            if(si_parser_e_free_cat(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}
  
static void _getNit(char *pFile)
{
  int iFd = -1;
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    
    if (si_parser_e_create(&tParserHandle, ePARSER_NIT))
    {
      TRACE_ERR;
    }
    else
    {
      TS_NIT stResult;
      memset(&stResult, 0, sizeof(TS_NIT));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_nit(tParserHandle, pabReadBuffer, CHUNK_SIZE, &stResult);

          if (eRc == eSI_PARSER_OK)
          {
            outputNIT(&stResult);

            if(si_parser_e_free_nit(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}

static void _getBat(char *pFile)
{
   int iFd = -1;
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    
    if (si_parser_e_create(&tParserHandle, ePARSER_BAT))
    {
      TRACE_ERR;
    }
    else
    {
      TS_BAT stResult;
      memset(&stResult, 0, sizeof(TS_BAT));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_bat(tParserHandle, pabReadBuffer, CHUNK_SIZE, &stResult);

          if (eRc == eSI_PARSER_OK)
          {
            outputBAT(&stResult);

            if(si_parser_e_free_bat(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}

static void _getSdt(char *pFile)
{
  int iFd = -1;
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    
    if (si_parser_e_create(&tParserHandle, ePARSER_SDT))
    {
      TRACE_ERR;
    }
    else
    {
      TS_SDT stResult;
      memset(&stResult, 0, sizeof(TS_SDT));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_sdt(tParserHandle, pabReadBuffer, CHUNK_SIZE, &stResult);

          if (eRc == eSI_PARSER_OK)
          {
            outputSDT(&stResult);

            if(si_parser_e_free_sdt(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          usleep(1000); //WTF? I have no clue why it stucks in some cases - so sleep a bit
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}

static void _getEit(char *pFile)
{
  int iFd = -1;
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    
    if (si_parser_e_create(&tParserHandle, ePARSER_EIT))
    {
      TRACE_ERR;
    }
    else
    {
      TS_EIT stResult;
      memset(&stResult, 0, sizeof(TS_EIT));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_eit(tParserHandle, pabReadBuffer, CHUNK_SIZE, &stResult);

          if (eRc == eSI_PARSER_OK)
          {
            outputEIT(&stResult);

            if(si_parser_e_free_eit(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}

static void _getRst(char *pFile)
{
  int iFd = -1;
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    
    if (si_parser_e_create(&tParserHandle, ePARSER_RST))
    {
      TRACE_ERR;
    }
    else
    {
      TS_RST stResult;
      memset(&stResult, 0, sizeof(TS_RST));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_rst(tParserHandle, pabReadBuffer, CHUNK_SIZE, &stResult);

          if (eRc == eSI_PARSER_OK)
          {
            outputRST(&stResult);

            if(si_parser_e_free_rst(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}

static void _getTdt(char *pFile)
{
  int iFd = -1;
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    //TODO move to an extra code part  PAT  
    if (si_parser_e_create(&tParserHandle, ePARSER_TDT))
    {
      TRACE_ERR;
    }
    else
    {
      TS_TDT stResult;
      memset(&stResult, 0, sizeof(TS_TDT));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_tdt(tParserHandle, pabReadBuffer, CHUNK_SIZE, &stResult);

          if (eRc == eSI_PARSER_OK)
          {
            outputTDT(&stResult);

            if(si_parser_e_free_tdt(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}

static void _getTot(char *pFile)
{
  int iFd = -1;
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    
    if (si_parser_e_create(&tParserHandle, ePARSER_TOT))
    {
      TRACE_ERR;
    }
    else
    {
      TS_TOT stResult;
      memset(&stResult, 0, sizeof(TS_TOT));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_tot(tParserHandle, pabReadBuffer, CHUNK_SIZE, &stResult);

          if (eRc == eSI_PARSER_OK)
          {
            outputTOT(&stResult);

            if(si_parser_e_free_tot(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}

static void _getSt(char *pFile)
{
  int iFd = -1; 
  char *pabReadBuffer = NULL;
  #define CHUNK_SIZE (64 * 1024)

  pabReadBuffer = (char*)malloc(CHUNK_SIZE);

  if (pabReadBuffer == NULL)
  {
    TRACE_ERR;
    return;
  }

  memset(pabReadBuffer, 0, CHUNK_SIZE);
  iFd  = open(pFile, O_RDONLY);

  if (iFd < 0)
  {
    TRACE_ERR;
  }
  else
  {
    T_SI_PARSER_HANDLE tParserHandle = SI_PARSER_INVALID;
    TE_SI_PARSER_RC eRc = eSI_PARSER_OK;
    int n = 0;
    
    if (si_parser_e_create(&tParserHandle, ePARSER_ST))
    {
      TRACE_ERR;
    }
    else
    {
      TS_ST stResult;
      memset(&stResult, 0, sizeof(TS_ST));

      while (1)
      {
        n = read(iFd, pabReadBuffer, CHUNK_SIZE);

        if (n > 0)
        {
          eRc = si_parser_e_parse_st(tParserHandle, pabReadBuffer, CHUNK_SIZE, &stResult);

          if (eRc == eSI_PARSER_OK)
          {
            outputST(&stResult);

            if(si_parser_e_free_st(&stResult))
            {
              TRACE_ERR;
            }
          }
          else
          {
            if (eRc == eSI_PARSER_ERROR)
            {
              TRACE_ERR;
            }
          }
        }

        if(eRc == eSI_PARSER_INCOMPLETE)
        {
          /*new buffer needed*/
          continue;
        }

        if ((n <= 0) || (eRc == eSI_PARSER_ERROR)) 
        {
          TRACE_ERR;
        }

        break;
      }//while

      if (si_parser_e_destroy(tParserHandle))
      {
        TRACE_ERR;
      }
    }
    close(iFd);
  }
  free(pabReadBuffer);
}


