#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"

#define SNAP_LEN            16500  // pcap's max capture size
#define MAX_TAGS            100    // Max number of connections to track
#define MAX_FIELD_TYPES     256

#include "mysql/mysqlsniffer.h"
#include "mysql/packet_handlers.h"
#include "mysql/state_map.h"
#include "mysql/mysql_defines.h"
#include "mysql/user_defines.h"
#include "mysql/misc.h"

/*
  Global vars
*/
u_char buff[SNAP_LEN];     // For general MySQL packet processing
u_char *buff_frag;         // Last pkt fragment (tag->frag) + next pkts
u_int  total_mysql_pkts;
u_int  total_mysql_bytes;
int tags_initialized = 0;
int state_map_initialized = 0;

tag_id tags[MAX_TAGS];
tag_id *tag;               // Information about the current connection

void init_tags(void);
tag_id *get_tag(u_int addr, u_short port);
void init_state_map(void);
int multi_pkts(const u_char *pkts, u_int total_len);
int parse_pkt(u_char *pkt, u_int len);

void
mysql_print(const u_char *sp, u_int length, struct in_addr *ip_src, u_short sport, struct in_addr *ip_dst, u_short dport)
{
    if (!tags_initialized) {
        init_tags();
        tags_initialized = 1;
    }

    if (!state_map_initialized) {
        init_state_map();
        state_map_initialized = 1;
    }

    if (sport == 3306) {
        tag = get_tag((u_int)ip_dst->s_addr, dport);
    }
    else {
        tag = get_tag((u_int)ip_src->s_addr, sport);
    }

    multi_pkts(sp, length);
}


/*
  MySQL packet processing
*/

/*
  MySQL will send N amount of logical packets in one physical packet. Each
  logical packet starts with a MySQL header which says how long that logical
  pkt is minus the header itself (m->pkt_length). Along w/ the total length of
  captured MySQL data from libpcap (total_len), we can seperate all the logical
  pkts even though they all vary in length.
*/
int multi_pkts(const u_char *pkts, u_int total_len)
{
   int retval = PKT_UNKNOWN_STATE;
   u_int i = 0;
   u_int used_len = 0;
   struct mysql_hdr *m;

   // If last pkt was fragmented, merge with current pkts
   if(tag->pkt_fragment) {
      tag->pkt_fragment = 0;

      printf("\n\t::FRAGMENT START::\n\t");

      if(buff_frag)
         buff_frag = (u_char *)realloc(buff_frag, tag->frag_len + total_len);
      else
         buff_frag = (u_char *)malloc(tag->frag_len + total_len);
      memcpy(buff_frag, tag->frag, tag->frag_len);
      memcpy(buff_frag + tag->frag_len, pkts, total_len);

      pkts = buff_frag;
      total_len += tag->frag_len;
   }

   while(1) {
      m = (struct mysql_hdr *)pkts; // Packet header

      pkts += 4; // First data byte
      i    += 4;

      // Check if pkts > len of pkts actually received (last pkt is fragmented)
      used_len = used_len + m->pkt_length + 4;
      if(used_len > total_len) {
         tag->pkt_fragment = 1;
         tag->frag_len     = m->pkt_length - (used_len - total_len) + 4;

         pkts -= 4;

         if(tag->frag)
            tag->frag = (u_char *)realloc(tag->frag, tag->frag_len);
         else
            tag->frag = (u_char *)malloc(tag->frag_len);
         memcpy(tag->frag, pkts, tag->frag_len);

         printf("::FRAGMENT END::\n");

         retval = PKT_FRAGMENTED;
         break;
      }

      tag->current_pkt_id = m->pkt_id;

      if(!op.no_myhdrs) printf("ID %u len %u ", m->pkt_id, m->pkt_length);

      total_mysql_pkts++;
      total_mysql_bytes = total_mysql_bytes + 4 + m->pkt_length;

      if(m->pkt_length) {
         memcpy(buff, pkts, m->pkt_length);
         retval = parse_pkt(buff, m->pkt_length);
      }
      else
         printf("ID %u Zero-length MySQL packet ", m->pkt_id);
      printf("\n");

      tag->last_pkt_id = m->pkt_id;

      if((i + m->pkt_length) >= total_len) break; // No more pkts

      pkts += m->pkt_length; // Next pkt header
      i += m->pkt_length;

      if(retval == PKT_PARSED_OK)
         tag->last_origin = tag->current_origin;

      printf("\t");
   }

   return retval;
}

/*
  Parse one logical MySQL packet

  This function has 6 parts:
    1. Parse error pkts
    2. Handle no last origin
    3. Handle client re-sending pkt (set state back to STATE_SLEEP)
    4. Set state and number of possible events for state
    5. Try to handle pkt given state and possible events
    6. Check if pkt was handled/parsed ok

  If the pkt fails to be handled, something is broken or missing because
  when 6 fails, it goes to 2 which acts as a kind of catch-all.
  But if 2 then fails and we get back to 6 a second time, a warning
  is printed ("Client pkt has no valid handler") and the function returns
  a failure.
*/
int parse_pkt(u_char *pkt, u_int len)
{
   u_short state;
   u_short event;
   u_short num_events;
   u_short have_failed_before = 0;
   PKT_HANDLER ha = 0;

   if(op.dump) {
      dump_pkt(pkt, len, 1);
      return PKT_PARSED_OK;
   }

   if(*pkt == 0xFF) { // Error
      pkt_error(pkt, len);
      tag->state = STATE_SLEEP;
      return PKT_PARSED_OK;
   }

   /*
     If there is no last origin, this usually means this is the first pkt
     we're seeing for this connection. However, this pkt could then be
     anything, so we have to wait for a reliable starting point which is
     any client > server command because a client will only send a command
     from a state of sleep (i.e, after the server is done responding).
   */
   if(!tag->last_origin) {
DETERMINE_PKT:
      if(tag->current_origin == ORIGIN_SERVER) {

         ha = state_map[STATE_NOT_CONNECTED].ha[0]; // server handshake pkt?
         if((*ha)(pkt, len) == PKT_HANDLED) {
            tag->state = state_map[STATE_NOT_CONNECTED].next_state[0];
            return PKT_PARSED_OK;
         }
         else {
            /*
              We're in the middle of a pre-established connection or something
              weird happened like the server responding for no reason (perhaps
              the client sent a TCP re-xmit?)
            */
            printf("Waiting for server to finish response... ");
            dump_pkt(pkt, len, 0);
            tag->state = STATE_SLEEP; // Will be asleep when done
            tag->last_origin = 0;
            return PKT_UNKNOWN_STATE; // Keeps multi_pkts() from setting tag->last_origin
         }

      }
      else { // pkt from client

         /*
           Since the MySQL protocol is purely request-response, if a pkt is from
           the client it must mean MySQL has finished responding and is asleep
           waiting for further commands.
         */
         tag->state = STATE_SLEEP;

         // Special cases
         if(len == 1) {
            if(*pkt == COM_STATISTICS) tag->state = STATE_ONE_STRING;
         }

      }
   }

   // Client re-sent pkt (MySQL probably didn't respond to the first pkt)
   if(tag->last_origin == ORIGIN_CLIENT &&
      tag->current_origin == ORIGIN_CLIENT &&
      tag->state != STATE_SLEEP)
   {
      printf("::RETRANSMIT:: ");
      tag->state = STATE_SLEEP;
   }

   // Safeguard
   if(tag->current_origin == ORIGIN_CLIENT &&
      tag->current_pkt_id == 0 &&
      tag->state != STATE_SLEEP)
   {
      tag->state = STATE_SLEEP;
   }

   state = tag->state; // Current state
   num_events = state_map[state].num_events; // Number of possible events for current state
   if(op.state) printf("state '%s' ", state_name[state]);

   // Try to handle the pkt...
   if(num_events == 1) {
      tag->event = state_map[state].event[0];
      ha = state_map[state].ha[0];

      if((*ha)(pkt, len))
         tag->state = state_map[state].next_state[0]; // pkt was handled
      else
         ha = 0;
   }
   else {
      for(event = 0; event < num_events; event++) {
         tag->event = state_map[state].event[event];
         ha = state_map[state].ha[event];

         if((*ha)(pkt, len)) {
            // pkt was handled
            tag->state = state_map[state].next_state[event];
            break;
         }
         else ha = 0;
      }
   }

   // ...Check if pkt was handled
   if(!ha) {
      printf("::Unhandled Event:: ");

      if(!have_failed_before) {
         have_failed_before = 1; // Prevent infinite loop
         goto DETERMINE_PKT;
      }
      else {
         printf("Client pkt has no valid handler ");
         dump_pkt(pkt, len, 1);
         return PKT_UNKNOWN_STATE;
      }
   }

   return PKT_PARSED_OK;
}

/*
  Connection tracking

  The following functions provides the means by which mysqlsniffer maintains
  information about the current state of each MySQL connection (identified by
  unique client IP-port pairs). Along with the psuedo state transition table
  we're less in the dark about what kind of data we're dealing with.
*/

void init_tags(void)
{
   int i;

   for(i = 0; i < MAX_TAGS; i++)
      tags[i].state = STATE_NOT_CONNECTED;
}

tag_id *get_tag(u_int addr, u_short port)
{
   int i;
   int last_i = -1;

   for(i = 0; i < MAX_TAGS; i++) {
      if(!tags[i].id_address) {
         if(last_i == -1) last_i = i;
         continue;
      }
      if(tags[i].id_address == addr && tags[i].id_port == port) return (tag_id *)&tags[i];
   }

   if(last_i >= 0) {
         tags[last_i].id_address = addr;
         tags[last_i].id_port = port;
         return (tag_id *)&tags[last_i];
   }

   return 0;
}

void remove_tag(tag_id *tag)
{
   if(!tag) return;

   // printf(" (Removing tag %u.%u) ", tag->id_address, tag->id_port);

   tag->id_address = 0;
   tag->id_port    = 0;

   tag->current_origin = 0;
   tag->current_pkt_id = 0;
   tag->last_origin    = 0;
   tag->last_pkt_id    = 0;
   tag->state          = STATE_NOT_CONNECTED;
}

void free_tags(void)
{
   int i;

   for(i = 0; i < MAX_TAGS; i++) {
      if(tags[i].frag)   free(tags[i].frag);
      if(tags[i].fields) free(tags[i].fields);

      tags[i].id_address = 0;
      tags[i].id_port    = 0;

      tags[i].current_origin = 0;
      tags[i].current_pkt_id = 0;
      tags[i].last_origin    = 0;
      tags[i].last_pkt_id    = 0;
      tags[i].state          = STATE_NOT_CONNECTED;

      tags[i].frag   = 0;
      tags[i].fields = 0;
   }
}

void init_state_map(void)
{
   state_map[STATE_ONE_STRING].ha[0] = &pkt_string;
   state_map[STATE_ONE_STRING].event[0] = EVENT_ONE_STRING;
   state_map[STATE_ONE_STRING].next_state[0] = STATE_SLEEP;
   state_map[STATE_ONE_STRING].num_events = 1;

   state_map[STATE_OK].ha[0] = &pkt_ok;
   state_map[STATE_OK].event[0] = EVENT_OK;
   state_map[STATE_OK].next_state[0] = STATE_SLEEP;
   state_map[STATE_OK].num_events = 1;

   state_map[STATE_FIELD_LIST].ha[0] = &pkt_field;
   state_map[STATE_FIELD_LIST].event[0] = EVENT_FL_FIELD;
   state_map[STATE_FIELD_LIST].next_state[0] = STATE_FIELD_LIST;
   state_map[STATE_FIELD_LIST].ha[1] = &pkt_end;
   state_map[STATE_FIELD_LIST].event[1] = EVENT_END;
   state_map[STATE_FIELD_LIST].next_state[1] = STATE_SLEEP;
   state_map[STATE_FIELD_LIST].num_events = 2;

   state_map[STATE_SLEEP].ha[0] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[0] = COM_QUERY;
   state_map[STATE_SLEEP].next_state[0] = STATE_TXT_RS;
   state_map[STATE_SLEEP].ha[1] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[1] = COM_INIT_DB;
   state_map[STATE_SLEEP].next_state[1] = STATE_OK;
   state_map[STATE_SLEEP].ha[2] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[2] = COM_FIELD_LIST;
   state_map[STATE_SLEEP].next_state[2] = STATE_FIELD_LIST;
   state_map[STATE_SLEEP].ha[3] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[3] = COM_CREATE_DB;
   state_map[STATE_SLEEP].next_state[3] = STATE_OK;
   state_map[STATE_SLEEP].ha[4] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[4] = COM_DROP_DB;
   state_map[STATE_SLEEP].next_state[4] = STATE_OK;
   state_map[STATE_SLEEP].ha[5] = &pkt_com_x_int;
   state_map[STATE_SLEEP].event[5] = COM_PROCESS_KILL;
   state_map[STATE_SLEEP].next_state[5] = STATE_OK;
   state_map[STATE_SLEEP].ha[6] = &pkt_com_x_int;
   state_map[STATE_SLEEP].event[6] = COM_REFRESH;
   state_map[STATE_SLEEP].next_state[6] = STATE_OK;
   state_map[STATE_SLEEP].ha[7] = &pkt_end;
   state_map[STATE_SLEEP].event[7] = COM_SHUTDOWN;
   state_map[STATE_SLEEP].next_state[7] = STATE_END;
   state_map[STATE_SLEEP].ha[8] = &pkt_com_x;
   state_map[STATE_SLEEP].event[8] = COM_DEBUG;
   state_map[STATE_SLEEP].next_state[8] = STATE_END;
   state_map[STATE_SLEEP].ha[9] = &pkt_com_x;
   state_map[STATE_SLEEP].event[9] = COM_STATISTICS;
   state_map[STATE_SLEEP].next_state[9] = STATE_ONE_STRING;
   state_map[STATE_SLEEP].ha[10] = &pkt_com_x;
   state_map[STATE_SLEEP].event[10] = COM_PING;
   state_map[STATE_SLEEP].next_state[10] = STATE_COM_PONG;
   state_map[STATE_SLEEP].ha[11] = &pkt_com_x;
   state_map[STATE_SLEEP].event[11] = COM_QUIT;
   state_map[STATE_SLEEP].next_state[11] = STATE_NOT_CONNECTED;
   state_map[STATE_SLEEP].ha[12] = &pkt_com_x_string;
   state_map[STATE_SLEEP].event[12] = COM_STMT_PREPARE;
   state_map[STATE_SLEEP].next_state[12] = STATE_STMT_META;
   state_map[STATE_SLEEP].ha[13] = &pkt_stmt_execute;
   state_map[STATE_SLEEP].event[13] = COM_STMT_EXECUTE;
   state_map[STATE_SLEEP].next_state[13] = STATE_BIN_RS;
   state_map[STATE_SLEEP].ha[14] = &pkt_com_x_int;
   state_map[STATE_SLEEP].event[14] = COM_STMT_CLOSE;
   state_map[STATE_SLEEP].next_state[14] = STATE_SLEEP;
   state_map[STATE_SLEEP].num_events = 15;

   state_map[STATE_STMT_META].ha[0] = &pkt_stmt_meta;
   state_map[STATE_STMT_META].event[0] = EVENT_STMT_META;
   state_map[STATE_STMT_META].next_state[0] = STATE_STMT_PARAM;
   state_map[STATE_STMT_META].num_events = 1;

   state_map[STATE_STMT_PARAM].ha[0] = &pkt_field;
   state_map[STATE_STMT_PARAM].event[0] = EVENT_STMT_PARAM;
   state_map[STATE_STMT_PARAM].next_state[0] = STATE_STMT_PARAM;
   state_map[STATE_STMT_PARAM].ha[1] = &pkt_end;
   state_map[STATE_STMT_PARAM].event[1] = EVENT_END;
   state_map[STATE_STMT_PARAM].next_state[1] = STATE_FIELD_LIST;
   state_map[STATE_STMT_PARAM].num_events = 2;

   state_map[STATE_FIELD].ha[0] = &pkt_field;
   state_map[STATE_FIELD].event[0] = EVENT_FIELD ;
   state_map[STATE_FIELD].next_state[0] = STATE_FIELD;
   state_map[STATE_FIELD].ha[1] = &pkt_end;
   state_map[STATE_FIELD].event[1] = EVENT_END;
   state_map[STATE_FIELD].next_state[1] = STATE_TXT_ROW;
   state_map[STATE_FIELD].num_events = 2;

   state_map[STATE_FIELD_BIN].ha[0] = &pkt_field;
   state_map[STATE_FIELD_BIN].event[0] = EVENT_FIELD_BIN;
   state_map[STATE_FIELD_BIN].next_state[0] = STATE_FIELD_BIN;
   state_map[STATE_FIELD_BIN].ha[1] = &pkt_end;
   state_map[STATE_FIELD_BIN].event[1] = EVENT_END;
   state_map[STATE_FIELD_BIN].next_state[1] = STATE_BIN_ROW;
   state_map[STATE_FIELD_BIN].num_events = 2;

   state_map[STATE_TXT_RS].ha[0] = &pkt_n_fields;
   state_map[STATE_TXT_RS].event[0] = EVENT_NUM_FIELDS;
   state_map[STATE_TXT_RS].next_state[0] = STATE_FIELD;
   state_map[STATE_TXT_RS].ha[1] = &pkt_ok;
   state_map[STATE_TXT_RS].event[1] = EVENT_OK;
   state_map[STATE_TXT_RS].next_state[1] = STATE_SLEEP;
   state_map[STATE_TXT_RS].num_events = 2;

   state_map[STATE_BIN_RS].ha[0] = &pkt_n_fields;
   state_map[STATE_BIN_RS].event[0] = EVENT_NUM_FIELDS_BIN;
   state_map[STATE_BIN_RS].next_state[0] = STATE_FIELD_BIN;
   state_map[STATE_BIN_RS].ha[1] = &pkt_ok;
   state_map[STATE_BIN_RS].event[1] = EVENT_OK;
   state_map[STATE_BIN_RS].next_state[1] = STATE_SLEEP;
   state_map[STATE_BIN_RS].num_events = 2;

   state_map[STATE_END].ha[0] = &pkt_end;
   state_map[STATE_END].event[0] = EVENT_END;
   state_map[STATE_END].next_state[0] = STATE_SLEEP;
   state_map[STATE_END].num_events = 1;

   state_map[STATE_ERROR].ha[0] = &pkt_error;
   state_map[STATE_ERROR].event[0] = EVENT_ERROR;
   state_map[STATE_ERROR].next_state[0] = STATE_SLEEP;
   state_map[STATE_ERROR].num_events = 1;

   state_map[STATE_TXT_ROW].ha[0] = &pkt_row;
   state_map[STATE_TXT_ROW].event[0] = EVENT_ROW;
   state_map[STATE_TXT_ROW].next_state[0] = STATE_TXT_ROW;
   state_map[STATE_TXT_ROW].ha[1] = &pkt_ok;
   state_map[STATE_TXT_ROW].event[1] = EVENT_OK;
   state_map[STATE_TXT_ROW].next_state[1] = STATE_TXT_ROW;
   state_map[STATE_TXT_ROW].ha[2] = &pkt_end;
   state_map[STATE_TXT_ROW].event[2] = EVENT_END;
   state_map[STATE_TXT_ROW].next_state[2] = STATE_SLEEP;
   state_map[STATE_TXT_ROW].ha[3] = &pkt_end;
   state_map[STATE_TXT_ROW].event[3] = EVENT_END_MULTI_RESULT;
   state_map[STATE_TXT_ROW].next_state[3] = STATE_TXT_RS;
   state_map[STATE_TXT_ROW].num_events = 4;

   state_map[STATE_BIN_ROW].ha[0] = &pkt_binary_row;
   state_map[STATE_BIN_ROW].event[0] = EVENT_ROW;
   state_map[STATE_BIN_ROW].next_state[0] = STATE_BIN_ROW;
   state_map[STATE_BIN_ROW].ha[1] = &pkt_ok;
   state_map[STATE_BIN_ROW].event[1] = EVENT_OK;
   state_map[STATE_BIN_ROW].next_state[1] = STATE_BIN_ROW;
   state_map[STATE_BIN_ROW].ha[2] = &pkt_end;
   state_map[STATE_BIN_ROW].event[2] = EVENT_END;
   state_map[STATE_BIN_ROW].next_state[2] = STATE_SLEEP;
   state_map[STATE_BIN_ROW].num_events = 3;

   state_map[STATE_NOT_CONNECTED].ha[0] = &pkt_handshake_server;
   state_map[STATE_NOT_CONNECTED].event[0] = EVENT_SERVER_HANDSHAKE;
   state_map[STATE_NOT_CONNECTED].next_state[0] = STATE_CLIENT_HANDSHAKE;
   state_map[STATE_NOT_CONNECTED].num_events = 1;

   state_map[STATE_CLIENT_HANDSHAKE].ha[0] = &pkt_handshake_client;
   state_map[STATE_CLIENT_HANDSHAKE].event[0] = EVENT_CLIENT_HANDSHAKE;
   state_map[STATE_CLIENT_HANDSHAKE].next_state[0] = STATE_OK;
   state_map[STATE_CLIENT_HANDSHAKE].num_events = 1;

   state_map[STATE_COM_PONG].ha[0] = &pkt_ok;
   state_map[STATE_COM_PONG].event[0] = COM_PONG;
   state_map[STATE_COM_PONG].next_state[0] = STATE_SLEEP;
   state_map[STATE_COM_PONG].num_events = 1;
}

// MySQL server > client connection handshake pkt
int pkt_handshake_server(u_char *pkt, u_int len)
{
   if(*pkt != 0x0A || len < 29) return PKT_WRONG_TYPE;

   u_char  proto;
   u_int   caps;
   u_short status;
   u_int   thd_id;
   u_char  *ver;
   u_char  *salt1;
   u_char  *salt2;

   proto   = *pkt;
   pkt    += 1;
   ver     = pkt;
   pkt    += strlen((char *)ver) + 1;
   thd_id  = G4(pkt)
   pkt    += 4;
   salt1   = pkt;
   pkt    += strlen((char *)salt1) + 1;
   caps    = *pkt;
   pkt    += 2;
   pkt    += 1; // For character set
   status  = G2(pkt)
   pkt    += 15; // 2 for status, 13 for zero-byte padding
   salt2   = pkt;

   printf("Handshake <proto %u ver %s thd %d> ", (u_int)proto, ver, thd_id);
   if(op.verbose) unmask_caps(caps);

   return PKT_HANDLED;
}

// MySQL client > server connection handshake pkt
int pkt_handshake_client(u_char *pkt, u_int len)
{
   u_char cs;
   u_int  caps;
   u_int  max_pkt;
   u_int  pass_len;
   u_char *user;
   u_char *db;
   u_char pass[128];
   u_char b3[3];

   if(op.v40) {
      caps  = G2(pkt);
      pkt  += 2;
      memcpy(b3, pkt, 3);
      max_pkt = *((u_int *)b3);
      pkt  += 3;
      user  = pkt;
      pkt  += strlen((char *)user) + 1;
      db    = 0;
   }
   else {
      caps     = G4(pkt);
      pkt     += 4;
      max_pkt  = G4(pkt);
      pkt     += 4;
      cs       = *pkt;
      pkt     += 24;
      user     = pkt;
      pkt     += strlen((char *)user) + 1;

      pass_len = (caps & CLIENT_SECURE_CONNECTION ? *pkt++ : strlen((char *)pkt));
      memcpy(pass, pkt, pass_len);
      pass[pass_len] = 0;

      pkt += pass_len;
      db = (caps & CLIENT_CONNECT_WITH_DB ? pkt : 0);
   }

   printf("Handshake (%s auth) <user %s db %s max pkt %u> ",
            (caps & CLIENT_SECURE_CONNECTION ? "new" : "old"), user, db, max_pkt);
   if(op.verbose) unmask_caps(caps);

   return PKT_HANDLED;
}


// MySQL OK pkt
int pkt_ok(u_char *pkt, u_int len)
{
   if(*pkt == 0xFE)         return PKT_WRONG_TYPE;
   if(op.v40 && (len < 5))  return PKT_WRONG_TYPE;
   if(!op.v40 && (len < 7)) return PKT_WRONG_TYPE;

   u_int  field_count;
   u_int  rows;
   u_int  insert_id;
   u_int  status;
   u_int  warn;
   u_char msg[len];

   field_count = (u_int)*pkt++;
   rows        = (u_int)*pkt++; // TODO: Can be LC
   insert_id   = (u_int)*pkt++; //       Can be LC
   status      = G2(pkt);
   if(op.v40) { warn = 0; }
   else {
      pkt     += 2;
      warn     = G2(pkt);
   }

   printf("OK <fields %u affected rows %u insert id %u warnings %u> ",
          field_count, rows, insert_id, warn);
   if(op.verbose) unmask_status(status);

   if(len > 7 || (op.v40 && len > 5)) { // Extra info on end of pkt
      pkt += 3;
      memcpy(msg, pkt, len - 8);
      msg[len - 8] = 0;
      printf(" (%s)", msg);
   }

   return PKT_HANDLED;
}

// MySQL end pkt
int pkt_end(u_char *pkt, u_int len)
{
   if(*pkt != 0xFE || len > 5) return PKT_WRONG_TYPE;

   u_short warn = 0;
   u_short status = 0;

   if(len > 1) { // 4.1+
      pkt++;
      warn    = G2(pkt);
      pkt    += 2;
      status  = G2(pkt);

      if((tag->state == STATE_TXT_ROW || tag->state == STATE_BIN_ROW) &&
         status & SERVER_MORE_RESULTS_EXISTS &&
         tag->event != EVENT_END_MULTI_RESULT)
            return PKT_WRONG_TYPE;
   }

   printf("End ");

   if(status & SERVER_MORE_RESULTS_EXISTS) printf("Multi-Result ");

   if(len > 1) { // 4.1+
      printf("<warnings %u> ", warn);
      if(op.verbose) unmask_status(status);
   }

   return PKT_HANDLED;
}

// MySQL error message pkt
int pkt_error(u_char *pkt, u_int len)
{
   if(*pkt != 0xFF) return PKT_WRONG_TYPE;

   u_short err_code;
   u_char sql_state[7], err_pkt[255];

   pkt++;
   err_code = G2(pkt);
   pkt += 2;
   if(op.v40) {
      sql_state[0] = 0;
      memcpy(err_pkt, pkt, (len - 3));
      err_pkt[len - 3] = 0;
   }
   else {
      memcpy(sql_state, pkt, 6);
      sql_state[6] = 0;
      pkt += 6;
      memcpy(err_pkt, pkt, (len - 9));
      err_pkt[len - 9] = 0;
   }

   printf("Error %u (%s): %s", err_code, sql_state, err_pkt);

   return PKT_HANDLED;
}

int pkt_com_x(u_char *pkt, u_int len)
{
   if(len > 1 || *pkt > COM_END) return PKT_WRONG_TYPE;

   int pkt_match_event = 0;

   // Does pkt match event?
   switch(tag->event) {
      case COM_QUIT:       pkt_match_event = MATCH(*pkt, COM_QUIT);       break;
      case COM_PING:       pkt_match_event = MATCH(*pkt, COM_PING);       break;
      case COM_STATISTICS: pkt_match_event = MATCH(*pkt, COM_STATISTICS); break;
      case COM_DEBUG:      pkt_match_event = MATCH(*pkt, COM_DEBUG);      break;
      default: pkt_match_event = 0;
   }

   if(!pkt_match_event) return PKT_WRONG_TYPE;

   printf("COM_%s", command_name[*pkt]);

   if(tag->event == COM_QUIT) remove_tag(tag);

   return PKT_HANDLED;
}

int pkt_com_x_string(u_char *pkt, u_int len)
{
   if(len == 1 || *pkt > COM_END) return PKT_WRONG_TYPE;

   int pkt_match_event = 0;

   // Does pkt match event?
   switch(tag->event) {
      case COM_QUERY:        pkt_match_event = MATCH(*pkt, COM_QUERY);        break;
      case COM_FIELD_LIST:   pkt_match_event = MATCH(*pkt, COM_FIELD_LIST);   break;
      case COM_INIT_DB:      pkt_match_event = MATCH(*pkt, COM_INIT_DB);      break;
      case COM_CREATE_DB:    pkt_match_event = MATCH(*pkt, COM_CREATE_DB);    break;
      case COM_DROP_DB:      pkt_match_event = MATCH(*pkt, COM_DROP_DB);      break;
      case COM_STMT_PREPARE: pkt_match_event = MATCH(*pkt, COM_STMT_PREPARE); break;

      default: pkt_match_event = 0;
   }

   if(!pkt_match_event) return PKT_WRONG_TYPE;

   printf("COM_%s: %s", command_name[*pkt], get_arg(pkt, len));

   return PKT_HANDLED;
}

int pkt_com_x_int(u_char *pkt, u_int len)
{
   if(len == 1 || len > 5) return PKT_WRONG_TYPE;

   int pkt_match_event = 0;

   // Does pkt match event?
   switch(tag->event) {
      case COM_PROCESS_KILL: pkt_match_event = MATCH(*pkt, COM_PROCESS_KILL); break;
      case COM_REFRESH:      pkt_match_event = MATCH(*pkt, COM_REFRESH);      break;
      case COM_STMT_CLOSE:   pkt_match_event = MATCH(*pkt, COM_STMT_CLOSE);   break;
      default: pkt_match_event = 0;
   }

   if(!pkt_match_event) return PKT_WRONG_TYPE;

   printf("COM_%s: ", command_name[*pkt]);
   *pkt++;
   printf("%u", get_uint(pkt));

   return PKT_HANDLED;
}

int pkt_string(u_char *pkt, u_int len)
{
   if(len == 1) return PKT_WRONG_TYPE;

   u_char buff[len + 1];

   memcpy(buff, pkt, len);
   buff[len] = 0;

   printf("%s", buff);

   return PKT_HANDLED;
}

int pkt_n_fields(u_char *pkt, u_int len)
{
   if(len > 1) return PKT_WRONG_TYPE;

   decode_len(pkt);

   printf("%llu Fields", decoded_len);

   if(EVENT_NUM_FIELDS_BIN) {
      tag->n_fields      = (u_int)*pkt; // Used by pkt_binary_row()
      tag->current_field = 0; // Used by pkt_field()

      if(!tag->fields) // tag->fields populated in pkt_field()
         tag->fields = (field_types *)malloc(sizeof(field_types));
   }

   return PKT_HANDLED;
}

// MySQL field description pkt
int pkt_field(u_char *pkt, u_int len)
{
   if(*pkt == 0xFE) return PKT_WRONG_TYPE;

   u_int   field_len;
   u_char  db[256];
   u_char  table[256];
   u_char  field[256];
   u_short field_type;
   u_short flags;

   // TODO: need to handle decimals and default

   if(op.v40) {
      db[0] = 0;
      pkt   = my_strcpy(table, pkt, 256);
      pkt   = my_strcpy(field, pkt, 256);
      pkt  += 1;
      field_len = G3(pkt);
      pkt  += 3;
      pkt  += 1; // For LCB on type
      field_type = *pkt++;
      pkt  += 1; // For LCB on flags
      flags = *pkt; // TODO: This has an 03 LCB but is supposedly only 2 bytes?
   }
   else {
      pkt  += 4; // Db length
      pkt   = my_strcpy(db, pkt, 256);
      pkt   = my_strcpy(table, pkt, 256);
      pkt   = my_strcpy(0, pkt, 256); // Org. table
      pkt   = my_strcpy(field, pkt, 256);
      pkt   = my_strcpy(0, pkt, 256); // Org. name
      pkt  += 3;
      field_len = G4(pkt);
      pkt  += 4;
      field_type = *((u_int *)pkt);
      pkt  += 1;
      flags = G2(pkt)
   }

   if(tag->event == EVENT_FIELD_BIN) {
      tag->fields->field_type[tag->current_field] = field_type;
      tag->fields->field_flags[tag->current_field++] = flags;
   }

   printf("Field: %s.%s.%s <type %s (%u) size %u>", db, table, field,
          get_field_type(field_type), (u_int)field_type, field_len);

   return PKT_HANDLED;
}

/*
  MySQL data row pkt (1 pkt per row):
   Row 1 Col 1 length   1 byte
   Row 1 Col 1 data     string
   ...
   Row 1 Col N length   1 byte
   Row 1 Col N data     string
*/
int pkt_row(u_char *pkt, u_int len)
{
   if(*pkt == 0xFE && (len == 1 || len == 5)) return PKT_WRONG_TYPE; // Is End pkt

   u_int   n;
   u_int   end = 0;
   u_char  col_LC;
   u_char  col_truncated = 0;
   ulonglong col_len;
   ulonglong real_col_len;
   static u_char col_data[MAX_COL_LEN + 9]; // +9 for '::TRUNC::' if necessary

   printf("||");
   while(1) {
      col_LC = *pkt;

      n = decode_len(pkt);
      real_col_len = col_len = decoded_len;

      // 1 for LC, n if LC followed in 2, 4, or 8 bytes
      pkt = pkt + 1 + (n > 1 ? n : 0);
      end = end + 1 + (n > 1 ? n : 0);

      if(col_LC != 0xFB) { // Column is not NULL
         if(col_len > MAX_COL_LEN - 1) {
            col_len = MAX_COL_LEN - 1;
            col_truncated = 1;
         }

         if(col_len) {
            memcpy(col_data, pkt, col_len);
            if(col_truncated) {
               memcpy(col_data + col_len, "::TRUNC::", 9);
               col_data[col_len + 9] = 0;
            }
            else
               col_data[col_len] = 0;

            printf(" %s |", col_data);
         }
         else
            printf("  |"); // Empty string ''
      }
      else {
         real_col_len = 0;
         printf(" NULL |");
      }

      if((end + real_col_len) >= len) break;

      col_truncated = 0;

      pkt += real_col_len;
      end += real_col_len;
   }
   printf("|");

   return PKT_HANDLED;
}

/*
  MySQL binary data row pkt (1 pkt per row):
   Zero byte            1 byte
   NULL bitmap          1..n bytes
   ...
   Row 1 Col A length   1 byte
   Row 1 Col A data     string
   ...
   Row 1 Col Z length   1 byte
   Row 1 Col Z data     string

   This function converts/expands pkt from binary to regular (text)
   protocol then passes it to pkt_row() for output processing.
*/
int pkt_binary_row(u_char *pkt, u_int len)
{
   if(*pkt != 0x00) return PKT_WRONG_TYPE;

   u_int   byte, bit, col;
   u_int   col_len;
   u_int   col_len_expanded;
   u_short n_bitmap_bytes = (tag->n_fields + 7 + 2) / 8;
   u_int   null_bitmap[16]; // 512 columns max
   u_short bb;
   u_char  txt_row[len + tag->n_fields];
   u_char  *row;
   u_int   row_len;
   u_short flags;

   pkt++;

   memset(null_bitmap, 0, sizeof(null_bitmap));

   null_bitmap[0] = *pkt++ >> 2;

   for(byte = 1, col = 6; byte < n_bitmap_bytes; byte++, pkt++) {
      for(bit = 0; bit < 8; bit++, col++) {
         bb = col / 32;
         null_bitmap[bb] |= (((*pkt >> bit) & 1) << (col - (32 * bb)));
      }
   }

   row     = txt_row;
   row_len = 0;

   for(col = 0; col <= tag->n_fields - 1; col++) {
      bb = col / 32;
      if(null_bitmap[bb] & (1 << (col - (bb * 32)))) { // Column is NULL
         *row++ = 0xFB;
         row_len++;
      }
      else {
         flags = tag->fields->field_flags[col];

         col_len_expanded = col_len = 0;

         switch(tag->fields->field_type[col])
         {  // Numerics
            case 1: col_len_expanded = convert_binary_number(pkt, flags, 1, row); col_len = 1; break;
            case 2: col_len_expanded = convert_binary_number(pkt, flags, 2, row); col_len = 2; break;
            case 3: col_len_expanded = convert_binary_number(pkt, flags, 4, row); col_len = 4; break;
            case 8: col_len_expanded = convert_binary_number(pkt, flags, 8, row); col_len = 8; break;
            // Date, datetime
            case 10:
            case 12:
                     col_len = ((u_short)*pkt) + 1;
                     col_len_expanded = convert_binary_datetime(pkt, row);
                     break;
            // Time
            case 11:
                     col_len = ((u_short)*pkt) + 1;
                     col_len_expanded = convert_binary_time(pkt, row);
                     break;
            // Strings and BLOBS
            case  15:
            case 249:
            case 250:
            case 251:
            case 252:
            case 253:
            case 254:
                      col_len = col_len_expanded = ((u_short)*pkt) + 1; // This can be LC
                      bit = decode_len(pkt);
                      col_len += (bit > 1 ? bit : 0); // If it was LC, bit will be > 1
                      col_len_expanded = col_len;
                      memcpy(row, pkt, col_len);
                      break;
            default:
               break;
         }

         row     += col_len_expanded;
         row_len += col_len_expanded;
         pkt     += col_len;
      }
   }

   row = txt_row;

   return pkt_row(row, row_len);
}

/*
   MySQL prepared statement metadata pkt:
     0 byte         1 byte
     Stmt ID        4 bytes
     Num. columns   2 bytes
     Num. params    2 bytes
     0 byte         1 byte
     Warnings       2 bytes
*/
int pkt_stmt_meta(u_char *pkt, u_int len)
{
   if(len != 12) return PKT_WRONG_TYPE;

   u_int   stmt_id;
   u_short n_cols;
   u_short n_params;
   u_short warns;

   *pkt++;
   stmt_id = G4(pkt);
   pkt += 4;
   n_cols = G2(pkt);
   pkt += 2;
   n_params = G2(pkt);
   pkt += 3;
   warns = G2(pkt);

   printf("Statement ID %u <%u params %u columns %u warnings>", stmt_id, n_params, n_cols, warns);

   return PKT_HANDLED;
}

int pkt_stmt_execute(u_char *pkt, u_int len)
{
   if(!MATCH(*pkt, COM_STMT_EXECUTE)) return PKT_WRONG_TYPE;

   u_int   stmt_id;
   u_int   itr;
   /*
     Can't figure these unless we track the number of params for each stmt ID
   u_short null_bitmap;
   u_short new_prep;
   */

   pkt++;
   stmt_id = G4(pkt);
   pkt += 5;
   itr = G4(pkt);

   printf("COM_EXECUTE Statement ID %u <iteration %u>", stmt_id, itr);

   return PKT_HANDLED;
}

void dump_pkt(u_char *pkt, u_int len, char only_hex)
{
   int i;

   printf("::DUMP:: ");
   for(i = 0; i < len; i++) {
      if(isprint(pkt[i]) && !only_hex) printf("%c ", pkt[i]);
      else printf("%02x ", pkt[i]);
   }
   printf("::DUMP::");
}

// Return argument of simple one-argument only commands
const u_char *get_arg(u_char *pkt, u_int len)
{
   static u_char arg[MAX_COM_ARG_LEN];

   if(len > MAX_COM_ARG_LEN) len = MAX_COM_ARG_LEN;

   pkt++;
   memcpy(arg, pkt, len - 1);
   arg[len - 1] = 0;

   return (const u_char *)arg;
}

u_char *my_strcpy(u_char *to, u_char *from, u_int to_size)
{
   u_int str_len, real_str_len;

   str_len = real_str_len = (u_int)*from;

   if(!str_len) {
      if(to) to[0] = 0;
      return (from + 1);
   }

   from++;

   if(!to)
      return (from + str_len);

   if(str_len > (to_size - 1)) str_len = to_size - 1;
   memcpy(to, from, str_len);
   to[str_len] = 0;

   return (from + real_str_len);
}

u_int G3(u_char *pkt)
{
   u_char buff[4];

   memcpy(buff, pkt, 3);
   buff[3] = 0;

   return *((u_int *)buff);
}

u_int convert_binary_number(u_char *number, u_short flags, u_int bytes, u_char *to)
{
   char      sz[16];
   u_int     len;
   long long ln = 0;
   int       n = 0;

   if(bytes == 1)       n = *number;
   else if(bytes == 2)  n = G2(number)
   else if(bytes == 4)  n = G4(number)
   else if(bytes == 8)  { memcpy((void *)&ln, number, 8); }

   // TODO: Using longlong for long makes long unsigned?
   if(bytes != 8) {
      if(flags & UNSIGNED_FLAG)
         sprintf(sz, "%u", n);
      else
         sprintf(sz, "%d", n);
   }
   else {
      if(flags & UNSIGNED_FLAG)
         sprintf(sz, "%llu", ln);
      else
         sprintf(sz, "%lld", ln);
   }

   len = strlen(sz);

   to[0] = len;
   memcpy(to + 1, sz, len);

   return len + 1;
}

u_int convert_binary_datetime(u_char *d, u_char *to)
{
   u_char  dt_len = *d;
   u_short year  = 0;
   u_char  month = 0;
   u_char  day   = 0;
   u_char  hour  = 0;
   u_char  min   = 0;
   u_char  sec   = 0;
   char    sz[11];
   u_short len;

   if(dt_len) {
      d++;
      year  = G2(d)
      d    += 2;
      month = *d++;
      day   = *d++;
   }

   sprintf(sz, "%04u-%02u-%02u", year, month, day);
   to[0] = len = strlen(sz);
   memcpy(to + 1, sz, len);

   if(dt_len == 7) { // Datetime
      hour = *d++;
      min  = *d++;
      sec  = *d++;

      sprintf(sz,  " %02u:%02u:%02u", hour, min, sec);
      to[0] = to[0] + strlen(sz);
      memcpy(to + 1 + len, sz, strlen(sz));
      len += strlen(sz);
   }

   return len + 1;
}

u_int convert_binary_time(u_char *t, u_char *to)
{
   u_char  sign  = 0;
   u_short days  = 0;
   u_short hours = 0;
   u_short mins  = 0;
   u_short secs  = 0;
   char    sz[11];
   u_short len;

   if(*t) {
      t++;
      sign  = *t++;
      days  = G4(t)
      t    += 4;
      hours = *t++;
      mins  = *t++;
      secs  = *t++;
   }

   if(days)
      hours += (days * 24);

   sprintf(sz, "%s%02u:%02u:%02u", (sign ? "-" : ""), hours, mins, secs);
   to[0] = len = strlen(sz);
   memcpy(to + 1, sz, len);

   return len + 1;
}

u_short decode_len(u_char *pkt)
{
   /*
     0-251  0-FB  Same
     252    FC    Len in next 2
     253    FD    Len in next 4
     254    FE    Len in next 8
   */

   if(*pkt <= 0xFB) { decoded_len = *pkt;        return 1; }
   if(*pkt == 0xFC) { decoded_len = G2(pkt + 1)  return 2; }
   if(*pkt == 0xFD) { decoded_len = G4(pkt + 1)  return 4; }
//   if(*pkt == 0xFE) { decoded_len = *((ulonglong *)&pkt + 1);  return 8; }
   if(*pkt == 0xFE) { memcpy((void *)&decoded_len, pkt + 1, 8); return 8; }

   return 0;
}

const char *get_field_type(u_char type)
{
   if(type < 246)
      return field_type_names[type];

   switch(type) {
      case MYSQL_TYPE_NEWDECIMAL:  return "new decimal";
      case MYSQL_TYPE_ENUM:        return "enum";
      case MYSQL_TYPE_SET:         return "set";
      case MYSQL_TYPE_TINY_BLOB:   return "tiny BLOB";
      case MYSQL_TYPE_MEDIUM_BLOB: return "medium BLOB";
      case MYSQL_TYPE_LONG_BLOB:   return "long BLOB";
      case MYSQL_TYPE_BLOB:        return "BLOB";
      case MYSQL_TYPE_VAR_STRING:  return "var string";
      case MYSQL_TYPE_STRING:      return "string";
      case MYSQL_TYPE_GEOMETRY:    return "geometry";
   }

   return "unknown";
}

void unmask_caps(u_int caps)
{
   printf("(Caps: ");
   if(caps & CLIENT_LONG_PASSWORD)     printf("Long password, ");
   if(caps & CLIENT_FOUND_ROWS)        printf("Found rows, ");
   if(caps & CLIENT_LONG_FLAG)         printf("Get all column flags, ");
   if(caps & CLIENT_CONNECT_WITH_DB)   printf("Connect w/DB, ");
   if(caps & CLIENT_NO_SCHEMA)         printf("No schema, ");
   if(caps & CLIENT_COMPRESS)          printf("Compression, ");
   if(caps & CLIENT_ODBC)              printf("ODBC client, ");
   if(caps & CLIENT_LOCAL_FILES)       printf("LOAD DATA LOCAL, ");
   if(caps & CLIENT_IGNORE_SPACE)      printf("Ignore space, ");
   if(caps & CLIENT_PROTOCOL_41)       printf("4.1 protocol, ");
   if(caps & CLIENT_INTERACTIVE)       printf("Interactive, ");
   if(caps & CLIENT_SSL)               printf("SSL, ");
   if(caps & CLIENT_IGNORE_SIGPIPE)    printf("Ignore SIGPIPE, ");
   if(caps & CLIENT_TRANSACTIONS)      printf("Transactions, ");
   if(caps & CLIENT_RESERVED)          printf("Reserved, ");
   if(caps & CLIENT_SECURE_CONNECTION) printf("4.1 authentication, ");
   if(caps & CLIENT_MULTI_STATEMENTS)  printf("Multi-statements, ");
   if(caps & CLIENT_MULTI_RESULTS)     printf("Multi-results");
   printf(")");
}

void unmask_status(u_short status)
{
   printf("(Status: ");
   if(status & SERVER_STATUS_IN_TRANS)             printf("Transaction started, ");
   if(status & SERVER_STATUS_AUTOCOMMIT)           printf("Auto-commit, ");
   if(status & SERVER_STATUS_MORE_RESULTS)         printf("More results, ");
   if(status & SERVER_MORE_RESULTS_EXISTS)         printf("Next query, ");
   if(status & SERVER_QUERY_NO_GOOD_INDEX_USED)    printf("No good index used, ");
   if(status & SERVER_QUERY_NO_INDEX_USED)         printf("No index used, ");
   if(status & SERVER_STATUS_CURSOR_EXISTS)        printf("Cursor ready, ");
   if(status & SERVER_STATUS_LAST_ROW_SENT)        printf("Last row sent, ");
   if(status & SERVER_STATUS_DB_DROPPED)           printf("DB dropped, ");
   if(status & SERVER_STATUS_NO_BACKSLASH_ESCAPES) printf("No backslash escapes");
   printf(")");
}
