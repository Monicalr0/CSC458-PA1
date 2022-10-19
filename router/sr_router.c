#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

void handle_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  if (len < sizeof(sr_ethernet_hdr_t)) {
    fprintf(stderr,"Error: Packet is too small\n");
    return;
  }

  if (ethertype(packet) == ethertype_ip){
    printf("Received packet is IP\n");
  }
  else if (ethertype(packet) == ethertype_arp){
    printf("Received packet is ARP\n");
    handle_arp(sr, packet, len, interface);
  }

}/* end sr_ForwardPacket */

void handle_arp(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    fprintf(stderr,"Error: Packet is too small\n");
    return;
  }
  sr_ethernet_hdr_t *received_ether_hdr = (sr_ethernet_hdr_t *) (packet);
  sr_arp_hdr_t *received_arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *current_interface = sr_get_interface(sr, interface);

  /* ARP packet is a request for IP address*/
  if (arp_op_request == ntohs(received_arp_hdr->ar_op)) {
    /* The current interface of the router does not have the requested IP address*/
    if (received_arp_hdr->ar_tip != current_interface->ip) {
      printf("ARP packet is not targeting this interface\n");
      return;
    }
    printf("ARP packet is requesting");
    /* Send reply packet containing information of the current interface to the sender of ARP packet*/
    uint8_t *reply_packet = (uint8_t *) malloc(len);

    /* Set values for reply ethernet header */
    sr_ethernet_hdr_t *reply_ether_hdr = (sr_ethernet_hdr_t *) (reply_packet);
    /* the source address is the address of router's current interface */
    memcpy(reply_ether_hdr->ether_shost, current_interface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    /* the destination address is the source address of received packet */
    memcpy(reply_ether_hdr->ether_dhost, received_ether_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    reply_ether_hdr->ether_type = htons(ethertype_arp);

    /* Set values for reply ARP header */
    sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *) (reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_arp_hdr->ar_hrd = received_arp_hdr->ar_hrd;
    reply_arp_hdr->ar_pro = received_arp_hdr->ar_pro;
    reply_arp_hdr->ar_hln = received_arp_hdr->ar_hln;
    reply_arp_hdr->ar_pln = received_arp_hdr->ar_pln;
    reply_arp_hdr->ar_op = htons(arp_op_reply);
    /* Sender of the reply packet is the router's current interface */
    memcpy(reply_arp_hdr->ar_sha, current_interface->addr, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_sip = current_interface->ip;
    /* Target of the reply packet is the source of received packet */
    memcpy(reply_arp_hdr->ar_tha, received_ether_hdr->ether_shost, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_tip = received_arp_hdr->ar_sip;

    /* Send the reply packet to the sender and free the malloc space */
    sr_send_packet(sr, reply_packet, len, interface);
    free(reply_packet);
  }

  /* ARP packet is a reply with information of the sender to the current interface */
  else if (arp_op_reply == ntohs(received_arp_hdr->ar_op)) { 
    printf("ARP packet is replying");
    /* Insert the received packet's source IP to MAC mapping in the router's cache, and marks it valid */
    struct sr_arpcache *cache = &(sr->cache);
    unsigned char *mac = received_arp_hdr->ar_sha;
    uint32_t ip = received_arp_hdr->ar_sha;
    struct sr_arpreq *request = sr_arpcache_insert(cache, mac, ip);

    /* If succesfully inserted to the router's cache*/
    if (request) {
      struct sr_packet *waiting_packet = req->packets;
      /*Send all packets waiting for the request to finish*/
      while (waiting_packet) {
        /*Initialize header for the raw ethernet frame of the waiting packet*/
        sr_ethernet_hdr_t *waiting_ether_hdr = (sr_ethernet_hdr_t *) waiting_packet->buf;
        /* the source address is the address of router's current interface */
        memcpy(waiting_ether_hdr->ether_shost, current_interface->addr, ETHER_ADDR_LEN);
        /* the destination address is the source address of received packet */
        memcpy(waiting_ether_hdr->ether_dhost, received_arp_hdr->ar_sha, ETHER_ADDR_LEN);

        /* Send the waiting packet to the sender and set to the next packet until NULL*/
        sr_send_packet(sr, waiting_packet->buf, waiting_packet->len, interface);
        waiting_packet = waiting_packet->next;
      }
      /* Free all memory associated with this arp request entry*/
      sr_arpreq_destroy(cache, request);
    }
  }
  return;
}
