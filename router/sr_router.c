#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
  sr_arp_hdr_t *received_arp_hdr =  (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  sr_ethernet_hdr_t *received_ether_hdr =  (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
  struct sr_if *current_interface = sr_get_interface(sr, interface);

  /* ARP packet is requesting */
  if (arp_op_request == ntohs(received_arp_hdr->ar_op)) {
    if (received_arp_hdr->ar_tip != current_interface->ip) {
      printf("ARP packet is not targeting this interface\n");
      return;
    }
    printf("ARP packet is requesting")
    /* Send reply packet to the sender */
    uint8_t *reply_packet = (uint8_t *) malloc(len);

    /* Set values for reply ethernet header */
    sr_ethernet_hdr_t *reply_ether_hdr =  (sr_ip_hdr_t *) (reply_packet + sizeof(sr_ethernet_hdr_t));
    /* the source address is the address of router's current interface */
    memcpy(reply_ether_hdr->ether_shost, current_interface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    /* the destination address is the source address of received packet */
    memcpy(reply_ether_hdr->ether_shost, received_arp_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    reply_ether_hdr->ether_type = htons(ethertype_arp);

    /* Set values for reply ARP header */
    sr_arp_hdr_t *reply_arp_hdr =  (sr_arp_hdr_t *) (reply_packet + sizeof(sr_ethernet_hdr_t));
    reply_arp_hdr->ar_hrd = received_arp_hdr->ar_hrd;
    reply_arp_hdr->ar_pro = received_arp_hdr->ar_pro;
    reply_arp_hdr->ar_hln = received_arp_hdr->ar_hln;
    reply_arp_hdr->ar_pln = received_arp_hdr->ar_pln;
    reply_arp_hdr->ar_op = htons(arp_op_reply);
    /* Sender of the reply packet is the router's current interface */
    memcpy(reply_arp_hdr->ar_sha, current_interface->addr, ETHER_ADDR_LEN);
    reply_arp_hdr->ar_sip = current_interface->ip;
    /* Target of the reply packet is the source of received packet */
    memcpy(reply_arp_hdr->ar_tha, received_arp_hdr->ether_shost, ETHER_ADDR_LEN);
    reply_arp_header->ar_tip = received_arp_hdr->ar_sip;

    /* Send the reply packet and free the malloc space */
    sr_send_packet(sr, reply_packet, len, interface);
    free(reply_packet);
  }

  /* ARP packet is replying */
  else if (arp_op_reply == ntohs(received_arp_header->ar_op)) { 
    printf("ARP packet is replying")
  }
    return;
}
