/*-------------------------------------------------------------*/
/* Exemplo Socket Raw - envio de mensagens                     */
/*-------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#define ETHERTYPE_LEN 2
#define MAC_ADDR_LEN 6
#define BUFFER_LEN 1518

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

typedef unsigned char MacAddress[MAC_ADDR_LEN];
extern int errno;

int main()
{
  int sockFd = 0, retValue = 0;
  char buffer[BUFFER_LEN], dummyBuf[50];
  struct sockaddr_ll destAddr;
  short int etherTypeT = htons(0x8200);

  /* Configura MAC Origem e Destino */
  MacAddress localMac = {0x00, 0x0B, 0xCD, 0xA8, 0x6D, 0x91};
  MacAddress destMac = {0x00, 0x17, 0x9A, 0xB3, 0x9E, 0x16};

  /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
  /* De um "man" para ver os parametros.*/
  /* htons: converte um short (2-byte) integer para standard network byte order. */
  if((sockFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    printf("Erro na criacao do socket.\n");
    exit(1);
  }

  /* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
  destAddr.sll_family = htons(PF_PACKET);
  destAddr.sll_protocol = htons(ETH_P_ALL);
  destAddr.sll_halen = 6;
  destAddr.sll_ifindex = 2;  /* indice da interface pela qual os pacotes serao enviados. Eh necess�rio conferir este valor. */
  memcpy(&(destAddr.sll_addr), destMac, MAC_ADDR_LEN);

  /* Cabecalho Ethernet */
  memcpy(buffer, destMac, MAC_ADDR_LEN);
  memcpy((buffer+MAC_ADDR_LEN), localMac, MAC_ADDR_LEN);
  memcpy((buffer+(2*MAC_ADDR_LEN)), &(etherTypeT), sizeof(etherTypeT));

  /* Add some data */
  memcpy((buffer+ETHERTYPE_LEN+(2*MAC_ADDR_LEN)), dummyBuf, 50);

  while(1) {
    /* Envia pacotes de 64 bytes */
    if((retValue = sendto(sockFd, buffer, 64, 0, (struct sockaddr *)&(destAddr), sizeof(struct sockaddr_ll))) < 0) {
       printf("ERROR! sendto() \n");
       exit(1);
    }
    printf("Send success (%d).\n", retValue);
  }
}
