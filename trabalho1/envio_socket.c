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
#include <net/if.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define ETHERTYPE_LEN 2
#define MAC_ADDR_LEN 6
#define BUFFER_LEN 1518

#define DEFAULT_IF "eth0" // interface padrao se n for passada por parametro
#define MY_DEST_MAC0 0xa4
#define MY_DEST_MAC1 0x1f
#define MY_DEST_MAC2 0x72
#define MY_DEST_MAC3 0xf5
#define MY_DEST_MAC4 0x90
#define MY_DEST_MAC5 0x80

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

typedef unsigned char MacAddress[MAC_ADDR_LEN];
extern int errno;
char ifName[IFNAMSIZ];

void configuraPacote(int opcao) {

  struct ifreq if_idx;
  struct ifreq if_mac;
  char sendbuf[1024];
  int sockFd = 0, retValue = 0;
  int tx_len = 0;
  struct ether_header *eh = (struct ether_header *) sendbuf;
  struct sockaddr_ll socket_address;

  if(opcao == 1) {
    printf("\n\nEntrou no IPv4 e UDP\n\n");
  } else if(opcao == 2) {
    printf("\n\nEntrou no IPv4 e TCP\n\n");
  } else if(opcao == 3) {
    printf("\n\nEntrou no IPv6 e UDP\n\n");
  } else {
    printf("\n\nEntrou no IPv6 e TCP\n\n");
  }

  /* Criacao do socket. Todos os pacotes devem ser construidos a partir do protocolo Ethernet. */
  /* De um "man" para ver os parametros.*/
  /* htons: converte um short (2-byte) integer para standard network byte order. */
  if((sockFd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    printf("Erro na criacao do socket.\n");
    exit(1);
  }

  // Pega o index da interface
  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
  if(ioctl(sockFd, SIOCGIFINDEX, &if_idx) < 0)
    perror("SIOCGIFINDEX");

  // Pega o endereço MAC da interface
  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
  if(ioctl(sockFd, SIOCGIFHWADDR, &if_mac) < 0)
    perror("SIOCGIFHWADDR");

  // Pega o endereço IP da interface
  //memset(&if_ip, 0, sizeof(struct ifreq));
  //strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
  //if(ioctl(sockFd, SIOCGIFADDR, &if_ip) < 0)
  //  perror("SIOCGIFADDR");

  memset(sendbuf, 0, 1024);

  // Cabecalho Ethernet
  eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
  eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
  eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
  eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
  eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
  eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
  eh->ether_dhost[0] = MY_DEST_MAC0;
  eh->ether_dhost[1] = MY_DEST_MAC1;
  eh->ether_dhost[2] = MY_DEST_MAC2;
  eh->ether_dhost[3] = MY_DEST_MAC3;
  eh->ether_dhost[4] = MY_DEST_MAC4;
  eh->ether_dhost[5] = MY_DEST_MAC5;
  eh->ether_type = htons(ETH_P_IP);
  tx_len += sizeof(struct ether_header);


  // Indice da interface pela qual os pacotes serao enviados
  socket_address.sll_ifindex = if_idx.ifr_ifindex;
  // Address length
  socket_address.sll_halen = ETH_ALEN;
  // Mac destino
  socket_address.sll_addr[0] = MY_DEST_MAC0;
  socket_address.sll_addr[1] = MY_DEST_MAC1;
  socket_address.sll_addr[2] = MY_DEST_MAC2;
  socket_address.sll_addr[3] = MY_DEST_MAC3;
  socket_address.sll_addr[4] = MY_DEST_MAC4;
  socket_address.sll_addr[5] = MY_DEST_MAC5;


  /*
  // Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket.
  destAddr.sll_family = htons(PF_PACKET);
  destAddr.sll_protocol = htons(ETH_P_ALL);
  destAddr.sll_halen = 6;
  destAddr.sll_ifindex = 2;  // indice da interface pela qual os pacotes serao enviados. Eh necessário conferir este valor.
  memcpy(&(destAddr.sll_addr), destMac, MAC_ADDR_LEN);

  // Cabecalho Ethernet
  memcpy(buffer, destMac, MAC_ADDR_LEN);
  memcpy((buffer+MAC_ADDR_LEN), localMac, MAC_ADDR_LEN);
  memcpy((buffer+(2*MAC_ADDR_LEN)), &(etherTypeT), sizeof(etherTypeT));
  */
  // Add some data
  //memcpy((sendbuf+ETHERTYPE_LEN+(2*MAC_ADDR_LEN)), dummyBuf, 50);

  int i = 0;
  while(i < 5) {
    // Envia pacotes de 64 bytes
    if((retValue = sendto(sockFd, sendbuf, tx_len, 0, (struct sockaddr *)&(socket_address), sizeof(struct sockaddr_ll))) < 0) {
       printf("ERROR! sendto() \n");
       exit(1);
    }
    printf("Send success (%d).\n", retValue);
    i++;
  }
}

int main(int argc, char*argv[])
{
  int escolha = 1;

  if(argc > 1) {
    strcpy(ifName, argv[1]);
  } else {
    strcpy(ifName, DEFAULT_IF);
    printf("Utilizando interface padrão eth0!\n\n");
  }

  while(escolha!=5) {
    printf("\n ################################################### ");
    printf("\nTrabalho 1 LAB-REDES");
    printf("\n 1 - Enviar utilizando IPv4 e UDP ");
    printf("\n 2 - Enviar utilizando IPv4 e TCP ");
    printf("\n 3 - Enviar utilizando IPv6 e UDP ");
    printf("\n 4 - Enviar utilizando IPv6 e TCP ");
    printf("\n 5 - Fechar Programa ");
    printf("\n\n Escolha uma opcao: ");
    scanf("%d",&escolha);

    switch(escolha) {
        case 1: configuraPacote(1);
                break;
        case 2: configuraPacote(2);
                break;
        case 3: configuraPacote(3);
                break;
        case 4: configuraPacote(4);
                break;
        case 5: printf("\nFinalizando ferramenta...\n\n");
                exit(0);
        default: printf("\nOpção inválida!..\n\n");
                break;
    }

  }
}
