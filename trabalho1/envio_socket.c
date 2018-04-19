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
#define MY_DEST_MAC0 0x70
#define MY_DEST_MAC1 0x8b
#define MY_DEST_MAC2 0xcd
#define MY_DEST_MAC3 0xe5
#define MY_DEST_MAC4 0x5d
#define MY_DEST_MAC5 0x32

// para filtrar no wireshark
// eth.dst == 70:8b:cd:e5:5d:32 and eth.src == 70:8b:cd:e5:5d:32

// Atencao!! Confira no /usr/include do seu sisop o nome correto
// das estruturas de dados dos protocolos.

typedef unsigned char MacAddress[MAC_ADDR_LEN];
extern int errno;
char ifName[IFNAMSIZ];
unsigned char buff[1500];

void monta_pacote(int opcao) {
  // as struct estao descritas nos seus arquivos .h
  // por exemplo a ether_header esta no net/ethert.h
  // a struct ip esta descrita no netinet/ip.h
  struct ether_header *eth;

  // coloca o ponteiro do header ethernet apontando para a 1a. posicao do buffer
  // onde inicia o header do ethernet.
  eth = (struct ether_header *) &buff[0];

  //Endereco Mac Destino
  eth->ether_dhost[0] = MY_DEST_MAC0;
  eth->ether_dhost[1] = MY_DEST_MAC1;
  eth->ether_dhost[2] = MY_DEST_MAC2;
  eth->ether_dhost[3] = MY_DEST_MAC3;
  eth->ether_dhost[4] = MY_DEST_MAC4;
  eth->ether_dhost[5] = MY_DEST_MAC5;

  //Endereco Mac Origem
  eth->ether_shost[0] = MY_DEST_MAC0;
  eth->ether_shost[1] = MY_DEST_MAC1;
  eth->ether_shost[2] = MY_DEST_MAC2;
  eth->ether_shost[3] = MY_DEST_MAC3;
  eth->ether_shost[4] = MY_DEST_MAC4;
  eth->ether_shost[5] = MY_DEST_MAC5;

  eth->ether_type = htons(0X800);

  if(opcao == 1) {
    printf("\n\nEntrou no IPv4 e UDP\n\n");

  } else if(opcao == 2) {
    printf("\n\nEntrou no IPv4 e TCP\n\n");
  } else if(opcao == 3) {
    printf("\n\nEntrou no IPv6 e UDP\n\n");
  } else {
    printf("\n\nEntrou no IPv6 e TCP\n\n");
  }

}

int main(int argc, char*argv[])
{
  int sock, i;
  struct ifreq ifr;
  struct sockaddr_ll to;
  socklen_t len;
  unsigned char addr[6];

  int escolha; // Menu

  if(argc > 1) {
    strcpy(ifName, argv[1]);
  } else {
    strcpy(ifName, DEFAULT_IF);
    printf("Utilizando interface padrão eth0!\n\n");
  }

  // Inicializa com 0 os bytes de memoria apontados por ifr.
	memset(&ifr, 0, sizeof(ifr));

  // Criacao do socket. Uso do protocolo Ethernet em todos os pacotes. De um "man" para ver os parametros.
  // htons: converte um short (2-byte) integer para standard network byte order.
	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
    printf("Erro na criacao do socket.\n");
    exit(1);
 	}

  // Pega o index da interface
  memset(&ifr, 0, sizeof(struct ifreq));
  strncpy(ifr.ifr_name, ifName, IFNAMSIZ-1);
  if(ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
    perror("SIOCGIFINDEX");

  /* Identicacao de qual maquina (MAC) deve receber a mensagem enviada no socket. */
	to.sll_protocol= htons(ETH_P_ALL);
	to.sll_ifindex = ifr.ifr_ifindex; /* indice da interface pela qual os pacotes serao enviados */
	addr[0]=0x00;
	addr[0]=0x06;
	addr[0]=0x5B;
	addr[0]=0x28;
	addr[0]=0xAE;
	addr[0]=0x73;
	memcpy (to.sll_addr, addr, 6);
	len = sizeof(struct sockaddr_ll);

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
        case 1: monta_pacote(1);
                break;
        case 2: monta_pacote(2);
                break;
        case 3: monta_pacote(3);
                break;
        case 4: monta_pacote(4);
                break;
        case 5: printf("\nFinalizando ferramenta...\n\n");
                exit(0);
        default: printf("\nOpção inválida!..\n\n");
                break;
    }

    if(sendto(sock, (char *) buff, sizeof(buff), 0, (struct sockaddr*) &to, len)<0)
      printf("sendto maquina destino.\n");

  }
}
