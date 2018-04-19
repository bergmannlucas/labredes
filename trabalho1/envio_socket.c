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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
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

//typedef unsigned char MacAddress[MAC_ADDR_LEN];
//extern int errno;
char ifName[IFNAMSIZ];
unsigned char buff[1500];
struct ifreq ifr;

// Função de checksum
unsigned short checksum(unsigned short *buf, int nwords)
{
    //

    unsigned long sum;

    for(sum=0; nwords>0; nwords--)
        sum += *buf++;

    sum = (sum >> 16) + (sum &0xffff);

    sum += (sum >> 16);

    return (unsigned short)(~sum);
}

// Função de checksum para o UDP
uint16_t check_udp_sum(uint8_t *buffer, int len)
{
    unsigned long sum = 0;
    struct iphdr *tempI = (struct iphdr *)(buff);
    struct udphdr *tempH = (struct udphdr *)(buff + sizeof(struct iphdr));
    //struct dnsheader *tempD = (struct dnsheader *)(buff + sizeof(struct iphdr) + sizeof(struct udphdr));
    tempH->check = 0;
    sum = checksum( (uint16_t *)   & (tempI->saddr) , 8 );
    sum += checksum((uint16_t *) tempH, len);

    sum += ntohs(IPPROTO_UDP + len);


    sum = (sum >> 16) + (sum & 0x0000ffff);
    sum += (sum >> 16);

    return (uint16_t)(~sum);

}

void monta_pacote(int opcao) {
  // as struct estao descritas nos seus arquivos .h
  // por exemplo a ether_header esta no net/ethert.h
  // a struct ip esta descrita no netinet/ip.h
  struct ether_header *eth;
  struct iphdr *ipv4;
  struct udphdr *udp;

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
    // coloca o ponteiro do header ip apontando para a 14. posicao do buffer
    // onde inicia o header do ip.
    ipv4 = (struct iphdr*)&buff[14];

    ipv4->version = 4;
    ipv4->ihl = 5; // IPv4
    ipv4->tos = 0;
    unsigned short int packetLength = (sizeof(struct iphdr) + sizeof(struct udphdr)); // length + dataEnd_size == UDP_payload_size
    ipv4->tot_len = htons(packetLength); // Tá errado
    ipv4->id = htons(rand());
    ipv4->ttl = 110;
    ipv4->protocol = 17; // UDP
    ipv4->saddr = inet_addr(inet_ntoa((((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr))); // IP ORIGEM
    ipv4->daddr = inet_addr(inet_ntoa((((struct sockaddr_in *)&(ifr.ifr_addr))->sin_addr))); // IP DESTINO

    // coloca o ponteiro do header udp apontando para a 34. posicao do buffer
    // onde inicia o header do udp.
    udp = (struct udphdr *) &buff[34];
    udp->source = htons(53);
    udp->dest = htons(33333);
    udp->len = htons(packetLength); // Tá errado

    ipv4->check = checksum((unsigned short*)(buff + sizeof(struct ether_header)), (sizeof(struct iphdr)/2));
    udp->check = check_udp_sum(buff, packetLength - sizeof(struct iphdr));

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
  //to.sll_halen = 6;
	addr[0]=MY_DEST_MAC0;
	addr[0]=MY_DEST_MAC1;
	addr[0]=MY_DEST_MAC2;
	addr[0]=MY_DEST_MAC3;
	addr[0]=MY_DEST_MAC4;
	addr[0]=MY_DEST_MAC5;
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
