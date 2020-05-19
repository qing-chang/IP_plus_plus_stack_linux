extern struct proto udppp_prot;
extern const struct proto_ops inetpp_dgram_ops;

int udppp_init(void);
void udppp_exit(void);
int inetpp_add_protocol(const struct net_protocol *prot, unsigned char protocol);
int inetpp_del_protocol(const struct net_protocol *prot, unsigned char protocol);
int inetpp_register_protosw(struct inet_protosw *p);
void inetpp_unregister_protosw(struct inet_protosw *p);