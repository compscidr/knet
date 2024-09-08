package com.jasonernst.knet.ip

/**
 * Protocol numbers for the protocol field in IPv4 packets or NextHeader field in Ipv6 packets
 *
 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
enum class IPType(
    val value: UByte,
) {
    HOPOPT(0u),
    ICMP(1u),
    IGMP(2u),
    GGP(3u),
    IPV4(4u),
    ST(5u),
    TCP(6u),
    CBT(7u),
    EGP(8u),
    IGP(9u),
    BBN_RCC_MON(10u),
    NVP_II(11u),
    PUP(12u),
    ARGUS(13u),
    EMCON(14u),
    XNET(15u),
    CHAOS(16u),
    UDP(17u),
    MUX(18u),
    DCN_MEAS(19u),
    HMP(20u),
    PRM(21u),
    XNS_IDP(22u),
    TRUNK_1(23u),
    TRUNK_2(24u),
    LEAF_1(25u),
    LEAF_2(26u),
    RDP(27u),
    IRTP(28u),
    ISO_TP4(29u),
    NETBLT(30u),
    MFE_NSP(31u),
    MERIT_INP(32u),
    DCCP(33u),
    THREE_PC(34u),
    IDPR(35u),
    XTP(36u),
    DDP(37u),
    IDPR_CMTP(38u),
    TP_PP(39u),
    IL(40u),
    IPv6(41u),
    SDRP(42u),
    IPV6_ROUTE(43u),
    IPV6_FRAG(44u),
    IDRP(45u),
    RSVP(46u),
    GRE(47u),
    DSR(48u),
    BNA(49u),
    ESP(50u),
    AH(51u),
    I_NLSP(52u),
    SWIPE(53u),
    NARP(54u),
    MOBILE(55u),
    TLSP(56u),
    SKIP(57u),
    IPV6_ICMP(58u),
    IPV6_NONXT(59u),
    IPV6_OPTS(60u),
    INTERNAL(61u),
    CFTP(62u),
    LOCAL(63u),
    SAT_EXPAK(64u),
    KRYPTOLAN(65u),
    RVD(66u),
    IPPC(67u),
    DISTRIBUTED_FS(68u),
    SAT_MON(69u),
    VISA(70u),
    IPCV(71u),
    CPNX(72u),
    CPHB(73u),
    WSN(74u),
    PVP(75u),
    BR_SAT_MON(76u),
    SUN_ND(77u),
    WB_MON(78u),
    WB_EXPAK(79u),
    ISO_IP(80u),
    VMTP(81u),
    SECURE_VMPT(82u),
    VINES(83u),
    IPTM(84u),
    NSFNET_IGP(85u),
    DGP(86u),
    TCF(87u),
    EIGRP(88u),
    OSPFIGP(89u),
    SPRITE_RPC(90u),
    LARP(91u),
    MTP(92u),
    AX_25(93u),
    IPIP(94u),
    MICP(95u),
    SCC_SP(96u),
    EHTERIP(97u),
    ENCAP(98u),
    ENCRYPTION(99u),
    GMTP(100u),
    IFMP(101u),
    PNNI(102u),
    PIM(103u),
    ARIS(104u),
    SCPS(105u),
    QNX(106u),
    AN(107u),
    IP_COMP(108u),
    SNP(109u),
    COMPAQ_PEER(110u),
    IPX_IN_IP(111u),
    VRRP(112u),
    PGM(113u),
    ZERO_HOP(114u),
    L2TP(115u),
    DDX(116u),
    IATP(117u),
    STP(118u),
    SRP(119u),
    UTI(120u),
    SMP(121u),
    SM(122u),
    PTP(123u),
    ISIS_IPV4(124u),
    FIRE(125u),
    CRTP(126u),
    CRUDP(127u),
    SSCOPMCE(128u),
    IPLT(129u),
    SPS(130u),
    PIPE(131u),
    SCTP(132u),
    FC(133u),
    RSVP_E2E_IGNORE(134u),
    MOBILITY_HEADER(135u),
    UPDLITE(136u),
    MPLS_IN_IP(137u),
    MANET(138u),
    HIP(139u),
    SHIM6(140u),
    WESP(141u),
    ROHC(142u),
    ETHERNET(143u),
    AGGFRAG(144u),
    NSH(145u),
    ;

    companion object {
        fun fromValue(value: UByte) = entries.first { it.value == value }
    }
}
