/*
 * Copyright (C) 2017 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 * @author  Martine Lenders <mlenders@inf.fu-berlin.de>
 */

#include <assert.h>
#include <kernel_defines.h>

#include "net/gnrc/ipv6/nib.h"
#include "net/gnrc/netif/internal.h"
#include "net/gnrc/sixlowpan/nd.h"

#include "_nib-6lr.h"

#define ENABLE_DEBUG 0
#include "debug.h"
#include "_nib-router.h"

#if IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_6LR)

static char addr_str[IPV6_ADDR_MAX_STR_LEN];

/**
 * @brief  If source IP address not derived from link-layer address, add compression context.
 * @return -ENOTSUP if not applicable
 * @return -1 on failure
 * @return 0 on success
 */
static int _setup_opportunistic_compression_context(gnrc_netif_t *netif, const ipv6_hdr_t *ipv6,
                                              const sixlowpan_nd_opt_ar_t *aro);

static uint8_t _update_nce_ar_state(gnrc_netif_t *netif,
                                    const sixlowpan_nd_opt_ar_t *aro,
                                    _nib_onl_entry_t *nce)
{
    if (nce != NULL) {
        memcpy(&nce->eui64, &aro->eui64, sizeof(aro->eui64));
        _evtimer_add(nce, GNRC_IPV6_NIB_ADDR_REG_TIMEOUT,
                     &nce->addr_reg_timeout,
                     byteorder_ntohs(aro->ltime) * SEC_PER_MIN * MS_PER_SEC);
        if (IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_ARSM)) {
            switch (_get_nud_state(nce)) {
            case GNRC_IPV6_NIB_NC_INFO_NUD_STATE_UNMANAGED:
            case GNRC_IPV6_NIB_NC_INFO_NUD_STATE_REACHABLE:
                /* nothing to do */
                break;
            default:
                assert(netif != NULL);
                evtimer_del(&_nib_evtimer, &nce->nud_timeout.event);
                _set_nud_state(netif, nce,
                               GNRC_IPV6_NIB_NC_INFO_NUD_STATE_STALE);
                break;
            }
        }
        _set_ar_state(nce,
                      GNRC_IPV6_NIB_NC_INFO_AR_STATE_REGISTERED);
        DEBUG("nib: Successfully registered %s\n",
              ipv6_addr_to_str(addr_str, &nce->ipv6, sizeof(addr_str)));
        return SIXLOWPAN_ND_STATUS_SUCCESS;
    }
    else {
        DEBUG("nib: Could not register %s, neighbor cache was full\n",
              ipv6_addr_to_str(addr_str, &nce->ipv6, sizeof(addr_str)));
        return SIXLOWPAN_ND_STATUS_NC_FULL;
    }
}

uint8_t _reg_addr_upstream(gnrc_netif_t *netif, const ipv6_hdr_t *ipv6,
                           const icmpv6_hdr_t *icmpv6,
                           const sixlowpan_nd_opt_ar_t *aro,
                           const ndp_opt_t *sl2ao, _nib_onl_entry_t *nce)
{
    if (!ipv6_addr_is_unspecified(&ipv6->src) && (sl2ao != NULL)) {
        DEBUG("nib: Trying to register %s with EUI-64 "
              "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
              ipv6_addr_to_str(addr_str, &ipv6->src, sizeof(addr_str)),
              aro->eui64.uint8[0], aro->eui64.uint8[1], aro->eui64.uint8[2],
              aro->eui64.uint8[3], aro->eui64.uint8[4], aro->eui64.uint8[5],
              aro->eui64.uint8[6], aro->eui64.uint8[7]);
        if ((nce == NULL) || !(nce->mode & _NC) ||
            (memcmp(&nce->eui64, &aro->eui64, sizeof(aro->eui64)) == 0)) {
#if IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_MULTIHOP_DAD)
            /* TODO */
#endif  /* CONFIG_GNRC_IPV6_NIB_MULTIHOP_DAD */
            if (aro->ltime.u16 != 0) {
                _handle_sl2ao(netif, ipv6, icmpv6, sl2ao);

                /* re-get NCE in case it was updated */
                nce = _nib_onl_get(&ipv6->src, netif->pid);

                /* NIB is full */
                if (nce == NULL) {
                    return SIXLOWPAN_ND_STATUS_NC_FULL;
                }

                /* and re-check EUI-64 in case nce was not an NC before */
                if ((memcmp(&nce->eui64, &aro->eui64,
                            sizeof(aro->eui64)) != 0) &&
                    (_get_ar_state(nce) != GNRC_IPV6_NIB_NC_INFO_AR_STATE_GC)) {
                    /* ignore address registration requests from upstream */
                    DEBUG("nib: Could not register %s, duplicate entry with "
                          "EUI-64 %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                          ipv6_addr_to_str(addr_str, &ipv6->src,
                                           sizeof(addr_str)),
                          nce->eui64.uint8[0], nce->eui64.uint8[1],
                          nce->eui64.uint8[2], nce->eui64.uint8[3],
                          nce->eui64.uint8[4], nce->eui64.uint8[5],
                          nce->eui64.uint8[6], nce->eui64.uint8[7]);
                    return SIXLOWPAN_ND_STATUS_DUP;
                }
                return _update_nce_ar_state(netif, aro, nce);
            }
            else if (nce != NULL) {
                _nib_nc_remove(nce);
                return SIXLOWPAN_ND_STATUS_SUCCESS;
            }
        }
        else if (_get_ar_state(nce) != GNRC_IPV6_NIB_NC_INFO_AR_STATE_GC) {
            /* ignore address registration requests from upstream */
            DEBUG("nib: Could not register %s, duplicate entry with EUI-64 "
                  "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                  ipv6_addr_to_str(addr_str, &ipv6->src, sizeof(addr_str)),
                  nce->eui64.uint8[0], nce->eui64.uint8[1], nce->eui64.uint8[2],
                  nce->eui64.uint8[3], nce->eui64.uint8[4], nce->eui64.uint8[5],
                  nce->eui64.uint8[6], nce->eui64.uint8[7]);
            return SIXLOWPAN_ND_STATUS_DUP;
        }
    }
    return _ADDR_REG_STATUS_IGNORE;
}

gnrc_pktsnip_t *_copy_and_handle_aro(gnrc_netif_t *netif,
                                     const ipv6_hdr_t *ipv6,
                                     const ndp_nbr_sol_t *nbr_sol,
                                     const sixlowpan_nd_opt_ar_t *aro,
                                     const ndp_opt_t *sl2ao)
{
    gnrc_pktsnip_t *reply_aro = NULL;
    assert(aro);
    uint8_t status = _handle_aro(netif, ipv6, (icmpv6_hdr_t *)nbr_sol, aro,
                                 sl2ao, NULL);

    if (status == SIXLOWPAN_ND_STATUS_SUCCESS) {
        _setup_opportunistic_compression_context(netif, ipv6, aro);
    }

    if ((status != _ADDR_REG_STATUS_TENTATIVE) &&
        (status != _ADDR_REG_STATUS_IGNORE)) {
        reply_aro = gnrc_sixlowpan_nd_opt_ar_build(status,
                                                   byteorder_ntohs(aro->ltime),
                                                   (eui64_t *)&aro->eui64,
                                                   NULL);
        if (reply_aro == NULL) {
            DEBUG("nib: No space left in packet buffer. Not replying NS");
        }
    }
#if IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_MULTIHOP_DAD)
    else if (status != _ADDR_REG_STATUS_IGNORE) {
        DEBUG("nib: Address was marked TENTATIVE => not replying NS, "
              "waiting for DAC\n");
    }
#endif  /* CONFIG_GNRC_IPV6_NIB_MULTIHOP_DAD */
    return reply_aro;
}

static int _setup_opportunistic_compression_context(gnrc_netif_t *netif,
                                                    const ipv6_hdr_t *ipv6,
                                                    const sixlowpan_nd_opt_ar_t *ns_aro) {
    if (!gnrc_netif_is_6ln(netif) || !gnrc_netif_is_rtr(netif) || !gnrc_netif_is_rtr_adv(netif)) {
        return -ENOTSUP;
    }
#if IS_USED(MODULE_GNRC_IPV6_NIB) && IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_6LBR) && IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_MULTIHOP_P6C) && IS_ACTIVE(CONFIG_GNRC_NETIF_IPV6_BR_AUTO_6CTX)
    ipv6_addr_t eui64_src_addr = IPV6_ADDR_UNSPECIFIED;
    int res;
    if ((res = gnrc_netif_ipv6_iid_from_addr(netif, (uint8_t *) &ns_aro->eui64,
                                             sizeof(ns_aro->eui64),
                                             (eui64_t *) &eui64_src_addr.u64[1])) < 0) {
        DEBUG("nib: Failed gnrc_netif_ipv6_iid_from_addr with %d for address %s\n",
              res, gnrc_netif_addr_to_str((const uint8_t *) &ns_aro->eui64, sizeof(ns_aro->eui64), addr_str));
        return -1;
    }

    if (memcmp(&ipv6->src.u64[1], &eui64_src_addr.u64[1], sizeof(network_uint64_t)) == 0) {
        DEBUG("nib: Address derived from EUI-64, which can already be compressed, no need for compression context. (%s)\n",
              ipv6_addr_to_str(addr_str, &ipv6->src, sizeof(addr_str)));
        return -1;
    }

    if (!gnrc_sixlowpan_ctx_update_6ctx(&ipv6->src, IPV6_ADDR_BIT_LEN,
                                        MS_PER_SEC * SEC_PER_MIN * byteorder_ntohs(ns_aro->ltime))) {
        DEBUG("nib: Failed gnrc_sixlowpan_ctx_update_6ctx for %s\n",
              ipv6_addr_to_str(addr_str, &ipv6->src, sizeof(addr_str)));
        return -1;
    }
    DEBUG("nib: add compression context for prefix %s/%u\n",
          ipv6_addr_to_str(addr_str, &ipv6->src, sizeof(addr_str)), IPV6_ADDR_BIT_LEN);

    //update abr contexts bitfield
    _nib_abr_entry_t *abr = _nib_abr_iter(NULL);
    res = gnrc_ipv6_nib_abr_add(&abr->addr);
    /* &ipv6->dst is a link-local addr, whereas ABR addr is a GUA */
    if (res != 0) {
        DEBUG("nib: Failed gnrc_ipv6_nib_abr_add: %d\n", res);
        return -1;
    }

    /* Do not send the router advertisement with the context applied already.
     * Done by sending it to the link-local address, which is not subject to the compression context,
     * whereas &ipv6->src, the address to be registered, is. */
    ipv6_addr_init_prefix(&eui64_src_addr, &ipv6_addr_link_local_prefix, 10U);
    /* send RA to disseminate new compression context */
    _snd_rtr_advs(netif, &eui64_src_addr, false);

    return 0;
#else
    (void)ipv6;
    (void)ns_aro;
    return -ENOTSUP;
#endif
}

#else  /* CONFIG_GNRC_IPV6_NIB_6LR */
typedef int dont_be_pedantic;
#endif /* CONFIG_GNRC_IPV6_NIB_6LR */

/** @} */
