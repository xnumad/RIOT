/*
 * Copyright (C) 2018 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup net_gnrc_ipv6_nib
 * @brief
 * @{
 *
 * @file
 * @brief   Definions related to SLAAC functionality of the NIB
 * @see     @ref CONFIG_GNRC_IPV6_NIB_SLAAC
 * @internal
 *
 * @author  Martine Lenders <m.lenders@fu-berlin.de>
 */
#ifndef PRIV_NIB_SLAAC_H
#define PRIV_NIB_SLAAC_H

#include <kernel_defines.h>
#include <stdint.h>

#include "net/gnrc/ipv6/nib/conf.h"
#include "net/gnrc/netif.h"
#include "net/ipv6/addr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SLAAC_PREFIX_LENGTH (64U)

/**
 * @name    Temporary address parameters
 * @see     [RFC 8981, section 3.8](https://tools.ietf.org/html/rfc8981#section-3.8)
 * @{
 */
/**
 * @brief   Maximum valid lifetime [days] of a temporary address
 */
#ifndef TEMP_VALID_LIFETIME
#define TEMP_VALID_LIFETIME            MS_PER_HOUR * HOURS_PER_DAY * (2U) /*default value*/
#endif

/**
 * @brief   Maximum preferred lifetime [days] of a temporary address
 * 
 * @note    "MUST be smaller than the TEMP_VALID_LIFETIME value"
 */
#ifndef TEMP_PREFERRED_LIFETIME
#define TEMP_PREFERRED_LIFETIME        MS_PER_HOUR * HOURS_PER_DAY * (1U) /*default value*/
#endif

/**
 * @brief   Maximum time to randomly subtract from TEMP_PREFERRED_LIFETIME
 *          for a temporary address
 */
#define MAX_DESYNC_FACTOR             (TEMP_PREFERRED_LIFETIME / 10 * 4)

/**
 * @brief   Maximum number of retries for generating a temporary address
 *          in case a duplicate addresses was detected (DAD failure)
 */
#ifndef TEMP_IDGEN_RETRIES
#define TEMP_IDGEN_RETRIES             (3U) /*default value*/
#endif
/** @} */

#if IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_6LN) || IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_SLAAC) || defined(DOXYGEN)
/**
 * @brief   Auto-configures an address from a given prefix
 *
 * @param[in] netif     The network interface the address should be added to.
 * @param[in] pfx       The prefix for the address.
 * @param[in] pfx_len   Length of @p pfx in bits.
 */
void _auto_configure_addr(gnrc_netif_t *netif, const ipv6_addr_t *pfx,
                          uint8_t pfx_len);
#else   /* CONFIG_GNRC_IPV6_NIB_6LN || CONFIG_GNRC_IPV6_NIB_SLAAC */
#define _auto_configure_addr(netif, pfx, pfx_len) \
    (void)netif; (void)pfx; (void)pfx_len;
#endif  /* CONFIG_GNRC_IPV6_NIB_6LN || CONFIG_GNRC_IPV6_NIB_SLAAC */

#if IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_SLAAC_TEMPORARY_ADDRESSES) || defined(DOXYGEN)
bool _iid_is_iana_reserved(const eui64_t *iid);

uint32_t gnrc_netif_ipv6_regen_advance(const gnrc_netif_t *netif);
#endif

#if IS_ACTIVE(CONFIG_GNRC_IPV6_NIB_SLAAC) || defined(DOXYGEN)
/**
 * @brief   Removes a tentative address from the interface and tries to
 *          reconfigure a new address
 *
 * @param[in] netif The network interface the address is to be removed from.
 * @param[in] addr  The address to remove.
 */
void _remove_tentative_addr(gnrc_netif_t *netif, const ipv6_addr_t *addr);

/**
 * @brief   Handle @ref GNRC_IPV6_NIB_DAD event
 *
 * @param[in] addr  A TENTATIVE address.
 */
void _handle_dad(const ipv6_addr_t *addr);

/**
 * @brief   Handle @ref GNRC_IPV6_NIB_VALID_ADDR event
 *
 * @param[in] addr  A TENTATIVE address.
 */
void _handle_valid_addr(const ipv6_addr_t *addr);
#else   /* CONFIG_GNRC_IPV6_NIB_SLAAC */
#define _remove_tentative_addr(netif, addr) \
    (void)netif; (void)addr
#define _handle_dad(addr)           (void)addr
#define _handle_valid_addr(addr)    (void)addr
#endif  /* CONFIG_GNRC_IPV6_NIB_SLAAC */

#ifdef __cplusplus
}
#endif

#endif /* PRIV_NIB_SLAAC_H */
/** @} */
