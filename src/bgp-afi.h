/**
 * @file bgp-afi.h
 * @author Nato Morichika <nat@nat.moe>
 * @brief The BGP AFI/SAFI.
 * @version 0.1
 * @date 2019-07-23
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#ifndef BGP_AFI_H_
#define BGP_AFI_H_

namespace libbgp {

/**
 * @brief Address Family Identifiers.
 * 
 */
enum Afi {
    UNKNOWN_AFI = 0,
    IPV4 = 1,
    IPV6 = 2
};

/**
 * @brief Subsequent Address Family Identifiers
 * 
 */
enum Safi {
    UNKNOWN_SAFI = 0,
    UNICAST = 1,
    MULTICAST = 2,
    UNICAST_AND_MULTICAST = 3
};

};

#endif // BGP_AFI_H_
