/**
 * @file bgp-rib4.cc
 * @author Nato Morichika <nat@nat.moe>
 * @brief The IPv4 BGP Routing Information Base.
 * @version 0.2
 * @date 2019-07-21
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#include "bgp-rib4.h"
#include <arpa/inet.h>
#define MAKE_ENTRY4(r, e) std::make_pair(BgpRib4EntryKey(r), e)

namespace libbgp {

BgpRib4Entry::BgpRib4Entry() {
    src_router_id = 0;
}

/**
 * @brief Construct a new Bgp Rib Entry:: Bgp Rib Entry object
 * 
 * @param r Prefix of the entry.
 * @param src Originating BGP speaker's ID in network bytes order.
 * @param as Path attributes for this entry.
 */
BgpRib4Entry::BgpRib4Entry(Prefix4 r, uint32_t src, const std::vector<std::shared_ptr<BgpPathAttrib>> as) : route(r) {
    src_router_id = src;
    attribs = as;
}

/**
 * @brief Get nexthop for this entry.
 * 
 * @return uint32_t nexthop in network byte order.
 * @throws "no_nexthop" nexthop attribute does not exist.
 */
uint32_t BgpRib4Entry::getNexthop() const {
    for (const std::shared_ptr<BgpPathAttrib> &attr : attribs) {
        if (attr->type_code == NEXT_HOP) {
            const BgpPathAttribNexthop &nh = dynamic_cast<const BgpPathAttribNexthop &>(*attr);
            return nh.next_hop;
        }
    }

    throw "no_nexthop";
}

/**
 * @brief Construct a new BgpRib4 object with logging.
 * 
 * @param logger Log handler to use.
 */
BgpRib4::BgpRib4(BgpLogHandler *logger) {
    this->logger = logger;
    update_id = 0;    
}

rib4_t::const_iterator BgpRib4::find_best (const Prefix4 &prefix) const {
    std::pair<rib4_t::const_iterator, rib4_t::const_iterator> its = 
        rib.equal_range(BgpRib4EntryKey(prefix));

    rib4_t::const_iterator best = rib.end();
    if (its.first == rib.end()) return rib.end();

    for (rib4_t::const_iterator it = its.first; it != its.second; it++) {
        if (it->second.route == prefix) {
            if (best == rib.end()) best = it;
            else {
                const BgpRib4Entry *best_ptr = selectEntry(&(best->second), &(it->second));
                best = best_ptr == &(best->second) ? best : it;
            }
        }
    }

    return best;
}

rib4_t::const_iterator BgpRib4::find_entry (const Prefix4 &prefix, uint32_t src) const {
    std::pair<rib4_t::const_iterator, rib4_t::const_iterator> its = 
        rib.equal_range(BgpRib4EntryKey(prefix));

    if (its.first == rib.end()) return rib.end();

    for (rib4_t::const_iterator it = its.first; it != its.second; it++) {
        if (it->second.route == prefix && it->second.src_router_id == src) {
            return it;
        }
    }

    return rib.end();
}

/**
 * @brief The actual insert implementation.
 * 
 * @param src_router_id source router ID.
 * @param route route to insert.
 * @param attrib route attributes.
 * @param weight route weight.
 * @param ibgp_asn remote ASN, if IBGP.
 * @return const BgpRib4Entry entry that should be send to peer. (NULL-able)
 */
const BgpRib4Entry* BgpRib4::insertPriv(uint32_t src_router_id, const Prefix4 &route, const std::vector<std::shared_ptr<BgpPathAttrib>> &attrib, int32_t weight, uint32_t ibgp_asn) {
    std::lock_guard<std::recursive_mutex> lock(mutex);

    /* construct the new entry object */
    BgpRib4Entry new_entry(route, src_router_id, attrib);
    new_entry.update_id = update_id;
    new_entry.weight = weight;
    new_entry.src = ibgp_asn > 0 ? SRC_IBGP : SRC_EBGP;
    new_entry.ibgp_peer_asn = ibgp_asn;

    // for logging
    const char *op = "new_entry";
    const char *act = "new_best";

    /* keep track of the old best route */
    bool old_exist = false;
    bool best_changed = false;
    uint64_t old_best_uid = 0;

    rib4_t::const_iterator best_before_insert = find_best (route);
    if (best_before_insert != rib.end()) {
        old_exist = true;
        old_best_uid = best_before_insert->second.update_id;
    }

    /* do the actual insert */
    rib4_t::const_iterator best_after_insert = rib.end();
    if (old_exist) { 
        // erase old entry from same peer if exist.
        std::pair<rib4_t::const_iterator, rib4_t::const_iterator> entries = 
            rib.equal_range(BgpRib4EntryKey(route));
        
        for (rib4_t::const_iterator it = entries.first; it != entries.second;) {
            if (it->second.route == route && it->second.src_router_id == src_router_id) {
                op = "update";
                it = rib.erase(it);
            } else it++;
        }

        // insert
        rib4_t::const_iterator insetred = rib.insert(MAKE_ENTRY4(route, new_entry));

        /* check the new best route */
        best_after_insert = find_best (route);

        // best route is old best route, 
        if (best_after_insert->second.update_id == old_best_uid) {
            act = "not_new_best";
        } else best_changed = true;
    } else {
        // no old entry exist, inserted automaically become new best
        best_after_insert = rib.insert(MAKE_ENTRY4(route, new_entry));
    }

    LIBBGP_LOG(logger, INFO) {
        uint32_t prefix = route.getPrefix();
        char src_router_id_str[INET_ADDRSTRLEN], prefix_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_router_id, src_router_id_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &prefix, prefix_str, INET_ADDRSTRLEN);
        logger->log(INFO, "BgpRib4::insertPriv: (%s/%s) group %d, scope %s, route %s/%d\n", op, act, new_entry.update_id, src_router_id_str, prefix_str, route.getLength());
    }

    if (best_after_insert == rib.end()) {
        logger->log(FATAL, "BgpRib4::insertPriv: internal error: best_after_insert does not exist.\n");
        return NULL;
    }

    return (!old_exist || best_changed) ? &(best_after_insert->second) : NULL;
}

/**
 * @brief Insert a local route into RIB.
 * 
 * Local routes are routes inserted to the RIB by user. The scope (src_router_id)
 * of local routes are 0. This method will create necessary path attribues
 * before inserting entry to RIB (AS_PATH, ORIGIN, NEXT_HOP). 
 * 
 * The logger pointer passed in is for attribues. (so if a attribute failed to 
 * deserialize, it will print to the provided logger).
 * 
 * To remove an entry inserted with this method, use 0 as `src_router_id`.
 * 
 * @param logger Pointer to logger for the created path attributes to use. 
 * @param route Prefix4.
 * @param nexthop Nexthop for the route.
 * @param weight weight of this entry.
 * @retval NULL failed to insert.
 * @retval !=NULL Inserted route.
 */
const BgpRib4Entry* BgpRib4::insert(BgpLogHandler *logger, const Prefix4 &route, uint32_t nexthop, int32_t weight) {
    std::vector<std::shared_ptr<BgpPathAttrib>> attribs;
    BgpPathAttribOrigin *origin = new BgpPathAttribOrigin(logger);
    BgpPathAttribNexthop *nexhop_attr = new BgpPathAttribNexthop(logger);
    BgpPathAttribAsPath *as_path = new BgpPathAttribAsPath(logger, true);
    nexhop_attr->next_hop = nexthop;
    origin->origin = IGP;

    attribs.push_back(std::shared_ptr<BgpPathAttrib>(origin));
    attribs.push_back(std::shared_ptr<BgpPathAttrib>(nexhop_attr));
    attribs.push_back(std::shared_ptr<BgpPathAttrib>(as_path));

    uint64_t use_update_id = update_id;

    for (const auto &entry : rib) {
        if (entry.second.src_router_id == 0 && entry.second.route == route) {
            this->logger->log(ERROR, "BgpRib4::insert: route exists.\n");
            return NULL;
        }

        // see if we can group this entry to other local entries
        if (entry.second.src_router_id == 0) {
            for (const std::shared_ptr<BgpPathAttrib> &attr : entry.second.attribs) {
                if (attr->type_code == NEXT_HOP) {
                    const BgpPathAttribNexthop &nh = dynamic_cast<const BgpPathAttribNexthop &>(*attr);
                    if (nh.next_hop == nexthop) use_update_id = entry.second.update_id;
                }
            }
        }
    }

    BgpRib4Entry new_entry(route, 0, attribs);
    std::lock_guard<std::recursive_mutex> lock(mutex);
    new_entry.update_id = use_update_id;
    new_entry.weight = weight;
    if (use_update_id == update_id) update_id++;
    rib4_t::const_iterator it = rib.insert(MAKE_ENTRY4(route, new_entry));

    return &(it->second);
}

/**
 * @brief Insert local routes into RIB.
 * 
 * ame as the other local insert, but this one insert mutiple routes.
 * 
 * @param logger Pointer to logger for the created path attributes to use. 
 * @param routes Routes.
 * @param nexthop Nexthop for the route.
 * @param weight weight of this entry.
 * @return const std::vector<const BgpRib4Entry*> Inserted routes.
 */
const std::vector<BgpRib4Entry> BgpRib4::insert(BgpLogHandler *logger, const std::vector<Prefix4> &routes, uint32_t nexthop, int32_t weight) {
    std::vector<BgpRib4Entry> inserted;
    std::vector<std::shared_ptr<BgpPathAttrib>> attribs;
    BgpPathAttribOrigin *origin = new BgpPathAttribOrigin(logger);
    BgpPathAttribNexthop *nexhop_attr = new BgpPathAttribNexthop(logger);
    BgpPathAttribAsPath *as_path = new BgpPathAttribAsPath(logger, true);
    nexhop_attr->next_hop = nexthop;
    origin->origin = IGP;

    attribs.push_back(std::shared_ptr<BgpPathAttrib>(origin));
    attribs.push_back(std::shared_ptr<BgpPathAttrib>(nexhop_attr));
    attribs.push_back(std::shared_ptr<BgpPathAttrib>(as_path));

    for (const Prefix4 &route : routes) {
        rib4_t::const_iterator it = find_entry(route, 0);

        if (it != rib.end()) continue;

        BgpRib4Entry new_entry (route, 0, attribs);
        new_entry.update_id = update_id;
        new_entry.weight = weight;
        rib4_t::const_iterator isrt_it = rib.insert(MAKE_ENTRY4(route, new_entry));
        inserted.push_back(isrt_it->second);
    }

    update_id++;
    return inserted;
}

/**
 * @brief Insert a new entry into RIB.
 * 
 * @param src_router_id Originating BGP speaker's ID in network bytes order.
 * @param route Prefix4.
 * @param attrib Path attribute.
 * @param weight weight of this entry.
 * @param ibgp_asn ASN of the peer if the route is from an IBGP peer. 0 if not.
 * @return const BgpRib4Entry* entry that should be send to peer. (NULL-able)
 */
const BgpRib4Entry* BgpRib4::insert(uint32_t src_router_id, const Prefix4 &route, const std::vector<std::shared_ptr<BgpPathAttrib>> &attrib, int32_t weight, uint32_t ibgp_asn) {
    update_id++;
    return insertPriv(src_router_id, route, attrib, weight, ibgp_asn);
}

/**
 * @brief Withdraw a route from RIB.
 * 
 * @param src_router_id Originating BGP speaker's ID in network bytes order.
 * @param route Prefix4.
 * @return <bool, const BgpRib4Entry*> withdrawn information
 * @retval <false, NULL> if the withdrawed route is no longer reachable.
 * @retval <true, NULL> if the route withdrawed but still reachable with current
 * best route.
 * @retval <true, const BgpRib4Entry*> if the route withdrawed and that changes
 * the current best route.
 */
std::pair<bool, const BgpRib4Entry*> BgpRib4::withdraw(uint32_t src_router_id, const Prefix4 &route) {
    std::lock_guard<std::recursive_mutex> lock(mutex);
    std::pair<rib4_t::const_iterator, rib4_t::const_iterator> old_entries = 
        rib.equal_range(BgpRib4EntryKey(route));

    if (old_entries.first == rib.end()) 
        return std::make_pair<bool, const BgpRib4Entry*>(false, NULL); // not in RIB.

    const char *op = "dropped/no_change";
    const BgpRib4Entry *replacement = NULL;
    uint64_t old_best_uid = 0;
    rib4_t::const_iterator to_remove = rib.end();
    
    for (rib4_t::const_iterator it = old_entries.first; it != old_entries.second; it++) {
        if (it->second.route == route) {
            if (it->second.src_router_id == src_router_id) {
                to_remove = it;
                continue;
            }
            if (replacement == NULL) replacement = &(it->second);
            else replacement = selectEntry(replacement, &(it->second));
        }
    }

    bool reachabled = true;

    if (to_remove == rib.end()) 
        return std::make_pair<bool, const BgpRib4Entry*>(false, NULL);
    if (replacement != NULL) {
        const BgpRib4Entry *candidate = selectEntry(replacement, &(to_remove->second));
        if (candidate == &(to_remove->second)) {
            op = "dropped/best_changed";
        } else replacement = NULL;
        rib.erase(to_remove);
    } else {
        reachabled = false;
        op = "dropped/unreachabled";
    }

    LIBBGP_LOG(logger, INFO) {
        uint32_t prefix = route.getPrefix();
        char src_router_id_str[INET_ADDRSTRLEN], prefix_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_router_id, src_router_id_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &prefix, prefix_str, INET_ADDRSTRLEN);
        logger->log(INFO, "BgpRib4::withdraw: (%s) scope %s, route %s/%d\n", op, src_router_id_str, prefix_str, route.getLength());
    }

    return std::pair<bool, const BgpRib4Entry*>(reachabled, replacement);
}

/**
 * @brief Drop all routes from RIB that originated from a BGP speaker.
 * 
 * @param src_router_id src_router_id Originating BGP speaker's ID in network bytes order.
 * @return std::pair<std::vector<Prefix4>, std::vector<BgpRib4Entry>> 
 * <dropped_routes, updated_routes> pair. dropped_routes should be send as
 * withdrawn to peers, updated_routes should be send as update to peer.
 * 
 */
std::pair<std::vector<Prefix4>, std::vector<const BgpRib4Entry*>> BgpRib4::discard(uint32_t src_router_id) {
    /*std::lock_guard<std::recursive_mutex> lock(mutex);
    std::vector<Prefix4> dropped_routes;

    for (rib4_t::const_iterator it = rib.begin(); it != rib.end();) {
        if (it->second.src_router_id == src_router_id) {
            dropped_routes.push_back(it->second.route);
            LIBBGP_LOG(logger, INFO) {
                uint32_t prefix = it->second.route.getPrefix();
                char src_router_id_str[INET_ADDRSTRLEN], prefix_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &src_router_id, src_router_id_str, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &prefix, prefix_str, INET_ADDRSTRLEN);
                logger->log(INFO, "BgpRib4::discard: (dropped) scope %s, route %s/%d\n", src_router_id_str, prefix_str, it->second.route.getLength());
            }
            it = rib.erase(it);
        } else it++;
    }

    return dropped_routes;*/
}

/**
 * @brief Lookup a destination in RIB.
 * 
 * @param dest The destination address in network byte order.
 * @return const BgpRib4Entry* Matching entry.
 * @retval NULL no match found.
 * @retval BgpRib4Entry* Matching entry.
 */
const BgpRib4Entry* BgpRib4::lookup(uint32_t dest) const {
    const BgpRib4Entry *selected_entry = NULL;

    for (const auto &entry : rib) {
        const Prefix4 &route = entry.second.route;
        if (route.includes(dest)) 
            selected_entry = selectEntry(&entry.second, selected_entry);
    }

    return selected_entry;
}

/**
 * @brief Scoped RIB lookup.
 * 
 * Simular to lookup with only one argument but only lookup in routes from the
 * given BGP speaker.
 * 
 * @param src_router_id Originating BGP speaker's ID in network bytes order.
 * @param dest The destination address in network byte order.
 * @return const BgpRib4Entry* Matching entry.
 * @retval NULL no match found.
 * @retval BgpRib4Entry* Matching entry.
 */
const BgpRib4Entry* BgpRib4::lookup(uint32_t src_router_id, uint32_t dest) const {
    const BgpRib4Entry *selected_entry = NULL;

    for (const auto &entry : rib) {
        if (entry.second.src_router_id != src_router_id) continue;
        const Prefix4 &route = entry.second.route;
        if (route.includes(dest)) 
            selected_entry = selectEntry(&entry.second, selected_entry);
    }

    return selected_entry;
}

/**
 * @brief Get the RIB.
 * 
 * @return const rib4_t& The RIB.
 */
const rib4_t& BgpRib4::get() const {
    return rib;
}

}