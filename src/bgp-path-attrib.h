/**
 * @file bgp-path-attrib.h
 * @author Nato Morichika <nat@nat.moe>
 * @brief The BGP path attributes.
 * @version 0.1
 * @date 2019-07-04
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#ifndef BGP_PATH_ATTR_H
#define BGP_PATH_ATTR_H

#include "serializable.h"
#include "prefix6.h"
#include <stdint.h>
#include <unistd.h>
#include <vector>

namespace libbgp {

/**
 * @brief BGP attribute type codes.
 * 
 */
enum BgpPathAttribType {
    UNKNOW = -1,
    RESERVED = 0,
    ORIGIN = 1,
    AS_PATH = 2,
    NEXT_HOP = 3,
    MULTI_EXIT_DISC = 4,
    LOCAL_PREF = 5,
    ATOMIC_AGGREGATE = 6,
    AGGREATOR = 7,
    COMMUNITY = 8,
    MP_REACH_NLRI = 14,
    MP_UNREACH_NLRI = 15,
    AS4_PATH = 17,
    AS4_AGGREGATOR = 18
};

/**
 * @brief The BgpPathAttrib class.
 * 
 */
class BgpPathAttrib : public Serializable {
public:

    /**
     * @brief Attribute flag: Optional.
     * 
     */
    bool optional;

    /**
     * @brief Attribute flag: Transitive
     * 
     */
    bool transitive;

    /**
     * @brief Attribute flag: partial
     * 
     */
    bool partial;

    /**
     * @brief Attribute flag: extended
     * 
     */
    bool extended;

    /**
     * @brief Attribute type code.
     * 
     */
    uint8_t type_code;

    BgpPathAttrib(BgpLogHandler *logger);
    BgpPathAttrib(BgpLogHandler *logger, const uint8_t *value, uint16_t val_len);

    // get attribute type from buffer, return 0 if failed.
    static uint8_t GetTypeFromBuffer(const uint8_t *buffer, size_t buffer_sz);

    // get extended flag from buffer.
    static bool GetExtendedFlagFromBuffer(const uint8_t *buffer, size_t buffer_sz);

    // print the attribute
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;

    /**
     * @brief Deserialize a BGP update message path attribute.
     * 
     * 
     * @param from Pointer to message body buffer.
     * @param msg_sz Size of message.
     * @return ssize_t Bytes read.
     * @retval -1 Deserialization error. Error may be logged.
     * @retval >=0 Bytes read.
     * @throws "bad_parse" Internal deserialization error.
     * @throws "bad_type" The type of message/field member in buffer does not 
     * match the attribute type of container.
     */
    virtual ssize_t parse(const uint8_t *from, size_t msg_sz);

    /**
     * @brief Serialize a BGP update message path attribute.
     * 
     * @param to Pointer to destination buffer.
     * @param buf_sz Max write size.
     * @return ssize_t Bytes written.
     * @retval -1 Serialization error. Error may be logged.
     * @retval >=0 Bytes written.
     */
    virtual ssize_t write(uint8_t *to, size_t buf_sz) const;

    virtual ssize_t length() const;

    /**
     * @brief Clone the attribute and replace logger.
     * 
     * @param new_logger New logger to use.
     * @return BgpPathAttrib* Pointer to the cloned attribute.
     * @throws "has_error" There's error in the attribute and the attribute can
     * not be clone.
     */
    BgpPathAttrib* clone(BgpLogHandler *new_logger) const;

    /**
     * @brief Clone the attribute.
     * 
     * @return BgpPathAttrib* Pointer to the cloned attribute.
     * @throws "has_error" There's error in the attribute and the attribute can
     * not be clone.
     */
    virtual BgpPathAttrib* clone() const;

    virtual ~BgpPathAttrib();

protected:
    // utility function to parse header (flags, typecode, length) from buffer
    ssize_t parseHeader(const uint8_t *buffer, size_t length);

    // utility function to print flags
    ssize_t printFlags(size_t indent, uint8_t **to, size_t *buf_sz) const;

    // utility function to write header (flags, type_code) to buffer. notice
    // that length is not write to buffer by this function.
    ssize_t writeHeader(uint8_t *buffer, size_t buffer_sz) const;

    /**
     * @brief Attribute length. 
     * Length field is only used in deserialization for parseHeader() to pass
     * length field in header to the underlying deserializers. The length field
     * is ignored when serialize. 
     */
    uint16_t value_len;

private:
    uint8_t* value_ptr;
};

/**
 * @brief BGP origin path attribute values
 * 
 */
enum BgpPathAttribOrigins {
    IGP = 0,
    EGP = 1,
    INCOMPLETE = 2
};

/**
 * @brief Origin Attribute
 * 
 */
class BgpPathAttribOrigin : public BgpPathAttrib {
public:
    BgpPathAttribOrigin(BgpLogHandler *logger);
    uint8_t origin;
    
    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
};

/**
 * @brief `AS_PATH` segment types.
 * 
 */
enum BgpAsPathSegmentType {
    AS_SET = 1,
    AS_SEQUENCE = 2
};

/**
 * @brief An AS_PATH or AS4_PATH segment
 * 
 */
class BgpAsPathSegment {
public:
    BgpAsPathSegment(bool is_4b, uint8_t type);

    /**
     * @brief Is ASNs in this segment four octets?
     * 
     */
    bool is_4b;

    /**
     * @brief Segment type.
     * 
     */
    uint8_t type;
    size_t getCount() const;
    bool prepend(uint32_t asn);

    /**
     * @brief The segment value.
     * 
     */
    std::vector<uint32_t> value;
};

/**
 * @brief AS Path attribute.
 * 
 */
class BgpPathAttribAsPath : public BgpPathAttrib {
public:
    // is_4b: 4b ASN in AS_PATH?
    BgpPathAttribAsPath(BgpLogHandler *logger, bool is_4b);

    BgpPathAttrib* clone() const;

    /**
     * @brief The AS Path segments.
     * 
     */
    std::vector<BgpAsPathSegment> as_paths;

    /**
     * @brief Is ASNs in the attribute four octets?
     * 
     */
    bool is_4b;

    // prepend: utility function to prepend an ASN to path
    bool prepend(uint32_t asn);

    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
private:
    // addSeg: add a new AS_SEQUENCE with one ASN to AS_PATH 
    void addSeg(uint32_t asn);
};

/**
 * @brief Nexthop attribute.
 * 
 */
class BgpPathAttribNexthop : public BgpPathAttrib {
public:
    BgpPathAttribNexthop(BgpLogHandler *logger);

    /**
     * @brief The nexthop in network byte order.
     * 
     */
    uint32_t next_hop;

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
};

/**
 * @brief Multi Exit Discriminator attribute
 * 
 */
class BgpPathAttribMed : public BgpPathAttrib {
public:
    BgpPathAttribMed(BgpLogHandler *logger);

    /**
     * @brief MED.
     * 
     */
    uint32_t med;

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
};

/**
 * @brief Local Pref attribute.
 * 
 */
class BgpPathAttribLocalPref : public BgpPathAttrib {
public:
    BgpPathAttribLocalPref(BgpLogHandler *logger);

    /**
     * @brief Local Pref.
     * 
     */
    uint32_t local_pref;

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
};

/**
 * @brief Atomic aggregate attribute.
 * 
 */
class BgpPathAttribAtomicAggregate : public BgpPathAttrib {
public:
    BgpPathAttribAtomicAggregate(BgpLogHandler *logger);

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
};

/**
 * @brief Aggregator attribute.
 * 
 */
class BgpPathAttribAggregator : public BgpPathAttrib {
public:
    // is_4b: 4b asn in aggregator?
    BgpPathAttribAggregator(BgpLogHandler *logger, bool is_4b);

    /**
     * @brief Aggregator in network byte order.
     * 
     */
    uint32_t aggregator;

    /**
     * @brief Aggregator ASN.
     * 
     */
    uint32_t aggregator_asn;

    /**
     * @brief Is ASNs in the attribute four octets?
     * 
     */
    bool is_4b;

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
};

/**
 * @brief AS4_PATH attribute.
 * 
 */
class BgpPathAttribAs4Path : public BgpPathAttrib {
public:
    BgpPathAttribAs4Path(BgpLogHandler *logger);

    /**
     * @brief The AS4_PATH segments.
     * 
     */
    std::vector<BgpAsPathSegment> as4_paths;

    bool prepend(uint32_t asn);

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
private:
    void addSeg(uint32_t asn);
};

/**
 * @brief AS4_AGGREGATOR attribute.
 * 
 */
class BgpPathAttribAs4Aggregator : public BgpPathAttrib {
public:
    BgpPathAttribAs4Aggregator(BgpLogHandler *logger);

    /**
     * @brief Aggregator in network byte order.
     * 
     */
    uint32_t aggregator;

    /**
     * @brief Aggregator ASN.
     * 
     */
    uint32_t aggregator_asn4;

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
};

/**
 * @brief BGP community attribute.
 * 
 */
class BgpPathAttribCommunity : public BgpPathAttrib {
public:
    BgpPathAttribCommunity(BgpLogHandler *logger);

    /**
     * @brief Raw community attribute in network byte order.
     * 
     */
    std::vector<uint32_t> communites;

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
};

/**
 * @brief MP-BGP Reach/Unreach NLRI base class.
 * 
 */
class BgpPathAttribMpNlriBase : public BgpPathAttrib {
public:
    BgpPathAttribMpNlriBase(BgpLogHandler *logger);
    static int16_t GetAfiFromBuffer(const uint8_t *buffer, size_t length, bool extended);

    /**
     * @brief Address Family Identifier
     * 
     */
    uint16_t afi;

    /**
     * @brief Subsequent Address Family Identifier
     * 
     */
    uint8_t safi;

protected:
    ssize_t parseHeader(const uint8_t *buffer, size_t length, bool is_unreach);
};

/**
 * @brief MP-BGP ReachNlri IPv6 NLRI class.
 * 
 */
class BgpPathAttribMpReachNlriIpv6 : public BgpPathAttribMpNlriBase {
public:
    BgpPathAttribMpReachNlriIpv6(BgpLogHandler *logger);

    uint8_t nexthop_global[16];
    uint8_t nexthop_linklocal[16];
    std::vector<Prefix6> nlri;

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
};

/**
 * @brief MP-BGP ReachNlri container for unknow AFI/SAFI.
 * 
 */
class BgpPathAttribMpReachNlriUnknow : public BgpPathAttribMpNlriBase {
public:
    BgpPathAttribMpReachNlriUnknow(BgpLogHandler *logger);
    BgpPathAttribMpReachNlriUnknow(BgpLogHandler *logger, const uint8_t *nexthop, size_t nexthop_len, const uint8_t *nlri, size_t nlri_len);
    ~BgpPathAttribMpReachNlriUnknow();

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;

    const uint8_t *getNexthop() const;
    const uint8_t *getNlri() const;

    size_t getNexthopLength() const;
    size_t getNlriLength() const;

private:
    uint8_t *nexthop;
    size_t nexthop_len;
    uint8_t *nlri;
    size_t nlri_len;
};

/**
 * @brief MP-BGP UnreachNlri IPv6 class.
 * 
 */
class BgpPathAttribMpUnreachNlriIpv6 : public BgpPathAttribMpNlriBase {
public:
    BgpPathAttribMpUnreachNlriIpv6(BgpLogHandler *logger);
    std::vector<Prefix6> withdrawn_routes;

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;
};

/**
 * @brief MP-BGP UnreachNlri container for unknow AFI/SAFI.
 * 
 */
class BgpPathAttribMpUnreachNlriUnknow : public BgpPathAttribMpNlriBase {
public:
    BgpPathAttribMpUnreachNlriUnknow(BgpLogHandler *logger);
    BgpPathAttribMpUnreachNlriUnknow(BgpLogHandler *logger, const uint8_t *withdrawn, size_t len);
    ~BgpPathAttribMpUnreachNlriUnknow();

    BgpPathAttrib* clone() const;
    ssize_t parse(const uint8_t *buffer, size_t length);
    ssize_t write(uint8_t *buffer, size_t buffer_sz) const;
    ssize_t doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const;
    ssize_t length() const;

    const uint8_t *getWithdrawnRoutes() const;
    size_t getWithdrawnRoutesLength() const;
private:
    uint8_t *withdrawn_routes;
    size_t withdrawn_routes_len;
};

}
#endif // BGP_PATH_ATTR_H
