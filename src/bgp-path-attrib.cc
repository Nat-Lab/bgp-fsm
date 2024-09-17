/**
 * @file bgp-path-attrib.cc
 * @author Nato Morichika <nat@nat.moe>
 * @brief BGP Path attributes.
 * @version 0.1
 * @date 2019-07-06
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#include "bgp-path-attrib.h"
#include "bgp-errcode.h"
#include "bgp-afi.h"
#include "value-op.h"
#include <stdlib.h>
#include <arpa/inet.h>

namespace libbgp {

/**
 * @brief Get type of attribute from buffer.
 * 
 * @param from Pointer to buffer.
 * @param buffer_sz Size of buffre.
 * @return int8_t Attribute type.
 * @retval 0 Failed to get attribute type.
 * @retval >0 Attribute type.
 */
uint8_t BgpPathAttrib::GetTypeFromBuffer(const uint8_t *from, size_t buffer_sz) {
    if (buffer_sz < 3) return -1;
    return *((uint8_t *) (from + 1));
}

bool BgpPathAttrib::GetExtendedFlagFromBuffer(const uint8_t *from, size_t buffer_sz)
{
  if (buffer_sz < 3) return -1;
  return (((*((uint8_t *)from)) >> 4) & 0x1);
}

/**
 * @brief Construct a new Bgp Path Attrib:: Bgp Path Attrib object
 * 
 * @param logger Pointer to logger object for error logging.
 */
BgpPathAttrib::BgpPathAttrib(BgpLogHandler *logger) : Serializable(logger) {
    optional = transitive = partial = extended = false;
    value_ptr = NULL;
}

/**
 * @brief Construct a new Bgp Path Attrib:: Bgp Path Attrib object
 * 
 * @param logger Pointer to logger object for error logging.
 * @param value Pointer to value buffer of unknow type attribute.
 * @param val_len Length of the value buffer.
 */
BgpPathAttrib::BgpPathAttrib(BgpLogHandler *logger, const uint8_t *value, uint16_t val_len) : BgpPathAttrib(logger) {
    if (value_len > 0) {
        logger->log(FATAL, "BgpPathAttrib::BgpPathAttrib: unknow attribute created with length != 0 but buffer NULL.\n");
        throw "bad_value_buffer";
    }

    value_ptr = (uint8_t *) malloc(val_len);
    memcpy(value_ptr, value, value_len);
}

/**
 * @brief Destroy the Bgp Path Attrib:: Bgp Path Attrib object
 * 
 */
BgpPathAttrib::~BgpPathAttrib() {
    if (value_ptr != NULL) free(value_ptr);
}

BgpPathAttrib* BgpPathAttrib::clone(BgpLogHandler *new_logger) const {
    BgpPathAttrib* cloned = clone();
    cloned->setLogger(new_logger);
    return cloned;
}

BgpPathAttrib* BgpPathAttrib::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttrib::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    BgpPathAttrib *attr = new BgpPathAttrib(logger, value_ptr, value_len);
    attr->transitive = transitive;
    attr->optional = optional;
    attr->partial = partial;
    attr->extended = attr->extended;
    return attr;
}

/**
 * @brief Utility function to print flags for attribute.
 * 
 * @param indent Indentation level.
 * @param to Pointer to buffer pointer.
 * @param buf_sz Pointer to avaliable buffer counter.
 * @return ssize_t Bytes written.
 */
ssize_t BgpPathAttrib::printFlags(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;

    if (!(transitive || optional || partial || extended)) {
        written += _print(indent, to, buf_sz, "Flags { }\n");
        return written;
    }

    written += _print(indent, to, buf_sz, "Flags {\n");
    indent++; {
        if (optional) written += _print(indent, to, buf_sz, "Optional\n");
        if (transitive) written += _print(indent, to, buf_sz, "Transitive\n");
        if (partial) written += _print(indent, to, buf_sz, "Partial\n");
        if (extended) written += _print(indent, to, buf_sz, "Extended\n");
    }; indent--;
    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

ssize_t BgpPathAttrib::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;

    written += _print(indent, to, buf_sz, "UnknowAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        written += _print(indent, to, buf_sz, "TypeCode { %d }\n", type_code);
    }; indent--;
    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

ssize_t BgpPathAttrib::parse(const uint8_t *from, size_t length) {
    ssize_t header_len = parseHeader(from, length);

    if (header_len < 0) return -1;

    const uint8_t *buffer = from + header_len;

    // Well-Known, Mandatory = !optional, transitive
    // Well-Known, Discretionary = !optional, !transitive
    // Optional, Transitive = optional, transitive
    // Optional, Non-Transitive = optional, !transitive
    if (!optional && transitive) {
        // well-known mandatory, but not recognized
        setError(E_UPDATE, E_BAD_WELL_KNOWN, from, value_len + header_len);
        logger->log(ERROR, "BgpPathAttrib::parse: flag indicates well-known, mandatory but this attribute is unknown.\n");
        // set value_len = 0, so we won't free() nullptr when destruct.
        value_len = 0; 
        return -1;
    }

    if (optional && !transitive && partial) {
        // optional non-transitive must not be partial
        setError(E_UPDATE, E_ATTR_FLAG, from, value_len + header_len);
        logger->log(ERROR, "BgpPathAttrib::parse: optional non-transitive must not be partial.\n");
        // set value_len = 0, so we won't free() nullptr when destruct.
        value_len = 0; 
        return -1;
    }

    value_ptr = (uint8_t *) malloc(value_len);
    memcpy(value_ptr, buffer, value_len);

    return value_len + header_len;
}

ssize_t BgpPathAttrib::length() const {
    return value_len + (extended ? 4 : 3);
}

ssize_t BgpPathAttrib::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < (size_t) (value_len + 3)) {
        logger->log(ERROR, "BgpPathAttrib::write: destination buffer size too small.\n");
        return -1;
    }

    if (!extended && value_len >= 0xffff) {
        logger->log(ERROR, "BgpPathAttrib::write: non-extended value has size > 65535: %d\n", value_len);
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 2) return -1;

    uint8_t *buffer = to + 2;
    if (extended) putValue<uint16_t>(&buffer, htons(value_len));
    else putValue<uint8_t>(&buffer, value_len);

    if (value_len > 0) memcpy(buffer, value_ptr, value_len);

    return value_len + 3;   
}

/**
 * @brief Utility function to parse attribute header. (Flag, type, length)
 * 
 * @param from Pointer to buffer.
 * @param buffer_sz Size of buffer.
 * @return ssize_t Bytes read.
 * @retval -1 Failed to parse header. error may be written to stderr with log
 * handler.
 * @retval >=0 Bytes read.
 */
ssize_t BgpPathAttrib::parseHeader(const uint8_t *from, size_t buffer_sz) {
    if (buffer_sz < 3) {
        setError(E_UPDATE, E_UNSPEC_UPDATE, NULL, 0);
        logger->log(ERROR, "BgpPathAttrib::parseHeader: invalid attribute header size.\n");
        return -1;
    }
    const uint8_t *buffer = from;

    uint8_t flags = getValue<uint8_t>(&buffer);

    optional = (flags >> 7) & 0x1;
    transitive = (flags >> 6) & 0x1;
    partial = (flags >> 5) & 0x1;
    extended = (flags >> 4) & 0x1;
    type_code = getValue<uint8_t>(&buffer);
    if (extended && buffer_sz < 4) {
        setError(E_UPDATE, E_UNSPEC_UPDATE, NULL, 0);
        logger->log(ERROR, "BgpPathAttrib::parseHeader: invalid attribute header size (extended but size < 4).\n");
        return -1;
    }
    const ssize_t hdr_size = extended ? 4 : 3;

    if (extended) value_len = ntohs(getValue<uint16_t>(&buffer));
    else value_len = getValue<uint8_t>(&buffer);

    if (value_len > buffer_sz - hdr_size) {
        err_code = E_UPDATE;
        // This is kind of "invalid length", but we are not using E_ATTR_LEN.
        // E_ATTR_LEN: "Attribute Length that conflict with the expected length
        // (based on the attribute type code)." This is not based on type code,
        // but it is buffer overflow, so we set subcode to E_UNSPEC,
        setError(E_UPDATE, E_UNSPEC_UPDATE, NULL, 0);
        logger->log(ERROR, "BgpPathAttrib::parseHeader: value_length (%d) < buffer left (%d).\n", value_len, buffer_sz - hdr_size);
        return -1;
    }

    return hdr_size;
}

/**
 * @brief Write attribute header to buffer. (Flag, Type)
 * 
 * Write attribute header to buffer. Notice that only attribute flags and type
 * will be written to buffer. You need to write attribute length yourself.
 * 
 * @param to Destnation buiffer.
 * @param buffer_sz Max write size.
 * @return ssize_t Bytes written.
 * @retval -1 Failed to write buffer. error may be written to stderr with log
 * handler.
 * @retval >=0 Bytes written.
 */
ssize_t BgpPathAttrib::writeHeader(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < (extended ? 3 : 4)) {
        logger->log(ERROR, "BgpPathAttrib::writeHeader: dst buffer too small: %d\n", buffer_sz);
        return -1;
    }
    
    uint8_t *buffer = to;
    uint8_t flags = (optional << 7) | (transitive << 6)| (partial << 5) | (extended << 4);
    putValue<uint8_t>(&buffer, flags);
    putValue<uint8_t>(&buffer, type_code);
    return 2;
}
/**
 * @brief Construct a new Bgp Path Attrib Origin:: Bgp Path Attrib Origin object
 * 
 * @param logger Pointer to logger object for error logging.
 */
BgpPathAttribOrigin::BgpPathAttribOrigin(BgpLogHandler *logger) : BgpPathAttrib(logger) {
    transitive = true;
    type_code = ORIGIN;
}

BgpPathAttrib* BgpPathAttribOrigin::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttribOrigin::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribOrigin(*this);
}

ssize_t BgpPathAttribOrigin::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    const char *origin_name = NULL;

    switch(origin) {
        case 0: origin_name = "IGP"; break;
        case 1: origin_name= "EGP"; break;
        case 2: origin_name = "Incomplete"; break;
        default: origin_name = "Invalid"; break;
    }

    size_t written = 0;
    written += _print(indent, to, buf_sz, "OriginAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        written += _print(indent, to, buf_sz, "Origin { %s }\n", origin_name);
    }; indent--;

    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

ssize_t BgpPathAttribOrigin::parse(const uint8_t *from, size_t length) {
    ssize_t header_length = parseHeader(from, length);
    if (header_length < 0) return -1;

    if (type_code != ORIGIN) {
        logger->log(FATAL, "BgpPathAttribOrigin::parse: type in header mismatch.\n");
        throw "bad_type";
    }

    const uint8_t *buffer = from + 3;

    if (value_len < 1) {
        logger->log(ERROR, "BgpPathAttribOrigin::parse: incomplete attrib.\n");
        setError(E_UPDATE, E_UNSPEC_UPDATE, NULL, 0);
        return -1;
    }

    if (value_len != 1) {
        logger->log(ERROR, "BgpPathAttribOrigin::parse: bad length, want 1, saw %d.\n", value_len);
        setError(E_UPDATE, E_ATTR_LEN, from, value_len + header_length);
        return -1;
    }

    if (optional || !transitive || extended || partial) {
        logger->log(ERROR, "BgpPathAttribOrigin::parse: bad flag bits, must be !optional, !extended, !partial, transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from, value_len + header_length);
        return -1;
    }

    origin = getValue<uint8_t>(&buffer);

    if (origin > 2) {
        setError(E_UPDATE, E_ORIGIN, from, 4);
        logger->log(ERROR, "BgpPathAttribOrigin::parse: Bad Origin Value: %d.\n", origin);
        return -1;
    }

    return 4;
}

ssize_t BgpPathAttribOrigin::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < 4) {
        logger->log(ERROR, "BgpPathAttribOrigin::write: destination buffer size too small.\n");
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 0) return -1;
    uint8_t *buffer = to + 2;

    putValue<uint8_t>(&buffer, 1); // length = 1
    putValue<uint8_t>(&buffer, origin);
    return 4;
}

ssize_t BgpPathAttribOrigin::length() const {
    return 4;
}

/**
 * @brief Construct a new Bgp Path Attrib As Path:: Bgp Path Attrib As Path object
 * 
 * @param logger Pointer to logger object for error logging.
 * @param is_4b Enable four octets ASN support.
 */
BgpPathAttribAsPath::BgpPathAttribAsPath(BgpLogHandler *logger, bool is_4b) : BgpPathAttrib(logger) {
    this->is_4b = is_4b;
    transitive = true;
    type_code = AS_PATH;
}

/**
 * @brief Construct a new Bgp As Path Segment:: Bgp As Path Segment object
 * 
 * @param is_4b Enable four octets ASN support.
 * @param type Type of AS path segment.
 */
BgpAsPathSegment::BgpAsPathSegment(bool is_4b, uint8_t type) {
    this->is_4b = is_4b;
    this->type = type;
}

/**
 * @brief Get number of ASNs in the segment.
 * 
 * @return size_t Number of ASNs.
 */
size_t BgpAsPathSegment::getCount() const {
    return value.size();
}

/**
 * @brief Prepend ASN to AS segment.
 * 
 * @param asn ASN to prepend.
 * @return true ASN prepended.
 * @return false Failed to prepend ASN.
 */
bool BgpAsPathSegment::prepend(uint32_t asn) {
    if (value.size() >= (is_4b ? 127 : 255)) return false;
    uint32_t prepend_asn = is_4b ? asn : (asn >= 0xffff ? 23456 : asn);

    value.insert(value.begin(), prepend_asn);
    return true;
}

BgpPathAttrib* BgpPathAttribAsPath::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttribAsPath::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribAsPath(*this);
}

ssize_t BgpPathAttribAsPath::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "AsPathAttribute {\n");
    indent++; {
        written += _print(indent, to, buf_sz, "FourOctet { %s }\n", is_4b ? "true" : "false");
        written += printFlags(indent, to, buf_sz);
        if (as_paths.size() == 0) written += _print(indent, to, buf_sz, "AsPathSegments { } \n");
        else {
            written += _print(indent, to, buf_sz, "AsPathSegments {\n");
            indent++; {
                for (const BgpAsPathSegment &seg : as_paths) {
                    switch (seg.type) {
                        case 1: written += _print(indent, to, buf_sz, "AsSet {\n"); break;
                        case 2: written += _print(indent, to, buf_sz, "AsSequence {\n"); break;
                        default: written += _print(indent, to, buf_sz, "Invalid {\n"); break;   
                    }
                    indent++; {
                        for (uint32_t asn : seg.value) {
                            written += _print(indent, to, buf_sz, "%u\n", asn);
                        }
                    }; indent--;
                    written += _print(indent, to, buf_sz, "}\n");
                }
            }; indent--;
            written += _print(indent, to, buf_sz, "}\n");
        }
    }; indent--;
    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

ssize_t BgpPathAttribAsPath::parse(const uint8_t *from, size_t length) {
    ssize_t header_length = parseHeader(from, length);
    if (header_length < 0) return -1;

    if (type_code != AS_PATH) {
        logger->log(FATAL, "BgpPathAttribAsPath::parse: type in header mismatch.\n");
        throw "bad_type";
    }

    if (optional || !transitive || partial) {
        logger->log(ERROR, "BgpPathAttribAsPath::parse: bad flag bits, must be !optional, !partial, transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from , value_len + header_length);
        return -1;
    }

    const uint8_t *buffer = from + header_length;

    // empty as_path
    if (value_len == 0) return header_length;

    uint8_t parsed_len = 0;

    while (parsed_len < value_len) {
        // bad as_path
        if (value_len - parsed_len < 3) {
            logger->log(ERROR, "BgpPathAttribAsPath::parse: incomplete as_path segment.\n");
            setError(E_UPDATE, E_AS_PATH, NULL, 0);
            return -1;
        }

        uint8_t type = getValue<uint8_t>(&buffer);
        uint8_t n_asn = getValue<uint8_t>(&buffer);

        // type & count
        parsed_len += 2;

        uint8_t asns_length = is_4b ? n_asn * sizeof(uint32_t) : n_asn * sizeof(uint16_t);

        // overflow
        if (parsed_len + asns_length > value_len) {
            logger->log(ERROR, "BgpPathAttribAsPath::parse: as_path overflow attribute length.\n");
            setError(E_UPDATE, E_AS_PATH, NULL, 0);
            return -1;
        }

        BgpAsPathSegment path(is_4b, type);
        if (is_4b) for (int i = 0; i < n_asn; i++) path.value.push_back(ntohl(getValue<uint32_t>(&buffer)));
        else for (int i = 0; i < n_asn; i++) path.value.push_back(ntohs(getValue<uint16_t>(&buffer)));
        as_paths.push_back(path);

        // parsed asns
        parsed_len += asns_length;
    }

    if (parsed_len != value_len) {
        logger->log(FATAL, "BgpPathAttribAsPath::parse: parsed length and value length mismatch, but no error reported.\n");
        throw "bad_parse";
    }

    return parsed_len + header_length;
}

ssize_t BgpPathAttribAsPath::length() const {
    size_t len = (extended ? 4: 3); // header len = 4/3

    for (const BgpAsPathSegment &seg : as_paths) {
        len += (seg.is_4b ? 4 : 2) * seg.value.size() + 2;
    }

    return len;
}

/**
 * @brief Add a new segment with one ASN in it.
 * 
 * @param asn The first ASN in the segment.
 */
void BgpPathAttribAsPath::addSeg(uint32_t asn) {
    BgpAsPathSegment segment(is_4b, AS_SEQUENCE);
    segment.prepend(asn);
    as_paths.push_back(segment);
}

/**
 * @brief Prepend an ASN into AS path.
 * 
 * This method will prepend an ASN to AS_SEQUENCE segment if the segment is the
 * first in path. A new AS_SEQUENCE will be create and append to AS_PATH 
 * otherwise. A new AS_SEQUENCE will also be create if the current one is full.
 * 
 * @param asn The ASN to append.
 * @return true ASN prepended.
 * @return false Failed to append ASN. error may be written to stderr with log
 * handler.
 */
bool BgpPathAttribAsPath::prepend(uint32_t asn) {
    if (as_paths.size() == 0) {
        // nothing here yet, add a new sequence. (5.1.2.b.3)
        addSeg(asn);
        return true;
    }

    // something here already. what to do?
    BgpAsPathSegment *segment = as_paths.data();

    if (segment->type == AS_SET) {
        // seg is set, create a new segment of type AS_SEQUENCE (5.1.2.b.2)
        // FIXME: checks needed: really create a new segment? 
        addSeg(asn);
        return true;
    } else if (segment->type == AS_SEQUENCE) {
        if (segment->getCount() >= (is_4b ? 127 : 255)) {
            // seg full, create a new segment of type AS_SEQUENCE (5.1.2.b.1)
            addSeg(asn);
            return true;
        } else {
            segment->prepend(asn);
            return true;
        }
    }

    logger->log(ERROR, "BgpPathAttribAsPath::prepend: unknow first segment type: %d, can't append.\n", segment->type);
    return false;
}

ssize_t BgpPathAttribAsPath::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < 3) {
        logger->log(ERROR, "BgpPathAttribAsPath::write: destination buffer size too small.\n");
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 0) return -1;
    uint8_t *buffer = to + 2; // 1 for flags, 1 for type code

    // keep track of length field so we can write it later
    uint8_t *len_field = buffer;

    // skip length field for now
    buffer += (extended ? 2: 1);

    uint16_t written_len = 0;

    for (const BgpAsPathSegment &seg : as_paths) {
        if (seg.is_4b != is_4b) { // maybe allow 2b-seg in 4b-mode?
            logger->log(ERROR, "BgpPathAttribAsPath::write: segment 4b-mode and message 4b-mode mismatch.\n");
            return -1;
        }

        size_t asn_count = seg.value.size();

        if (asn_count >= (is_4b ? 127 : 255)) {
            logger->log(ERROR, "BgpPathAttribAsPath::write: segment size too big: %d\n", asn_count);
            return -1;
        }

        size_t bytes_need = asn_count * (is_4b ? sizeof(uint32_t) : sizeof(uint16_t)) + 2;

        if (written_len + bytes_need > buffer_sz) {
            logger->log(ERROR, "BgpPathAttribAsPath::write: destination buffer size too small.\n");
            return -1;
        }

        putValue<uint8_t>(&buffer, seg.type);
        putValue<uint8_t>(&buffer, asn_count);

        if (seg.is_4b) for (uint32_t asn : seg.value) putValue<uint32_t>(&buffer, htonl(asn));
        else for (uint16_t asn : seg.value) putValue<uint16_t>(&buffer, htons(asn));

        written_len += bytes_need;
    }

    // fill in the length.
    if (extended) {
      putValue<uint16_t>(&len_field, htons(written_len));
    } else {
      putValue<uint8_t>(&len_field, written_len);
    }

    // written_len: the as_paths, 3/4: attr header (flag, typecode, length)
    return written_len + (extended ? 4: 3);
}

/**
 * @brief Construct a new Bgp Path Attrib Nexthop:: Bgp Path Attrib Nexthop object
 * 
 * @param logger Pointer to logger object for error logging.
 */
BgpPathAttribNexthop::BgpPathAttribNexthop(BgpLogHandler *logger) : BgpPathAttrib(logger) {
    type_code = NEXT_HOP;
    transitive = true;
}

ssize_t BgpPathAttribNexthop::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "NexthopAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        written += _print(indent, to, buf_sz, "Nexthop { %s }\n", inet_ntoa(*(struct in_addr*) &next_hop));
    }; indent--;

    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

BgpPathAttrib* BgpPathAttribNexthop::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttribNexthop::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribNexthop(*this);
}

ssize_t BgpPathAttribNexthop::parse(const uint8_t *from, size_t length) {
    ssize_t header_length = parseHeader(from, length);
    if (header_length < 0) return -1;

    if (type_code != NEXT_HOP) {
        logger->log(FATAL, "BgpPathAttribNexthop::parse: type in header mismatch.\n");
        throw "bad_type";
    }

    const uint8_t *buffer = from + 3;

    if (value_len < 4) {
        logger->log(ERROR, "BgpPathAttribNexthop::parse: incomplete attrib.\n");
        setError(E_UPDATE, E_UNSPEC_UPDATE, NULL, 0);
        return -1;
    }

    if (value_len != 4) {
        logger->log(ERROR, "BgpPathAttribNexthop::parse: bad length, want 4, saw %d.\n", value_len);
        setError(E_UPDATE, E_ATTR_LEN, from, value_len + header_length);
        return -1;
    }

    if (optional || !transitive || extended || partial) {
        logger->log(ERROR, "BgpPathAttribNexthop::parse: bad flag bits, must be !optional, !extended, !partial, transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from, value_len + header_length);
        return -1;
    }

    next_hop = getValue<uint32_t>(&buffer);

    return 7;
}

ssize_t BgpPathAttribNexthop::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < 7) {
        logger->log(ERROR, "BgpPathAttribNexthop::write: destination buffer size too small.\n");
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 0) return -1;
    uint8_t *buffer = to + 2;

    putValue<uint8_t>(&buffer, 4); // length = 4
    putValue<uint32_t>(&buffer, next_hop);
    return 7;
}

ssize_t BgpPathAttribNexthop::length() const {
    return 7;
}

/**
 * @brief Construct a new Bgp Path Attrib Med:: Bgp Path Attrib Med object
 * 
 * @param logger Pointer to logger object for error logging.
 */
BgpPathAttribMed::BgpPathAttribMed(BgpLogHandler *logger) : BgpPathAttrib(logger) {
    type_code = MULTI_EXIT_DISC;
    optional = true;
}

ssize_t BgpPathAttribMed::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "MedAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        written += _print(indent, to, buf_sz, "Med { %d }\n", med);
    }; indent--;

    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

BgpPathAttrib* BgpPathAttribMed::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttribMed::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribMed(*this);
}

ssize_t BgpPathAttribMed::parse(const uint8_t *from, size_t length) {
    ssize_t header_length = parseHeader(from, length);
    if (header_length < 0) return -1;

    if (type_code != MULTI_EXIT_DISC) {
        logger->log(FATAL, "BgpPathAttribMed::parse: type in header mismatch.\n");
        throw "bad_type";
    }

    const uint8_t *buffer = from + 3;

    if (value_len < 4) {
        logger->log(ERROR, "BgpPathAttribMed::parse: incomplete attrib.\n");
        setError(E_UPDATE, E_UNSPEC_UPDATE, NULL, 0);
        return -1;
    }

    if (value_len != 4) {
        logger->log(ERROR, "BgpPathAttribMed::parse: bad length, want 4, saw %d.\n", value_len);
        setError(E_UPDATE, E_ATTR_LEN, from, value_len + header_length);
        return -1;
    }

    if (!optional || transitive || extended || partial) {
        logger->log(ERROR, "BgpPathAttribMed::parse: bad flag bits, must be optional, !extended, !partial, !transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from, value_len + header_length);
        return -1;
    }

    med = ntohl(getValue<uint32_t>(&buffer));

    return 7;
}

ssize_t BgpPathAttribMed::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < 7) {
        logger->log(ERROR, "BgpPathAttribMed::write: destination buffer size too small.\n");
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 0) return -1;
    uint8_t *buffer = to + 2;

    putValue<uint8_t>(&buffer, 4); // length = 4
    putValue<uint32_t>(&buffer, htonl(med));
    return 7;
}

ssize_t BgpPathAttribMed::length() const {
    return 7;
}

/**
 * @brief Construct a new Bgp Path Attrib Local Pref:: Bgp Path Attrib Local Pref object
 * 
 * @param logger Pointer to logger object for error logging.
 */
BgpPathAttribLocalPref::BgpPathAttribLocalPref(BgpLogHandler *logger) : BgpPathAttrib(logger) {
    type_code = LOCAL_PREF;
}

ssize_t BgpPathAttribLocalPref::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "LocalPrefAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        written += _print(indent, to, buf_sz, "LocalPref { %d }\n", local_pref);
    }; indent--;

    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

BgpPathAttrib* BgpPathAttribLocalPref::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttribLocalPref::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribLocalPref(*this);
}

ssize_t BgpPathAttribLocalPref::parse(const uint8_t *from, size_t length) {
    ssize_t header_length = parseHeader(from, length);
    if (header_length < 0) return -1;

    if (type_code != LOCAL_PREF) {
        logger->log(FATAL, "BgpPathAttribLocalPref::parse: type in header mismatch.\n");
        throw "bad_type";
    }

    const uint8_t *buffer = from + 3;

    if (value_len < 4) {
        logger->log(ERROR, "BgpPathAttribLocalPref::parse: incomplete attrib.\n");
        setError(E_UPDATE, E_UNSPEC_UPDATE, NULL, 0);
        return -1;
    }

    if (value_len != 4) {
        logger->log(ERROR, "BgpPathAttribLocalPref::parse: bad length, want 4, saw %d.\n", value_len);
        setError(E_UPDATE, E_ATTR_LEN, from, value_len + header_length);
        return -1;
    }

    if (optional || !transitive || extended || partial) {
        logger->log(ERROR, "BgpPathAttribLocalPref::parse: bad flag bits, must be !optional, !extended, !partial, transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from, value_len + header_length);
        return -1;
    }

    local_pref = ntohl(getValue<uint32_t>(&buffer));

    return 7;
}

ssize_t BgpPathAttribLocalPref::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < 7) {
        logger->log(ERROR, "BgpPathAttribLocalPref::write: destination buffer size too small.\n");
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 0) return -1;
    uint8_t *buffer = to + 2;

    putValue<uint8_t>(&buffer, 4); // length = 4
    putValue<uint32_t>(&buffer, htonl(local_pref));
    return 7;
}

ssize_t BgpPathAttribLocalPref::length() const {
    return 7;
}

/**
 * @brief Construct a new Bgp Path Attrib Atomic Aggregate:: Bgp Path Attrib Atomic Aggregate object
 * 
 * @param logger Pointer to logger object for error logging.
 */
BgpPathAttribAtomicAggregate::BgpPathAttribAtomicAggregate(BgpLogHandler *logger) : BgpPathAttrib(logger) {
    type_code = ATOMIC_AGGREGATE;
    transitive = true;
}

ssize_t BgpPathAttribAtomicAggregate::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "AtomicAggregateAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
    }; indent--;

    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

BgpPathAttrib* BgpPathAttribAtomicAggregate::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttribAtomicAggregate::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribAtomicAggregate(*this);
}

ssize_t BgpPathAttribAtomicAggregate::parse(const uint8_t *from, size_t length) {
    ssize_t header_length = parseHeader(from, length);
    if (header_length < 0) return -1;

    if (type_code != ATOMIC_AGGREGATE) {
        logger->log(FATAL, "BgpPathAttribAtomicAggregate::parse: type in header mismatch.\n");
        throw "bad_type";
    }

    if (value_len != 0) {
        logger->log(ERROR, "BgpPathAttribAtomicAggregate::parse: bad length, want 0, saw %d.\n", value_len);
        setError(E_UPDATE, E_ATTR_LEN, from, value_len + header_length);
        return -1;
    }

    if (optional || !transitive || extended || partial) {
        logger->log(ERROR, "BgpPathAttribAtomicAggregate::parse: bad flag bits, must be !optional, !extended, !partial, transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from, value_len + header_length);
        return -1;
    }

    return 3;
}

ssize_t BgpPathAttribAtomicAggregate::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < 3) {
        logger->log(ERROR, "BgpPathAttribAtomicAggregate::write: destination buffer size too small.\n");
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 0) return -1;
    uint8_t *buffer = to + 2;

    putValue<uint8_t>(&buffer, 0); // length = 0

    return 3;
}

ssize_t BgpPathAttribAtomicAggregate::length() const {
    return 3;
}

/**
 * @brief Construct a new Bgp Path Attrib Aggregator:: Bgp Path Attrib Aggregator object
 * 
 * @param logger Pointer to logger object for error logging.
 * @param is_4b Enable four octets ASN support.
 */
BgpPathAttribAggregator::BgpPathAttribAggregator(BgpLogHandler *logger, bool is_4b) : BgpPathAttrib(logger) {
    this->is_4b = is_4b;
    type_code = AGGREATOR;
    optional = true;
    transitive = true;
}

ssize_t BgpPathAttribAggregator::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "AggregatorAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        written += _print(indent, to, buf_sz, "Aggregator { %s }\n", inet_ntoa(*(struct in_addr*) &aggregator));
        written += _print(indent, to, buf_sz, "AggregatorAsn { %d }\n", aggregator_asn);
    }; indent--;

    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

BgpPathAttrib* BgpPathAttribAggregator::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttribAggregator::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribAggregator(*this);
}

ssize_t BgpPathAttribAggregator::parse(const uint8_t *from, size_t length) {
    ssize_t header_length = parseHeader(from, length);
    if (header_length < 0) return -1;

    if (type_code != AGGREATOR) {
        logger->log(FATAL, "BgpPathAttribAggregator::parse: type in header mismatch.\n");
        throw "bad_type";
    }

    const uint8_t *buffer = from + 3;
    const uint8_t want_len = (is_4b ? 8 : 6);

    if (value_len < want_len) {
        logger->log(ERROR, "BgpPathAttribAggregator::parse: incomplete attrib.\n");
        setError(E_UPDATE, E_UNSPEC_UPDATE, NULL, 0);
        return -1;
    }

    if (value_len != want_len) {
        logger->log(ERROR, "BgpPathAttribAggregator::parse: bad length, want %d, saw %d.\n", want_len, value_len);
        setError(E_UPDATE, E_ATTR_LEN, from, value_len + header_length);
        return -1;
    }

    if (!optional || !transitive || extended || partial) {
        logger->log(ERROR, "BgpPathAttribAggregator::parse: bad flag bits, must be optional, !extended, !partial, transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from, value_len + header_length);
        return -1;
    }

    if (is_4b) aggregator_asn = ntohl(getValue<uint32_t>(&buffer));
    else aggregator_asn = ntohs(getValue<uint16_t>(&buffer));
    aggregator = getValue<uint32_t>(&buffer);

    return 3 + want_len;
}

ssize_t BgpPathAttribAggregator::write(uint8_t *to, size_t buffer_sz) const {
    uint8_t write_value_sz = (is_4b ? 6 : 8);

    if (buffer_sz < (size_t) (write_value_sz + 3)) {
        logger->log(ERROR, "BgpPathAttribAggregator::write: destination buffer size too small.\n");
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 0) return -1;
    uint8_t *buffer = to + 2;

    putValue<uint8_t>(&buffer, write_value_sz);
    
    if (!is_4b && aggregator_asn >= 0xffff) {
        logger->log(ERROR, "BgpPathAttribAggregator::write: bad asn. not 4b but asn is %d.\n", aggregator_asn);
        return -1;
    }

    if (is_4b) putValue<uint32_t>(&buffer, htonl(aggregator_asn));
    else putValue<uint16_t>(&buffer, htons(aggregator_asn));
    putValue<uint32_t>(&buffer, aggregator);

    return write_value_sz + 3;
}

ssize_t BgpPathAttribAggregator::length() const {
    return 3 + (is_4b ? 6 : 8);
}

/**
 * @brief Construct a new Bgp Path Attrib As 4 Path:: Bgp Path Attrib As 4 Path object
 * 
 * @param logger Pointer to logger object for error logging.
 */
BgpPathAttribAs4Path::BgpPathAttribAs4Path(BgpLogHandler *logger) : BgpPathAttrib(logger) {
    optional = true;
    transitive = true;
    type_code = AS4_PATH;
}

ssize_t BgpPathAttribAs4Path::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "As4PathAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        if (as4_paths.size() == 0) written += _print(indent, to, buf_sz, "As4PathSegments { } \n");
        else {
            written += _print(indent, to, buf_sz, "As4PathSegments {\n");
            indent++; {
                for (const BgpAsPathSegment &seg : as4_paths) {
                    switch (seg.type) {
                        case 1: written += _print(indent, to, buf_sz, "AsSet {\n"); break;
                        case 2: written += _print(indent, to, buf_sz, "AsSequence {\n"); break;
                        default: written += _print(indent, to, buf_sz, "Invalid {\n"); break;   
                    }
                    indent++; {
                        for (uint32_t asn : seg.value) {
                            written += _print(indent, to, buf_sz, "%u\n", asn);
                        }
                    }; indent--;
                    written += _print(indent, to, buf_sz, "}\n");
                }
            }; indent--;
            written += _print(indent, to, buf_sz, "}\n");
        }
    }; indent--;
    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

BgpPathAttrib* BgpPathAttribAs4Path::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttribAs4Path::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribAs4Path(*this);
}

ssize_t BgpPathAttribAs4Path::parse(const uint8_t *from, size_t length) {
    ssize_t header_length = parseHeader(from, length);
    if (header_length < 0) return -1;

    if (type_code != AS4_PATH) {
        logger->log(FATAL, "BgpPathAttribAs4Path::parse: type in header mismatch.\n");
        throw "bad_type";
    }

    if (!optional || !transitive || extended || partial) {
        logger->log(ERROR, "BgpPathAttribAs4Path::parse: bad flag bits, must be optional, !extended, !partial, transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from , value_len + header_length);
        return -1;
    }

    const uint8_t *buffer = from + 3;

    // empty as_path
    if (value_len == 0) return 3; 

    uint8_t parsed_len = 0;

    while (parsed_len < value_len) {
        // bad as_path
        if (value_len - parsed_len < 3) {
            logger->log(ERROR, "BgpPathAttribAs4Path::parse: incomplete as_path segment.\n");
            setError(E_UPDATE, E_AS_PATH, NULL, 0);
            return -1;
        }

        uint8_t type = getValue<uint8_t>(&buffer);
        uint8_t n_asn = getValue<uint8_t>(&buffer);

        // type & count
        parsed_len += 2;

        uint8_t asns_length = n_asn * sizeof(uint32_t);

        // overflow
        if (parsed_len + asns_length > value_len) {
            logger->log(ERROR, "BgpPathAttribAs4Path::parse: as_path overflow attribute length.\n");
            setError(E_UPDATE, E_AS_PATH, NULL, 0);
            return -1;
        }

        BgpAsPathSegment path(true, type);
        for (int i = 0; i < n_asn; i++) path.value.push_back(ntohl(getValue<uint32_t>(&buffer)));
        as4_paths.push_back(path);

        // parsed asns
        parsed_len += asns_length;
    }

    if (parsed_len != value_len) {
        logger->log(FATAL, "BgpPathAttribAs4Path::parse: parsed length and value length mismatch, but no error reported.\n");
        throw "bad_parse";
    }

    return parsed_len + 3;
}

ssize_t BgpPathAttribAs4Path::length() const {
    size_t len = 3; // header len = 3

    for (const BgpAsPathSegment &seg : as4_paths) {
        len += 4 * seg.value.size() + 2;
    }

    return len;
}

/**
 * @brief Add a new segment with one ASN in it.
 * 
 * @param asn The first ASN in the segment.
 */
void BgpPathAttribAs4Path::addSeg(uint32_t asn) {
    BgpAsPathSegment segment(true, AS_SEQUENCE);
    segment.prepend(asn);
    as4_paths.push_back(segment);
}

/**
 * @brief Prepend an ASN into AS4 path.
 * 
 * This method will prepend an ASN to AS_SEQUENCE segment if the segment is the
 * first in path. A new AS_SEQUENCE will be create and append to AS_PATH 
 * otherwise. A new AS_SEQUENCE will also be create if the current one is full.
 * 
 * @param asn The ASN to append.
 * @return true ASN prepended.
 * @return false Failed to append ASN. error may be written to stderr with log
 * handler.
 */
bool BgpPathAttribAs4Path::prepend(uint32_t asn) {
    if (as4_paths.size() == 0) {
        // nothing here yet, add a new sequence. (5.1.2.b.3)
        addSeg(asn);
        return true;
    }

    // something here already. what to do?
    BgpAsPathSegment *segment = as4_paths.data();

    if (segment->type == AS_SET) {
        // seg is set, create a new segment of type AS_SEQUENCE (5.1.2.b.2)
        // FIXME: checks needed: really create a new segment? 
        addSeg(asn);
        return true;
    } else if (segment->type == AS_SEQUENCE) {
        if (segment->getCount() >= 127) {
            // seg full, create a new segment of type AS_SEQUENCE (5.1.2.b.1)
            addSeg(asn);
            return true;
        } else {
            segment->prepend(asn);
            return true;
        }
    }

    logger->log(ERROR, "BgpPathAttribAs4Path::prepend: unknow first segment type: %d, can't append.\n", segment->type);
    return false;
}

ssize_t BgpPathAttribAs4Path::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < 3) {
        logger->log(ERROR, "BgpPathAttribAs4Path::write: destination buffer size too small.\n");
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 0) return -1;
    uint8_t *buffer = to + 2;

    // keep track of length field so we can write it later
    uint8_t *len_field = buffer;

    // skip length field for now
    buffer++;

    uint8_t written_len = 0;

    for (const BgpAsPathSegment &seg4 : as4_paths) {
        size_t asn_count = seg4.value.size();

        if (asn_count > 127) {
            logger->log(ERROR, "BgpPathAttribAs4Path::write: segment size too big: %d\n", asn_count);
            return -1;
        }

        // asn list + seg type & asn count
        size_t bytes_need = asn_count * sizeof(uint32_t) + 2;

        if (written_len + bytes_need > buffer_sz) {
            logger->log(ERROR, "BgpPathAttribAs4Path::write: destination buffer size too small.\n");
            return -1;
        }

        // put type
        putValue<uint8_t>(&buffer, seg4.type);

        // put asn count
        putValue<uint8_t>(&buffer, asn_count);

        // put asns
        for (uint32_t asn : seg4.value) {
            putValue<uint32_t>(&buffer, htonl(asn));
        }

        written_len += bytes_need;
    }

    // fill in the length.
    putValue<uint8_t>(&len_field, written_len);

    // written_len: the as_paths, 3: attr header (flag, typecode, length)
    return written_len + 3;
}

BgpPathAttrib* BgpPathAttribAs4Aggregator::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttribAs4Aggregator::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribAs4Aggregator(*this);
}

/**
 * @brief Construct a new Bgp Path Attrib As 4 Aggregator:: Bgp Path Attrib As 4 Aggregator object
 * 
 * @param logger Pointer to logger object for error logging.
 */
BgpPathAttribAs4Aggregator::BgpPathAttribAs4Aggregator(BgpLogHandler *logger) : BgpPathAttrib(logger) {
    type_code = AS4_AGGREGATOR;
    optional = true;
    transitive = true;
}

ssize_t BgpPathAttribAs4Aggregator::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "Aggregator4Attribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        written += _print(indent, to, buf_sz, "Aggregator { %s }\n", inet_ntoa(*(struct in_addr*) &aggregator));
        written += _print(indent, to, buf_sz, "AggregatorAsn { %d }\n", aggregator_asn4);
    }; indent--;

    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

ssize_t BgpPathAttribAs4Aggregator::parse(const uint8_t *from, size_t length) {
    ssize_t header_length = parseHeader(from, length);
    if (header_length < 0) return -1;

    if (type_code != AS4_AGGREGATOR) {
        logger->log(FATAL, "BgpPathAttribAs4Aggregator::parse: type in header mismatch.\n");
        throw "bad_type";
    }

    const uint8_t *buffer = from + 3;

    if (value_len < 8) {
        logger->log(ERROR, "BgpPathAttribAs4Aggregator::parse: incomplete attrib.\n");
        setError(E_UPDATE, E_UNSPEC_UPDATE, NULL, 0);
        return -1;
    }

    if (value_len != 8) {
        logger->log(ERROR, "BgpPathAttribAs4Aggregator::parse: bad length, want 8, saw %d.\n", value_len);
        setError(E_UPDATE, E_ATTR_LEN, from, value_len + header_length);
        return -1;
    }

    if (!optional || !transitive || extended || partial) {
        logger->log(ERROR, "BgpPathAttribAs4Aggregator::parse: bad flag bits, must be optional, !extended, !partial, transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from, value_len + header_length);
        return -1;
    }

    aggregator_asn4 = ntohl(getValue<uint32_t>(&buffer));
    aggregator = getValue<uint32_t>(&buffer);

    return 11;
}

ssize_t BgpPathAttribAs4Aggregator::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < 11) {
        logger->log(ERROR, "BgpPathAttribAs4Aggregator::write: destination buffer size too small.\n");
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 0) return -1;
    uint8_t *buffer = to + 2;

    putValue<uint8_t>(&buffer, 11);

    putValue<uint32_t>(&buffer, htonl(aggregator_asn4));
    putValue<uint32_t>(&buffer, aggregator);

    return 11;
}

ssize_t BgpPathAttribAs4Aggregator::length() const {
    return 11;
}

/**
 * @brief Construct a new Bgp Path Attrib Community:: Bgp Path Attrib Community object
 * 
 * @param logger Pointer to logger object for error logging.
 */
BgpPathAttribCommunity::BgpPathAttribCommunity(BgpLogHandler *logger) : BgpPathAttrib(logger) {
    type_code = COMMUNITY;
    optional = true;
    transitive = true;
}

ssize_t BgpPathAttribCommunity::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "CommunityAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        written += _print(indent, to, buf_sz, "Community {\n");
        indent++; {
            for (uint32_t community : communites) {
                uint16_t community_[2];
                memcpy(community_, &community, 4);
                written += _print(indent, to, buf_sz, "%d:%d\n", ntohs(community_[0]), ntohs(community_[1]));
            }
        }; indent--;
        written += _print(indent, to, buf_sz, "}\n");
    }; indent--;
    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

BgpPathAttrib* BgpPathAttribCommunity::clone() const {
    if(hasError()) {
        logger->log(FATAL, "BgpPathAttribCommunity::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribCommunity(*this);
}

ssize_t BgpPathAttribCommunity::parse(const uint8_t *from, size_t length) {
    ssize_t header_length = parseHeader(from, length);
    if (header_length < 0) return -1;

    if (type_code != COMMUNITY) {
        logger->log(FATAL, "BgpPathAttribCommunity::parse: type in header mismatch.\n");
        throw "bad_type";
    }

    const uint8_t *buffer = from + 3;

    if (value_len < 4) {
        logger->log(ERROR, "BgpPathAttribCommunity::parse: incomplete attrib.\n");
        setError(E_UPDATE, E_UNSPEC_UPDATE, NULL, 0);
        return -1;
    }

    if (value_len % 4 != 0) {
        logger->log(ERROR, "BgpPathAttribCommunity::parse: bad length, want multiple of 4, saw %d.\n", value_len);
        setError(E_UPDATE, E_ATTR_LEN, from, value_len + header_length);
        return -1;
    }

    if (!optional || !transitive || extended || partial) {
        logger->log(ERROR, "BgpPathAttribCommunity::parse: bad flag bits, must be optional, !extended, !partial, transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from, value_len + header_length);
        return -1;
    }

    size_t read_len = 0;

    while (read_len < value_len) {
        communites.push_back(getValue<uint32_t>(&buffer));
        read_len += 4;
    }

    if (read_len != value_len) {
        logger->log(FATAL, " BgpPathAttribCommunity::parse: parse ends with read_len != value_len.\n");
        throw "bad_parse";
    }

    return value_len + 3;
}

ssize_t BgpPathAttribCommunity::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < 7) {
        logger->log(ERROR, "BgpPathAttribCommunity::write: destination buffer size too small.\n");
        return -1;
    }

    if (writeHeader(to, buffer_sz) < 0) return -1;
    uint8_t *buffer = to + 2;

    putValue<uint8_t>(&buffer, 4 * communites.size()); // length = 4 * nCommunity
    
    size_t write_len = 0;

    for (uint32_t community : communites) {
        write_len += putValue<uint32_t>(&buffer, community);
    }

    return 3 + write_len;
}

ssize_t BgpPathAttribCommunity::length() const {
    return 3 + 4 * communites.size();
}

BgpPathAttribMpNlriBase::BgpPathAttribMpNlriBase(BgpLogHandler *logger) : BgpPathAttrib(logger) {
    optional = true;
    afi = Afi::UNKNOWN_AFI;
    safi = Safi::UNKNOWN_SAFI;
}

int16_t BgpPathAttribMpNlriBase::GetAfiFromBuffer(const uint8_t *buffer, size_t length, bool extended) {
    if (length < 3) return -1;
    const uint8_t *ptr = buffer + (extended ? 4: 3);
    return ntohs(getValue<uint16_t>(&ptr));
}

ssize_t BgpPathAttribMpNlriBase::parseHeader(const uint8_t *from, size_t length, bool is_unreach) {
    ssize_t hdr_len = BgpPathAttrib::parseHeader(from, length);

    if (hdr_len < 0) return -1;

    if (!optional || transitive || partial) {
        logger->log(ERROR, "BgpPathAttribMpNlriBase::parseHeader: bad flag bits, must be optional, !partial, !transitive.\n");
        setError(E_UPDATE, E_ATTR_FLAG, from , value_len + hdr_len);
        return -1;
    }

    if (type_code != MP_REACH_NLRI && type_code != MP_UNREACH_NLRI) {
        logger->log(FATAL, "BgpPathAttribMpNlriBase::parseHeader: type in header mismatch.\n");
        throw "bad_type";
    }

    if (value_len < (is_unreach ? 3 : 5)) {
        logger->log(ERROR, "BgpPathAttribMpNlriBase::parseHeader: incompete attribute.\n");
        setError(E_UPDATE, E_OPT_ATTR, NULL, 0);
        return -1;
    }

    const uint8_t *buffer = from + hdr_len;
    afi = ntohs(getValue<uint16_t>(&buffer));
    safi = getValue<uint8_t>(&buffer);

    return hdr_len + 3;
}

BgpPathAttribMpReachNlriIpv6::BgpPathAttribMpReachNlriIpv6(BgpLogHandler *logger) : BgpPathAttribMpNlriBase(logger) {
    type_code = MP_REACH_NLRI;
    afi = IPV6;
}

BgpPathAttrib* BgpPathAttribMpReachNlriIpv6::clone() const {
    if (hasError()) {
        logger->log(ERROR, "BgpPathAttribMpReachNlriIpv6::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }
    return new BgpPathAttribMpReachNlriIpv6(*this);
}

ssize_t BgpPathAttribMpReachNlriIpv6::parse(const uint8_t *from, size_t length) {
    ssize_t hdr_len = BgpPathAttribMpNlriBase::parseHeader(from, length, false);

    if (hdr_len < 0) return -1;

    if (afi != IPV6) {
        logger->log(FATAL, "BgpPathAttribMpReachNlriIpv6::parse: afi mismatch.\n");
        throw "bad_type";
    }

    const uint8_t *buffer = from + hdr_len;
    uint8_t nexthop_length = getValue<uint8_t>(&buffer);

    if (nexthop_length != 16 && nexthop_length != 32) {
        logger->log(ERROR, "BgpPathAttribMpReachNlriIpv6::parse: bad nexthop length %d (want 16 or 32).\n", nexthop_length);
        setError(E_UPDATE, E_OPT_ATTR, NULL, 0);
        return -1;
    }

    ssize_t buf_left = value_len - hdr_len - 1 + (extended ? 4 : 3); // 4/3: attr headers

    if (buf_left < (ssize_t) nexthop_length) {
        logger->log(ERROR, "BgpPathAttribMpReachNlriIpv6::parse: nexthop overflows buffer.\n");
        setError(E_UPDATE, E_OPT_ATTR, NULL, 0);
        return -1;
    }

    memcpy(nexthop_global, buffer, 16); buffer += 16;
    if (nexthop_length == 32) {
        memcpy(nexthop_linklocal, buffer, 16); buffer += 16;
    } else memset(nexthop_linklocal, 0, 16);
    
    buf_left -= nexthop_length;

    if (buf_left < 1) {
        logger->log(ERROR, "BgpPathAttribMpReachNlriIpv6::parse: reserved bits overflows buffer.\n");
        setError(E_UPDATE, E_OPT_ATTR, NULL, 0);
        return -1;
    }

    uint8_t res = getValue<uint8_t>(&buffer);
    buf_left--;

    if (res != 0) {
        logger->log(WARN, "BgpPathAttribMpReachNlriIpv6::parse: reserved bits != 0\n");
    }

    while (buf_left > 0) {
        Prefix6 this_prefix = Prefix6();
        ssize_t pfx_read_len = this_prefix.parse(buffer, buf_left);

        if (pfx_read_len < 0) {
            logger->log(ERROR, "BgpPathAttribMpReachNlriIpv6::parse: error parsing nlri entry.\n");
            setError(E_UPDATE, E_OPT_ATTR, NULL, 0);
            return -1;
        }

        buffer += pfx_read_len;
        buf_left -= pfx_read_len;
        nlri.push_back(this_prefix);
    }

    if (buf_left != 0) {
        logger->log(FATAL, "BgpPathAttribMpReachNlriIpv6::parse: parsed end with non-zero buf_left (%d).\n", buf_left);
        throw "bad_parse";
    }

    return value_len + hdr_len - 3; // 3: afi/safi, already part of "value_len"
}

ssize_t BgpPathAttribMpReachNlriIpv6::write(uint8_t *to, size_t buffer_sz) const {
    ssize_t header_len = writeHeader(to, buffer_sz);

    if (header_len < 0) return -1;
    uint8_t *attr_len_field = to + header_len;
    uint8_t *buffer = attr_len_field + (extended ? 2: 1);

    if (buffer_sz - header_len < 5) {
        logger->log(ERROR, "BgpPathAttribMpReachNlriIpv6::write: dst buffer too small.\n");
        return -1;
    }

    size_t written_len = header_len + (extended ? 2: 1);

    putValue<uint16_t>(&buffer, htons(afi));
    putValue<uint8_t>(&buffer, safi);

    bool has_linklocak = !v6addr_is_zero(nexthop_linklocal);

    putValue<uint8_t>(&buffer, has_linklocak ? 32 : 16);
    written_len += 4;
    
    if ((has_linklocak && buffer_sz - written_len < 32) || (!has_linklocak && buffer_sz - written_len < 16)) {
        logger->log(ERROR, "BgpPathAttribMpReachNlriIpv6::write: dst buffer too small.\n");
        return -1;
    }
    
    memcpy(buffer, nexthop_global, 16); buffer += 16; written_len += 16;
    if (has_linklocak) {
        memcpy(buffer, nexthop_linklocal, 16); buffer += 16; written_len += 16;
    }

    putValue<uint8_t>(&buffer, 0);
    written_len++;

    for (const Prefix6 &route : nlri) {
        ssize_t rou_wrt_len = route.write(buffer, buffer_sz - written_len);
        if (rou_wrt_len < 0) {
            logger->log(ERROR, "BgpPathAttribMpReachNlriIpv6::write: failed to write nlri.\n");
            return -1;
        }
        written_len += rou_wrt_len;
        buffer += rou_wrt_len;
    }

    if (extended) {
      putValue<uint16_t>(&attr_len_field, htons(written_len - 4));
    } else {
      putValue<uint8_t>(&attr_len_field, written_len - 3);
    }
    if (written_len != (size_t) (buffer - to)) {
        logger->log(FATAL, "BgpPathAttribMpReachNlriIpv6::write: inconsistent written size (len=%d, diff=%d)\n", written_len, buffer - to);
        return -1;
    }

    return written_len;
}

ssize_t BgpPathAttribMpReachNlriIpv6::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "MpReachNlriAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        const char *safi_str = "Unknow";
        if (safi == UNICAST) safi_str = "Unicast";
        if (safi == MULTICAST) safi_str = "Multicast";
        written += _print(indent, to, buf_sz, "AFI { IPv6 }\n");
        written += _print(indent, to, buf_sz, "SAFI { %s }\n", safi_str);
        char nh_global_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, nexthop_global, nh_global_str, INET6_ADDRSTRLEN);

        written += _print(indent, to, buf_sz, "Nexthops {\n");
        indent++; {
            written += _print(indent, to, buf_sz, "%s\n", nh_global_str);
            if (!v6addr_is_zero(nexthop_linklocal)) {
                char nh_linklocal_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, nexthop_linklocal, nh_linklocal_str, INET6_ADDRSTRLEN);
                written += _print(indent, to, buf_sz, "%s\n", nh_linklocal_str);
            }
        }; indent--;
        written += _print(indent, to, buf_sz, "}\n");

        written += _print(indent, to, buf_sz, "NLRI {\n");
        indent++; {
            for (const Prefix6 &route : nlri) {
                uint8_t prefix[16];
                route.getPrefix(prefix);
                char prefix_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, prefix, prefix_str, INET6_ADDRSTRLEN);
                written += _print(indent, to, buf_sz, "%s/%d\n", prefix_str, route.getLength());
            }
        }; indent--;
        written += _print(indent, to, buf_sz, "}\n");
        
    }; indent--;

    written += _print(indent, to, buf_sz, "}\n");

    return written;
}

ssize_t BgpPathAttribMpReachNlriIpv6::length() const {
    size_t len = (extended ? 4 : 3) + 5; // 4 or 3: attribute headers, 5: afi, safi, nh_len, res
    bool has_linklocak = !v6addr_is_zero(nexthop_linklocal);
    len += (has_linklocak ? 32 : 16);
    for (const Prefix6 &route : nlri) {
        len += (1 + (route.getLength() + 7) / 8);
    }
    return len;
}

BgpPathAttribMpReachNlriUnknow::BgpPathAttribMpReachNlriUnknow(BgpLogHandler *logger) : BgpPathAttribMpNlriBase(logger) {
    nexthop = NULL;
    nexthop_len = 0;
    nlri = NULL;
    nlri_len = 0;
}

BgpPathAttribMpReachNlriUnknow::BgpPathAttribMpReachNlriUnknow(BgpLogHandler *logger, const uint8_t *nexthop, size_t nexthop_len, const uint8_t *nlri, size_t nlri_len) : BgpPathAttribMpNlriBase(logger) {
    if (nexthop_len > 0) {
        this->nexthop = (uint8_t *) malloc(nexthop_len);
        memcpy(this->nexthop, nexthop, nexthop_len);
    }

    if (nlri_len > 0) {
        this->nlri = (uint8_t *) malloc(nlri_len);
        memcpy(this->nlri, nlri, nlri_len);
    }
    this->nexthop_len = nexthop_len;
    this->nlri_len = nlri_len;
}

BgpPathAttribMpReachNlriUnknow::~BgpPathAttribMpReachNlriUnknow() {
    if (nlri_len != 0) free(nlri);
    if (nexthop_len != 0) free(nexthop);
}

BgpPathAttrib* BgpPathAttribMpReachNlriUnknow::clone() const {
    if (hasError()) {
        logger->log(FATAL, "BgpPathAttribMpReachNlriUnknow::clone: can't clone an attribute with error.\n");
        throw "has_error";
    }

    if (nexthop_len == 0 && nlri_len == 0) return new BgpPathAttribMpReachNlriUnknow(logger);
    return new BgpPathAttribMpReachNlriUnknow(logger, nexthop, nexthop_len, nlri, nlri_len);
}

ssize_t BgpPathAttribMpReachNlriUnknow::parse(const uint8_t *from, size_t length) {
    ssize_t hdr_len = BgpPathAttribMpNlriBase::parseHeader(from, length, false);
    if (hdr_len < 0) return -1;

    if (nexthop_len != 0) free(nexthop);

    const uint8_t *buffer = from + hdr_len;
    nexthop_len = getValue<uint8_t>(&buffer);
    size_t parsed_len = hdr_len + 1;

    if (length < parsed_len + nexthop_len) {
        logger->log(FATAL, "BgpPathAttribMpReachNlriUnknow::parse: unexpected end of attribute.\n");
        setError(E_UPDATE, E_OPT_ATTR, NULL, 0);
        return -1;
    }

    parsed_len += nexthop_len;
    nexthop = (uint8_t *) malloc(nexthop_len);
    memcpy(nexthop, buffer, nexthop_len);
    buffer += nexthop_len;

    uint8_t res = getValue<uint8_t>(&buffer);
    parsed_len++;

    if (res != 0) {
        logger->log(WARN, "BgpPathAttribMpReachNlriIpv6::parse: reserved bits != 0\n");
    }

    if (nlri_len != 0) free(nlri);

    nlri_len = value_len - parsed_len + (extended ? 4 : 3); // 4/3: attr header
    parsed_len += nlri_len;
    nlri = (uint8_t *) malloc(nlri_len);
    memcpy(nlri, buffer, nlri_len);

    return parsed_len;
}

ssize_t BgpPathAttribMpReachNlriUnknow::write(uint8_t *to, size_t buffer_sz) const {
    size_t expected_len = (extended ? 4 : 3) + 5 + nexthop_len + nlri_len;

    if (buffer_sz < expected_len) {
        logger->log(ERROR, "BgpPathAttribMpReachNlriUnknow::write: dst buffer too small.\n");
        return -1;
    }

    ssize_t hdr_len = writeHeader(to, buffer_sz);
    if (hdr_len < 0) return -1;
    uint8_t *buffer = to + hdr_len;
    
    if (extended) {
      putValue<uint16_t>(&buffer, htons(expected_len - 4));
    } else {
      putValue<uint8_t>(&buffer, expected_len - 3);
    }
    putValue<uint16_t>(&buffer, htons(afi));
    putValue<uint8_t>(&buffer, safi);
    putValue<uint8_t>(&buffer, nexthop_len);
    memcpy(buffer, nexthop, nexthop_len); buffer += nexthop_len;
    putValue<uint8_t>(&buffer, 0);
    memcpy(buffer, nlri, nlri_len);

    if ((size_t) (buffer - to) != expected_len) {
        logger->log(ERROR, "BgpPathAttribMpReachNlriUnknow::write: unexpected written length.\n");
        return -1;
    }

    return expected_len;
}

ssize_t BgpPathAttribMpReachNlriUnknow::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "MpReachNlriAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        written += _print(indent, to, buf_sz, "AFI { %d }\n", afi);
        written += _print(indent, to, buf_sz, "SAFI { %d }\n", safi);
    }; indent--;
    written += _print(indent, to, buf_sz, "}\n");
    return written;
}

ssize_t BgpPathAttribMpReachNlriUnknow::length() const {
    return (extended ? 4 : 3) + 5 + nexthop_len + nlri_len;
}

const uint8_t* BgpPathAttribMpReachNlriUnknow::getNexthop() const {
    return nexthop;
}

const uint8_t* BgpPathAttribMpReachNlriUnknow::getNlri() const {
    return nlri;
}

size_t BgpPathAttribMpReachNlriUnknow::getNexthopLength() const {
    return nexthop_len;
}

size_t BgpPathAttribMpReachNlriUnknow::getNlriLength() const {
    return nlri_len;
}

BgpPathAttribMpUnreachNlriIpv6::BgpPathAttribMpUnreachNlriIpv6(BgpLogHandler *logger) : BgpPathAttribMpNlriBase(logger) {
    type_code = MP_UNREACH_NLRI;
    afi = IPV6;
}

BgpPathAttrib* BgpPathAttribMpUnreachNlriIpv6::clone() const {
    if (hasError()) {
        logger->log(FATAL, "BgpPathAttribMpUnreachNlriIpv6::clone: can clone attribute with error.\n");
        throw "has_error";
    }

    return new BgpPathAttribMpUnreachNlriIpv6(*this);
}

ssize_t BgpPathAttribMpUnreachNlriIpv6::parse(const uint8_t *from, size_t length) {
    ssize_t hdr_len = BgpPathAttribMpNlriBase::parseHeader(from, length, true);
    if (hdr_len < 0) return -1;

    if (afi != IPV6) {
        logger->log(FATAL, "BgpPathAttribMpUnreachNlriIpv6::parse: afi mismatch.\n");
        throw "bad_type";
    }

    size_t buf_left = value_len - hdr_len + (extended ? 4 : 3); // 4/3: attrib headers
    const uint8_t *buffer = from + hdr_len;

    while (buf_left > 0) {
        Prefix6 this_prefix = Prefix6();
        ssize_t pfx_read_len = this_prefix.parse(buffer, buf_left);

        if (pfx_read_len < 0) {
            logger->log(ERROR, "BgpPathAttribMpUnreachNlriIpv6::parse: error parsing withdrawn entry.\n");
            setError(E_UPDATE, E_OPT_ATTR, NULL, 0);
            return -1;
        }

        buffer += pfx_read_len;
        buf_left -= pfx_read_len;
        withdrawn_routes.push_back(this_prefix);
    }

    if (buf_left != 0) {
        logger->log(FATAL, "BgpPathAttribMpUnreachNlriIpv6::parse: parsed end with non-zero buf_left (%d).\n", buf_left);
        throw "bad_parse";
    }

    return hdr_len + value_len - 3; // 3: afi/safi, already part of "value_len"
}

ssize_t BgpPathAttribMpUnreachNlriIpv6::write(uint8_t *to, size_t buffer_sz) const {
    if (buffer_sz < (extended ? 4 : 3) + 3) {
        logger->log(ERROR, "BgpPathAttribMpUnreachNlriIpv6::write: dst buffer too small.\n");
        return -1;
    }

    ssize_t hdr_len = writeHeader(to, buffer_sz);
    if (hdr_len < 0) return -1;

    uint8_t *len_field = to + hdr_len;
    uint8_t *buffer = len_field + (extended ? 2 : 1);

    putValue<uint16_t>(&buffer, htons(afi));
    putValue<uint8_t>(&buffer, safi);
    size_t written_val_len = 3;

    for (const Prefix6 &route : withdrawn_routes) {
        ssize_t pfx_wrt_ret = route.write(buffer, buffer_sz - (extended ? 4 : 3) - written_val_len);
        if (pfx_wrt_ret < 0) {
            logger->log(ERROR, "BgpPathAttribMpUnreachNlriIpv6::write: error writing withdrawn routes.\n");
            return -1;
        }

        buffer += pfx_wrt_ret;
        written_val_len += pfx_wrt_ret;
    }

    if (extended) {
      putValue<uint16_t>(&len_field, htons(written_val_len));
    } else {
      putValue<uint8_t>(&len_field, written_val_len);
    }

    return (extended ? 4 : 3) + written_val_len;
}

ssize_t BgpPathAttribMpUnreachNlriIpv6::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;

    written += _print(indent, to, buf_sz, "MpUnreachNlriAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        const char *safi_str = "Unknow";
        if (safi == UNICAST) safi_str = "Unicast";
        if (safi == MULTICAST) safi_str = "Multicast";
        written += _print(indent, to, buf_sz, "AFI { IPv6 }\n");
        written += _print(indent, to, buf_sz, "SAFI { %s }\n", safi_str);
        written += _print(indent, to, buf_sz, "WithdrawnRoutes {\n");
        indent++; {
            for (const Prefix6 &route : withdrawn_routes) {
                uint8_t prefix[16];
                route.getPrefix(prefix);
                char prefix_str[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, prefix, prefix_str, INET6_ADDRSTRLEN);
                written += _print(indent, to, buf_sz, "%s/%d\n", prefix_str, route.getLength());
            }
        }; indent--;
        written += _print(indent, to, buf_sz, "}\n");
    }; indent--;
    _print(indent, to, buf_sz, "}\n");

    return written;
}

ssize_t BgpPathAttribMpUnreachNlriIpv6::length() const {
    size_t len = (extended ? 4 : 3) + 3; // 4/3: attribute headers, 3: afi, safi
    for (const Prefix6 &route : withdrawn_routes) {
        len += (1 + (route.getLength() + 7) / 8);
    }
    return len;
}

BgpPathAttribMpUnreachNlriUnknow::BgpPathAttribMpUnreachNlriUnknow(BgpLogHandler *logger) : BgpPathAttribMpNlriBase(logger) {
    withdrawn_routes_len = 0;
    withdrawn_routes = NULL;
}

BgpPathAttribMpUnreachNlriUnknow::BgpPathAttribMpUnreachNlriUnknow(BgpLogHandler *logger, const uint8_t *withdrawn, size_t len) : BgpPathAttribMpNlriBase(logger) {
    withdrawn_routes_len = len;

    if (len > 0) {
        withdrawn_routes = (uint8_t *) malloc(len);
        memcpy(withdrawn_routes, withdrawn, len);
    }
}

BgpPathAttribMpUnreachNlriUnknow::~BgpPathAttribMpUnreachNlriUnknow() {
    if (withdrawn_routes_len > 0) free(withdrawn_routes);
}

BgpPathAttrib* BgpPathAttribMpUnreachNlriUnknow::clone() const {
    if (hasError()) {
        logger->log(FATAL, "BgpPathAttribMpUnreachNlriUnknow::clone: can clone attribute with error.\n");
        throw "has_error";
    }

    if (withdrawn_routes_len == 0) return new BgpPathAttribMpUnreachNlriUnknow(logger);
    return new BgpPathAttribMpUnreachNlriUnknow(logger, withdrawn_routes, withdrawn_routes_len);
}

ssize_t BgpPathAttribMpUnreachNlriUnknow::parse(const uint8_t *from, size_t length) {
    ssize_t hdr_len = BgpPathAttribMpNlriBase::parseHeader(from, length, true);
    if (hdr_len < 0) return -1;

    if (withdrawn_routes_len > 0) free(withdrawn_routes);

    withdrawn_routes_len = value_len - hdr_len;
    const uint8_t *buffer = from + hdr_len;

    withdrawn_routes = (uint8_t *) malloc(withdrawn_routes_len);
    memcpy(withdrawn_routes, buffer, withdrawn_routes_len);

    return hdr_len + value_len - 3;  // 3: afi/safi, already part of "value_len"
}

ssize_t BgpPathAttribMpUnreachNlriUnknow::write(uint8_t *to, size_t buffer_sz) const {
    size_t expected_len = (extended ? 4 : 3) + 3 + withdrawn_routes_len;
    if (buffer_sz < expected_len) {
        logger->log(ERROR, "BgpPathAttribMpUnreachNlriUnknow::write: dst buffer too small.\n");
        return -1;
    }

    ssize_t hdr_len = writeHeader(to, buffer_sz);
    if (hdr_len < 0) return -1;

    uint8_t *buffer = to + hdr_len;
    if (extended) {
      putValue<uint16_t>(&buffer, htons(expected_len - 4));
    } else {
      putValue<uint8_t>(&buffer, expected_len - 3);
    }
    putValue<uint16_t>(&buffer, htons(afi));
    putValue<uint8_t>(&buffer, safi);
    memcpy(buffer, withdrawn_routes, withdrawn_routes_len);

    return expected_len;
}

ssize_t BgpPathAttribMpUnreachNlriUnknow::doPrint(size_t indent, uint8_t **to, size_t *buf_sz) const {
    size_t written = 0;
    written += _print(indent, to, buf_sz, "MpUnreachNlriAttribute {\n");
    indent++; {
        written += printFlags(indent, to, buf_sz);
        written += _print(indent, to, buf_sz, "AFI { %d }\n", afi);
        written += _print(indent, to, buf_sz, "SAFI { %d }\n", safi);
    }; indent--;
    written += _print(indent, to, buf_sz, "}\n");
    return written;
}

ssize_t BgpPathAttribMpUnreachNlriUnknow::length() const {
    return (extended ? 4 : 3) + 3 + withdrawn_routes_len;
}

const uint8_t* BgpPathAttribMpUnreachNlriUnknow::getWithdrawnRoutes() const {
    return withdrawn_routes;
}

size_t BgpPathAttribMpUnreachNlriUnknow::getWithdrawnRoutesLength() const {
    return withdrawn_routes_len;
}

}
