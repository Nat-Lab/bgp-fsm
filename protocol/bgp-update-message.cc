#include "bgp-update-message.h"
#include "bgp-error.h"

namespace bgpfsm {

BgpUpdateMessage::BgpUpdateMessage(bool use_4b_asn) {
    this->use_4b_asn = use_4b_asn;
}

BgpPathAttrib& BgpUpdateMessage::getAttrib(uint8_t type) {
    for (BgpPathAttrib &attrib : path_attribute) {
        if (attrib.type_code == type) return attrib;
    }

    throw "no such attribute";
}

const BgpPathAttrib& BgpUpdateMessage::getAttrib(uint8_t type) const {
    for (const BgpPathAttrib &attrib : path_attribute) {
        if (attrib.type_code == type) return attrib;
    }

    throw "no such attribute";
}

bool BgpUpdateMessage::hasAttrib(uint8_t type) const {
    for (const BgpPathAttrib &attrib : path_attribute) {
        if (attrib.type_code == type) return true;
    }

    return false;
}

bool BgpUpdateMessage::addAttrib(const BgpPathAttrib &attrib) {
    if (hasAttrib(attrib.type_code)) return false;

    path_attribute.push_back(attrib);
    return true;
}

bool BgpUpdateMessage::setAttribs(const std::vector<BgpPathAttrib> &attrs) {
    path_attribute = attrs;
    return true;
}

bool BgpUpdateMessage::dropAttrib(uint8_t type) {
    for (auto attr = path_attribute.begin(); attr != path_attribute.end(); attr++) {
        if (attr->type_code == type) {
            path_attribute.erase(attr);
            return true;
        }
    }

    return false;
}

bool BgpUpdateMessage::dropNonTransitive() {
    bool removed = false;

    for (auto attr = path_attribute.begin(); attr != path_attribute.end();) {
        if (!attr->transitive) {
            removed = true;
            path_attribute.erase(attr);
        } else attr++;
    }

    return removed;
}

bool BgpUpdateMessage::updateAttribute(const BgpPathAttrib &attrib) {
    dropAttrib(attrib.type_code);
    return addAttrib(attrib);
}

bool BgpUpdateMessage::setNextHop(uint32_t nexthop) {
    BgpPathAttribNexthop nh = BgpPathAttribNexthop();
    nh.next_hop = nexthop;
    return updateAttribute(nh);
}

bool BgpUpdateMessage::prepend(uint32_t asn) {
    if (use_4b_asn) {
        // in 4b mode, prepend 4b asn to AS_PATH directly.

        // AS4_PATH can't exist in 4b mode
        if (hasAttrib(AS4_PATH)) {
            _bgp_error("BgpUpdateMessage::prepend: we have AS4_PATH attribute but we are running in 4b mode. " 
                       "consider restoreAsPath().\n");
            return false;
        }

        if (!hasAttrib(AS_PATH)) {
            BgpPathAttribAsPath path(use_4b_asn);
            path.prepend(asn);
            path_attribute.push_back(path);
            return true;
        }

        BgpPathAttribAsPath &path = dynamic_cast<BgpPathAttribAsPath &>(getAttrib(AS_PATH));
        if (!path.is_4b) {
            _bgp_error("BgpUpdateMessage::prepend: existing AS_PATH is 2b but we are running in 4b mode. " 
                       "consider restoreAsPath().\n");
            return false;
        }

        return path.prepend(asn);
    } else {
        // in 2b-mode, prepend 2b asn to AS_PATH and update AS4_PATH.
        // (yes, you don't update AS4_PATH as a 2b-speaker, but simplicity we do that for now)
        // FIXME: don't change as4_path if both side disabled 4b support

        uint16_t prep_asn = asn >= 0xffff ? 23456 : asn;

        if (!hasAttrib(AS_PATH)) {
            BgpPathAttribAsPath path(use_4b_asn);
            path.prepend(prep_asn);
            path_attribute.push_back(path);
        } else {
            BgpPathAttribAsPath &path = dynamic_cast<BgpPathAttribAsPath &>(getAttrib(AS_PATH));
            if (path.is_4b) {
                _bgp_error("BgpUpdateMessage::prepend: existing AS_PATH is 4b but we are running in 2b mode. " 
                           "consider downgradeAsPath().\n");
                return false;
            }
            if(!path.prepend(prep_asn)) return false;
        }

        if (hasAttrib(AS4_PATH)) {
            BgpPathAttribAs4Path &path4 = dynamic_cast<BgpPathAttribAs4Path &>(getAttrib(AS4_PATH));
            if(!path4.prepend(prep_asn)) return false;
        }

        return true;
    }
}

bool BgpUpdateMessage::restoreAsPath() {
    if (!hasAttrib(AS_PATH)) return true;

    BgpPathAttribAsPath &path = dynamic_cast<BgpPathAttribAsPath &>(getAttrib(AS_PATH));
    if (path.is_4b) {
        _bgp_error("BgpUpdateMessage::restoreAsPath: AS_PATH is already 4B.\n");
        return false;
    }

    // no AS4_PATH, just make AS_PATH 4b
    if (!hasAttrib(AS4_PATH)) return asPathSegsTo4b();

    // we have AS4_PATH recorver AS_TRANS.
    std::vector<uint32_t> full_as_path;
    const BgpPathAttribAs4Path &as4_path = dynamic_cast<const BgpPathAttribAs4Path &>(getAttrib(AS4_PATH));
    for (const BgpAsPathSegment &seg : as4_path.as4_paths) {
        if (!seg.is_4b) {
            _bgp_error("BgpUpdateMessage::restoreAsPath: bad as4_path: found 2b seg.\n");
            return false;
        }
        
        if (seg.type == AS_SEQUENCE) {
            const BgpAsPathSegment4b &seg4 = dynamic_cast<const BgpAsPathSegment4b &>(seg);
            const std::vector<uint32_t> &part = seg4.value;
            full_as_path.insert(full_as_path.end(), part.begin(), part.end());
        }
    }

    return asPathSegsTo4b(full_as_path);
}

bool BgpUpdateMessage::downgradeAsPath() {
    if (!hasAttrib(AS_PATH)) return true;

    BgpPathAttribAsPath &path = dynamic_cast<BgpPathAttribAsPath &>(getAttrib(AS_PATH));
    if (!path.is_4b) {
        _bgp_error("BgpUpdateMessage::restoreAsPath: AS_PATH is already 2B.\n");
        return false;
    }

    std::vector<BgpAsPathSegment> new_segs;
    BgpPathAttribAs4Path path4;

    for (const BgpAsPathSegment &seg : path.as_paths) {
        if (!seg.is_4b) {
            _bgp_error("BgpUpdateMessage::restoreAsPath: 2b seg found in 4b attrib.\n");
            return false;
        }

        BgpAsPathSegment2b new_seg (seg.type);
        const BgpAsPathSegment4b &seg4 = dynamic_cast<const BgpAsPathSegment4b &>(seg);
        for (uint32_t asn : seg4.value) {
            uint16_t new_as = asn >= 0xffff ? 23456 : asn;
            if(!new_seg.prepend(new_as)) return false;
        }

        path4.as4_paths.push_back(seg4);
        new_segs.push_back(new_seg);
    }
    
    updateAttribute(path4);
    path.as_paths = new_segs;
    return true;
}

}
