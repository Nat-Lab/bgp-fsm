/**
 * @file bgp-fsm.h
 * @author Nato Morichika <nat@nat.moe>
 * @brief The BGP Finite State Machine.
 * @version 0.1
 * @date 2019-07-05
 * 
 * @copyright Copyright (c) 2019
 * 
 */
#ifndef BGP_FSM_H_
#define BGP_FSM_H_
#define BGP_FSM_SINK_SIZE 8192
#define BGP_FSM_BUFFER_SIZE 4096

#include "clock.h"
#include "bgp-rib.h"
#include "bgp-config.h"
#include "bgp-sink.h"
#include "route-event-receiver.h"
#include "bgp.h"
#include <stdint.h>
#include <unistd.h>
#include <mutex>

namespace libbgp {

/**
 * @brief BGP Finite State Machine status.
 * 
 */
enum BgpState {
    IDLE,
    OPEN_SENT,
    OPEN_CONFIRM,
    ESTABLISHED,
    BROKEN
};

/**
 * @brief The BgpFsm class.
 * 
 */
class BgpFsm : public RouteEventReceiver {
public:
    BgpFsm(const BgpConfig &config);
    ~BgpFsm();

    /**
     * @brief Get local ASN.
     * 
     * @return uint32_t local ASN.
     */
    uint32_t getAsn() const;

    /**
     * @brief Get local BGP ID.
     * 
     * @return uint32_t local BGP ID in network btyes order.
     */
    uint32_t getBgpId() const;

    /**
     * @brief Get peer ASN.
     * 
     * @return uint32_t peer ASN.
     * @retval 0 Peer ASN unknow at this time.
     * @retval >=0 Peer ASN.
     */
    uint32_t getPeerAsn() const;

    /**
     * @brief Get peer BGP ID.
     * 
     * @return uint32_t peer BGP ID in network btyes order.
     * @retval 0 Peer BGP ID unknow at this time.
     * @retval >=0 Peer BGP ID.
     */
    uint32_t getPeerBgpId() const;

    /**
     * @brief Get the negotiated hold timer.
     * 
     * @return uint16_t negotiated hold timer.
     * @retval 0 Hold timer was not negotiated yet.
     * @retval >0 negotiated hold timer.
     */
    uint16_t getHoldTimer() const;

    /**
     * @brief Get the Routing Information Base.
     * 
     * @return const BgpRib& const reference to RIB.
     */
    const BgpRib& getRib() const;

    /**
     * @brief Get current FSM state.
     * 
     * @return BgpState Current state.
     */
    BgpState getState() const;

    /**
     * @brief send OPEN message to peer. (IDLE -> OpenSent)
     * 
     * @retval 0 Failed to start. error may be written to stderr with log
     * handler.
     * @retval 1 open message sent.
     */
    int start();

    /**
     * @brief Stop the FSM. (Any -> Idle)
     * 
     * @retval 0 Failed to stop. error may be written to stderr with log
     * handler.
     */
    int stop();

    /**
     * @brief Run the FSM on buffer.
     * 
     * @param buffer Pointer to buffer.
     * @param buffer_size Size of buffer.
     * @retval -1 Fatal error occured. FSM is now in BROKEN state and needs to 
     * be reset. error may be written to stderr with log handler.
     * @retval 0 Protocol error occurred on the other side. Notification message
     * was sent to peer and FSM is now IDLE state. error may be written to 
     * stderr with log handler.
     * @retval 1 Success.
     * @retval 2 Protocol error occurred on the local side. Got Notification 
     * message from peer and FSM is now IDLE state. error may be written to 
     * stderr with log handler.
     * @retval 3 The packet passed in was incomplete. FSM will wait for more
     * data.
     */
    int run(const uint8_t *buffer, const size_t buffer_size);

    /**
     * @brief Tick the clock (Check for time-based events)
     * 
     * tick() should be called regularly to check for time-based events like 
     * hold timer checks and keepalive message sending. BGP FSM will tick itself
     * when run() is called but you should call tink() regularly to ensure the 
     * hold timer on the other side won't expire.
     * 
     * @retval 0 Hold timer expired. Notification message was sent to the peer.
     * FSM is now in IDLE state. error may be written to stderr with log 
     * handler.
     * @retval 1 Success.
     * @retval 2 Success, KEEPALIVE message sent to peer.
     */
    int tick();

    // soft reset: send Administrative Reset and go to idle
    // return value:
    // -1: fatal_error, FSM now BROKEN, check errbuf.
    // 0: success, NOTIFY sent, FSM not IDLE

    /**
     * @brief Perform a soft reset.
     * 
     * An Administrative Reset Notification will be sent to peer and FSM will
     * go IDLE. This will also clear the BGP packet buffer.
     * 
     * @retval -1 Fatal Error. FSM is now in BROKEN state. error may be written
     * to stderr with log handler.
     * @retval 0 Success. Notification sent. FSM is now IDLE.
     */
    int resetSoft();

    // hard reset: go to idle
    /**
     * @brief Perform a hard reset.
     * 
     * Set FSM state to IDLE and clear the packet buffer.
     * 
     */
    void resetHard();

private:
    bool rib_local;
    bool clock_local;
    bool log_local;
    bool rev_bus_exist;

    bool handleRouteEvent(const RouteEvent &ev);
    bool handleRouteCollisionEvent(const RouteCollisionEvent &ev);
    bool handleRouteWithdrawEvent(const RouteWithdrawEvent &ev);
    bool handleRouteAddEvent(const RouteAddEvent &ev);

    int validateState(uint8_t type);
    int fsmEvalIdle(const BgpMessage *msg);
    int fsmEvalOpenSent(const BgpMessage *msg);
    int fsmEvalOpenConfirm(const BgpMessage *msg);
    int fsmEvalEstablished(const BgpMessage *msg);

    // resloveCollison: resloving collsion
    // return value:
    // -1: fatal_error, FSM now BROKEN, check errbuf.
    // 0: there is a collision and this FSM should be dispose, FSM is now
    // IDLE and should be disposed
    // 1: there is a collision and the other FSM should be dispose.
    int resloveCollision(uint32_t peer_bgp_id, bool is_new);

    // since we handle open recv event in both idle and opensent, make it a func
    int openRecv(const BgpOpenMessage *open);

    bool writeMessage(const BgpMessage &msg);

    // prepare update message for advertisement (prepend my_asn, remove 
    // non-trans attrs)
    void prepareUpdateMessage(BgpUpdateMessage &update);

    BgpSink in_sink;
    BgpState state;
    BgpConfig config;
    BgpRib *rib;
    Clock *clock;
    BgpLogHandler *logger;

    std::recursive_mutex out_buffer_mutex;

    // pointer to output buffer
    uint8_t *out_buffer;

    // peer's bgp id
    uint32_t peer_bgp_id;

    // negotiated hold_timer
    uint16_t hold_timer;

    // time last event sent
    uint64_t last_sent;

    // time last event received
    uint64_t last_recv;

    // true if both peer & local support 4B ASN
    bool use_4b_asn;

    uint32_t peer_asn;

};

}

#endif // BGP_FSM_H_