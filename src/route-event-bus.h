#ifndef ROUTE_EV_BUS_H_
#define ROUTE_EV_BUS_H_
#include "route-event.h"
#include "route-event-receiver.h"
#include <vector>
namespace libbgp {

class RouteEventReceiver;

class RouteEventBus {
public:
    RouteEventBus();

    // publish a route event. For non FSM (administratively/other proto), use fsm = NULL
    // return number of subscriber reached, or -1 on error
    int publish(RouteEventReceiver *recv, const RouteEvent &ev);

    // subscribe to event bus, return true if success
    bool subscribe(RouteEventReceiver *recv);

    // unsubscribe from event bus, return true if success
    bool unsubscribe(RouteEventReceiver *recv);
private:
    std::vector<RouteEventReceiver *> subscribers;
    int subscription_id;
};

}

#endif // ROUTE_EV_BUS_H_