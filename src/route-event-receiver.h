#ifndef ROUTE_EV_RECV_H_
#define ROUTE_EV_RECV_H_
#include "route-event-bus.h"

namespace libbgp {

class RouteEventBus;

class RouteEventReceiver {
    friend class RouteEventBus;

public:
    RouteEventReceiver() { subscription_id = 0; }

protected:

    // handle a route event
    // return:
    // true: event handled
    // false: event not handled
    virtual bool handleRouteEvent(const RouteEvent &ev) = 0;
    
    virtual ~RouteEventReceiver() {};
private:
    int subscription_id;
};

}

#endif // ROUTE_EV_RECV_H_