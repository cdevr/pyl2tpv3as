pyl2tpv3as
==========

A virtual switch. Configure remote network devices to do l2tpv3 connections to the machine this is running up, and packets will be switched between same-numbered ports. Things like windows file sharing will work the same way they work on a wireless LAN, over the WAN link.

What does this do ?
-------------------

TLDR: it creates a "virtual" switch over a backbone network using the L2tpv3 protocol without requiring ASR routers.

In an L2tpv3 layer2 point-to-multipoint connection you have 2 components :

* any edge device, which encapsulates the l2 packets and sends them to the LAS
* the LAS, which decapsulates the packets, switches them, and sends them to other endpoints

This project is a python version that, when started on a linux server, will play the role of the LAS. The only network devices that implement the LAS part are the bigger routers, and they have limited policy options. You cannot place them everywhere you'd want to, and you cannot get them to do what you want them to (such as drop weird and troublesome layer2 packets).

How to use ?
------------

Start the program on a linux server. It will listen for protocol (not port) 115, and this means you will not be able to start other protocol 115 programs on that server. It also has to run as root. Let's say the IP address of this router is 1.2.3.4.

On any cisco device, configure the following, to connect the customer to switch "1234" :

    pseudowire-class l2tpv3
      encapsulation l2tpv3
      interworking ethernet
      
      (you may want to put, but not strictly necessary)
      ip local interface Loopback0

    interface GigabitEthernet1/3 (<-- interface where L2 PMP is terminated)
      xconnect 1.2.3.4 1234 encapsulation l2tpv3 pw-class l2tpv3

That's it. You can configure the same on other interfaces and it will appear to the customer that the interfaces are connected to the same switch, when in fact they can be located anywhere on a l3 network, hundreds of miles apart. You have zero issues with l2 network management in between and you can even interconnect them over the internet.

As soon as you configure a switch number (like 1234 in the above example) it will be created in the switch

In case of problems
-------------------

In case of problems, the first thing you should realize is that this requires a high-MTU backbone network. You should be able to ping the server with an MTU of your customer's MTU + encapsulation length from the router and vice-versa. Make sure to configure the MTU sufficiently high on the server using the ifconfig command.

It won't forward NetBEUI => this is by design. You can change it by adapting the list of filtered ethertypes in the switchPacket method. Please keep in mind that that filter is there for a reason, if you remove it entirely, expect problems with STP and switches misbehaving.

It won't forward VLANS => same process. Just add the 0x81 0x00 ethertype in main.py's switchPacket method. If this doesn't work and the customer still can't use VLANs, allow 0x91 0x00 as well.

I'm seeing weird STP issues, the switch seems to filter STP packets => this is by design. It is done so that STP domains wouldn't merge across a WAN link, as this will lead to trouble because the protocol has not been designed with high-latency connections in mind. Furthermore, customers generally have no idea they even enabled STP, and it is unlikely they will get redundant L2 connections. If they do, modify the filter. I have thought about making this configurable behavior, but the nice thing about this project in it's current state is that it requires zero configuration. You start it, and that's it. As long as I can keep it that way, I'll keep it that way. 

What should still be done
-------------------------

Redundancy. It should be possible to start 2 of these, and have packets switched between the same "virtual switches" on either server.

Monitoring. This tool should export per-switch statistics, and other diagnostic aids.
