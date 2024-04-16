#!/bin/bash

# Set the number of NIC pairs
NumNicPairs=1

if [ "$1" == "install" ]; then
    # Configure each pair separately with its own hard-coded subnet, ie 192.168.x.0/24 and fc00::x/112
    for ((i=1; i<=NumNicPairs; i++)); do
        echo "Plumbing IP config for pair $i"

        # Generate the "ID" of the NICs, eg 1 and 2 for the first pair
        nic1="duo$((i * 2 - 1))"
        nic2="duo$((i * 2))"

        # Create veth pair
        sudo ip link add ${nic1} type veth peer name ${nic2}

        # Set the veth interfaces up
        sudo ip link set ${nic1} up
        sudo ip link set ${nic2} up

        # Assign IPv4 addresses
        sudo ip addr add 192.168.${i}.11/24 dev ${nic1}
        sudo ip addr add 192.168.${i}.12/24 dev ${nic2}

        # Assign IPv6 addresses
        sudo ip -6 addr add fc00::${i}:11/112 dev ${nic1}
        sudo ip -6 addr add fc00::${i}:12/112 dev ${nic2}

        # Add static neighbor entries (ARP)
        sudo ip neigh add 192.168.${i}.12 lladdr 22:22:22:22:00:0$((i * 2)) dev ${nic1} nud permanent
        sudo ip neigh add 192.168.${i}.11 lladdr 22:22:22:22:00:0$((i * 2 - 1)) dev ${nic2} nud permanent

        # Add static neighbor entries (IPv6)
        sudo ip -6 neigh add fc00::${i}:12 lladdr 22:22:22:22:00:0$((i * 2)) dev ${nic1} nud permanent
        sudo ip -6 neigh add fc00::${i}:11 lladdr 22:22:22:22:00:0$((i * 2 - 1)) dev ${nic2} nud permanent

        # Configure routing rules for IPv4
        sudo ip route add 192.168.${i}.12/32 dev ${nic1} metric 0
        sudo ip route add 192.168.${i}.11/32 dev ${nic2} metric 0



        # Configure routing rules for IPv6
        sudo ip -6 route add fc00::${i}:12/128 dev ${nic1} metric 0
        sudo ip -6 route add fc00::${i}:11/128 dev ${nic2} metric 0

        # Configure firewall rules for IPv4
        sudo iptables -A INPUT -p all -s 192.168.${i}.0/24 -i ${nic1} -j ACCEPT
        sudo iptables -A INPUT -p all -s 192.168.${i}.0/24 -i ${nic2} -j ACCEPT

        # Configure firewall rules for IPv6
        sudo ip6tables -A INPUT -p all -s fc00::${i}:0/112 -i ${nic1} -j ACCEPT
        sudo ip6tables -A INPUT -p all -s fc00::${i}:0/112 -i ${nic2} -j ACCEPT

        sleep 2
        sudo ip route change 192.168.${i}.12 dev duo1 src 192.168.${i}.11
        sudo ip route change 192.168.${i}.11 dev duo2 src 192.168.${i}.12

        sudo ip -6 route change fc00::${i}:12 dev duo1 src fc00::${i}:11
        sudo ip -6 route change fc00::${i}:11 dev duo2 src fc00::${i}:12
    done
elif [ "$1" == "uninstall" ]; then
    # Cleanup each pair separately
    for ((i=1; i<=NumNicPairs; i++)); do
        echo "Cleaning up pair $i"

        # Generate the "ID" of the NICs, eg 1 and 2 for the first pair
        nic1="duo$((i * 2 - 1))"
        nic2="duo$((i * 2))"

        # Delete firewall rules for IPv4
        sudo iptables -D INPUT -p all -s 192.168.${i}.0/24 -i ${nic1} -j ACCEPT
        sudo iptables -D INPUT -p all -s 192.168.${i}.0/24 -i ${nic2} -j ACCEPT

        # Delete firewall rules for IPv6
        sudo ip6tables -D INPUT -p all -s fc00::${i}:0/112 -i ${nic1} -j ACCEPT
        sudo ip6tables -D INPUT -p all -s fc00::${i}:0/112 -i ${nic2} -j ACCEPT

        # Remove routing rules for IPv4
        sudo ip route del 192.168.${i}.12/32 dev ${nic1}
        sudo ip route del 192.168.${i}.11/32 dev ${nic2}

        # Remove routing rules for IPv6
        sudo ip -6 route del fc00::${i}:12/128 dev ${nic1}
        sudo ip -6 route del fc00::${i}:11/128 dev ${nic2}

        # Remove static neighbor entries (ARP)
        sudo ip neigh del 192.168.${i}.12 lladdr 22:22:22:22:00:0$((i * 2)) dev ${nic1}
        sudo ip neigh del 192.168.${i}.11 lladdr 22:22:22:22:00:0$((i * 2 - 1)) dev ${nic2}

        # Remove static neighbor entries (IPv6)
        sudo ip -6 neigh del fc00::${i}:12 lladdr 22:22:22:22:00:0$((i * 2)) dev ${nic1}
        sudo ip -6 neigh del fc00::${i}:11 lladdr 22:22:22:22:00:0$((i * 2 - 1)) dev ${nic2}

        # Remove the veth pair
        sudo ip link delete ${nic1}
    done
else
    echo "Usage: $0 {install|uninsatll}"
    exit 1
fi
