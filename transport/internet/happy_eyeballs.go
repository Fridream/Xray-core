package internet

import (
	"context"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"time"
)

type result struct {
	err   error
	conn  net.Conn
	index int
}

func TcpRaceDial(ctx context.Context, src net.Address, ips []net.IP, port net.Port, sockopt *SocketConfig, domain string) (net.Conn, error) {
	if len(ips) < 2 {
		panic("at least 2 ips is required to race dial")
	}

	prioritizeIPv6 := sockopt.HappyEyeballs.PrioritizeIpv6
	interleave := sockopt.HappyEyeballs.Interleave
	tryDelayMs := time.Duration(sockopt.HappyEyeballs.TryDelayMs) * time.Millisecond
	maxConcurrentTry := sockopt.HappyEyeballs.MaxConcurrentTry

	ips = sortIPs(ips, prioritizeIPv6, interleave)
	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var resultCh = make(chan *result)
	nextTryIndex := 0
	activeNum := uint32(0)
	timer := time.NewTimer(0)
	timeUp := func() {
		if nextTryIndex == len(ips) || activeNum == maxConcurrentTry {
			panic("impossible situation")
		}
		go tcpTryDial(newCtx, src, sockopt, ips[nextTryIndex], port, nextTryIndex, resultCh)
		activeNum++
		nextTryIndex++
		if nextTryIndex < len(ips) && activeNum < maxConcurrentTry {
			timer.Reset(tryDelayMs)
		}
	}
	errors.LogDebug(ctx, "happy eyeballs racing dial for ", domain, " with IPs ", ips)
	for {
		select {
		case <-timer.C:
			timeUp()
		case <-ctx.Done():
			cancel()
			timer.Stop()
			return nil, ctx.Err()
		case r := <-resultCh:
			activeNum--
			if r.conn != nil {
				cancel()
				timer.Stop()
				errors.LogDebug(ctx, "happy eyeballs established connection for ", domain, " with IP ", ips[r.index])
				return r.conn, nil
			}
			if nextTryIndex < len(ips) {
				timer.Stop()
				timeUp()
				continue
			}
			if activeNum > 0 {
				continue
			}
			errors.LogDebugInner(ctx, r.err, "happy eyeballs no connection established for ", domain)
			return nil, r.err
		}
	}
}

// sortIPs sort IPs according to rfc 8305.
func sortIPs(ips []net.IP, prioritizeIPv6 bool, interleave uint32) []net.IP {
	if len(ips) == 0 {
		return ips
	}
	var ip4 = make([]net.IP, 0, len(ips))
	var ip6 = make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		parsedIp := net.IPAddress(ip).IP()
		if len(parsedIp) == net.IPv4len {
			ip4 = append(ip4, parsedIp)
		} else {
			ip6 = append(ip6, parsedIp)
		}
	}

	if len(ip4) == 0 || len(ip6) == 0 {
		return ips
	}

	var newIPs = make([]net.IP, 0, len(ips))
	consumeIP4 := 0
	consumeIP6 := 0
	consumeTurn := uint32(0)
	ip4turn := true
	if prioritizeIPv6 {
		ip4turn = false
	}
	for {
		if ip4turn {
			newIPs = append(newIPs, ip4[consumeIP4])
			consumeIP4++
			if consumeIP4 == len(ip4) {
				newIPs = append(newIPs, ip6[consumeIP6:]...)
				break
			}
			consumeTurn++
			if consumeTurn == interleave {
				ip4turn = false
				consumeTurn = uint32(0)
			}
		} else {
			newIPs = append(newIPs, ip6[consumeIP6])
			consumeIP6++
			if consumeIP6 == len(ip6) {
				newIPs = append(newIPs, ip4[consumeIP4:]...)
				break
			}
			consumeTurn++
			if consumeTurn == interleave {
				ip4turn = true
				consumeTurn = uint32(0)
			}
		}
	}

	return newIPs
}

func tcpTryDial(ctx context.Context, src net.Address, sockopt *SocketConfig, ip net.IP, port net.Port, index int, resultCh chan<- *result) {
	conn, err := effectiveSystemDialer.Dial(ctx, src, net.Destination{Address: net.IPAddress(ip), Network: net.Network_TCP, Port: port}, sockopt)
	select {
	case resultCh <- &result{conn: conn, err: err, index: index}:
	case <-ctx.Done():
		if conn != nil {
			conn.Close()
		}
	}
}
