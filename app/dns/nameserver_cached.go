package dns

import (
	"context"
	go_errors "errors"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

type CachedNameserver interface {
	getCacheController() *CacheController

	sendQuery(ctx context.Context, noResponseErrCh chan<- error, fqdn string, option dns.IPOption)
}

// queryIP is called from dns.Server->queryIPTimeout
func queryIP(ctx context.Context, s CachedNameserver, domain string, option dns.IPOption) ([]net.IP, uint32, error) {
	fqdn := Fqdn(domain)

	cache := s.getCacheController()
	if !cache.disableCache {
		if rec := cache.findRecords(fqdn); rec != nil {
			ips, ttl, err := merge(option, rec.A, rec.AAAA)
			if err == nil || go_errors.Is(err, dns.ErrEmptyResponse) {
				if ttl > 0 {
					errors.LogDebugInner(ctx, err, cache.name, " cache HIT ", fqdn, " -> ", ips)
					log.Record(&log.DNSLog{Server: cache.name, Domain: fqdn, Result: ips, Status: log.DNSCacheHit, Elapsed: 0, Error: err})
					return ips, uint32(ttl), err
				}
				if cache.serveStale && (cache.serveExpiredTTL == 0 || cache.serveExpiredTTL < ttl) {
					errors.LogDebugInner(ctx, err, cache.name, " cache OPTIMISTE ", fqdn, " -> ", ips)
					log.Record(&log.DNSLog{Server: cache.name, Domain: fqdn, Result: ips, Status: log.DNSCacheOptimiste, Elapsed: 0, Error: err})
					go pull(ctx, s, fqdn, option)
					return ips, 1, err
				}
			}
		}
	} else {
		errors.LogDebug(ctx, "DNS cache is disabled. Querying IP for ", fqdn, " at ", cache.name)
	}

	if option.CacheCheck { go pull(ctx, s, fqdn, option); return nil, 0, nil }
	return fetch(ctx, s, fqdn, option)
}

func pull(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) {
	nctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 8*time.Second)
	defer cancel()

	fetch(nctx, s, fqdn, option)
}

func fetch(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) ([]net.IP, uint32, error) {
	key := fqdn
	switch {
	case option.IPv4Enable && option.IPv6Enable:
		key = key + "46"
	case option.IPv4Enable:
		key = key + "4"
	case option.IPv6Enable:
		key = key + "6"
	}

	v, _, _ := s.getCacheController().requestGroup.Do(key, func() (any, error) {
		return doFetch(ctx, s, fqdn, option), nil
	})
	ret := v.(result)

	return ret.ips, ret.ttl, ret.error
}

type result struct {
	ips []net.IP
	ttl uint32
	error
}

func doFetch(ctx context.Context, s CachedNameserver, fqdn string, option dns.IPOption) result {
	sub4, sub6 := s.getCacheController().registerSubscribers(fqdn, option)
	defer closeSubscribers(sub4, sub6)

	noResponseErrCh := make(chan error, 2)
	pending := 0
	var ch4, ch6 <-chan interface{}
	if sub4 != nil {
		ch4 = sub4.Wait()
		pending++
	}
	if sub6 != nil {
		ch6 = sub6.Wait()
		pending++
	}

	start := time.Now()
	s.sendQuery(ctx, noResponseErrCh, fqdn, option)
	
	var rec4, rec6 *IPRecord
	var errs []error

	for pending > 0 {
		select {
		case <-ctx.Done():
			errs = append(errs, ctx.Err())
			pending = 0
		case err := <-noResponseErrCh:
			errs = append(errs, err)
			pending--
		case msg := <-ch4:
			sub4.Close();ch4 = nil;pending--
			rec4 = msg.(*IPRecord)
			if option.IPv4Prefer && len(rec4.IP) > 0 {
				if !option.IPv6Prefer {
					pending = 0
					if sub6 != nil { sub6.Close() }
				}
			}
		case msg := <-ch6:
			sub6.Close();ch6 = nil;pending--
			rec6 = msg.(*IPRecord)
			if option.IPv6Prefer && len(rec6.IP) > 0 {
				if !option.IPv4Prefer {
					pending = 0
					if sub4 != nil { sub4.Close() }
				}
			}
		}
	}
	
	ips, ttl, err := merge(option, rec4, rec6, errs...)
	var rTTL uint32
	if ttl > 0 {
		rTTL = uint32(ttl)
	} else if ttl == 0 && go_errors.Is(err, errRecordNotFound) {
		rTTL = 0
	} else { // edge case: where a fast rep's ttl expires during the rtt of a slower, parallel query
		rTTL = 1
	}

	log.Record(&log.DNSLog{Server: s.getCacheController().name, Domain: fqdn, Result: ips, Status: log.DNSQueried, Elapsed: time.Since(start), Error: err})
	return result{ips, rTTL, err}
}

func merge(option dns.IPOption, rec4 *IPRecord, rec6 *IPRecord, errs ...error) ([]net.IP, int32, error) {
	var allIPs []net.IP
	var rTTL int32 = dns.DefaultTTL

	if !option.IPv4Prefer && !option.IPv6Prefer {
		option.IPv4Prefer, option.IPv6Prefer = option.IPv4Enable, option.IPv6Enable
	}

	if option.IPv4Prefer && option.IPv4Enable {
		ips, ttl, err := rec4.getIPs() // it's safe
		if err != nil {
			if !option.IPv6Enable || !go_errors.Is(err, dns.ErrEmptyResponse) { return ips, ttl, err }
			errs = append(errs, err)
		} else {
			if !option.IPv6Prefer { return ips, ttl, err }
			if ttl < rTTL { rTTL = ttl }
			allIPs = append(allIPs, ips...)
		}
	}

	if option.IPv6Prefer && option.IPv6Enable {
		ips, ttl, err := rec6.getIPs() // it's safe
		if err != nil {
			if !option.IPv4Enable || !go_errors.Is(err, dns.ErrEmptyResponse) { return ips, ttl, err }
			errs = append(errs, err)
		} else {
			if !option.IPv4Prefer { return ips, ttl, err }
			if ttl < rTTL { rTTL = ttl }
			allIPs = append(allIPs, ips...)
		}
	}

	if option.IPv4Prefer && !option.IPv6Prefer { return rec6.getIPs() }
	if option.IPv6Prefer && !option.IPv4Prefer { return rec4.getIPs() }
	if len(allIPs) > 0 { return allIPs, rTTL, nil }

	if len(errs) == 2 && go_errors.Is(errs[0], errs[1]) { return nil, rTTL, errs[0] }
	return nil, rTTL, errors.Combine(errs...)
}
