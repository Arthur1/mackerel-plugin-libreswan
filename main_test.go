package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

var ipsecStatusOutput = `using kernel interface: xfrm

interface lo UDP [::1]:4500
interface lo UDP [::1]:500
interface lo UDP 127.0.0.1:4500
interface lo UDP 127.0.0.1:500
interface eth0 UDP 172.19.0.2:4500
interface eth0 UDP 172.19.0.2:500

fips mode=disabled;
SElinux=disabled
seccomp=unsupported

config setup options:

configdir=/etc, configfile=/etc/ipsec.conf, secrets=/etc/ipsec.secrets, ipsecdir=/etc/ipsec.d
nssdir=/etc/ipsec.d, dumpdir=/run/pluto, statsbin=unset
sbindir=/usr/local/sbin, libexecdir=/usr/local/libexec/ipsec
pluto_version=5.0, pluto_vendorid=OE-Libreswan-5.0, audit-log=yes
nhelpers=-1, uniqueids=no, dnssec-enable=no, logappend=yes, logip=yes, shuntlifetime=900s, xfrmlifetime=30s
ddos-cookies-threshold=25000, ddos-max-halfopen=50000, ddos-mode=auto, ikev1-policy=accept
ikebuf=0, msg_errqueue=yes, crl-strict=no, crlcheckinterval=0, listen=<any>, nflog-all=0
ocsp-enable=no, ocsp-strict=no, ocsp-timeout=2, ocsp-uri=<unset>
ocsp-trust-name=<unset>
ocsp-cache-size=1000, ocsp-cache-min-age=3600, ocsp-cache-max-age=86400, ocsp-method=get
global-redirect=no, global-redirect-to=<unset>
debug:

nat-traversal=yes, keep-alive=20, nat-ikeport=4500
virtual-private (%priv):
- allowed subnets: 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12
- excluded subnets: 192.168.42.0/24, 192.168.43.0/24

Kernel algorithms supported:

algorithm ESP encrypt: name=3DES_CBC, keysizemin=192, keysizemax=192
algorithm ESP encrypt: name=AES_CBC, keysizemin=128, keysizemax=256
algorithm ESP encrypt: name=AES_CCM_12, keysizemin=128, keysizemax=256
algorithm ESP encrypt: name=AES_CCM_16, keysizemin=128, keysizemax=256
algorithm ESP encrypt: name=AES_CCM_8, keysizemin=128, keysizemax=256
algorithm ESP encrypt: name=AES_CTR, keysizemin=128, keysizemax=256
algorithm ESP encrypt: name=AES_GCM_12, keysizemin=128, keysizemax=256
algorithm ESP encrypt: name=AES_GCM_16, keysizemin=128, keysizemax=256
algorithm ESP encrypt: name=AES_GCM_8, keysizemin=128, keysizemax=256
algorithm ESP encrypt: name=CAMELLIA_CBC, keysizemin=128, keysizemax=256
algorithm ESP encrypt: name=CHACHA20_POLY1305, keysizemin=256, keysizemax=256
algorithm ESP encrypt: name=NULL, keysizemin=0, keysizemax=0
algorithm ESP encrypt: name=NULL_AUTH_AES_GMAC, keysizemin=128, keysizemax=256
algorithm AH/ESP auth: name=AES_CMAC_96, key-length=128
algorithm AH/ESP auth: name=AES_XCBC_96, key-length=128
algorithm AH/ESP auth: name=HMAC_MD5_96, key-length=128
algorithm AH/ESP auth: name=HMAC_SHA1_96, key-length=160
algorithm AH/ESP auth: name=HMAC_SHA2_256_128, key-length=256
algorithm AH/ESP auth: name=HMAC_SHA2_256_TRUNCBUG, key-length=256
algorithm AH/ESP auth: name=HMAC_SHA2_384_192, key-length=384
algorithm AH/ESP auth: name=HMAC_SHA2_512_256, key-length=512
algorithm AH/ESP auth: name=NONE, key-length=0

IKE algorithms supported:

algorithm IKE encrypt: v1id=5, v1name=OAKLEY_3DES_CBC, v2id=3, v2name=3DES, blocksize=8, keydeflen=192
algorithm IKE encrypt: v1id=8, v1name=OAKLEY_CAMELLIA_CBC, v2id=23, v2name=CAMELLIA_CBC, blocksize=16, keydeflen=128
algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=20, v2name=AES_GCM_C, blocksize=16, keydeflen=128
algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=19, v2name=AES_GCM_B, blocksize=16, keydeflen=128
algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=18, v2name=AES_GCM_A, blocksize=16, keydeflen=128
algorithm IKE encrypt: v1id=13, v1name=OAKLEY_AES_CTR, v2id=13, v2name=AES_CTR, blocksize=16, keydeflen=128
algorithm IKE encrypt: v1id=7, v1name=OAKLEY_AES_CBC, v2id=12, v2name=AES_CBC, blocksize=16, keydeflen=128
algorithm IKE encrypt: v1id=-1, v1name=n/a, v2id=28, v2name=CHACHA20_POLY1305, blocksize=16, keydeflen=256
algorithm IKE PRF: name=HMAC_MD5, hashlen=16
algorithm IKE PRF: name=HMAC_SHA1, hashlen=20
algorithm IKE PRF: name=HMAC_SHA2_256, hashlen=32
algorithm IKE PRF: name=HMAC_SHA2_384, hashlen=48
algorithm IKE PRF: name=HMAC_SHA2_512, hashlen=64
algorithm IKE PRF: name=AES_XCBC, hashlen=16
algorithm IKE DH Key Exchange: name=MODP1024, bits=1024
algorithm IKE DH Key Exchange: name=MODP1536, bits=1536
algorithm IKE DH Key Exchange: name=MODP2048, bits=2048
algorithm IKE DH Key Exchange: name=MODP3072, bits=3072
algorithm IKE DH Key Exchange: name=MODP4096, bits=4096
algorithm IKE DH Key Exchange: name=MODP6144, bits=6144
algorithm IKE DH Key Exchange: name=MODP8192, bits=8192
algorithm IKE DH Key Exchange: name=DH19, bits=512
algorithm IKE DH Key Exchange: name=DH20, bits=768
algorithm IKE DH Key Exchange: name=DH21, bits=1056
algorithm IKE DH Key Exchange: name=DH31, bits=256

stats db_ops: {curr_cnt, total_cnt, maxsz} :context={0,0,0} trans={0,0,0} attrs={0,0,0}

Connection list:

"ikev2-cp": 0.0.0.0/0===172.19.0.2[@example.com,MS+S=C]---172.19.0.1...%any[%fromcert,+MC+S=C]; unrouted; my_ip=unset; their_ip=unset;
"ikev2-cp":   host: oriented; local: 172.19.0.2; remote: %any;
"ikev2-cp":   mycert=example.com; my_updown=ipsec _updown;
"ikev2-cp":   xauth us:none, xauth them:none,  my_username=[any]; their_username=[any]
"ikev2-cp":   our auth:rsasig(RSASIG+RSASIG_v1_5), their auth:RSASIG+ECDSA+RSASIG_v1_5, our autheap:none, their autheap:none;
"ikev2-cp":   modecfg info: us:server, them:client, modecfg policy:push, dns:8.8.8.8, 8.8.4.4, domains:unset, cat:unset;
"ikev2-cp":   sec_label:unset;
"ikev2-cp":   CAs: 'CN=IKEv2 VPN CA, O=IKEv2 VPN'...'CN=IKEv2 VPN CA, O=IKEv2 VPN'
"ikev2-cp":   ike_life: 86400s; ipsec_life: 86400s; ipsec_max_bytes: 2^63B; ipsec_max_packets: 2^63; replay_window: 128; rekey_margin: 540s; rekey_fuzz: 100%;
"ikev2-cp":   retransmit-interval: 500ms; retransmit-timeout: 300s; iketcp:no; iketcp-port:4500;
"ikev2-cp":   initial-contact:no; cisco-unity:no; fake-strongswan:no; send-vendorid:no; send-no-esp-tfc:no;
"ikev2-cp":   policy: IKEv2+RSASIG+ECDSA+RSASIG_v1_5+ENCRYPT+TUNNEL+DONT_REKEY+IKEV2_ALLOW_NARROWING+IKE_FRAG_ALLOW+MOBIKE+ESN_NO+ESN_YES;
"ikev2-cp":   v2-auth-hash-policy: SHA2_256+SHA2_384+SHA2_512;
"ikev2-cp":   conn_prio: 0,0; interface: eth0; metric: 0; mtu: unset; sa_prio:auto; sa_tfc:none;
"ikev2-cp":   nflog-group: unset; mark: unset; vti-iface:unset; vti-routing:no; vti-shared:no; nic-offload:no;
"ikev2-cp":   our idtype: ID_FQDN; our id=@example.com; their idtype: %fromcert; their id=%fromcert
"ikev2-cp":   liveness: active; dpddelay:30s; retransmit-timeout:300s
"ikev2-cp":   nat-traversal: encapsulation:yes; keepalive:20s
"ikev2-cp":   routing: unrouted;
"ikev2-cp":   conn serial: $3;
"ikev2-cp":   IKE algorithms: AES_GCM_16_256-HMAC_SHA2_256-DH19, AES_CBC_256-HMAC_SHA2_256-DH19+DH20+DH21+DH31+MODP4096+MODP3072+MODP2048+MODP8192, AES_CBC_128-HMAC_SHA2_256-DH19+DH20+DH21+DH31+MODP4096+MODP3072+MODP2048+MODP8192, AES_CBC_256-HMAC_SHA1-DH19+DH20+DH21+DH31+MODP4096+MODP3072+MODP2048+MODP8192, AES_CBC_128-HMAC_SHA1-DH19+DH20+DH21+DH31+MODP4096+MODP3072+MODP2048+MODP8192
"ikev2-cp":   ESP algorithms: AES_GCM_16-NONE, AES_CBC_128-HMAC_SHA1_96, AES_CBC_256-HMAC_SHA1_96, AES_CBC_128-HMAC_SHA2_256_128, AES_CBC_256-HMAC_SHA2_256_128
"l2tp-psk": 172.19.0.2/32/UDP/1701===172.19.0.2[34.127.60.171]---172.19.0.1...%any; unrouted; my_ip=unset; their_ip=unset;
"l2tp-psk":   host: oriented; local: 172.19.0.2; remote: %any;
"l2tp-psk":   my_updown=ipsec _updown;
"l2tp-psk":   xauth us:none, xauth them:none,  my_username=[any]; their_username=[any]
"l2tp-psk":   our auth:secret, their auth:secret, our autheap:none, their autheap:none;
"l2tp-psk":   modecfg info: us:none, them:none, modecfg policy:push, dns:unset, domains:unset, cat:unset;
"l2tp-psk":   sec_label:unset;
"l2tp-psk":   ike_life: 86400s; ipsec_life: 86400s; ipsec_max_bytes: 2^63B; ipsec_max_packets: 2^63; replay_window: 128; rekey_margin: 540s; rekey_fuzz: 100%;
"l2tp-psk":   retransmit-interval: 500ms; retransmit-timeout: 60s; iketcp:no; iketcp-port:4500;
"l2tp-psk":   initial-contact:no; cisco-unity:no; fake-strongswan:no; send-vendorid:no; send-no-esp-tfc:no;
"l2tp-psk":   policy: IKEv1+PSK+ENCRYPT+TRANSPORT+DONT_REKEY+IKE_FRAG_ALLOW+ESN_NO+ESN_YES;
"l2tp-psk":   conn_prio: 32,0; interface: eth0; metric: 0; mtu: unset; sa_prio:auto; sa_tfc:none;
"l2tp-psk":   nflog-group: unset; mark: unset; vti-iface:unset; vti-routing:no; vti-shared:no; nic-offload:no;
"l2tp-psk":   our idtype: ID_IPV4_ADDR; our id=34.127.60.171; their idtype: %none; their id=(none)
"l2tp-psk":   dpd: active; delay:30s; timeout:300s
"l2tp-psk":   nat-traversal: encapsulation:yes; keepalive:20s; ikev1-method:rfc+drafts
"l2tp-psk":   routing: unrouted;
"l2tp-psk":   conn serial: $1;
"l2tp-psk":   IKE algorithms: AES_CBC_256-HMAC_SHA2_256-MODP2048, AES_CBC_128-HMAC_SHA2_256-MODP2048, AES_CBC_256-HMAC_SHA1-MODP2048, AES_CBC_128-HMAC_SHA1-MODP2048
"l2tp-psk":   ESP algorithms: AES_GCM_16-NONE, AES_CBC_128-HMAC_SHA1_96, AES_CBC_256-HMAC_SHA1_96, AES_CBC_256-HMAC_SHA2_512_256, AES_CBC_128-HMAC_SHA2_256_128, AES_CBC_256-HMAC_SHA2_256_128
"xauth-psk": 0.0.0.0/0===172.19.0.2[34.127.60.171,MS+XS+S=C]---172.19.0.1...%any[+MC+XC+S=C]; unrouted; my_ip=unset; their_ip=unset;
"xauth-psk":   host: oriented; local: 172.19.0.2; remote: %any;
"xauth-psk":   my_updown=ipsec _updown;
"xauth-psk":   xauth us:server, xauth them:client, xauthby:file; my_username=[any]; their_username=[any]
"xauth-psk":   our auth:secret, their auth:secret, our autheap:none, their autheap:none;
"xauth-psk":   modecfg info: us:server, them:client, modecfg policy:pull, dns:8.8.8.8, 8.8.4.4, domains:unset, cat:unset;
"xauth-psk":   sec_label:unset;
"xauth-psk":   ike_life: 86400s; ipsec_life: 86400s; ipsec_max_bytes: 2^63B; ipsec_max_packets: 2^63; replay_window: 128; rekey_margin: 540s; rekey_fuzz: 100%;
"xauth-psk":   retransmit-interval: 500ms; retransmit-timeout: 60s; iketcp:no; iketcp-port:4500;
"xauth-psk":   initial-contact:no; cisco-unity:yes; fake-strongswan:no; send-vendorid:no; send-no-esp-tfc:no;
"xauth-psk":   policy: IKEv1+PSK+ENCRYPT+TUNNEL+DONT_REKEY+XAUTH+MODECFG_PULL+IKE_FRAG_ALLOW+ESN_NO+ESN_YES;
"xauth-psk":   conn_prio: 0,0; interface: eth0; metric: 0; mtu: unset; sa_prio:auto; sa_tfc:none;
"xauth-psk":   nflog-group: unset; mark: unset; vti-iface:unset; vti-routing:no; vti-shared:no; nic-offload:no;
"xauth-psk":   our idtype: ID_IPV4_ADDR; our id=34.127.60.171; their idtype: %none; their id=(none)
"xauth-psk":   dpd: active; delay:30s; timeout:300s
"xauth-psk":   nat-traversal: encapsulation:yes; keepalive:20s; ikev1-method:rfc+drafts
"xauth-psk":   routing: unrouted;
"xauth-psk":   conn serial: $2;
"xauth-psk":   IKE algorithms: AES_CBC_256-HMAC_SHA2_256-MODP2048, AES_CBC_128-HMAC_SHA2_256-MODP2048, AES_CBC_256-HMAC_SHA1-MODP2048, AES_CBC_128-HMAC_SHA1-MODP2048
"xauth-psk":   ESP algorithms: AES_GCM_16-NONE, AES_CBC_128-HMAC_SHA1_96, AES_CBC_256-HMAC_SHA1_96, AES_CBC_256-HMAC_SHA2_512_256, AES_CBC_128-HMAC_SHA2_256_128, AES_CBC_256-HMAC_SHA2_256_128

Total IPsec connections: loaded 3, active 0

State Information: DDoS cookies not required, Accepting new IKE connections
IKE SAs: total(6), half-open(1), open(2), authenticated(3), anonymous(0)
IPsec SAs: total(3), authenticated(2), anonymous(1)

Bare Shunt list:
`

func TestGetTotalConnectionsFromIPsecStatusOutput(t *testing.T) {
	want := &TotalConnections{
		Loaded: 3,
		Active: 0,
	}
	got, err := getTotalConnectionsFromIPsecStatusOutput(ipsecStatusOutput)
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(got, want))
}

func TestGetIKESAsFromIPsecStatusOutput(t *testing.T) {
	want := &IKESAs{
		Total:         6,
		HalfOpen:      1,
		Open:          2,
		Authenticated: 3,
		Anonymous:     0,
	}
	got, err := getIKESAsFromIPsecStatusOutput(ipsecStatusOutput)
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(got, want))
}

func TestGetIPsecSAsFromIPsecStatusOutput(t *testing.T) {
	want := &IPsecSAs{
		Total:         3,
		Authenticated: 2,
		Anonymous:     1,
	}
	got, err := getIPsecSAsFromIPsecStatusOutput(ipsecStatusOutput)
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(got, want))
}
