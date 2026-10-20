# xdp-ratelimit

iptables(netfilter) `hashlimit`와 XDP 기반 source-IP token bucket rate limiter의
성능/동작을 같은 토폴로지에서 비교하는 프로젝트.

기본 정책(양쪽 동일):

- source IP별 token bucket
- 평균 1000 pkt/s
- burst 2000 pkt
- 초과 패킷 DROP

## 구성

```
src/xdp_ratelimit.bpf.c   XDP token bucket 프로그램
src/xdp_ratelimit.c       libbpf 기반 로더 (load/detach/stats)
src/xdp_ratelimit.h       공용 상수
scripts/setup_testbed.sh  netns + veth 테스트베드 생성
scripts/teardown_testbed.sh
scripts/iptables_rules.sh iptables hashlimit 규칙 on/off
tests/send_udp.py         UDP 부하 생성기 (기본/스모크용)
tests/udp_sink.py         전달 검증용 UDP 수신기
tests/test_xdp_ratelimit.sh
tests/test_iptables_rules.sh
tmp/                      설계/분석 메모 (git 미포함)
```

## 빌드

필수 패키지:

```
clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config iproute2 iptables
```

테스트 편의: `util-linux`(flock), `ethtool`(offload 정규화, 선택).

```
make          # build/xdp-ratelimit
make test     # netns/veth에서 XDP 동작 스모크 테스트
```

## 사용

```bash
# 수신 측 netns의 veth에 XDP 부착 (프로세스 종료 후에도 유지)
./build/xdp-ratelimit load --netns xdp_dst --iface veth_dst \
    --rate 1000 --burst 2000 --mode auto

# 통계
./build/xdp-ratelimit stats --iface veth_dst

# 해제 + pin 정리
./build/xdp-ratelimit detach --netns xdp_dst --iface veth_dst
```

`--netns`는 mount namespace를 바꾸지 않고 network namespace만 전환한다.
`ip netns exec`를 쓰면 `/sys`가 netns sysfs로 덮여 bpffs pin이 실패하므로
XDP 로더에는 `--netns`를 사용한다.

`load`는 netlink 기반 `bpf_xdp_attach`를 사용하므로 로더가 종료해도 부착이
유지된다. map은 `/sys/fs/bpf/xdp-ratelimit/<iface>/`에 pin된다.

## iptables 기준선

```bash
scripts/iptables_rules.sh on       # 규칙 설치 (멱등: 동명 규칙 교체)
scripts/iptables_rules.sh reset    # 카운터 0으로 초기화
scripts/iptables_rules.sh stats    # 사람용 규칙/카운터
scripts/iptables_rules.sh metrics  # pass/drop/total key=value
scripts/iptables_rules.sh off      # 동명 규칙 모두 제거
scripts/iptables_rules.sh flush    # 체인 전체 비우기 (전용 testbed 전용)
```

`metrics`는 XDP 로더의 `stats`와 동일한 키를 출력한다.
pass 카운터는 전용 체인의 policy 카운터를 사용하므로, 다른 ACCEPT 규칙이
있는 체인에서는 의미가 달라진다.

## 알고리즘

토큰을 "나노초 예산"으로 저장한다.

```
cost_ns     = 1e9 / rate_pps          # 패킷 1개 비용
capacity_ns = burst * cost_ns         # 버킷 최대치
tokens     += now_ns - last_ns        # clamp to capacity_ns
pass if tokens >= cost_ns; tokens -= cost_ns
```

1000 pps -> `cost_ns = 1,000,000`, burst 2000 -> `capacity_ns = 2,000,000,000`.
rate가 1e9을 나누어떨어지지 않으면 1ns 단위 반올림이 발생한다.

## 제약

- IPv4만 처리한다 (IPv6는 통과). v2에서 확장 예정.
- 공유 LRU hash를 사용하므로 다중 CPU에서 약간의 over-admission이 가능하다.
- LRU eviction 시 재등장 source는 full bucket으로 시작한다.
- map 조회/갱신 실패 시 fail-open(통과)한다.
- veth 테스트는 물리 NIC의 절대 성능이 아니라 상대 비교용이다.
- 테스트베드는 고정 이름(`xdp_src/xdp_dst`, `veth_src/veth_dst`)을 쓰며,
  테스트 스크립트는 `flock`으로 직렬화한다. 직접 병렬 실행하면 pin 경로가
  충돌한다.
- `send_udp.py`는 최대 ~30만 pps 수준의 스모크용이다. 고속/정밀 벤치는
  AF_PACKET 기반 pktgen이 필요하다.
- 수신기가 없으면 통과 패킷에 대해 ICMP port unreachable이 생성된다
  (커널 rate limit으로 소수만 발생). `udp_sink.py`를 사용하면 이를 없애고
  실제 전달량까지 확인할 수 있다.
- setup은 GRO/GSO/TSO를 best-effort로 끈다. IPv6와 ARP는 각각 sysctl과
  static neighbor로 배제한다.
