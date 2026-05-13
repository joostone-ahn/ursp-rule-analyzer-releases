# URSP Rule Analyzer 사용자 가이드

**버전:** v1.0.0  
**최종 수정일:** 2026-05-13

---

## 1. 실행 방법

1. `URSP-Rule-Analyzer-v1.0.0.exe` 파일을 더블클릭합니다.
2. 콘솔 창에 `Access the application at: http://127.0.0.1:8081` 메시지가 표시됩니다.
3. 웹 브라우저에서 해당 주소에 접속합니다.
4. 종료: 콘솔 창을 닫거나 `Ctrl+C`

> 방화벽 경고 시 "허용"을 선택하세요. 로컬에서만 동작합니다.

---

## 2. 화면 구성

| 영역 | 설명 |
|------|------|
| 헤더 | 프로그램 제목, 버전, 📖 Guide 버튼, 🔗 GitHub 링크 |
| 탭 바 | Encoder / Decoder / Result 탭 전환 + 액션 버튼 (PLMN, Encoding/Decoding) |
| 메인 영역 | 선택된 탭의 콘텐츠 |
| 하단 바 (모바일) | PLMN 입력 + Encoding/Decoding 버튼 |

---

## 3. Encoder 탭

### 3.1 기본 구조

URSP Rule은 **Traffic Descriptor (TD)**와 **Route Selection Descriptor (RSD)**로 구성됩니다.

- 프로그램 시작 시 **Match-all** 규칙이 기본 생성됩니다 (PV 255, 삭제 불가)
- `+ Add URSP Rule` 버튼으로 새 규칙을 추가합니다 (최상단에 삽입)
- 새 규칙 추가 시 기존 규칙은 자동으로 접힙니다
- 카드 헤더 클릭으로 접기/펼치기 가능

### 3.2 넘버링과 우선순위

- **넘버링**: Rule, TD, RSD, Comp 번호는 1부터 시작합니다 (예: Rule1.TD1, Rule1.RSD1.Comp1)
- **PV (Precedence Value)**: 0부터 시작하며, 카드 순서에 따라 자동 할당됩니다
- 위에 있을수록 낮은 PV = 높은 우선순위
- Match-all 규칙은 항상 PV 255 (최저 우선순위)

### 3.3 PLMN 설정

탭 바 우측(데스크톱) 또는 하단 바(모바일)에서 6자리 hex 값을 입력합니다.
- 기본값: `45006F` (LG U+ Korea)
- MCC/MNC를 직접 이어붙인 형식 (MCC=450, MNC=06 → 45006, 홀수 자리 시 F 패딩 → 45006F)
- 프로그램 내부에서 nibble-swap 처리하여 인코딩합니다 (45006F → 54F060)

---

## 4. Traffic Descriptor (TD) 상세

`+ TD` 버튼으로 컴포넌트 추가, `✕`로 삭제 (최소 1개 필수)

### 4.1 OS Id + OS App Id

OS별 앱 식별자를 설정합니다.

**Android 모드:**
- OS 드롭다운에서 `Android` 선택
- Slice Category 드롭다운에서 선택 (ENTERPRISE, CBS, PRIORITIZE_LATENCY 등)

**iOS 모드:**
- OS 드롭다운에서 `iOS` 선택
- App Category 드롭다운: gaming-6014, communication-9000, streaming-9001
- Traffic Category 드롭다운: defaultslice-1, video-2, background-3, voice-4 등
- **Custom 입력**: App Category에서 `custom-9XXX` 선택 → 텍스트 입력으로 전환 (4자리 숫자, 9로 시작)
  - Traffic Category는 자동으로 `wildcard-*`로 고정됨
  - `☰` 버튼으로 드롭다운 모드로 복귀
  - 알려진 코드(6014, 9000, 9001) 입력 시 자동으로 드롭다운 전환

### 4.2 DNN

Data Network Name을 텍스트로 입력합니다 (예: `internet`, `business`)

### 4.3 Connection capabilities

체크박스로 다중 선택합니다. 최소 1개 이상 선택 필수.
- IMS, Internet, MMS, SUPL, IoT delay-tolerant 등

### 4.4 IP 3 tuple

IP 주소, 프로토콜, 포트를 조합하여 트래픽을 매칭합니다.

- **IP type**: IPv4 / IPv6 선택
- **IPv4**: 주소 (예: 10.0.0.1) + 서브넷 마스크 (예: 255.255.255.0)
- **IPv6**: 주소 (예: 2001:db8::1) + 프리픽스 길이 (예: 64)
- **Protocol**: None / TCP / UDP / ICMP / ICMPv6 / ESP
- **Port type**: Single remote port / Remote port range
  - Single: 포트 번호 하나 (예: 8080)
  - Range: Remote port low + Remote port high (예: 5000~6000)
- 최소 1개 필드 입력 필수

### 4.5 Type of service/traffic class (ToS/TC)

DSCP 값과 마스크를 설정합니다.

**Value (DSCP):**
- 드롭다운에서 표준 DSCP 선택 (CS0~CS7, AF11~AF43, EF 등)
- `Custom` 선택 시 텍스트 입력으로 전환 (2 hex digits, 예: A4)
- `☰` 버튼으로 드롭다운 복귀
- 알려진 값 입력 시 자동으로 드롭다운 전환

**Mask:**
- 드롭다운: 0xFC (DSCP only), 0xFF (exact), 0xE0 (IP Precedence only)
- `Custom` 선택 시 텍스트 입력 (2 hex digits, 예: F0)
- 동일하게 `☰` 복귀 및 알려진 값 자동 전환

### 4.6 IPv4 remote address

- IPv4 주소 (예: 10.0.0.0) + 서브넷 마스크 (예: 255.0.0.0)
- 둘 다 입력하거나 둘 다 비워야 함

### 4.7 IPv6 remote address/prefix length

- IPv6 주소 (예: 2001:db8::) + 프리픽스 길이 (예: 64)
- 둘 다 입력하거나 둘 다 비워야 함

### 4.8 Remote port range

- Remote port low (예: 1024) + Remote port high (예: 65535)
- low ≤ high 필수

### 4.9 Destination MAC address range

- Low limit (예: AA:BB:CC:DD:EE:00) + High limit (예: AA:BB:CC:DD:EE:FF)

### 4.10 기타 TD 타입

| 타입 | 설명 | 입력 |
|------|------|------|
| Single remote port | 단일 포트 | 숫자 (0~65535) |
| Protocol identifier/next header | 프로토콜 | 드롭다운 |
| Security parameter index | IPSec SPI | 4바이트 hex (예: 0x12345678) |
| Flow label | IPv6 Flow label | 3바이트 hex (예: 0x12345) |
| Destination MAC address | 목적지 MAC | MAC 주소 (예: AA:BB:CC:DD:EE:FF) |
| 802.1Q C-TAG/S-TAG VID | VLAN ID | 숫자 |
| 802.1Q C-TAG/S-TAG PCP/DEI | 우선순위 | hex |
| Ethertype | 이더넷 타입 | hex (예: 0x0800) |
| Destination FQDN | 도메인 | 텍스트 (예: example.com) |
| Regular expression | 정규식 | 텍스트 |
| OS App Id | 앱 식별자 | 텍스트 |
| Match-all | 모든 트래픽 | 값 없음 (자동 관리) |

### 4.11 TD 조합 규칙

| 규칙 | 설명 |
|------|------|
| 같은 타입 복수 | OR 조건 (하나만 매칭되면 됨) |
| 다른 타입 조합 | AND 조건 (모두 매칭되어야 함) |
| PIN ID | 단독 사용만 가능 (다른 TD와 조합 불가) |
| Single remote port ↔ Remote port range | 동시 사용 불가 |
| Destination MAC ↔ Destination MAC range | 동시 사용 불가 |

---

## 5. Route Selection Descriptor (RSD) 상세

`+ RSD`로 RSD 추가, `+ Component`로 컴포넌트 추가, `✕`로 삭제

### 5.1 S-NSSAI

네트워크 슬라이스 식별자를 설정합니다.
- **SST**: 드롭다운 (01=eMBB, 02=URLLC, 03=MIoT, 04=V2X 등)
- **SD** (선택): 0~FFFFFF (3바이트 hex)
  - 입력값은 hex로 인식됩니다. 예: `10` 입력 시 0x10 (decimal 16), `000064` 입력 시 0x000064 (decimal 100)

### 5.2 DNN

라우팅할 Data Network Name (예: `internet`, `business`)

### 5.3 SSC mode

Session and Service Continuity 모드
- SSC mode 1: 기본 (IP 주소 유지)
- SSC mode 2: 새 PDU 세션으로 전환
- SSC mode 3: IP 주소 변경 허용

### 5.4 Preferred access type

- 3GPP access: 셀룰러 우선
- Non-3GPP access: Wi-Fi 등 우선

### 5.5 Multi-access preference

값 없음 (선택만으로 의미). 다중 접속 선호를 나타냄.

### 5.6 Time window

- Starttime: 시작 날짜/시간 선택
- Stoptime: 종료 날짜/시간 선택
- 내부적으로 NTP 64-bit timestamp으로 인코딩됨

### 5.7 Location criteria

`Edit` 버튼 클릭 → 전용 모달에서 편집

**모달 구성:**
- `+ Location Area` 버튼으로 영역 추가
- 영역 타입: NR cell identities list / E-UTRA cell identities list / Global RAN node identities list / TAI list
- 각 영역에 `+ Add Id`로 Cell ID 추가
- 입력 필드: PLMN (6 hex) + Cell ID (NR: 10 hex, E-UTRA: 8 hex, gNB: 8 hex) 또는 TAC (6 hex)
- 실시간 hex 문자 수 카운터 표시
- `💾 Save` 또는 모달 닫기로 저장
- 최소 1개 Cell ID 또는 TAI 필수

**TAI list 인코딩 최적화:**
- 입력된 TAI를 PLMN 단위로 그룹핑 후 TAC 정렬
- 연속 TAC(+1씩 증가)는 Type 1 (consecutive)로 압축 인코딩
- 나머지는 하나의 Type 0 (non-consecutive)으로 합쳐 바이트 절약

### 5.8 PDU session pair ID

PDU 세션 쌍 식별자 (드롭다운)

### 5.9 RSN (Redundancy Sequence Number)

중복 전송 시퀀스 번호 (드롭다운: v1, v2)

### 5.10 기타 RSD 타입

| 타입 | 설명 |
|------|------|
| PDU session type | IPv4 / IPv6 / IPv4v6 |
| Non-seamless non-3GPP offload | 값 없음 (단독 사용) |
| 5G ProSe layer-3 UE-to-network relay offload | 값 없음 (단독 사용) |
| 5G ProSe multi-path preference | 값 없음 |

### 5.11 RSD 조합 규칙

| 규칙 | 설명 |
|------|------|
| 같은 타입 중복 | 불가 (하나의 RSD 내에서 동일 타입 2개 이상 금지) |
| Non-seamless offload | 단독 사용 (다른 컴포넌트와 조합 불가) |
| 5G ProSe relay offload | 단독 사용 |
| Preferred access type ↔ Multi-access preference | 동시 사용 불가 |
| PDU session pair ID ↔ Multi-access preference | 동시 사용 불가 |
| RSN ↔ Multi-access preference | 동시 사용 불가 |
| 5G ProSe relay offload ↔ 5G ProSe multi-path | 동시 사용 불가 |

---

## 6. 인코딩 실행과 에러 처리

### 6.1 인코딩

1. URSP 규칙을 구성합니다
2. PLMN 값을 확인합니다
3. `🚀 Encoding` 버튼을 클릭합니다
4. 성공 시 자동으로 Result 탭으로 이동합니다

### 6.2 에러 발생 시

- 상단에 에러 메시지가 배지 형태로 표시됩니다
  - 빨간 배지: 에러 코드 (예: E-TD02)
  - 초록/분홍 배지: 위치 (예: Rule1.TD1)
- 해당 컴포넌트가 빨간 테두리로 강조됩니다
- 접힌 카드는 자동으로 펼쳐집니다
- 첫 번째 에러 위치로 스크롤 이동합니다

### 6.3 에러 해소

- **값 수정**: 올바른 값 입력 시 실시간으로 빨간 박스 해제
- **컴포넌트 삭제**: 배타/단독 조건이 해소되면 자동 해제
- **타입 변경**: 충돌하는 타입을 다른 것으로 변경하면 자동 해제
- 모든 에러 해소 시 상단 에러 메시지도 자동 제거

---

## 7. Decoder 탭

1. 텍스트 영역에 hex 데이터를 붙여넣습니다
2. `🔍 Decoding` 버튼을 클릭합니다
3. 성공 시 Result 탭으로 이동합니다

**지원 입력 형식:**
- Wireshark hex dump (오프셋 포함):
  ```
  0000   68 05 00 1F 97 01 00 1B ...
  ```
- Plain hex string:
  ```
  6805001F9701001B...
  ```

**지원 메시지 타입:**
- `6805...`: DL NAS Transport
- `80...`: SIM EF_URSP

**보조 버튼:**
- `🗑 Clear`: 텍스트 영역 초기화
- `📋 Load Sample`: 테스트용 샘플 데이터 로드

---

## 8. Result 탭

인코딩/디코딩 결과가 3개의 카드로 표시됩니다.
- 데스크톱: 3열 그리드 레이아웃
- 모바일: 좌우 스와이프 (하단 도트 인디케이터)

### 8.1 URSP RULE 카드 (보라색 헤더)

- **Tree 뷰** (기본): 계층 구조로 규칙 표시
- **JSON 뷰**: JSON 형식으로 표시
- `📋 Copy`: 현재 뷰의 내용을 클립보드에 복사

### 8.2 SIM EF.URSP 카드 (초록색 헤더)

- **Table 뷰** (기본): Bytemap 테이블 (Idx, Hex, Description)
  - Length 필드는 description 뒤에 decimal 값이 자동 계산되어 표시됩니다 (1-byte: 직접 표시, 2-byte: 합산값 표시)
- **Hex 뷰**: 오프셋 포함 hex 덤프
- `📋 Copy`: Table → TSV (Excel 붙여넣기 가능), Hex → raw hex string

> **활용**: 이 hex 값을 SIM 카드의 EF_URSP 파일에 직접 write하여 네트워크 슬라이싱 테스트에 활용할 수 있습니다. SIM write를 위한 도구:
> - [SIM AT Command](https://github.com/joostone-ahn/sim-at-command-releases) — AT 명령어 기반 SIM 파일 읽기/쓰기
> - [SIM OTA Test](https://github.com/joostone-ahn/sim-ota-test-releases) — OTA 방식 SIM 프로비저닝 테스트

### 8.3 DL NAS TRANSPORT 카드 (파란색 헤더)

- **Table 뷰** (기본): Bytemap 테이블 (Idx, Hex, Description)
  - Length 필드는 description 뒤에 decimal 값이 자동 계산되어 표시됩니다 (1-byte: 직접 표시, 2-byte: 합산값 표시)
- **Hex 뷰**: 오프셋 포함 hex 덤프
- `📦 PCAP`: Wireshark에서 열 수 있는 .pcap 파일 다운로드
- `✏️ Edit`: PTI/UPSC 값 직접 수정 모드
  - 편집 가능 필드가 노란색으로 강조됨
  - 2자리 hex 값 수정 후 `💾 Save` 클릭
  - 수정된 값은 Hex 뷰에도 자동 반영
- `📋 Copy`: Table → TSV (Excel 호환), Hex → raw hex string

---

## 9. Guide 모달

헤더의 `📖 Guide` 버튼 클릭 시 표시됩니다.

**포함 내용:**
- 약어 설명 (URSP, TD, RSD, PTI, PLMN, UPSC, PV)
- URSP Rule 구조 (PV, TD, RSD 관계)
- TD 유효성 검증 규칙 (Same Type: OR, Different: AND, Standalone, Exclusive)
- RSD 유효성 검증 규칙 (중복 금지, 단독 사용, 배타 쌍, PV 규칙)

닫기: `✕` 버튼, 배경 클릭, 또는 `Esc` 키

---

## 10. FAQ

**Q: 인코딩 시 에러가 발생합니다.**  
A: 에러 코드(예: E-TD02)와 위치(예: Rule1.TD1)를 확인하세요. 해당 컴포넌트가 빨간색으로 강조됩니다.

**Q: Match-all 규칙을 삭제할 수 있나요?**  
A: 아니요. 3GPP 규격상 필수이며 프로그램이 자동 관리합니다.

**Q: PCAP 파일은 어떻게 사용하나요?**  
A: DL NAS 카드의 `📦 PCAP` 버튼으로 다운로드 후 Wireshark에서 열면 NAS-5GS 프로토콜로 자동 디코딩됩니다.

**Q: 프로그램이 실행되지 않습니다.**  
A: 포트 8081이 다른 프로그램에 의해 사용 중인지 확인하세요.

**Q: Copy 버튼으로 복사한 Table 데이터를 Excel에 붙여넣을 수 있나요?**  
A: 네. Table 뷰에서 복사하면 TSV(탭 구분) 형식으로 복사되어 Excel에 바로 붙여넣기 가능합니다.

**Q: iOS custom App Category에서 어떤 값을 입력해야 하나요?**  
A: 9로 시작하는 4자리 숫자를 입력합니다 (예: 9500). 이미 알려진 코드(6014, 9000, 9001)를 입력하면 자동으로 드롭다운으로 전환됩니다.

**Q: ToS/TC custom 값은 어떻게 입력하나요?**  
A: 정확히 2자리 hex를 입력합니다 (예: A4). 알려진 DSCP 값을 입력하면 자동으로 드롭다운으로 전환됩니다.

---

**© 2026 JUSEOK AHN <ajs3013@lguplus.co.kr> All rights reserved.**
