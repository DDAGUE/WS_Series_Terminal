<div align="center">

# 📡 Serial_Terminal

> `Serial_Terminal`은 시리얼 장비 테스트를 위한 데스크톱 터미널 도구입니다.  
> 기본적으로 **UMB Binary 통신 확인**에 맞춰져 있으며, 필요할 때는 **ASCII 문자열 터미널 모드**로 전환해 일반 문자열 기반 센서도 함께 테스트할 수 있습니다.

<p>
  <img src="https://img.shields.io/badge/Mode-UMB%20Binary-blue" alt="UMB Binary">
  <img src="https://img.shields.io/badge/Mode-ASCII-green" alt="ASCII">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6" alt="Windows">
  <img src="https://img.shields.io/badge/Interface-Desktop-orange" alt="Desktop">
</p>

</div>

---

## 📚 목차

- [주요 기능](#-주요-기능)
- [동작 모드](#-동작-모드)
  - [1) UMB Binary 모드](#1-umb-binary-모드)
  - [2) ASCII 모드](#2-ascii-모드)
- [빠른 시작](#-빠른-시작)
  - [UMB Binary 모드](#umb-binary-모드-1)
  - [ASCII 모드](#ascii-모드-1)
- [화면 구성](#-화면-구성)
- [Save TXT](#-save-txt)
- [Flow Control 안내](#-flow-control-안내)
- [트러블슈팅](#-트러블슈팅)
- [용도 정리](#-용도-정리)

---

## ✨ 주요 기능

| 구분 | 내용 |
|:---|:---|
| **UMB Binary 모드 지원** | UMB 요청 프레임 생성<br>선택 채널 요청 및 응답 파싱<br>상단 RAW / 하단 Parsed 출력 분리 |
| **ASCII 모드 지원** | 동일한 UI에서 문자열 터미널 동작<br>상단 창에 TX / RX 문자열 로그 표시<br>하단 창에서 문자열 입력 후 Enter로 즉시 전송 |
| **시리얼 설정 지원** | COM Port<br>Baudrate<br>Data bits / Parity / Stop bits<br>XON/XOFF, RTS/CTS, DSR/DTR |
| **TXT 로그 저장** | 화면 출력 내용을 TXT 파일로 저장 가능 |

---

## 🔀 동작 모드

### 1) UMB Binary 모드

> UMB Binary 통신 확인용 모드입니다.

#### 상단 창
- `[HH:MM:SS] TX:` 전송 프레임
- `[HH:MM:SS] RX:` 수신 프레임
- View 옵션에 따라 **HEX / DEC** 표시

#### 하단 창
- 수신 프레임에서 추출한 채널 값을 사람이 읽기 쉬운 형태로 표시
- `channels`에 지정한 순서대로 `값 ; 값 ; 값` 형태 출력

#### 주요 제어 항목
- **TX Mode**
  - `UMB_2F`: WS 시리즈 채널 요청 프레임 자동 생성
  - `CUSTOM`: 사용자가 직접 HEX 프레임 입력
- **WS class / device_id / channels**
- **Send Once**
- **Auto TX**
  - 설정 창에서 Interval / Repeat 지정 가능

---

### 2) ASCII 모드

> ASCII 문자열 기반 센서 또는 장비를 확인하기 위한 모드입니다.

ASCII를 선택하면 프로그램이 **문자열 터미널 방식**으로 동작합니다.

#### 상단 창
- `[HH:MM:SS] TX: asdqwe...`
- `[HH:MM:SS] RX: sensor,data,...`
- 송수신 문자열 로그를 시간과 함께 표시

#### 하단 창
- 사용자 입력창으로 동작
- 원하는 문자열 입력 후 **Enter**를 누르면 즉시 전송
- 전송 시 기본적으로 **CRLF (`\r\n`)** 가 함께 붙습니다

#### ASCII 모드에서 비활성화되는 항목
다음 UMB 전용 항목은 자동으로 비활성화됩니다.

- TX Mode
- WS class
- device_id
- channels
- Send Once
- Custom TX (hex)

`Clear`는 그대로 사용할 수 있습니다.

#### 수신 방식
- 수신 데이터는 **CR / LF 기준으로 한 줄씩** 표시됩니다.
- 일반적인 polling형 ASCII 센서 점검용으로 사용할 수 있습니다.

---

## 🚀 빠른 시작

### UMB Binary 모드

1. 프로그램 실행
2. **Settings**에서 시리얼 포트와 통신 조건 설정
3. **Connect** 클릭
4. 필요 시 `channels` 수정
5. `Send Once` 또는 Auto TX로 요청 전송
6. 상단 RAW / 하단 Parsed 결과 확인

#### 예시 기본 채널

```text
100,200,300,401,501
```

일반적으로 다음과 같이 사용합니다.

- `100`: 기온
- `200`: 상대습도
- `300`: 기압
- `401`: 풍속
- `501`: 풍향

> 실제 채널 의미와 스케일은 장비 설정 및 펌웨어에 따라 달라질 수 있습니다.

---

### ASCII 모드

1. 우측 상단 **View**를 `ASCII`로 변경
2. **Connect** 클릭
3. 하단 입력창에 문자열 입력
4. **Enter**로 전송
5. 상단에서 TX / RX 문자열 로그 확인

#### 예

```text
TX: TEST\r\n
RX: OK,25.1,63.2
```

---

## 🖥️ 화면 구성

- **상단**: RAW / TX / RX 로그
- **하단**:
  - UMB 모드: 파싱된 값 출력
  - ASCII 모드: 문자열 입력창
- **하단 제어부**:
  - UMB 모드에서는 프레임 생성 / 채널 요청 관련 제어
  - ASCII 모드에서는 UMB 관련 항목 비활성화

---

## 💾 Save TXT

- `Save TXT` 체크 후 저장할 TXT 파일을 선택하면 로그를 저장할 수 있습니다.
- UMB 모드에서는 하단 Parsed 출력값 위주로 저장됩니다.
- ASCII 모드에서는 상단 TX / RX 로그 기준으로 저장하는 방식으로 사용할 수 있습니다.

---

## ⚙️ Flow Control 안내

> 대부분 환경에서는 아래 옵션을 **OFF**로 두는 것이 일반적입니다.  
> 필요한 장비에서만 활성화해 테스트하십시오.

- XON/XOFF
- RTS/CTS
- DSR/DTR

---

## 업데이트 내역

### 2026.05.20 - 실행 안정성 및 Windows 환경 호환성 개선

프로그램 실행 환경과 시리얼 통신 동작 오류를 개선했습니다.

일부 Windows PC 환경에서 장시간 실행, 포트 재연결, 프로그램 종료 과정 중 예외 상황이 발생한 부분을 보완했으며, 여러 PC에서 동작을 유지할 수 있도록 내부 처리 방식을 수정했습니다.

#### 주요 업데이트 내용

- Windows 실행 환경 호환성 개선
- 시리얼 포트 연결 및 해제 동작 안정성 개선
- 포트 재연결 시 발생할 수 있는 예외 상황 완화
- 프로그램 종료 시 리소스 정리 동작 개선
- 로그 저장 및 화면 표시 동작 안정성 개선
- 일부 PC 환경에서 발생할 수 있는 비정상 종료 가능성 개선
- 내부 예외 처리 및 사용자 알림 동작 개선
- 최신 Python 실행 환경 기준으로 코드 정리

#### 업데이트 권장 사항

기존 파일을 사용 중인 경우, 안정적인 사용을 위해 2026.05.20 이후 업데이트된 파일로 교체하는 것을 권장합니다.

---

## 🛠️ 트러블슈팅

### 1) Connect가 되지 않을 때
- 다른 프로그램이 COM 포트를 점유 중인지 확인하십시오.
- 장치 관리자에서 포트 번호와 드라이버 상태를 확인하십시오.
- Baudrate / Parity / Stop bits가 장비 설정과 일치하는지 확인하십시오.

### 2) UMB 모드에서 값이 보이지 않을 때
- 실제 장비가 요청 채널에 응답하는지 확인하십시오.
- `channels` 값이 올바른지 확인하십시오.
- 케이블 / 컨버터 / 종단 / 배선 상태를 점검하십시오.

### 3) ASCII 모드에서 RX가 보이지 않을 때
- 장비가 실제로 ASCII 문자열을 송신하는지 확인하십시오.
- 장비의 줄 끝 문자가 CR / LF 계열인지 확인하십시오.
- Baudrate 및 시리얼 포맷이 장비와 일치하는지 확인하십시오.

---

## 📌 용도 정리

이 프로그램은 다음과 같은 상황에서 유용합니다.

- UMB Binary 프레임 테스트
- 채널 요청 및 응답 확인
- 시리얼 포트 통신 상태 점검
- ASCII 센서 문자열 송수신 테스트
- 현장 설치 전 / 후 기본 통신 검증
