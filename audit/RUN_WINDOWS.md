## Windows 실행 가이드 (진단자용)

이 패키지는 **로컬에서 실제 멀티 도메인 HTTPS 구조**(DPoP 전용 사이트 + 레가시 사이트 프록시)를 재현하기 위한 데모입니다.
ZIP에는 **`.dev.vars`(비밀값 포함)** 이 들어있습니다. 외부 공유 금지.

### 0) 준비물

- **Node.js**: LTS 설치
- **터미널**: PowerShell 권장

### 1) hosts 파일 수정 (관리자 권한 필요)

`C:\Windows\System32\drivers\etc\hosts`에 아래를 추가합니다.

```text
127.0.0.1 dpop.skplanet.com
127.0.0.1 www.okcashbag.com
127.0.0.1 member.okcashbag.com
```

### 1-1) (대안) hosts 수정 없이 Chromium 실행 옵션으로 매핑하기

관리자 권한이 없거나 hosts 변경이 어려우면, Chromium/Chrome을 아래 옵션으로 실행해도 됩니다.

- 핵심 옵션: `--host-resolver-rules="MAP <domain> 127.0.0.1, ..."`
- **중요**: Passkey/WebAuthn을 쓰려면 `--ignore-certificate-errors`는 사용하지 마세요(차단될 수 있음)

예시(Windows, PowerShell):

```powershell
$rules = "MAP dpop.skplanet.com 127.0.0.1, MAP www.okcashbag.com 127.0.0.1, MAP member.okcashbag.com 127.0.0.1"
Start-Process "chrome.exe" -ArgumentList @(
  "--user-data-dir=$PWD\.chrome-profile",
  "--host-resolver-rules=$rules"
)
```

### 2) 로컬 CA 인증서 신뢰(Trust) 등록 (1회)

1) `dev\certs\local-ca.crt` 파일을 더블클릭 → 설치
2) **로컬 컴퓨터(Local Machine)** 저장소 선택
3) **신뢰할 수 있는 루트 인증 기관(Trusted Root Certification Authorities)** 에 추가

또는(권장, 관리자 PowerShell):

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\dev\trust-local-ca-windows.ps1
```

※ 브라우저(Chromium/Chrome) 재시작이 필요할 수 있습니다.

### 3) 의존성 설치

ZIP을 압축 해제한 폴더에서:

```powershell
npm install
```

### 4) 로컬 DB 초기화 (최초 1회)

```powershell
npx wrangler d1 execute dpop_db --local --file=.\schemas\init.sql
```

### 5) 서버 실행 (터미널 2개)

**터미널 A (Worker)**

```powershell
npm run dev -- --local
```

**터미널 B (TLS 프록시, HTTPS 8443)**

```powershell
npm run dev:tls
```

만약 아래 에러가 나오면:

- `Missing TLS cert/key. Generate them first: bash dev/generate-local-certs.sh`

ZIP이 제대로 풀렸는지 먼저 확인하세요:

- `dev\certs\okcashbag.local.crt`
- `dev\certs\okcashbag.local.key`
- `dev\certs\local-ca.crt`

그래도 안되면(경로 문제 가능) 최신 ZIP을 다시 받거나, 임시로 환경변수로 경로를 지정해 실행할 수 있습니다:

```powershell
$env:TLS_CERT = (Resolve-Path .\dev\certs\okcashbag.local.crt).Path
$env:TLS_KEY  = (Resolve-Path .\dev\certs\okcashbag.local.key).Path
npm run dev:tls
```

### 6) 접속 URL

- 레가시 프록시(실사이트 HTML을 가져와 SDK를 주입): `https://www.okcashbag.com:8443/`
- 레가시 프록시(회원): `https://member.okcashbag.com:8443/`
- DPoP 에이전트/로그인: `https://dpop.skplanet.com:8443/`

### 7) 문제 해결

- **인증서 경고가 계속 뜸**
  - 2) CA 신뢰 등록이 올바른 저장소(Trusted Root / Local Machine)에 들어갔는지 확인
  - Chrome 완전 종료 후 재실행
  - **중요**: `NotAllowedError: WebAuthn is not supported on sites with TLS certificate errors`가 나오면
    - 브라우저가 해당 사이트를 “인증서 오류”로 인식 중입니다.
    - “고급 → 계속” 같은 예외로는 WebAuthn이 동작하지 않습니다. 반드시 `local-ca.crt`를 신뢰 저장소에 넣어야 합니다.
    - `--ignore-certificate-errors` 옵션을 켜면 Passkey/WebAuthn이 차단될 수 있습니다.
- **포트가 사용 중**
  - 8443 또는 8787을 점유한 프로세스 종료 후 재시도

