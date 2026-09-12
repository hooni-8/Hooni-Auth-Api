# Hooni Template Auth API

회원가입, 로그인, 세션 확인, JWT 발급·갱신 및 로그아웃을 담당하는 공용 인증 API 템플릿입니다.

Auth API만 RSA 개인키를 보유하고, Gateway와 업무 API는 Auth API가 공개하는 JWKS 공개키로 JWT를 검증합니다. 따라서 여러 프로젝트가 Auth API를 공유해도 JWT 서명용 비밀키를 각 프로젝트에 배포할 필요가 없습니다.

## 1. 전체 구성

```text
React Front
    │
    ▼
Gateway
    ├─ /auth/** ───────────▶ Auth API
    │                         ├─ 회원가입·로그인
    │                         ├─ Access/Refresh Token 발급
    │                         ├─ Refresh 세션 관리
    │                         └─ RSA Private/Public Key 관리
    │
    └─ /api/** ────────────▶ Business API
                              ├─ JWT 재검증
                              ├─ 업무 로직
                              └─ 리소스별 권한 검사
```

외부 클라이언트는 Gateway만 호출합니다. Auth API와 Business API는 가능하면 Kubernetes 내부 네트워크에만 노출합니다.

## 2. 프로젝트별 책임

| 프로젝트 | 책임 |
| --- | --- |
| Front | 로그인 화면, 인증 상태 확인, 자동 토큰 갱신 |
| Gateway | 외부 진입점, JWT 1차 검증, 요청 라우팅, Access Token 전달 |
| Auth API | 계정·비밀번호·Refresh 세션·RSA 개인키 관리, JWT 발급 |
| Business API | JWT 2차 검증, 업무 로직, 데이터별 세부 권한 검사 |

Gateway는 로그인 여부와 공통 역할을 확인하고, Business API는 실제 업무 권한을 확인합니다.

```text
Gateway: 로그인한 사용자인가?
Business API: 이 사용자가 해당 주문이나 게시물을 수정할 수 있는가?
```

### 공통 응답 형식

Auth Controller는 Template API와 동일하게 DTO나 `ResponseEntity`를 그대로 반환합니다.
`ApiResponseAdvice`가 일반 API의 성공 응답을 다음 형식으로 자동 변환합니다.

```json
{
  "code": "0000",
  "message": "SUCCESS",
  "data": {}
}
```

반환 데이터가 없는 회원가입·로그인·갱신·로그아웃 성공 응답은 `data`가 `null`입니다.
오류 응답은 `ApiExceptionHandler`가 같은 공통 형식으로 반환합니다.

`/oauth2/jwks`는 OAuth/JWT 라이브러리가 읽는 표준 JWKS 형식을 유지해야 하므로
`@RawResponse`를 사용해 공통 응답 변환에서 제외합니다.

## 3. RSA 키와 JWKS

Auth API는 RSA 키 쌍을 관리합니다.

```text
Private Key
└─ Auth API에서 JWT를 생성하고 서명할 때만 사용

Public Key
└─ Gateway와 Business API가 JWT 서명을 검증할 때 사용
```

개인키는 Auth API 밖으로 전달하지 않습니다. 공개키는 비밀정보가 아니며 다음 엔드포인트에서 JWKS 형식으로 제공합니다.

```http
GET /oauth2/jwks
```

응답 예시:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "hooni-template-rsa-ab12cd34",
      "n": "RSA modulus",
      "e": "AQAB"
    }
  ]
}
```

JWT 헤더의 `kid`와 JWKS의 `kid`를 이용해 검증할 공개키를 선택합니다.

## 4. JWT 계약

현재 템플릿의 기본 계약은 다음과 같습니다.

```yaml
jwt:
  algorithm: RS256
  issuer: hooni-template-auth
  audience: hooni-template-api
```

Access Token의 주요 Claim:

```json
{
  "sub": "accessToken",
  "iss": "hooni-template-auth",
  "aud": "hooni-template-api",
  "jti": "토큰 고유 ID",
  "userCode": "사용자 코드",
  "userName": "사용자 이름",
  "role": "FREE_USER",
  "iat": "발급 시각",
  "exp": "만료 시각"
}
```

Refresh Token은 동일한 서명 방식을 사용하지만 `sub` 값이 `refreshToken`입니다. Gateway와 Business API는 `sub=accessToken`인 토큰만 인증에 허용합니다.

검증 항목:

- RSA 서명과 `RS256` 알고리즘
- `iss` 발급자
- `aud` 대상 API
- `sub` 토큰 용도
- `exp` 만료 시각
- `jti` 토큰 고유 ID
- `userCode`, `role` 필수 Claim

## 5. 회원가입

```http
POST /auth/register
Content-Type: application/json
```

```json
{
  "userName": "사용자 이름",
  "userId": "user01",
  "userPassword": "password123"
}
```

처리 흐름:

```text
Front
  → Gateway
  → Auth API
  → 요청 횟수 제한 확인
  → 입력값 및 아이디 중복 확인
  → 비밀번호 bcrypt 해시
  → 사용자 계정 저장
```

아이디 중복 확인:

```http
POST /auth/register/exists
```

```json
{
  "userId": "user01"
}
```

회원 테이블과 스키마는 이 템플릿 외부의 데이터베이스 프로젝트에서 관리합니다.

## 6. 로그인과 쿠키

```http
POST /auth/login
Content-Type: application/json
```

```json
{
  "userId": "user01",
  "password": "password123"
}
```

처리 흐름:

```text
1. Front가 Gateway로 로그인 요청
2. Gateway가 Auth API로 요청 전달
3. Auth API가 IP·사용자별 Rate Limit 확인
4. 사용자와 비밀번호 검증
5. RSA Private Key로 Access/Refresh Token 서명
6. 토큰을 HttpOnly 쿠키로 응답
```

| 쿠키 | 기본 유효기간 | Path | 용도 |
| --- | --- | --- | --- |
| `accessToken` | 15분 | `/` | Gateway와 API 요청 인증 |
| `refreshToken` | 7일 | `/auth` | 토큰 갱신과 로그아웃 |

두 토큰은 JavaScript 응답 본문이나 `localStorage`에 저장하지 않습니다.

```text
HttpOnly = true
SameSite = Lax
Secure   = 로컬 false, 운영 true
```

Refresh Token은 Redis에 SHA-256 해시로 저장하며 갱신할 때마다 회전합니다.

## 7. 세션 확인

Front는 애플리케이션 시작 시 로그인 상태를 확인합니다.

```http
POST /auth/session
```

Access Token이 유효한 경우:

```json
{
  "status": true,
  "refreshable": false,
  "name": "사용자 이름",
  "userCode": "USER_CODE",
  "role": "FREE_USER"
}
```

Access Token이 만료됐지만 Refresh Token이 유효한 경우:

```text
1. /auth/session → status=false, refreshable=true
2. Front → POST /auth/refresh
3. Auth API가 Access/Refresh Token 재발급
4. Front → POST /auth/session 재호출
5. 로그인 상태 복구
```

Refresh Token도 사용할 수 없으면 로그인 페이지로 이동합니다.

## 8. 일반 API 인증

로그인 후 Front가 업무 API를 호출하는 흐름입니다.

```text
Front
  │ Access Token 쿠키
  ▼
Gateway
  ├─ 쿠키에서 Access Token 추출
  ├─ Auth API JWKS 공개키로 JWT 검증
  ├─ issuer, audience, subject, 만료 및 Claim 검증
  └─ Authorization: Bearer <Access Token> 생성
       │
       ▼
Business API
  ├─ Auth API JWKS 공개키로 JWT 재검증
  ├─ 인증 사용자 Principal 생성
  └─ 업무 권한 확인 후 요청 처리
```

Gateway는 일반 API로 브라우저 쿠키를 전달하지 않습니다.

```text
제거: Cookie: accessToken=...; refreshToken=...
전달: Authorization: Bearer <access-token>
```

따라서 Business API는 Refresh Token이나 브라우저 쿠키를 관리할 필요가 없습니다.

## 9. Access Token 자동 갱신

일반 API 요청이 401을 반환하면 Front의 Axios 인터셉터가 갱신을 시도합니다.

```text
API 요청
  → 401
  → POST /auth/refresh
  → 새 Access/Refresh Token 발급
  → 기존 API 요청 한 번 재시도
```

한 브라우저 탭에서 여러 요청이 동시에 401을 받아도 하나의 Refresh 요청을 공유합니다.

- `/auth/refresh`가 401이면 로그인 페이지로 이동합니다.
- 갱신 후 특정 Business API만 다시 401이면 로그인 상태를 종료하지 않고 해당 API 오류를 호출 화면에 전달합니다.
- 네트워크 장애나 5xx 응답은 로그인 만료로 처리하지 않습니다.

## 10. 로그아웃

```http
POST /auth/logout
```

```text
Front
  → Gateway
  → Auth API
  → 서버 Refresh 세션 정리
  → Access/Refresh 쿠키 만료
  → Front 인증 상태 초기화
  → /login 이동
```

## 11. Gateway 라우팅

Gateway는 기존 `routers.defaults` 방식으로 Auth API와 각 Business API를 연결합니다.

로컬 예시:

```yaml
routers:
  defaults:
    auth-api:
      context: auth
      scheme: http
      host: localhost
      port: 8080
      forward-cookies: true

    template-api:
      context: api
      scheme: http
      host: localhost
      port: 8200
```

`forward-cookies: true`는 로그인·갱신·로그아웃을 처리하는 Auth API 라우트에만 설정합니다. 일반 Business API 라우트는 Gateway가 검증한 Bearer Token만 전달합니다.

## 12. JWKS 연결 설정

Gateway와 Business API는 Auth API의 JWKS 주소를 알아야 합니다.

### 로컬 환경

```yaml
jwt:
  jwk-set-uri: http://localhost:8080/oauth2/jwks
```

또는 환경변수:

```env
AUTH_API_JWK_SET_URI=http://localhost:8080/oauth2/jwks
```

### Kubernetes 환경

Service가 다음과 같다고 가정합니다.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: auth-api-service
  namespace: auth
spec:
  selector:
    app: auth-api
  ports:
    - port: 80
      targetPort: 8080
```

다른 namespace의 Pod에서는 다음 주소를 사용합니다.

```env
AUTH_API_JWK_SET_URI=http://auth-api-service.auth.svc/oauth2/jwks
```

전체 Service DNS를 사용해도 됩니다.

```text
http://auth-api-service.auth.svc.cluster.local/oauth2/jwks
```

DNS 형식:

```text
http://<service-name>.<namespace>.svc.cluster.local:<service-port>/<path>
```

- 같은 namespace에서는 `http://auth-api-service/oauth2/jwks`처럼 Service 이름만 사용할 수 있습니다.
- 다른 namespace에서는 Service 이름과 namespace를 함께 사용합니다.
- `targetPort`가 8080이어도 호출자는 Service의 `port`인 80을 사용합니다.
- Service port가 80이면 URL에서 포트를 생략할 수 있습니다.
- 이 주소는 Kubernetes 클러스터 내부 전용이며 로컬 브라우저에서는 일반적으로 접근할 수 없습니다.

JWKS를 Gateway를 거쳐 조회하게 만들 수도 있지만 `Business API → Gateway → Auth API` 의존성이 생깁니다. Gateway와 Business API가 Auth API의 내부 Service DNS를 직접 사용하는 구성을 권장합니다.

## 13. 로컬 키와 운영 키

### 로컬

`JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`가 모두 비어 있으면 Auth API가 2048-bit RSA 키 쌍을 실행 시 자동 생성합니다.

```text
Auth API 재시작
→ 새로운 RSA 키 생성
→ 기존 Access/Refresh Token 검증 실패
→ 브라우저 쿠키 삭제 후 다시 로그인
```

### 운영

운영에서는 고정 키를 비밀 저장소에서 Auth API에 주입해야 합니다.

```env
JWT_PRIVATE_KEY=<Base64 PKCS#8 RSA private key>
JWT_PUBLIC_KEY=<Base64 X.509 RSA public key>
```

- Private Key는 Auth API에만 주입합니다.
- Public Key는 `/oauth2/jwks`를 통해 제공합니다.
- 모든 Auth API replica는 동일한 운영 키 쌍을 사용해야 합니다.
- Private/Public Key 중 하나만 설정하면 Auth API가 시작되지 않습니다.
- Private Key를 Git, Docker 이미지 또는 일반 ConfigMap에 저장하지 않습니다.

운영 키 저장소 예시:

- Kubernetes Secret
- AWS Secrets Manager 또는 KMS
- Azure Key Vault
- HashiCorp Vault

## 14. 여러 프로젝트에서 Auth API 공유

현재 템플릿은 하나의 Business API를 대상으로 합니다.

```text
audience = hooni-template-api
```

여러 프로젝트에서 Auth API를 공유할 때는 프로젝트별 `client_id`, `audience`, `scope`를 등록해야 합니다.

```text
Project A: client_id=project-a, audience=project-a-api
Project B: client_id=project-b, audience=project-b-api
NAS:       client_id=nas,       audience=nas-api
```

각 API는 자신에게 발급된 audience만 허용합니다.

```text
aud=project-a-api → Project A API 허용
aud=project-a-api → NAS API 거부
```

브라우저가 임의의 audience를 자유롭게 지정하도록 만들면 안 됩니다. Auth API가 등록된 `client_id → 허용 audience` 관계를 서버 설정이나 DB에서 검증해야 합니다.

## 15. 실행 순서

로컬 권장 실행 순서:

```text
1. PostgreSQL 및 Redis
2. Auth API      :8080
3. Gateway       :9090
4. Template API  :8200
5. React Front   :3000
```

Windows:

```powershell
.\gradlew.bat bootRun
```

macOS/Linux:

```bash
./gradlew bootRun
```

Auth API의 암호화된 DB·Redis 설정을 복호화하려면 `ENCRYPTOR_PROFILE`을 실행 환경에 주입해야 합니다.

## 16. 주요 설정

| 설정 | 기본값 | 설명 |
| --- | --- | --- |
| `server.port` | `8080` | Auth API 포트 |
| `jwt.algorithm` | `RS256` | JWT 서명 알고리즘 |
| `jwt.issuer` | `hooni-template-auth` | JWT 발급자 |
| `jwt.audience` | `hooni-template-api` | JWT 대상 API |
| `jwt.key-id` | `hooni-template-rsa` | 운영 RSA 키 식별자 |
| `jwt.access-token-validity` | `15m` | Access Token 유효기간 |
| `jwt.refresh-token-validity` | `7d` | Refresh Token 유효기간 |
| `application.cookie.secure` | 로컬 `false`, 운영 `true` | HTTPS 전용 쿠키 여부 |
| `application.cookie.same-site` | `Lax` | 쿠키 SameSite 정책 |

## 17. 엔드포인트

| Method | Path | 설명 |
| --- | --- | --- |
| `POST` | `/auth/register` | 회원가입 |
| `POST` | `/auth/register/exists` | 아이디 중복 확인 |
| `POST` | `/auth/login` | 로그인 및 토큰 쿠키 발급 |
| `POST` | `/auth/session` | 로그인·갱신 가능 상태 확인 |
| `POST` | `/auth/refresh` | Access/Refresh Token 회전 |
| `POST` | `/auth/logout` | 서버 세션 및 쿠키 정리 |
| `GET` | `/oauth2/jwks` | JWT 검증용 RSA 공개키 조회 |

## 18. 문제 해결

### 로그인 후 API가 401을 반환하는 경우

다음을 순서대로 확인합니다.

1. Auth API의 `/oauth2/jwks`가 접근 가능한지 확인합니다.
2. Gateway와 Business API의 `AUTH_API_JWK_SET_URI`를 확인합니다.
3. 세 서비스의 `issuer`와 `audience`가 일치하는지 확인합니다.
4. 기존 HS256 또는 이전 RSA 키로 발급된 브라우저 쿠키를 삭제합니다.
5. Auth API 재시작 후 새로 로그인합니다.

### Kubernetes에서 JWKS 주소가 해석되지 않는 경우

```text
Service 이름과 namespace 확인
→ Service selector와 Endpoint 확인
→ Service port 확인
→ CoreDNS 확인
→ NetworkPolicy 확인
```

### Auth API 재시작마다 로그인이 풀리는 경우

로컬 자동 생성 키를 사용하고 있기 때문입니다. 지속적인 세션이 필요한 환경에서는 고정된 `JWT_PRIVATE_KEY`, `JWT_PUBLIC_KEY`를 주입합니다.

## 19. 검증

```powershell
.\gradlew.bat test
```

테스트에는 다음 항목이 포함됩니다.

- RS256 Access/Refresh Token 발급과 파싱
- Access Token과 Refresh Token 용도 분리
- 다른 RSA 키로 서명된 토큰 거부
- JWKS 공개키로 실제 JWT 검증
- JWKS 응답에 개인키 정보가 포함되지 않는지 확인
- 회원가입·로그인 요청 검증
- Refresh Token 회전 및 인증 서비스 로직

## 참고 문서

- [Spring Security OAuth2 Resource Server JWT](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html)
- [Kubernetes DNS for Services and Pods](https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/)
