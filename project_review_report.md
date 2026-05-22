# 프로젝트 코드 리뷰 리포트

## 검사 대상

- 파일명: `apps/web-platform/backend/src/server.js`
- 전체 경로: `C:\Users\user\ktcloud2nd\apps\web-platform\backend\src\server.js`
- 총 라인 수: 544줄
- 언어/환경: JavaScript, Node.js, Express
- 검사 기준: 코드 스타일, 유지보수성, OWASP Top 10 기반 보안 점검

---

## 스타일 검사 결과

### 1. 하나의 파일에 책임이 너무 많이 모여 있음

**문제점**

`server.js` 파일 하나 안에 서버 생성, CORS 설정, 세션 토큰 생성/검증, 인증 미들웨어, 회원가입/로그인 API, 사용자 대시보드 API, 운영자 API, 서버 실행 코드가 모두 들어 있습니다.

```javascript
const app = express();
const port = Number(process.env.PORT || 4000);
const appTarget = readTrimmedEnv('APP_TARGET', 'all').toLowerCase();
const sessionTtlSeconds = Number(process.env.SESSION_TTL_SECONDS || 60 * 60);
const sessionSecret = getSessionSecret();
```

**개선 방법**

라우터와 서비스 계층을 분리하면 파일을 읽기 쉬워지고 수정 영향 범위도 줄어듭니다.

```text
src/
  server.js
  routes/
    authRoutes.js
    userRoutes.js
    operatorRoutes.js
  services/
    sessionService.js
    dashboardService.js
  middlewares/
    requireRoleSession.js
```

---

### 2. 같은 경로의 라우트가 중복 등록되어 있음

**문제점**

`/api/user/dashboard` 경로가 두 번 등록되어 있습니다.

```javascript
// 491번째 줄 부근
app.get('/api/user/dashboard', async (request, response) => {
  const vehicleId = String(request.query.vehicleId || '').trim();
  // ...
});

// 593번째 줄 부근
app.get('/api/user/dashboard', requireUserSession, async (request, response) => {
  const dashboard = await loadUserDashboard(request.session.userId);
  // ...
});
```

**원인**

같은 API 경로에 인증 없는 버전과 인증 있는 버전이 함께 존재합니다. Express는 먼저 등록된 라우트부터 처리하므로, 뒤쪽의 인증 라우트가 의도대로 동작하지 않을 수 있습니다.

**개선 방법**

사용자 대시보드는 로그인 사용자의 세션 기준으로 조회하도록 하나의 라우트만 남기는 것이 좋습니다.

```javascript
app.get('/api/user/dashboard', requireUserSession, async (request, response) => {
  const dashboard = await loadUserDashboard(request.session.userId);

  if (!dashboard) {
    response.status(404).json({
      message: 'User dashboard data could not be found.'
    });
    return;
  }

  response.json(dashboard);
});
```

---

### 3. 에러 응답 코드가 반복됨

**문제점**

여러 라우트에서 `try/catch`와 `response.status(500).json(...)` 패턴이 반복됩니다.

```javascript
} catch (error) {
  response.status(500).json({
    message: 'Failed to load the anomaly dashboard.',
    details: error.message
  });
}
```

**개선 방법**

공통 에러 핸들러를 만들어 응답 형식과 로그 정책을 통일하는 것이 좋습니다.

```javascript
function sendServerError(response, message, error) {
  console.error(message, error);
  response.status(500).json({ message });
}
```

---

### 4. 인증 토큰 로직을 별도 모듈로 분리할 필요가 있음

**문제점**

세션 토큰 생성과 검증 함수가 `server.js` 내부에 직접 구현되어 있습니다.

```javascript
function createSessionToken(account) {
  const payload = {
    userId: account.userId,
    role: account.role,
    issuedAt: Math.floor(Date.now() / 1000)
  };
  // ...
}
```

**개선 방법**

`sessionService.js` 같은 별도 파일로 분리하면 테스트가 쉬워지고, 토큰 정책 변경 시 라우터 코드를 건드리지 않아도 됩니다.

---

## 보안 검사 결과

## 취약점 1. 인증 없는 사용자 대시보드 조회

**위험도:** HIGH  
**OWASP:** A01:2021 - Broken Access Control

**문제 코드**

```javascript
app.get('/api/user/dashboard', async (request, response) => {
  const vehicleId = String(request.query.vehicleId || '').trim();

  if (!vehicleId) {
    response.status(400).json({
      message: 'vehicleId is required.'
    });
    return;
  }

  const result = await query(
    `
      SELECT
        vehicle_id AS "vehicleId",
        timestamp,
        lat,
        lon,
        speed,
        engine_on AS "engineOn",
        fuel_level AS "fuelLevel",
        event_type AS "eventType",
        mode
      FROM vehicle_stats
      WHERE vehicle_id = $1
      ORDER BY timestamp DESC
      LIMIT 60
    `,
    [vehicleId]
  );
});
```

**원인**

사용자 차량 대시보드 데이터는 개인 차량 정보에 해당하지만, 해당 라우트는 `requireUserSession` 인증 미들웨어 없이 `vehicleId` 쿼리 값만으로 데이터를 조회합니다. 공격자가 `car_1`, `car_2` 같은 차량 ID를 추측하면 다른 사용자의 차량 상태, 위치, 속도, 연료 정보가 노출될 수 있습니다.

**수정 방법**

인증 없는 라우트를 제거하고, 로그인 세션의 `userId`를 기준으로 차량 정보를 조회해야 합니다.

```javascript
app.get('/api/user/dashboard', requireUserSession, async (request, response) => {
  const dashboard = await loadUserDashboard(request.session.userId);

  if (!dashboard) {
    response.status(404).json({
      message: 'User dashboard data could not be found.'
    });
    return;
  }

  response.json(dashboard);
});
```

---

## 취약점 2. 상세 에러 메시지 클라이언트 노출

**위험도:** MEDIUM  
**OWASP:** A05:2021 - Security Misconfiguration

**문제 코드**

```javascript
response.status(500).json({
  message: 'Failed to load the user vehicle dashboard.',
  details: error.message
});
```

```javascript
response.status(500).json({
  message: `Failed to load the operator vehicle dashboard. ${error.message}`,
  details: error.message
});
```

**원인**

`error.message`를 그대로 응답하면 DB 오류, 테이블명, 컬럼명, 내부 서비스 구조 등이 외부 사용자에게 노출될 수 있습니다. 운영 환경에서는 이런 정보가 공격자의 정찰 정보로 활용될 수 있습니다.

**수정 방법**

클라이언트에는 일반적인 메시지만 반환하고, 상세 오류는 서버 로그에만 남기는 방식이 안전합니다.

```javascript
} catch (error) {
  console.error('Failed to load user dashboard', error);
  response.status(500).json({
    message: 'Failed to load the user dashboard.'
  });
}
```

---

## 취약점 3. 로그인 API에 요청 제한이 없음

**위험도:** MEDIUM  
**OWASP:** A07:2021 - Identification and Authentication Failures

**문제 코드**

```javascript
app.post('/api/auth/login', async (request, response) => {
  const { userId, password } = request.body;
  // ...
});
```

**원인**

로그인 API에 rate limit, 계정 잠금, 실패 횟수 제한이 없습니다. 공격자가 자동화 도구로 비밀번호를 반복 시도할 수 있습니다.

**수정 방법**

`express-rate-limit` 같은 미들웨어를 적용하고, 같은 IP 또는 같은 계정에 대해 짧은 시간 내 반복 실패를 제한해야 합니다.

```javascript
import rateLimit from 'express-rate-limit';

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/api/auth/login', loginLimiter, async (request, response) => {
  // login logic
});
```

---

## 취약점 4. 보안 HTTP 헤더 설정 부족

**위험도:** LOW  
**OWASP:** A05:2021 - Security Misconfiguration

**문제점**

현재 Express 앱은 `cors`와 `express.json()`만 전역 미들웨어로 사용합니다.

```javascript
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
        return;
      }

      callback(new Error('Origin not allowed by CORS'));
    }
  })
);
app.use(express.json());
```

**원인**

`Helmet` 같은 보안 헤더 미들웨어가 없어 `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Content-Security-Policy` 등의 기본 방어 헤더가 설정되지 않습니다.

**수정 방법**

운영 환경에서는 `helmet`을 추가해 기본 보안 헤더를 적용하는 것이 좋습니다.

```javascript
import helmet from 'helmet';

app.use(helmet());
```

---

## 취약점 5. 비동기 인증 미들웨어의 예외 처리 부족

**위험도:** LOW  
**OWASP:** A09:2021 - Security Logging and Monitoring Failures

**문제 코드**

```javascript
function requireRoleSession(requiredRole) {
  return async (request, response, next) => {
    const session = await verifySessionToken(request.header('authorization'));

    if (!session || session.role !== requiredRole) {
      response.status(401).json({
        message: `A valid authenticated ${requiredRole} session is required.`
      });
      return;
    }

    request.session = session;
    next();
  };
}
```

**원인**

`verifySessionToken` 내부에서 DB 조회 오류가 발생하면 Express 4 환경에서는 비동기 미들웨어 예외가 공통 에러 핸들러로 자연스럽게 전달되지 않을 수 있습니다. 이 경우 요청이 비정상적으로 멈추거나 로그가 누락될 수 있습니다.

**수정 방법**

비동기 미들웨어 내부에서 `try/catch`로 `next(error)`를 호출하거나 async wrapper를 사용하는 것이 좋습니다.

```javascript
function requireRoleSession(requiredRole) {
  return async (request, response, next) => {
    try {
      const session = await verifySessionToken(request.header('authorization'));

      if (!session || session.role !== requiredRole) {
        response.status(401).json({
          message: `A valid authenticated ${requiredRole} session is required.`
        });
        return;
      }

      request.session = session;
      next();
    } catch (error) {
      next(error);
    }
  };
}
```

---

## 보안 검사 참고 문서

- OWASP Top 10 2021 - A01 Broken Access Control
- OWASP Top 10 2021 - A05 Security Misconfiguration
- OWASP Top 10 2021 - A07 Identification and Authentication Failures
- OWASP Top 10 2021 - A09 Security Logging and Monitoring Failures
- Express.js Security Best Practices

---

## 종합 평가

`server.js`는 SQL Injection 방어를 위해 대부분의 DB 쿼리에 파라미터 바인딩을 사용하고, 비밀번호 해시와 토큰 서명 검증도 구현되어 있어 기본 보안 방향은 좋습니다. 다만 같은 사용자 대시보드 경로가 인증 없는 라우트와 인증 라우트로 중복되어 있어 접근 제어 문제가 발생할 수 있습니다.

우선순위는 다음과 같습니다.

| 순위 | 항목 | 위험도 |
| --- | --- | --- |
| 1 | 인증 없는 `/api/user/dashboard` 제거 또는 인증 적용 | HIGH |
| 2 | 클라이언트에 `error.message` 반환 중단 | MEDIUM |
| 3 | 로그인 API rate limit 적용 | MEDIUM |
| 4 | Helmet 기반 보안 헤더 추가 | LOW |
| 5 | 비동기 인증 미들웨어 예외 처리 보강 | LOW |

가장 먼저 `/api/user/dashboard` 라우트 중복을 정리하고, 사용자 세션 기반 조회만 허용하도록 수정해야 합니다.
