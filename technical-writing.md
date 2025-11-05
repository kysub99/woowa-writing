# Broken Access Control

## 들어가며

**봄봄**은 복잡한 메일함을 뒤지지 않고 오늘 도착한 뉴스레터만 깔끔하게 모아 보는 개인 전용 뉴스레터 서비스입니다.
그런데 간단한 URL 조작만으로 다른 사람의 글이나 정보를 볼 수 있다면 어떨까요? 이는 단순한 버그가 아니라 **민감한 개인정보 유출**과 **콘텐츠 저작권 침해**로 이어질 수 있는 심각한 보안 사고입니다. 이러한 사고의 핵심에는 바로 **Broken Access Control(접근 제어 실패)** 취약점이 있습니다.

글로벌 웹 보안 비영리단체인 **OWASP(The Open Web Application Security Project)** 는 정기적으로 웹 애플리케이션에서 위험도가 높은 취약점들을 정리합니다. Broken Access Control은 2017년부터 현재까지 최상위 위험으로 분류되었는데, 이는 기능 구현에만 집중할 때 가장 쉽게 놓치는 동시에 가장 치명적인 취약점임을 뜻합니다.

이 글은 Broken Access Control의 정의와 유형을 설명하고, **Spring Security**가 제공하는 기능으로 각 유형을 어떻게 방어할지 구체적 코드와 함께 제시합니다.

---

## Broken Access Control이란?

**Broken Access Control**은 인증된 사용자가 허용되지 않은 기능이나 데이터에 접근할 수 있는 취약점입니다. 요약하면:

* **인증(Authentication)**: 사용자가 누구인지 확인하는 과정(예: 아이디/비밀번호)
* **인가(Authorization)**: 인증된 사용자가 특정 리소스나 기능에 접근할 권한이 있는지 확인하는 과정(예: 관리자만 신규 뉴스레터 등록 가능)

Broken Access Control은 **인가 과정이 누락되거나 잘못 구현**될 때 발생합니다. 주요 유형은 다음 네 가지입니다.

1. **수직적 권한 상승(Vertical Privilege Escalation)** — 일반 사용자가 관리자 전용 기능에 접근
2. **수평적 권한 상승 / IDOR(Insecure Direct Object Reference)** — 동등 권한 사용자 간에 데이터 탈취
3. **상황 의존적 권한 누락(Context-dependent access failure)** — 객체 상태나 비즈니스 규칙을 확인하지 않음
4. **메타데이터 조작(Metadata manipulation)** — 클라이언트가 보낸 민감 필드를 악용

다음 섹션에서 각 유형의 문제점과 실무 적용 가능한 해결책을 설명합니다.

---

## 유형 1 — 수직적 권한 상승 (Vertical Privilege Escalation)

**문제**
일반 사용자(USER)가 관리자(ADMIN)만 접근해야 할 기능(예: `/admin/newsletters`)에 접근할 수 있는 경우입니다. URL을 직접 입력하거나 요청 필드를 조작하면 관리자 페이지가 노출될 수 있습니다.

### 기본 해결책 — URL 패턴 기반 제어

`SecurityFilterChain`에서 URL 패턴별로 접근을 제한합니다.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                // /admin/**: ADMIN 역할만 허용
                .requestMatchers("/admin/**").hasRole("ADMIN")
                // /my-page/**: USER 또는 ADMIN
                .requestMatchers("/my-page/**").hasAnyRole("USER", "ADMIN")
                // 그 외는 공개
                .anyRequest().permitAll()
            );
        return http.build();
    }
}
```

> 장점: 중앙에서 URL 기반 규칙을 관리 가능.
> 단점: 개발자가 새로운 관리자 API를 추가하고 `SecurityConfig` 수정하는 것을 잊으면 규칙에서 누락될 위험이 있음.

### 권장(더 견고한) 해결책 — 메서드 시큐리티 (Defense in Depth)

URL 제어는 1차 방어로 유지하되, 비즈니스 로직 레이어(서비스 메서드)에 권한 검사를 추가합니다. 이렇게 하면 URL 규칙 누락 시에도 보호됩니다.

```java
@Configuration
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {
    // ...
}

@Service
public class NewsletterAdminService {

    // 메서드 자체에 ROLE_ADMIN 제약을 둠
    @Secured("ROLE_ADMIN")
    public void addNewsletter(NewsletterCreateDto createDto) {
        newsletterRepository.save(createDto.toEntity());
    }
}
```

> 핵심: **다층 방어** — URL 규칙 + 메서드 레벨 권한 검사.

---

## 유형 2 — 수평적 권한 상승 / IDOR (Insecure Direct Object Reference)

**문제**
사용자 A가 자신의 글(`/articles/101`)을 보다가 URL의 ID만 바꿔(`/articles/102`) 사용자 B의 글에 접근할 수 있는 상황입니다. 소유권 검사가 없을 때 발생합니다.

### 기본 해결책 — 서비스 레벨에서 소유권 직접 확인

서비스 메서드에서 현재 사용자와 리소스 소유자를 비교합니다.

```java
@Service
public class ArticleService {

    public Article getArticle(Long articleId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();

        Article article = articleRepository.findById(articleId)
                .orElseThrow(() -> new ArticleNotFoundException());

        if (!article.getUsername().equals(currentUsername)) {
            throw new AccessDeniedException("이 글을 조회할 권한이 없습니다.");
        }
        return article;
    }
}
```

> 단점: 인가 로직과 비즈니스 로직이 섞이고, 중복 검사 코드가 발생하기 쉽다.

### 권장(더 견고한) 해결책 — `@PostAuthorize`로 인가 분리

메서드 실행 후 반환 객체를 검사하도록 `@PostAuthorize`를 사용하면 비즈니스 로직과 인가 로직을 분리할 수 있습니다.

```java
@Service
public class ArticleService {

    @PostAuthorize("returnObject.username == principal.username")
    public Article getArticle(Long articleId) {
        return articleRepository.findById(articleId)
                .orElseThrow(() -> new ArticleNotFoundException());
    }

    public void deleteArticle(Long articleId) {
        Article article = getArticle(articleId); // getArticle에서 소유권 검증됨
        articleRepository.delete(article);
    }
}
```

추가 권장: 자원 식별자(id)로 추측 가능한 정수 대신 **UUID**를 사용하면 무작위 추측을 어렵게 해 보안성을 높일 수 있습니다.

---

## 유형 3 — 상황 의존적 권한 누락 (Context-Dependent Access Control Failure)

**문제**
사용자 역할은 맞지만 객체 상태와 비즈니스 규칙에 따라 접근을 제한해야 하는데, 상태 검사를 하지 않아 규칙을 우회하는 경우입니다. (예: 하루에 한 번만 출석 체크 가능한데 여러 번 체크되는 상황)

### 기본 해결책 — 서비스에서 상태 확인

서비스 메서드 내 `if`로 상태를 확인합니다.

```java
public void checkIn(Long userId) {
    boolean alreadyCheckedIn = attendanceRepository.existsByUserIdAndDate(userId, LocalDate.now());
    if (alreadyCheckedIn) {
        throw new IllegalStateException("오늘은 이미 출석체크를 완료했습니다.");
    }
    attendanceRepository.save(new Attendance(userId));
    userService.addExperience(userId, 10);
}
```

> 단점: 비즈니스 로직과 인가/검사 로직이 혼재되고, 규칙 변경 시 여러 곳을 수정해야 할 수 있음.

### 권장(더 견고한) 해결책 — SpEL + `@PreAuthorize`로 규칙 중앙화

`Spring Expression Language(SpEL)`과 `@PreAuthorize`를 사용해 권한 규칙을 별도 Bean으로 분리하면 정책 변경에 유연하게 대응할 수 있습니다.

```java
@Service("attendanceSecurity")
public class AttendanceSecurityService {

    @Autowired private AttendanceRepository attendanceRepository;
    @Autowired private UserRepository userRepository;

    public boolean canCheckIn(String username) {
        User user = userRepository.findByUsername(username).orElseThrow();
        return !attendanceRepository.existsByUserIdAndDate(user.getId(), LocalDate.now());
    }
}
```

```java
@Service
public class AttendanceService {

    @PreAuthorize("@attendanceSecurity.canCheckIn(principal.username)")
    public void checkIn() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByUsername(username).orElseThrow();

        attendanceRepository.save(new Attendance(user.getId()));
        userService.addExperience(user.getId(), 10);
    }
}
```

> 장점: 규칙을 한 곳에 모아 유지보수성 향상. 비즈니스 로직은 순수하게 기능만 담당.

---

## 유형 4 — 메타데이터 조작 (Metadata Manipulation)

**문제**
클라이언트가 요청 본문에 `role: "ADMIN"` 같은 민감 필드를 끼워 넣어 권한을 탈취하는 경우입니다.

### 기본 해결책 — 서비스에서 민감 필드 무시

요청 데이터를 엔티티에 바로 반영하지 않고 민감 필드를 수동으로 무시합니다. 그러나 신규 민감 필드가 추가되면 이를 일일이 처리해야 하므로 누락 위험이 큽니다.

### 권장(더 견고한) 해결책 — DTO 분리 (Secure by Design)

Request DTO와 Entity를 명확히 분리하고, **클라이언트가 보낼 수 있는 필드만 DTO에 포함**시킵니다. 서비스는 DTO에 정의된 필드만 엔티티에 반영합니다. 이렇게 하면 클라이언트가 어떤 필드를 추가로 보내더라도 서버가 무시합니다.

```java
// 요청 DTO (민감 필드 없음)
public class UserProfileUpdateRequestDto {
    private String nickname;
    private String email;
    // getter, setter
}

// User 엔티티 (민감 필드 포함)
@Entity
public class User {
    @Id private Long id;
    private String username;
    private String nickname;
    private String email;
    private String role; // 민감 필드
    // ...
}
```

```java
@Service
public class UserService {

    public void updateUserProfile(String username, UserProfileUpdateRequestDto requestDto) {
        User user = userRepository.findByUsername(username).orElseThrow();

        user.setNickname(requestDto.getNickname());
        user.setEmail(requestDto.getEmail());

        userRepository.save(user);
    }
}
```

> 핵심: **입력 가능한 필드를 명시적으로 제한**하면 메타데이터 조작 공격을 원천 차단할 수 있음.

---

## 정리 및 권장 원칙

### 한눈에 보는 대응 전략

| 취약점 유형           |         기본적인 해결책 | 권장(더 견고한) 해결책                          | 핵심 원칙                        |
| ---------------- | ---------------: | -------------------------------------- | ---------------------------- |
| 수직적 권한 상승        |     URL 패턴 기반 제어 | `@Secured`, `@PreAuthorize` 등 메서드 시큐리티 | 다층 방어 (Defense in Depth)     |
| 수평적 권한 상승 (IDOR) | 서비스 `if`로 소유권 검사 | `@PostAuthorize`, UUID 사용              | 인가 로직 분리(리소스 소유권 확인)         |
| 상황 의존적 권한 누락     |  서비스 `if`로 상태 검사 | `@PreAuthorize` + SpEL 규칙 중앙화          | 비즈니스 규칙 중앙화                  |
| 메타데이터 조작         |      민감 필드 수동 무시 | Request/Response DTO 분리                | Secure by Design (명시적 입력 필드) |

### 권장 체크리스트

* URL 기반 접근 제어와 메서드 레벨 보안을 **중복 적용**했는가?
* 리소스별 **소유권 검증**이 서비스 레이어 또는 AOP에서 일관되게 수행되는가?
* 예측 가능한 수치형 ID 대신 **UUID**를 사용할 수 있는가?
* 클라이언트 입력은 **DTO로 명확히 제한**하고, 엔티티에 직접 바인딩하지 않는가?
* 복잡한 비즈니스 규칙은 **별도 보안 Bean**으로 분리하여 `@PreAuthorize`/SpEL로 호출하는가?
* 민감 필드(권한, 포인트, 상태 등)가 API 요청으로 수정될 가능성을 **전혀 허용하지 않는가**?

---

## 참고 자료

* OWASP Top 10 2021 — https://owasp.org/Top10/
* Spring Security 공식 문서 — https://spring.io/projects/spring-security

---

### 마무리

Broken Access Control은 흔히 발생하지만 예방하기 쉬운 취약점이 아닙니다. 애초에 **설계 단계에서 '누가 어떤 리소스에, 어떤 상황에서 접근 가능한가'** 를 명확히 정의하고, URL 규칙과 서비스 레이어의 권한 검사를 중복 적용하며, 입력을 명시적으로 제한하는 설계 습관이 중요합니다.
이 글의 패턴(다층 방어, 인가 로직 분리, Secure by Design)을 프로젝트에 적용하면 접근 제어 실수를 크게 줄일 수 있습니다.
