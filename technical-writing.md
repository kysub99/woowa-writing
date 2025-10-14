# Broken Access Control

## 들어가며

'봄봄'은 복잡한 메일함을 뒤적이지 않아도 오늘 도착한 뉴스레터만 깔끔하게 모아 볼 수 있는 나만의 뉴스레터 전용 서비스입니다. 그런데 만약 간단한 URL 조작만으로 다른 사람의 글이나 정보를 볼 수 있다면 어떻게 될까요? 이는 단순한 버그를 넘어, 사용자의 민감한 개인정보 유출과 뉴스레터 콘텐츠의 저작권 문제로까지 이어질 수 있는 심각한 보안 사고입니다. 이러한 사고의 중심에는 바로 **Broken Access Control** 취약점이 있습니다.

글로벌 웹 보안 프로젝트인 OWASP(The Open Web Application Security Project)는 매년 가장 위험한 웹 애플리케이션 보안 취약점 10가지를 선정하여 발표합니다. **Broken Access Control** 은 2017년부터 2021년까지 부동의 1위를 차지했습니다. 이는 기능 구현에만 집중하다 보면 개발자가 가장 쉽게 놓치는, 하지만 가장 치명적인 취약점이라는 의미이기도 합니다.

이 글에서는 Broken Access Control이 무엇인지, 어떤 유형이 있는지 알아보고, Spring Security가 제공하는 강력한 기능들을 활용하여 각 취약점을 어떻게 효과적으로 방어할 수 있는지 구체적인 코드와 함께 살펴보겠습니다.

## 1. Broken Access Control 이란?

**Broken Access Control**은 인증된 사용자가 허용되지 않은 기능이나 데이터에 접근할 수 있는 취약점을 말합니다. 즉, "당신이 누구인지는 확인했지만(인증), 당신이 이 일을 할 자격이 있는지(인가)는 제대로 확인하지 않았다"는 뜻입니다.

**인증(Authentication)**: 사용자가 누구인지 신원을 확인하는 과정입니다. 아이디와 비밀번호로 로그인하는 것이 대표적입니다.

**인가(Authorization)**: 인증된 사용자가 특정 리소스나 기능에 접근할 수 있는 권한이 있는지 확인하는 과정입니다. '관리자만 뉴스레터 추가 가능'과 같은 규칙이 여기에 해당합니다.

Broken Access Control은 바로 이 인가 과정이 누락되거나 잘못 구현되었을 때 발생합니다. 이 취약점은 크게 4가지 유형으로 나눌 수 있으며, 지금부터 각 유형의 문제점과 Spring Security를 이용한 해결책을 살펴보겠습니다.

- **수직적 권한 상승**: 일반 사용자가 관리자 기능을 사용하는 경우
- **수평적 권한 상승 (IDOR)**: A 사용자가 B 사용자의 정보에 접근하는 경우
- **상황 의존적 권한 누락**: 특정 조건에서만 허용되어야 하는 기능에 아무 때나 접근하는 경우
- **메타데이터 조작**: API 요청 데이터를 조작하여 권한을 탈취하는 경우

## 2. 유형별 해결책: 수직적 권한 상승

> "일반 사용자가 관리자 페이지에서 새로운 뉴스레터를 추가할 수 있다면?"

**수직적 권한 상승(Vertical Privilege Escalation)** 은 가장 직관적이면서도 치명적인 접근 제어 실패 사례입니다. 역할이 다른 사용자 간의 권한 경계가 무너진 상태로, 일반 사용자(USER)가 관리자(ADMIN)만 접근해야 하는 기능(ex: 신규 뉴스레터 등록)에 접근하는 경우를 말합니다.

**그림1:수직적권한상승시나리오**
일반 사용자 'user1'이 브라우저 주소창에 `/admin/newsletters` URL을 직접 입력합니다. 서버는 권한 검사를 제대로 수행하지 않고, 관리자에게만 보여야 할 뉴스레터 관리 페이지를 'user1'에게 그대로 노출합니다.

### 기본적인 해결책: URL 패턴으로 막기

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                // 1. /admin/으로 시작하는 모든 요청은 "ADMIN" 역할을 가진 사용자만 접근 가능
                .requestMatchers("/admin/**").hasRole("ADMIN")
                // 2. /my-page/로 시작하는 모든 요청은 "USER" 또는 "ADMIN" 역할이 필요
                .requestMatchers("/my-page/**").hasAnyRole("USER", "ADMIN")
                // 3. 위에서 지정하지 않은 나머지 모든 요청은 누구나 접근 가능
                .anyRequest().permitAll()
            );
        return http.build();
    }
}
```

이 방식은 특정 URL 그룹에 대한 접근 규칙을 중앙에서 관리할 수 있어 편리합니다. 하지만 개발자가 새로운 관리자 API를 추가하고 SecurityConfig 수정을 잊는다면, 해당 API는 `anyRequest().permitAll()` 규칙에 따라 아무런 보호도 받지 못하는 상태로 노출될 수 있습니다.

### 더 견고한 해결책: 비즈니스 로직에 직접 보안 적용 (메서드 시큐리티)

더욱 견고한 방어를 위해서는 **다층 방어(Defense in Depth)** 개념을 적용해야 합니다. URL로 1차 방어를 하고, 실제 비즈니스 로직이 담긴 서비스 메서드 레벨에서 2차 방어를 하는 것입니다. 이를 **메서드 시큐리티(Method Security)** 라고 합니다.

먼저, `@EnableMethodSecurity` 어노테이션으로 메서드 시큐리티를 활성화합니다.

```java
@Configuration
// securedEnabled=true: @Secured("ROLE_ADMIN") 어노테이션을 사용할 수 있게 함
// prePostEnabled=true: @PreAuthorize, @PostAuthorize 어노테이션을 사용할 수 있게 함
@EnableMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {
    // ...
}
```

이제 관리자 전용 기능이 있는 서비스 메서드에 직접 보안 어노테이션을 적용합니다.

```java
@Service
public class NewsletterAdminService {

    // 이 메서드는 "ROLE_ADMIN" 역할을 가진 사용자만 호출할 수 있음
    // 만약 다른 권한을 가진 사용자가 호출하면 AccessDeniedException 발생
    @Secured("ROLE_ADMIN")
    public void addNewsletter(NewsletterCreateDto createDto) {
        // 신규 뉴스레터 추가 로직
        newsletterRepository.save(createDto.toEntity());
    }
}
```

이제 SecurityConfig에서 실수로 URL 패턴을 누락하더라도, `addNewsletter()` 메서드 자체가 `ROLE_ADMIN` 권한으로 보호됩니다. 보안 규칙이 실제 코드와 함께 위치하므로 의도가 명확해지고, 개발자의 실수를 방지하여 더욱 안전한 코드를 작성할 수 있습니다.

## 3. 유형별 해결책: 수평적 권한 상승 (IDOR)

> "로그인한 내가 URL의 숫자만 바꿔서 다른 사람의 글을 볼 수 있다면?"

**수평적 권한 상승(Horizontal Privilege Escalation)** 은 동일한 권한 수준을 가진 사용자들 사이에서 발생하는 문제입니다. 사용자 A가 자신의 권한을 벗어나 사용자 B의 데이터에 접근하거나 수정하는 상황을 말하며, **IDOR(Insecure Direct Object Reference, 안전하지 않은 직접 객체 참조)** 취약점이라고도 부릅니다.

**그림2:IDOR(수평적권한상승)시나리오**
사용자 'user-A'가 자신의 글 상세 정보 페이지 URL (`/articles/101`)에 접속합니다. 이후 주소창의 숫자 101을 다른 사용자의 글 ID인 102로 바꾸어 요청하자, 서버가 소유권 검사 없이 사용자 'user-B'의 글 내용을 보여주는 상황.

### 기본적인 해결책: 서비스 로직에서 소유권 직접 확인

가장 직관적인 방법은 서비스 메서드 내에서 해당 리소스의 소유자와 현재 로그인한 사용자가 일치하는지 if문으로 직접 확인하는 것입니다.

```java
@Service
public class ArticleService {

    public Article getArticle(Long articleId) {
        // 현재 로그인한 사용자 정보 가져오기
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUsername = authentication.getName();

        Article article = articleRepository.findById(articleId)
                .orElseThrow(() -> new ArticleNotFoundException());

        // 소유권 확인 로직
        if (!article.getUsername().equals(currentUsername)) {
            throw new AccessDeniedException("이 글을 조회할 권한이 없습니다.");
        }

        return article;
    }
}
```

이 방법은 간단하지만, 인가 로직(권한 검사)과 비즈니스 로직(글 조회)이 섞여 코드가 복잡해지고, 유사한 확인 로직이 여러 서비스 메서드에 중복되어 나타날 수 있습니다.

### 더 견고한 해결책: @PostAuthorize로 인가 로직 분리

Spring Security는 메서드 실행 후에 반환되는 객체를 검사하여 인가를 결정하는 `@PostAuthorize` 어노테이션을 제공합니다. 이를 통해 인가 로직을 비즈니스 로직과 깔끔하게 분리할 수 있습니다.

```java
@Service
public class ArticleService {

    // 메서드가 성공적으로 실행된 후(Article 객체를 반환한 후),
    // 1. returnObject: 반환된 Article 객체를 의미
    // 2. principal: 현재 인증된 사용자의 정보를 담고 있는 객체 (UserDetails)
    // 3. 반환된 Article의 소유자(username)와 로그인한 사용자의 이름(principal.username)이 같은지 검사
    @PostAuthorize("returnObject.username == principal.username")
    public Article getArticle(Long articleId) {
        return articleRepository.findById(articleId)
                .orElseThrow(() -> new ArticleNotFoundException());
    }

    public void deleteArticle(Long articleId) {
        // 이제 이 메서드는 소유권 검사를 직접 할 필요가 없음
        // getArticle 메서드가 소유권이 확인된 객체만 반환하기 때문
        Article article = getArticle(articleId);
        articleRepository.delete(article);
    }
}
```

이제 `getArticle` 메서드는 글 정보를 조회한 뒤, Spring Security가 알아서 소유권 검사를 수행합니다. 만약 다른 사람의 글을 조회하려 했다면 `AccessDeniedException`이 발생합니다. 비즈니스 로직은 순수하게 자신의 역할에만 집중할 수 있어 코드의 가독성과 유지보수성이 크게 향상됩니다.

## 4. 유형별 해결책: 상황 의존적 권한 누락

> "이미 오늘 출석체크를 해서 경험치를 받았는데, 계속해서 출석체크가 가능하다면?"

**상황 의존적 권한 누락(Context-Dependent Access Control Failure)** 은 사용자의 역할(Role)은 맞지만, 특정 객체의 상태(State)나 비즈니스 규칙(Rule)에 따라 접근이 제한되어야 하는 경우에 발생하는 취약점입니다. 예를 들어, 사용자는 하루에 한 번만 '출석 체크'를 통해 경험치를 얻을 수 있어야 하는데, 이 상태를 확인하지 않아 중복으로 요청이 가능한 경우입니다.

### 기본적인 해결책: if문으로 객체 상태 확인

서비스 메서드 내에서 if문으로 사용자의 마지막 출석 기록을 직접 확인하는 방식으로 해결할 수 있습니다.

```java
public void checkIn(Long userId) {
    // 오늘 날짜에 해당 유저의 출석 기록이 있는지 확인
    boolean alreadyCheckedIn = attendanceRepository.existsByUserIdAndDate(userId, LocalDate.now());

    // 출석 기록 확인 로직
    if (alreadyCheckedIn) {
        throw new IllegalStateException("오늘은 이미 출석체크를 완료했습니다.");
    }

    // 출석 처리 및 경험치 지급 로직
    attendanceRepository.save(new Attendance(userId));
    userService.addExperience(userId, 10);
}
```

이 방식 또한 비즈니스 로직(출석 처리, 경험치 지급)과 인가 로직(중복 출석 확인)이 혼재되고, 출석 가능 조건(예: 특정 이벤트 기간에는 하루 2회 가능)이 변경될 때마다 관련된 모든 코드를 찾아 수정해야 하는 불편함이 있습니다.

### 더 견고한 해결책: SpEL을 활용한 비즈니스 규칙 중앙화

**Spring Expression Language(SpEL)**와 `@PreAuthorize`를 함께 사용하면, 복잡한 비즈니스 규칙 기반의 인가 로직을 별도의 메서드로 분리하고 중앙에서 관리할 수 있습니다.

먼저, 인가 규칙을 검사하는 로직을 별도의 Bean으로 분리합니다.

```java
@Service("attendanceSecurity") // SpEL에서 '@attendanceSecurity' 형태로 참조할 수 있도록 Bean 이름 지정
public class AttendanceSecurityService {

    @Autowired private AttendanceRepository attendanceRepository;
    @Autowired private UserRepository userRepository;

    public boolean canCheckIn(String username) {
        User user = userRepository.findByUsername(username).orElseThrow();
        // 오늘 날짜에 해당 유저의 출석 기록이 없는 경우에만 true 반환
        return !attendanceRepository.existsByUserIdAndDate(user.getId(), LocalDate.now());
    }
}
```

이제 실제 비즈니스 로직에서는 `@PreAuthorize`를 통해 이 메서드를 호출하기만 하면 됩니다.

```java
@Service
public class AttendanceService {

    // 메서드 실행 전에 권한을 검사
    // 1. @attendanceSecurity: 위에서 정의한 attendanceSecurity Bean을 의미
    // 2. .canCheckIn(...): 해당 Bean의 canCheckIn 메서드를 호출
    // 3. principal.username: 현재 로그인한 사용자의 이름을 인자로 전달
    @PreAuthorize("@attendanceSecurity.canCheckIn(principal.username)")
    public void checkIn() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();
        User user = userRepository.findByUsername(username).orElseThrow();

        // 순수한 비즈니스 로직만 남음
        attendanceRepository.save(new Attendance(user.getId()));
        userService.addExperience(user.getId(), 10);
    }
}
```

이제 '출석 가능 조건'이 바뀌더라도 `AttendanceSecurityService`의 `canCheckIn` 메서드만 수정하면 되므로, 정책 변경에 매우 유연하게 대처할 수 있습니다.

## 5. 유형별 해결책: 메타데이터 조작

> "회원정보 수정 API에 role: 'ADMIN' 파라미터를 추가해서 보낸다면?"

**메타데이터 조작(Metadata Manipulation)** 은 사용자가 직접 수정해서는 안 되는 데이터(권한, 포인트, 상태 등)를 API 요청에 포함시켜 시스템을 속이는 취약점입니다. 뉴스레터 서비스의 일반 사용자가 자신의 프로필을 수정하면서 스스로를 관리자로 승격시키는 경우가 해당됩니다.

**그림3:메타데이터조작시나리오**
사용자가 자신의 닉네임을 변경하는 API를 호출합니다. 정상적인 요청 본문은 `{"nickname": "new-nick"}` 이어야 하지만, 악의적인 사용자는 여기에 `,"role": "ADMIN"` 필드를 몰래 추가하여 전송합니다. 서버는 이 값을 필터링 없이 그대로 User 객체에 반영하여 데이터베이스에 저장하고, 사용자는 스스로 관리자 권한을 획득합니다.

### 기본적인 해결책: 서비스 로직에서 민감 필드 무시

엔티티를 업데이트하기 전에 서비스 로직에서 민감한 필드들을 수동으로 null 처리하거나 무시하는 방법이 있습니다. 하지만 이 방법은 개발자가 새로운 민감 필드가 추가될 때마다 코드를 수정해야 하고, 누락할 가능성이 매우 높습니다.

### 더 견고한 해결책: DTO 분리로 설계 단계부터 차단

가장 효과적이고 안전한 방법은 **요청(Request) DTO와 응답(Response) DTO를 명확하게 분리**하는 것입니다. 이는 **Secure by Design** 원칙을 구현하는 좋은 예시입니다.

- **Request DTO**: 클라이언트로부터 입력을 받을 때 사용하는 객체. 사용자가 수정할 수 있는 필드만 명시적으로 포함합니다.
- **Entity**: 데이터베이스와 직접 매핑되는 핵심 도메인 객체. role과 같은 민감 정보를 포함합니다.

```java
// 사용자가 수정을 "요청"할 때 사용하는 DTO (민감한 role 필드가 아예 없음)
public class UserProfileUpdateRequestDto {
    private String nickname;
    private String email;
    // getter, setter
}

// 데이터베이스와 매핑되는 User 엔티티 (민감 정보 포함)
@Entity
public class User {
    @Id private Long id;
    private String username;
    private String nickname;
    private String email;
    private String role; // 사용자가 직접 수정해서는 안 되는 민감 필드
    // ...
}
```

서비스 로직에서는 Request DTO를 받아 엔티티의 특정 필드만 선택적으로 업데이트합니다.

```java
@Service
public class UserService {

    public void updateUserProfile(String username, UserProfileUpdateRequestDto requestDto) {
        User user = userRepository.findByUsername(username).orElseThrow();

        // DTO에 명시적으로 정의된 필드만 엔티티에 반영
        user.setNickname(requestDto.getNickname());
        user.setEmail(requestDto.getEmail());

        // 사용자가 요청에 'role' 필드를 포함시켜도, DTO에 해당 필드가 없으므로
        // 무시되며, 엔티티의 role 값은 변경되지 않음
        userRepository.save(user);
    }
}
```

이처럼 DTO를 분리하면, 사용자가 어떤 데이터를 요청에 포함시키든 서버는 애초에 정의된 필드만 인식하므로 메타데이터 조작 공격을 원천적으로 차단할 수 있습니다.

## 6. 결론: 설계부터 안전하게

지금까지 Broken Access Control의 다양한 유형과 Spring Security를 활용한 해결책을 살펴보았습니다. 안전한 애플리케이션은 단순히 몇 가지 보안 기능을 추가하는 것만으로 완성되지 않습니다. 개발 초기 설계 단계부터 보안을 고려하는 문화가 중요합니다.

| 취약점 유형 | 기본적인 해결책 | 더 견고한 해결책 | 핵심 원칙 |
|---|---|---|---|
| 수직적 권한 상승 | URL 패턴 기반 제어 | @Secured, @PreAuthorize("hasRole(...)") | 다층 방어 |
| 수평적 권한 상승(IDOR) | 서비스 내 if문 소유권 검사 | @PostAuthorize, UUID 사용 | 인가 로직 분리 |
| 상황 의존적 권한 누락 | 서비스 내 if문 상태 검사 | @PreAuthorize + SpEL | 비즈니스 규칙 중앙화 |
| 메타데이터 조작 | 서비스 내 민감 필드 무시 | Request/Response DTO 분리 | Secure by Design |

---

### 참고 자료

- OWASP Top 10 2011: https://owasp.org/Top10/
- Spring Security 공식 문서: https://spring.io/projects/spring-security
