## 시작하기 (Getting Started)

### 1. 환경 구축 (Development Mode)
실시간 코드 수정이 반영되는 개발 모드로 컨테이너를 실행합니다.
```bash
docker-compose up -d --build
```

### 2. 패킷 캡처 및 분석
테스트 컨테이너 내에서 통신을 감시하고 로컬 폴더(`tester/captures`)로 추출합니다.

```bash
# 1. 컨테이너 접속 및 캡처 시작
docker exec -it tls-tester /bin/bash
tshark -i eth0 -w /data/capture_test.pcap

# 2. (별도 터미널에서 트래픽 발생)
docker exec -it tls-tester curl http://proxy-server

# 3. 저장된 파일은 로컬의 ./tester/captures/ 폴더에서 Wireshark로 확인
```

---

## 프로젝트 로드맵 (Project Roadmap)

- [x] Phase 1: 3-Tier 기반 도커 베이스라인 구축 및 네트워크 연동
- [ ] Phase 2: OQS-OpenSSL(Post-Quantum) 엔진 빌드 및 Nginx 탑재
- [ ] Phase 3: 양자 내성 암호 기반 인증서 발급 및 하이브리드 TLS 설정
- [ ] Phase 4: GitHub Actions 기반 자동 보안 검증 파이프라인 연동
- [ ] Phase 5: 성능 비교 분석 (전통적 암호 vs PQC) 및 최종 결과 도출

---

## 폴더 구조 (Directory Structure)

```
2026capstone/
 ┣ 📂 nginx/                    # Nginx 및 OQS 빌드 환경
 ┣ 📂 backend/                  # FastAPI 기반 웹 서버 로직
 ┣ 📂 tester/                   # 검증용 툴 및 패킷 캡처 저장소
 ┣ 📜 docker-compose.yml        # 개발용 설정 (Volume 연동)
 ┣ 📜 docker-compose.prod.yml   # 배포용 설정 (Clean Build)
 ┗ 📜 README.md
```

 ---

# 프로젝트 협업 규칙 (Contribution Guide)

이 프로젝트의 일관성을 유지하고 효율적인 협업을 위해 아래 규칙을 준수해 주세요.

---

## 1. 커밋 메시지 규칙 (Commit Convention)

커밋 메시지는 **`Type: Subject`** 형식을 사용하며, 첫 글자는 대문자로 시작합니다.

### 커밋 타입 (Type)
| 타입 | 설명 |
| :--- | :--- |
| `Feat` | 새로운 기능 추가 |
| `Fix` | 버그 수정 |
| `Docs` | 문서 수정 (README, Wiki 등) |
| `Style` | 코드 의미에 영향을 주지 않는 수정 (세미콜론 누락, 포맷팅 등) |
| `Refactor` | 코드 리팩토링 |
| `Chore` | 빌드 업무, 패키지 매니저 설정, 프로젝트 설정 변경 |

### 예시 (Example)
* `Feat: 구글 소셜 로그인 기능 구현`
* `Fix: 메인 페이지 이미지 로딩 에러 수정`
* `Docs: 설치 방법 안내 섹션 추가`

---

## 2. 브랜치 전략 (Branching Strategy)

기본적으로 **GitHub Flow** 전략을 따릅니다.

* **`main`**: 배포 가능한 상태의 안정된 코드만 관리합니다.
* **`develop`**: 다음 출시를 위한 개발을 진행하는 브랜치입니다.
* **`feature/기능명`**: 새로운 기능을 개발할 때 사용합니다.
    * 예: `feature/login`, `feature/chart-ui`
* **`hotfix/이슈명`**: 배포 후 긴급 수정이 필요할 때 사용합니다.
* **`docs/기능명`**: 문서 수정이 필요할 때 사용합니다.

기능 브랜치 -> develop -> main

---

## 3. Pull Request 규칙

모든 코드는 PR을 통한 코드 리뷰 후 `main`에 병합(Merge)됩니다.

1. **Self-Review**: PR을 올리기 전 본인의 코드를 다시 한번 확인합니다.
2. **Reviewers**: 최소 1명 이상의 팀원을 리뷰어로 지정합니다.
3. **Template**: 아래 내용을 포함하여 작성합니다.
    * 작업 내용 (Summary)
    * 주의 사항 및 참고 자료 (Optional)

---

