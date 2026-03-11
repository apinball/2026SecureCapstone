## 🚀 시작하기 (Getting Started)

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

## 🗺️ 프로젝트 로드맵 (Project Roadmap)

- [x] Phase 1: 3-Tier 기반 도커 베이스라인 구축 및 네트워크 연동
- [ ] Phase 2: OQS-OpenSSL(Post-Quantum) 엔진 빌드 및 Nginx 탑재
- [ ] Phase 3: 양자 내성 암호 기반 인증서 발급 및 하이브리드 TLS 설정
- [ ] Phase 4: GitHub Actions 기반 자동 보안 검증 파이프라인 연동
- [ ] Phase 5: 성능 비교 분석 (전통적 암호 vs PQC) 및 최종 결과 도출

---

## 📂 폴더 구조 (Directory Structure)

```
2026capstone/
 ┣ 📂 nginx/                    # Nginx 및 OQS 빌드 환경
 ┣ 📂 backend/                  # FastAPI 기반 웹 서버 로직
 ┣ 📂 tester/                   # 검증용 툴 및 패킷 캡처 저장소
 ┣ 📜 docker-compose.yml        # 개발용 설정 (Volume 연동)
 ┣ 📜 docker-compose.prod.yml   # 배포용 설정 (Clean Build)
 ┗ 📜 README.md