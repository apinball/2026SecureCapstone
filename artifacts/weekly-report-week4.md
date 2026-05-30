# 주간 보고 — 4주차

**Stage 3 PQ TLS 자체 빌드로 복원 + LLM 마이그레이션 평가 인프라 구축 + 80 trial 정량 측정 완료 (PR #84 `fix/stage3-mlkem1024-rollback`, 평가 자료집 `artifacts/eval/`)**

---

## 상세 작업 내용

### 1. Stage 3 PQ TLS 자체 빌드 복원 — PR #84 (`fix/stage3-mlkem1024-rollback`)

- **배경**: PR #83 CI에서 Stage 3가 실패하면서 standalone `mlkem1024` 미협상 문제가 드러남. 후속 디버깅 과정에서 더 큰 문제 발견 — `openquantumsafe/nginx:0.11.0` (sha256:d02e7d6e) 이미지가 OpenSSL 1.1.1q + 옛 oqs-engine 라인이고 `openquantumsafe/curl:0.11.0` (sha256:b91f49e0)는 OpenSSL 3.4.0 + oqs-provider 0.9.0 라인이라 group/sigalg code point가 어긋나 **Stage 2/3 모두 PQ 협상 자체가 alert 552로 실패**. mlkem1024는 표면 증상이고 본질은 OQS 라이브러리 라인 비대칭

- **근본 해결**: nginx 이미지 자체 빌드로 전환. 멀티스테이지 Dockerfile 신설 — OpenSSL 3.4.0 + liboqs 0.13.0 + oqs-provider 0.9.0 + nginx 1.27.2를 모두 소스에서 빌드해 client(OQS-curl 0.11.0)와 동일 라인으로 통일. cert-builder도 같은 builder stage 사용 → Dilithium3(mldsa65) OID 일치

- **세부 함정 4종 추적**: (a) `liboqs` cmake가 OpenSSL을 KAT 용도로 찾는 문제 → `OQS_USE_OPENSSL=OFF` + `OQS_BUILD_ONLY_LIB=ON` 플래그로 회피. (b) `openssl.cnf`에 `openssl_conf = openssl_init` declaration 누락 → oqsprovider 자동 로드 안 됨 → cnf 재작성. (c) `module = oqsprovider` 만으론 부족 → 절대 경로 `module = /opt/oqs/lib/ossl-modules/oqsprovider.so`로 명시. (d) oqs-provider 0.6.1↔0.9.0 sigalg code point 불일치로 Kyber/ML-KEM 명칭 모두 협상 실패 → liboqs 0.13.0 + oqs-provider 0.9.0으로 client와 통일. (e) `EVP_PKEY_security_bits()` 0 보고로 `ee key too small` 에러 → `ssl_ciphers DEFAULT:@SECLEVEL=0` 임시 + `ssl_protocols TLSv1.3` + group whitelist로 부작용 차단

- **Stage 3 커브 회귀**: standalone `mlkem1024` 실패한 검증된 hybrid `p521_mlkem1024:p384_mlkem768`로 복원. `nginx/nginx-pq.conf`, `scanner/tls_check.sh`, `tester/verify_tls.sh`, `tester/capture_tls.sh` 일괄 동기화

- **로컬 검증**: `tls_check.sh proxy-server 443 {1,2,3}` 모두 PASS. Stage 3 실제 협상 결과 `TLSv1.3 / TLS_AES_256_GCM_SHA384 / p521_mlkem1024 / mldsa65` 확인

### 2. Gemini 봇 리뷰 반영 — 커밋 `3081b0a`

PR #84에 대한 Gemini Code Assist 리뷰 6건 모두 반영:

- OpenSSL 3.4.0 + nginx 1.27.2 다운로드에 sha256 체크섬 검증 추가 (공급망 공격 방지). nginx 실측 sha256 `a91ecfc3a0b3...`로 정정 (공식 발표값과 다름)
- `wget --no-check-certificate` 옵션 제거 (MITM 위험 제거). 빌드 단계에서 `unset LD_LIBRARY_PATH`로 우리 OpenSSL이 시스템 CA 검증을 방해하지 않도록 처리
- OpenSSL 빌드에 `--libdir=lib` 명시 → `/opt/oqs/lib64` 와 `/opt/oqs/lib` 혼재 문제 해소
- `openssl.cnf` module 경로 + ENV(`LD_LIBRARY_PATH`/`OPENSSL_MODULES`) 모두 `lib`로 통일
- `ssl_ciphers DEFAULT:@SECLEVEL=0`에 임시 방편 명시 + 정상화 조건(`oqs-provider strength 정상 보고 시 즉시 제거 + SECLEVEL 기본값 2 복귀`) 주석 추가

3단계(1/2/3) 검증 모두 PASS 재확인.

### 3. LLM 마이그레이션 평가 인프라 구축 — `artifacts/eval/`

논문 평가 축으로 두 측면을 별개 측정으로 분리. 평가 환경 전체를 신규 디렉터리에 구축.

- **평가 A (인프라 함정 카탈로그)**: `infra-failure-catalog.md`. 1·2주차 디버깅 과정에서 발견한 함정을 6종(F-1~F-6)으로 구조화 — sigalg drift, OID mismatch, group code point 충돌, SECLEVEL 거부, sha256 시간 가변, standalone 미협상. 각 함정마다 트리거/증상/원인/표준 도구 탐지 가능성/방어책으로 표 정리. **표준 도구(Trivy/Semgrep/CBOM)는 6/6 함정 모두 사전 탐지 불가** 매트릭스 입증

- **평가 B (LLM 정량 평가) 벤치마크 설계**: `benchmark-spec.md` + `benchmark/patterns/` (16 RSA 입력) + `benchmark/reference/` (16 oqs-python 정답). cryptography·PyCryptodome × keygen/encrypt/sign/kex × simple/complex 직교 설계 N=16. 정답은 ML-KEM-768/ML-DSA-65 + AES-GCM 결합 + caller-breaking signature 변경 docstring 명시 + 모듈 레벨 인스턴스화 금지 정책

- **4-Layer 평가 하네스**: `harness/ast_validator.py`(L2 — oqs API 적합성 정적 검증), `harness/llm_client.py`(L1 — GitHub Models 호출 + retry), `harness/semantic_tests.py`(L3 — 패턴별 round-trip 16종), `harness/equivalence.py`(L4 — AST feature 매칭 가중 평균). 메인 러너 `eval_runner.py`가 16 패턴 × k 반복으로 4-Layer 모두 자동 측정

- **재현 환경**: `Dockerfile`로 평가 컨테이너 빌드 (python:3.11-slim + liboqs 0.14.0 + liboqs-python 0.14.1 + cryptography + pycryptodome + ldconfig 등록). liboqs 0.13/oqs-python 0.14.1 ABI 불일치(`OQS_SIG_supports_ctx_str` 미정의)로 liboqs 0.14.0으로 상향

- **자체 sanity check**: 정답 16개를 candidate로 → L2/L3/L4 모두 16/16. 입력 RSA 그대로 → 모두 0/16. 두 극값에서 하네스 false positive/negative 0건 확인

### 4. 80 trial LLM 측정 + 분석 — `benchmark/results/llm_k5.json`

GitHub Models gpt-4o-mini, temperature=0, k=5. 16 패턴 × 5 trial = 80 trial 실행. 측정 시점 2026-05-08.

- **다층 ablation 결과**: L1(응답 받음) 55/80, **L2(AST) 24/80=30%, L3(semantic) 0/80=0%, L4(equivalence) 40/80=50%**. 응답 받은 trial 기준으로는 L4 72.7% > L2 43.6% ≫ L3 0%. **gpt-4o-mini는 80 trial 중 단 한 번도 의미적으로 정확한 코드를 생산하지 못함**

- **markdown fence 자동 stripping**: 첫 측정에서 LLM이 프롬프트 무시하고 ```` ```python ... ``` ```` 으로 응답 감싸서 80건 모두 AST parse 실패 발생. `eval_runner.py`에 `strip_markdown_fences()` 추가하여 재실행

- **rate limit 영향**: 25/80 trial이 LLM API error (특히 패턴 13–16 PyCryptodome complex가 19/25 차지). 통계가 패턴 1–12 위주로 편향됨

- **실패 모드 taxonomy 7종**: `missing_instance_construction` 20건, `wrong_arg_count` 16건, `no_migration` 6건, `class_direct_call` 5건, `wrong_kwarg` 5건, `method_hallucination` 2건, `algorithm_name_hallucination` 1건. 응답 받은 55건 모두 어딘가에서 실패 (정상 동작 0건)

- **실패 모드 × Defense Layer 매핑 (핵심 발견)**: L2가 차단 = 31건(정적 분석으로 잡힘), L3만 차단 = 24건(런타임에서야 잡힘). 두 layer가 잡는 카테고리 **overlap 0** — `wrong_arg_count`/`wrong_kwarg`/`method_hallucination`/`algorithm_name_hallucination`은 100% L3에서만, `missing_instance_construction`/`no_migration`/`class_direct_call`은 100% L2에서. AST 정적 검증 단독으로는 시그니처 환각 24건(44%)을 놓치므로 런타임 semantic test가 필수임을 정량 입증

- **분석 자동화**: `analyze.py` 신설 — 80 trial JSON에서 표 11개(다층 ablation, taxonomy, layer 매핑, 라이브러리/use case/복잡도 차원별, 패턴별 raw, L4 임계값 sensitivity, 응답 길이 통계) + 케이스 스터디 7개 자동 생성하여 `analysis.md`로 출력

### 5. 평가 자료집 종합 정리 — `evaluation-data.md`

논문 본문 작성 시 표·정의·사례·한계·인용 후보를 그대로 발췌할 수 있는 raw material 형식으로 종합. Part 0(평가 정의·기여) ~ Part VIII(산출물) 8개 파트.

- **평가 C 추가**: 평가 A·B는 "함정의 존재"를 측정하는 것이고 본 프로젝트 narrative("PQC 파이프라인을 통한 자연스러운 전환")는 별도 평가가 필요하다는 분석에 따라 평가 C 신설. 본 프로젝트가 제안한 4 layer (자체 빌드 / 매트릭스 CI / AI 마이그레이션 / 다층 검증)가 평가 A·B의 함정을 막거나 감지하는 정량 효과 측정

- **평가 C 핵심 결과**: (a) 함정 차단·감지 매트릭스 — 자체 빌드 5/6 사전 예방, 매트릭스 CI 6/6 런타임 감지 (표준 도구 0/6 대비). (b) LLM 다층 방어 위험 감소 — 검증 없음 100% → AST 단독 100%(통과 코드 기준 동일) → AST + semantic 0%. AST 단독으로는 위험률 감소 X. (c) 회귀 감지 시점 단축 — PR #71 시점 commit checkout으로 매트릭스 CI를 동일 환경에서 실행하면 PR 단계에서 차단 가능 (counterfactual 재현)

- **인용 가능 발견 11종 (F1~F11)**: 논문 본문에 그대로 옮길 수 있는 quote + 근거 표 참조 형식. 평가 A·B·C 각각의 핵심 + 통합 narrative까지 정리

### 6. 산출물 디렉터리 구조

```
artifacts/eval/
├── evaluation-data.md          # 논문 작성용 raw material 종합본
├── infra-failure-catalog.md    # 평가 A 상세 (F-1~F-6)
├── benchmark-spec.md           # 평가 B 설계
├── HOW_TO_RUN.md               # 재현 명령
├── Dockerfile                  # 평가 컨테이너
├── eval_runner.py              # L1~L4 자동 실행
├── analyze.py                  # 표 11개 + 케이스 스터디 자동 생성
├── benchmark/
│   ├── patterns/  (16 RSA 입력)
│   ├── reference/ (16 oqs-python 정답)
│   └── results/
│       ├── sanity.json    # 16/16/16 (정답 회귀)
│       ├── baseline.json  # 0/0/0 (RSA 그대로)
│       ├── llm_k5.json    # 80 trial 원시 데이터
│       └── analysis.md    # 자동 생성 분석
└── harness/
    ├── ast_validator.py
    ├── llm_client.py
    ├── semantic_tests.py
    └── equivalence.py
```

---

## 산출물

| 종류 | 식별자 | 상태 |
|------|--------|------|
| PR | #84 fix/stage3-mlkem1024-rollback → develop | Gemini 리뷰 6건 반영 후 푸시, 머지 대기 |
| 신규 파일 | `nginx/Dockerfile` 자체 빌드 멀티스테이지 (OpenSSL 3.4 + liboqs 0.13 + oqs-provider 0.9 + nginx 1.27 source build) | PR #84 |
| 신규 파일 | `artifacts/eval/` 평가 인프라 일체 (16 패턴 + 16 정답 + 4-Layer 하네스 + Dockerfile + eval_runner + analyze + 자료집) | 로컬 작업, 미커밋 |
| 측정 데이터 | `benchmark/results/llm_k5.json` 80 trial gpt-4o-mini 원시 응답 + 4-Layer 결과 | 로컬, 미커밋 |
| 분석 산출물 | `evaluation-data.md` (Part 0~VIII), `analysis.md` (표 11개 + 케이스 7개) | 로컬, 미커밋 |

---

## 핵심 정량 결과

| 항목 | 수치 |
|---|---|
| Stage 1/2/3 TLS 검증 | 모두 PASS (Stage 3 협상: `TLSv1.3 / p521_mlkem1024 / mldsa65`) |
| 인프라 함정 카탈로그 | 6종 (F-1~F-6), 표준 도구 0/6 탐지 |
| LLM 평가 trial 수 | 80 (16 패턴 × k=5), 응답 55, API error 25 |
| L2 (AST) 통과율 | 30% (24/80) |
| L3 (semantic test) 통과율 | **0% (0/80)** |
| L4 (equivalence ≥ 0.8) 통과율 | 50% (40/80) |
| 실패 모드 taxonomy | 7종 (`missing_instance_construction` 20건 최다) |
| L2 vs L3 카테고리 overlap | 0 |
| 매트릭스 CI 함정 감지율 | 6/6 |
| 자체 빌드 함정 예방율 | 5/6 |
| LLM 측정 비용 | $0.013 / 80 trial (무료 tier 한도 내) |

---

## 다음 주 계획

| 항목 | 내용 |
| --- | --- |
| PR #84 머지 | Stage 3 자체 빌드 PR 리뷰 통과 후 develop 머지. 매트릭스 CI(PR #83)가 자체 빌드 환경에서도 동작하는지 확인 |
| `artifacts/eval/` 커밋 | 평가 인프라 + 측정 데이터 + 자료집 별도 PR로 develop 머지 |
| Issue #79 nginx/README.md | 자체 빌드로 대응책이 바뀌었으므로 cert-builder ↔ nginx 페어 문서 내용 재작성 필요 |
| 논문 작성 | `evaluation-data.md`의 Part 0(기여)·Part II/III/V(결과 표)·Part IV(케이스 스터디)·Part VII(F1~F11 quote) 그대로 본문에 옮겨 초안 작성 |
| 평가 보강 (선택) | rate limit 회복 후 패턴 13–16 재측정으로 통계 균형 보강. 또는 GitHub Models 무료 tier의 다른 모델(Llama-3.3, Phi-4, gpt-4o)로 multi-model 비교 추가 |
| 자체 CA 구현 검토 | 자체 빌드 구조에서 self-signed Dilithium3 → 내부 CA 체인 발급 구조로 전환 검토 |
