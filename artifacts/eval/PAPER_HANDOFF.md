# 논문 작성 세션 인계 문서

> 본 문서는 캡스톤 논문 작성을 새 세션에서 이어갈 수 있도록 현재 상태·할 일·필요한 자료를 정리한 핸드오프 자료다.
> 새 세션에서 이 파일과 PDF/LaTeX 원본을 같이 첨부하면 즉시 작업 가능.

---

## 1. 현재 상태 (2026-05-11 기준)

### 논문 초안

- **형식**: LNCS Springer 17 페이지 한국어
- **제목**: "DevSecOps 파이프라인을 활용한 단계적 Hybrid PQC-TLS 전환 자동화"
- **저자**: First Author 외 4명 + Hwa-Jeong Seo (Hansung University)
- **상태**: 본문 전체 완료. References 17곳 미작성 + Figure 1개만 있음
- **목표 venue**: 국내 학회(KIISC/CISC/JCCI 종합학술대회) 또는 국제 워크샵 short paper

### 구조 (5장)

```
1. 서론
   1.1 HNDL 위협과 PQC 전환 필요성
   1.2 기존 TLS 전환 방식의 문제 정의 (4가지)
   1.3 연구 범위 및 위협 모델
   1.4 기여 (4종 contribution)
2. 관련 연구
   2.1 PQC TLS 전환 연구
   2.2 DevSecOps 및 CI/CD 보안 통합
   2.3 CBOM 및 암호화 자산 관리
   2.4 LLM 기반 보안 코드 마이그레이션
3. 설계 및 구현
   3.1 3단계 TLS 마이그레이션 모델 (Stage 1/2/3)
   3.2 11-Step DevSecOps 파이프라인 구조
   3.3 OQS-Nginx 자체 빌드 기반 PQC TLS 서버
   3.4 취약점 분석 및 TLS 정책 검증 모듈
   3.5 CBOM 생성, Diff, TLS 교차 검증 (가장 분량 큼, 5 layer)
   3.6 성능 검증 및 자동 롤백
   3.7 AI 기반 레거시 코드 마이그레이션
   3.8 매트릭스 CI 기반 회귀 감지
4. 평가 (Q1~Q4 + Table 4~9 + Figure 미작성)
   4.1 평가 설계 및 질문
   4.2 실험 환경
   4.3 평가 A: PQC 도구 체인 함정 카탈로그
   4.4 평가 B: LLM 기반 코드 마이그레이션 정확도
   4.5 평가 C: 파이프라인의 함정 차단 및 감지 효과
   4.6 논의
5. 결론
   5.1 연구 요약
   5.2 한계점 (6종)
   5.3 향후 연구 방향 (5종)
References (미작성)
```

### 현재 Figure / Table 목록

- Figure 1: Stage 3 CBOM 컴포넌트 의존 관계 (3.5 위치, **완성**)
- Table 1: 3단계 TLS 마이그레이션 모델
- Table 2: Stage별 TLS 정책 판정 기준
- Table 3: CBOM 생성 시 결합 데이터 소스
- Table 4: 실험 환경 및 도구 버전
- Table 5: PQC 도구 체인 함정 6종 카탈로그
- Table 6: 4단계 검증 계층별 통과율 (80 trial)
- Table 7: LLM 실패 모드 7종 및 차단 계층
- Table 8: 함정 6종에 대한 파이프라인 layer별 효과
- Table 9: 검증 계층 적용 시나리오별 실패 코드 전달 위험

---

## 2. 핵심 기여 / 평가 결과 (논문 본문 외워두기)

### 기여 4종 (1.4 절)

1. **Policy as Code 기반 3단계 TLS 마이그레이션 + 11-Step DevSecOps 파이프라인**
2. **PQC 도구 체인 함정 6종(F-1~F-6) 카탈로그 + 자체 빌드/매트릭스 CI 기반 완화**
3. **CycloneDX 1.7 기반 CBOM Diff (BASELINE/IMPROVED/UNCHANGED/REGRESSED 자동 판정)**
4. **LLM 기반 코드 마이그레이션 + 다층 검증 필요성 정량 평가**

### 평가 핵심 수치 (논문에서 반복 인용)

| 지표 | 수치 | 출처 |
|---|---|---|
| 표준 도구(Trivy/Semgrep/CBOM)의 함정 6종 사전 탐지율 | **0/6** | Table 5 |
| 자체 빌드의 함정 사전 예방율 | **5/6** | Table 8 |
| 매트릭스 CI의 함정 런타임 감지율 | **6/6** | Table 8 |
| LLM 80 trial 중 L3(semantic) 통과 | **0/80 = 0%** | Table 6 |
| LLM 응답 받은 55건 중 어딘가 실패 | **55/55 = 100%** | 4.4 |
| L2 통과했지만 L3 실패 (시그니처 환각) | **24/55 = 44%** | 4.4 |
| L2와 L3 차단 카테고리 overlap | **0** | 4.4 / Table 7 |
| LLM 평가 비용 | **$0.013 / 80 trial** | 부수 |

### Stage 3 실제 협상 결과 (검증 증거)

```
TLSv1.3 / TLS_AES_256_GCM_SHA384 / p521_mlkem1024 / mldsa65
```

`docker exec tls-tester tls_check.sh proxy-server 443 3` → `[PASS]` 확인됨.

---

## 3. 즉시 해야 할 작업 (우선순위)

### 필수 (게재 전 반드시 — 약 3시간)

#### 작업 1: References 17곳 채우기 (1~2시간)

"[인용 추가]" 표시가 17곳. 다음 표 참고:

| 위치 | 인용 후보 |
|---|---|
| 1.1 Shor 알고리즘 | P. W. Shor, "Algorithms for quantum computation: discrete logarithms and factoring," FOCS 1994 |
| 1.1 HNDL 공격 | NSA "Commercial National Security Algorithm Suite 2.0", Mosca "Cybersecurity in an Era with Quantum Computers" 2018 |
| 1.1, 2.1 NIST FIPS | NIST FIPS 203 (ML-KEM, 2024-08-13), FIPS 204 (ML-DSA, 2024-08-13), FIPS 205 (SLH-DSA, 2024-08-13) |
| 2.1 OQS Project | D. Stebila and M. Mosca, "Post-quantum key exchange for the Internet and the Open Quantum Safe project," SAC 2016 |
| 2.1 liboqs/oqs-provider | Open Quantum Safe Project, https://openquantumsafe.org/ |
| 2.1 X25519MLKEM768 | IETF draft-ietf-tls-hybrid-design (Stebila, Fluhrer, Gueron) |
| 2.1 hybrid TLS 실험 | Paquin, Stebila, Tamvada "Benchmarking Post-Quantum Cryptography in TLS," PQCrypto 2020; 또는 Cloudflare 블로그 |
| 2.2 DevSecOps | H. Myrbakken, R. Colomo-Palacios "DevSecOps: A Multivocal Literature Review" 2017 |
| 2.2 Trivy/Gitleaks/Semgrep | 각 도구 공식 GitHub repo 인용 또는 관련 도구 비교 논문 |
| 2.2 OPA | T. Sandall et al., "Open Policy Agent," CNCF Project |
| 2.3 CBOM/CycloneDX | S. Springett et al., "CycloneDX Specification," OWASP |
| 2.3 PQC 전환 지침 | NIST SP 800-208, BSI PQC migration guidance |
| 2.4 LLM 코드 마이그레이션 | Pearce et al. "Asleep at the Keyboard? Assessing the Security of GitHub Copilot's Code Contributions," S&P 2022 |
| 2.4 LLM 암호 API 오용 | C. Sandoval et al. or J. Cassel et al. on LLM crypto API misuse |
| 2.4 정적분석 + LLM | M. Bavishi et al. "Repair Is Nearly Generation: Multilingual Program Repair with LLMs" 또는 유사 |

**참고**: 학회 양식이 LNCS면 모두 `\cite{Shor1994}` 형태로. 인용 styles:
- IEEE: 번호 [1], [2]
- ACM: Author-Year (Shor 1994)
- LNCS: 보통 번호 [1] (논문 양식 확인 필요)

#### 작업 2: Figure 2 추가 — 11-Step 파이프라인 (1시간)

3.2 절에 다이어그램. TikZ 또는 draw.io로 작성. 권장 구조:

```
[GitHub Push/PR] 
       ↓
┌──────────────────────────────────────────┐
│ 1. 코드 체크아웃                          │
│ 2. Stage 감지 및 TLS 설정 준비            │
│ 3. nginx 설정 자동 변경                   │
└──────────────────────────────────────────┘
       ↓
┌──────────────────────────────────────────┐
│ 4. 고전 암호 탐지 (Semgrep)               │
│ 5. 정적 보안 분석 (Trivy/Gitleaks/Semgrep)│
│ 6. TLS 암호 정책 검증 [Security Gate]     │  ← 차단 가능
└──────────────────────────────────────────┘
       ↓
┌──────────────────────────────────────────┐
│ 7. PQC Nginx 도커 빌드 및 가동            │
│ 8. 배포 후 동적 검증 (tls_check.sh)       │
│ 9. 성능 검증 (perf_check.sh)              │  → 임계치 초과 시 rollback.sh
└──────────────────────────────────────────┘
       ↓
┌──────────────────────────────────────────┐
│ 10. CBOM 생성/Diff (cbom_gen, cbom_diff)  │
│ 11. 결과 업로드, PR 코멘트, 이슈 생성     │
└──────────────────────────────────────────┘
```

TikZ 예시:
```latex
\begin{figure}[h]
\centering
\begin{tikzpicture}[node distance=0.5cm, every node/.style={draw, rounded corners, align=center, font=\small}]
  \node (start) {GitHub Push/PR};
  \node[below=of start] (prep) {1-3. 체크아웃 / Stage 감지 / 설정 변경};
  \node[below=of prep] (scan) {4-6. 고전 암호·정적 분석·정책 게이트};
  \node[below=of scan, draw=red, thick] (gate) {Security Gate (차단 가능)};
  \node[below=of gate] (deploy) {7-9. 빌드·동적 검증·성능 (롤백 트리거)};
  \node[below=of deploy] (cbom) {10-11. CBOM Diff / 결과 업로드};
  \draw[->] (start) -- (prep);
  \draw[->] (prep) -- (scan);
  \draw[->] (scan) -- (gate);
  \draw[->] (gate) -- (deploy);
  \draw[->] (deploy) -- (cbom);
\end{tikzpicture}
\caption{11-Step DevSecOps 파이프라인 흐름. Security Gate(Step 6)는 정책 위반 시 배포를 차단하며, 성능 검증(Step 9) 실패 시 자동 롤백된다.}
\label{fig:pipeline}
\end{figure}
```

#### 작업 3: Abstract 마지막 문장 톤 조정 (5분)

**현재**:
> "LLM 기반 코드 마이그레이션 80 trial 평가에서 정적 AST 검증만으로는 런타임 실패를 차단할 수 없으며, 의미적 실행 검증이 필수적임을 확인하였다."

**제안**:
> "LLM 기반 코드 마이그레이션 80 trial 평가에서 정적 AST 검증을 적용해도 시그니처 환각 유형의 실패 24건(44%)이 런타임 단계에서야 차단되어, 의미적 실행 검증이 다층 방어의 필수 요소임을 정량 확인하였다."

### 권장 (있으면 ↑ — 약 1.5시간)

#### 작업 4: 4.6 논의에서 Q1-Q4 명시적 답 (20분)

현재 4.6은 한 단락 정도라 Q1-Q4 답이 명시적이지 않음. 다음을 4.6 앞에 추가:

> **Q1에 대해**: 평가 A(표 5)는 OQS 스택 통합 시 6종 함정(F-1~F-6)이 발생하며 Trivy/Semgrep/CycloneDX CBOM 모두 0/6 사전 탐지함을 보였다. 함정의 본질이 라이브러리 라인 비대칭과 wire-level code point 불일치이므로 표준 도구의 정적·SBOM 기반 탐지 범위 밖이다.
>
> **Q2에 대해**: 평가 B는 L2(AST 검증)와 L3(의미적 실행 검증)가 차단하는 실패 카테고리의 overlap이 0임을 보였다(표 7). `wrong_arg_count`(16건), `wrong_kwarg`(5건), `method_hallucination`(2건) 같은 시그니처 환각은 L3에서만 차단되며, `missing_instance_construction`(20건), `no_migration`(6건), `class_direct_call`(5건)은 L2에서 차단된다. 두 layer가 상호 보완적이며 어느 한쪽만으로는 모든 카테고리를 처리할 수 없다.
>
> **Q3에 대해**: 평가 C(표 8)는 자체 빌드가 함정 6종 중 5종을 사전 예방하고 매트릭스 CI가 6종 모두를 런타임에서 감지함을 보였다. 표준 도구의 0/6 사각지대가 본 파이프라인으로 메워진다.
>
> **Q4에 대해**: 평가 C(표 9)는 LLM 출력을 검증 없이 적용할 경우 응답 받은 55건이 모두 production crash 위험을 가지며, AST + 의미적 실행 검증을 모두 적용할 경우 production 단계로 전달되는 코드가 0건임을 보였다. 다만 본 평가에서 통과된 코드 자체가 0건이므로 다층 방어는 "위험 차단"의 안전장치로 기능하며, 실 운영 적용은 모델 정확도 향상이 선행되어야 한다.

#### 작업 5: 약어 풀네임 정의 (10분)

처음 등장 시 풀네임 추가:
- "표준 SCA(Software Composition Analysis)/SAST(Static Application Security Testing)/SBOM(Software Bill of Materials)"
- "CBOM(Cryptographic Bill of Materials)" — 2.3에 이미 풀네임 정의됨, OK
- "PQC(Post-Quantum Cryptography)" — abstract에 풀네임 권장

#### 작업 6: "production" → "운영" 또는 "배포" (10분)

본문 5개 정도 위치에 "production 단계"가 있음 → "운영 단계" 또는 "배포 단계"로 통일 (한국 학회 관습).

### 선택 (시간 남으면)

#### 작업 7: Figure 3 — 4-Layer 평가 검증 흐름 (1시간)

4.4 절에 다이어그램. L1→L2→L3→L4 + 각 layer가 어떤 실패 모드를 차단하는지.

#### 작업 8: Table 9 ③ 설명 정확화

"해당 없음" → "통과 trial 0건이므로 측정 대상 없음 (모든 LLM 출력이 거부됨)"

---

## 4. 자료 위치 (논문 본문 작성용 raw material)

```
artifacts/eval/
├── evaluation-data.md      ★ 본문 작성용 raw material 종합본 (Part 0 ~ VIII)
├── infra-failure-catalog.md  — F-1~F-6 상세 (트리거/증상/원인/방어)
├── benchmark-spec.md         — 평가 B 설계 명세
├── benchmark/
│   ├── patterns/   (16 RSA 입력 .py)
│   ├── reference/  (16 oqs-python 정답 .py)
│   └── results/
│       ├── sanity.json      (16/16/16)
│       ├── baseline.json    (0/0/0)
│       ├── llm_k5.json      ★ 80 trial 원시 데이터
│       └── analysis.md      ★ 표 11개 + 케이스 스터디 7개 자동 생성
├── HOW_TO_RUN.md            — 재현 명령
├── Dockerfile               — 평가 컨테이너
├── eval_runner.py           — L1~L4 자동 실행
├── analyze.py               — 표/케이스 자동 생성
├── PAPER_HANDOFF.md         — 본 문서
└── harness/
    ├── ast_validator.py     — L2
    ├── llm_client.py        — L1
    ├── semantic_tests.py    — L3
    └── equivalence.py       — L4
```

### `evaluation-data.md` 활용법

논문 본문 작성 시 섹션별로 다음 부분에서 발췌:

| 논문 위치 | evaluation-data.md 위치 |
|---|---|
| 1.4 기여 | Part 0.2-0.4 (C-A1~C-A4, C-B1~C-B6, C-C1~C-C4) |
| 4.1 Q1-Q4 | Part 0.1 (세 평가의 위치 표) |
| 4.2 실험 환경 | Part I §1.1-1.2 |
| 4.3 평가 A | Part II §2.1-2.2 (F-1~F-6 + 매트릭스) |
| 4.4 평가 B | Part III §3.2-3.7 (다층 ablation + taxonomy + 차원별) |
| 4.4 케이스 스터디 | Part IV (Case 1~6) |
| 4.5 평가 C | Part V §5.2-5.5 |
| 4.6 논의 | Part VI Findings F1~F11 |
| 5.2 한계 | Part V (이미 6종 정리됨) |

---

## 5. 관련 PR / git 정보

### 머지된 PR (논문에 인용 가능)

| PR | 머지일 | 내용 |
|---|---|---|
| #71 | (이전) | OQS 이미지 sha256 핀 도입 — F-2/F-5 발견 계기 |
| #76 | 2026-04-17 | nginx 이미지 :0.11.0 회귀 — F-2 임시 대응 |
| #77 | 2026-04-18 | CycloneDX 1.7 CBOM + TLS 교차 검증 |
| #82 | 2026-04-27 | AI 마이그레이션 PoC (평가 B 프롬프트 출처) |
| #83 | 2026-04-30 | Stage 2/3 매트릭스 CI 도입 |
| #84 | 2026-05-05 | 자체 빌드로 OQS 라인 통일 (F-1, F-3, F-4, F-6 근본 해결) |
| #85 | 2026-05-10 | PR #80 비충돌 변경 이식 (Trivy 개선, captures) |
| #86 | 2026-05-10 | Stage 3 캡처 비교 + verify_tls.sh EXPECT |
| #87 | 2026-05-10 | tester Dockerfile에 verify_tls.sh COPY |
| #88 | 2026-05-10 | develop → main 릴리스 |

### 닫힌 PR

- #80 (yulim4hyoung): Stage 3 standalone mlkem1024 회귀로 close, 좋은 부분은 #85로 이식
- #81: 자동 생성 demo PR, close

---

## 6. 솔직한 평가 / venue 적합성

### 현재 상태로 가능한 venue

✅ **국내 학회**: KIISC 종합학술대회, JCCI, CISC — 통과 충분
✅ **학부 졸업논문 / 캡스톤 보고서** — 매우 잘 짠 수준
✅ **국제 워크샵 short paper**: SecDev, CCS workshops, ISSRE workshops — 작업 1-3번 보강 후 도전 가능

### 어림없는 venue

❌ **Top-tier**: USENIX Security, CCS, NDSS, S&P — N=1 + 단일 LLM + 합성 패턴 제약
❌ **A급 journal**: IEEE TIFS, JCS — 동일 이유

### 보강 시 ↑ 가능 venue

⚠️ **Mid-tier journal** (IEEE Access, MDPI Sensors 등) — multi-model 비교 + 실 OSS 사례 추가 시 도전 가능

---

## 7. 새 세션에서 시작하는 법

다음을 첨부:
1. **본 문서** (`PAPER_HANDOFF.md`)
2. **현재 PDF** (`2026_Capstone.pdf`)
3. **LaTeX 원본** (`.tex` 파일)
4. (선택) `evaluation-data.md`

새 세션 첫 프롬프트 예시:

> 캡스톤 논문 작성 중이다. `PAPER_HANDOFF.md`에 현재 상태와 할 일이 정리되어 있다.
> 우선순위 필수 작업 1번(References 채우기) 먼저 진행하고 싶다.
> LaTeX 파일에 `\cite{...}` 형태로 적용해줘.

또는:

> 작업 2번(Figure 2: 11-Step 파이프라인 TikZ 다이어그램)을 진행하고 싶다.
> PAPER_HANDOFF.md의 작업 2에 있는 TikZ 예시를 본 논문 LaTeX 스타일에 맞게 다듬어줘.

또는 모든 작업 한 번에:

> PAPER_HANDOFF.md의 필수 보강 3개(작업 1, 2, 3) + 권장 보강 3개(작업 4, 5, 6)를 모두 적용한 LaTeX 파일을 만들어줘.

---

## 8. 체크리스트 (게재 전)

- [ ] References 17곳 모두 채움
- [ ] Figure 2 (11-Step 파이프라인) 추가
- [ ] Abstract 마지막 문장 톤 조정
- [ ] 4.6 논의에 Q1-Q4 명시적 답 추가
- [ ] 약어 풀네임 정의 (SCA/SAST/SBOM/PQC)
- [ ] "production" → "운영"/"배포" 통일
- [ ] 학회 양식(LNCS/IEEE/ACM) 확인 후 인용 스타일 일치
- [ ] 저자 정보 (First Author 등) 실명으로 교체
- [ ] 페이지 수 학회 한도 확인 (LNCS short 6-12p, full 12-16p 등)
- [ ] 영문 abstract (학회가 요구하면)
- [ ] 키워드 (현재 4개, 학회 요구 갯수 확인)
- [ ] (선택) Figure 3 (4-Layer 검증 흐름)
- [ ] (선택) 더 큰 LLM 모델 비교 데이터 (rate limit 풀린 후)
