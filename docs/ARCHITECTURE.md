# Architecture

> Status: draft, in progress.

## 1. Problem Statement

In my previous roles, I wrote Python scripts to parse NVD feeds, cutting vulnerability triage time by 90%. I also prioritized 11 CISA KEV vulnerabilities and coordinated the remediation across different teams. But the actual fixes still relied entirely on humans. I personally remediated SQL injection issues using parameterized queries, reducing recurring findings by 60%. Through that hands-on experience, I learned early on that just because a scanner stops flagging an alert doesn't mean the vulnerability is actually fixed. Today, AI can generate patches automatically, which shifts the real question to: how do we verify that a fix actually works without breaking anything else?

**Where the bottleneck moves.** Keller & Nowakowski (2024) report that within Google's internal codebase alone, sanitizers uncover thousands of new bugs every year, and engineers spend an average of two hours writing a single fix. They used Gemini to automatically fix 15% of those sanitizer bugs, yet even their pipeline ends with every generated fix going to human review before submission. That still leaves the remaining unpatched issues, plus the need to verify whether that 15% was handled correctly. Human effort shifts toward finding out whether the patch itself is broken.

**Two modes of failure.** Looking closely at Keller & Nowakowski (2024), I see two main ways an AI patch can fail.

The first is an incomplete or bogus fix. Developers sometimes leave temporary workarounds marked with "TODO" comments. If that kind of code isn't filtered out of training sets, LLMs pick up the habit and suggest the same provisional fixes. Even worse are fake fixes: Google observed suggestions that "resolved" an error by deleting the failing test case entirely. Everything looks green on the surface, but the vulnerability is still wide open.

The second mode is fixing the vulnerability while breaking functionality. In one real case, to resolve a data race, a model made the code run sequentially and added a comment saying, "cannot run in parallel because it causes a data race." The race condition was gone and the code still ran, but the parallelism was gone with it.

**The cost of missing data.** Right now, nobody knows how often these failures happen. Without concrete data, teams hesitate to touch AI-generated patches, and the problematic code simply sits there. One option is reviewing every patch manually, which makes humans the bottleneck; nobody has published what that review costs per patch, either. The alternative is skipping the patches altogether, leaving vulnerabilities exposed longer and risking product security. The data we are missing includes: what percentage of a model's patches break existing features, how long it takes to generate and validate them, and what the success-to-failure ratio looks like across different models.

**Why not just follow Google's playbook?** Google's answer is to improve the quality of the training data. But the vast majority of security teams are end users of these models; we can't touch the training data. My approach is to evaluate whether we can rigorously validate the model's output instead: measuring regression rates, generation and validation times, and success/failure splits to decide which patches genuinely require human eyes.

**The core question.** Under what conditions can an AI-generated security patch be safely merged? In this project, "safely merged" means the previously failing security test now passes (the vulnerability is truly gone), the application builds and runs, and all existing regression tests pass (nothing broke). Re-scan results from vulnerability scanners are logged for tracking, but they are not used as the pass/fail criteria. The goal is to back this up with visualized metrics, using hard data to decide when a human actually needs to step in.

**Reference.** Jan Keller and Jan Nowakowski, *AI-powered patching: the future of automated vulnerability fixes*, Google Security Engineering Technical Report, 2024. https://research.google/pubs/ai-powered-patching-the-future-of-automated-vulnerability-fixes/

## 2. Related Work and What This Project Adds

<!--
- CVE-Bench、PatchEval、SWE-bench 各自量了什麼？用什麼判定「修好」與「沒弄壞」？
- 它們「沒有」做的是哪一段？（提示：部署閘門、掃描器綠燈 vs 真的修好、在自己 fork 的實戰）
- 用一句話回答面試官會問的：「這跟 CVE-Bench 差在哪？」
- 你沿用了什麼（資料集、判定方法），並註明來源與授權。
-->

## 3. Scope and Non-goals

<!--
- 這個專案「做」什麼？列 3–5 條。
- Non-goals：不自己寫掃描器、不追求高修補成功率、不做 agent、不碰釣魚分析、不送上游 PR。
- 每一條 Non-goal 都補一句「為什麼不做」——這比清單本身更重要。
-->

## 4. System Overview

<!--
- 三個階段（校準 → 閘門 → 實戰）各自的目的是什麼？為什麼順序不能反？
- 資料流：setup_case → scan → patch → verify → report。
  每一步的「輸入」是什麼、「輸出」是什麼檔案或格式？（例：scan 輸出 SARIF）
- 可以畫一張簡單的圖（ASCII 或 Mermaid 都可以）。
-->

## 5. Outcome Classification

<!--
全文最重要的一節。每條規則都要能直接寫成 if/else。
- 四種結果的定義：patch 套不上／沒修好／修好但弄壞功能／修好且通過。
- 「修好」用什麼判斷？採用 FAIL_TO_PASS（修補前失敗、修補後通過的安全測試）嗎？
- 「沒弄壞」用什麼判斷？採用 PASS_TO_PASS 嗎？原有測試本來就失敗的怎麼處理？
- 判定順序：哪一步失敗就停？
- 附加檢查：掃描器重掃是否變安靜？這個結果「不」影響分類，只是記錄——為什麼？
- 模型每次輸出不同：每組跑幾次？結果怎麼彙整？
-->

## 6. Merge Gate Policy

<!--
- patch-bot 在什麼條件下自動開 PR？什麼條件下改開 issue 給人看？
- 每一條規則都要能指回第一階段的某個量測數字（例：「模型 X 的弄壞功能率是 Y%，所以……」）。
  數字還沒出來的話，先寫「待階段 1 結果」和你預期要看哪個數字。
- 什麼情況一律需要人工審查？
-->

## 7. Model Layer and Reproducibility

<!--
- 用哪幾個模型？為什麼選它們（跨廠商比較、同家族大小對照）？
- 從 cwe-explainer 沿用了哪些設計？（OpenAI 相容介面換 base_url、參數自動調整、模型輸出當不可信輸入）
- 為了讓別人能重跑，固定了哪些東西？（模型 ID、溫度、重跑次數、prompt 版本）
- 每次執行記錄哪些欄位？要不要存 SQLite、用 SQL 產生報表？為什麼？
-->

## 8. Relationship to Existing Code

<!--
- 原本的 CVE 查詢／KEV 對照／SLA 追蹤保留下來扮演什麼角色？
- 什麼已經移走（釣魚分析 → phishing-analyzer branch）？
- 已知但還沒修的既有問題：NVD 查詢失敗時顯示「系統安全」（fail-open）、CVE 頁面 XSS。
-->

## 9. Security of the Harness

<!--
這一節是 THREAT_MODEL.md 的摘要。
- 你會執行別人的程式碼和模型產生的修補——要怎麼隔離？
- patch-bot 的 token 需要哪些權限？最少可以少到哪裡？fork 來的 PR 拿得到 secrets 嗎？
- 被修補的程式碼裡如果藏了對模型的指令（prompt injection），會發生什麼事？
- 模型 API key 放哪裡？
-->

## 10. Disclosure and Contribution Rules (Phase 3)

<!--
- 只在自己的 fork 做實驗，不送上游 PR。為什麼？
- 公開報告放什麼、不放什麼？
- 如果發現尚未公開、可被利用的漏洞怎麼辦？（負責任揭露、SECURITY.md）
-->

## 11. Secure SDLC Mapping

<!--
用一張表把 SDLC 各階段對應到專案裡的具體東西：
  設計 → THREAT_MODEL.md
  建置 → SAST（Bandit、Semgrep）、SCA（pip-audit）、秘密掃描（gitleaks）
  發佈 → patch-bot 合併閘門、分支保護
可以對照 NIST SSDF 的四個實踐群組（PO、PS、PW、RV）。
-->

## 12. Decision Log

<!--
每個重要決定一小段：背景 → 考慮過的選項 → 選了什麼 → 為什麼 → 代價。
這是證明「是你做的決定」最有力的地方。第一條可以寫：
  「沿用 CVE-Bench 的案例，而不是自己挑 10 個 CVE 自己架環境」
-->

## 13. Open Questions

<!--
還沒決定、或需要數據才能決定的事。
-->

## 14. AI Assistance

<!--
照 cwe-explainer README 的做法：誠實說明哪些是你決定的、AI 幫了什麼。
-->
