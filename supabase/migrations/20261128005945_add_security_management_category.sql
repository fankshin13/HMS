-- KISA 2026 상세가이드의 Windows 서버 "5. 보안 관리" 분야. 새 열거형 값은 같은 트랜잭션에서 쓸 수 없어 별도 마이그레이션으로 둔다.
alter type public.compliance_category add value if not exists 'security_management';
