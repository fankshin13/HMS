-- KISA 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」 Windows 서버 대표 항목 초기 적재.
-- 표준 점검 스크립트(kisa_check_windows.bat)가 근거를 수집하는 계정 관리 4개 항목만 우선 넣는다.
-- 항목 코드·문구·기준값(특히 W-04 임계값)은 공식 가이드 원문과 대조해 후속 마이그레이션으로 보정·확장한다.

insert into public.compliance_guidelines (
  item_code, category, name, risk_level, standard_criteria, good_condition, vulnerable_condition, remediation_guide
) values
  ('W-01', 'account_management', 'Administrator 계정 이름 바꾸기', 'high',
   '기본 관리자 계정(RID 500)의 이름이 Administrator 로 유지되는지 점검',
   'Administrator 기본 계정 이름을 변경했거나 강화된 비밀번호를 적용한 경우',
   'Administrator 기본 계정 이름을 변경하지 않은 경우',
   '로컬 보안 정책 > 보안 옵션 > "계정: Administrator 계정 이름 바꾸기"에서 추측하기 어려운 이름으로 변경'),
  ('W-02', 'account_management', 'Guest 계정 비활성화', 'high',
   'Guest 계정(RID 501)의 사용 여부 점검',
   'Guest 계정이 비활성화되어 있는 경우',
   'Guest 계정이 활성화되어 있는 경우',
   '컴퓨터 관리 > 로컬 사용자 및 그룹 > 사용자 > Guest 속성에서 "계정 사용 안 함" 선택'),
  ('W-04', 'account_management', '계정 잠금 임계값 설정', 'high',
   '로그온 실패 시 계정 잠금 임계값 설정 여부 점검',
   '계정 잠금 임계값이 5 이하의 값으로 설정되어 있는 경우',
   '계정 잠금 임계값이 설정되지 않았거나 5 초과의 값으로 설정된 경우',
   '로컬 보안 정책 > 계정 정책 > 계정 잠금 정책 > "계정 잠금 임계값"을 5 이하로 설정'),
  ('W-05', 'account_management', '해독 가능한 암호화를 사용하여 암호 저장 해제', 'high',
   '"해독 가능한 암호화를 사용하여 암호 저장" 정책 사용 여부 점검',
   '"해독 가능한 암호화를 사용하여 암호 저장" 정책이 사용 안 함으로 되어 있는 경우',
   '"해독 가능한 암호화를 사용하여 암호 저장" 정책이 사용으로 되어 있는 경우',
   '로컬 보안 정책 > 계정 정책 > 암호 정책 > "해독 가능한 암호화를 사용하여 암호 저장"을 사용 안 함으로 설정')
on conflict (item_code) do update set
  category = excluded.category,
  name = excluded.name,
  risk_level = excluded.risk_level,
  standard_criteria = excluded.standard_criteria,
  good_condition = excluded.good_condition,
  vulnerable_condition = excluded.vulnerable_condition,
  remediation_guide = excluded.remediation_guide;
