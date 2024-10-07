# Scalr Audit Points
클라우드 인프라 관리 플랫폼 Scalr의 보안 Audit Points를 다룹니다. 일부 항목의 경우에는 플러그인 구성에 따라 옵션이 상이할 수 있으며, 관리자가 자체적으로 별도 이행하고 있는지 검토가 필요한 항목도 있습니다. 

## Version
1.0.0 

## Audit Points 목록 
1. 장기 미사용 계정 등 사용자 계정 현황 검토
1. 입퇴사자에 대한 계정 관리 프로세스 검토
1. 사용자 계정 식별자 할당 여부
1. 시스템 계정 운영 현황 검토
1. 사용자/그룹 권한 부여 현황 검토
1. 특수 권한이 부여된 사용자에 대한 검토
1. IP ACL을 통한 네트워크 접근 통제 여부
1. 사용자 세션 타임아웃 통제 설정 여부
1. 로그 별도 보관 및 관리 여부 
1. 각 어카운트 별 Terraform/OpenTofu 현황 검토
1. API 토큰 사용 현황 검토
1. 클라우드 연동 계정에 대한 키 관리 여부
1. IaC 스캐닝 정책 적용 검토
1. 운영중인 OPA 현황 검토
1. 솔루션 통합 현황 관리 여부
1. 리소스 배포 승인 이력 및 변경 관리 현황 검토
1. 워크스페이스 별 무분별한 삭제 방지 대응 여부
1. 환경 변수 내 민감 정보 노출 점검