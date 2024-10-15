import requests
import pandas as pd

# Okta API URL과 API 키 설정
OKTA_DOMAIN = "<https://*.okta.com>"  # Okta 도메인
API_TOKEN = "<api_token>"  # Okta에서 생성한 API 키

headers = {
    'Authorization': f'SSWS {API_TOKEN}',
    'Content-Type': 'application/json'
}

# 감사 결과 저장을 위한 리스트
audit_data = []

# 사용자 목록 가져오기
def get_users():
    url = f"{OKTA_DOMAIN}/api/v1/users"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        users = response.json()
        total_users = len(users)
        user_list = [user['profile']['login'] for user in users]
        # 리스트를 줄바꿈 처리
        formatted_user_list = "\n".join(user_list)
        audit_data.append(["Users", f"Total users: {total_users}", formatted_user_list])
    else:
        audit_data.append(["Users", "Error fetching users", response.status_code])
    return None

# 사용자 계정 관리 현황 (입퇴사자 관리, 장기 미사용 계정, 공용계정 관리 등)
def get_account_management():
    url = f"{OKTA_DOMAIN}/api/v1/users"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        users = response.json()
        deactivated_users = [user['profile']['login'] for user in users if user['status'] == 'DEPROVISIONED']
        inactive_users = [user['profile']['login'] for user in users if user['status'] == 'SUSPENDED']
        shared_accounts = [user['profile']['login'] for user in users if 'shared' in user['profile']['login']]
        audit_data.append(["Deactivated Users", f"Total: {len(deactivated_users)}", ", ".join(deactivated_users)])
        audit_data.append(["Inactive Users", f"Total: {len(inactive_users)}", ", ".join(inactive_users)])
        audit_data.append(["Shared Accounts", f"Total: {len(shared_accounts)}", ", ".join(shared_accounts)])
    else:
        audit_data.append(["Account Management", "Error fetching users", response.status_code])
    return None

# MFA 정책 확인
def get_mfa_status():
    url = f"{OKTA_DOMAIN}/api/v1/policies"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        policies = response.json()
        mfa_policy_count = sum(1 for policy in policies if policy['type'] == 'MFA_ENROLL')
        policy_list = [policy['name'] for policy in policies if policy['type'] == 'MFA_ENROLL']
        formatted_policy_list = "\n".join(policy_list)
        audit_data.append(["MFA", f"MFA policies found: {mfa_policy_count}", formatted_policy_list])
    else:
        audit_data.append(["MFA", "Error fetching MFA policies", response.status_code])
    return None

# 그룹 목록 및 동적 할당 규칙 관리 현황 점검
def get_groups():
    url = f"{OKTA_DOMAIN}/api/v1/groups"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        groups = response.json()
        total_groups = len(groups)
        group_list = [group['profile']['name'] for group in groups]
        formatted_group_list = "\n".join(group_list)
        audit_data.append(["Groups", f"Total groups: {total_groups}", formatted_group_list])
        # 동적 할당 규칙 추가
        dynamic_groups = [group['profile']['name'] for group in groups if group['type'] == 'DYNAMIC']
        formatted_dynamic_group_list = "\n".join(dynamic_groups)
        audit_data.append(["Dynamic Groups", f"Total dynamic groups: {len(dynamic_groups)}", formatted_dynamic_group_list])
    else:
        audit_data.append(["Groups", "Error fetching groups", response.status_code])
    return None

# 디렉터리 에이전트 관리 현황
def get_agents():
    url = f"{OKTA_DOMAIN}/api/v1/idps"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        agents = response.json()
        total_agents = len(agents)
        agent_list = [agent['name'] for agent in agents]
        audit_data.append(["Directory Agents", f"Total agents: {total_agents}", ", ".join(agent_list)])
    else:
        audit_data.append(["Directory Agents", "Error fetching directory agents", response.status_code])
    return None

# 네트워크 접근 통제 설정 확인
def get_network_zone():
    url = f"{OKTA_DOMAIN}/api/v1/zones"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        zones = response.json()
        total_zones = len(zones)
        zone_list = [zone['name'] for zone in zones]
        audit_data.append(["Network Zones", f"Total zones: {total_zones}", ", ".join(zone_list)])
    else:
        audit_data.append(["Network Zones", "Error fetching network zones", response.status_code])
    return None

# 관리자 권한 부여 현황 점검
def get_admin_privileges():
    url = f"{OKTA_DOMAIN}/api/v1/groups"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        groups = response.json()
        admin_groups = [group['profile']['name'] for group in groups if 'ADMIN' in group['profile']['name'].upper()]
        audit_data.append(["Admin Privileges", f"Admin groups found: {len(admin_groups)}", ", ".join(admin_groups)])
    else:
        audit_data.append(["Admin Privileges", "Error fetching admin groups", response.status_code])
    return None

# API Rate Limit 설정 확인
def check_rate_limit():
    url = f"{OKTA_DOMAIN}/api/v1/users"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        limit = response.headers.get('X-Rate-Limit-Limit', 'N/A')
        remaining = response.headers.get('X-Rate-Limit-Remaining', 'N/A')
        reset_time = response.headers.get('X-Rate-Limit-Reset', 'N/A')
        audit_data.append(["API Rate Limit", "Limit", limit])
        audit_data.append(["API Rate Limit", "Remaining", remaining])
        audit_data.append(["API Rate Limit", "Reset Time", reset_time])
    else:
        audit_data.append(["API Rate Limit", "Error fetching rate limit", response.status_code])
    return None

# 사용자 계정 보안 변경사항 알림 설정 여부
def get_security_notifications():
    url = f"{OKTA_DOMAIN}/api/v1/logs"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        logs = response.json()
        total_logs = len(logs)
        log_list = [log['eventType'] for log in logs]
        audit_data.append(["Security Notifications", f"Logs found: {total_logs}", ", ".join(log_list)])
    else:
        audit_data.append(["Security Notifications", "Error fetching logs", response.status_code])
    return None

# 엑셀 저장 시 자동 줄바꿈 적용
def save_to_excel(audit_df):
    with pd.ExcelWriter('okta_audit_results.xlsx', engine='openpyxl') as writer:
        audit_df.to_excel(writer, sheet_name='Audit Results', index=False)
        
        # 엑셀의 자동 줄바꿈 설정
        workbook = writer.book
        worksheet = writer.sheets['Audit Results']
        for col in worksheet.columns:
            max_length = 0
            col_letter = col[0].column_letter  # 컬럼 이름
            for cell in col:
                try:
                    if cell.value:
                        max_length = max(max_length, len(str(cell.value)))
                    if isinstance(cell.value, str) and '\n' in cell.value:
                        cell.alignment = cell.alignment.copy(wrap_text=True)  # 줄바꿈 적용
                except:
                    pass
            worksheet.column_dimensions[col_letter].width = max(max_length, 10)  # 적절한 너비 설정

# 주요 항목 점검 수행 및 엑셀 저장
def audit_okta_security():
    print("Running Okta security audit...")
    
    get_users()  # 사용자 목록 점검 (200명 이상 페이징 포함)
    get_mfa_status()
    get_groups()

    # pandas 데이터프레임으로 변환
    audit_df = pd.DataFrame(audit_data, columns=["Category", "Check", "Details"])

    # 엑셀 파일로 저장 및 자동 줄바꿈 적용
    save_to_excel(audit_df)

    print("Audit completed and saved to okta_audit_results.xlsx")

# 실행
if __name__ == "__main__":
    audit_okta_security()
