import requests
import google.generativeai as genai
import datetime
import time
import os

# 1. GitHub Secrets에서 API 키 불러오기 (보안 처리)
GOOGLE_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GOOGLE_API_KEY:
    raise ValueError("🚨 GEMINI_API_KEY가 설정되지 않았습니다.")
genai.configure(api_key=GOOGLE_API_KEY)
model = genai.GenerativeModel('gemini-1.5-flash')

# 2. CISA KEV 데이터 수집
def fetch_cisa_kev():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    kev_dict = {}
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        for item in response.json().get('vulnerabilities', []):
            kev_dict[item['cveID']] = item
    except Exception as e:
        print(f"KEV 수집 실패: {e}")
    return kev_dict

# 3. CVE 수집 및 KEV 최우선 정렬 필터링
def fetch_and_filter_cves(kev_dict):
    url = "https://cve.circl.lu/api/last/100"
    valid_cves = []
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        for cve in response.json():
            cvss = cve.get('cvss')
            if cvss and float(cvss) >= 7.0:
                cve['cvss_float'] = float(cvss)
                cve['is_kev'] = cve.get('id') in kev_dict
                if cve['is_kev']:
                    cve['kev_details'] = kev_dict[cve.get('id')]
                valid_cves.append(cve)
    except Exception as e:
        print(f"CVE 수집 실패: {e}")
        return []

    valid_cves.sort(key=lambda x: (x.get('is_kev', False), x.get('cvss_float', 0.0)), reverse=True)
    return valid_cves[:5]

# 4. AI 리포트 생성
def generate_ai_report(cve_list):
    with open("prompt.md", "r", encoding="utf-8") as f:
        prompt_template = f.read()

    cve_data_text = ""
    for cve in cve_list:
        is_kev = cve.get('is_kev', False)
        kev_alert = "🚨 [CISA KEV 악용 확인!]" if is_kev else ""
        cve_data_text += f"- CVE 번호: {cve.get('id')} {kev_alert}\n"
        cve_data_text += f"- CVSS 점수: {cve.get('cvss_float')}\n"
        cve_data_text += f"- 요약: {cve.get('summary', '정보 없음')}\n"
        if is_kev:
            kev_info = cve.get('kev_details', {})
            cve_data_text += f"- 벤더: {kev_info.get('vendorProject')}\n"
            cve_data_text += f"- 권고: {kev_info.get('requiredAction')}\n"
        cve_data_text += "-"*30 + "\n"

    final_prompt = prompt_template.replace("{CVE_DATA}", cve_data_text)
    
    for attempt in range(3):
        try:
            return model.generate_content(final_prompt).text
        except Exception:
            time.sleep(5)
    return "AI 리포트 생성 실패"

# 5. 메인 실행부 (GitHub Pages 블로그용 포맷으로 저장)
def main():
    today = datetime.datetime.now()
    week_num = (today.day - 1) // 7 + 1
    
    kev_dict = fetch_cisa_kev()
    top_cves = fetch_and_filter_cves(kev_dict)
    
    if not top_cves:
        return

    ai_content = generate_ai_report(top_cves)

    # 깃허브 블로그(Jekyll)가 인식할 수 있는 머리말(Front Matter) 추가
    front_matter = f"""---
layout: post
title: "{today.year}년 {today.month}월 {week_num}주차 보안 위협(CVE) 동향 리포트"
date: {today.strftime('%Y-%m-%d %H:%M:%S')} +0900
categories: SecOps
---

"""
    # 깃허브 블로그 포스팅 규칙에 맞게 _posts 폴더 생성 및 저장
    os.makedirs("_posts", exist_ok=True)
    filename = f"_posts/{today.strftime('%Y-%m-%d')}-cve-report.md"
    
    with open(filename, "w", encoding="utf-8") as file:
        file.write(front_matter + ai_content)
    print(f"[{filename}] 생성 완료!")

if __name__ == "__main__":
    main()
