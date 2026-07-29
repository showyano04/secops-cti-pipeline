---
layout: default
---

## 🛡️ SecOps 주간 위협 인텔리전스 리포트
이 블로그는 CISA KEV 및 NVD(CIRCL) 데이터를 기반으로, AI가 매주 금요일 자동으로 생성하는 **사이버 위협 동향 모니터링 파이프라인**입니다.

---

### 📋 최신 리포트 목록

<ul>
  {% for post in site.posts %}
    <li style="margin-bottom: 10px;">
      <a href="{{ post.url | relative_url }}" style="font-size: 18px; font-weight: bold;">{{ post.title }}</a>
      <br>
      <span style="color: #888;">발행일: {{ post.date | date: "%Y년 %m월 %d일" }}</span>
    </li>
  {% endfor %}
</ul>
