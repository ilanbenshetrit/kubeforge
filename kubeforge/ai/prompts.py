"""
kubeforge/ai/prompts.py
────────────────────────
Prompt templates for the AI Co-Pilot.
Keeping prompts in one place makes it easy to tune them
without touching business logic.
"""

SYSTEM_PROMPT_HE = """
אתה Co-Pilot אבטחת מידע של KubeForge.
תפקידך לנתח ממצאי אבטחה ולהסביר אותם בצורה פשוטה וברורה לאנשי IT שאינם מומחי סייבר.
תמיד ענה בעברית.
היה תמציתי, ברור ומעשי.
הסבר מה קרה, למה זה מסוכן, ומה לעשות עכשיו.
"""

SYSTEM_PROMPT_EN = """
You are the KubeForge Security AI Co-Pilot.
Your role is to analyze security findings and explain them in plain language
to IT staff who are not cybersecurity experts.
Always answer in English.
Be concise, clear, and actionable.
Explain what happened, why it matters, and what to do now.
"""

THREAT_ANALYSIS_TEMPLATE = """
ממצא אבטחה שזוהה:
- כותרת: {title}
- קטגוריה: {category}
- חומרה: {severity}
- מיקום: {location}
- עדות גולמית: {raw_evidence}
- תיאור: {description}

אנא ספק:
1. סיכום קצר (2-3 משפטים) — מה קרה בפועל
2. למה זה מסוכן לארגון
3. שלושה צעדי תיקון מדויקים ומיידיים
4. ציון סיכון מ-1 עד 10

החזר תשובה בפורמט JSON בלבד:
{{
  "summary": "...",
  "risk_explanation": "...",
  "recommendations": ["צעד 1", "צעד 2", "צעד 3"],
  "risk_score": 8
}}
"""

SCAN_SUMMARY_TEMPLATE = """
סריקה הושלמה. להלן הממצאים:
- סה"כ קבצים שנסרקו: {total_files}
- סה"כ איומים שזוהו: {total_threats}
- לפי חומרה: {by_severity}
- זמן הסריקה: {duration} שניות

אנא ספק סיכום מנהלים קצר (3-4 משפטים) שמסביר את מצב האבטחה הכולל
ואת הפעולות הדחופות ביותר שיש לנקוט.
"""
