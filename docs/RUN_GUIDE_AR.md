# دليل التشغيل خطوة بخطوة — مشروع Lightweight SIEM & SOAR

هذا الدليل يشرح تشغيل المشروع من الصفر على جهازك (Windows) ثم اختبار الأداء بسجلات حقيقية (بعضها ملوّث/هجومي) للتأكد من أن الأداة تعمل بشكل صحيح وجاهزة للعرض أو النشر.

---

## المتطلبات الأساسية

| المكوّن            | الإصدار المطلوب                          | ملاحظة                                    |
| ------------------ | ---------------------------------------- | ----------------------------------------- |
| Python             | 3.10 أو 3.11                             | مثبّت مسبقًا لديك — venv جاهزة داخل المشروع |
| Node.js            | 18 أو 20                                 | لتشغيل الواجهة (Vite)                     |
| Docker Desktop     | آخر إصدار (اختياري)                       | للتشغيل بأمر واحد فقط                     |
| VirtualBox         | آخر إصدار                                | لتشغيل Kali / Ubuntu لاختبار الهجمات       |

---

## الطريقة الأولى: التشغيل بأمر واحد باستخدام Docker

من جذر المشروع افتح PowerShell وشغّل:

```powershell
cd C:\Users\ASUS\Downloads\lightweight-siem
docker compose up --build
```

بعد اكتمال البناء (2-3 دقائق أول مرة):

- الـ Backend: <http://localhost:8000> — التوثيق التفاعلي على <http://localhost:8000/docs>
- الواجهة: <http://localhost:5173>
- بيانات الدخول الافتراضية: **admin** / **ChangeMe123!**

لإيقاف كل شيء: `Ctrl+C` ثم `docker compose down`.
لبدء المشروع من قاعدة بيانات نظيفة: `docker compose down; rm data/siem.db; docker compose up --build`.

---

## الطريقة الثانية: تشغيل يدوي بدون Docker (موصى بها للتطوير)

### الخطوة 1 — تشغيل الـ Backend

```powershell
cd C:\Users\ASUS\Downloads\lightweight-siem\backend

# البيئة الافتراضية موجودة مسبقًا — إذا احتجت إنشاءها من جديد:
# py -3.11 -m venv venv
# .\venv\Scripts\pip install -r requirements.txt

.\venv\Scripts\Activate.ps1
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

عند أول تشغيل ستظهر رسائل مثل:

```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Started reloader process
INFO:     Application startup complete.
```

الـ Backend يقوم تلقائيًا بـ:

1. إنشاء ملف قاعدة البيانات `data/siem.db`
2. إنشاء حساب المدير `admin / ChangeMe123!`
3. إضافة قواعد الكشف الخمس من الوثيقة (مع MITRE + Kill Chain)

### الخطوة 2 — تشغيل الواجهة

في نافذة PowerShell جديدة:

```powershell
cd C:\Users\ASUS\Downloads\lightweight-siem\frontend
npm install     # فقط عند أول مرة
npm run dev
```

ستظهر رسالة: `Local: http://localhost:5173`. افتحها في المتصفح، وسجّل الدخول بـ `admin / ChangeMe123!`.

### الخطوة 3 — تشغيل اختبارات pytest

في نافذة PowerShell ثالثة (مع تفعيل الـ venv):

```powershell
cd C:\Users\ASUS\Downloads\lightweight-siem\backend
.\venv\Scripts\Activate.ps1
pytest -q
```

يجب أن تظهر جميع الاختبارات باللون الأخضر. الاختبارات تُشغَّل على قاعدة بيانات مؤقتة، ولا تلمس `data/siem.db` الحقيقي.

### الخطوة 4 — اختبار طرف-إلى-طرف مع سجلات حقيقية

من جذر المشروع، بعد أن يكون الـ Backend يعمل:

```powershell
python scripts\smoke_test.py
```

هذا الاختبار يقوم بـ **16 فحصًا** يمرّر سجلات حقيقية عبر الـ API:

| # | الفحص                                                                 |
| - | --------------------------------------------------------------------- |
| 1 | فحص الصحة (`/health`) — قاعدة البيانات + محرك الكشف + SOAR             |
| 2 | تسجيل دخول JWT صحيح                                                    |
| 3 | كلمة مرور خاطئة تُرفض بـ 401 (ولا تكشف وجود المستخدم)                    |
| 4 | رفض الوصول غير المصادق عليه                                            |
| 5 | رفض عنوان IP غير صالح بـ 422 (طبقة التحقق)                             |
| 6 | استقبال سجل سليم (تسجيل دخول ناجح) بدون توليد تنبيه                    |
| 7 | **كشف Brute Force**: 6 محاولات فاشلة من نفس IP ← تنبيه HIGH T1110       |
| 8 | **كشف Port Scan**: 12 منفذ مختلف من نفس IP ← تنبيه HIGH T1046           |
| 9 | كشف تغيير ملف حرج `/etc/shadow` ← تنبيه CRITICAL T1098                 |
| 10 | كشف تصعيد صلاحيات عبر `/bin/bash` في sudo ← تنبيه CRITICAL T1548       |
| 11 | نقطة `/api/alerts` تعكس التنبيهات المولّدة                              |
| 12 | كل تنبيه يحتوي MITRE ID و Kill Chain Phase                            |
| 13 | SOAR سجّل إجراء block_ip للـ IP المهاجم (بدون تنفيذ فعلي — record only) |
| 14 | إحصائيات لوحة القيادة صحيحة                                             |
| 15 | تغطية MITRE للقواعد الخمس                                              |
| 16 | **حارس الإيجابيات الكاذبة**: 4 محاولات فاشلة (تحت العتبة) لا تُطلق تنبيه |

Exit code = 0 يعني أن كل شيء يعمل بشكل صحيح.

---

## اختبار الأداة بسجلات حقيقية (بعضها ملوّث)

### الطريقة أ — من داخل المتصفح (Simulation Lab)

بعد تسجيل الدخول، افتح صفحة **Simulation lab** واختر أحد السيناريوهات:

| السيناريو                        | ماذا يحدث؟                                                                   | ماذا تراقب في اللوحة؟                                     |
| -------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------- |
| Network port scan                | 12 محاولة اتصال على منافذ مختلفة من IP وثائقي                                  | تنبيه HIGH T1046 يظهر خلال ثوانٍ                          |
| Credential compromise            | 6 محاولات فاشلة ثم دخول ناجح                                                  | تنبيهان: HIGH brute_force ثم CRITICAL login_after_failure |
| Privilege escalation via sudo    | أمر إداري روتيني (يُتجاهل) ثم `/bin/bash` و `visudo`                          | تنبيه CRITICAL T1548 على الأمر الثاني فقط                  |
| Critical file tampering          | تعديل على `/var/tmp/scratch` (يُتجاهل) ثم `/etc/passwd` و `/etc/shadow`      | تنبيهان منفصلان CRITICAL T1098                             |
| **Full attack chain**            | سلسلة الهجوم كاملة: استطلاع ← اختراق بيانات ← تصعيد صلاحيات ← تثبيت              | كل قواعد الكشف الخمس تعمل، وسلسلة Kill Chain تمتلئ         |

هذه السيناريوهات تمرّر سطور سجل حقيقية (raw log lines) عبر نفس خط الأنابيب الذي يستخدمه أي جهاز حقيقي، فما تراه في اللوحة هو ناتج المحرك الحقيقي وليس بيانات مزيّفة.

### الطريقة ب — من محطة Kali حقيقية

إذا كان لديك Kali VM يعمل على نفس شبكة VirtualBox الخاصة (مثلاً 192.168.56.0/24):

**من Kali (بعد نسخ `scripts/kali_attack.sh` إليه):**

```bash
chmod +x scripts/kali_attack.sh
./scripts/kali_attack.sh \
    --target 192.168.56.20 \
    --siem   http://192.168.56.1:8000 \
    --siem-user admin \
    --siem-pass 'ChangeMe123!' \
    --ssh-user analyst \
    --attack brute_force
```

السكربت يقوم بـ:

1. تشغيل `hydra` حقيقية ضد الهدف (Ubuntu server مثلاً)
2. قراءة `/var/log/auth.log` عبر SSH بعد الهجوم
3. إرسال السطور المطابقة إلى الـ SIEM عبر `POST /api/logs`

النتيجة: SIEM يرى المحاولات الحقيقية لأنها من `auth.log` الحقيقي — لا شيء مزوّر.

### الطريقة ج — سكربت مولّد بايثون مستقل

يعمل من أي جهاز يصل للـ SIEM:

```powershell
# ترافيك عادي (خلفية):
python agent_simulator.py --url http://localhost:8000

# محاكاة هجوم brute force:
python agent_simulator.py --url http://localhost:8000 --attack brute_force --count 8

# قائمة أنواع الهجمات المتاحة:
python agent_simulator.py --list-attacks
```

### الطريقة د — تمرير سطور من ملف log حقيقي عبر cURL

مثال لتمرير سطر واحد من ملف `/var/log/auth.log` حقيقي:

```powershell
# استخرج رمز الدخول أولاً:
$body = @{ username='admin'; password='ChangeMe123!' } | ConvertTo-Json
$response = Invoke-RestMethod -Uri http://localhost:8000/api/auth/login -Method Post -ContentType 'application/json' -Body $body
$token = $response.access_token

# أرسل سطر log حقيقي:
$log = @{ raw_log = 'Failed password for root from 45.146.164.110 port 51742 ssh2'; hostname='web-01' } | ConvertTo-Json
Invoke-RestMethod -Uri http://localhost:8000/api/logs -Method Post -ContentType 'application/json' -Headers @{ Authorization = "Bearer $token" } -Body $log
```

كرّر السطر خمس مرات لترى تنبيه brute_force يظهر في اللوحة.

---

## تكامل مع Wazuh Manager الموجود لديك على Ubuntu

إذا كنت تريد ربط SIEM الخفيف بـ Wazuh الحقيقي (يعمل على Ubuntu VM لديك):

في ملف `.env` بجذر المشروع:

```env
WAZUH_URL=https://192.168.56.30:55000
WAZUH_USERNAME=wazuh
WAZUH_PASSWORD=your-wazuh-password
WAZUH_VERIFY_SSL=false
```

بعد إعادة تشغيل الـ Backend، صفحة **Endpoints** ستدمج عملاء Wazuh مع العملاء المحليين. لو تعذّر الوصول للـ Manager سترى رسالة "unreachable" مع سبب الفشل الحقيقي — لن ترى قائمة عملاء مزوّرة أبدًا.

لتمرير تنبيهات Wazuh نفسها إلى SIEM الخفيف:

```bash
# على Ubuntu VM حيث Wazuh Manager:
python scripts/wazuh_forwarder.py \
    --siem http://192.168.56.1:8000 \
    --siem-user admin \
    --siem-pass 'ChangeMe123!'
```

---

## قائمة الفحص قبل العرض التقديمي

ضع علامة صح بجانب كل بند قبل يوم المناقشة:

- [ ] `docker compose up --build` يعمل بدون أخطاء
- [ ] الواجهة تفتح على 5173 وتظهر لوحة القيادة كاملة
- [ ] `python scripts/smoke_test.py` يعطي 16/16 أخضر
- [ ] `pytest -q` في مجلد backend يعطي جميع الاختبارات باللون الأخضر
- [ ] Simulation → Full attack chain يظهر التنبيهات مباشرة في toast rail
- [ ] فتح تنبيه من صفحة Alerts يظهر السجل المُطلِق + الأدلة المرتبطة + شارات MITRE
- [ ] Rules → تعديل عتبة brute_force من 5 إلى 3 وحفظها ثم توليد 3 محاولات → التنبيه يعمل (يثبت أن القواعد بيانات وليست كود)
- [ ] Response → سجل SOAR يعرض إجراءات الاحتواء بعلامة "record_only"
- [ ] تغيير كلمة مرور admin من الواجهة يعمل، وإعادة الدخول بها ناجحة

---

## المشاكل الشائعة وحلولها

| المشكلة                                                | الحل                                                                                        |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Backend يعطي `ModuleNotFoundError: fastapi`            | فعّل الـ venv أولاً: `.\venv\Scripts\Activate.ps1` ثم شغّل uvicorn                              |
| Frontend يظهر "Backend unreachable" في شاشة الدخول    | تأكد أن الـ Backend يعمل على المنفذ 8000، وأن `VITE_API_URL` في `frontend/.env` صحيح          |
| قاعدة البيانات ملأى بتجارب سابقة                       | `docker compose down; Remove-Item data\siem.db; docker compose up --build`                  |
| تنبيه Wazuh integration يقول "unreachable"            | تحقق أن Ubuntu VM يعمل + `WAZUH_URL` صحيح + شهادة SSL (استخدم `WAZUH_VERIFY_SSL=false`)      |
| WebSocket لا يتّصل (Offline في شريط الحالة)             | تحقق من CORS في `.env` — أضف عنوان مضيف الواجهة في `CORS_ORIGINS`                            |

---

## بنية المشروع الكاملة

راجع `README.md` (الإنجليزي) لبنية المشروع الكاملة، جدول قواعد الكشف، والوضع الأمني.

راجع `docs/architecture.md` لمعرفة **لماذا** هذا التصميم يستبدل Wazuh + Elasticsearch + Kibana بحل خفيف الوزن (لأن ELK وحده يستهلك 3-4 GB RAM، وهو ما لا يتوافق مع هدف < 2 GB في وثيقة المشروع).
