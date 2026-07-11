# تبيّن · Tabayyan

**كشف وتعقيم البيانات الشخصية (PII) بوعي سعودي، لمسارات نماذج اللغة (LLM). محلي بالكامل، صفر telemetry.**

[English README](README.md) · [التوثيق](docs/) · [سجل التغييرات](CHANGELOG.md) · [الترخيص: Apache-2.0](LICENSE)

الإصدار العام الحالي: **v0.10.0** — اسم الحزمة على PyPI هو **`tabayyan-privacy`**، ومساحة الاستيراد وأمر سطر الأوامر ما زالا `tabayyan`.

أدوات كشف الـ PII العامة مبنية حول المعرّفات الغربية وتفوّت السعودية—أو تعلّمها بدون تحقّق. **تبيّن** يكشف البيانات الشخصية السعودية (الهوية الوطنية، الإقامة، الآيبان السعودي، الرقم الضريبي، السجل التجاري، الجوال والهاتف الثابت، جواز السفر، رقم الحدود، العنوان الوطني، الرقم الموحد 700، رقم الملف الطبي) **مع تحقّق فعلي من checksum حيثما وُجد**، ثم يصنّف كل نتيجة حسب فئة البيانات ومستوى الثقة وتصنيف NDMO—عشان تعقّم أو تحجب قبل ما يغادر النص بيئتك إلى أي LLM.

يعمل **offline بالكامل**: صفر اتصال خارجي، صفر telemetry، صفر dependencies في نواة الكشف. التطبيع المضاد للتحايل يزيل المحارف غير المرئية (zero-width/bidi) ويوحّد الأرقام العربية (٠-٩) والفارسية وfullwidth قبل الكشف، مع إسقاط النتائج على المواضع الأصلية.

## التثبيت

```bash
pip install tabayyan-privacy                 # النواة (صفر dependencies)
pip install "tabayyan-privacy[crypto]"       # + خزنة tokenize مشفّرة
pip install "tabayyan-privacy[presidio]"     # + كاشفات Microsoft Presidio
pip install "tabayyan-privacy[fastapi]"      # + وسيط FastAPI / Starlette
```

> **مهاجر من حزمة `tabayyan` القديمة (≤ 0.8.x)؟** أُعيدت تسمية المشروع على
> PyPI إلى `tabayyan-privacy` في 0.9.1، والاستيراد ما زال `tabayyan`.
> الحزمتان تكتبان في نفس مجلد `tabayyan/`، فاحذف القديمة أولاً:
>
> ```bash
> pip uninstall tabayyan && pip install tabayyan-privacy
> ```

## البدء السريع

```python
from tabayyan import scan, scan_and_redact, RedactionMode

for m in scan("الهوية 1158813996، جوال +966512345678"):
    print(m.entity_type.value, m.confidence.value, m.category.value)

print(scan_and_redact("الهوية 1158813996", RedactionMode.MASK).text)
# الهوية [SAUDI_NATIONAL_ID]
```

من الطرفية: `echo "الهوية 1158813996" | tabayyan scan -` — التفاصيل في [docs/cli.md](docs/cli.md).

## أنماط التعقيم

| النمط | المخرَج لهوية وطنية | الاستخدام |
|------|--------------------|-----------|
| `mask` | `[SAUDI_NATIONAL_ID]` | الافتراضي؛ يُبقي النص مقروءاً |
| `remove` | *(حذف كامل)* | إزالة تامة |
| `hash` | `[HASH:f999c93a6934]` | HMAC-SHA256 بمفتاح إلزامي؛ حتمي للربط بلا كشف |
| `partial` | `******3996` | إبقاء آخر N محارف؛ القيم القصيرة تُقنَّع بالكامل |
| `tokenize` | `<SAUDI_NATIONAL_ID_1>` | قابل للعكس عبر خزنة (token → القيمة الأصلية) |

`hash` **يتطلب مفتاحاً غير فارغ** (`--salt` أو `--salt-file` أو متغيّر البيئة
`TABAYYAN_SALT`)؛ عامل مخرجاته كأسماء مستعارة (pseudonymous) لا كإخفاء هوية
كامل. خزنة `tokenize` هي مفتاح العكس—خزّنها بنفس ضوابط البيانات الأصلية
(`tabayyan.vault` يوفّر حفظاً مشفّراً بكلمة مرور).

## نموذج الثقة

- **HIGH** — ينجح في checksum منشور (الهوية، الإقامة، الآيبان، البطاقة). نسبة false positive منخفضة جداً.
- **MEDIUM** — تطابق صيغة قوي بلا checksum (جوال `+966`، إيميل، الرقم الضريبي بسياقه).
- **LOW** — صيغة/سياق فقط، احتمال false positive معتبر (CR، MRN، الأسماء). أكّد قبل التصرف.

## وسيط FastAPI / Starlette

يعقّم أجسام طلبات JSON قبل وصولها لمعالجات المسارات، مع ترشيح بالمسار
والطريقة والحقل، وحد لحجم الجسم، ورفض JSON غير الصالح (400) بدل تمريره،
وحجب فعلي (403) عند تفعيل `block_cross_border`:

```python
from fastapi import FastAPI
from tabayyan.integrations.fastapi import TabayyanPrivacyMiddleware

app = FastAPI()
app.add_middleware(
    TabayyanPrivacyMiddleware,
    destination="https://api.openai.com",
    include_paths={"/chat"},
    include_methods={"POST"},
)
```

التفاصيل الكاملة في [docs/middleware.md](docs/middleware.md).

## Guard و Audit (Azure / OpenAI / Anthropic)

حارس قدام الـ LLM endpoint: يعقّم البيانات الشخصية قبل المغادرة، ويطلع audit
trail—مع **تعليم النقل خارج الحدود (cross-border)** تحت PDPL المادة 29 لأي
endpoint خارجي حقيقي (الوجهات المحلية مثل `localhost` لا تُعلَّم). كل سجل
يحمل تصنيف NDMO للبيانات المكتشفة.

```python
from tabayyan import Guard, AuditLog

guard = Guard(in_kingdom_hosts=["llm.myhospital.health.sa"],
              audit=AuditLog(path="audit.jsonl"))
pr = guard.protect("الهوية 1158813996", destination="https://contoso.openai.azure.com")
pr.audit.cross_border_transfer  # True للـ endpoints الخارجية مع بيانات شخصية
```

ولفّ أي عميل LLM (OpenAI/Azure أو Anthropic، يُكتشف تلقائياً) عبر
`guard.wrap(client, destination=...)`—يشمل التعقيم محتوى الرسائل وحقل
`system` وحمولات أدوات الاستدعاء (tool calls).

## التكامل مع Presidio

تستخدم [Microsoft Presidio](https://microsoft.github.io/presidio/)؟ أضف كاشفات تبيّن المُتحقَّقة بسطر واحد:

```bash
pip install "tabayyan-privacy[presidio]"
```
```python
from presidio_analyzer import AnalyzerEngine
from tabayyan.integrations.presidio import register_saudi_recognizers
analyzer = AnalyzerEngine()
register_saudi_recognizers(analyzer)   # SA_NATIONAL_ID, SA_IQAMA, SA_IBAN, ...
```

## النطاق والحدود (بصدق)

تبيّن **أداة مساعِدة للكشف، مب ضمان امتثال**.

- نجاح الـ checksum يعني القيمة *صحيحة بنيوياً*، **مب** إنها صدرت فعلاً أو تخص شخصاً حقيقياً.
- خوارزمية **الهوية** هي المعيار المجتمعي (مُتحقَّقة تفاضلياً مقابل مرجع مستقل بتطابق 100%) لكنها **مب** مواصفة حكومية رسمية—تحقّق قبل الإنتاج (انظر docs/REFERENCES.md).
- **CR** و **MRN** بلا checksum عام؛ الكشف صيغة + سياق فقط. **الأسماء العربية** heuristic مب ML NER—الـ recall محدود بالتصميم لحماية الـ precision.
- توجد false negatives. لا تجعلها ضابطك الوحيد للبيانات الشخصية أو الصحية.
- المقاييس المنشورة على **بيانات synthetic**؛ لا تمثّل توزيع النصوص الواقعية.
- أمر `scan` يطبع القيم المكتشفة افتراضياً—استخدم `--no-values` قبل توجيه المخرجات إلى سجلات CI.

نموذج التهديد الكامل في [docs/threat-model.md](docs/threat-model.md).

## التحقّق المستقل

| الكاشف | المرجع المستقل |
|---|---|
| الهوية / الإقامة | alhazmy13/Saudi-ID-Validator — تطابق 100% على 50k+ |
| الآيبان | python-stdnum + أمثلة معيارية |
| البطاقة (Luhn) | python-stdnum + أرقام شبكات رسمية |

## الترخيص

[Apache-2.0](LICENSE). المساهمات مرحّب بها—قاعدة واحدة صارمة: **بيانات synthetic فقط، لا تُودِع أي بيانات شخصية حقيقية أبداً.**
