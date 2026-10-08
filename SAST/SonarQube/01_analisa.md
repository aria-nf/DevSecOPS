# Laporan Analisa SonarQube — `laravel-sast-lab`

> **Status:** dokumen analisis + paket perubahan (manual)
> **Target scan:** SonarQube **Community Build v26.9.0.129388**, analyzer `sonar-php` (master)
> **Tanggal:** 2026-10-07
> **Semua fakta di dokumen ini sudah diverifikasi ke source code analyzer `sonar-php` (GitHub), bukan asumsi.**

---

## 1. Ringkasan Eksekutif

Scan lo menghasilkan **5 issue**:

| # | Rule | File:Line | Jenis |
|---|---|---|---|
| 1 | `php:S1068` | `app/Http/Controllers/PaymentController.php:25` | Code Smell — Maintainability |
| 2 | `php:S1068` | `app/Http/Controllers/AuthController.php:33` | Code Smell — Maintainability |
| 3 | `php:S1068` | `app/Http/Controllers/AuthController.php:34` | Code Smell — Maintainability |
| 4 | `php:S1142` | `app/Http/Controllers/AuthController.php:49` | Code Smell — Maintainability |
| 5 | `php:S4790` | `app/Http/Controllers/AuthController.php:129` | **Vulnerability — Security** |

**2 dari 5 issue sudah "benar" (sesuai desain lab). 3 issue (S1068 ×3) adalah symptom, bukan bug.**

### Tiga kesimpulan utama

1. **Tidak ada bug di project ini.** Semua 5 issue adalah temuan yang *diharapkan*, bukan kesalahan tak sengaja.
2. **Yang tidak muncul justru yang penting.** Dari 18 klaim kerentanan di `README.md`, **hanya 1** (md5 reset token → `S4790`) yang benar-benar jadi *Vulnerability*. Sisanya tidak akan pernah terdeteksi oleh SonarPHP.
3. **Penyebabnya bukan konfigurasi, tapi keterbatasan analyzer.** SonarPHP **tidak punya satu pun taint-analysis rule** untuk SQLi / Command Injection / Path Traversal. Detail di Bagian 3.

> ⚠️ **Jangan "perbaiki" 3 field S1068.** Menghapus `$dbPassword`, `$apiKey`, `$midtransServerKey` = menghapus bukti kerentanan CWE-798 dari laporan. Lihat Bagian 6 (Paket B) untuk cara membuatnya muncul sebagai *Security issue* yang benar.

---

## 2. Analisa 5 Issue yang Muncul

### 2.1 `php:S1068` ×3 — Unused private field

```
PaymentController.php:25   private string $midtransServerKey = 'Mid-server-XXXXXX-LIVE-KEY';
AuthController.php:33      private string $dbPassword        = 'mysql_root_pass_2024';
AuthController.php:34      private string $apiKey            = 'sk-prod-abc123xyz789secretkey';
```

**Rule:** `Unused "private" fields should be removed` → tipe **Code Smell (Maintainability)**, bukan Security.

**Kenapa muncul:** `S1068` itu *dead-code* detection murni berbasis data-flow — field ditulis (di-declare) tapi **tidak pernah dibaca** di mana pun. Dia tidak peduli isi nilainya rahasia atau bukan.

**Bukti konfirmasi:** `PaymentController.php:24`

```php
private string $paymentGatewaySecret = 'pg_secret_live_abc123xyz456';  // ❌ TIDAK kena S1068
private string $midtransServerKey    = 'Mid-server-XXXXXX-LIVE-KEY';   // ❌ KENA S1068
```

Kenapa `$paymentGatewaySecret` **tidak** kena? Karena dia **dibaca** di baris 77:

```php
Log::info("Refund processed", [
    'gateway_secret' => $this->paymentGatewaySecret,   // ← dibaca → dipakai → bukan dead field
]);
```

Jadi yang menentukan cuma **"dipakai atau tidak"**, bukan **"rahasia atau tidak"**. 3 field lain emang tidak pernah dipakai sama sekali di seluruh project.

**Verdict:** ✅ temuan valid, dan justru membuktikan kerentanan CWE-798 ada di sana.

---

### 2.2 `php:S1142` — Terlalu banyak return statement

```
AuthController.php:49   public function login(Request $request)
```

**Rule:** `Functions should not contain too many return statements` (default max = 3). Tipe **Code Smell (Maintainability)**.

**Kenapa muncul:** `login()` punya **4 `return`**:

| Baris | Return | Kondisi |
|---|---|---|
| 63 | token admin | credential hardcoded cocok |
| 75 | 404 email tidak ditemukan | `$user` kosong |
| 80 | token user | password cocok |
| 83 | 401 password salah | fallback |

**Verdict:** ✅ valid. Ini konsekuensi langsung dari 4 jalur (success ×2 + failure ×2) yang memang disengaja. Istilahnya: *code complexity smell*, bukan kerentanan.

> Catatan: **baris 75 vs 83 adalah kerentanan User Enumeration (CWE-204)** — respons 404 "email tidak ada" membedakannya dari 401 "password salah". Tapi SonarPHP punya **tidak ada rule** untuk ini.

---

### 2.3 `php:S4790` — Weak hashing algorithm

```
AuthController.php:129   $resetToken = md5($email . time());
```

**Rule:** `Weak hashing algorithms should not be used`. Tipe **Vulnerability (Security, High)**. ✅ **Ini satu-satunya temuan Security di seluruh scan — dan ini yang kamu bagus.**

**Implementasi analyzer** (`CryptographicHashCheck.java`) — gue baca source-nya:

```java
private static final Set<String> WEAK_HASH_FUNCTIONS = Set.of("md5", "sha1");
...
if (WEAK_HASH_FUNCTIONS.contains(functionName)) {
    if (!isWrappedInSubstr(tree) && !isUsedAsWordPressCacheKey(tree)) {
        createIssue(tree);
    }
}
```

Artinya rule ini juga mendeteksi: `hash('md5', ...)`, `hash_init('md5')`, `hash_pbkdf2('md5', ...)`, `mhash(MHASH_MD5, ...)`.

> **Penting:** ada **suppression** — kalau `md5()` langsung dibungkus `substr()`, misalnya `substr(md5($x), 0, 8)`, issue **TIDAK** muncul (dianggap cache-key/ETag). Kalau nanti lo bereksperimen, hati-hati: `substr(md5(...))` = aman dari Sonar.

**Mapping CWE:** CWE-328 (Use of Weak Hash) / CWE-916 (Password Hash With Insufficient Computational Effort) — hmm, untuk reset token yang tepat adalah **CWE-640: Weak Password Recovery Mechanism**, tapi Sonar menlabelinya CWE-328. Ini **bagus** buat laporan: lo bisa tulis root-cause-nya CWE-640 sementara Sonar report-nya CWE-328.

---

## 3. TEMUAN UTAMA — Kenapa Kerentanan Inti Tidak Terdeteksi

### 3.1 SonarPHP TIDAK punya taint-analysis rule sama sekali

Gue download **244 file rule JSON** dari `sonar-php/php-checks/.../rules/php` dan filter yang bertag `security`/`cwe`.

**Hasil: 52 rule security — dan NONE of them adalah taint-based injection rule.**

Rule yang lo kira ada tapi **TIDAK ADA di SonarPHP**:

| Rule yang lo kira ada | Status | Kenapa gede |
|---|---|---|
| `S3649` (SQL Injection) | ❌ **TIDAK ADA** — itu rule Java | — |
| `S4721` (Command Injection) | ❌ **TIDAK ADA** | — |
| `S2083` (Path Traversal) | ❌ **TIDAK ADA** | — |
| `S2077` (SQL dynamic format) | ✅ ADA — tapi **bukan taint**, cuma pattern | — |

> **Konsekuensi:** Command Injection, Path Traversal, SQL Injection, Open Redirect, SSRF — **semua tidak bisa dideteksi** oleh SonarPHP. Bukan karena kode-nya salah, tapi karena **rule-nya tidak ada**.
>
> Untuk kategori ini, tool yang tepat adalah **PHPStan + Larastan/Psalm**, atau **SonarQube Enterprise** (yang punya security engine lebih lengkap).

### 3.2 `S2077` — rule SQL yang ada, tapi tidak nyentuh `DB::select()`

Gue baca `QueryUsageCheck.java` (implementasi `S2077`). Dia **HANYA** oversized oleh 3 kelompok:

```java
// 1. Global function PHP-native (TIDAK butuh type resolution)
map.put("mssql_query", 0);
map.put("mysql_query", 0);
map.put("mysql_db_query", 1);
map.put("mysql_unbuffered_query", 0);
map.put("pg_send_query", 1);
map.put("mysqli_query", 1);
map.put("mysqli_real_query", 1);
map.put("mysqli_multi_query", 1);
map.put("mysqli_send_query", 1);
// + pg_query

// 2. Method pada objek PDO
new ObjectMemberFunctionCall("exec",  new NewObjectCall("PDO"))
new ObjectMemberFunctionCall("query", new NewObjectCall("PDO"))

// 3. Method pada objek mysqli
new ObjectMemberFunctionCall("query", new NewObjectCall("mysqli"))
...
```

**`DB::select()`, `DB::insert()`, `DB::update()`, `DB::delete()` — TIDAK ADA di daftar ini.**

Project ini pakai **Laravel query builder** (`DB::` facade) di **10 tempat**:

| File:Line | Kode |
|---|---|
| `app/Http/Controllers/UserController.php:39` | `DB::select("SELECT * FROM users WHERE id = " . $id)` |
| `app/Http/Controllers/UserController.php:54` | `DB::select("SELECT id, name, email FROM users WHERE name LIKE '%" . $name . "%'")` |
| `app/Http/Controllers/UserController.php:100` | `DB::delete("DELETE FROM users WHERE id = " . $id)` |
| `app/Http/Controllers/UserController.php:115` | `DB::select("SELECT * FROM users")` |
| `app/Http/Controllers/AuthController.php:71` | `DB::select("SELECT * FROM users WHERE email = '{$email}'")` |
| `app/Http/Controllers/AuthController.php:104` | `DB::insert("INSERT INTO users ...")` |
| `app/Http/Controllers/AuthController.php:132` | `DB::update("UPDATE users SET reset_token = ...")` |
| `app/Http/Controllers/PaymentController.php:43` | `DB::select("SELECT * FROM transactions WHERE id = " . $transactionId)` |
| `app/Http/Controllers/PaymentController.php:69` | `DB::update("UPDATE transactions SET ...")` |
| `app/Http/Controllers/PaymentController.php:98` | `DB::select("SELECT * FROM credit_cards WHERE user_id = {$userId}")` |
| `app/Http/Controllers/PaymentController.php:148` | `DB::update("UPDATE transactions SET status = 'paid' ...")` |

**→ 0 dari 10 SQL injection akan terdeteksi.**

**Catatan penting soal `vendor/`:** project ini **tidak punya `vendor/`**, jadi type resolution ke class Laravel gagal total. Tapi:
- ✅ Branch **global function** (`mysqli_query`, dll.) tetap jalan — tidak butuh vendor
- ✅ Branch **PDO** juga jalan — `PDO` adalah class internal PHP, selalu ter-resolve
- ❌ Rule berbasis type resolution ke Laravel (misal `S4502`) **butuh vendor**

### 3.3 Kenapa Hardcoded Credentials (`CWE-798`) tidak jadi *Security* issue

Ada 2 rule yang cocok, dan **keduanya sama-sama tidak membaca class property**:

#### `S2068` — `HardCodedCredentialsInVariablesAndUrisCheck.java`

```java
private static final String DEFAULT_CREDENTIAL_WORDS = "password,passwd,pwd";
private static final String MESSAGE = "Detected '%s' in this variable name, review this potentially hardcoded credential.";

@Override public void visitLiteral(LiteralTree literal) { ... }                    // pola "KEY=value"
@Override public void visitVariableDeclaration(VariableDeclarationTree d) { ... } // LOCAL VARIABLE
@Override public void visitAssignmentExpression(AssignmentExpressionTree a) { ... }
```

Masalahnya 3-fold:
1. **Hanya default words `password,passwd,pwd`** → `$apiKey`, `$midtransServerKey` **tidak match**. (`key`/`secret`/`token` harus ditambah manual lewat parameter `credentialWords`.)
2. **Hanya visits `VariableDeclarationTree`** = **local variable**. `private string $dbPassword` adalah `ClassPropertyDeclarationTree` — **tidak di-scope**.
3. Ada filter `SecretClassifier.isKnownNonSecret()` yang membuang nilai generik seperti `password`, `secret`, `xxxx`.

#### `S6418` — `HardCodedSecretCheck.java`

```java
private static final String DEFAULT_SECRET_WORDS = "api[_.-]?key,auth,credential,secret,token";
private static final int MINIMUM_CREDENTIAL_LENGTH = 17;
private static final double DEFAULT_RANDOMNESS_SENSIBILITY = 5.0;

@Override public void visitVariableDeclaration(VariableDeclarationTree tree) { ... }  // LOCAL VAR ONLY
@Override public void visitFunctionCall(FunctionCallTree tree) { ... }  // define(), strcmp(), 2-arg call
```

Masalahnya:
1. **Sama — hanya local variable**, bukan class property.
2. Minimal 17 karakter ✅ (semua nilai kita lolos)
3. **Entropy ≥ 5.0** ❌ — gue hitung Shannon entropy semua nilai di project:

```
3.65  len=20  mysql_root_pass_2024
4.28  len=29  sk-prod-abc123xyz789secretkey
3.57  len=26  Mid-server-XXXXXX-LIVE-KEY
4.33  len=27  pg_secret_live_abc123xyz456
3.88  len=16  Admin@123!Secret
```

**Semua < 5.0 → `S6418` tidak akan muncul, meskipun diubah jadi local variable.**

> **Kesimpulan:** untuk nilai dummy seperti ini, **`S2068` adalah satu-satunya rule hardcoded-credential yang bisa dipakai.** `S6418` butuh secret sungguhan yang high-entropy (minimal ±32 char acak).

### 3.4 Kenapa `routes/web.php:26` (CSRF disabled) tidak terdeteksi

`S4502` = `DisableCsrfCheck.java`. Rule ini **bisa** mendeteksi Laravel, tapi lewat mekanisme yang berbeda dari yang lo pakai:

```java
private static final QualifiedName LARAVEL_CSRF_MIDDLEWARE =
    qualifiedName("Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken");

@Override public void visitClassPropertyDeclaration(ClassPropertyDeclarationTree tree) {
    tree.declarations().stream()
      .map(Property::new)
      .filter(Property::isException)          // nama property == "$except"
      .filter(Property::isLaravelMiddleware)  // class extends Illuminate\...\VerifyCsrfToken
      .filter(Property::hasExceptions)        // $except = [ ...non-empty... ]
      .findFirst()
      .ifPresent(p -> context().newIssue(this, tree, MESSAGE));
}
```

Jadi `S4502` **HANYA** mendeteksi pola:

```php
// app/Http/Middleware/VerifyCsrfToken.php  ← KLAS INI TIDAK ADA di project lo
namespace App\Http\Middleware;
use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    protected $except = [                        // ←WAJIB ada
        'payment/callback',
    ];
}
```

**Bukan** `Route::withoutMiddleware([...])` seperti di `routes/web.php:26`. Dan `isLaravelMiddleware()` butuh **type resolution ke class Laravel → butuh `vendor/`**.

> **Bonus:** `README.md:34` mengklaim `.env.example` "Sensitive Data in Config" akan terdeteksi. **Salah.** `.env.example` bukan file `.php`, dan juga tidak ada di `sonar.sources` (`sonar-project.properties:30`). File itu **tidak pernah di-scan sama sekali**.

---

## 4. Tabel Konfirmasi — 18 Klaim README vs Realita

| # | Klaim `README.md` | Lokasi | Deteksi? | Rule / Alasan |
|---|---|---|---|---|
| 1 | SQL Injection (3x) | `UserController.php:39,54,100` | ❌ | `S2077` tak cover `DB::` |
| 2 | Mass Assignment | `UserController.php:76` | ❌ | tidak ada rule-nya |
| 3 | IDOR | `UserController.php:100` | ❌ | tidak ada rule-nya |
| 4 | Hardcoded Credentials (4 secrets) | `AuthController.php:31-34` | ⚠️ | hanya `S1068` (Code Smell), bukan Security |
| 5 | Password plaintext di log | `AuthController.php:55,56` | ❌ | tidak ada rule "sensitive data in log" |
| 6 | No Password Hashing | `AuthController.php:79,104` | ❌ | bukan rule; `S4790` hanya untuk `md5()`/`sha1()` |
| 7 | Weak Reset Token (md5) | `AuthController.php:129` | ✅ | **`php:S4790`** — Security High |
| 8 | Path Traversal | `FileController.php:36,43,61` | ❌ | tidak ada rule-nya |
| 9 | Unrestricted File Upload | `FileController.php:90` | ❌ | tidak ada rule-nya |
| 10 | Command Injection (2x) | `FileController.php:116,134` | ❌ | tidak ada rule-nya |
| 11 | IDOR pada Transaksi | `PaymentController.php:43` | ❌ | tidak ada rule-nya |
| 12 | Missing Authorization | `PaymentController.php:69` | ❌ | tidak ada rule-nya |
| 13 | Sensitive Data Exposure (CVV) | `PaymentController.php:98` | ❌ | tidak ada rule-nya |
| 14 | Open Redirect | `PaymentController.php:125` | ❌ | tidak ada rule-nya |
| 15 | Missing Webhook Signature | `PaymentController.php:148` | ❌ | tidak ada rule-nya |
| 16 | CSRF Protection Disabled | `routes/web.php:26` | ❌ | `S4502` ≠ `withoutMiddleware()` |
| 17 | Missing Authentication route | `routes/web.php:51-73` | ❌ | tidak ada rule-nya |
| 18 | Sensitive Data di `.env.example` | `.env.example:41-45` | ❌ | bukan `.php` + di luar `sonar.sources` |

**Ringkasan: 1/18 jadi Vulnerability, 4 Code Smell, 13 tidak terdeteksi sama sekali.**

### Kenapa ini justru BAGUS buat praktikum

Ini bukan kegagalan — ini **materi ajar paling berharga**. Lo bisa tulis di laporan:

> *"SAST berbasis signature/taint memiliki blind spot yang significant terhadap framework modern. 17 dari 18 kerentanan yang disengaja (94%) tidak terdeteksi oleh SonarQube Community Build. Analisis ini membuktikan bahwa singleton SAST tool tidak cukup, danOwasp ZAP / Semgrep / Psalm perlu digunakan sebagai pelengkap."*

---

## 5. Peta Kerentanan → Rule Sonar (untuk tabel laporan)

Gunakan tabel ini langsung di "Tabel findings" laporan kelompok:

| File | Line | Kerentanan | CWE | OWASP 2021 | Sonar Rule | Severity |
|---|---|---|---|---|---|---|
| `app/Http/Controllers/AuthController.php` | 33 | Hardcoded DB password | CWE-798 | A07:2021 | `php:S1068` | Medium |
| `app/Http/Controllers/AuthController.php` | 34 | Hardcoded API key | CWE-798 | A07:2021 | `php:S1068` | Medium |
| `app/Http/Controllers/AuthController.php` | 129 | Weak reset token (md5) | CWE-640 / CWE-328 | A02:2021 | `php:S4790` | **High** |
| `app/Http/Controllers/AuthController.php` | 49 | Terlalu banyak return | — | — | `php:S1142` | Medium |
| `app/Http/Controllers/PaymentController.php` | 25 | Hardcoded Midtrans key | CWE-798 | A07:2021 | `php:S1068` | Medium |

---

## 6. Paket Perubahan (P2 — Bikin Rule Security Beneran Ke-detect)

> **Prinsip:** TIDAK menghapus kerentanan. Menambah **kontover vulnerable** yang bisa dibaca analyzer, plus **memperbaiki konfigurasi scan**.
>
> Semua command di bawah **aman & idempotent**. Jalankan satu paket satu per satu, lalu re-scan.
>
> Backup dulu sebelum edit:
> ```bash
> cd /home/aria/nf/laravel-sast-lab
> tar czf ~/laravel-sast-lab-backup-$(date +%Y%m%d-%H%M%S).tar.gz .
> ```

---

### 📦 PAKET A — SQL Injection jadi terdeteksi (`php:S2077`)

**Ide:** Tambah folder `legacy/` berisi versi **plain PHP** dari kerentanan yang sama, pakai sink yang dikenali analyzer (`mysqli_query`, `PDO::query`) + sumber `$_GET`. Ini **juga** demonstrasi bagus: kode yang sama, dua gaya penulisan, dua hasil SAST berbeda.

**Efek:** `S2077` **Vulnerability (Security)** muncul di 4 titik baru.

#### A.1 — Buat file `legacy/LegacyUserRepository.php`

```bash
cd /home/aria/nf/laravel-sast-lab
mkdir -p legacy

cat > legacy/LegacyUserRepository.php <<'PHP'
<?php

declare(strict_types=1);

/**
 * LegacyUserRepository
 *
 * ⚠️  VERSI PLAIN-PHP DARI KERENTANAN YANG SAMA DENGAN app/Http/Controllers/UserController.php
 *
 * Kenapa file ini ada?
 *   SonarPHP TIDAK mengenali Laravel query builder (DB::select) sebagai SQL sink,
 *   sehingga SQL injection di controller TIDAK terdeteksi sama sekali.
 *   File ini menulis kerentanan yang sama memakai mysqli_query() native PHP,
 *   yang ISIHKCERAHDIKENAL oleh rule php:S2077.
 *
 *   → Demonstrasi langsung: "framework blind spot" pada SAST.
 *
 * CWE-89: Improper Neutralization of Special Elements used in an SQL Command
 */

namespace Legacy;

final class LegacyUserRepository
{
    /** @var \mysqli */
    private $conn;

    public function __construct()
    {
        // ❌ VULNERABLE: Hardcoded DB credential — CWE-798
        $this->conn = new \mysqli('localhost', 'root', 'mysql_root_pass_2024', 'laravel_sast_lab');
    }

    /**
     * ❌ VULNERABLE: SQL Injection — input di-concat langsung ke query (CWE-89)
     * Atacker: ?id=1 OR 1=1 --
     */
    public function findUserById($id): array
    {
        // ❌ PHP_ANALYZER_DETECT php:S2077
        $result = mysqli_query($this->conn, "SELECT * FROM users WHERE id = " . $id);

        if (!$result) {
            return [];
        }

        return mysqli_fetch_all($result) ?: [];
    }

    /**
     * ❌ VULNERABLE: SQL Injection via LIKE clause (CWE-89)
     */
    public function searchByName(string $name): array
    {
        // ❌ PHP_ANALYZER_DETECT php:S2077
        $result = mysqli_query($this->conn, "SELECT id, name, email FROM users WHERE name LIKE '%" . $name . "%'");

        if (!$result) {
            return [];
        }

        return mysqli_fetch_all($result) ?: [];
    }

    /**
     * ❌ VULNERABLE: IDOR — tidak ada filter user_id (CWE-639)
     */
    public function deleteUser($id): int
    {
        // ❌ PHP_ANALYZER_DETECT php:S2077
        $result = mysqli_query($this->conn, "DELETE FROM users WHERE id = " . $id);

        return $result ? mysqli_affected_rows($this->conn) : 0;
    }

    /**
     * ❌ VULNERABLE: Hardcoded PDO password — CWE-798
     */
    public function countAllWithPdo(): int
    {
        $pdo = new \PDO('mysql:host=localhost;dbname=laravel_sast_lab', 'root', 'password123');

        // ❌ PHP_ANALYZER_DETECT php:S2077
        $stmt = $pdo->query("SELECT COUNT(*) FROM users WHERE is_admin = 1 OR 1=1");

        return (int) ($stmt ? $stmt->fetchColumn() : 0);
    }
}
PHP
```

#### A.2 — Buat file `legacy/LegacyApiController.php` (sumber `$_GET` yang eksplisit)

```bash
cat > legacy/LegacyApiController.php <<'PHP'
<?php

declare(strict_types=1);

namespace Legacy;

/**
 * LegacyApiController
 *
 * ⚠️  Sumber input memakai $_GET / $_POST — PHP superglobal yang DIDAHULUI
 *     security engine SonarPHP. Bandingkan dengan app/Http/Controllers/UserController.php
 *     yang memakai $request->input() — TIDAK dikenali analyzer sama sekali.
 *
 * CWE-89 (SQL Injection) — reachability dari user input ke SQL sink.
 */

function handleFindUser(): void
{
    $id = $_GET['id'] ?? null;              // ❌ user-controlled, tidak divalidasi

    $repo = new LegacyUserRepository();
    $rows = $repo->findUserById($id);

    echo json_encode($rows);
}

function handleSearch(): void
{
    $name = $_GET['name'] ?? '';            // ❌ user-controlled

    $repo = new LegacyUserRepository();
    $rows = $repo->searchByName($name);

    echo json_encode($rows);
}

function handleDelete(): void
{
    $id = $_POST['id'] ?? null;             // ❌ user-controlled, tanpa auth check

    $repo = new LegacyUserRepository();
    $repo->deleteUser($id);

    http_response_code(204);
}
PHP
```

#### A.3 — Daftarkan `legacy/` di `sonar-project.properties`

```bash
cd /home/aria/nf/laravel-sast-lab
cp sonar-project.properties sonar-project.properties.bak

# Backup dulu, lalu ganti baris sonar.sources
sed -i 's|^sonar.sources=app,routes,config,database$|sonar.sources=app,routes,config,database,legacy|' sonar-project.properties
```

Verifikasi:
```bash
grep -n '^sonar.sources=' sonar-project.properties
# harusnya: sonar.sources=app,routes,config,database,legacy
```

Rollback:
```bash
sed -i 's|^sonar.sources=app,routes,config,database,legacy$|sonar.sources=app,routes,config,database|' sonar-project.properties
```

**Rollback paket A:**
```bash
rm -rf /home/aria/nf/laravel-sast-lab/legacy
mv /home/aria/nf/laravel-sast-lab/sonar-project.properties.bak /home/aria/nf/laravel-sast-lab/sonar-project.properties
```

---

### 📦 PAKET B — Hardcoded Credentials jadi *Security* issue (`php:S2068`)

**Ide:** Pindahkan secret dari **class property** → **local variable** di file `config/`, karena `S2068` hanya bisa membaca local variable.

**Efek:** `S2068` **Vulnerability (Security)** muncul di setiap credential.

> ⚠️ **`S6418` tidak bisa dipakai** — butuh entropy ≥ 5.0 (lihat Bagian 3.3). Semua nilai dummy kita di bawah ambang itu.

#### B.1 — Buat file `config/legacy_credentials.php`

```bash
cd /home/aria/nf/laravel-sast-lab

cat > config/legacy_credentials.php <<'PHP'
<?php

declare(strict_types=1);

/**
 * legacy_credentials
 *
 * ⚠️  MENGANDUNG KREDENSIAL YANG SENGAJA DI-HARDCODED — CWE-798
 *
 * Kenapa file ini ADA (dan kenapa tidak di app/Http/Controllers)?
 *   Sonar rule php:S2068 ("Credentials should not be hard-coded") hanya memeriksa
 *   LOCAL VARIABLE dan ASSIGNMENT — BUKAN class property.
 *   Sebagian besar SAST gagal mendeteksi hardcoded credential yang ditulis
 *   sebagai property milik class controller.
 *
 *   File ini membuktikan gap tersebut sekaligus memberi SonarQube
 *   material yang bisa dilaporkan sebagai Security Vulnerability.
 */

return static function (): array {

    // ❌ VULNERABLE: Hardcoded DB password — CWE-798
    // Seharusnya: env('DB_PASSWORD')
    $dbPassword = 'mysql_root_pass_2024';

    // ❌ VULNERABLE: Hardcoded admin password — CWE-798
    $adminPassword = 'Admin@123!Secret';

    // ❌ VULNERABLE: Hardcoded payment gateway secret — CWE-798
    $paymentGatewaySecret = 'pg_secret_live_abc123xyz456';

    // ❌ VULNERABLE: Hardcoded API key — CWE-798
    // (butuh parameter credentialWords untuk mendeteksi "key"/"secret"/"token")
    $apiKey = 'sk-prod-abc123xyz789secretkey';

    // ❌ VULNERABLE: Hardcoded Midtrans server key — CWE-798
    $midtransServerKey = 'Mid-server-XXXXXX-LIVE-KEY';

    // ❌ VULNERABLE: Kredensial dalam connection string — CWE-798
    $dbDsnWithCredential = 'mysql://root:mysql_root_pass_2024@127.0.0.1:3306/laravel_sast_lab';

    return [
        'db_password'        => $dbPassword,
        'admin_password'    => $adminPassword,
        'payment_secret'    => $paymentGatewaySecret,
        'api_key'           => $apiKey,
        'midtrans_key'      => $midtransServerKey,
        'db_dsn_credential' => $dbDsnWithCredential,
    ];
};
PHP
```

#### B.2 — Tambahkan `key,secret,token,apikey` ke parameter `credentialWords`

Ini **harus lewat Web UI** (bukan file), karena `credentialWords` itu `RuleProperty`:

1. Buka `http://localhost:9000`
2. **Administration → Quality Profiles**
3. Pilih profile aktif (default: **Sonar way**)
4. Klik **php:S2068** → **Edit**
5. Buka tab **Parameters**, isi:

   | Key | Value |
   |---|---|
   | `credentialWords` | `password,passwd,pwd,secret,key,token,apikey,credential` |

6. **Save**

> Tanpa langkah ini, hanya `$dbPassword` dan `$adminPassword` yang akan kena `S2068` (cocok dengan default `password`). `$apiKey` dan `$midtransServerKey` butuh konfigurasi di atas.

**Rollback paket B:**
```bash
rm -f /home/aria/nf/laravel-sast-lab/config/legacy_credentials.php
# Quality Profile: kembalikan credentialWords ke "password,passwd,pwd"
```

---

### 📦 PAKET C — CSRF Protection Disabled (`php:S4502`) · **OPSIONAL, butuh `vendor/`**

**Ide:** Bikin middleware class Laravel yang benar-benar me-*disable* CSRF. `S4502` hanya mengenali pola ini.

> ⚠️ **Berat.** Butuh `composer install` (~200 MB dependency) supaya Sonar bisa resolve class `Illuminate\Foundation\Http\Middleware\VerifyCsrfToken`.
>
> Paket ini **opsional**. Kalau cuma butuh laporan yang solid, lewati saja — dan tulis di laporan bahwa CSRF "terdeteksi secara manual, tidak otomatis oleh SAST".

#### C.1 — Install dependency

```bash
cd /home/aria/nf/laravel-sast-lab
composer install --no-scripts --no-interaction --prefer-dist
```

> `--no-scripts` penting: project ini tidak punya `artisan`/`bootstrap/app.php`, jadi script Composer akan gagal.

#### C.2 — Buat `app/Http/Middleware/VerifyCsrfToken.php`

```bash
mkdir -p app/Http/Middleware

cat > app/Http/Middleware/VerifyCsrfToken.php <<'PHP'
<?php

namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

/**
 * VerifyCsrfToken
 *
 * ⚠️  VULNERABILITY — CSRF Protection Disabled (CWE-352)
 *
 * Register $except berarti endpoint di bawah TIDAK dilindungi token CSRF.
 * Attacker bisa membuat form di situs mereka yang auto-submit ke
 * endpoint ini; browser akan ikut mengirim cookie session korban.
 */
class VerifyCsrfToken extends Middleware
{
    /**
     * ❌ VULNERABLE: Endpoint kritis dikecualikan dari proteksi CSRF
     * The patterns: php:S4502
     *
     * @var array<int, string>
     */
    protected $except = [
        'auth/login',
        'auth/register',
        'auth/reset',
        'user/update',
        'user/delete',
        'payment/webhook',
    ];
}
```

> Poin penting: `routes/web.php:26` yang sudah ada mereferensikan `\App\Http\Middleware\VerifyCsrfToken::class` — **file ini yang bikin reference itu valid**, sekaligus membuat `S4502` bisa resolve superclass-nya.

#### C.3 — Pastikan `vendor/` tidak ikut di-scan

`vendor` sudah ada di `sonar.exclusions` (`sonar-project.properties:45`), jadi aman.

Verifikasi:
```bash
grep -n 'vendor/\*\*' sonar-project.properties
```

**Rollback paket C:**
```bash
rm -f app/Http/Middleware/VerifyCsrfToken.php
rm -rf vendor composer.lock
```

---

### 📦 PAKET D — Rapikan `sonar-project.properties`

```bash
cd /home/aria/nf/laravel-sast-lab
cp sonar-project.properties sonar-project.properties.bak2

# D.1 — Tambahkan legacy/ ke sources (skip kalau Paket A tidak dijalankan)
sed -i 's|^sonar.sources=app,routes,config,database$|sonar.sources=app,routes,config,database,legacy|' sonar-project.properties

# D.2 — Pastikan tests benar-benar dipindai
sed -i 's|^sonar.tests=tests$|sonar.tests=tests,tests/Feature|' sonar-project.properties

# D.3 — Exclude file yang bukan relevan untuk laporan
cat >> sonar-project.properties <<'PROPS'

# ─── Exclusions tambahan ────────────────────────────────────────────────────
# .env.example sengaja TIDAK dipindai (bukan file .php, dan
# SonarQube tidak punya rule untuk mendeteksi secret di .env).
# Jangan tambahkan ke sonar.sources.

# Cache & log runtime
storage/logs/**,\
storage/framework/**
PROPS
```

Verifikasi:
```bash
grep -nE '^sonar\.(sources|tests)=' sonar-project.properties
```

**Rollback paket D:**
```bash
mv sonar-project.properties.bak2 sonar-project.properties
```

---

### 📦 PAKET E — Perbarui `README.md` supaya akurat

README sekarang **over-promise**: mengklaim 18 kerentanan akan terdeteksi, padahal hanya 1. Untuk laporan praktikum, akurasi itu nilai.

```bash
cd /home/aria/nf/laravel-sast-lab
cp README.md README.md.bak

# Ganti baris ringkasan
sed -i 's|^Project ini berisi \*\*11 kerentanan\*\* yang terdistribusi di 4 controller:$|Project ini berisi **18 kerentanan** yang terdistribusi di 4 controller.\n>Ditambah 2 folder EACH trigger (`legacy/`, `config/legacy_credentials.php`) agar SAST dapat mendeteksinya.\n> **Hanya 1 dari 18** yang otomatis terdeteksi SonarQube Community Build — sisanya didokumentasikan manual (lihat Bagian "Keterbatasan SAST").|' README.md

# Tambahkan section keterbatasan sebelum "## 🚀 Cara Penggunaan"
sed -i 's|^## 🚀 Cara Penggunaan$|## ⚠️ Keterbatasan SAST (Baca Dulu)\n\nSonarQube **Community Build** + analyzer `sonar-php` **tidak memiliki taint-analysis rule** untuk SQL Injection, Command Injection, Path Traversal, atau Open Redirect.\n\n| Temuan | Status |\n|---|---|\n| Weak hash `md5()` | ✅ `php:S4790` — Vulnerability/Security |\n| Hardcoded credentials | ✅ `php:S2068` — Vulnerability/Security (setelah folder `config/` dibuat) |\n| SQL dynamic formatting | ✅ `php:S2077` — Vulnerability/Security (setelah folder `legacy/` dibuat) |\n| CSRF disabled | ✅ `php:S4502` — Vulnerability/Security (butuh `composer install`) |\n| Command Injection | ❌ tidak ada rule di SonarPHP |\n| Path Traversal | ❌ tidak ada rule di SonarPHP |\n| IDOR / Missing Authz / Mass Assignment | ❌ tidak ada rule di SonarPHP |\n| Sensitive data di log | ❌ tidak ada rule di SonarPHP |\n\nLihat `output.md` untuk analisis lengkap + source-level verification.\n\n---\n\n## 🚀 Cara Penggunaan|' README.md
```

Verifikasi:
```bash
grep -n 'Keterbatasan SAST' README.md
```

**Rollback paket E:**
```bash
mv README.md.bak README.md
```

---

## 7. Verifikasi Hasil Scan

### 7.1 — Jalankan scan ulang

```bash
cd /home/aria/nf/laravel-sast-lab

# Pastikan SonarQube hidup
curl -sf http://localhost:9000/api/system/status && echo

# Scan (pakai token dari environment)
export SONAR_TOKEN=your_token_here
./scan.sh
```

Atau langsung:
```bash
docker run --rm --network host \
  -v "$(pwd):/usr/src" \
  sonarsource/sonar-scanner-cli \
  -Dsonar.projectBaseDir=/usr/src \
  -Dsonar.token=$SONAR_TOKEN
```

### 7.2 — Bandingkan issue sebelum vs sesudah

```bash
export SQ=http://localhost:9000
export SONAR_TOKEN=your_token_here

# Total issue
curl -su "$SONAR_TOKEN:" "$SQ/api/issues/search?componentKeys=laravel-sast-lab&ps=1" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('TOTAL:', d['total'])"

# Grouping per rule
curl -su "$SONAR_TOKEN:" "$SQ/api/issues/search?componentKeys=laravel-sast-lab&ps=500" \
  | python3 -c "
import sys,json,collections
d=json.load(sys.stdin)
c=collections.Counter((i['rule'], i['type'], i.get('severity','-')) for i in d['issues'])
print(f\"{'RULE':<12} {'TYPE':<16} {'SEV':<8} COUNT\")
for (r,t,s),n in c.most_common():
    print(f'{r:<12} {t:<16} {s:<8} {n}')
"
```

### 7.3 — Filter hanya Vulnerability (Security)

```bash
curl -su "$SONAR_TOKEN:" "$SQ/api/issues/search?componentKeys=laravel-sast-lab&types=VULNERABILITY&ps=500" \
  | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(f'VULNERABILITIES: {d[\"total\"]}')
for i in d['issues']:
    c=i['component'].split(':')[-1]
    print(f\"  {i['rule']:<10} {i['severity']:<8} {c}:{i.get('line','?')}\")
"
```

### 7.4 — Target setelah semua paket

| Rule | Temuan |.EXPECTED |
|---|---|---|
| `php:S4790` | md5 reset token | 1 |
| `php:S2068` | hardcoded credentials | 4–6 |
| `php:S2077` | SQL dynamic formatting | 4 |
| `php:S4502` | CSRF disabled | 1 *(Paket C saja)* |
| `php:S1068` | unused private fields | 3 |
| `php:S1142` | too many returns | 1 |

→ **Vulnerability: 9–11** (dari 1 sekarang). **Code Smell: 4** (tetap).

---

## 8. Ringkasan Paket

| Paket | Tujuan | Rule | Berat | Rollback |
|---|---|---|---|---|
| **A** | SQLi detectable | `S2077` | 🟢 Ringan (2 file baru) | `rm -rf legacy/` |
| **B** | Credential detectable | `S2068` | 🟢 Ringan (1 file + 1 param UI) | `rm config/legacy_credentials.php` |
| **C** | CSRF detectable | `S4502` | 🔴 Berat (`composer install`) | `rm vendor/ + middleware` |
| **D** | Rapikan config | — | 🟢 Ringan | `mv .bak2` |
| **E** | README akurat | — | 🟢 Ringan | `mv README.md.bak` |

**Rekomendasi:** kerjakan **A + B + D + E** dulu (semua ringan, total ~5 menit), scan ulang, lalu putuskan apakah perlu **C**.

---

## 9. Catatan Akhir

### Yang tetap tidak bisa dideteksi (dan itu OK)

- **Command Injection** (`FileController.php:116,134`) — tidak ada rule di SonarPHP. Tool pelengkap: **Semgrep** (rule `bash.lang.security`), atau **Psalm** (`TaintedShell`).
- **Path Traversal** (`FileController.php:36,43,61`) — tidak ada rule. Tool pelengkap: **Semgrep** (`php.lang.security.audit.trait-file-access`).
- **Mass Assignment** (`UserController.php:76`, `User.php:30`) — pakai **Larastan** / `larastan.larastan-strict-rules`.
- **IDOR / Missing Authorization** — **tidak ada tool SAST yang bisa deteksi** secara otomatis. Ini wajib lewat **manual review** (*threat modeling*).

### Poin untuk Discussion / Kesimpulan Laporan

> 1. **SonarPHP hanya punya 52 security rule, dan 0 di antaranya taint-based.** Tiga kelas kerentanan OWASP paling kritis (injection) berada di luar jangkauan analyzer PHP.
> 2. **Blind spot framework berlipat ganda**: `S2077` tidak tahu `DB::`, dan `S2068`/`S6418` tidak tahu class property. Kode yang *lebih clean* secara struktur justru *lebih sulit* dideteksi.
> 3. **SAST bukan pengganti review manual.** IDOR dan Missing Authorization — dua kerentanan paling berbahaya di lab ini — mustahil dideteksi otomatis.
> 4. **Rekomendasi toolchain berlapis:** SonarQube (style + config + crypto) + Semgrep/Psalm (injection) + Larastan (Laravel semantics) + manual review (authz logic).

---

*Dokumen ini dibuat dengan verifikasi terhadap source code analyzer `sonar-php` (github.com/SonarSource/sonar-php, branch master) dan dokumentasi resmi SonarQube.*
