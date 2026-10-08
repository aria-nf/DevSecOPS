aria@s2-ubuntu:~/nf/laravel-sast-lab$ cat analysia.md
# Analisa & Rencana Remediasi — `laravel-sast-lab`

> **Dokumen ini hanya analisis. Tidak ada file kode yang diubah.**
> Semua perubahan ditulis sebagai command yang harus kamu jalankan sendiri.
>
> **Scope:** fix 5 issue yang ditemukan SonarQube → target **0 issue**
> **Backup:** `~/sast-lab-BEFORE-20261007-055639.tar.gz`

---

## 1. Ringkasan

| # | Rule | File:Line | Jenis | Fix | Risiko |
|---|---|---|---|---|---|
| 1 | `php:S1068` | `PaymentController.php:25` | Code Smell | Hapus `$midtransServerKey` | 🟢 Nol |
| 2 | `php:S1068` | `AuthController.php:33` | Code Smell | Hapus `$dbPassword` | 🟢 Nol |
| 3 | `php:S1068` | `AuthController.php:34` | Code Smell | Hapus `$apiKey` | 🟢 Nol |
| 4 | `php:S1142` | `AuthController.php:49` | Code Smell | Gabung 2 return terakhir jadi ternary | 🟡 Sedang |
| 5 | `php:S4790` | `AuthController.php:129` | **Vulnerability** | `md5()` → `random_bytes()` | 🟢 Nol |

**Target: 5 issue → 0 issue.**

---

## 2. Analisa Detail

### ISSUE 1–3 — `php:S1068` Unused private field

#### Kenapa这三个 field bisa dihapus dengan aman

`S1068` hanya muncul kalau field **tidak pernah dibaca** di seluruh project. Ini sudah dibuktikan oleh SonarQube sendiri:

```php
// PaymentController.php
private string $paymentGatewaySecret = 'pg_secret_live_abc123xyz456';  // L24 → TIDAK kena S1068
private string $midtransServerKey    = 'Mid-server-XXXXXX-LIVE-KEY';   // L25 → KENA S1068
```

| Field | Dibaca di | Status |
|---|---|---|
| `$paymentGatewaySecret` | `PaymentController.php:77` (`Log::info`) | Dipakai → tetap |
| `$adminEmail` | `AuthController.php:59` | Dipakai → tetap |
| `$adminPassword` | `AuthController.php:59` | Dipakai → tetap |
| **`$midtransServerKey`** | — | ❌ **Tidak pernah dipakai** |
| **`$dbPassword`** | — | ❌ **Tidak pernah dipakai** |
| **`$apiKey`** | — | ❌ **Tidak pernah dipakai** |

> ✅ **Verifikasi manual (sebelum eksekusi):** pastikan tidak ada teks `midtransServerKey`, `dbPassword`, atau `apiKey` di file lain.
> ```bash
> grep -rn 'midtransServerKey\|dbPassword\|apiKey' app/ routes/ database/ config/
> ```

#### Before → After

**`app/Http/Controllers/PaymentController.php`**
```php
// BEFORE (L23-25)
    // Hardcoded payment gateway secret — VULNERABILITY!
    private string $paymentGatewaySecret = 'pg_secret_live_abc123xyz456';  // ❌ CWE-798
    private string $midtransServerKey    = 'Mid-server-XXXXXX-LIVE-KEY';   // ❌ CWE-798
```
```php
// AFTER
    // Hardcoded payment gateway secret — VULNERABILITY!
    private string $paymentGatewaySecret = 'pg_secret_live_abc123xyz456';  // ❌ CWE-798
```
> ⚠️ `$paymentGatewaySecret` **sengaja dibiarkan** — Sonar tidak menandainya, dan ini bahan demo CWE-798 (secret masuk ke log, L77).

**`app/Http/Controllers/AuthController.php`**
```php
// BEFORE (L31-34)
    private string $adminEmail    = 'admin@company.com';
    private string $adminPassword = 'Admin@123!Secret';      // HARDCODED PASSWORD!
    private string $dbPassword    = 'mysql_root_pass_2024';  // HARDCODED DB PASSWORD!
    private string $apiKey        = 'sk-prod-abc123xyz789secretkey'; // HARDCODED API KEY!

// AFTER
    private string $adminEmail    = 'admin@company.com';
    private string $adminPassword = 'Admin@123!Secret';      // HARDCODED PASSWORD!
```
> ⚠️ `$adminPassword` **sengaja dibiarkan** — masih hardcoded (CWE-798) tapi dipakai di L59, jadi di luar scope fix ini.

#### Command
```bash
cd /home/aria/nf/laravel-sast-lab

# Hapus per-pattern (aman, idempotent, aman dari pergeseran nomor baris)
sed -i '/private string \$midtransServerKey/d' app/Http/Controllers/PaymentController.php
sed -i '/private string \$dbPassword/d'        app/Http/Controllers/AuthController.php
sed -i '/private string \$apiKey/d'            app/Http/Controllers/AuthController.php
```

#### Verifikasi
```bash
grep -c 'midtransServerKey\|dbPassword\|apiKey' app/Http/Controllers/*.php
# harusnya: 0 (atau tidak ada output)

php -l app/Http/Controllers/PaymentController.php
php -l app/Http/Controllers/AuthController.php
# harusnya: "No syntax errors detected"
```

#### Rollback
```bash
cd /tmp && rm -rf rollback-sast && mkdir rollback-sast && cd rollback-sast
tar xzf ~/sast-lab-BEFORE-*.tar.gz
cp -r app/Http/Controllers/. /home/aria/nf/laravel-sast-lab/app/Http/Controllers/
```

---

### ISSUE 4 — `php:S1142` Terlalu banyak return statement

#### Analisa

`login()` (`AuthController.php:49`) punya **4 return**:

| # | Baris (sebelum fix) | Response | Kondisi |
|---|---|---|---|
| 1 | 63 | token admin | credential hardcoded cocok |
| 2 | 75 | 404 "email tidak ditemukan" | `$user` kosong |
| 3 | 80 | token user | password cocok |
| 4 | 83 | 401 "Password salah" | fallback |

Limit default rule = **3 return per method**.

#### KonstRAINTI — kerentanan HARUS tetap ada

Fix ini **tidak boleh** menghapus kerentanan, karena itu bahan laporan. Yang wajib masih ada setelah fix:

- ❌ Hardcoded credential check (`AuthController.php:59`)
- ❌ Hardcoded admin token (`AuthController.php:64`)
- ❌ SQL Injection di `DB::select` (`AuthController.php:71`)
- ❌ User enumeration — 404 vs 401 masih bisa dibedakan (`AuthController.php:75` vs `83`)
- ❌ Password dibandingkan tanpa hashing (`AuthController.php:79`)
- ❌ Password di-log plaintext (`AuthController.php:55-56`)

#### Solusi: ternary pada return terakhir

Ganti blok:
```php
    // ❌ VULNERABLE: Membandingkan password tanpa hashing
    if ($user[0]->password === $password) {  // No password_verify()!
        return response()->json(['token' => 'user-token-' . $user[0]->id]);
    }

    return response()->json(['error' => 'Password salah'], 401);
```

menjadi:
```php
    // ❌ VULNERABLE: Membandingkan password tanpa hashing — TIDAK ada password_verify()
    return $user[0]->password === $password
        ? response()->json(['token' => 'user-token-' . $user[0]->id])
        : response()->json(['error' => 'Password salah'], 401);
```

**Kenapa ini aman:**
- `return` dihitung per kata kunci `return` → dari 4 jadi **3** (1 admin + 1 not-found + 1 ternary)
- TERNARY **bukan** return statement, jadi tidak dihitung S1142
- Semua kondisi & response **tidak berubah** — user enumeration (404 vs 401) tetap ada
- Perilaku kode identik

**Hasil: 3 return → lolos S1142.**

#### Command
Gunakan `python3` supaya eksak (blok multi-baris, tidak bisa di-handle `sed` baris tunggal dengan aman):

```bash
cd /home/aria/nf/laravel-sast-lab

cp app/Http/Controllers/AuthController.php /tmp/AuthController.php.bak

python3 - <<'PY'
import io, sys

path = 'app/Http/Controllers/AuthController.php'
src = io.open(path, encoding='utf-8').read()

old = """        // ❌ VULNERABLE: Membandingkan password tanpa hashing
        if ($user[0]->password === $password) {  // No password_verify()!
            return response()->json(['token' => 'user-token-' . $user[0]->id]);
        }

        return response()->json(['error' => 'Password salah'], 401);
"""

new = """        // ❌ VULNERABLE: Membandingkan password tanpa hashing — tidak ada password_verify()!
        //    FIX S1142: dua return digabung jadi satu ternary agar jumlah return <= 3.
        //    Perilaku & status code TIDAK berubah (user enumeration tetap bisa dilakukan).
        return $user[0]->password === $password
            ? response()->json(['token' => 'user-token-' . $user[0]->id])
            : response()->json(['error' => 'Password salah'], 401);
"""

if old not in src:
    sys.exit('❌ POLA TIDAK COCOK — file tidak diubah. Cek manual.')

io.open(path, 'w', encoding='utf-8').write(src.replace(old, new, 1))
print('✅ AuthController.php updated')
PY
```

#### Verifikasi
```bash
php -l app/Http/Controllers/AuthController.php
# harusnya: No syntax errors detected

# hitung jumlah return di login()
sed -n '/public function login/,/^    }/p' app/Http/Controllers/AuthController.php | grep -c 'return'
# harusnya: 3
```

#### Rollback
```bash
cp /tmp/AuthController.php.bak app/Http/Controllers/AuthController.php
```

---

### ISSUE 5 — `php:S4790` Weak hashing algorithm

#### Analisa

```php
// BEFORE (AuthController.php:129)
$resetToken = md5($email . time());  // md5 sudah deprecated untuk keamanan!
```

Rule `S4790` (`CryptographicHashCheck.java`) mendeteksi `md5()` / `sha1()`.
Root cause sebenarnya bukan cuma "md5 lemah", tapi **token-nya `predictable`**:
`md5(email + time())` → attacker bisa hitung sendiri kalau tahu email + perkirakan waktu.

**CWE:** CWE-640 (Weak Password Recovery Mechanism) — Sonar melabelinya CWE-328.

#### ⚠️ Kendala yang ditemukan

Migration `database/migrations/2024_01_01_000000_create_users_table.php:35` **tidak punya kolom `reset_token_expires_at`**:

```php
// ❌ VULNERABILITY: reset_token tanpa expiry time dan tidak di-hash
$table->string('reset_token')->nullable();
```

Jadi remediation "lengkap" (token + expiry) butuh ubah skema DB.

#### Opsi 5a — Minimal (recommended, cukup untuk hilangkan S4790)

Ganti baris 129 saja, tidak perlu ubah skema:

```php
// AFTER
$resetToken = bin2hex(random_bytes(32));
```

**Dampak:**
- ✅ `S4790` hilang
- ✅ Token jadi unpredictable (CSPRNG, 256-bit)
- ✅ Tidak ada perubahan skema DB
- ✅ Perilaku endpoint tidak berubah
- ⚠️ Token masih **tidak punya expiry** → CWE-640 belum tuntas 100%

#### Opsi 5b — Lengkap (fix CWE-640 sampai tuntas)

Perlu 2 perubahan:

**B.1 — Tambah kolom expiry di migration**
```bash
cd /home/aria/nf/laravel-sast-lab
cp database/migrations/2024_01_01_000000_create_users_table.php /tmp/users_migration.bak

python3 - <<'PY'
import io, sys
path = 'database/migrations/2024_01_01_000000_create_users_table.php'
src = io.open(path, encoding='utf-8').read()

old = """            // ❌ VULNERABILITY: reset_token tanpa expiry time dan tidak di-hash
            $table->string('reset_token')->nullable();
"""

new = """            // FIX CWE-640: reset_token sekarang punya masa berlaku (15 menit)
            $table->string('reset_token')->nullable();
            $table->timestamp('reset_token_expires_at')->nullable();
"""

if old not in src:
    sys.exit('❌ POLA TIDAK COCOK')
io.open(path, 'w', encoding='utf-8').write(src.replace(old, new, 1))
print('✅ migration updated')
PY
```

**B.2 — Ganti resetPassword()**
```php
    public function resetPassword(Request $request)
    {
        $email = $request->input('email');

        // ✅ FIXED (CWE-330): token dari CSPRNG — tidak bisa di-predict atau di-brute-force
        $resetToken = bin2hex(random_bytes(32));

        // ✅ FIXED (CWE-613): token hanya berlaku 15 menit
        $resetTokenExpiresAt = date('Y-m-d H:i:s', time() + 900);

        // ❌ VULNERABLE (CWE-89): SQL Injection — belum di-bind. Di luar scope fix ini.
        DB::update(
            "UPDATE users SET reset_token = '{$resetToken}', "
            . "reset_token_expires_at = '{$resetTokenExpiresAt}' WHERE email = '{$email}'"
        );

        // ❌ VULNERABLE (CWE-532): token di-log — di luar scope fix ini
        Log::info("Password reset requested for: {$email}, token: {$resetToken}");

        // ❌ VULNERABLE (CWE-200): token dikembalikan ke response — di luar scope fix ini
        return response()->json([
            'message' => 'Token reset dikirim',
            'debug_token' => $resetToken,
        ]);
    }
```

> **Rekomendasi:** pakai **5a** kalau mau cepat & minimal. Pakai **5b** kalau mau remediasi CWE-640 yang benar-benar tuntas — dan itu contoh "remediationbefore/after" terbaik buat laporan.

#### Command Opsi 5a
```bash
cd /home/aria/nf/laravel-sast-lab

cp app/Http/Controllers/AuthController.php /tmp/AuthController.php.bak5

python3 - <<'PY'
import io, sys
path = 'app/Http/Controllers/AuthController.php'
src = io.open(path, encoding='utf-8').read()

old = "        $resetToken = md5($email . time());  // md5 sudah deprecated untuk keamanan!"
new = "        $resetToken = bin2hex(random_bytes(32));"

if old not in src:
    sys.exit('❌ POLA TIDAK COCOK — file tidak diubah')
io.open(path, 'w', encoding='utf-8').write(src.replace(old, new, 1))
print('✅ resetToken fixed')
PY
```

#### Verifikasi
```bash
grep -n 'resetToken =' app/Http/Controllers/AuthController.php
# harusnya: $resetToken = bin2hex(random_bytes(32));
# pastikan tidak ada md5( lagi
grep -cn 'md5(' app/Http/Controllers/AuthController.php
# harusnya: 0

php -l app/Http/Controllers/AuthController.php
```

---

## 3. Urutan Eksekusi yang Aman

Jalankan **berurutan**, re-scan di akhir:

```
STEP 1  Backup sudah ada?          → tar tzf ~/sast-lab-BEFORE-*.tar.gz | head
STEP 2  ISSUE 1-3: hapus 3 field  → 3× sed
STEP 3  ISSUE 4: ternary          → python3 block
STEP 4  ISSUE 5: md5 → random_bytes → python3 block
STEP 5  Syntax check              → php -l (2 file)
STEP 6  Lihat diff                → diff -u vs backup
STEP 7  Scan ulang                → ./scan.sh
STEP 8  Cek hasil                 → API command (Bagian 5)
```

### Preview diff tanpa mengubah apa pun
```bash
cd /tmp && rm -rf sast-orig && mkdir sast-orig && cd sast-orig
tar xzf ~/sast-lab-BEFORE-*.tar.gz

cd /home/aria/nf/laravel-sast-lab
diff -u /tmp/sast-orig/app/Http/Controllers/AuthController.php \
        app/Http/Controllers/AuthController.php
diff -u /tmp/sast-orig/app/Http/Controllers/PaymentController.php \
        app/Http/Controllers/PaymentController.php
```

---

## 4. ⚠️ Nomor Baris Akan Bergeser

Setelah fix, **nomor baris berubah**. Kalau lo screenshot hasil "sesudah", pakai nomor **baru**:

| File | Item | Baris SEBELUM | Perkiraan SESUDAH |
|---|---|---|---|
| `PaymentController.php` | `$midtransServerKey` dihapus | L25 | — (dihapus) |
| `PaymentController.php` | `processRefund` | L61 | **L60** (−1) |
| `AuthController.php` | `$dbPassword`, `$apiKey` dihapus | L33, L34 | — (dihapus) |
| `AuthController.php` | `login()` | L49 | **L47** (−2) |
| `AuthController.php` | `register()` | L96 | **L91** (−5) |
| `AuthController.php` | `resetPassword()` | L124 | **L119** (−5) |
| `AuthController.php` | `md5()` | L129 | **L125** (−4, setelah refactor) |

> 📸 **Screenshot SEBELUM sudah kamu punya** (5 issue di atas). Ambil screenshot SESUDAH setelah re-scan.

---

## 5. Verifikasi Hasil Scan

```bash
export SQ=http://localhost:9000
export SONAR_TOKEN=your_token_here

# Total issue — target: 0
curl -su "$SONAR_TOKEN:" "$SQ/api/issues/search?componentKeys=laravel-sast-lab&ps=1" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('TOTAL ISSUES:', d['total'])"
```

Kalau hasilnya `TOTAL ISSUES: 0` → 🎉 berhasil.
Kalau masih ada → buka issue-nya di Web UI, catat rule-nya, bandingkan dengan tabel di Bagian 6.

### Kalau `S1142` masih muncul
Cek jumlah return:
```bash
sed -n '/public function login/,/^    }/p' app/Http/Controllers/AuthController.php | grep -c 'return'
```
Harus `3`. Kalau `4`, berarti STEP 3 belum dijalankan atau polanya tidak cocok.

### Kalau `S4790` masih muncul
```bash
grep -n 'md5(\|sha1(' app/Http/Controllers/AuthController.php
```
Kalau masih ada → `substr(md5(...))` yang变态, atau STEP 4 gagal.

---

## 6. Apa yang TETAP Rentan Setelah Fix

Fix di atas **tidak** menyentuh 13 kerentanan lain, karena SonarPHP **tidak punya rule-nya** — jadi kalau lo fix atau nggak, dashboard tetap sama.

| Kerentanan | Lokasi | CWE | Kenapa Sonar gak bisa deteksi |
|---|---|---|---|
| SQL Injection | `UserController.php:39,54,100` | CWE-89 | `S2077` tak cover `DB::` facade |
| SQL Injection | `AuthController.php:71,104,132` | CWE-89 | idem |
| SQL Injection | `PaymentController.php:43,69,98,148` | CWE-89 | idem |
| Command Injection | `FileController.php:116,134` | CWE-78 | tidak ada rule OS command di SonarPHP |
| Path Traversal | `FileController.php:36,43,61` | CWE-22 | tidak ada rule path traversal |
| Unrestricted File Upload | `FileController.php:90` | CWE-434 | tidak ada rule-nya |
| Mass Assignment | `UserController.php:76`, `User.php:30` | CWE-915 | tidak ada rule-nya (tools: Larastan) |
| IDOR | `UserController.php:100`, `PaymentController.php:43` | CWE-639 | tidak ada rule-nya |
| Missing Authorization | `PaymentController.php:69`, `routes/web.php:73` | CWE-862 | tidak ada rule-nya |
| Hardcoded credential | `AuthController.php:32` | CWE-798 | dipakai di L59 → bukan dead field |
| Sensitive data di log | `AuthController.php:55,56,109,134` | CWE-532 | tidak ada rule-nya |
| Password plaintext | `AuthController.php:79,104` | CWE-256 | bukan rule SonarPHP |
| Sensitive Data Exposure | `PaymentController.php:98` | CWE-200 | tidak ada rule-nya |
| Open Redirect | `PaymentController.php:125` | CWE-601 | tidak ada rule-nya |
| Missing Webhook Signature | `PaymentController.php:148` | CWE-345 | tidak ada rule-nya |
| CSRF disabled | `routes/web.php:26` | CWE-352 | `S4502` ≠ `withoutMiddleware()` |
| Missing Authentication | `routes/web.php:51-73` | CWE-306 | tidak ada rule-nya |

> **Jumlah: 17 titik kerentanan masih ada.** Ini yang harus lo tulis sebagai temuan *manual review* di laporan.

---

## 7. Dampak terhadap Tugas Kelompok

README:139-147 minta 5 deliverables. Impact dari fix ini:

| Deliverable | Impact |
|---|---|
| 1. Screenshot Quality Gate dashboard | ✅ **Lebih bagus** — ada before (5 issue) + after (0 issue) |
| 2. Tabel findings | ✅ Isi 5 Sonar findings + 17 temuan manual review |
| 3. Root cause analysis | ✅ Makin kuat — lo bisa jelaskan kenapa Sonar buta |
| 4. **Remediasi — kode sebelum & sesudah** | ✅ **Ini dia gunanya.** 5 contoh before/after lengkap |
| 5. Laporan BAB I–VI | ✅ |

### Temuan diskusi paling kuat

> **"SAST signature/taint memiliki blind spot signifikan terhadap framework modern."**
> 5 dari 22 kerentanan terdeteksi otomatis (23%), 17 sisanya (77%) butuh manual review.
>
> Prioritas tooling: SonarQube (style/config/crypto) + **Semgrep** (injection) + **Psalm** (taint) + **Larastan** (Laravel semantics) + **manual review** (authz logic).

---

## 8. Command Lengkap (Copy-Paste Sekaligus)

Kalau mau sekali jalan (semua 5 fix):

```bash
cd /home/aria/nf/laravel-sast-lab

cp app/Http/Controllers/AuthController.php   /tmp/AC.bak
cp app/Http/Controllers/PaymentController.php /tmp/PC.bak

# ── ISSUE 1-3: hapus unused private field ─────────────────────────────
sed -i '/private string \$midtransServerKey/d' app/Http/Controllers/PaymentController.php
sed -i '/private string \$dbPassword/d'        app/Http/Controllers/AuthController.php
sed -i '/private string \$apiKey/d'            app/Http/Controllers/AuthController.php

# ── ISSUE 4: turunkan jumlah return di login() ─────────────────────────
python3 - <<'PY'
import io, sys
p = 'app/Http/Controllers/AuthController.php'
s = io.open(p, encoding='utf-8').read()
old = """        // ❌ VULNERABLE: Membandingkan password tanpa hashing
        if ($user[0]->password === $password) {  // No password_verify()!
            return response()->json(['token' => 'user-token-' . $user[0]->id]);
        }

        return response()->json(['error' => 'Password salah'], 401);
"""
new = """        // ❌ VULNERABLE: Membandingkan password tanpa hashing — tidak ada password_verify()!
        //    FIX S1142: dua return digabung jadi satu ternary agar jumlah return <= 3.
        //    Perilaku & status code TIDAK berubah (user enumeration tetap bisa dilakukan).
        return $user[0]->password === $password
            ? response()->json(['token' => 'user-token-' . $user[0]->id])
            : response()->json(['error' => 'Password salah'], 401);
"""
sys.exit('❌ pola tidak cocok') if old not in s else io.open(p,'w',encoding='utf-8').write(s.replace(old,new,1))
print('✅ ISSUE 4 done')
PY

# ── ISSUE 5: md5() → CSPRNG ───────────────────────────────────────────
python3 - <<'PY'
import io, sys
p = 'app/Http/Controllers/AuthController.php'
s = io.open(p, encoding='utf-8').read()
old = "        $resetToken = md5($email . time());  // md5 sudah deprecated untuk keamanan!"
new = "        $resetToken = bin2hex(random_bytes(32));"
sys.exit('❌ pola tidak cocok') if old not in s else io.open(p,'w',encoding='utf-8').write(s.replace(old,new,1))
print('✅ ISSUE 5 done')
PY

# ── VERIFIKASI ─────────────────────────────────────────────────────────
echo "--- syntax check ---"
php -l app/Http/Controllers/AuthController.php
php -l app/Http/Controllers/PaymentController.php

echo "--- jumlah return di login() (target: 3) ---"
sed -n '/public function login/,/^    }/p' app/Http/Controllers/AuthController.php | grep -c 'return'

echo "--- sisa md5/sha1 (target: 0) ---"
grep -c 'md5(\|sha1(' app/Http/Controllers/AuthController.php

echo "--- sisa field unused (target: 0) ---"
grep -c 'midtransServerKey\|dbPassword\|apiKey' app/Http/Controllers/*.php
```

### Rollback total
```bash
cd /home/aria/nf/laravel-sast-lab
cp /tmp/AC.bak app/Http/Controllers/AuthController.php
cp /tmp/PC.bak app/Http/Controllers/PaymentController.php
```
atau dari backup penuh:
```bash
cd /tmp && rm -rf rb && mkdir rb && cd rb && tar xzf ~/sast-lab-BEFORE-*.tar.gz
cp -r /tmp/rb/. /home/aria/nf/laravel-sast-lab/
```

---

## 9. Ringkasan residuals

| Metrik | Sebelum | Sesudah |
|---|---|---|
| Sonar Issues | **5** | **0** (target) |
| — Vulnerability (Security) | 1 | 0 |
| — Code Smell | 4 | 0 |
| Titik kerentanan di kode | 22 | **17** |
| Deteksi otomatis | 23% | 0% *(vuln sisa memang tak terdeteksi)* |
| Pemenuhan deliverable #4 | ❌ | ✅ |

---

*Dokumen analisis. Tidak ada file yang diubah — eksekusi dilakukan manual lewat command di Bagian 8.*
aria@s2-ubuntu:~/nf/laravel-sast-lab$
