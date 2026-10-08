# DevSecOPS
Link Materi tambahan dan praktikum DevSecOps

#**LMS**
1. LMS pembelajaran materi DevOpsSec ada pada url: https://elena.nurulfikri.ac.id/course/view.php?id=2664
2. Berikut ini adalah enrollment key untuk LMS nya: DevOpsSec_2026-1
3. Tugas dan materi akan di publish pada LMS.
4. Materi tambahan dan materi terkait Lab atau praktikum akan di publish di github Dosen.

#**Praktikum**

```INI
# ─── Project Identity ──────────────────────────────────────────────────────────
sonar.projectKey=laravel-sast-lab
sonar.projectName=Laravel SAST Lab
sonar.projectVersion=1.0.0
sonar.projectDescription=Sample Laravel project with intentional vulnerabilities for SAST learning

# ─── SonarQube Server ──────────────────────────────────────────────────────────
sonar.host.url=http://localhost:9000

# Token autentikasi — buat di: SonarQube > My Account > Security > Generate Token
sonar.token=<TOKEN_ANDA>

# ─── Source Code ───────────────────────────────────────────────────────────────
# Folder-folder yang akan di-scan
sonar.sources=app,routes,config,database

# Folder test (dianalisis secara terpisah)
sonar.tests=tests

# ─── Language ──────────────────────────────────────────────────────────────────
sonar.language=php
sonar.php.version=8.1

# ─── Encoding ──────────────────────────────────────────────────────────────────
sonar.sourceEncoding=UTF-8

# ─── Exclusions ────────────────────────────────────────────────────────────────
# Folder yang TIDAK perlu di-scan
sonar.exclusions=\
  vendor/**,\
  node_modules/**,\
  storage/**,\
  bootstrap/cache/**,\
  public/vendor/**,\
  *.min.js,\
  *.min.css

# File test yang di-include
sonar.test.inclusions=tests/**/*.php
```
