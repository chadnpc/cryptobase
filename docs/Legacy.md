# Legacy & Specialized Primitives

These primitives are provided for compatibility with legacy systems or specific non-standard requirements. **For new applications, use modern alternatives like AES-GCM and SHA-3.**

## MD5 (Message Digest 5)
Broken and insecure for cryptographic purposes. Use only for non-security tasks (like file checksums).

```powershell
$hash = [MD5]::ComputeHash($data)
```

---

## TripleDES (3DES)
Legacy encryption standard. Significantly slower and less secure than AES.

```powershell
$tdes = [TripleDES]::new($key)
$ciphertext = $tdes.Encrypt($plainbytes)
```

---

## XOR
Simple XOR stream cipher. Provides no security on its own if the key is reused or predictable.

```powershell
$cipher = [XOR]::Process($data, $key)
```

---

## Rabbit
A fast stream cipher developed for the eSTREAM project.

```powershell
$rabbit = [Rabbit]::new($key, $iv)
$stream = $rabbit.Process($data)
```

---

## HC-128 & HC-256
Fast software-based stream ciphers.

```powershell
$hc = [Hc128]::new($key, $iv)
```
